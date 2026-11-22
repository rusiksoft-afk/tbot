"""Страница кода 2FA и первичная привязка: поведение HTTP-слоя (TZ §8.2, §8.3, §9.3 п. 2–3; `T-103`, срез `R4c`).

Здесь проверяется то, что видно со стороны браузера: куда ведёт вход после пароля, при каком шаге
сессии открывается `/totp`, как выглядит первичная привязка (`GET` ничего не меняет, секрет выдаёт
только `POST /mfa-enroll/start`), чем выглядит отказ (`400`/`401`/`403`/`409`/`429`/`503`) и чего он
не делает (не двигает счётчик неудач, не выдаёт секрет, не открывает консоль, не расходует код).

Граница честности та же, что во всех офлайновых файлах среза (`web_support.py`): репозиторий в памяти
воспроизводит предикаты, но не базу. Поэтому здесь нет проверок частичного уникального индекса
`ix_totp_enrollments_user_active`, атомарности guarded-`UPDATE` в `claim_totp_step` и того, что
`rowcount` на повторном коде действительно `0` — их держит живая проверка
`tests/integration/test_totp_enrollment_db.py` (CI job `migrations`). Офлайн проверяется договорённость
слоя: «повторный код не принят», «шаг не израсходован вторично», «отказ не изменил состояние».

Время заморожено и переводимо (`Clock`): окна TOTP живут 30 секунд, окна лимитов — минуты. Сдвиг на
«минуту с запасом» проходил бы только при удачной секунде запуска и был бы нестабильной проверкой.
Границы, которые относятся к одной строке (срок незавершённой привязки), задаются правкой самой
строки, а не глобальным временем: `PENDING_ENROLLMENT_TTL` совпадает с `IDLE_TIMEOUT` намеренно, и
сдвиг часов, превышающий TTL, одновременно убил бы и сеанс — проверка проверяла бы просрочку сеанса,
а не просрочку привязки.

Проверок `audit_log` в этом файле нет намеренно: имена событий привязки, блокировок и отказов `429`
и цепочка хэшей относятся к `T-109` (перенос зафиксирован `ADR-009`); компенсирующие контроля —
строки `totp_enrollments`, `totp_failures`, `users.locked_until`, `rate_buckets` — проверяются здесь.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import re
import secrets
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final
from uuid import UUID

import pytest
import structlog
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.login as login_routes
import apps.web.routes.sessions as session_routes
import apps.web.routes.totp as totp_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.qrcode import QrBuildError, QrGraphic, qr_graphic
from apps.web.routes.totp import (
    ALREADY_BOUND_DETAIL,
    CODE_FAILURE_DETAIL,
    CONFIRM_NOTE,
    EMPTY_CODE_DETAIL,
    ENROLL_ONCE_DETAIL,
    FIELD_CODE,
    FIELD_FIRST_CODE,
    FIELD_SECOND_CODE,
    LOCK_NOTE,
    NO_ENROLLMENT_DETAIL,
    STALE_ENROLLMENT_DETAIL,
)
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.keys import TWO_FACTOR_UNAVAILABLE_DETAIL
from apps.web.security.rate_limit import (
    IP_BAN_SCOPE,
    MUTATION_USER_SCOPE,
    RATE_LIMITS,
    TOTP_IP_SCOPE,
    TOTP_SESSION_SCOPE,
)
from apps.web.security.sessions import (
    CONSOLE_PATH,
    LOGIN_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    POST_CODE_REDIRECT,
    POST_LOGIN_REDIRECT,
    SESSIONS_PATH,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.common.logging import configure_logging
from packages.identity.totp import (
    TOTP_FAILURE_HORIZON,
    TOTP_MAX_FAILED_CODES,
    TOTP_PERIOD_SECONDS,
    new_totp_secret,
    totp_code,
    totp_provisioning_uri,
)
from packages.identity.totp_enrollment import PENDING_ENROLLMENT_TTL, TOTP_ISSUER
from packages.storage.models import TotpEnrollment, User, UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
    session_cookie,
    set_kek_file,
)

#: Момент, от которого живёт файл. Основой служат реальные часы: `totp_code`, который тест считает
#: сам, обязан оставаться в том же окне, что и слой приложения.
FROZEN = datetime.now(UTC).replace(microsecond=0)

#: Адреса из резервных диапазонов RFC 5737: счётчик лимитов и окно перебора ключуются адресом,
#: поэтому в проверках адрес обязан быть явным, а не «пустым» (`client.address` без `XFF`).
ADDRESS_A: Final = "203.0.113.11"
ADDRESS_B: Final = "203.0.113.12"
ADDRESS_C: Final = "203.0.113.13"

#: Области, которых не должно быть у отказов, не тронувших слой кода.
CODE_SCOPES: Final = frozenset({TOTP_SESSION_SCOPE, TOTP_IP_SCOPE})

META_TOKEN = re.compile(r'name="csrf-token" content="([^"]+)"')
SECRET_BLOCK = re.compile(r"<code>([A-Z2-7]{16,128})</code>")


class Clock:
    """Задаваемое «сейчас» для слоя входа (см. модульный докстринг)."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях слоя, где его вызывают напрямую.

    Маршруты входа, сеансов и страницы кода, слой сессий и механизм лимитов: пропуск любого из них
    означал бы, что часть проверок живёт в реальном времени, а часть — в замороженном, и вывод по
    ним был бы неотличим от случайности. Доменные модули `packages/identity/*` не подменяются: момент
    им передаёт слой входа параметром, и это часть контракта `R2`.
    """
    fake = Clock(FROZEN)
    for module in (
        login_routes,
        session_routes,
        totp_routes,
        security_sessions,
        rate_limit_module,
    ):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    owner = memory.seed_user()
    # Ключ обязан быть заполнен явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не срабатывает
    # и `user.id` остался бы `None`. Строка привязки и лента неудач хранят `user_id`; с `None`
    # проверки изоляции (§8.8) сравнивали бы `None` с `None` и проходили бы молча.
    owner.id = uuid.uuid4()
    return memory


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей в песочнице: тот же формат, что пишет `deploy/vps/keys_setup.py`.

    Боевой путь (`/etc/tbot/keys/kek.json`) здесь недоступен намеренно: он требует POSIX-прав и root.
    Подмена пути меняет только источник байтов: разбор формата, проверка версий и проверка прав
    (`ADR-014` п. 5) остаются боевыми, а POSIX-ветку проверки прав держат
    `tests/unit/test_envelope_crypto.py`.
    """
    path = tmp_path / "kek.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": base64.b64encode(secrets.token_bytes(32)).decode()}],
            }
        ),
        encoding="utf-8",
    )
    # Режим ставится явно. На Linux файл в песочнице появляется с маской, унаследованной от umask
    # (0644), а политика файла ключей разрешает только биты внутри `0640` (`ADR-014` п. 5) — то есть
    # боевая проверка прав отказала бы такому файлу, и страница привязки отвечала бы `503`.
    # На Windows битов POSIX нет, поэтому локально этот дефект невиден вовсе: его поймал только
    # прогон на Linux. `0600` проходит политику (биты владельца) и не даёт доступа «остальным».
    path.chmod(0o600)
    return path


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock, kek: Path) -> Iterator[TestClient]:
    assert clock() == FROZEN, "фикстура сдвинула время, а тест ждёт `FROZEN`"
    with build_client(store, settings) as test_client:
        set_kek_file(test_client, kek)
        yield test_client


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _headers(*, address: str | None = None, origin: str = "https://testserver") -> dict[str, str]:
    headers = {"Origin": origin, "User-Agent": "totp-test"}
    if address is not None:
        headers["X-Forwarded-For"] = address
    return headers


def _войти(client: TestClient) -> str:
    """Войти паролем и вернуть значение куки (шаг `'password'`, §8.2 шаг (1))."""
    response = login(client)
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    assert secret, "после входа куки нет"
    return secret


def _статус(response: Response) -> int:
    """Код ответа типизированно: у `httpx` он объявлен как `Any`, а тесты обязаны сравнивать `int`."""
    status: int = response.status_code
    return status


def _вход_с_адреса(client: TestClient, address: str) -> int:
    """Запрос входа с заданного адреса и его код ответа (для проверки общего окна адреса)."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers=_headers(address=address),
        follow_redirects=False,
    )
    return _статус(response)


def _токен(client: TestClient) -> str:
    """CSRF-токен из страницы привязки (§8.3, `ADR-008`).

    Страница привязки выбрана не случайно: она отдаёт `200` на обоих шагах `'password'` и `'totp'`,
    тогда как `/totp` без подтверждённой привязки редиректит и токена в ответе не несёт. У полной
    сессии эта страница тоже редирект, поэтому таким тестам токен берётся до перехода на `'full'`.
    """
    response = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert response.status_code == 200, response.text
    match = META_TOKEN.search(response.text)
    assert match, f"в странице нет meta токена: {response.text[:300]}"
    return match.group(1)


def _начать_привязку(client: TestClient, *, address: str = ADDRESS_A) -> tuple[str, str]:
    """Мутация «выдать секрет»: возвращает (токен, показанный секрет).

    Отдельная функция, а не инлайн в тестах: она же фиксирует, что секрет выдался именно мутацией,
    и не даёт тестам забыть `Origin` (без него второй слой CSRF просто выключен).
    """
    token = _токен(client)
    response = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: token},
        headers=_headers(address=address),
    )
    assert response.status_code == 200, response.text
    match = SECRET_BLOCK.search(response.text)
    assert match, f"мутация не показала секрет: {response.text[:400]}"
    return token, match.group(1)


def _пара(secret: str, moment: datetime) -> tuple[str, str]:
    """Два кода из соседних окон (§8.2: «2 последовательных кода»)."""
    return (
        totp_code(secret, moment),
        totp_code(secret, moment + timedelta(seconds=TOTP_PERIOD_SECONDS)),
    )


def _подтвердить(
    client: TestClient, secret: str, clock: Clock, *, address: str = ADDRESS_A
) -> tuple[str, str]:
    """Подтвердить привязку парой из соседних окон; вернуть эту пару."""
    token = _токен(client)
    first, second = _пара(secret, clock())
    response = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(address=address),
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == TOTP_CODE_PATH
    return first, second


def _привязать(client: TestClient, clock: Clock) -> str:
    """Полный цикл привязки: выдать секрет и подтвердить. Шаг сессии после него — `'totp'`."""
    _token, secret = _начать_привязку(client)
    _подтвердить(client, secret, clock)
    return secret


def _код(client: TestClient, secret: str, clock: Clock, *, address: str = ADDRESS_A) -> int:
    """Один запрос `POST /totp` кодом из текущего окна; возвращает код ответа."""
    token = _токен(client)
    response = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=address),
        follow_redirects=False,
    )
    return _статус(response)


def _пустой_код(client: TestClient, path: str, *, address: str) -> int:
    """Форма с пустым полем кода: поле обязано быть пустым, а не отсутствующим."""
    token = _токен(client)
    field = FIELD_FIRST_CODE if path == MFA_ENROLL_VERIFY_PATH else FIELD_CODE
    response = client.post(
        path, data={CSRF_FORM_FIELD: token, field: ""}, headers=_headers(address=address)
    )
    return _статус(response)


def _чужой_код(clock: Clock) -> str:
    """Код, который точно не подходит: значение из другого секрета в текущем окне.

    Случайная строка не годится: подходившее значение сделало бы проверку непредсказуемой, а код вне
    окна проверял бы отклонение по окну, а не по значению.
    """
    return totp_code(new_totp_secret(), clock())


def _пользователь(store: MemoryStore) -> User:
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None
    assert user.id is not None
    return user


def _сеанс(store: MemoryStore, cookie: str) -> UserSession:
    """Строка сеанса по значению куки: ключ счётчика по сеансу — `id` этой строки (§8.3)."""
    record = store.find_by_secret(cookie)
    assert record is not None, "сеанс пропал из репозитория"
    return record


def _шаг(store: MemoryStore, cookie: str) -> str:
    return _сеанс(store, cookie).auth_step


def _привязки(store: MemoryStore, user_id: UUID) -> tuple[TotpEnrollment, ...]:
    """Все строки привязки учётной записи, включая отозванные (история)."""
    return tuple(row for row in store.enrollments() if row.user_id == user_id)


def _попытки(store: MemoryStore, user_id: UUID, clock: Clock) -> int:
    """Строки ленты `totp_failures` в горизонте окна (§8.2)."""
    return len(store.totp_failures(user_id, not_before=clock() - TOTP_FAILURE_HORIZON))


def _области(store: MemoryStore) -> set[str]:
    """Области счётчика частоты, в которых завелись окна (§8.3)."""
    return {scope for scope, _key, _start in store.buckets()}


def _обращения(store: MemoryStore, scope: str, key: str) -> int:
    """Сколько раз область уже потратили на этот ключ в заведённых окнах.

    Нужно проверкам пределов: цикл обязан довести счётчик до границы, а не «сделать `лимит`
    запросов». Часть обращений уже стоила сама привязка (её подтверждение — это мутация страницы
    кода), и отсчёт с нуля ловил бы `429` внутри цикла, где проверяется `400`.
    """
    return sum(
        attempts
        for (row_scope, row_key, _start), attempts in store.buckets().items()
        if row_scope == scope and row_key == key
    )


# ─── §9.3 п. 1–2: маршрут второй половины входа ───────────────────────────────────────────────


def _окна_кода(store: MemoryStore) -> dict[tuple[str, str, object], int]:
    """Снимок областей кода: их отказ по шагу страницы трогать не должен (§8.3).

    Снимок всех областей сравнивать нельзя: мутации привязки и успешный код входа свои
    обращения уже стоили, и общее сравнение проверяло бы весь предыдущий цикл вместо отказа.
    """
    return {key: attempts for key, attempts in store.buckets().items() if key[0] in CODE_SCOPES}


def test_вход_после_пароля_ведёт_на_страницу_кода(client: TestClient, store: MemoryStore) -> None:
    """§9.3: «`/totp` — страница ввода кода», и после пароля человек попадает именно на неё.

    До `R4c` целью редиректа был корень, и это было следствие отсутствия страницы: вести человека в
    несуществующий адрес значило бы показать `404` тому, у кого верный пароль. Теперь страница есть,
    и редирект обязан совпадать с ней: попадание в консоль означало бы доступ, которого шаг
    `'password'` не даёт (§8.2 шаг (2)).
    """
    response = login(client)
    assert response.status_code == 302
    assert response.headers["location"] == TOTP_CODE_PATH
    assert POST_LOGIN_REDIRECT == TOTP_CODE_PATH, "константа редиректа и страница разошлись"
    assert response.headers["location"] != CONSOLE_PATH
    assert _шаг(store, session_cookie(client)) == "password"

    открытая = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert открытая.status_code == 302
    assert (
        открытая.headers["location"] == MFA_ENROLL_PATH
    ), "учётной записи без привязки вводить нечего: её ведёт на страницу привязки (§9.3 п. 3)"


def test_страница_кода_доступна_только_сессии_шага_входа(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2: без живой сессии — на вход; без привязки — на привязку; с `'full'` — в консоль.

    Три состояния проверяются вместе, потому что у страницы ровно одно основание существовать:
    человек уже ввёл пароль. Открытая для полной сессии страница предлагала бы ей израсходовать код
    впустую, а открытая без привязки — вводить то, чего не существует.
    """
    anonymous = client.get(TOTP_CODE_PATH, follow_redirects=False)
    assert anonymous.status_code == 302
    assert anonymous.headers["location"] == LOGIN_PATH

    cookie = _войти(client)
    без_привязки = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert без_привязки.status_code == 302
    assert без_привязки.headers["location"] == MFA_ENROLL_PATH

    _token, secret = _начать_привязку(client)
    неподтверждённая = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert неподтверждённая.status_code == 302, "неподтверждённая привязка открыла страницу кода"
    assert неподтверждённая.headers["location"] == MFA_ENROLL_PATH
    assert _шаг(store, cookie) == "password", "посещение страницы кода не двигает шаг сессии"

    _подтвердить(client, secret, clock)
    подтверждённая = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert подтверждённая.status_code == 200, "подтверждённая привязка не открыла страницу кода"

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    assert _код(client, secret, clock) == 302
    полная = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert полная.status_code == 302, "полная сессия осталась на странице кода"
    assert полная.headers["location"] == CONSOLE_PATH


def test_подтверждённая_привязка_открывает_страницу_кода(client: TestClient, clock: Clock) -> None:
    """§9.3 п. 2: при подтверждённой привязке `/totp` отдаётся и объясняет одноразовость кодов.

    Отдельная проверка нужна потому, что «страница открылась» и «привязка подтверждена» — разные
    условия: до подтверждения человек находится на странице привязки, после — на странице кода, и
    перепутать их означает оставить пользователя между двумя формами без кода входа.
    """
    _войти(client)
    secret = _привязать(client, clock)
    page = client.get(TOTP_CODE_PATH, headers=_headers())
    assert page.status_code == 200, page.text
    assert CONFIRM_NOTE in page.text, "страница не сказала, что коды подтверждения израсходованы"
    assert f'name="{FIELD_CODE}"' in page.text, "на странице нет поля ввода кода"
    assert "До смены кода осталось" in page.text, "нет таймера окна (§9.3 п. 2)"
    assert LOCK_NOTE in page.text, "правило блокировки не объяснено (§9.3 п. 2)"
    assert secret not in page.text, "страница кода не обязана повторять секрет привязки"


def test_открытие_страницы_не_тратит_лимит_кода(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.3: пределы считаются по запросам-мутациям, и `GET` страницы кода не расходует ничего.

    Иначе каждое обновление страницы («код не подошёл, обновлю») съедало бы лимит 10/мин/сессия, и
    человек, который просто ищет генератор, упирался бы в `429`, не введя ни одного кода.
    """
    _войти(client)
    _привязать(client, clock)
    # Снимок, а не «областей нет вовсе»: мутации привязки свои обращения счётчику уже стоили, и
    # сравнивать с пустотой значило бы проверять не `GET`, а весь предыдущий цикл.
    до = dict(store.buckets())
    for _ in range(5):
        assert client.get(TOTP_CODE_PATH, headers=_headers()).status_code == 200
    assert store.buckets() == до, "`GET` страницы кода передвинул счётчик частоты (§8.3)"


# ─── §8.2 и §9.3 п. 3: первичная привязка ─────────────────────────────────────────────────────


def test_секрет_выдаёт_только_мутация_и_только_один_раз(client: TestClient) -> None:
    """§8.2: «20 секретных символов … в UI больше не показывается».

    Три утверждения держат три разных риска:
    `GET /mfa-enroll` секрета не содержит — иначе токен не нужен, и CSRF обходится одним `GET`;
    после `POST /mfa-enroll/start` секрет показан ровно один раз — это и есть «20 символов» из ТЗ;
    ни одна последующая страница его не повторяет — иначе «один показ» превращается в «секрет можно
    переснять», а он оседает в истории браузера и в логах прокси.
    """
    _войти(client)
    страница = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert SECRET_BLOCK.search(страница.text) is None, "`GET` выдал секрет"
    assert "Начать" in страница.text, "без привязки страница не предложила её начать"

    token, secret = _начать_привязку(client)
    assert len(secret) >= 16, "секрет короче минимума формата (§8.4, `packages/identity/totp.py`)"
    assert CONFIRM_NOTE in (client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}).text)

    again = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert secret not in again.text, "страница привязки повторила секрет"
    assert ENROLL_ONCE_DETAIL in again.text, "путь «начать заново» не объяснён"
    assert CONFIRM_NOTE in again.text, "форму двух кодов потеряли: человек не поймёт, что делать"

    code_page = client.get(TOTP_CODE_PATH, follow_redirects=False, headers=_headers())
    assert code_page.status_code == 302, "неподтверждённая привязка не открывает страницу кода"


def test_повторная_выдача_отзывает_прежнюю_привязку(client: TestClient, store: MemoryStore) -> None:
    """Со стороны слоя: неотозванной остаётся ровно одна привязка, а прежняя уходит в историю.

    На живой базе `ix_totp_enrollments_user_active` запрещает две неотозванные строки на учётку, и
    наивная повторная выдача падала бы `UniqueViolation` посреди HTTP-запроса (замер 2026-11-21).
    Здесь проверяется поведение, которое такой `INSERT` делает невозможным: прежняя строка отозвана,
    активна одна, секрет новый. Сам индекс и сам отказ базы держит живой файл
    `tests/integration/test_totp_enrollment_db.py`.
    """
    _войти(client)
    user_id = _пользователь(store).id
    _first_token, first_secret = _начать_привязку(client)
    assert len(_привязки(store, user_id)) == 1
    assert store.active_enrollment(user_id) is not None

    _second_token, second_secret = _начать_привязку(client)
    rows = _привязки(store, user_id)
    assert len(rows) == 2, "повторная выдача обязана оставить историю, а не перезаписать строку"
    assert rows[0].revoked_at is not None, "прежняя привязка не отозвана"
    assert rows[-1].revoked_at is None
    assert first_secret != second_secret, "секрет обязан быть новым значением"
    active = store.active_enrollment(user_id)
    assert active is not None
    assert active.id == rows[-1].id


def test_подтверждение_требует_двух_кодов_из_разных_окон(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2: «подтверждение двумя последовательными кодами генератора».

    Один и тот же код дважды — это один код, а не два: генератор меняет значение раз в
    `TOTP_PERIOD_SECONDS`, и человек, который про это не знает, вводит одно значение дважды. Поэтому
    страница объясняет правило (`CONFIRM_NOTE`), слой принимает пару из соседних окон, а на повторе
    отказывает. Отказ не должен израсходовать ничего: следующая корректная пара обязана пройти, иначе
    опечатка блокировала бы привязку.
    """
    _войти(client)
    user_id = _пользователь(store).id
    _token, secret = _начать_привязку(client)
    token = _токен(client)
    first, _second = _пара(secret, clock())

    отказ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: first},
        headers=_headers(),
    )
    assert отказ.status_code == 401, отказ.text[:300]
    assert CODE_FAILURE_DETAIL in отказ.text
    assert EMPTY_CODE_DETAIL not in отказ.text, "отказ по коду нельзя выдавать за пустую форму"
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.confirmed_at is None, "привязка подтверждена без корректной пары"
    assert _попытки(store, user_id, clock) == 1, "неудача не попала в ленту (§8.2)"

    clock.advance(seconds=TOTP_PERIOD_SECONDS)
    _подтвердить(client, secret, clock)
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.confirmed_at is not None, "корректная пара не подтвердила привязку"
    assert row.last_used_step is not None, "коды подтверждения не израсходованы (§8.2, `ADR-013`)"


def test_коды_подтверждения_не_открывают_доступ(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2 шаг (2) и `ADR-013`: доступ даёт только код входа, подтверждение привязки — нет.

    В этом различии и смысл шага `'totp'`: сессия, которая могла попросить секрет и показать два
    кода, не обязана автоматически оказываться внутри консоли, иначе второй фактор сводится к одному
    паролю. Проверка держит обе половины: консоль закрыта, и тот же шаг кода вход не открывает.
    """
    cookie = _войти(client)
    user_id = _пользователь(store).id
    secret = _привязать(client, clock)
    assert _шаг(store, cookie) == "totp", "подтверждение обязано поднять шаг до 'totp'"

    закрыто = client.get(SESSIONS_PATH, follow_redirects=False, headers=_headers())
    assert закрыто.status_code == 302
    assert закрыто.headers["location"] == TOTP_CODE_PATH, "шаг 'totp' ведёт на страницу кода (§8.2)"

    _first, second = _пара(secret, clock() + timedelta(seconds=TOTP_PERIOD_SECONDS))
    token = _токен(client)
    ответ = client.post(
        TOTP_CODE_PATH, data={CSRF_FORM_FIELD: token, FIELD_CODE: second}, headers=_headers()
    )
    assert ответ.status_code == 401, "код, израсходованный подтверждением, открыл доступ"
    assert CODE_FAILURE_DETAIL in ответ.text, "причина отказа не объяснена человеку"
    assert _шаг(store, cookie) == "totp", "отказ не должен менять шаг сессии"
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.confirmed_at is not None, "отказ повредил привязку"


def test_новый_код_завершает_вход_и_открывает_консоль(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2 шаг (2): код из следующего окна → шаг `'full'`, редирект в консоль, лента не обнуляется.

    Лента неудач не чистится успехом намеренно (`ADR-013` п. 4): иначе переборщик, чередующий
    «неверный код — верный код», никогда не дошёл бы до порога блокировки.
    """
    cookie = _войти(client)
    user_id = _пользователь(store).id
    secret = _привязать(client, clock)

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    assert _код(client, secret, clock) == 302
    record = store.find_by_secret(cookie)
    assert record is not None
    assert record.auth_step == "full"
    assert POST_CODE_REDIRECT == CONSOLE_PATH, "константа редиректа после кода ведёт не в консоль"

    консоль = client.get(SESSIONS_PATH, follow_redirects=False, headers=_headers())
    assert консоль.status_code == 200, "полный вход не открыл защищённую страницу"
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.last_used_step is not None
    assert _попытки(store, user_id, clock) == 0, "успех не должен выдумывать неудачи"


def test_израсходованный_код_не_работает_в_новом_сеансе(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2 «коды принимаются один раз» — по учётной записи, а не по сеансу (`ADR-013`).

    Второй вход той же учётной записи — отдельный сеанс с новым токеном и новым CSRF-токеном; если бы
    одноразовость держалась в памяти запроса или в сеансе, такой вход принял бы уже использованный
    код. Проверка идёт при неизменных часах: код остаётся в допустимом окне и отклоняется именно как
    повтор, а не как «код не из этого окна» — иначе проверялась бы граница окна, а не одноразовость.
    """
    _войти(client)
    user_id = _пользователь(store).id
    secret = _привязать(client, clock)

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    момент = clock()
    использованный = totp_code(secret, момент)
    assert _код(client, secret, clock) == 302, "первый код входа не прошёл"
    assert _шаг(store, session_cookie(client)) == "full"

    assert _войти(client) != "", "второй вход не состоялся"
    assert _шаг(store, session_cookie(client)) == "password", "вход обязан начинаться с шага пароля"
    повтор = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: использованный},
        headers=_headers(address=ADDRESS_B),
    )
    assert повтор.status_code == 401, "израсходованный в другом сеансе код прошёл"
    assert CODE_FAILURE_DETAIL in повтор.text
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.last_used_step is not None
    assert _шаг(store, session_cookie(client)) == "password", "отказ не должен менять шаг сессии"

    clock.advance(seconds=TOTP_PERIOD_SECONDS)
    assert _код(client, secret, clock) == 302, "свежий код в новом сеансе не прошёл"


def test_полная_сессия_не_может_ни_ввести_код_ни_начать_привязку(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2: мутации входной зоны закрыты для шага `'full'` — и код, и выдача секрета.

    Порядок зависимостей (`require_csrf` → предел пользователя → шаг страницы) даёт следствие,
    которое фиксируется здесь осознанно: попытка мутации полной сессией стоит обращения счётчику
    пользователя, хотя отказ человек получает редиректом. Это верно по §8.3 (считаются запросы
    пользователя, а не удачные запросы) и нужно, чтобы проверку шага нельзя было обойти без расхода
    счётчика. При этом область кода (`totp_session`) тронута не быть не должна: до неё дело не
    доходит.
    """
    _войти(client)
    token = _токен(client)
    secret = _привязать(client, clock)
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    assert _код(client, secret, clock) == 302
    до = _окна_кода(store)
    было = _обращения(store, MUTATION_USER_SCOPE, str(_пользователь(store).id))

    код = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: _чужой_код(clock)},
        headers=_headers(),
        follow_redirects=False,
    )
    assert код.status_code == 302
    assert код.headers["location"] == CONSOLE_PATH

    привязка = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: token},
        headers=_headers(),
        follow_redirects=False,
    )
    assert привязка.status_code == 302
    assert привязка.headers["location"] == CONSOLE_PATH
    # Успешный код входа свои обращения счётчику уже стоил, поэтому сравнивается снимок до и после
    # двух отказов по шагу: область кода до них дойти не должна (проверка шага стоит до `enforce_scope`).
    assert _окна_кода(store) == до, "отказ по шагу тронул области частоты кода (§8.3)"
    # Предел пользователя при этом сдвигается: порядок зависимостей (§8.3, `ADR-008`) —
    # `require_csrf` → предел пользователя → шаг страницы, и формулировка «считаются запросы
    # пользователя, а не удачные запросы» означает, что попытка мутации полной сессией стоит
    # обращения. Это следствие закреплено здесь, а не «как получилось».
    assert (
        _обращения(store, MUTATION_USER_SCOPE, str(_пользователь(store).id)) > было
    ), "отказ по шагу не стоил обращения пределу пользователя (§8.3)"


def test_повторная_первичная_привязка_отклонена(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2 случай 2: со страницы первичной привязки привязку нельзя ни выдать заново, ни подтвердить.

    «Просто выдать новый секрет» означало бы сбросить второй фактор, не спросив действующий код, то
    есть превратить 2FA в пароль. Сброс делает администратор с записью в журнал (§9.3 п. 6, допуск
    `T-106`). Ответ здесь — `409` с объяснением, и состояние не меняется: прежняя строка не отзывается,
    новая не создаётся, секрет не показывается.
    """
    _войти(client)
    user_id = _пользователь(store).id
    secret = _привязать(client, clock)
    прежняя = store.active_enrollment(user_id)
    assert прежняя is not None
    assert прежняя.confirmed_at is not None

    token = _токен(client)
    response = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())
    assert response.status_code == 409, response.text[:300]
    assert ALREADY_BOUND_DETAIL in response.text, "отказ без объяснения, куда идти дальше"
    assert SECRET_BLOCK.search(response.text) is None, "на отказе секрет показывать нельзя"

    после = store.active_enrollment(user_id)
    assert после is прежняя
    assert после.revoked_at is None, "отказ изменил привязку"
    assert len(_привязки(store, user_id)) == 1

    first, second = _пара(secret, clock())
    подтверждение = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(),
    )
    assert (
        подтверждение.status_code == 409
    ), "подтверждение уже подтверждённой привязки — тоже отказ"
    assert ALREADY_BOUND_DETAIL in подтверждение.text


def test_подтвердить_протухшую_привязку_нельзя(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Срок незавершённой привязки (`PENDING_ENROLLMENT_TTL`) держит и страницу, и подтверждение.

    Незавершённая строка не имеет права жить вечно: пока она есть, новая выдача обязана её отзывать
    (частичный уникальный индекс), а человек, вернувшийся к странице позже, не должен обнаружить
    «вечную» форму подтверждения с потерянным секретом. Просрочку задаёт сама строка, а не часы:
    `PENDING_ENROLLMENT_TTL` равен `IDLE_TIMEOUT`, и сдвиг времени убил бы ещё и сеанс.

    Отказ по сроку — не попытка подбора: лента неудач остаётся пустой (§8.2 считает попытки кода).
    """
    _войти(client)
    user_id = _пользователь(store).id
    _token, secret = _начать_привязку(client)
    строка = store.active_enrollment(user_id)
    assert строка is not None
    строка.enrolled_at = clock() - PENDING_ENROLLMENT_TTL - timedelta(minutes=1)

    страница = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert STALE_ENROLLMENT_DETAIL in страница.text, "состояние «срок истёк» не объяснено"

    token = _токен(client)
    first, second = _пара(secret, clock())
    ответ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(),
    )
    assert ответ.status_code == 400, "протухшую привязку подтвердили"
    assert STALE_ENROLLMENT_DETAIL in ответ.text
    row = store.active_enrollment(user_id)
    assert row is not None
    assert row.confirmed_at is None, "подтверждение всё-таки произошло"
    assert _попытки(store, user_id, clock) == 0, "отказ по сроку — не попытка подбора (§8.2)"

    _second_token, новый = _начать_привязку(client)
    assert новый != secret
    rows = _привязки(store, user_id)
    assert rows[0].revoked_at is not None
    assert rows[-1].revoked_at is None


def test_подтвердить_без_привязки_нельзя(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Мутация подтверждения без привязки — `400` с объяснением, а не `500` и не «неверный код».

    Форма подтверждения могла прийти от старой страницы (человек держал её открытой). Отказ обязан
    называть причину — «привязки ещё нет» — и вести к действию «начать привязку», иначе пользователь
    крутит форму с кодами, которые нечем подтвердить.
    """
    _войти(client)
    token = _токен(client)
    first, second = _пара(new_totp_secret(), clock())
    ответ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(),
    )
    assert ответ.status_code == 400, ответ.text[:300]
    assert NO_ENROLLMENT_DETAIL in ответ.text
    assert store.enrollments() == (), "отказ создал привязку"
    assert (
        _попытки(store, _пользователь(store).id, clock) == 0
    ), "несуществующая привязка записала неудачу"


def test_пустая_форма_подтверждения_не_приближает_блокировку(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2: пустые поля обеих форм — `400`, без записи в ленту неудач.

    Отправивший пустую форму (нажал «подтвердить» раньше, чем открыл генератор) не должен получать
    блокировку, а переборщик — способ размывать счётчик. Предел частоты при этом расходуется: §8.3
    считает запросы, а не удачные запросы, иначе счётчик обходили бы мусорными запросами.
    """
    _войти(client)
    user_id = _пользователь(store).id
    secret = _начать_привязку(client)[1]

    # Пустая форма подтверждения — при начатой привязке; пустая форма кода — при подтверждённой:
    # иначе запрос ушёл бы на редирект «сначала привяжи», и проверялся бы редирект, а не форма.
    assert _пустой_код(client, MFA_ENROLL_VERIFY_PATH, address=ADDRESS_A) == 400
    _подтвердить(client, secret, clock)
    assert _пустой_код(client, TOTP_CODE_PATH, address=ADDRESS_A) == 400
    assert _попытки(store, user_id, clock) == 0, "пустая форма записала неудачу"
    assert IP_BAN_SCOPE not in _области(store), "пустое отправление двинуло окно перебора"
    assert TOTP_SESSION_SCOPE in _области(store), "пустой запрос не стоил обращения счётчику"


# ─── §8.3: пределы по сеансу и по адресу ──────────────────────────────────────────────────────


def test_предел_мутаций_пользователя_на_выдаче_секрета(
    client: TestClient, store: MemoryStore
) -> None:
    """Выдача секрета попадает под счётчик мутаций пользователя и отвечает `429`, а не ошибкой.

    Первичная привязка — самая «дорогая» мутация страницы: она создаёт строку привязки и шифрует
    секрет, поэтому «60 обращений пользователя в минуту» (`ADR-007`) обязан держать и её, иначе
    перебор сводится к бесконечному перевыпуску привязки. Отдельно здесь держится форма отказа:
    `429` с `Retry-After`, без нового секрета в ответе и без новой строки привязки — иначе отказ
    «лимит исчерпан» сам выдавал бы материал для входа.

    Чтение страницы при этом остаётся доступным: лимит мутаций не превращает отказ в недоступность
    объяснения, и человек видит, что происходит, а не пустой экран.
    """
    _войти(client)
    user = _пользователь(store)
    лимит = RATE_LIMITS[MUTATION_USER_SCOPE]

    for номер in range(1, лимит + 1):
        ответ = client.post(
            MFA_ENROLL_START_PATH,
            data={CSRF_FORM_FIELD: _токен(client)},
            headers=_headers(),
        )
        assert _статус(ответ) == 200, f"выдача {номер} отклонена раньше предела"

    отказ = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: _токен(client)},
        headers=_headers(),
    )
    assert _статус(отказ) == 429, "предел мутаций пользователя на выдаче секрета не сработал"
    retry_after = отказ.headers.get("retry-after")
    assert retry_after is not None, "у отказа по лимиту нет `Retry-After`"
    assert int(retry_after) > 0, f"`Retry-After` неположительный: {retry_after}"
    assert not SECRET_BLOCK.search(отказ.text), "отказ по лимиту выдал секрет"

    # Состояние: отказ не создал привязку. История отзывов остаётся, действующая строка одна.
    строки = _привязки(store, user.id)
    assert len(строки) == лимит, f"лимитированный запрос создал строку привязки: {len(строки)}"
    assert (
        sum(1 for row in строки if row.revoked_at is None) == 1
    ), "после серии выдач действующих привязок больше одной"
    assert not (
        _области(store) & CODE_SCOPES
    ), f"выдача секрета тронула области кода: {sorted(_области(store) & CODE_SCOPES)}"

    чтение = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert _статус(чтение) == 200, "отказ по лимиту мутаций закрыл и чтение страницы привязки"
    assert not SECRET_BLOCK.search(чтение.text), "чтение страницы привязки выдало секрет"


@pytest.mark.parametrize("область", [TOTP_IP_SCOPE, TOTP_SESSION_SCOPE])
def test_предел_кодов_по_адресу_и_по_сеансу(
    client: TestClient, store: MemoryStore, clock: Clock, область: str
) -> None:
    """§8.3: `totp_ip` (5/мин/IP) и `totp_session` (10/мин/сессия) срабатывают до криптографии.

    Проверки разделены, потому что ключи у них разные и защищают они от разного: адресный предел
    — от перебора там, где сессию украсть проще и где за адресом сидят соседи (NAT), предел на сеанс
    — от того, кто держит одну сессию и круит коды. Один общий счётчик эти случаи не различает, и
    второй из них терялся бы за первым.

    Отправляются пустые формы: они доходят до счётчика (он стоит до проверки поля) и не пишут неудачу,
    иначе проверка смешалась бы с блокировками §8.2 и не отличала бы `429` лимита от `429` блокировки.
    """
    cookie = _войти(client)
    _привязать(client, clock)
    лимит = RATE_LIMITS[область]
    ключ = ADDRESS_A if область == TOTP_IP_SCOPE else str(_сеанс(store, cookie).id)
    # Адресные запросы в цикле меняются только у предела по сеансу: иначе срабатывал бы предел по
    # адресу, и проверка «предел по сеансу» проверяла бы чужое правило.
    ротация = область == TOTP_SESSION_SCOPE

    for номер in range(лимит - _обращения(store, область, ключ)):
        адрес = ADDRESS_A if not ротация else f"198.51.100.{20 + номер}"
        assert _пустой_код(client, TOTP_CODE_PATH, address=адрес) == 400
    ответ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: ""},
        headers=_headers(address=ADDRESS_A if not ротация else "198.51.100.99"),
    )

    assert _статус(ответ) == 429, f"предел {область} не сработал"
    assert "Retry-After" in ответ.headers, "отказ по лимиту без подсказки о сроке (§8.3)"
    assert область in _области(store)
    assert _попытки(store, _пользователь(store).id, clock) == 0, "предел записал неудачу в ленту"


def test_окно_перебора_по_адресу_один_счётчик_для_пароля_и_для_кода(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2 «3 неудачные попытки с одного IP за 5 минут»: попытки кода считаются вместе с паролем.

    Раздельные окна адреса обходились бы чередованием полей («пароль — код — пароль»), и правило «3
    попытки» теряло бы смысл. Проверка идёт через две разные страницы: три неверных кода с адреса,
    затем запрос входа с того же адреса — вход обязан отказать по бану адреса, не проверяя пароль.
    """
    _войти(client)
    _привязать(client, clock)
    for _ in range(3):
        # Часы в цикле не двигаются: неудачи обязаны попасть в одно 300-секундное окно `ip_ban`.
        # Сдвиг на минуту переносил бы часть попыток в соседнее окно, и ни в одном окне порог не
        # набрался бы — проверка зависела бы от секунды запуска (тот же урок, что у окон лимитов).
        ответ = client.post(
            TOTP_CODE_PATH,
            data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: _чужой_код(clock)},
            headers=_headers(address=ADDRESS_C),
        )
        assert _статус(ответ) in (401, 429), ответ.text[:300]
    assert IP_BAN_SCOPE in _области(store), "окно перебора не двигалось попыткой кода"

    assert (
        _вход_с_адреса(client, ADDRESS_C) == 429
    ), "бан адреса не закрыл вход: попытка пароля после трёх попыток кода прошла"
    assert _вход_с_адреса(client, ADDRESS_B) == 302, "бан адреса расползся на чужой адрес (§8.2)"


def test_неверные_коды_закрывают_вход(client: TestClient, store: MemoryStore, clock: Clock) -> None:
    """§8.2: `MAX_FAILED_ATTEMPTS` неверных кодов подряд закрывают учётную запись (`429`).

    Адрес в каждой попытке новый: окно «3 попытки с одного адреса» наступило бы раньше и закрыло бы
    проверяемое событие — блокировку учётной записи. Порядок отказов держит `_rejection_answer`:
    сначала учётная запись (зона меньше — одна учётка против адреса, за которым сидят соседи),
    потом адрес (`ADR-007`).
    """
    cookie = _войти(client)
    user_id = _пользователь(store).id
    _привязать(client, clock)

    for номер in range(TOTP_MAX_FAILED_CODES - 1):
        clock.advance(seconds=TOTP_PERIOD_SECONDS)
        ответ = client.post(
            TOTP_CODE_PATH,
            data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: _чужой_код(clock)},
            headers=_headers(address=f"203.0.113.{30 + номер}"),
        )
        assert _статус(ответ) == 401, ответ.text[:300]
        assert CODE_FAILURE_DETAIL in ответ.text

    # Порог закрывает учётную запись на самой попытке, которая до него дошла, а не на следующей:
    # `register_totp_code_failure` возвращает срок блокировки вместе с записью о неудаче, и ответ
    # обязан показать это сразу — иначе человек узнавал бы о блокировке только из следующего запроса,
    # а проверка «порог сработал» превращалась бы в проверку «сработал с запозданием».
    clock.advance(seconds=TOTP_PERIOD_SECONDS)
    последняя = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: _чужой_код(clock)},
        headers=_headers(address="203.0.113.60"),
    )
    assert _статус(последняя) == 429, "попытка, дошедшая до порога, не показала блокировку"
    assert "Retry-After" in последняя.headers, "отказ без подсказки о сроке (§8.3)"
    assert "/locked?" in последняя.text, "причина блокировки не названа (§8.2)"
    assert "attempts" in последняя.text
    assert _попытки(store, user_id, clock) == TOTP_MAX_FAILED_CODES
    assert _пользователь(store).locked_until is not None, "порог не закрыл учётную запись"
    assert _шаг(store, cookie) == "totp", "блокировка не меняет шаг сессии"

    clock.advance(seconds=TOTP_PERIOD_SECONDS)
    запрос = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: _чужой_код(clock)},
        headers=_headers(address=ADDRESS_B),
    )
    assert _статус(запрос) == 429, "закрытая учётная запись приняла запрос как обычно"
    assert "Retry-After" in запрос.headers
    assert (
        _попытки(store, user_id, clock) == TOTP_MAX_FAILED_CODES
    ), "заблокированная учётная запись копит новые неудачи"


def test_страница_кода_не_сообщает_число_попыток(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§9.3 п. 2: «счётчик попыток не показывается, но блокировка объясняется».

    Сравнение двух ответов (после одной и после двух неудач) сильнее проверки по подстроке: текст
    обязан остаться одинаковым. Иначе «осталось N попыток» становится картой для переборщика: по
    изменению ответа подбором узнаётся, сколько ещё осталось, а человеку эта цифра не помогает —
    правило ему объясняет `LOCK_NOTE`, и он видит его в обоих ответах.

    Адрес у второй попытки другой: порог окна перебора (3) наступил бы раньше, и сравнивался бы
    отказ `429` с отказом `401`, а не два одинаковых отказа по коду.
    """
    _войти(client)
    _привязать(client, clock)
    token = _токен(client)

    одна = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: _чужой_код(clock)},
        headers=_headers(address=ADDRESS_A),
    )
    вторая = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: _чужой_код(clock)},
        headers=_headers(address=ADDRESS_B),
    )
    assert одна.status_code == 401
    assert вторая.status_code == 401
    assert одна.text == вторая.text, "ответ изменился по числу попыток: страница показывает счётчик"
    assert LOCK_NOTE in вторая.text, "правило блокировки обязано объясняться всегда"
    assert _попытки(store, _пользователь(store).id, clock) == 2


def test_блокировка_учётной_записи_не_расходует_код(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.2: при активной блокировке код не проверяется — и не расходуется.

    Иначе блокировка стала бы способом «спалить» следующий код: он был бы израсходован и после
    разморозки уже не подошёл бы. Проверка идёт в обе стороны: `429` на мутации и объясняющая
    страница на `GET` (открыть страницу — не попытка входа, поэтому не `429`), и верный код после
    разморозки расходуется как обычно.
    """
    _войти(client)
    user = _пользователь(store)
    secret = _привязать(client, clock)
    user.locked_until = clock() + timedelta(minutes=5)

    страница = client.get(TOTP_CODE_PATH, headers=_headers())
    assert (
        страница.status_code == 200
    ), "открытие страницы закрытой учётной записи — не попытка входа"
    assert "/locked?" in страница.text
    assert "attempts" in страница.text

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    ответ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=ADDRESS_B),
    )
    assert ответ.status_code == 429, "верный код проверили в заблокированной учётной записи"
    assert "Retry-After" in ответ.headers
    row = store.active_enrollment(user.id)
    assert row is not None
    израсходовано = row.last_used_step

    user.locked_until = None
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    после = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=ADDRESS_B),
        follow_redirects=False,
    )
    assert после.status_code == 302, "верный код после разморозки не прошёл"
    row = store.active_enrollment(user.id)
    assert row is not None
    assert row.last_used_step is not None
    assert row.last_used_step > (
        израсходовано or 0
    ), "шаг кода не был израсходован после разморозки"


# ─── §8.8: CSRF и состояние ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("путь", "поля"),
    [
        (MFA_ENROLL_START_PATH, {}),
        (MFA_ENROLL_VERIFY_PATH, {FIELD_FIRST_CODE: "123456", FIELD_SECOND_CODE: "654321"}),
        (TOTP_CODE_PATH, {FIELD_CODE: "123456"}),
    ],
)
def test_мутация_без_токена_отклонена_и_состояние_не_изменено(
    client: TestClient, store: MemoryStore, путь: str, поля: dict[str, str]
) -> None:
    """§8.8: «CSRF обязателен для всех POST» — `403`, и ни одна мутация не тронута.

    Порядок зависимостей (§8.3, `ADR-008`) ставит токен до обращений к базе и до расхода лимита
    жертвы, поэтому проверяется не только код ответа: после отказа нет ни строк привязки, ни окон
    областей кода, ни счётчик мутаций пользователя. `403`, а не `302`: редирект делал бы отказ
    неотличимым от просроченной сессии, и по нему подбирали бы, где живёт запрошенный ресурс.
    """
    _войти(client)
    response = client.post(путь, data=поля, headers=_headers())
    assert response.status_code == 403, response.text[:300]
    assert store.enrollments() == (), "отказ без токена создал привязку"
    assert not (CODE_SCOPES | {MUTATION_USER_SCOPE, IP_BAN_SCOPE}) & _области(
        store
    ), "отказ без токена стоил обращений счётчику"


def test_чужой_источник_запроса_отклонён(client: TestClient, store: MemoryStore) -> None:
    """§8.3: `Origin` — второй слой; с чужим источником отказ даже с верным токеном.

    Без этого форма, скопированная на чужую страницу, открывала бы привязку: сам токен не отличает
    «нашу форму» от чужой.
    """
    _войти(client)
    token = _токен(client)
    response = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: token},
        headers=_headers(origin="https://example.com"),
    )
    assert response.status_code == 403
    assert store.enrollments() == (), "отказ по источнику создал привязку"


# ─── `ADR-014` п. 5: файл ключей недоступен ───────────────────────────────────────────────────


@pytest.mark.parametrize("состояние", ["нет файла", "битый файл", "чужой формат"])
def test_без_файла_ключей_отказ_503_а_не_отказ_кода(
    client: TestClient,
    store: MemoryStore,
    clock: Clock,
    tmp_path: Path,
    состояние: str,
) -> None:
    """Неисправность площадки не должна выглядеть как «неверный код» (§9, §8.2, `ADR-014` п. 5).

    `401` на сломанном файле ключей двигал бы счётчик неудач учётной записи: человек, который ничего
    не вводил, получил бы блокировку из-за площадки, а переборщик — способ маскировать собственную
    активность чужими поломками. Поэтому `503`, объяснение и ноль обращений к ленте и к окну адреса.
    """
    _войти(client)
    if состояние == "нет файла":
        set_kek_file(client, tmp_path / "нет-такого-файла.json")
    elif состояние == "битый файл":
        битый = tmp_path / "битый.json"
        битый.write_text("{ это не json", encoding="utf-8")
        # Режим нужен не «для порядка»: без него на Linux файл получает 0644, и отказ пришёл бы
        # из-за прав, а не из-за разбора JSON — проверка проверяла бы не то, о чём говорит имя.
        битый.chmod(0o600)
        set_kek_file(client, битый)
    else:
        чужой = tmp_path / "чужой.json"
        чужой.write_text(
            json.dumps({"format_version": 99, "active_version": 1, "keys": []}), encoding="utf-8"
        )
        чужой.chmod(0o600)
        set_kek_file(client, чужой)

    token = _токен(client)
    ответ = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())
    assert ответ.status_code == 503, ответ.text[:300]
    assert TWO_FACTOR_UNAVAILABLE_DETAIL in ответ.text, "отказ без объяснения"
    assert store.enrollments() == (), "привязка создана без файла ключей"
    assert (
        _попытки(store, _пользователь(store).id, clock) == 0
    ), "неполадка площадки записана как неудача пользователя"
    assert not CODE_SCOPES & _области(store), "отказ 503 тронул счётчик частоты"


def test_страница_привязки_открывается_без_файла_ключей(
    client: TestClient, store: MemoryStore, clock: Clock, tmp_path: Path
) -> None:
    """`GET` страницы не требует файла ключей: файл нужен действию, а не просмотру формы.

    Если бы проверка файла стояла на `GET`, сломанный файл ключей отрезал бы человеку и страницу, с
    которой можно понять, что случилось. Разделение видно по коду маршрутов: `request_key_ring`
    вызывается только в мутациях, и здесь это проверяется парой «`GET` — `200`», «`POST` — `503`».
    """
    _войти(client)
    _token, secret = _начать_привязку(client)
    set_kek_file(client, tmp_path / "нет-такого-файла.json")

    страница = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert страница.status_code == 200, "страница привязки не открылась без файла ключей"
    assert ENROLL_ONCE_DETAIL in страница.text

    token = _токен(client)
    first, second = _пара(secret, clock())
    ответ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(),
    )
    assert ответ.status_code == 503
    assert TWO_FACTOR_UNAVAILABLE_DETAIL in ответ.text
    row = store.active_enrollment(_пользователь(store).id)
    assert row is not None
    assert row.confirmed_at is None, "подтверждение прошло без файла ключей"
    assert _попытки(store, _пользователь(store).id, clock) == 0


# ─── §8.2 «QR + ручной ввод секрета»: картинка привязки (срез `R4d`) ─────────────────────────


def _картинка_из_ответа(text: str) -> tuple[int, str]:
    """Пара «сторона квадрата в модулях / строка путей» из разметки ответа.

    Разбор вынесен отдельно, потому что сравнение идёт с ожиданием, которое тест собирает сам:
    сверять «в странице есть картинка» бессмысленно — проверять нужно, какая именно.
    """
    рамка = re.search(r'<svg[^>]*viewBox="0 0 (\d+) (\d+)"', text)
    assert рамка, f"в ответе нет встроенной картинки привязки: {text[:400]}"
    assert рамка.group(1) == рамка.group(2), "холст QR не квадратный"
    путь = re.search(r'<path d="([^"]*)"', text)
    assert путь, f"в разметке нет пути QR: {text[:400]}"
    return int(рамка.group(1)), путь.group(1)


def _ожидание_картинки(secret: str) -> QrGraphic:
    """Картинка, собранная тестом из показанного секрета, а не из того, что вернул маршрут."""
    return qr_graphic(totp_provisioning_uri(secret, account_name=TEST_LOGIN, issuer=TOTP_ISSUER))


def test_qr_картинка_кодирует_тот_же_секрет_что_показывает_страница(client: TestClient) -> None:
    """§8.2: «QR + ручной ввод секрета» — картинка и ключ обязаны быть про одно и то же значение.

    Сравнение не «длина ненулевая», а строка путей с ожиданием, которое тест собирает сам: из
    показанного в `<code>` секрета, логина учётной записи и метки `issuer`. Так ловятся три
    дефекта, на глаз на странице неотличимые: картинка из другого секрета (например из прежней,
    только что отозванной привязки), картинка без метки или без параметров (`issuer`, `algorithm`,
    `digits`, `period`) — генератор привяжет не то, — и картинка, собранная повторным
    расшифровыванием `secret_enc`, то есть вторая точка вывода материала (`ADR-015` п. 6).
    """
    _войти(client)
    token = _токен(client)
    ответ = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())
    assert _статус(ответ) == 200, ответ.text
    ключи = SECRET_BLOCK.findall(ответ.text)
    assert len(ключи) == 1, "секрет показан не один раз"
    секрет = ключи[0]

    модули, путь = _картинка_из_ответа(ответ.text)
    ожидание = _ожидание_картинки(секрет)
    assert (
        путь == ожидание.path_d
    ), "QR кодирует не ту `otpauth://`-ссылку, которая следует из показанного ключа и логина"
    assert модули == ожидание.modules, "размер картинки не совпадает с ожиданием"
    assert ответ.text.count("<svg") == 1, "картинка выведена больше одного раза"

    # Повторная выдача меняет и ключ, и картинку: иначе «начать заново» вернуло бы прежний QR.
    второй = client.post(
        MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: _токен(client)}, headers=_headers()
    )
    другой = SECRET_BLOCK.findall(второй.text)[0]
    assert другой != секрет, "повторная выдача повторила секрет"
    модули2, путь2 = _картинка_из_ответа(второй.text)
    assert путь2 != путь, "картинка повторяется вместе с прежним секретом"
    assert модули2 == _ожидание_картинки(другой).modules


def test_ответы_без_картинки_не_несут_ни_её_ни_ссылку_ни_секрет(client: TestClient) -> None:
    """Ни `GET` страницы, ни другие состояния картинки не имеют (§8.2, `ADR-015` п. 6).

    Картинка — тот же секрет, только в форме, которую генератор считывает за секунду. Вывод на
    `GET` означал бы и повторный показ (§8.2: «в UI больше не показывается»), и повторное
    расшифровывание `secret_enc`. `otpauth://`-ссылка и встроенное изображение в разметке — тот
    же риск в другом виде: ссылку видно в адресной строке и в access-логе прокси.
    """
    _войти(client)
    начало = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert _статус(начало) == 200, начало.text
    assert "Начать" in начало.text, "без привязки страница не предложила её начать"
    assert "<svg" not in начало.text, "состояние `start` показало картинку"

    _token, секрет = _начать_привязку(client)

    страница = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert _статус(страница) == 200, страница.text
    assert ENROLL_ONCE_DETAIL in страница.text, "начатая привязка не объяснила путь «заново»"
    for marker in ("<svg", "<path d=", "otpauth", "data:", секрет):
        assert marker not in страница.text, f"`GET` привязки отдаёт {marker!r}"

    код = client.get(TOTP_CODE_PATH, headers=_headers(), follow_redirects=False)
    assert _статус(код) == 302, "неподтверждённая привязка не уводит на страницу привязки"


def test_в_разметке_привязки_нет_ни_нарушения_csp_ни_внешнего_источника(client: TestClient) -> None:
    """Картинка встроена геометрией: без `data:`, без `<img>` и без чужого адреса.

    Единственный способ показать `<img>` при CSP `img-src 'self'` (§8.3) — ослабить политику, а
    это решение заказчика, не оформителя (`tests/integration/test_compose_prod_contract.py`
    держит `img-src` ровно `'self'`). Второй способ — отдельный адрес с картинкой, и он же
    вторая точка вывода секрета. Проверка держит оба закрытыми, пока шаблон не переписали.
    """
    _войти(client)
    token = _токен(client)
    ответ = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())

    assert "<svg" in ответ.text, "картинки нет — проверять нечего"
    for forbidden in ("data:", "<img", "otpauth", "//", "http://", "https://"):
        assert forbidden not in ответ.text, f"в разметке привязки появился источник {forbidden!r}"
    assert 'fill="#000"' in ответ.text, "у картинки нет тёмного переднего плана"
    assert (
        'fill="#fff"' in ответ.text
    ), "у картинки нет светлого фона: QR без контрастного фона читают не все генераторы"


def test_без_картинки_страница_привязки_остаётся_рабочей(
    client: TestClient, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Отказ кодировщика не ломает привязку: §8.2 требует QR **и** ручной ввод, а не вместо.

    Проверка ровно про тот случай, который обычно и чинят неправильно: если картинка —
    обязательная часть ответа, отказ кодировщика превращается в `500` или в «привязка не
    началась». Здесь ответ остаётся `200`, ключ показан, отсутствие картинки объяснено в том же
    ответе, где картинка стояла бы, а привязка создана и активна: человек вводит ключ руками и
    продолжает. Дальше страница ведёт себя как обычно: повторного показа нет (§8.2), и объяснение
    не превращается в «секрет можно увидеть ещё раз».
    """

    def отказ(нагрузка: str) -> QrGraphic:
        raise QrBuildError(f"проверка: нагрузка {len(нагрузка)} знаков не помещается в QR")

    monkeypatch.setattr(totp_routes, "qr_graphic", отказ)
    _войти(client)
    token = _токен(client)
    ответ = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())

    assert _статус(ответ) == 200, "отказ кодировщика сломал выдачу привязки"
    ключи = SECRET_BLOCK.findall(ответ.text)
    assert len(ключи) == 1, "без картинки пропал и ручной ключ (§8.2)"
    секрет = ключи[0]
    assert (
        "не собрался" in ответ.text
    ), "отсутствующую картинку страница не объяснила: человек ищет QR, которого нет"
    assert "<svg" not in ответ.text, "без картинки в разметке остался блок картинки"
    assert "<path d=" not in ответ.text, "без картинки в разметке остался путь QR"

    страница = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert секрет not in страница.text, "страница повторила ключ вместе с отсутствующей картинкой"

    user_id = _пользователь(store).id
    assert store.active_enrollment(user_id) is not None, "отказ кодировщика отменил привязку"
    assert len(_привязки(store, user_id)) == 1


@pytest.fixture
def json_logs() -> Iterator[Callable[[], list[str]]]:
    """Логи процесса в буфер — тем же конвейером, что у боевого процесса (`packages/common/logging`).

    Приёмник подменяется буфером, а не `caplog`: форматирует и маскирует конвейер `structlog`, и
    «ушло ли в stdout» зависело бы от порядка плагинов pytest, а не от проверяемого.
    """
    stream = io.StringIO()
    configure_logging("DEBUG", json_output=True, stream=stream)

    def readout() -> list[str]:
        return [line for line in stream.getvalue().splitlines() if line.strip()]

    yield readout
    logging.getLogger().handlers.clear()
    structlog.reset_defaults()


def test_отказ_кодировщика_объясняется_в_логе_и_не_содержит_секрета(
    client: TestClient,
    json_logs: Callable[[], list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Строка `totp_qr_unavailable` в логе есть, а полезной нагрузки в ней нет (§8.4).

    Отказ обязан быть различим в разборе — иначе «QR не собирается» неотличимо от «QR не
    просили». При этом в логе не должно быть ни base32-ключа, ни `otpauth://`-ссылки целиком: в
    ссылке ключ лежит открытым текстом, а логи и access-лог прокси живут дольше страницы.
    """

    def отказ(нагрузка: str) -> QrGraphic:
        raise QrBuildError(f"проверка: нагрузка {len(нагрузка)} знаков не помещается в QR")

    monkeypatch.setattr(totp_routes, "qr_graphic", отказ)
    _войти(client)
    _token, секрет = _начать_привязку(client)

    строки = json_logs()
    assert строки, "отказ кодировщика не объяснён в логе процесса"
    захват = "\n".join(строки)
    assert "totp_qr_unavailable" in захват, "в логе нет ни строки об отказе, ни её причин"
    assert секрет not in захват, "base32-ключ привязки ушёл в лог"
    assert "otpauth" not in захват, "ссылка привязки ушла в лог"


def test_неудача_кода_не_оставляет_секрет_и_ссылку_в_логе(
    client: TestClient, json_logs: Callable[[], list[str]], clock: Clock
) -> None:
    """Лента неудач подтверждения пишет исход отказа, но не материал привязки.

    Проверка не повторяет предыдущую: здесь картинка собирается нормально, а в лог уходит
    отказная ветка `totp_confirm_rejected`. Смысл в том, что ни одна ветка ответа о привязке не
    имеет права печатать ключ или `otpauth://`-ссылку — в том числе та, где с QR всё получилось.
    """
    _войти(client)
    _token, секрет = _начать_привязку(client)
    token = _токен(client)
    неверный = _чужой_код(clock)
    ответ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: неверный, FIELD_SECOND_CODE: неверный},
        headers=_headers(),
    )
    assert _статус(ответ) == 401, ответ.text

    захват = "\n".join(json_logs())
    assert "totp_confirm_rejected" in захват, "отказ подтверждения не объяснён в логе процесса"
    assert секрет not in захват, "base32-ключ привязки ушёл в лог"
    assert "otpauth" not in захват, "ссылка привязки ушла в лог"
