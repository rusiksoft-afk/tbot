"""Порог уведомлений §8.7 в HTTP-слое: кто спрашивает, кто молчит, что видит администратор.

Файл проверяет путь «маршрут → решение порога → строка журнала решений → страница раздела», и
именно тот его слой, который офлайн-репозиторий в памяти воспроизводит честно: точки вызова в
`routes/login.py` и `routes/totp.py` (вход по паролю, полный вход кодом 2FA, вход расходом
резервного кода), порядок «ключ → состояние → решение → запись» (`ADR-026` п. 4) и то, что
страница `/admin/notifications` показывает ровно решения, не обещая доставки.

Граница честности — та же, что во всех офлайновых файлах входного среза (`web_support.py`).
Поэтому здесь нет и не может быть: частичного уникального индекса `ix_web_audit_outbox_dedup_key`
(в памяти «повтор» воспроизводится предикатом, а не отказом `23505`), поведения `ON CONFLICT DO
NOTHING RETURNING id` (в памяти это просто пропуск строки, и отличить его от «решение не
вынесено» нельзя), отказа внешнего ключа `fk_web_audit_outbox_audit_id_audit_log` с `23503`,
`CHECK` доменов и append-only прав роли приложения. Это держит живой файл
`tests/integration/test_audit_notify_db.py` (шаг CI-job'а `миграции`). Здесь проверяется
договорённость слоя: событие спрошено ровно один раз, `muted` записано строкой, страница не
выводит наружу материал стража повтора и не производит решений.

Время заморожено и переводимо (`Clock`, тот же приём, что у `test_web_totp_page.py`): код TOTP
живёт 30 секунд, а окно порога — 300 секунд. Тест, который считает код по реальному «сейчас»,
проходил бы только при удачной секунде запуска, а проверка окна порога на реальных часах
зависела бы от скорости машины.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.login as login_routes
import apps.web.routes.sessions as session_routes
import apps.web.routes.totp as totp_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.routes.notifications import (
    ADMIN_NOTIFICATIONS_PATH,
    CHANNEL_NOTE,
    EMPTY_NOTE,
)
from apps.web.routes.totp import (
    FIELD_BACKUP_CODE,
    FIELD_CODE,
    FIELD_FIRST_CODE,
    FIELD_SECOND_CODE,
)
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.sessions import (
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    MFA_RECOVERY_PATH,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.identity.backup_codes import BACKUP_CODE_COUNT
from packages.identity.notify import (
    AUDIT_NOTIFY_LOGIN_COOLDOWN_S,
    GROUND_BACKUP_CODE_SPENT,
    GROUND_LOGIN,
    REASON_BACKUP_CODE_SPENT,
    REASON_KNOWN_PAIR,
    REASON_LOGIN_COOLDOWN,
    REASON_NEW_PAIR,
    login_pair,
)
from packages.identity.totp import TOTP_PERIOD_SECONDS, totp_code
from packages.storage.audit_store import NotifyDecisionRow
from packages.storage.models import User, UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
    set_kek_file,
)

#: Момент, от которого живёт файл (тот же приём, что у `test_web_totp_page.py`).
FROZEN: Final = datetime(2026, 11, 24, 9, 0, tzinfo=UTC).replace(microsecond=0)

#: Адреса из резервных диапазонов RFC 5737. Каждой церемонии — свой адрес там, где это не мешает
#: проверяемому: окно порога (§8.7) считается по учётной записи, а лимиты частоты §8.3 — по
#: адресу, и несколько попыток с одного адреса уперлись бы в `429` раньше, чем наступило бы
#: решение порога.
ADDRESSES: Final = tuple(f"203.0.113.{index}" for index in range(21, 40))

#: Значения `User-Agent`: материал второй половинки ключа сочетания. Разные значения — это
#: «другое устройство» в смысле §8.7, и различие обязано читаться из отпечатков в `details`.
DEVICE_A: Final = "notify-test-device-alpha"
DEVICE_B: Final = "notify-test-device-beta"

META_TOKEN: Final = re.compile(r'name="csrf-token" content="([^"]+)"')
SECRET_BLOCK: Final = re.compile(r"<code>([A-Z2-7]{16,128})</code>")
ISSUED_BLOCK: Final = re.compile(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>")


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

    Момент решения попадает в строку `web_audit_outbox.at`, а по нему считается окно порога:
    если часть модулей живёт в замороженном времени, а часть — в реальном, «прошло меньше окна»
    и «прошло больше окна» становятся зависимыми от скорости машины.
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
    """Учётная запись роли `admin` с заполненным `id`.

    Роль — `admin`, а не дефолтный `operator`: раздел `/admin/notifications` (§9.3 п. 6–10)
    охраняется ролью, и проверке нужен допущенный сеанс, иначе страница была бы недоступна
    всему файлу. Матрица «роль × маршрут» для этого адреса стоит отдельной строкой в
    `tests/integration/test_web_role_matrix.py`, и подменять её здесь нечем.

    `id` ставится явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не срабатывает, а
    `web_audit_outbox.user_id` и предикаты репозитория сравнивают именно `id`. С `None` ссылки
    сравнивались бы `None` с `None` и проходили бы молча.
    """
    memory = MemoryStore()
    owner = memory.seed_user(role="admin")
    owner.id = uuid.uuid4()
    return memory


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей в песочнице: тот же формат, что пишет `deploy/vps/keys_setup.py` (`ADR-014` п. 5).

    Без KEK привязка 2FA недоступна (`503`), а без привязки полный вход невозможен — то есть
    повод §8.7 не наступил бы вовсе.
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
    # `0600` — чтобы боевая проверка прав файла ключей не отказала песочнице на Linux (на Windows
    # битов POSIX нет, и дефект был бы невиден локально; его ловил прогон на Linux).
    path.chmod(0o600)
    return path


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock, kek: Path) -> Iterator[TestClient]:
    assert clock() == FROZEN, "фикстура сдвинула время, а тест ждёт `FROZEN`"
    with build_client(store, settings) as test_client:
        set_kek_file(test_client, kek)
        yield test_client


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _headers(*, address: str, device: str = DEVICE_A) -> dict[str, str]:
    """Заголовки запроса: адрес через `X-Forwarded-For` (как ставит Caddy) и устройство.

    `Origin` обязателен: браузер шлёт его на мутациях всегда, а без него второй слой CSRF (§8.3)
    просто выключается — и тест шёл бы не тем путём, которым идёт площадка.
    """
    return {"Origin": "https://testserver", "User-Agent": device, "X-Forwarded-For": address}


def _статус(response: Response) -> int:
    status: int = response.status_code
    return status


def _токен(client: TestClient) -> str:
    """CSRF-токен из страницы привязки (она отдаёт `200` на шагах `'password'` и `'totp'`)."""
    response = client.get(MFA_ENROLL_PATH, headers=_headers(address=ADDRESSES[0]))
    assert _статус(response) == 200, response.text
    match = META_TOKEN.search(response.text)
    assert match, f"в странице нет meta токена: {response.text[:300]}"
    return match.group(1)


def _привязать(
    client: TestClient, clock: Clock, *, address: str, device: str = DEVICE_A
) -> tuple[str, tuple[str, ...]]:
    """Вход паролем + первичная привязка: выдать секрет, подтвердить парой кодов, вернуть пачку.

    Вход паролем стоит здесь намеренно: страница привязки существует только при живом сеансе
    (§8.3), и без неё `GET /mfa-enroll` редиректит на `/login` с пустым CSRF-токеном. Пачка
    резервных кода возвращается, потому что показывается ровно один раз — в этом ответе
    (`ADR-016` п. 2 и п. 11), и другого способа её получить у теста нет.

    После подтверждения сеанс стоит на шаге `'totp'` — оттуда его завершает `_вход_кодом`.
    """
    _войти_паролем(client, address=address, device=device)
    token = _токен(client)
    response = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: token},
        headers=_headers(address=address, device=device),
    )
    assert _статус(response) == 200, response.text
    match = SECRET_BLOCK.search(response.text)
    assert match, f"мутация не показала секрет: {response.text[:400]}"
    secret = match.group(1)

    token = _токен(client)
    first = totp_code(secret, clock())
    second = totp_code(secret, clock() + timedelta(seconds=TOTP_PERIOD_SECONDS))
    response = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(address=address, device=device),
        follow_redirects=False,
    )
    assert _статус(response) == 200, response.text
    shown = tuple(ISSUED_BLOCK.findall(response.text))
    assert len(shown) == BACKUP_CODE_COUNT, "привязка не выпустила пачку резервных кодов целиком"
    return secret, shown


def _войти_паролем(client: TestClient, *, address: str, device: str = DEVICE_A) -> None:
    """Первая половина входа (§8.2 шаг (1)): пароль принят, сеанс остался на шаге `'password'`."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers=_headers(address=address, device=device),
        follow_redirects=False,
    )
    assert _статус(response) == 302, response.text
    assert session_cookie(client), "после входа куки нет"


def _вход_кодом(
    client: TestClient,
    clock: Clock,
    secret: str,
    *,
    address: str,
    device: str = DEVICE_A,
) -> None:
    """Завершить текущий сеанс кодом 2FA из текущего окна: шаг становится `'full'`.

    Отдельная функция, а не часть `_полный_вход`: первый полный вход после привязки продолжает
    тот же сеанс (сеанс после подтверждения стоит на шаге `'totp'`), а последующие входы начинаются
    с пароля. Два этих пути различаются для проверки: повод §8.7 обязан спросить один раз и там,
    и там.
    """
    token = _токен(client)
    response = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=address, device=device),
        follow_redirects=False,
    )
    assert _статус(response) in (200, 302), response.text[:400]


def _полный_вход(
    client: TestClient,
    clock: Clock,
    secret: str,
    *,
    address: str,
    device: str = DEVICE_A,
) -> None:
    """Церемония входа целиком: пароль + код 2FA. Шаг сеанса — `'full'`."""
    _войти_паролем(client, address=address, device=device)
    _вход_кодом(client, clock, secret, address=address, device=device)


def _вход_резервным_кодом(
    client: TestClient, code: str, *, address: str, device: str = DEVICE_A
) -> None:
    """Вход расходом резервного кода (§8.2, `ADR-016` п. 9): это тоже полный вход."""
    _войти_паролем(client, address=address, device=device)
    token = _токен(client)
    response = client.post(
        MFA_RECOVERY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_BACKUP_CODE: code},
        headers=_headers(address=address, device=device),
        follow_redirects=False,
    )
    assert _статус(response) == 200, response.text[:400]


def _решения(store: MemoryStore) -> tuple[NotifyDecisionRow, ...]:
    """Все решения порога в порядке от свежих к старым — тот же путь чтения, что у страницы."""
    return store.notify_decisions(limit=100)


def _по_основанию(store: MemoryStore, ground: str) -> tuple[NotifyDecisionRow, ...]:
    return tuple(row for row in _решения(store) if row.ground == ground)


def _сеанс(client: TestClient, store: MemoryStore) -> UserSession:
    record = store.find_by_secret(session_cookie(client))
    assert record is not None, "сеанс не найден — вход не состоялся"
    return record


def _учётка(store: MemoryStore) -> User:
    account = store.user_by_login(TEST_LOGIN)
    assert account is not None, "тестовой учётной записи нет в репозитории"
    assert account.id is not None, "у учётной записи нет идентификатора"
    return account


# ─── точки вопроса: у кого повод, а у кого нет (§8.7, `ADR-025` п. 6) ─────────────────────────


def test_вход_по_паролю_без_второго_фактора_повода_не_пишет(
    client: TestClient, store: MemoryStore
) -> None:
    """Пароль принят — события §8.7 ещё нет, и решения нет.

    Строка `session.login` с шагом `'password'` существует: её пишет маршрут (§8.4), иначе
    «кто пытался войти» нечем было бы восстановить. Поводом уведомления она не является, потому
    что второй фактор ещё не пройден (`ADR-015` п. 3): иначе на каждый вход с 2FA было бы по два
    вопроса, и счётчик поводов §8.7 удваивался бы молча.

    Проверка держит ровно этот разрыв: событие в журнале есть, решения в таблице решений нет.
    """
    _войти_паролем(client, address=ADDRESSES[1])

    password_rows = [row for row in store.audit_rows if row.action == "session.login"]
    assert password_rows, "вход паролем не записал событие журнала"
    assert all(
        (row.details or {}).get("auth_step") == "password" for row in password_rows
    ), f"в журнале появился шаг не 'password': {[r.details for r in password_rows]}"
    assert _решения(store) == (), (
        "порог спрошен на шаге 'password': решений должно быть ноль "
        f"(найдено: {[(r.ground, r.outcome, r.reason) for r in _решения(store)]})"
    )


def test_первый_полный_вход_пишет_одно_решение_уведомить(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Полный вход с незнакомого сочетания: ровно одно `notify` + `new_pair`, со ссылкой на журнал.

    «Ровно одно» — важная часть проверки: у входа две строки `session.login` (шаг пароля и шаг
    `full`), и точка вопроса обязана стоять на второй. Удвоение повода §8.7 выглядело бы как
    «защита бдительнее, чем надо», а на площадке с двумя администраторами означало бы удвоенный
    поток (§10.1).

    `audit_id` обязан указывать на строку входа, а не на любую строку журнала: ссылка — то, за
    чем администратор пойдёт разбирать адрес и субъекта (`ADR-028` п. 2). В памяти идентификаторы
    выдаются по порядку вставки — тот же порядок, что у `IDENTITY`/последовательности базы;
    настоящий отказ внешнего ключа держит живая проверка.
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[2])
    # Окно кода сдвигается обязательно: оба кода подтверждения привязки уже отмечены использованными
    # (§8.2 «2 последовательных кода»), и код того же окна вход отклонил бы как повтор — проверка
    # не дошла бы до порога.
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[2])

    rows = _по_основанию(store, GROUND_LOGIN)
    assert (
        len(rows) == 1
    ), f"ожидалось одно решение, найдено: {[(r.outcome, r.reason) for r in rows]}"
    row = rows[0]
    assert (row.outcome, row.reason) == ("notify", REASON_NEW_PAIR)
    assert row.user_id == _учётка(store).id, "решение отнесено не на ту учётную запись"
    assert row.login == TEST_LOGIN, "страница раздела показала бы не тот логин"

    login_ids = [
        index
        for index, audit in enumerate(store.audit_rows, start=1)
        if audit.action == "session.login" and (audit.details or {}).get("auth_step") == "full"
    ]
    assert len(login_ids) == 1, f"полных входов в журнале не один: {login_ids}"
    assert (
        row.audit_id == login_ids[0]
    ), f"ссылка ведёт не на строку полного входа: {row.audit_id} против {login_ids[0]}"


# ─── порог: окно, известное сочетание, новое сочетание (§8.7, `ADR-028` п. 6) ─────────────────


def test_то_же_сочетание_внутри_окна_молчит_строкой(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Второй вход тем же сочетанием внутри окна: `muted` + `login_cooldown`, и это записано.

    `muted` обязано быть строкой, а не отсутствием строки (`ADR-028` п. 4): иначе «порог
    промолчал» неотличимо от «события не было», а именно это различие нужно администратору при
    разборе. Число `notify`-строк при этом остаётся единицей — страж повтора сработал на уровне
    решения, до базы (на базе его держит частичный уникальный индекс, живая проверка).
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[3])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[3])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _полный_вход(client, clock, secret, address=ADDRESSES[3])

    rows = _по_основанию(store, GROUND_LOGIN)
    assert (
        len(rows) == 2
    ), f"ожидалось два решения, найдено: {[(r.outcome, r.reason) for r in rows]}"
    свежее, первое = rows[0], rows[1]
    assert (первое.outcome, первое.reason) == ("notify", REASON_NEW_PAIR)
    assert (свежее.outcome, свежее.reason) == ("muted", REASON_LOGIN_COOLDOWN)
    assert (
        (свежее.at - первое.at).total_seconds() < AUDIT_NOTIFY_LOGIN_COOLDOWN_S
    ), "молчание объявлено кулдауном вне окна: значение окна разошлось с проверкой"
    assert (
        sum(1 for row in rows if row.outcome == "notify") == 1
    ), "повторное уведомление всё-таки заведено: страж повтора не сработал"


def test_окно_считается_по_учётной_записи_а_не_по_сочетанию(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Новое сочетание внутри окна тоже молчит: окно держит шум, а не пару.

    У мобильного клиента адрес меняется на каждую выдачу провайдера, и каждое такое значение —
    «новое сочетание». Если бы окно применялось только к уже известному сочетанию, порог шумел бы
    ровно там, для чего написан (§10.1 требует агрегации при массовых событиях), а §8.3 от этого
    не защищает: входы успешны, лента неудач молчит.

    Вторая половина проверки обязана быть достижимой: через окно после первого уведомления новое
    сочетание снова получает `notify`, иначе молчание навсегда прикрепилось бы к учётной записи.
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[4])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[4])

    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _полный_вход(client, clock, secret, address=ADDRESSES[5], device=DEVICE_B)
    rows = _по_основанию(store, GROUND_LOGIN)
    assert (
        len(rows) == 2
    ), f"ожидалось два решения, найдено: {[(r.outcome, r.reason) for r in rows]}"
    assert (rows[0].outcome, rows[0].reason) == ("muted", REASON_LOGIN_COOLDOWN), (
        "новое сочетание внутри окна дало уведомление: окно применяется только к известному "
        "сочетанию, и порог шумит при сменах адреса"
    )

    clock.advance(seconds=AUDIT_NOTIFY_LOGIN_COOLDOWN_S + TOTP_PERIOD_SECONDS * 2)
    _полный_вход(client, clock, secret, address=ADDRESSES[6], device=DEVICE_A)
    rows = _по_основанию(store, GROUND_LOGIN)
    assert (
        len(rows) == 3
    ), f"ожидалось три решения, найдено: {[(r.outcome, r.reason) for r in rows]}"
    assert (rows[0].outcome, rows[0].reason) == ("notify", REASON_NEW_PAIR), (
        "за окном новое сочетание не получило уведомления: окно приклеилось к учётной записи "
        "навсегда и §8.7 перестал выполняться"
    )


def test_известное_сочетание_за_окном_молчит_причиной_known_pair(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """За окном то же сочетание молчит по другой причине — и различие читается из кода.

    Обе половины порога дают `muted`, и различать их обязан код причины: «уже уведомляли об этом
    сочетании» и «не уведомляем чаще окна» — это разные ответы на вопрос §8.7, и разбор по
    таблице обязан отличать одно от другого. Без этого пункта порог выглядел бы как одна
    запретительная настройка, а не как правило «новое сочетание → уведомить».
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[7])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[7])
    clock.advance(seconds=AUDIT_NOTIFY_LOGIN_COOLDOWN_S + TOTP_PERIOD_SECONDS * 2)
    _полный_вход(client, clock, secret, address=ADDRESSES[7])

    rows = _по_основанию(store, GROUND_LOGIN)
    assert (
        len(rows) == 2
    ), f"ожидалось два решения, найдено: {[(r.outcome, r.reason) for r in rows]}"
    assert (rows[0].outcome, rows[0].reason) == ("muted", REASON_KNOWN_PAIR), (
        "известное сочетание за окном дало новое уведомление: ключ сочетания не опознан, и "
        "каждый вход с того же адреса уведомлял бы заново"
    )
    assert rows[0].audit_id != rows[1].audit_id, (
        "оба решения сослались на одну строку журнала: ссылки должны вести на события, а не на "
        "первое попавшееся"
    )


# ─── второй повод с производителем: расход резервного кода (§8.7) ────────────────────────────


def test_расход_резервного_кода_пишет_своё_основание_один_раз(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Вход расходом кода даёт повод `backup_code.spent` + `notify`, без порога и без дубля.

    Порога на этот повод нет сознательно (§8.7 называет его отдельно, `ADR-028` п. 6): код тратят,
    когда обычный второй фактор недоступен, и это ровно тот момент, когда администратор обязан
    узнать о входе. При этом строка одна: повторная попытка зафиксировать тот же расход не
    создаёт второго уведомления (в памяти — предикт по ключу, на площадке — частичный уникальный
    индекс; различие держит живая проверка).

    Отдельно проверяется, что событие журнала и повод — разные имена: `backup_code.spent` пишется
    и в журнал (§8.4), и как основание решения, а полный вход по коду даёт ещё и повод входа.
    """
    _secret, shown = _привязать(client, clock, address=ADDRESSES[8])
    clock.advance(seconds=AUDIT_NOTIFY_LOGIN_COOLDOWN_S + TOTP_PERIOD_SECONDS * 2)
    _вход_резервным_кодом(client, shown[0], address=ADDRESSES[8])

    spend_rows = _по_основанию(store, GROUND_BACKUP_CODE_SPENT)
    assert len(spend_rows) == 1, (
        f"ожидалось одно решение о расходе кода, найдено: "
        f"{[(r.outcome, r.reason) for r in spend_rows]}"
    )
    row = spend_rows[0]
    assert (row.outcome, row.reason) == (
        "notify",
        REASON_BACKUP_CODE_SPENT,
    ), "у расхода кода появился порог или вердикт не 'notify': повод спрятан"
    assert row.login == TEST_LOGIN

    spend_events = [audit for audit in store.audit_rows if audit.action == "backup_code.spent"]
    assert len(spend_events) == 1, (
        f"событий расхода кода в журнале не одно: {len(spend_events)} — повод и событие должны "
        "оставаться разными именами в одном количестве"
    )
    assert row.audit_id is not None, "ссылки на строку расхода нет: разбирать нечем"
    assert (
        row.audit_id > 0
    ), f"ссылка на строку журнала имеет недопустимый идентификатор {row.audit_id}"

    login_rows = _по_основанию(store, GROUND_LOGIN)
    assert login_rows, "вход расходом кода не поднят до полного: повод входа не спрошен"
    assert all(r.outcome in ("notify", "muted") for r in login_rows)


# ─── раздел администратора: что видно и чего видно быть не должно (§9.3 п. 6–10) ──────────────


def test_раздел_показывает_решения_и_не_обещает_доставку(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Страница перечисляет решения и прямо говорит, что канал не заведён.

    Это и есть исполненная половина §8.7 по решению заказчика (ask
    `128ac2e2-877d-45ec-8e6d-d8b63cab8f53`, `outbox_admin_read`): пока `tgbot` не поднят (`T-714`),
    исполненным считается зафиксированное и перечитываемое решение порога. Надпись «отправлено»
    или «доставлено» была бы неправдой, а неправда в разделе безопасности хуже отсутствия
    раздела: по ней судят о том, что администратор уже узнал.
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[9])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[9])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _полный_вход(client, clock, secret, address=ADDRESSES[9])

    response = client.get(ADMIN_NOTIFICATIONS_PATH, headers=_headers(address=ADDRESSES[9]))
    assert _статус(response) == 200, response.text[:400]
    page = response.text

    assert CHANNEL_NOTE in page, "постоянная шапка о ненастроенном канале пропала со страницы"
    assert "не отправляет" in page, "страница перестала говорить, что ничего не отправляет"
    for запрещённое in ("отправлено", "доставлено", "уведомление отправлено", "sent"):
        assert запрещённое not in page, f"страница обещает доставку: {запрещённое!r}"

    rows = _решения(store)
    assert len(rows) == 2, f"в репозитории два решения, страница обязана показать оба: {rows}"
    for row in rows:
        assert row.ground in page, f"основание {row.ground} не показано в таблице"
        assert row.reason in page, f"причина {row.reason} не показана в таблице"
    assert "уведомить" in page, "вердикт `notify` не подписан"
    assert "промолчать" in page, "вердикт `muted` не подписан: строка молчания читается как сбой"
    assert TEST_LOGIN in page, "учётная запись повода не показана"


def test_раздел_не_выводит_ключ_и_отпечатки_и_не_производит_решений(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Страница читает: ни материала стража повтора, ни новых строк от самого просмотра.

    `details` и `dedup_key` наружу не выводятся (§8.4): `details` — произвольный `jsonb`,
    вторая поверхность утечки после журнала, а `dedup_key` — материал стража, а не сведения для
    администратора. Отпечатки половинок сочетания — часть `details`, и они в ответе тоже не
    должны появляться: иначе страница стала бы вторым носителем адреса и `User-Agent`, что
    противоречит `ADR-025` п. 2 при публичном репозитории (`ADR-019`).

    Второе утверждение — про «только чтение»: три `GET` не добавляют ни строки решений, ни
    строки журнала, а `POST` на адрес раздела отсутствует (`405`). Страница, которая умеет
    отправлять или переспрашивать, превратила бы просмотр в действие и обошла бы лимиты §10.1.
    """
    secret, _shown = _привязать(client, clock, address=ADDRESSES[10])
    clock.advance(seconds=TOTP_PERIOD_SECONDS * 2)
    _вход_кодом(client, clock, secret, address=ADDRESSES[10], device=DEVICE_A)

    pair = login_pair(user_id=_учётка(store).id, address=ADDRESSES[10], user_agent=DEVICE_A)
    до = (_решения(store), len(store.audit_rows))

    for _ in range(3):
        response = client.get(ADMIN_NOTIFICATIONS_PATH, headers=_headers(address=ADDRESSES[10]))
        assert _статус(response) == 200, response.text[:400]
        page = response.text
        assert pair.dedup_key not in page, "ключ деидентификации показан на странице"
        assert pair.address_fp not in page, "отпечаток адреса показан на странице"
        assert pair.device_fp not in page, "отпечаток устройства показан на странице"
        assert ADDRESSES[10] not in page, "адрес показан на странице раздела"
        assert DEVICE_A not in page, "значение User-Agent показано на странице раздела"
        assert "details" not in page, "страница ссылается на details как на отображаемые данные"

    not_allowed: int = client.post(
        ADMIN_NOTIFICATIONS_PATH,
        data={},
        headers=_headers(address=ADDRESSES[11]),
    ).status_code
    assert not_allowed == 405, f"у раздела есть мутация: POST вернул {not_allowed}"

    assert (
        _решения(store),
        len(store.audit_rows),
    ) == до, "просмотр раздела произвёл строки: страница обязана оставаться читающей"


def test_пустой_раздел_объясняет_пустоту(client: TestClient, store: MemoryStore) -> None:
    """Пустая таблица — состояние, и страница называет его причинами.

    Пустой раздел без объяснения читается как «защита не работает». Объяснение обязано назвать
    именно те поводы, у которых есть производитель (вход с новым сочетанием и расход резервного
    кода): основания `risk.*` и `token.revoked` производителя не имеют (`ADR-028` п. 3), и
    упоминать их как «ещё не случилось» значило бы обещать то, чего не завели.

    Сеанс поднят до `'full'` без церемонии 2FA намеренно: иначе сам вход создал бы повод, и
    пустоту было бы нечем проверить (тот же приём, что у `_поднять_до_full` в
    `tests/integration/test_web_role_matrix.py`).
    """
    _войти_паролем(client, address=ADDRESSES[12])
    record = _сеанс(client, store)
    assert record.auth_step == "password", "вход паролем обязан оставить сеанс на шаге пароля"
    record.auth_step = "full"

    assert _решения(store) == (), "решения появились без повода: точка вопроса стоит не там"
    response = client.get(ADMIN_NOTIFICATIONS_PATH, headers=_headers(address=ADDRESSES[12]))
    assert _статус(response) == 200, response.text[:400]
    assert EMPTY_NOTE in response.text, "пустота раздела не объяснена"
    assert GROUND_BACKUP_CODE_SPENT not in response.text, (
        "пустота объяснена поводом, которого не было: список причин обязан называть поводы, "
        "а не основание из будущего среза"
    )
