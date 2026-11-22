"""Резервные коды входа: поведение HTTP-слоя (TZ §8.2, §8.8, §9.3 п. 2–3; `T-104`, срез `R5c`).

Файл проверяет переход целиком: выдачу пачки в ответе подтверждения привязки, единственный показ
значений, расход кода как шаг полной аутентификации, предупреждение §8.2 и семидневный срок. Имя
обязательной проверки взято из `tasks/todo.md` — `test_backup_code_flow`; что именно она обязана
покрыть, записано в докстринге `tests/unit/test_backup_codes.py`: «пачка показана один раз,
предупреждение после расхода, отказ на шаге `password`».

Граница честности — та же, что во всех офлайновых файлах входного среза (`web_support.py`):
репозиторий в памяти воспроизводит предикаты слоя доступа, но не базу. Поэтому здесь нет и не может
быть: атомарности guarded-`UPDATE` расхода (два «параллельных» входа в одном тесте физически не
приходят), наличия `used_at IS NULL` в тексте SQL, частичного уникального индекса
`ix_backup_codes_user_id_unused`, `CHECK ck_backup_codes_code_hash_sha256`, уникального индекса
`uq_backup_codes_user_id_code_hash`, того, что `created_at` и `used_at` приходят из `now()` базы, и
неутечки значений в текст запроса. Всё это держит живой файл
`tests/integration/test_backup_codes_db.py` (CI job `миграции`), включая обязательную
`test_backup_code_single_use`. Здесь проверяется договорённость слоя: «показан один раз», «шаг
поднят», «отказ не различает чужой / потраченный / несуществующий», «формат отличается от
отсутствия», «неудачи считаются в одной ленте», «срок держит вход по 2FA, но не путь кода».

Время заморожено так же, как в `test_web_totp_page.py`, и по той же причине: коды TOTP живут по 30
секунд, и проверка, вычисляющая код сама, обязана считать его по тому же моменту, что и слой
приложения. Границы семидневного срока задаются не глобальным сдвигом часов, а правкой дат у строк:
сдвиг «на восемь дней» убил бы и сеанс, и проверка проверяла бы просрочку сеанса (тот же приём, что
у `PENDING_ENROLLMENT_TTL` в `R4c`).

Проверок `audit_log` нет намеренно: имена событий выпуска, расхода и блокировок относятся к `T-109`
(перенос зафиксирован `ADR-009`). Компенсирующие контроля — строки `backup_codes` (включая `used_at`
как единственный носитель начала срока), лента `totp_failures`, `users.locked_until`, окна
`rate_buckets` — проверяются здесь же. Алерта администратору о расходе (§8.2 «+ алерт
администратору») тоже нет: доставка уведомлений — `T-716`, в этом срезе остаётся событие журнала
`backup_code_spent`, здесь оно проверяется как факт журнала, а не как доставка.
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

import pytest
import structlog
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.login as login_routes
import apps.web.routes.sessions as session_routes
import apps.web.routes.totp as totp_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.routes.totp import (
    EMPTY_BACKUP_CODE_DETAIL,
    FIELD_BACKUP_CODE,
    FIELD_CODE,
    FIELD_FIRST_CODE,
    FIELD_SECOND_CODE,
    GRACE_EXPIRED_DETAIL,
    NO_SPARE_CODE_DETAIL,
    RECOVERY_FAILURE_DETAIL,
    RECOVERY_FORMAT_DETAIL,
)
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.rate_limit import (
    IP_BAN_SCOPE,
    MUTATION_USER_SCOPE,
    TOTP_IP_SCOPE,
    TOTP_SESSION_SCOPE,
)
from apps.web.security.sessions import (
    CONSOLE_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    MFA_RECOVERY_PATH,
    POST_CODE_REDIRECT,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.common.logging import configure_logging
from packages.identity.backup_codes import (
    BACKUP_CODE_COUNT,
    RECOVERY_REGENERATION_WINDOW,
    hash_backup_code,
    is_sha256_hex,
    new_backup_codes,
    normalize_backup_code,
)
from packages.identity.totp import (
    TOTP_FAILURE_HORIZON,
    TOTP_MAX_FAILED_CODES,
    TOTP_PERIOD_SECONDS,
    totp_code,
)
from packages.storage.models import BackupCode, User, UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    MemoryStore,
    build_client,
    login,
    session_cookie,
    set_kek_file,
)

#: Момент, от которого живёт файл (тот же приём, что у `test_web_totp_page.py`).
FROZEN = datetime.now(UTC).replace(microsecond=0)

#: Адреса из резервных диапазонов RFC 5737. В этом файле адрес обязан различаться у разных попыток
#: там, где проверяется лента неудач: §8.3 даёт на адрес 5 запросов кода в минуту, и пять попыток с
#: одного адреса закончились бы `429` по частоте раньше, чем наступила бы блокировка учётной записи
#: по §8.2, — проверка проверяла бы не то.
ADDRESSES: Final = tuple(f"203.0.113.{host}" for host in range(11, 40))

#: Показная форма выпущенного значения (`ABCDE-FGHJK`). Разделители в канон не входят (`ADR-016`
#: п. 4), поэтому смысл проверки — «пачка показана целиком, значения настоящие», а не «выпал именно
#: дефис»: алфавит без `I`, `L`, `O`, `0`, `1` здесь намеренно упрощён до `[A-Z2-9]`.
SHOWN_CODE: Final = re.compile(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>")

#: Секрет привязки в разметке (тот же шаблон, что у `test_web_totp_page.py`).
SECRET_BLOCK: Final = re.compile(r"<code>([A-Z2-7]{16,128})</code>")

META_TOKEN: Final = re.compile(r'name="csrf-token" content="([^"]+)"')

#: Области счётчика частоты, которые имеет право трогать церемония входа. Проверка держит закрытый
#: перечень: новой области под резервный код заведено не было (`ADR-016` п. 8).
CODE_AREAS: Final = frozenset(
    {TOTP_SESSION_SCOPE, TOTP_IP_SCOPE, MUTATION_USER_SCOPE, IP_BAN_SCOPE}
)

#: Насколько «назад» сдвигается выпуск пачки в памяти (см. `_привязать`).
ISSUED_LAG: Final = timedelta(hours=1)


class Clock:
    """Задаваемое «сейчас» для слоя входа."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: float = 0.0, days: float = 0.0) -> None:
        self.now += timedelta(seconds=seconds, days=days)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях слоя, где его вызывают напрямую.

    Набор модулей совпадает с `test_web_totp_page.py`: пропуск любого из них означал бы, что часть
    проверок живёт в реальном времени, а часть — в замороженном. Доменные модули
    `packages/identity/*` не подменяются: момент им передаёт слой входа параметром.
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
    # `id` заполняется явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не срабатывает, а
    # строки `backup_codes`, привязки и ленты неудач хранят `user_id`. С `None` проверки изоляции
    # (§8.8) сравнивали бы `None` с `None` и проходили бы молча.
    owner.id = uuid.uuid4()
    return memory


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей в песочнице: тот же формат, что пишет `deploy/vps/keys_setup.py`.

    Привязка без файла ключей не состоялась бы, а привязка здесь нужна: пачка резервных кодов
    выпускается только в ответе подтверждения привязки (`ADR-016` п. 2).
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
    # `0600` — как в `R4c`: на Linux маска из `umask` (0644) не прошла бы политику файла ключей
    # (`ADR-014` п. 5), и страница привязки ответила бы `503` вместо привязки.
    path.chmod(0o600)
    return path


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock, kek: Path) -> Iterator[TestClient]:
    assert clock() == FROZEN, "фикстура сдвинула время, а тест ждёт `FROZEN`"
    # Щуп `/probe-full` нужен матрице шага: §8.8 требует, чтобы незавершённый вход не открывал ни
    # один маршрут, кроме страницы кода, и чтобы страница резервного кода не стала дырой в правиле.
    with build_client(store, settings, with_probe=True) as test_client:
        set_kek_file(test_client, kek)
        yield test_client


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


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _headers(*, address: str = ADDRESSES[0]) -> dict[str, str]:
    return {
        "Origin": "https://testserver",
        "User-Agent": "backup-codes-test",
        "X-Forwarded-For": address,
    }


def _токен(client: TestClient) -> str:
    """CSRF-токен со страницы привязки: она отдаёт `200` на обоих шагах церемонии входа."""
    response = client.get(MFA_ENROLL_PATH, headers=_headers())
    assert response.status_code == 200, response.text
    match = META_TOKEN.search(response.text)
    assert match, f"в странице нет meta токена: {response.text[:300]}"
    return match.group(1)


def _владельец(store: MemoryStore) -> User:
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None, "тестовой учётной записи нет в репозитории"
    assert user.id is not None, "тестовая учётная запись без `id`"
    return user


def _id_владельца(store: MemoryStore) -> uuid.UUID:
    return _владельец(store).id


def _привязать(client: TestClient, store: MemoryStore, clock: Clock) -> tuple[str, tuple[str, ...]]:
    """Полная привязка: выдать секрет, подтвердить парой; вернуть (секрет, показанные коды).

    Возвращает и секрет, и показную форму пачки: секрет нужен для кодов входа, а расходуется ровно
    то значение, которое увидел человек — проверка канона ввода идёт по показной форме, а не по
    сгенерированному значению без разделителей.

    Дата выпуска пачки сдвигается на час назад намеренно. В памяти и `created_at`, и `used_at`
    берут из часов процесса, и они могут совпасть до микросекунды, а `recovery_state` трактует пару
    дат как «выпущено до расхода» / «выпущено после расхода» (`ADR-016` п. 6 и п. 11): на боевом
    пути `created_at` — `now()` базы из момента вставки, он заведомо предшествует расходу. Ровно эта
    пара и проверяется ниже (предупреждение о перевыпуске, семидневный срок), поэтому ничья по
    микросекундам здесь — не абстракция, а проверка, которая время от времени краснела бы.
    """
    token = _токен(client)
    response = client.post(MFA_ENROLL_START_PATH, data={CSRF_FORM_FIELD: token}, headers=_headers())
    assert response.status_code == 200, response.text
    match = SECRET_BLOCK.search(response.text)
    assert match, f"мутация не показала секрет: {response.text[:400]}"
    secret = match.group(1)

    момент = clock()
    first = totp_code(secret, момент)
    second = totp_code(secret, момент + timedelta(seconds=30))
    token = _токен(client)
    ответ = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        headers=_headers(),
        follow_redirects=False,
    )
    assert ответ.status_code == 200, ответ.text
    codes = tuple(SHOWN_CODE.findall(ответ.text))
    assert len(codes) == BACKUP_CODE_COUNT, f"пачка показана не целиком: {ответ.text[:600]}"

    for row in store.backup_code_rows(_id_владельца(store)):
        row.created_at = datetime.now(UTC) - ISSUED_LAG
    return secret, codes


def _расход(client: TestClient, code: str, *, address: str = ADDRESSES[1]) -> Response:
    """Один `POST /mfa-recovery`; ответ возвращается целиком (нужны и тело, и заголовки)."""
    token = _токен(client)
    response: Response = client.post(
        MFA_RECOVERY_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_BACKUP_CODE: code},
        headers=_headers(address=address),
        follow_redirects=False,
    )
    return response


def _код_входа(
    client: TestClient, secret: str, clock: Clock, *, address: str = ADDRESSES[20]
) -> Response:
    """`POST /totp` кодом из окна, следующего за подтверждением привязки: переход на `'full'`.

    Часы сдвигаются на два окна намеренно: подтверждение привязки расходует свои два кода
    (`ADR-013`), и код из подтверждённого окна вход не откроет — слой отвечает отказом `replay` (это
    отдельная проверка `test_web_totp_page.py`). Здесь нужен успех самого перехода, поэтому значение
    берётся из окна после подтверждённой пары.
    """
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    token = _токен(client)
    response: Response = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=address),
        follow_redirects=False,
    )
    return response


def _войти(client: TestClient) -> Response:
    """Вход паролем: шаг `'password'` (§8.2 шаг (1))."""
    return login(client)


def _статус(response: Response) -> int:
    """Код ответа типизированно: у `httpx` он объявлен как `Any`, а тесты обязаны сравнивать `int`."""
    status: int = response.status_code
    return status


def _сеанс(store: MemoryStore, client: TestClient) -> UserSession:
    secret = session_cookie(client)
    assert secret, "куки сеанса нет"
    record = store.find_by_secret(secret)
    assert record is not None, "сеанс пропал из репозитория"
    return record


def _шаг(store: MemoryStore, client: TestClient) -> str:
    return _сеанс(store, client).auth_step


def _набор(store: MemoryStore) -> tuple[BackupCode, ...]:
    return store.backup_code_rows(_id_владельца(store))


def _неиспользованные(store: MemoryStore) -> int:
    return len(tuple(row for row in _набор(store) if row.used_at is None))


def _попытки(store: MemoryStore) -> int:
    """Строки ленты `totp_failures` в горизонте окна (§8.2: лента одна на оба поля формы)."""
    not_before = datetime.now(UTC) - TOTP_FAILURE_HORIZON
    return len(store.totp_failures(_id_владельца(store), not_before=not_before))


def _просрочить(store: MemoryStore, *, days: int) -> None:
    """Сдвинуть даты набора в прошлое — граница семидневного срока.

    Правятся обе даты, и порядок между ними важен: обязательство перевыпустить снимается выпуском,
    созданным **не раньше** расхода (`recovery_state`, `ADR-016` п. 6). Сдвинуть только `used_at`
    означало бы получить «пачка выпущена после расхода» и потерять саму просрочку. Глобальный сдвиг
    часов здесь не годится: он же просрочил бы сеанс, и проверка проверяла бы просрочку сеанса.
    """
    база = datetime.now(UTC)
    for row in _набор(store):
        row.created_at = база - timedelta(days=days + 1)
        if row.used_at is not None:
            row.used_at = база - timedelta(days=days)


def _отозвать_привязку(store: MemoryStore) -> None:
    """Отозвать подтверждённую привязку, чтобы цикл привязки можно было пройти заново.

    Нужен проверке перевыпуска: отдельной команды «выпустить ещё кодов» в этом срезе нет
    (`§9.3 п. 5` — остаток `T-104`), поэтому второй выпуск достижим только через новый цикл
    привязки. Отзыв строки делает то же, что начало перепривязки: `active_enrollment` перестаёт
    видеть запись.
    """
    for row in store.enrollments():
        if row.user_id == _id_владельца(store) and row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)


def _чужой_код(store: MemoryStore) -> str:
    """Показная форма значения, выпущенного другой учётной записи.

    Значение настоящее (тот же генератор, тот же хэш), но в наборе проверяемой учётной записи его
    нет: так проверяется именно изоляция по `user_id`, а не «случайная строка не совпала».
    """
    foreign = new_backup_codes()[0]
    store.insert_backup_code_hashes(uuid.uuid4(), (hash_backup_code(foreign),))
    return foreign


# ─── §8.2: выдача, единственный показ, расход как шаг входа ───────────────────────────────────


def test_backup_code_flow(client: TestClient, store: MemoryStore, clock: Clock) -> None:
    """Обязательная проверка `tasks/todo.md`: пачка показана один раз, предупреждение после расхода.

    Три утверждения собраны в один проход по церемонии, потому что они про один и тот же переход:
    выдача происходит в ответе `POST /mfa-enroll/verify`, а дальше меняются только шаги сеанса.

    1. **Пачка показана один раз.** Значения есть в ответе подтверждения и нет больше нигде: ни на
       странице привязки после подтверждения, ни на странице кода, ни на странице резервного кода
       (§8.2: «показываются один раз при генерации»). В наборе при этом лежат только хэши (§8.2),
       поэтому «показать ещё раз» нечем — это проверяется составом строк, а не отсутствием ссылки.
    2. **Расход кода = шаг полной аутентификации** (§8.2, `ADR-016` п. 9): сеанс поднимается до
       `'full'`, закрытый маршрут-щуп открывается, а предупреждение «нужно выпустить новые» уходит
       в том же ответе, где код был истрачен (§9.3 п. 3: «расход + предупреждение»).
    3. **Отказ на шаге `password`** (§8.8 «вход без TOTP невозможен ни для одного маршрута, кроме
       страницы кода»): страница резервного кода — часть церемонии входа, а не пропуск в консоль: до
       расхода щуп закрыт, после — открыт.
    """
    assert _статус(_войти(client)) == 302, "вход паролем не состоялся"
    _secret, shown = _привязать(client, store, clock)

    # (1) выдача: значения — в этом ответе, в наборе — только хэши этих значений.
    rows = _набор(store)
    assert len(rows) == BACKUP_CODE_COUNT, "выпущена не полная пачка"
    assert all(
        is_sha256_hex(row.code_hash) for row in rows
    ), "в наборе есть строка не формы SHA-256 hex: §8.2 хранит только хэши"
    assert {row.code_hash for row in rows} == {
        hash_backup_code(code) for code in shown
    }, "в наборе лежат хэши не тех значений, которые показали человеку"
    assert not any(
        row.used_at is not None for row in rows
    ), "свежая пачка уже помечена израсходованной"

    for path in (MFA_ENROLL_PATH, TOTP_CODE_PATH, MFA_RECOVERY_PATH):
        ответ = client.get(path, headers=_headers())
        assert _статус(ответ) == 200, f"{path}: {ответ.text[:200]}"
        for code in shown:
            assert code not in ответ.text, f"{path}: значение показано повторно (§8.2)"

    # (3) отказ на шаге второй половины входа: резервная страница не открывает закрытое до 2FA.
    assert _шаг(store, client) == "totp", "после подтверждения привязки шаг не 'totp'"
    щуп = client.get("/probe-full", headers=_headers(), follow_redirects=False)
    assert _статус(щуп) == 302, "сеанс без кода входа получил доступ к закрытому маршруту"
    assert щуп.headers["location"] == TOTP_CODE_PATH

    # (2) расход: полный вход + предупреждение в том же ответе.
    код = shown[0]
    ответ = _расход(client, код)
    assert _статус(ответ) == 200, ответ.text[:400]
    assert (
        _шаг(store, client) == "full"
    ), "расход резервного кода не стал шагом полной аутентификации"
    assert (
        "резервные коды нужно выпустить" in ответ.text
    ), "в ответе расхода нет обязательного предупреждения (§8.2)"
    срок = (FROZEN + RECOVERY_REGENERATION_WINDOW).strftime("%d.%m.%Y %H:%M")
    assert срок in ответ.text, f"предупреждение не называет срок перевыпуска до {срок} UTC (§8.2)"

    щуп = client.get("/probe-full", headers=_headers(), follow_redirects=False)
    assert _статус(щуп) == 200, "после расхода кода доступ в консоль не открылся (§8.2)"

    # Резервная страница больше не нужна: сеанс полный, и второй расход нечем повторить.
    снова = client.get(MFA_RECOVERY_PATH, headers=_headers(), follow_redirects=False)
    assert _статус(снова) == 302, "полная сессия осталась на странице расхода"
    assert снова.headers["location"] == CONSOLE_PATH

    # Израсходованная строка перестаёт быть неиспользованной, а предупреждение живёт и дальше:
    # обязательство §8.2 не должно жить на одной странице, иначе о перевыпуске забывают вместе
    # с ответом, где код был истрачен. Для следующего входа нужен новый сеанс: текущий уже
    # полный, и страницу кода он не открывает.
    assert _неиспользованные(store) == BACKUP_CODE_COUNT - 1, "расход не пометил строку"
    assert _статус(_войти(client)) == 302, "новый сеанс не начался"
    страница_кода = client.get(TOTP_CODE_PATH, headers=_headers(address=ADDRESSES[17]))
    assert _статус(страница_кода) == 200, страница_кода.text[:200]
    assert (
        "выпустить новые" in страница_кода.text
    ), "предупреждение пропало при следующем открытии страницы кода (§8.2)"
    assert (
        "кодов осталось: 9" in страница_кода.text
    ), "предупреждение на странице кода не называет остаток набора"


def test_значение_кода_не_уходит_в_лог(
    client: TestClient, store: MemoryStore, clock: Clock, json_logs: Callable[[], list[str]]
) -> None:
    """Значение кода живёт в HTTP-ответе один показ, поэтому маска журнала обязательна.

    Строка `backup_code_spent` обязана остаться в логе — без неё расход неотличим от отказа. При
    этом ни само значение, ни его каноническая форма без разделителей, ни его хэш в строке журнала
    не появляются (§8.8 «токен не встречается в дампе БД/логах», `ADR-016` п. 4 и п. 11). Хэш —
    отдельная проверка: SHA-256 без соли, и значение восстанавливается по нему перебором по
    алфавиту за секунды, поэтому хэш в журнале — та же утечка, только замедленная.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)
    код = shown[0]
    assert _статус(_расход(client, код)) == 200

    захват = "\n".join(json_logs())
    assert "backup_code_spent" in захват, "в логе нет ни строки о расходе, ни её следствий"
    assert "backup_codes_issued" in захват, "в логе нет ни строки о выпуске пачки"
    assert код not in захват, "значение кода ушло в лог"
    assert normalize_backup_code(код) not in захват, "канон значения ушёл в лог"
    assert hash_backup_code(код) not in захват, "хэш кода ушёл в лог"


def test_пустая_форма_и_битый_формат_не_приближают_блокировку(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """`400` до криптографии и без строки в ленте неудач: пустое поле и набор вне алфавита (§8.2).

    Лента считает попытки угадать значение; пустая отправка и строка вроде `ILO0O1IL0O` значением не
    являются (алфавит `ADR-016` п. 2 их исключил), и разрешить им двигать счётчик означало бы дать
    способ блокировать себе вход, не подбирая код. Отказ по формату при этом обязан отличаться от
    отказа «такого кода нет» — иначе подсказка «проверьте алфавит» появлялась бы у человека, который
    ввёл всё правильно.
    """
    assert _статус(_войти(client)) == 302
    _secret, _shown = _привязать(client, store, clock)

    было = _попытки(store)
    пустая = _расход(client, "")
    assert _статус(пустая) == 400, пустая.text[:200]
    assert EMPTY_BACKUP_CODE_DETAIL in пустая.text, "пустая форма объяснена не как пустая форма"

    # `I`, `L`, `O`, `0`, `1` в алфавите отсутствуют: это отказ по формату, а не «кода нет».
    битая = _расход(client, "ILO0O1IL0O", address=ADDRESSES[2])
    assert _статус(битая) == 400, битая.text[:200]
    assert RECOVERY_FORMAT_DETAIL in битая.text, "отказ по формату не объяснён как отказ по формату"

    assert _попытки(store) == было, "пустая форма или битый формат записали попытку в ленту (§8.2)"
    assert _неиспользованные(store) == BACKUP_CODE_COUNT, "отказ по формату израсходовал строку"
    assert _шаг(store, client) == "totp", "отказ по формату поднял шаг сеанса"


def test_показная_форма_значения_принимается(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Канон ввода (`ADR-016` п. 4): тот же код в показной форме, строчными буквами и с пробелами.

    Человек переписывает значение со страницы, где оно показано как `ABCDE-FGHJK`, и вводит его с
    экранной клавиатуры — строчными буквами, иногда с пробелами из буфера. Без канона каждая такая
    попытка сожгла бы одноразовый код и добавила бы строку в ленту неудач, а смысл «алфавит без
    похожих знаков» от этого только пострадал бы.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)
    показан = shown[3]
    assert "-" in показан, "показанная форма без разделителя: проверка канона ничего не стоит"

    искажённое = f"  {показан.lower().replace('-', ' ')} "
    ответ = _расход(client, искажённое)
    assert _статус(ответ) == 200, ответ.text[:400]
    assert (
        _неиспользованные(store) == BACKUP_CODE_COUNT - 1
    ), "код в искажённой форме не израсходован"
    assert _шаг(store, client) == "full"


# ─── §8.8: одноразовость и неразличимость отказов ─────────────────────────────────────────────


def test_код_одноразов_при_втором_входе(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Офлайновая половина строки §8.8 «резервный код одноразовый» на уровне маршрута.

    Живая половина — `test_backup_code_single_use` (атомарность guarded-`UPDATE` под параллельными
    входами, job `миграции`). Здесь проверяется другое: что после успеха сеанс уходит с резервной
    страницы, а в **новом** сеансе тот же код уже не находится — путь «первый вход прошёл, второй
    попробует тем же значением» закрыт на всех трёх уровнях: поиск среди неиспользованных,
    guarded-`UPDATE` и отказ маршрута полной сессии.

    Второй сеанс берётся новым `login`: сессия после расхода полная, и на ней расход невозможен по
    шагу, поэтому проверка без нового сеанса проверяла бы только шаг сеанса.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)
    код = shown[1]
    assert _статус(_расход(client, код)) == 200

    assert _статус(_войти(client)) == 302, "повторный вход не состоялся"
    assert _шаг(store, client) == "password", "новый сеанс не начался с шага 'password'"

    ответ = _расход(client, код, address=ADDRESSES[4])
    assert _статус(ответ) == 401, f"израсходованный код принят повторно: {ответ.text[:300]}"
    assert RECOVERY_FAILURE_DETAIL in ответ.text, "отказ не объяснён как отказ по коду"
    assert _неиспользованные(store) == BACKUP_CODE_COUNT - 1, "повторный расход изменил набор"
    assert _шаг(store, client) == "password", "израсходованный код поднял шаг нового сеанса"


def test_чужой_израсходованный_и_несуществующий_код_дают_один_отказ(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§8.8 и `ADR-016` п. 5: страница не должна быть оракулом для того, кто подсмотрел экран выпуска.

    «Такого кода нет», «такой код уже потрачен» и «такой код принадлежит другой учётной записи» —
    один и тот же ответ: тот же код состояния, тот же текст. Иначе человек, увидевший значение при
    выпуске, получает способ проверить, живёт ли оно ещё. Различие «нашёл, но guarded-`UPDATE`
    отказал» (параллельный расход) уходит в лог, а не в ответ — офлайн оно невоспроизводимо и
    держится живой проверкой.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)

    потраченный = shown[2]
    assert _статус(_расход(client, потраченный)) == 200
    assert _статус(_войти(client)) == 302, "повторный вход не состоялся"

    чужой = _чужой_код(store)
    ответы = [
        _расход(client, потраченный, address=ADDRESSES[5]),  # израсходованный
        _расход(client, чужой, address=ADDRESSES[6]),  # настоящий, но из чужого набора
        _расход(client, "QQQQQ-QQQQQ", address=ADDRESSES[7]),  # формата, но никогда не выпущенный
    ]
    статусы = [_статус(response) for response in ответы]
    assert статусы == [401, 401, 401], f"отказы различаются кодом состояния: {статусы}"
    assert all(
        RECOVERY_FAILURE_DETAIL in response.text for response in ответы
    ), "отказ объяснён по-разному: страница стала оракулом (§8.8)"
    assert (
        len({response.text for response in ответы}) == 1
    ), "тело отказа различается: страница стала оракулом (§8.8)"
    assert _неиспользованные(store) == BACKUP_CODE_COUNT - 1, "отказ изменил набор"


# ─── §8.2: общая лента неудач и общий срок ────────────────────────────────────────────────────


def test_неудачи_резервного_кода_складываются_с_кодами_2fa(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Один счётчик на второй фактор: §8.2 и `ADR-016` п. 8.

    Пять неудач — это пять неудач второго фактора, независимо от того, в каком поле они пришли.
    Раздельные счётчики дали бы 5 + 5 попыток и обошли бы блокировку чередованием полей, поэтому
    здесь смешаны `POST /totp` и `POST /mfa-recovery`: пятая попытка обязана дать блокировку учётной
    записи, `429` с `Retry-After` и `locked_until` в строке учётной записи.

    Адрес у каждой попытки свой: §8.3 даёт на адрес 5 запросов кода в минуту, и с одним адресом
    пятая попытка упёрлась бы в лимит частоты раньше, чем наступила бы блокировка по §8.2.
    """
    assert _статус(_войти(client)) == 302
    secret, shown = _привязать(client, store, clock)
    assert _статус(_войти(client)) == 302, "новый сеанс не начался"

    адреса = iter(ADDRESSES[9:])
    статусы: list[int] = []
    for _ in range(2):  # две неудачи полем кода 2FA
        token = _токен(client)
        response = client.post(
            TOTP_CODE_PATH,
            data={CSRF_FORM_FIELD: token, FIELD_CODE: "000000"},
            headers=_headers(address=next(адреса)),
            follow_redirects=False,
        )
        статусы.append(_статус(response))
    for _ in range(3):  # три неудачи полем резервного кода
        статусы.append(_статус(_расход(client, "QQQQQ-QQQQQ", address=next(адреса))))

    assert статусы[:4] == [
        401,
        401,
        401,
        401,
    ], f"неудачи до блокировки объяснены не как отказ: {статусы}"
    assert статусы[4] == 429, f"пятая неудача не закрыла вход: {статусы}"
    assert (
        _попытки(store) == TOTP_MAX_FAILED_CODES
    ), "в ленте не ровно пять строк второго фактора: счётчики разъехались по полям форм"
    user = _владельец(store)
    assert user.locked_until is not None, "блокировка учётной записи не записана в строку (§8.2)"

    # Пока вход закрыт, даже настоящий код не расходуется: лента и блокировка живут до кода.
    ответ = _расход(client, shown[0], address=ADDRESSES[28])
    assert _статус(ответ) == 429, "заблокированная учётная запись приняла резервный код"
    assert "Retry-After" in ответ.headers, "отказ `429` без `Retry-After` (§8.3)"
    assert _неиспользованные(store) == BACKUP_CODE_COUNT, "расход при блокировке всё-таки произошёл"
    assert secret, "секрет привязки нужен для кодов входа — иначе начало теста бессмысленно"


def test_просроченный_срок_закрывает_вход_по_2fa_и_открывает_путь_кода(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Решение заказчика от 2026-11-22 (ask `2f6bab2b`), `ADR-016` п. 6.

    Просроченный семидневный срок держит переход «пароль + код 2FA»: `POST /totp` отказывает `403`
    **до** криптографии — код не проверяется и не расходуется, потому что при просрочке вход закрыт
    правилом §8.2, а не потому, что код неверный. Резервный путь при этом остаётся открытым ровно
    тогда, когда есть неиспользованные строки: проверяет это поиск среди неиспользованных, а не
    отдельный флаг.

    Отдельно держится, что отказ не записывает неудачу в ленту: у человека всё могло быть правильно,
    закрыт сам переход, и считать это попыткой нельзя.
    """
    assert _статус(_войти(client)) == 302
    secret, shown = _привязать(client, store, clock)
    assert _статус(_расход(client, shown[0])) == 200, "первый расход не состоялся"
    _просрочить(store, days=RECOVERY_REGENERATION_WINDOW.days + 1)

    assert _статус(_войти(client)) == 302, "новый сеанс не начался"
    попытки_до = _попытки(store)

    token = _токен(client)
    ответ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address=ADDRESSES[10]),
        follow_redirects=False,
    )
    assert _статус(ответ) == 403, f"просроченный срок не закрыл вход по 2FA: {ответ.text[:300]}"
    assert GRACE_EXPIRED_DETAIL in ответ.text, "отказ не называет причину и выход (§8.2)"
    assert _попытки(store) == попытки_до, "закрытый переход записал неудачу в ленту (§8.2)"
    assert _шаг(store, client) == "password", "просрочка подняла шаг сеанса"

    # Путь резервного кода открыт: неиспользованные строки есть.
    ответ = _расход(client, shown[1], address=ADDRESSES[11])
    assert _статус(ответ) == 200, f"резервный путь закрыт при просрочке: {ответ.text[:300]}"
    assert _шаг(store, client) == "full", "расход при просрочке не дал полного входа"
    assert (
        "резервные коды нужно выпустить" in ответ.text
    ), "предупреждение о перевыпуске пропало при просрочке"


def test_просрочка_без_остатков_закрывает_вход_полностью(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Принятый риск формулировки (б): просрочка и все коды израсходованы — вход закрыт целиком.

    Это то следствие, которое заказчик принял осознанно: снимает его только сброс привязки
    администратором (`T-106`, §9.3 п. 6), поэтому здесь обязано быть объяснение, а не вечная форма с
    заведомо неверным ответом. Страница резервного кода не показывает форму, если неиспользованных
    строк нет, а переход по 2FA закрыт правилом срока.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)
    # Расход исчерпывает пачку напрямую: HTTP-путь умеет тратить по одному коду за сеанс (после
    # расхода сеанс полный), а проверять нужно состояние «неиспользованных не осталось».
    for row in _набор(store):
        row.used_at = datetime.now(UTC)
    _просрочить(store, days=RECOVERY_REGENERATION_WINDOW.days + 1)

    assert _статус(_войти(client)) == 302, "новый сеанс не начался"
    страница = client.get(MFA_RECOVERY_PATH, headers=_headers())
    assert _статус(страница) == 200, страница.text[:200]
    assert (
        NO_SPARE_CODE_DETAIL in страница.text
    ), "пустой набор не объяснён (§9: состояние объясняется)"
    assert (
        f'name="{FIELD_BACKUP_CODE}"' not in страница.text
    ), "при пустом наборе на странице осталась форма расхода"

    token = _токен(client)
    ответ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: token, FIELD_CODE: "000000"},
        headers=_headers(address=ADDRESSES[13]),
        follow_redirects=False,
    )
    assert _статус(ответ) == 403, "просроченный срок не закрыл вход по 2FA"
    assert _шаг(store, client) == "password", "закрытый вход поднял шаг сеанса"
    assert _неиспользованные(store) == 0, "израсходованные строки должны остаться в наборе"
    assert (
        len(_набор(store)) == BACKUP_CODE_COUNT
    ), "пустота набора достигнута удалением строк (§8.2)"


# ─── §9.3 п. 2–3: разметка второй половины входа ──────────────────────────────────────────────


def test_страница_кода_содержит_ссылку_на_резервный_код(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """§9.3 п. 2: у страницы кода обязана быть ссылка «использовать резервный код».

    Ссылка обязана быть видна **до** попытки и до отказа: резервный путь нужен именно тому, у кого
    второй фактор не сработал, и прятать его за неудачей — значит оставить человека без второго пути
    ровно в тот момент, когда он нужен. Адрес в разметке не пишется: его даёт обработчик из
    `security/sessions.py`, иначе разметка разошлась бы с маршрутом.
    """
    assert _статус(_войти(client)) == 302
    _secret, _shown = _привязать(client, store, clock)
    страница = client.get(TOTP_CODE_PATH, headers=_headers())
    assert _статус(страница) == 200, страница.text[:200]
    assert f'href="{MFA_RECOVERY_PATH}"' in страница.text, "ссылки на резервный код нет (§9.3 п. 2)"
    assert "Использовать резервный код" in страница.text, "ссылка подписана не по §9.3"
    assert f'action="{TOTP_CODE_PATH}"' in страница.text, "у страницы пропала форма кода"


def test_страница_кода_и_страница_резервного_кода_не_подменяют_друг_друга(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Отказ резервного пути не перекидывает человека на страницу кода, и наоборот.

    Это не косметика: отдать вместо резервной формы страницу кода означало бы предложить вводить код
    из генератора там, где генератор у человека как раз и не работает (§9.3 держит `/mfa-recovery`
    отдельной страницей). При этом обе страницы объясняют блокировку одинаково и обе ссылаются на
    `/locked` только тогда, когда вход действительно закрыт на срок (§9).
    """
    assert _статус(_войти(client)) == 302
    _secret, _shown = _привязать(client, store, clock)

    резерв = client.get(MFA_RECOVERY_PATH, headers=_headers())
    assert _статус(резерв) == 200, резерв.text[:200]
    assert (
        f'action="{MFA_RECOVERY_PATH}"' in резерв.text
    ), "страница расхода показала форму кода 2FA"
    assert (
        f'href="{TOTP_CODE_PATH}"' not in резерв.text
    ), "страница расхода отправила человека на страницу кода: второй путь стал недостижим"

    ответ = _расход(client, "QQQQQ-QQQQQ", address=ADDRESSES[14])
    assert _статус(ответ) == 401, ответ.text[:200]
    assert (
        f'href="{TOTP_CODE_PATH}"' not in ответ.text
    ), "отказ по резервному коду открыл страницу кода: формы смешались"
    assert (
        'href="/locked' not in ответ.text
    ), "ссылка на объяснение блокировки показана там, где блокировки нет (§9)"


# ─── §8.8: матрица «шаг сеанса × маршрут» ─────────────────────────────────────────────────────

#: Строки матрицы — (шаг сеанса, маршрут, ожидаемое поведение) для правила §8.8 «вход без TOTP
#: невозможен ни для одного маршрута, кроме страницы кода». Две строки добавляет этот срез:
#: `/mfa-recovery` при полной сессии (расход кода и есть шаг полной аутентификации — `ADR-016` п. 9,
#: повторить его нечем) и `/mfa-recovery` при шаге второй половины входа (страница доступна, но
#: доступа к закрытым маршрутам она не даёт — иначе резервный путь стал бы дырой в том же правиле).
MATRIX: Final = (
    ("password", "/probe-full", "redirect", TOTP_CODE_PATH),
    ("totp", "/probe-full", "redirect", TOTP_CODE_PATH),
    ("full", "/probe-full", "allow", ""),
    ("password", MFA_RECOVERY_PATH, "page", ""),
    ("totp", MFA_RECOVERY_PATH, "page", ""),
    ("full", MFA_RECOVERY_PATH, "redirect", POST_CODE_REDIRECT),
)


@pytest.mark.parametrize(("step", "route", "ожидается", "адрес_отказа"), MATRIX)
def test_route_requires_full_auth(
    step: str,
    route: str,
    ожидается: str,
    адрес_отказа: str,
    client: TestClient,
    store: MemoryStore,
    clock: Clock,
) -> None:
    """Матрица §8.8: до кода входа (или резервного кода) закрыто всё, кроме страницы кода.

    Сеанс приводится к нужному шагу так: `password` — только пароль, `totp` — подтверждённая
    привязка, `full` — код входа. Строки с `/probe-full` используют маршрут-щуп из `probe_router`:
    боевой точки, требующей полный вход, у среза ещё нет, поэтому правило проверяется на щупе, а не
    «на честном слове».

    `page` означает «страница открылась, но щуп по-прежнему закрыт»: резервный путь обязан быть
    доступен внутри церемонии входа и не обязан открывать консоль.
    """
    assert _статус(_войти(client)) == 302, "вход паролем не состоялся"
    secret, _shown = _привязать(client, store, clock)
    if step == "full":
        assert (
            _статус(_код_входа(client, secret, clock)) == 302
        ), "код входа не поднял сеанс до 'full'"
        assert _шаг(store, client) == "full", "сеанс не в шаге 'full'"
    elif step == "password":
        assert _статус(_войти(client)) == 302, "новый сеанс не начался"
        assert _шаг(store, client) == "password", "сеанс не в шаге 'password'"
    else:
        assert _шаг(store, client) == "totp", "сеанс не в шаге 'totp'"

    if ожидается == "allow":
        assert _статус(client.get(route, headers=_headers(), follow_redirects=False)) == 200
        return

    if ожидается == "page":
        ответ = client.get(route, headers=_headers(), follow_redirects=False)
        assert _статус(ответ) == 200, f"{route} недоступна на шаге {step!r}: {ответ.text[:200]}"
        assert f'action="{MFA_RECOVERY_PATH}"' in ответ.text, f"{route} показала не форму расхода"
        щуп = client.get("/probe-full", headers=_headers(), follow_redirects=False)
        assert _статус(щуп) == 302, f"{route} на шаге {step!r} открыла доступ к закрытому маршруту"
        assert щуп.headers["location"] == TOTP_CODE_PATH
        return

    ответ = client.get(route, headers=_headers(), follow_redirects=False)
    assert _статус(ответ) == 302, f"{route} пустила сеанс шага {step!r}"
    assert ответ.headers["location"] == адрес_отказа


# ─── перевыпуск и области счётчика ────────────────────────────────────────────────────────────


def test_перевыпуск_аннулирует_остатки_и_не_трогает_израсходованные(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Порядок «аннулирование → вставка» в обработчике: обратный оставляет учётку без рабочих кодов.

    Аннулирование прежней пачки идёт по предикату `used_at IS NULL` и о пачках не знает
    (`ADR-016` п. 7, `SqlStore.invalidate_unused_backup_codes`). Если обработчик вставит новую пачку
    **до** аннулирования, аннулирование задевает и её: человек получает «коды выпущены» и ноль
    рабочих кодов. Проверка проходит цикл привязки заново и смотрит ровно это: сколько
    неиспользованных строк осталось после выпуска.

    Израсходованные строки прежней пачки обязаны остаться израсходованными: `used_at` — единственный
    носитель начала семидневного срока (п. 6 и п. 11 того же ADR), и «почистить историю» означало бы
    снять с учётной записи обязательство перевыпустить коды.

    Второй выпуск достижим только через новый цикл привязки: отдельной команды перевыпуска в этом
    срезе нет (`§9.3 п. 5` — остаток `T-104`), поэтому привязка предварительно отзывается.
    """
    assert _статус(_войти(client)) == 302
    _secret, shown = _привязать(client, store, clock)
    assert len(_набор(store)) == BACKUP_CODE_COUNT

    assert _статус(_расход(client, shown[0])) == 200
    потраченный = next(row for row in _набор(store) if row.used_at is not None)
    момент_расхода = потраченный.used_at
    assert момент_расхода is not None, "расход не записал момент"

    _отозвать_привязку(store)
    assert _статус(_войти(client)) == 302, "новый сеанс не начался"
    _secret2, shown2 = _привязать(client, store, clock)

    набор = _набор(store)
    assert (
        len(набор) == 2 * BACKUP_CODE_COUNT
    ), "выпуск удалил строки прежней пачки: израсходованные обязаны остаться (§8.2, `ADR-016` п. 11)"
    assert _неиспользованные(store) == BACKUP_CODE_COUNT, (
        "после перевыпуска рабочих кодов не столько, сколько в новой пачке: обработчик переставил "
        "местами аннулирование и вставку"
    )
    assert {row.code_hash for row in набор if row.used_at is None} == {
        hash_backup_code(code) for code in shown2
    }, "неиспользованные строки — не та пачка, которую показали человеку"
    assert потраченный.used_at == момент_расхода, "расход прежней пачки сдвинут или снят"
    assert _secret2, "вторая привязка не состоялась"


def test_церемония_не_заводит_новых_областей_счётчика(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Ни выдача пачки, ни расход резервного кода не заводят новой области счётчика частоты.

    Резервный код пользуется областями страницы кода (`totp_session`, `totp_ip`) и общим пределом
    мутаций пользователя: §8.3 называет лимиты для `/totp`, а резервный код — та же попытка второго
    фактора (`ADR-016` п. 8). Новой области в закрытом перечне схемы
    (`packages.storage.models.RATE_SCOPES`, `CHECK` ревизии `0003`) заведено не было, и завести её
    без новой ревизии и отдельного решения заказчика нельзя. Если обработчик начнёт изобретать свою
    область, она появится здесь же.
    """
    assert _статус(_войти(client)) == 302
    _привязать(client, store, clock)
    _расход(client, "QQQQQ-QQQQQ", address=ADDRESSES[18])
    _расход(client, "", address=ADDRESSES[19])
    области = {scope for scope, _key, _start in store.buckets()}
    assert (
        области <= CODE_AREAS
    ), f"слой завёл область счётчика вне закрытого перечня: {sorted(области)}"


def test_исчерпание_пачки_не_закрывает_вход_по_2fa_до_истечения_срока(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Израсходованы все коды, но срок ещё не истёк: вход по 2FA открыт, закрыт только резервный путь.

    Это не косметика и не «второй вариант» проверки с просрочкой: состояние «неиспользованных не
    осталось» возникает и здесь, и текст страницы не имеет права врать про закрытый вход. При
    просроченном сроке закрыт весь вход (§8.2, принятый риск `ADR-016` п. 6), до просрочки — только
    резервный путь, а переход «пароль + код 2FA» обязан пройти. Иначе объяснение стало бы способом
    отговорить человека от входа, который у него ещё есть.
    """
    assert _статус(_войти(client)) == 302
    secret, _shown = _привязать(client, store, clock)
    assert _статус(_расход(client, _shown[0])) == 200, "первый расход не состоялся"
    for row in _набор(store):
        row.used_at = datetime.now(UTC)

    assert _статус(_войти(client)) == 302, "новый сеанс не начался"
    страница = client.get(MFA_RECOVERY_PATH, headers=_headers(address=ADDRESSES[15]))
    assert _статус(страница) == 200, страница.text[:200]
    assert NO_SPARE_CODE_DETAIL in страница.text, "пустой набор не объяснён (§9)"

    assert (
        _статус(_код_входа(client, secret, clock, address=ADDRESSES[16])) == 302
    ), "израсходованная пачка закрыла вход по коду 2FA до истечения срока (§8.2)"
    assert _шаг(store, client) == "full", "код входа не поднял сеанс до 'full'"
