"""События мутаций в журнале аудита (TZ §8.7, §4.1; `T-109`, срез `R2b`, `ADR-025` п. 6).

Половинка в памяти: приложение боевое (`create_app`), репозиторий — `MemoryStore` из
`tests/integration/web_support.py`. Предмет — **факт события и его содержание**: какое событие
порождает каждая мутация, с каким субъектом, каким объектом, каким идентификатором объекта и какими
причинами, и ровно ли один раз. Отдельный предмет — **одна точка на событие**: удвоенная строка
искажает счётчик при разборе так же, как отсутствующая, поэтому каждая проверка считает строки
своего имени, а не «весь журнал».

Файл сознательно не дублирует живую половину (`tests/integration/test_audit_append_db.py`, CI job
`миграции`): блокировка хвоста, код состояния `23505`, откат транзакции целиком и `RETURNING id` —
свойства протокола добавления, у памяти их нет ни в каком виде. Живой файл под этот срез не заведён
намеренно: HTTP-слой над боевой базой исполняется в `compose-smoke`/`e2e`, а связь «маршрут → имя
события» видна офлайн целиком, включая `flush()` перед `append_audit` (в памяти `id` проставляется
на `add`, в бою — на флаше; непустой `entity_id` обязаны показывать обе половинки).

Здесь проверяется то, чего живая половина не проверяет: что маршруты вообще порождают события §8.7
и что в деталях нет значений допуска.

Что держится этими проверками:

* **у каждой мутации ровно одна строка её имени** (`ADR-025` п. 6): `session.login`,
  `session.login_failed`, `session.logout`, `session.revoke`, `session.revoke_all`,
  `account.password_changed`, `account.created`, `account.approved`, `account.state_changed`,
  `invitation.issued`, `invitation.accepted`, `invitation.accept_failed`, `invitation.revoked`,
  `totp.enrolled`, `totp.confirmed`, `totp.verify_failed`, `backup_codes.issued`,
  `backup_codes.invalidated`, `backup_code.spent`;
* **`entity_id` обязан быть у события о конкретном объекте**: у `account.created` — идентификатор
  созданной учётной записи (в бою его выдаёт база на флаше, §4.1), у `session.login` — идентификатор
  сеанса, у событий 2FA и кодов — идентификатор учётной записи, а объект церемонии (`enrollment_id`,
  `backup_code_id`) уходит в детали;
* **значений допуска в журнале нет**: ни значения ссылки приглашения, ни значения резервного кода,
  ни пароля, ни материала привязки — журнал читают администраторы, и он попадает в дампы
  (`ADR-002`, `ADR-004`, `ADR-019`);
* **момент события совпадает с моментом изменения** (одна метка на событие, `ADR-025` п. 2): у
  строки журнала и у строки сеанса один и тот же `at`;
* **отказ, не меняющий состояние, фиксируется своей фиксацией** (`invitation.accept_failed`), а
  состоявшееся изменение — общей транзакцией (`invitation.accepted` + `account.created`): «ссылка
  истрачена, а учётной записи нет» и «учётная запись есть, а события нет» — одно откатанное
  состояние, а не два разных.

Чего здесь сознательно нет: `ip` и `request_id` в колонках (их заполняет контекст запроса, который в
памяти не строится — это держит живая половина) и разбор цепочки целиком (`scripts/audit_verify.py` —
срез `R3` задачи `T-109`). Связь соседних строк проверяется локально: `hash_prev` следующей равен
`hash` предыдущей.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.admin_users as admin_routes
import apps.web.routes.invitations as invitation_routes
import apps.web.routes.login as login_routes
import apps.web.routes.profile as profile_routes
import apps.web.routes.sessions as session_routes
import apps.web.routes.totp as totp_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.forms import FIELD_LOGIN, FIELD_PHRASE
from apps.web.routes.admin_users import (
    ACTION_SUSPEND,
    ACTION_UNSUSPEND,
    ADMIN_ACCOUNT_APPROVE_PATH,
    ADMIN_ACCOUNT_SUSPEND_PATH,
    ADMIN_ACCOUNT_UNSUSPEND_PATH,
    ADMIN_INVITATION_REVOKE_PATH,
    ADMIN_INVITATIONS_PATH,
    ADMIN_USERS_PATH,
    FIELD_EMAIL,
    FIELD_ROLE,
    USER_ID_PARAM,
)
from apps.web.routes.invitations import FIELD_REPEAT
from apps.web.routes.profile import FIELD_CURRENT_PHRASE, FIELD_NEW_PHRASE, FIELD_REPEAT_PHRASE
from apps.web.routes.totp import (
    FIELD_BACKUP_CODE,
    FIELD_CODE,
    FIELD_FIRST_CODE,
    FIELD_SECOND_CODE,
)
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.sessions import (
    INVITE_LINK_KEY,
    INVITE_PATH,
    LOGOUT_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    MFA_RECOVERY_PATH,
    SECURITY_PATH,
    SESSION_COOKIE_NAME,
    SESSION_REVOKE_PATH,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.identity.audit import AUDIT_ACTIONS
from packages.identity.backup_codes import BACKUP_CODE_COUNT
from packages.identity.sessions import advance_auth_step, create_session
from packages.identity.totp import TOTP_PERIOD_SECONDS, totp_code
from packages.storage.models import AuditLogEntry, User
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
    session_cookie,
    set_kek_file,
)

#: Момент, от которого живёт файл: окна кодов (30 с) и окна частоты (минута) не должны зависеть от
#: секунды запуска проверки (тот же приём, что у `test_web_totp_page.py`).
FROZEN = datetime.now(UTC).replace(microsecond=0)

#: Адрес из резервного диапазона RFC 5737: счётчики частоты ключуются адресом, и у проверок отказа
#: адрес обязан быть явным, чтобы разные проверки не складывались в одно окно.
ADDRESS: Final = "203.0.113.41"

META_TOKEN: Final = re.compile(r'name="csrf-token" content="([^"]+)"')
SECRET_BLOCK: Final = re.compile(r"<code>([A-Z2-7]{16,128})</code>")
SHOWN_CODE: Final = re.compile(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>")
INVITED_LINK: Final = re.compile(
    re.escape(f"{INVITE_PATH}?{INVITE_LINK_KEY}=") + r"([A-Za-z0-9_-]{43})"
)

#: Логин и адресат приглашения: адресат указывает администратор, логин приглашённый выбирает сам
#: (§1.2, `ADR-020`).
INVITED_LOGIN: Final = "op.invited-r2b"
INVITED_EMAIL: Final = "invited-r2b@example.invalid"

#: Роль выпуска приглашения: закрытый набор из трёх ролей (§1.1), держит домен.
INVITED_ROLE: Final = "operator"

#: Вторая учётная запись раздела администрирования: целей проверок администратор быть не должен —
#: правило «последний администратор» (§8.4) отклоняет блокировку единственного администратора, и
#: проверка блокировала бы не переход, а охрану.
TARGET_LOGIN: Final = "op.target-r2b"
ADMIN_LOGIN: Final = "admin.r2b"

#: Новый пароль смены (`§8.2`): значение проверяется на отсутствие в журнале.
NEW_PHRASE: Final = "Новый-пароль-для-смены-2026"


class Clock:
    """Задаваемое «сейчас» для слоя приложения."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: float = 0.0) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях слоя, которые вызывают его напрямую.

    Набор — все модули с прямым вызовом (`grep` по `apps/web`): пропуск любого из них означал бы,
    что часть журнала живёт в реальном времени, а часть — в замороженном, и сравнение `at` события
    с моментом изменения стало бы случайным.
    """
    fake = Clock(FROZEN)
    for module in (
        admin_routes,
        invitation_routes,
        login_routes,
        profile_routes,
        session_routes,
        totp_routes,
        rate_limit_module,
        security_sessions,
    ):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    # `id` заполняется явно: в памяти нет `INSERT`, поэтому default движка не срабатывает, а строки
    # журнала хранят `actor`/`entity_id` и сравнивать `None` с `None` — значит не проверять ничего.
    memory.seed_user().id = uuid4()
    return memory


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей в песочнице: привязка без него отвечает `503` (`ADR-014` п. 5)."""
    path = tmp_path / "kek.json"
    payload = {
        "format_version": 1,
        "active_version": 1,
        "keys": [{"version": 1, "key": base64.b64encode(secrets.token_bytes(32)).decode()}],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    # `0600` — маска боевого файла ключей: на Linux права из `umask` (0644) не прошли бы политику.
    path.chmod(0o600)
    return path


@pytest.fixture
def client(store: MemoryStore, settings: Settings, kek: Path) -> Iterator[TestClient]:
    """Боевое приложение с файлом ключей: привязка 2FA нужна большинству проверок файла."""
    with build_client(store, settings) as test_client:
        set_kek_file(test_client, kek)
        yield test_client


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _заголовки(address: str = ADDRESS) -> dict[str, str]:
    """Как их отправляет браузер: `Origin` — источник того же хоста, адрес — из-за терминатора."""
    return {
        "Origin": "https://testserver",
        "User-Agent": "t109-r2b",
        "X-Forwarded-For": address,
    }


def _токен(client: TestClient, *, path: str = SESSIONS_PATH) -> str:
    """CSRF-токен из `meta`: мутации консоли, профиля и администрирования требуют его (§8.3).

    По умолчанию — страница сеансов, а не `CONSOLE_PATH`: адрес `/` на этой вехе отвечает
    JSON-заглушкой без `meta`-токена, и помощник молча просил бы токен там, где его нет.
    """
    response = client.get(path, headers=_заголовки())
    assert response.status_code == 200, response.text[:300]
    match = META_TOKEN.search(response.text)
    assert match, f"в странице нет meta токена: {response.text[:300]}"
    return match.group(1)


def _владелец(store: MemoryStore) -> User:
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None, "тестовой учётной записи нет в репозитории"
    assert user.id is not None, "тестовая учётная запись без `id`"
    return user


def _войти_полностью(client: TestClient, store: MemoryStore) -> None:
    """Вход паролем и перевод сеанса на шаг `'full'` (`packages/identity/sessions`).

    Второй фактор в этих проверках не обязателен: предмет — строки журнала, а не механика 2FA (её
    держат `test_web_totp_page.py` и `test_web_backup_codes.py`). Тот же приём, что у
    `test_audit_events_web.py`.
    """
    assert login(client).status_code == 302, "вход не состоялся"
    secret = session_cookie(client)
    assert secret, "куки сеанса нет"
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full", now=record.created_at)


def _выпустить_сеанс(store: MemoryStore, user_id: UUID, *, device: str) -> UUID:
    """Завести отдельный сеанс учётной записи и вернуть его `id` — цель отзыва."""
    issued = create_session(user_id, user_agent=device, auth_step="full", now=FROZEN)
    issued.record.expires_at = FROZEN + timedelta(hours=1)
    store.seed_session(issued)
    assert issued.record.id is not None
    return issued.record.id


def _мутация(
    client: TestClient,
    path: str,
    payload: dict[str, str] | None = None,
    *,
    token_path: str = SESSIONS_PATH,
) -> Response:
    """POST той же мутации, что делает браузер: `Origin`, токен из `meta`, поля формы."""
    data = {CSRF_FORM_FIELD: _токен(client, path=token_path), **(payload or {})}
    ответ: Response = client.post(path, data=data, headers=_заголовки(), follow_redirects=False)
    return ответ


def _текст(value: UUID) -> str:
    """Канонический текст идентификатора: `entity_id` живёт в колонке `TEXT` (§4.1)."""
    return str(value)


def _все(store: MemoryStore) -> list[AuditLogEntry]:
    return list(store.audit_rows)


def _имена(store: MemoryStore) -> list[str]:
    return [row.action for row in _все(store)]


def _событие(store: MemoryStore, action: str) -> AuditLogEntry:
    """Ровно одна строка с этим именем: вторая — удвоенное событие, ноль — событие без носителя."""
    rows = [row for row in _все(store) if row.action == action]
    assert (
        len(rows) == 1
    ), f"ожидается ровно одна строка {action!r}, получено {len(rows)}: {_имена(store)}"
    return rows[0]


def _события(store: MemoryStore, action: str) -> list[AuditLogEntry]:
    """Все строки имени: нужен порядковый разбор там, где проверка намеренно делает два действия."""
    return [row for row in _все(store) if row.action == action]


def _сколько(store: MemoryStore, action: str) -> int:
    return len(_события(store, action))


def _детали(row: AuditLogEntry) -> dict[str, object]:
    assert row.details is not None, f"{row.action}: события без деталей здесь быть не должно"
    return row.details


def _цепочка(store: MemoryStore) -> None:
    """Связь соседних строк: `hash_prev` следующей равен `hash` предыдущей (`ADR-025` п. 7)."""
    rows = _все(store)
    assert rows, "журнал пуст — проверке нечего связывать"
    assert rows[0].hash_prev is None, "первая запись обязана быть без предка"
    for earlier, later in pairwise(rows):
        assert later.hash_prev == earlier.hash, (
            f"строка {later.action} не связана с предыдущей: незацепленные хэши при разборе "
            "неотличимы от вырезанного куска журнала"
        )


def _завести(store: MemoryStore, login_value: str, *, role: str, state: str) -> User:
    """Учётная запись нужной роли и состояния, с `id` (в памяти `INSERT` нет, §4.1)."""
    user = store.seed_user(login=login_value, password=TEST_PASSWORD, role=role)
    assert not user.id, "в памяти идентификатор проставляет только тест, а не `add`"
    user.id = uuid4()
    user.state = state
    store.commit()
    return user


def _администратор(store: MemoryStore, settings: Settings, kek: Path) -> TestClient:
    """Клиент администратора с полным сеансом: раздел требует и роли, и полного шага (§8.4, §8.8).

    Сеанс заведён напрямую, а не входом: у администратора свой вход, а предмет этих проверок —
    строки журнала раздела; механику входа и матрицу допуска держат другие файлы.
    """
    admin = _завести(store, ADMIN_LOGIN, role="admin", state="active")
    assert admin.id is not None
    test_client = build_client(store, settings)
    set_kek_file(test_client, kek)
    issued = create_session(admin.id, user_agent="admin-console", auth_step="full", now=FROZEN)
    issued.record.expires_at = FROZEN + timedelta(hours=1)
    store.seed_session(issued)
    test_client.cookies.set(SESSION_COOKIE_NAME, issued.secret)
    return test_client


def _гость(admin: TestClient) -> TestClient:
    """Клиент без сеанса: приём ссылки анонимный, свой счётчик частоты (§1.2, `ADR-021`)."""
    return TestClient(admin.app, base_url="https://testserver")


def _привязать(client: TestClient, момент: datetime = FROZEN) -> tuple[str, tuple[str, ...]]:
    """Полная церемония привязки: выдать секрет и подтвердить парой кодов.

    Момент передаётся параметром: тесты сдвигают часы (окно кода и защита от повтора считают по
    `utc_now()` слоя), и коды обязаны считаться по тому же моменту, по которому идёт слой.


    Возвращает секрет (нужен для кодов входа) и показную форму пачки резервных кодов: расходуется
    ровно то значение, которое увидел человек (`ADR-016` п. 4), а не сгенерированное без разделителей.
    """
    ответ = _мутация(client, MFA_ENROLL_START_PATH, token_path=MFA_ENROLL_PATH)
    assert ответ.status_code == 200, ответ.text[:400]
    match = SECRET_BLOCK.search(ответ.text)
    assert match, f"мутация не показала секрет: {ответ.text[:400]}"
    secret = match.group(1)

    first = totp_code(secret, момент)
    second = totp_code(secret, момент + timedelta(seconds=TOTP_PERIOD_SECONDS))
    подтверждение = _мутация(
        client,
        MFA_ENROLL_VERIFY_PATH,
        {FIELD_FIRST_CODE: first, FIELD_SECOND_CODE: second},
        token_path=MFA_ENROLL_PATH,
    )
    assert подтверждение.status_code == 200, подтверждение.text[:600]
    codes = tuple(SHOWN_CODE.findall(подтверждение.text))
    assert len(codes) == BACKUP_CODE_COUNT, f"пачка показана не целиком: {подтверждение.text[:600]}"
    return secret, codes


# ─── вход, выход, отзыв сеансов (§8.7 «вход», «выход», «неудачные попытки») ──────────────────


def test_вход_и_выход_дают_по_одной_строке_на_событие(
    client: TestClient, store: MemoryStore
) -> None:
    """Пароль принят → `session.login`; выход → `session.logout`.

    `entity_id` — идентификатор сеанса, `actor` — учётная запись: пара читается из журнала без
    дополнительной колонки (`ADR-025` п. 2). Шаг входа в деталях обязателен, потому что у записи две
    роли: выпуск сеанса после пароля и полный вход после второго фактора.
    """
    assert login(client).status_code == 302, "вход не состоялся"
    secret = session_cookie(client)
    assert secret
    record = store.find_by_secret(secret)
    assert record is not None, "сеанс входа не найден в репозитории"
    assert record.id is not None

    row = _событие(store, "session.login")
    assert row.entity == "session"
    assert row.entity_id == _текст(record.id)
    assert row.actor == _владелец(store).id
    assert _детали(row) == {"auth_step": "password"}
    assert row.at == record.created_at, (
        "момент события не совпадает с моментом строки сеанса: журнал обязан показывать тот же "
        "момент входа, а две метки различались бы микросекундами (`ADR-025` п. 2)"
    )

    advance_auth_step(record, step="full", now=record.created_at)
    выход = _мутация(client, LOGOUT_PATH)
    assert выход.status_code in (302, 303), выход.text[:300]
    logout = _событие(store, "session.logout")
    assert logout.entity == "session"
    assert logout.entity_id == _текст(record.id)
    assert _детали(logout) == {"auth_step": "full"}
    _цепочка(store)


def test_отказ_входа_различается_причиной_и_субъектом(
    client: TestClient, store: MemoryStore
) -> None:
    """«Такого логина нет» — без субъекта; «пароль не тот» — с субъектом и причиной.

    Наружу оба отказа отдаются одинаково (§8.8: отказ не должен быть оракулом существования
    учётной записи), различие живёт в журнале. Выдуманного `actor` у первой строки нет намеренно
    (`ADR-025` п. 2).
    """
    assert login(client, password="не-тот-пароль-совсем").status_code == 401
    wrong = _событие(store, "session.login_failed")
    assert wrong.actor == _владелец(store).id
    assert wrong.entity_id == _текст(_владелец(store).id)
    assert _детали(wrong)["reason"] == "password"

    store.audit_rows.clear()
    assert login(client, login_value="net.takogo.logina").status_code == 401
    unknown = _событие(store, "session.login_failed")
    assert unknown.actor is None, "у отказа по несуществующей учётной записи субъекта быть не может"
    assert unknown.entity_id is None, "объекта нет — идентификатора объекта тоже нет"
    assert _детали(unknown) == {"reason": "unknown_login"}
    assert (
        _сколько(store, "session.login") == 0
    ), "отказанный вход не имеет права ни выпускать сеанс, ни писать событие успеха"


def test_отзыв_сеанса_и_отзыв_всех_сеансов_различаются_объектом(
    client: TestClient, store: MemoryStore
) -> None:
    """Один отзыв — строка о сеансе; «отозвать все» — одна строка об учётной записи с числом.

    Реестр §8.7 даёт на действие одно имя: отдельной строки `session.revoke` на каждую закрытую
    запись при массовом отзыве нет намеренно — журнал показывает решение, а не его следствия
    построчно, а сколько строк закрыто, видно из `details.count`.
    """
    _войти_полностью(client, store)
    user = _владелец(store)
    assert user.id is not None
    чужой = _выпустить_сеанс(store, user.id, device="чужой-ноутбук")

    отзыв = _мутация(client, SESSION_REVOKE_PATH.format(session_id=чужой), token_path=SESSIONS_PATH)
    assert отзыв.status_code in (302, 303), отзыв.text[:300]
    revoke = _событие(store, "session.revoke")
    assert revoke.entity == "session"
    assert revoke.entity_id == _текст(чужой)
    assert _детали(revoke) == {"is_current": "no"}

    все = _мутация(client, SESSIONS_REVOKE_ALL_PATH, token_path=SESSIONS_PATH)
    assert все.status_code in (302, 303), все.text[:300]
    whole = _событие(store, "session.revoke_all")
    assert whole.entity == "user"
    assert whole.entity_id == _текст(user.id)
    assert _детали(whole) == {"count": 1}, (
        "в счёт попадают только живые сеансы: ранее отозванный, о котором уже есть своя строка, "
        "не считается повторно — иначе журнал показывал бы число закрытых строк вместо числа "
        "решений, и разбор завысил бы эффект массового отзыва"
    )
    assert (
        _сколько(store, "session.revoke_all") == 1
    ), "массовый отзыв обязан дать одну строку с числом, а не строку на каждую сессию"
    assert all(row.revoked_at is not None for row in store.sessions()), (
        "после массового отзыва живых сеансов не осталось: событие обязано соответствовать "
        "состоянию, а не только намерению"
    )


# ─── смена пароля (§8.2, §8.3) ────────────────────────────────────────────────────────────────


def test_смена_пароля_пишет_одно_событие_с_числом_закрытых_сеансов(
    client: TestClient, store: MemoryStore
) -> None:
    """`account.password_changed` — одна строка: пересоздание сеанса и отзывы остальных.

    Число отозванных *остальных* сеансов входит в детали: §8.3 требует закрыть их все, и разбор
    обязан видеть, сколько строк закрыла одна смена пароля, не считая таблицу `sessions`.
    """
    _войти_полностью(client, store)
    user = _владелец(store)
    assert user.id is not None
    _выпустить_сеанс(store, user.id, device="второй-ноутбук")

    смена = _мутация(
        client,
        SECURITY_PATH,
        {
            FIELD_CURRENT_PHRASE: TEST_PASSWORD,
            FIELD_NEW_PHRASE: NEW_PHRASE,
            FIELD_REPEAT_PHRASE: NEW_PHRASE,
        },
        token_path=SECURITY_PATH,
    )
    assert смена.status_code == 302, смена.text[:300]

    row = _событие(store, "account.password_changed")
    assert row.entity == "user"
    assert row.entity_id == _текст(user.id)
    assert row.actor == user.id
    details = _детали(row)
    assert details["session_rotated"] is True
    assert details["sessions_revoked"] == 1
    assert _сколько(store, "session.revoke") == 0, (
        "отзывы, следующие из смены пароля, не имеют права плодить отдельные строки §8.7: событие "
        "описывает одно решение"
    )
    assert NEW_PHRASE not in json.dumps(
        details, ensure_ascii=False
    ), "значение нового пароля попало в журнал (§8.4, `ADR-004`)"


# ─── приглашения: выпуск, приём, отказ, отзыв (§1.2, §8.7, `ADR-020`, `ADR-021`) ─────────────


def _выпустить(admin: TestClient, store: MemoryStore) -> tuple[str, str]:
    """Выпустить ссылку администратором и вернуть (значение ссылки, `id` выпуска)."""
    выпуск = _мутация(
        admin,
        ADMIN_INVITATIONS_PATH,
        {FIELD_EMAIL: INVITED_EMAIL, FIELD_ROLE: INVITED_ROLE},
        token_path=ADMIN_USERS_PATH,
    )
    assert выпуск.status_code == 200, выпуск.text[:400]
    match = INVITED_LINK.search(выпуск.text)
    assert match, f"в ответе нет значения ссылки: {выпуск.text[:400]}"
    return match.group(1), str(_событие(store, "invitation.issued").entity_id)


def test_выпуск_приём_и_создание_учётной_записи(
    store: MemoryStore, settings: Settings, kek: Path
) -> None:
    """Три события одной церемонии: `invitation.issued`, `invitation.accepted`, `account.created`.

       `entity_id` у `account.created` обязан быть идентификатором созданной учётной записи: в бою его
       выдаёт флаш (`Store.flush`, §4.1), поэтому порядок `add` → `flush` → `append_audit` → `commit`
       проверяется и здесь, и в живой половинке. Значения ссылки в журнале нет ни в одной строке —
    иначе журнал стал бы каналом одноразовой ссылки в таблицу, которую читают администраторы (`ADR-019`).
    """
    admin = _администратор(store, settings, kek)

    значение, выпуск_id = _выпустить(admin, store)
    issued = _событие(store, "invitation.issued")
    assert issued.entity == "invitation"
    assert issued.entity_id == выпуск_id
    assert _детали(issued) == {"role": INVITED_ROLE}

    гость = _гость(admin)
    ответ = гость.post(
        f"{INVITE_PATH}?{INVITE_LINK_KEY}={значение}",
        data={FIELD_LOGIN: INVITED_LOGIN, FIELD_PHRASE: TEST_PASSWORD, FIELD_REPEAT: TEST_PASSWORD},
        headers=_заголовки(),
        follow_redirects=False,
    )
    assert ответ.status_code == 200, ответ.text[:600]

    принятое = _событие(store, "invitation.accepted")
    assert принятое.entity_id == выпуск_id, "приём обязан относиться к тому же выпуску"
    новичок = store.user_by_login(INVITED_LOGIN)
    assert новичок is not None, "учётная запись не создана"
    assert новичок.id is not None, "у созданной учётной записи нет идентификатора"
    созданный = _событие(store, "account.created")
    assert созданный.entity == "user"
    assert созданный.entity_id == _текст(новичок.id), (
        "`entity_id` события о созданной учётной записи обязан быть её идентификатором: без него "
        "событие не связывается с объектом (§8.7)"
    )
    assert _детали(принятое) == {"created_user_id": str(новичок.id), "role": INVITED_ROLE}
    details = _детали(созданный)
    assert details["invitation_id"] == str(выпуск_id)
    assert details["role"] == INVITED_ROLE
    assert details["state"] == новичок.state
    assert значение not in json.dumps(
        [_детали(принятое), details, _детали(issued)], ensure_ascii=False
    ), "значение ссылки приглашения попало в журнал (`ADR-021`, §8.4)"
    assert _имена(store)[-2:] == [
        "invitation.accepted",
        "account.created",
    ], "оба события состоявшегося приёма обязаны идти подряд одной транзакцией"
    _цепочка(store)


def test_отказ_приёма_ссылки_фиксируется_своей_фиксацией(
    store: MemoryStore, settings: Settings, kek: Path
) -> None:
    """`invitation.accept_failed` переживает ответ сам: бизнес-транзакции у отказа нет.

    Форма не заполнена — состояние не меняется, и обычная «общая» фиксация не состоялась бы: без
    `commit_now` попытка осталась бы в незафиксированной транзакции запроса и пропала бы вместе с
    ответом, а §8.7 требует писать **все** попытки использования ссылки.
    """
    admin = _администратор(store, settings, kek)
    значение, выпуск_id = _выпустить(admin, store)

    гость = _гость(admin)
    до = store.commits
    отказ = гость.post(
        f"{INVITE_PATH}?{INVITE_LINK_KEY}={значение}",
        data={FIELD_LOGIN: INVITED_LOGIN, FIELD_PHRASE: "", FIELD_REPEAT: ""},
        headers=_заголовки(),
        follow_redirects=False,
    )
    assert отказ.status_code == 400, отказ.text[:600]

    row = _событие(store, "invitation.accept_failed")
    assert row.entity == "invitation"
    assert (
        row.entity_id == выпуск_id
    ), "строка ссылки найдена — её идентификатор обязан быть в событии"
    assert _детали(row) == {"reason": "empty_form"}
    assert store.commits > до, (
        "у попытки, приведшей к отказу, обязан быть свой фиксационный шаг: без него событие "
        "пропадает вместе с незафиксированной транзакцией запроса, а §8.7 требует писать все "
        "попытки использования ссылки. Число коммитов здесь не проверяется: счётчики частоты "
        "фиксируются тем же маршрутом и сами по себе"
    )
    assert (
        store.user_by_login(INVITED_LOGIN) is None
    ), "отказ не имеет права создавать учётную запись"
    assert _сколько(store, "invitation.accepted") == 0


def test_отзыв_приглашения_и_одобрение_учётной_записи(
    store: MemoryStore, settings: Settings, kek: Path
) -> None:
    """`invitation.revoked` и `account.approved`: субъект — администратор, объект — его цель.

    Разница между `actor` и `entity_id` здесь и есть смысл §8.7 («действие, субъект, объект»):
    решение принял администратор, а изменился чужой объект. Автор выпуска приглашения субъектом
    одобрения не становится.
    """
    admin = _администратор(store, settings, kek)
    admin_id = store.user_by_login(ADMIN_LOGIN)
    assert admin_id is not None, "администратор не заведён"
    assert admin_id.id is not None

    _, выпуск_id = _выпустить(admin, store)
    отзыв = _мутация(
        admin,
        ADMIN_INVITATION_REVOKE_PATH.format(invitation_id=выпуск_id),
        token_path=ADMIN_USERS_PATH,
    )
    assert отзыв.status_code in (302, 303), отзыв.text[:300]
    revoked = _событие(store, "invitation.revoked")
    assert revoked.actor == admin_id.id
    assert revoked.entity == "invitation"
    assert revoked.entity_id == выпуск_id

    цель = _завести(store, TARGET_LOGIN, role=INVITED_ROLE, state="awaiting_approval")
    assert цель.id is not None
    одобрение = _мутация(
        admin,
        ADMIN_ACCOUNT_APPROVE_PATH.format(**{USER_ID_PARAM: str(цель.id)}),
        token_path=ADMIN_USERS_PATH,
    )
    assert одобрение.status_code in (302, 303), одобрение.text[:300]
    approved = _событие(store, "account.approved")
    assert (
        approved.actor == admin_id.id
    ), "субъект одобрения — администратор, а не автор приглашения"
    assert approved.entity == "user"
    assert approved.entity_id == _текст(цель.id)
    assert _детали(approved) == {
        "from": "awaiting_approval",
        "to": "active",
        "role": INVITED_ROLE,
    }
    assert цель.state == "active"


def test_блокировка_и_разблокировка_пишут_переходы_с_кодом_действия(
    store: MemoryStore, settings: Settings, kek: Path
) -> None:
    """Два `account.state_changed`: код действия, пара состояний, число закрытых сеансов.

    Код действия (`suspend`/`unsuspend`) — тот же, что сегмент адреса и ключ выбора доменного
    перехода: один список на три употребления, иначе адрес, действие и журнал разошлись бы при
    добавлении перехода. Отдельных `session.revoke` на сеансы, закрытые блокировкой, нет.
    """
    admin = _администратор(store, settings, kek)
    admin_id = store.user_by_login(ADMIN_LOGIN)
    assert admin_id is not None, "администратор не заведён"
    assert admin_id.id is not None

    цель = _завести(store, TARGET_LOGIN, role=INVITED_ROLE, state="active")
    assert цель.id is not None
    _выпустить_сеанс(store, цель.id, device="ноутбук-цели")

    блокировка = _мутация(
        admin,
        ADMIN_ACCOUNT_SUSPEND_PATH.format(**{USER_ID_PARAM: str(цель.id)}),
        token_path=ADMIN_USERS_PATH,
    )
    assert блокировка.status_code in (302, 303), блокировка.text[:300]
    переходы = _события(store, "account.state_changed")
    assert len(переходы) == 1, "блокировка обязана дать ровно одну строку перехода"
    first = переходы[0]
    assert first.actor == admin_id.id
    assert first.entity_id == _текст(цель.id)
    assert _детали(first) == {
        "action": ACTION_SUSPEND,
        "from": "active",
        "to": "suspended",
        "sessions_revoked": 1,
    }

    снятие = _мутация(
        admin,
        ADMIN_ACCOUNT_UNSUSPEND_PATH.format(**{USER_ID_PARAM: str(цель.id)}),
        token_path=ADMIN_USERS_PATH,
    )
    assert снятие.status_code in (302, 303), снятие.text[:300]
    переходы = _события(store, "account.state_changed")
    assert len(переходы) == 2, (
        "два действия — ровно две строки перехода: ни удвоения, ни потери второй нельзя "
        "различить по одной длине журнала"
    )
    second = переходы[1]
    assert _детали(second) == {
        "action": ACTION_UNSUSPEND,
        "from": "suspended",
        "to": "active",
    }
    assert _сколько(store, "session.revoke") == 0, (
        "сеансы, закрытые блокировкой, не плодят отдельные строки: реестр §8.7 даёт на такое "
        "решение одно имя"
    )


# ─── 2FA и резервные коды (§8.2, `ADR-013`, `ADR-015`, `ADR-016`) ─────────────────────────────


def test_привязка_2fa_подтверждение_и_пачка_кодов(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """`totp.enrolled` → `totp.confirmed` → `backup_codes.issued` (+ переход очереди одобрения).

    Учётная запись в состоянии `invited` проходит и четвёртое событие: подтверждённая привязка
    ставит её в очередь одобрения (`ADR-020` п. 3), и это изменение состояния учётной записи (§8.7),
    а не деталь привязки.
    """
    assert clock() == FROZEN, "привязка считает коды по `FROZEN`, а часы сдвинулись"
    владелец = _владелец(store)
    assert владелец.id is not None
    владелец.state = "invited"
    assert login(client).status_code == 302, "вход не состоялся"

    секрет, _ = _привязать(client)

    enrolled = _событие(store, "totp.enrolled")
    assert enrolled.entity == "user"
    assert enrolled.entity_id == _текст(владелец.id)
    assert _детали(enrolled)["replaced_unconfirmed"] == 0

    confirmed = _событие(store, "totp.confirmed")
    assert confirmed.entity_id == _текст(владелец.id)
    assert _детали(confirmed)["enrollment_id"] == str(store.enrollments()[0].id)

    issued = _событие(store, "backup_codes.issued")
    assert _детали(issued) == {"count": BACKUP_CODE_COUNT, "superseded": 0}
    assert _сколько(store, "backup_codes.invalidated") == 0, (
        "при первом выпуске аннулировать нечего: строка о нулевом аннулировании описывала бы "
        "действие, которого не было"
    )

    очередь = _событие(store, "account.state_changed")
    assert _детали(очередь) == {
        "action": "enqueue_for_approval",
        "from": "invited",
        "to": "awaiting_approval",
    }
    снимок = json.dumps([[row.action, row.details] for row in _все(store)], ensure_ascii=False)
    assert секрет not in снимок, "секрет привязки попал в журнал (§8.4, `ADR-013`)"
    assert not any(
        "secret" in str(row.details) for row in _все(store)
    ), "ключ `secret` в деталях: протокол отклоняет его как значение допуска (`ADR-025` п. 2)"
    _цепочка(store)


def test_код_входа_даёт_полный_вход_а_неудачный_код_пишет_попытку(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """`totp.verify_failed` — одна строка на отказ; успешный код — вторая `session.login`, `full`.

    Реестр §8.7 не даёт имени для «шаг поднят», и выдумывать его срез не вправе: полный вход
    описывается той же строкой `session.login` с другим `auth_step`, поэтому у входа с вторым
    фактором их две — выпуск сеанса после пароля и переход на `'full'` после кода.
    """
    владелец = _владелец(store)
    assert login(client).status_code == 302, "вход не состоялся"
    секрет, _ = _привязать(client)
    store.audit_rows.clear()

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    шаг = clock()
    отказ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client, path=TOTP_CODE_PATH), FIELD_CODE: "000000"},
        headers=_заголовки(),
        follow_redirects=False,
    )
    assert отказ.status_code == 401, отказ.text[:400]
    failed = _событие(store, "totp.verify_failed")
    assert failed.entity == "user"
    assert failed.entity_id == _текст(владелец.id)
    assert _детали(failed) == {"stage": "login_code"}

    успех = client.post(
        TOTP_CODE_PATH,
        data={
            CSRF_FORM_FIELD: _токен(client, path=TOTP_CODE_PATH),
            FIELD_CODE: totp_code(секрет, шаг),
        },
        headers=_заголовки(),
        follow_redirects=False,
    )
    assert успех.status_code == 302, успех.text[:400]
    полный = _событие(store, "session.login")
    assert _детали(полный) == {"auth_step": "full"}
    сеанс = store.find_by_secret(session_cookie(client))
    assert сеанс is not None, "сеанс после кода не найден"
    assert сеанс.id is not None
    assert полный.entity_id == _текст(сеанс.id)
    assert _сколько(store, "totp.verify_failed") == 1


def test_расход_резервного_кода_и_аннулирование_прежней_пачки(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """`backup_code.spent` с идентификатором строки; при повторной привязке — `invalidated`.

    Значения кода в журнале нет: протокол отклоняет ключ `code`/`code_hash`, а резервный код —
    одноразовый второй фактор (`ADR-016` п. 3, `ADR-025` п. 2). `spare_left` — тот же остаток,
    который видит человек.
    """
    владелец = _владелец(store)
    assert владелец.id is not None
    assert login(client).status_code == 302, "вход не состоялся"
    _, коды = _привязать(client)
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)

    расход = client.post(
        MFA_RECOVERY_PATH,
        data={CSRF_FORM_FIELD: _токен(client, path=MFA_RECOVERY_PATH), FIELD_BACKUP_CODE: коды[0]},
        headers=_заголовки(),
        follow_redirects=False,
    )
    assert расход.status_code == 200, расход.text[:600]
    spent = _событие(store, "backup_code.spent")
    assert spent.entity == "user"
    assert spent.entity_id == _текст(владелец.id)
    details = _детали(spent)
    assert details["spare_left"] == BACKUP_CODE_COUNT - 1
    assert isinstance(details["backup_code_id"], str)
    assert details["backup_code_id"], "событие обязано нести идентификатор строки кода"
    снимок = json.dumps(details, ensure_ascii=False)
    assert коды[0] not in снимок, "значение резервного кода попало в журнал (`ADR-016` п. 3)"
    assert коды[0].replace("-", "") not in снимок, (
        "значение резервного кода без разделителей попало в журнал: событие обязано нести "
        "`backup_code_id`, а не код (`ADR-025` п. 2)"
    )

    # Вторая церемония: привязка отзывается, неиспользованные остатки прежней пачки аннулируются.
    # Вход — новым клиентом: привязка относится к шагам входа (`TIER_CEREMONY`), и полный сеанс
    # на `/mfa-enroll` не пускается намеренно (`ADR-015` п. 3), поэтому повторная церемония
    # приходит тем же путём, которым её видит человек, — новый вход, а не кнут над хранилищем.
    for row in store.enrollments():
        row.revoked_at = clock()
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    новый = TestClient(client.app, base_url="https://testserver")
    assert login(новый).status_code == 302, "повторный вход не состоялся"
    _привязать(новый, clock())
    invalidated = _событие(store, "backup_codes.invalidated")
    assert _детали(invalidated) == {"count": BACKUP_CODE_COUNT - 1}
    assert _сколько(store, "backup_codes.issued") == 2
    _цепочка(store)


def test_реестр_держит_имена_событий_этого_файла() -> None:
    """Каждое имя события, которое проверяет файл, есть в закрытом реестре §8.7.

    Опечатка в имени не прошла бы записью (`AUDIT_ACTIONS` замкнут, `ADR-025` п. 2), но опечатка в
    *проверке* прошла бы зелёной и оставила бы событие §8.7 без наблюдателя: имена сверяются со
    справочником, а не берутся из кода маршрутов.
    """
    for action in (
        "session.login",
        "session.login_failed",
        "session.logout",
        "session.revoke",
        "session.revoke_all",
        "account.password_changed",
        "account.created",
        "account.approved",
        "account.state_changed",
        "invitation.issued",
        "invitation.accepted",
        "invitation.accept_failed",
        "invitation.revoked",
        "totp.enrolled",
        "totp.confirmed",
        "totp.verify_failed",
        "backup_codes.issued",
        "backup_codes.invalidated",
        "backup_code.spent",
    ):
        assert action in AUDIT_ACTIONS, f"{action} нет в закрытом реестре §8.7 (`ADR-025` п. 2)"
