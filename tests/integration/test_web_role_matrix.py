"""Матрица «маршрут × роль»: `test_role_matrix`, `AC-identity-01` и отказ без утечки (`T-106`, `R6`).

Таблица `ROUTE_POLICY` в этом файле — единственное место, где описано, какой маршрут требует
какого уровня допуска. Она же кормит контрактную проверку
(`tests/contract/test_web_roles_contract.py::test_таблица_допуска_покрывает_каждый_маршрут_приложения`):
таблицу с реальным перечнем маршрутов приложения и с зависимостью-стражем, которая у маршрута
действительно стоит. Таблица, которая расходится с маршрутами, даёт красный тест, а не тихую дыру —
того же рода приём, что перечень мутаций `ADR-008` и перечень живых групп базы.

Что проверяется и чего это стоит:

1. **Каждый маршрут × каждая роль** (`REQ-identity-01`: ровно три роли, проверка на уровне сервиса).
   Это не «три проверки на одном щупе»: запрос идёт по настоящему адресу приложения, собранного
   `create_app`, поэтому отказ роли отличается от отказа сеанса поведением, а не домыслом.
2. **`AC-identity-01`**: `operator` открывает `/admin/users` → `403`, и в ответе нет ни имён
   пользователей, ни счётчиков. Отказ обязан быть побайтово одинаковым для `operator` и `viewer`,
   иначе по различию ответов становится различим уровень, который сработал.
3. **Владение объектом** (§8.8 «доступ `operator` к чужим данным → 403/404 без утечки»): чужой `id`
   отзываемого сеанса и никогда не существовавший отвечают одинаково, и чужой отзыв не происходит.
4. **Отказ неотличим по причине**: роль ниже требуемой, роль вне закрытого набора (§1.1) и сеанс без
   строки учётной записи дают одно и то же тело.
5. **Выход не требует роли** (`ADR-017` п. 6): отказ в выходе оставил бы живой вход у того, кто
   просит его закрыть.

Граница честности. Репозиторий здесь — `MemoryStore`: он проверяет поведение слоя входа, но не
проверяет ни то, что предикат `user_id` действительно уходит в `SELECT` и попадает в индекс, ни
CHECK-ограничение `ck_users_role` (которое в памяти не исполняется вовсе), ни то, что роль читается
из таблицы, а не из кэша процесса. Живую половину держит job `миграции`: предикат и индекс —
`tests/integration/test_web_sessions_db.py` (файл уже зарегистрирован в шаге CI; новых живых групп
этот срез не заводит), набор значений роли — `tests/contract/test_identity_schema.py` и
`tests/integration/test_identity_schema_db.py`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.routes.admin_users import (
    ADMIN_ACCOUNT_APPROVE_PATH,
    ADMIN_ACCOUNT_ARCHIVE_PATH,
    ADMIN_ACCOUNT_ROLE_PATH,
    ADMIN_ACCOUNT_SUSPEND_PATH,
    ADMIN_ACCOUNT_TOTP_RESET_PATH,
    ADMIN_ACCOUNT_UNSUSPEND_PATH,
    ADMIN_INVITATION_REVOKE_PATH,
    ADMIN_INVITATIONS_PATH,
    ADMIN_USERS_NOTE,
    ADMIN_USERS_PATH,
)
from apps.web.routes.notifications import ADMIN_NOTIFICATIONS_PATH
from apps.web.security.authorization import DENIAL_BODY
from apps.web.security.csrf import CSRF_FORM_FIELD, csrf_token_for
from apps.web.security.sessions import (
    INVITE_PATH,
    LOCKED_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    MFA_RECOVERY_PATH,
    SECURITY_PATH,
    SESSION_EXPIRED_PATH,
    SESSION_REVOKE_PATH,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.identity.authorization import (
    ADMIN_TIER,
    CONSOLE_TIER,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    ROLES,
)
from packages.storage.models import User, UserSession
from tests.integration.web_support import (
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
    session_cookie,
)

# ─── уровни допуска ───────────────────────────────────────────────────────────────────────────

#: Уровень «служебный каркас: ответа на этот адрес охрана не касается» (`/healthz`, `/readyz`,
#: `/metrics`, корневая заглушка `M0`). Он обязан быть в таблице, иначе маршрут без охраны выглядит
#: «забытым», а не «осознанным».
TIER_INFRA: Final = "infra"

#: Уровень «церемония входа»: живой сеанс не нужен, а роли ещё нет — человека с ролью на этих
#: адресах быть не может (`security/authorization.py`, `ADR-017` п. 6).
TIER_CEREMONY: Final = "ceremony"

#: Уровень «охрана есть, роли нет»: выход (§8.2 разрешает его на любом шаге входа). Обоснование —
#: `ADR-017` п. 6.
TIER_SESSION: Final = "session"

#: Уровень раздела «Профиль и безопасность»: любая из трёх ролей (§9.3 п. 4–5 «любая роль»).
TIER_ANY_ROLE: Final = "any_role"

#: Уровень раздела «Администрирование»: роль `admin` (§9.3 п. 6–10).
TIER_ADMIN: Final = "admin"


@dataclass(frozen=True)
class Policy:
    """Строка таблицы допуска: уровень, разрешённые коды ответа и обоснование уровня.

    `note` обязана быть непустой у каждой строки: обоснование уровня — то, что проверяющий читает
    первым, и «уровень выбран на глаз» в этом перечне не принимается (тот же порядок, что у перечня
    мутаций без CSRF-токена в `ADR-008`).
    """

    tier: str
    allowed: frozenset[int]
    note: str


#: Маршрут → допуск. Ключ — `(путь, метод)` ровно в той форме, в какой путь отдаёт OpenAPI-схема
#: приложения; контрактная проверка сверяет множество ключей с реальным перечнем маршрутов, поэтому
#: новый маршрут обязан появиться здесь, а не «дожить до приёмки».
ROUTE_POLICY: Final[dict[tuple[str, str], Policy]] = {
    ("/", "GET"): Policy(
        TIER_INFRA,
        frozenset({200}),
        "заглушка каркаса `M0` (`apps/web/main.py`): ответа касаются заголовки §8.3, а не охрана",
    ),
    ("/healthz", "GET"): Policy(
        TIER_INFRA,
        frozenset({200}),
        "liveness для оркестратора: доступ изнутри состава, внешних проверок нет намеренно",
    ),
    ("/readyz", "GET"): Policy(
        TIER_INFRA,
        frozenset({503}),
        "readiness: без адреса базы ответ `503` — проверка готовности, а не маршрут пользователя",
    ),
    ("/metrics", "GET"): Policy(
        TIER_INFRA,
        frozenset({200}),
        "метрики собирает оркестратор из внутренней сети состава (`ADR-003`: наружу — только Caddy)",
    ),
    (LOGIN_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({200}),
        "форма входа: сеанса ещё нет, токен CSRF выводить не из чего (`ADR-009`)",
    ),
    (LOGIN_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "сам вход: охрана — источник запроса, частота по адресу и блокировка учётки (§8.2)",
    ),
    (SESSION_EXPIRED_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({200}),
        "объясняющая страница состояния: охранять её редиректом означало бы петлю (§9)",
    ),
    (LOCKED_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({200}),
        "страница блокировки входа: она показывается именно тому, у кого живого сеанса нет",
    ),
    (TOTP_CODE_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "страница кода: полный вход на неё не пускается (`ADR-015` п. 3), поэтому `302` на консоль",
    ),
    (TOTP_CODE_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "ввод кода входа: токен, счётчик и шаг страницы; с `'full'` — тот же редирект",
    ),
    (MFA_ENROLL_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "первичная привязка: доступна на шаге `'password'`/`'totp'`, но не полного входа",
    ),
    (MFA_ENROLL_START_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "выдача секрета привязки: материал доступа, охрана — шаг страницы и токен (§8.2)",
    ),
    (MFA_ENROLL_VERIFY_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "подтверждение привязки и выдача пачки (`ADR-016` п. 2): тот же уровень допуска",
    ),
    (MFA_RECOVERY_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "резервный путь нужен до полного входа; расход кода и есть шаг полной аутентификации",
    ),
    (MFA_RECOVERY_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({302}),
        "расход резервного кода: счётчик второй попытки (§8.2) и guarded-`UPDATE` (`ADR-016` п. 7)",
    ),
    (LOGOUT_PATH, "POST"): Policy(
        TIER_SESSION,
        frozenset({302}),
        "выход не требует роли: отказ в выходе оставил бы живой вход у того, кто просит закрыть "
        "доступ (`ADR-017` п. 6); охрана — токен, счётчик и живость сеанса",
    ),
    (SESSIONS_PATH, "GET"): Policy(
        TIER_ANY_ROLE,
        frozenset({200}),
        "список своих сеансов: §9.3 п. 4 держит раздел профиля доступным любой роли",
    ),
    (SESSIONS_REVOKE_ALL_PATH, "GET"): Policy(
        TIER_ANY_ROLE,
        frozenset({200}),
        "страница подтверждения «отозвать все»: `GET` ничего не меняет (`ADR-010`)",
    ),
    (SESSIONS_REVOKE_ALL_PATH, "POST"): Policy(
        TIER_ANY_ROLE,
        frozenset({302}),
        "отзыв всех своих сеансов: мутация профиля, включая текущий сеанс (`ADR-010`)",
    ),
    (SESSION_REVOKE_PATH, "GET"): Policy(
        TIER_ANY_ROLE,
        frozenset({404}),
        "подтверждение отзыва одного сеанса: в матрице адрес проверяется идентификатором"
        "которого не существовало никогда → `404` без подробностей; чужой живой `id`"
        "держит отдельная проверка владения ниже",
    ),
    (SESSION_REVOKE_PATH, "POST"): Policy(
        TIER_ANY_ROLE,
        frozenset({404}),
        "отзыв одного сеанса: в матрице — идентификатор, которого не существует (`404`);"
        "чтобы отзыв чужого живого сеанса не произошёл, есть отдельная проверка"
        "владения ниже (§8.8 «403/404 без утечки»)",
    ),
    (SECURITY_PATH, "GET"): Policy(
        TIER_ANY_ROLE,
        frozenset({200}),
        "страница смены пароля: §9.3 п. 5, раздел профиля доступен любой роли (§1.1)",
    ),
    (SECURITY_PATH, "POST"): Policy(
        TIER_ANY_ROLE,
        frozenset({400}),
        "смена пароля пустой формой → `400`: отказ формы наступает до сравнения текущего пароля",
    ),
    (ADMIN_USERS_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({200}),
        "раздел администратора из карты §9.3 п. 6: адрес занят допуском, содержимое строит срез `R7b` (`T-105`)",
    ),
    (ADMIN_NOTIFICATIONS_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({200}),
        "журнал решений порога уведомлений (§8.7, `T-116`, `ADR-028`): страница только "
        "читает `web_audit_outbox`, мутаций нет, поэтому CSRF-цепочка не участвует "
        "(`ADR-008`); канал доставки не заведён (`T-714`), и раздел не обещает отправку",
    ),
    (ADMIN_INVITATIONS_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({400}),
        "выпуск приглашения: пустая форма → `400`, потому что адресата требует домен (§1.2); "
        "значение ссылки показывается ровно один раз в ответе выпуска (`ADR-020` п. 3)",
    ),
    (ADMIN_INVITATION_REVOKE_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "подтверждение отзыва выпуска: в матрице адрес проверяется идентификатором, которого не "
        "существовало никогда → `404` без подробностей; отзыв живого выпуска держит отдельная "
        "проверка ниже (`ADR-020` п. 4)",
    ),
    (ADMIN_INVITATION_REVOKE_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "отзыв выпуска guarded-`UPDATE`-ом: в матрице — несуществующий `id` (`404`); что отзыв "
        "не закрывает уже принятую учётную запись, проверяет отдельная проверка ниже",
    ),
    (ADMIN_ACCOUNT_APPROVE_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "одобрение (§1.2 шаг 2): в матрице — несуществующий `id` учётной записи; переход "
        "`awaiting_approval → active` и отметку автора делает домен (`ADR-020` п. 3)",
    ),
    (ADMIN_ACCOUNT_SUSPEND_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "страница подтверждения блокировки: `GET` ничего не меняет (§9.1), в матрице — "
        "несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_SUSPEND_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "блокировка: в матрице — несуществующий `id`; для живого объекта порядок «счёт "
        "администраторов → переход → отзыв сеансов» проверяет отдельная проверка ниже (§8.3, "
        "`ADR-020` п. 6)",
    ),
    (ADMIN_ACCOUNT_UNSUSPEND_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "разблокировка: действие открывает доступ, поэтому подтверждающей страницы нет; в "
        "матрице — несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_ARCHIVE_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "страница подтверждения архивирования: переход терминальный (§1.2), подтверждение "
        "обязано называть объект (§9.1); в матрице — несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_ARCHIVE_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "архивирование: тот же порядок закрытия доступа, что у блокировки, и отсутствие "
        "обратного перехода; в матрице — несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_ROLE_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "окно смены роли: `GET` ничего не меняет (§9.1); страница показывает выбор значений, "
        "поэтому она отдельная, а не общая страница подтверждения; в матрице — несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_ROLE_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "смена роли (§9.3 п. 6): правка поля вместо перехода состояния, но тот же счёт живых "
        "администраторов до правки и тот же страж последнего администратора, только по будущей "
        "роли (§8.7, `ADR-020` п. 6); живые сеансы цели не отзываются — роль читается на каждый "
        "охраняемый запрос (`ADR-017` п. 7); в матрице — несуществующий `id`",
    ),
    (ADMIN_ACCOUNT_TOTP_RESET_PATH, "GET"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "страница сброса второго фактора: `GET` ничего не меняет (§9.1), показывает состояние "
        "привязки цели и требует код администратора (§8.1, §9.3 п. 6); в матрице — несуществующий "
        "`id`",
    ),
    (ADMIN_ACCOUNT_TOTP_RESET_PATH, "POST"): Policy(
        TIER_ADMIN,
        frozenset({404}),
        "сброс 2FA администратором (§9.3 п. 6, §8.1 случай «без восстановления по почте»): цепочка "
        "допуска та же, плюс обязательный код второго фактора администратора; вместе с привязкой "
        "отзываются живые сеансы цели и аннулируются неиспользованные резервные коды (§8.2, "
        "`ADR-016` п. 6); в матрице — несуществующий `id`",
    ),
    (INVITE_PATH, "GET"): Policy(
        TIER_CEREMONY,
        frozenset({404}),
        "приём приглашения по одноразовой ссылке: без значения ссылки страница, принимающая "
        "пароль, не существует — `404`; что это не открытая регистрация, держит "
        "`test_no_public_registration.py` (`ADR-020` п. 3, `ADR-021` п. 3)",
    ),
    (INVITE_PATH, "POST"): Policy(
        TIER_CEREMONY,
        frozenset({404}),
        "приём ссылки без действующего значения: адрес не смотрит на тело формы и отвечает `404` "
        "(тот же ответ, что у `GET` — §8.8 «один ответ на несколько случаев»); роли ещё нет, "
        "поэтому вместо токена сеанса — проверка источника и частота по адресу (`ADR-021` п. 2), "
        "а отказ формы `400` держит `test_invitation_flow`",
    ),
}

#: Уровни, у которых обязан стоять страж роли, и имя зависимости-стража для `GET`. Контрактный тест
#: сверяет имя с реальным деревом зависимостей маршрута, поэтому переименование стража красное, а не
#: «тихо разошлось».
GET_GUARDS: Final[dict[str, str]] = {
    TIER_ANY_ROLE: "require_console_role",
    TIER_ADMIN: "require_admin_role",
}

#: То же для мутаций: имя стража, которое обязано появиться в дереве зависимостей мутационного
#: маршрута того же уровня. Раздел администратора добавлен срезом `R7b` (`T-105`): у него своя
#: зависимость `require_admin_role_mutation`, а не `require_admin_role` рядом с `FullMutation`,
#: потому что живой сеанс проверялся бы дважды и два обращения к строке сеанса могли бы увидеть
#: разные состояния (сеанс отозвали другим входом между ними).
MUTATION_GUARDS: Final[dict[str, str]] = {
    TIER_ANY_ROLE: "require_console_role_mutation",
    TIER_ADMIN: "require_admin_role_mutation",
}

#: Все имена стражей: контракт проверяет, что у маршрута без уровня роли ни один из них не стоит.
ALL_GUARDS: Final[frozenset[str]] = frozenset([*GET_GUARDS.values(), *MUTATION_GUARDS.values()])

#: Логины тестовых учётных записей по ролям: три учётки, потому что матрица обязана прогонять
#: каждый маршрут каждой ролью, а не «одной учёткой с подменённым полем». Значения намеренно
#: непохожи на реальные: проверка утечки ищет их в тексте отказа как канареек.
ROLE_LOGINS: Final[dict[str, str]] = {
    ROLE_ADMIN: "ad.matriks-r6",
    ROLE_OPERATOR: "op.matriks-r6",
    ROLE_VIEWER: "vw.matriks-r6",
}

#: Порядок ролей для параметризации. Равенство набору домена держит отдельная проверка ниже (и она
#: же — в `tests/unit/test_authorization_roles.py`).
ROLE_SEQUENCE: Final[tuple[str, ...]] = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER)

#: Заведомо несуществующий идентификатор объекта: половина проверок «чужой/несуществующий».
STRANGE_ID: Final = UUID("00000000-0000-0000-0000-000000000000")

#: Адреса запросов: каждой попытке — свой адрес, как в `test_web_backup_codes.py`, чтобы лимит
#: частоты по адресу (§8.3) не подменил собой проверяемое поведение допуска.
ADDRESSES: Final[tuple[str, ...]] = tuple(f"203.0.113.{index}" for index in range(1, 40))


# ─── обвязка ───────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def store() -> MemoryStore:
    """Три учётные записи — по одной на роль, с заполненными `id`.

    `id` ставятся явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не срабатывает, а предикаты
    репозитория (`user_of_id`, `session_of_user`) сравнивают `id`. С `None` у всех трёх проверка
    владения сравнивала бы `None` с `None` и проходила бы молча — ровно та ловушка, на которой
    уже горели проверки `R5c`.
    """
    memory = MemoryStore()
    for роль, login_value in ROLE_LOGINS.items():
        account = memory.seed_user(login=login_value, role=роль)
        account.id = uuid4()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> Iterator[TestClient]:
    """Боевое приложение с репозиторием в памяти; щупы не нужны — админский адрес настоящий."""
    with build_client(store, settings) as test_client:
        yield test_client


def _headers(address_index: int = 1) -> dict[str, str]:
    return {
        "Origin": "https://testserver",
        "User-Agent": "role-matrix-test",
        "X-Forwarded-For": ADDRESSES[address_index % len(ADDRESSES)],
    }


def _войти(client: TestClient, роль: str) -> Response:
    """Войти учётной записью выбранной роли; кука остаётся в клиенте."""
    return login(client, login_value=ROLE_LOGINS[роль], password=TEST_PASSWORD)


def _сеанс(client: TestClient, store: MemoryStore) -> UserSession:
    """Запись сеанса текущего клиента (по предъявленной куке, как это делает слой входа)."""
    record = store.find_by_secret(session_cookie(client))
    assert record is not None, "сеанс не найден — вход не состоялся"
    return record


def _шаг(client: TestClient, store: MemoryStore) -> str:
    """Шаг входа текущего сеанса.

    После входа паролем это всегда `'password'`: поднятие шага — отдельный помощник, а не
    побочный эффект входа.
    """
    return _сеанс(client, store).auth_step


def _поднять_до_full(client: TestClient, store: MemoryStore) -> None:
    """Поднять сеанс до шага `'full'`, не проходя TOTP-церемонию.

    Предмет этого файла — роль, а не вторая половина входа. Шаг `'full'` приложение
    производит и производит именно так, как описано в §8.2 (код 2FA или резервный код), и это
    держат отдельные файлы с настоящей привязкой и `kek.json`: `test_web_totp_page.py` и
    `test_web_backup_codes.py` (там же матрица §8.8 «шаг × маршрут»). Пересобирать церемонию
    в каждом файле значило бы проверать роль кодом 2FA, а не ролью: отказ роли утонул бы в
    отказе шага, и различить их в тексте падения было бы нельзя.

    Состояние при этом не поддельное: `auth_step` — то же значение, которое держит база
    (CHECK закрытого набора шагов, ревизия `0002`), и `ensure_full_auth` читает его так же,
    как на боевом пути. Проверка ниже держит и обратное: пока шаг не поднят, охрана роли до
    отказа роли вообще не доходит.
    """
    record = _сеанс(client, store)
    assert record.auth_step == "password", "вход паролем обязан оставить сеанс на шаге пароля"
    record.auth_step = "full"
    assert record.auth_step == "full"


def _токен(client: TestClient, store: MemoryStore) -> str:
    """CSRF-токен текущего сеанса (`ADR-008`): значение выводится из куки и `id` сеанса.

    Токен считается, а не вычитывается из страницы: страница раздела администратора для
    не-администратора не существует, а читать meta из отказного ответа означало бы проверять
    «отказ содержит разметку», чего здесь проверяется ровно ноль.
    """
    secret = session_cookie(client)
    return csrf_token_for(secret, _сеанс(client, store).id)


def _учётка(store: MemoryStore, роль: str) -> User:
    account = store.user_by_login(ROLE_LOGINS[роль])
    assert account is not None, "тестовой учётной записи роли нет в репозитории"
    return account


def _вызвать(
    client: TestClient,
    store: MemoryStore,
    method: str,
    path: str,
    роль: str,
    *,
    address_index: int = 1,
    object_id: UUID = STRANGE_ID,
) -> Response:
    """Вызвать маршрут так же, как его вызывает браузер: форма с токеном, `Origin`, адрес.

    `follow_redirects=False` обязателен: иначе вместо решения слоя входа (редирект §8.2 или `403`)
    тест получил бы итоговую страницу, и «роль не пущена» перестал бы отличаться от «роль пустила,
    и страница редиректит».
    """
    url = path
    for элемент in (
        "{session_id}",
        "{user_id}",
        "{invitation_id}",
    ):
        url = url.replace(элемент, str(object_id))

    headers = _headers(address_index)
    # Ответ `TestClient` типизирован как `Any` (стубов у
    # httpx-перегрузок нет), поэтому ответ держится в
    # переменной с аннотацией: иначе вся матрица
    # сравнивает статусы у `Any`, и опечатка в имени
    # атрибута ответа прошла бы незамеченной.
    if method == "GET":
        ответ: Response = client.get(url, headers=headers, follow_redirects=False)
    elif path == LOGIN_PATH:
        ответ = client.post(
            url,
            data={"login": ROLE_LOGINS[роль], "password": TEST_PASSWORD},
            headers=headers,
            follow_redirects=False,
        )
    else:
        ответ = client.post(
            url,
            data={CSRF_FORM_FIELD: _токен(client, store)},
            headers=headers,
            follow_redirects=False,
        )
    return ответ


def _отказ_допуска(ответ: Response) -> bool:
    """`403` ровно тем телом, которым отвечает отказ допуска, а не другим `403` (CSRF, например)."""
    return ответ.status_code == 403 and ответ.json() == DENIAL_BODY


# ─── матрица «маршрут × роль» ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("роль", ROLE_SEQUENCE)
@pytest.mark.parametrize(("path", "method"), sorted(ROUTE_POLICY))
def test_role_matrix(
    path: str, method: str, роль: str, client: TestClient, store: MemoryStore
) -> None:
    """Каждый маршрут приложения — каждой из трёх ролей (§1.1, `AC-identity-01`).

    Ожидаемое поведение берётся из `ROUTE_POLICY`, а не из кода маршрута: если уровень допуска
    меняется в коде, таблица остаётся напоминанием, что поведение менялось осознанно, и тест
    требует описать новое (или вернуть старое).

    Смысл проверки двоякий. Для уровней с охраной роли: разрешённой роли маршрут обязан ответить
    штатно, а неразрешённой — ровно отказом допуска (не редиректом «сеанс не подходит», не `404`,
    не `500`). Для уровней без охраны: ответ не зависит от роли вовсе, потому что роль там ещё не
    определена.
    """
    policy = ROUTE_POLICY[(path, method)]
    assert policy.note, f"{method} {path}: строка таблицы без обоснования уровня допуска"
    assert policy.tier in {
        TIER_INFRA,
        TIER_CEREMONY,
        TIER_SESSION,
        TIER_ANY_ROLE,
        TIER_ADMIN,
    }, f"{method} {path}: уровень {policy.tier!r} вне закрытого набора уровней"

    assert _войти(client, роль).status_code == 302, f"вход ролью {роль!r} не состоялся"
    _поднять_до_full(client, store)

    ответ = _вызвать(client, store, method, path, роль)

    if policy.tier == TIER_ADMIN and роль != ROLE_ADMIN:
        assert _отказ_допуска(ответ), (
            f"{method} {path} ролью {роль!r} ответил {ответ.status_code} вместо отказа допуска: "
            "роль администратора требуется по §9.3 п. 6"
        )
        return

    assert ответ.status_code in policy.allowed, (
        f"{method} {path} ролью {роль!r}: код {ответ.status_code}, ожидалось "
        f"{sorted(policy.allowed)} ({policy.note})"
    )
    assert not _отказ_допуска(
        ответ
    ), f"{method} {path} ролью {роль!r} вернулся отказом допуска при уровне {policy.tier!r}"


# ─── `AC-identity-01`: 403 без утечки списка пользователей ────────────────────────────────────


@pytest.mark.parametrize("роль", [ROLE_OPERATOR, ROLE_VIEWER])
def test_отказ_админского_раздела_не_содержит_имён_и_счётчиков(
    роль: str, client: TestClient, store: MemoryStore
) -> None:
    """Сценарий `AC-identity-01` буквальным адресом: `operator` → `/admin/users` → `403`.

    Проверяются три вещи, и все три — про тело ответа, а не про код:

    * ни одного логина из таблицы — `AC-identity-01` называет утечку прямо («ни имён, ни счётчиков»);
    * ни цифр: счётчик учётных записей — тоже утечка, и он же подсказывает, сколько учётных записей
      находится за этой границей;
    * тело побайтово равно `DENIAL_BODY`. Ни имени требуемой роли, ни пути раздела в ответе нет:
        подставив требуемую роль, ответ начал бы различать границы доступа, и перебором стало бы
        видно, какой уровень за чем отвечает.
    """
    assert _войти(client, роль).status_code == 302
    _поднять_до_full(client, store)
    ответ = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)

    assert ответ.status_code == 403, ответ.text[:200]
    assert ответ.json() == DENIAL_BODY
    текст = ответ.text
    for login_value in ROLE_LOGINS.values():
        assert login_value not in текст, f"в отказе утёк логин {login_value!r}"
    assert not any(символ.isdigit() for символ in текст), f"в отказе есть цифры: {текст!r}"
    assert ADMIN_USERS_NOTE not in текст, "отказ выдал текст админской страницы — уровни смешались"


def test_отказ_админского_раздела_одинаков_для_operator_и_viewer(
    client: TestClient, store: MemoryStore
) -> None:
    """Ответы двух неразрешённых ролей побайтово совпадают.

    Если бы «оператору нельзя» и «наблюдателю нельзя» отвечали по-разному, различие ответов стало бы
    способом проверить, какая именно граница сработала, не имея ни одной привилегии. Требование того
    же рода, что `ADR-016` п. 5 для резервных кодов.
    """
    ответы = []
    for роль in (ROLE_OPERATOR, ROLE_VIEWER):
        assert _войти(client, роль).status_code == 302
        _поднять_до_full(client, store)
        ответы.append(client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False))
    первый, второй = ответы
    assert (первый.status_code, первый.content) == (
        второй.status_code,
        второй.content,
    ), "отказы двух ролей различаются: ответ становится оракулом уровня допуска"


def test_отказ_роли_не_меняет_состояния_своего_раздела(
    client: TestClient, store: MemoryStore
) -> None:
    """Отказ роли наступает до чтения данных: побочного эффекта у него нет.

    `operator` открывает адрес администратора, а затем свою страницу сеансов — она обязана открыться
    как ни в чём не бывало: отказ не отзывает сеанс, не двигает счётчик неудач входа (§8.2 считает
    попытки второго фактора, а не попытки залезть в админку) и не даёт редирект «сеанс не
    подходит». Иначе «попытка» стала бы способом устроить отказ в обслуживании самому себе.
    """
    assert _войти(client, ROLE_OPERATOR).status_code == 302
    _поднять_до_full(client, store)
    отказ = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert отказ.status_code == 403

    своя_страница = client.get(SESSIONS_PATH, headers=_headers(), follow_redirects=False)
    assert своя_страница.status_code == 200, "отказ роли отнял доступ к собственному разделу"
    assert _шаг(client, store) == "full", "отказ роли понизил шаг входа"


def test_шаг_входа_важнее_роли(client: TestClient, store: MemoryStore) -> None:
    """Пока сеанс на шаге `'password'`, охрана роли до отказа роли не доходит (§8.2).

    Порядок закреплён `ADR-017` п. 3 и он не косметика: человеку с верным паролем, но без кода
    2FA направление отказа одно для всех закрытых маршрутов — страница кода. Если бы роль
    проверялась раньше, такой человек получил бы `403` «недостаточно прав» вместо «введите код»,
    а ответ начал бы сообщать, какой уровень у его учётной записи, до того как он доказал,
    что он вообще он.
    """
    assert _войти(client, ROLE_OPERATOR).status_code == 302
    assert _шаг(client, store) == "password", "после входа паролем шаг — парольный"

    отказ = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert (
        отказ.status_code == 302
    ), f"сеанс шага 'password' получил {отказ.status_code} вместо редиректа на страницу кода"
    assert отказ.headers["location"] == TOTP_CODE_PATH
    assert not _отказ_допуска(отказ), "отказ роли наступил раньше отказа шага входа"


# ─── владение объектом (§8.8) ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("роль", ROLE_SEQUENCE)
def test_чужой_объект_и_несуществующий_отвечают_одинаково(
    роль: str, client: TestClient, store: MemoryStore
) -> None:
    """«Чужой», «кривой» и «никогда не существовавший» `id` — один ответ (§8.8, `ADR-017` п. 4).

    Чужой `id` берётся из настоящего живого сеанса **другой** учётной записи (для роли-администратора
    жертвой выступает оператор, и наоборот): проверка не по выдуманному значению, а по объекту,
    который существует и который нельзя отозвать чужой рукой. Ответ обязан совпасть побайтово с
    ответом на никогда не существовавший `id` — иначе страница отзыва стала бы оракулом «есть такой
    сеанс или нет». И отдельная часть утверждения: чужой сеанс остался живым.
    """
    роль_жертвы = ROLE_OPERATOR if роль == ROLE_ADMIN else ROLE_ADMIN

    assert _войти(client, роль_жертвы).status_code == 302
    _поднять_до_full(client, store)
    чужой_сеанс = _сеанс(client, store)
    assert чужой_сеанс.revoked_at is None
    чужой_id = чужой_сеанс.id
    assert (
        _учётка(store, роль_жертвы).id != _учётка(store, роль).id
    ), "жертва и заявитель — одна учётная запись: «чужой» объект перестал быть чужим"

    assert _войти(client, роль).status_code == 302
    _поднять_до_full(client, store)

    чужой = client.get(
        f"{SESSIONS_PATH}/{чужой_id}/revoke", headers=_headers(), follow_redirects=False
    )
    нет_такого = client.get(
        f"{SESSIONS_PATH}/{STRANGE_ID}/revoke", headers=_headers(), follow_redirects=False
    )
    assert чужой.status_code == 404 == нет_такого.status_code, (
        f"чужой → {чужой.status_code}, несуществующий → {нет_такого.status_code}: ответ различает "
        "существование объекта (§8.8 допускает 403/404, но не два разных ответа)"
    )
    assert чужой.content == нет_такого.content, "тела различаются — страница отзыва стала оракулом"

    мутация_чужого = client.post(
        f"{SESSIONS_PATH}/{чужой_id}/revoke",
        data={CSRF_FORM_FIELD: _токен(client, store)},
        headers=_headers(),
        follow_redirects=False,
    )
    assert мутация_чужого.status_code == 404, "чужой сеанс отозван чужой учётной записью"
    # Тот же объект, что держит репозиторий в памяти (identity map работает и здесь): правка
    # `revoked_at` была бы видна без всякого поиска по значению куки.
    assert чужой_сеанс.revoked_at is None, "чужой сеанс всё-таки отозван"


# ─── причины отказа неотличимы ────────────────────────────────────────────────────────────────


def test_роль_вне_закрытого_набора_отклоняется_тем_же_отказом(
    client: TestClient, store: MemoryStore
) -> None:
    """Значение `users.role` вне набора §1.1 не получает прав и не объясняет причину.

    Схема ограничивает значение CHECK-ограничением, поэтому в живой базе такого значения нет;
    офлайн-проверка получает его, записав роль прямо в объект памяти (CHECK в памяти не
    исполняется). Смысл проверки в том, что сервис не «разбирается, какая роль хуже», а отвечает
    отказом, неотличимым от отказа по роли: роль `superuser` не обязана превращаться ни в «пустые
    права», ни, что хуже, в «неизвестная роль, значит пропускаем».
    """
    assert _войти(client, ROLE_OPERATOR).status_code == 302
    _поднять_до_full(client, store)
    _учётка(store, ROLE_OPERATOR).role = "superuser"

    профиль = client.get(SECURITY_PATH, headers=_headers(), follow_redirects=False)
    assert профиль.status_code == 403, "роль вне набора пустила в раздел профиля"
    assert профиль.json() == DENIAL_BODY

    админка = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert админка.status_code == 403
    assert (
        профиль.content == админка.content
    ), "отказ по «неизвестной роли» отличается от отказа по роли — причина просочилась в ответ"


def test_сеанс_без_строки_учётной_записи_отклоняется_одинаково_на_обоих_уровнях(
    client: TestClient, store: MemoryStore
) -> None:
    """«Учётной записи сеанса больше нет» — отказ, неотличимый от нехватки прав.

    Состояние реальное (архивация строки, ручная правка таблицы), и объясняющей страницы у него нет
    намеренно: страница «вас удалили» тому, у кого живая кука, сообщила бы состояние учётной записи.
    Причина различается только журналом (`access_denied` + `reason`), и именно это делает закрытый
    набор `DENIAL_REASONS` безопасным.
    """
    assert _войти(client, ROLE_ADMIN).status_code == 302
    _поднять_до_full(client, store)
    store.drop_user(ROLE_LOGINS[ROLE_ADMIN])

    профиль = client.get(SESSIONS_PATH, headers=_headers(), follow_redirects=False)
    админка = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert профиль.status_code == админка.status_code == 403
    assert профиль.json() == админка.json() == DENIAL_BODY


def test_выход_работает_без_роли_и_без_строки_учётной_записи(
    client: TestClient, store: MemoryStore
) -> None:
    """Испорченные данные не должны мешать закрыть доступ (`ADR-017` п. 6).

    Роль вне набора плюс отсутствующая строка учётной записи: выход обязан отозвать сеанс. Отказ в
    выходе при таких данных означал бы «живой вход остаётся живым, пока кто-то не починит таблицу»,
    то есть ровно противоположность тому, чего человек просит.
    """
    assert _войти(client, ROLE_VIEWER).status_code == 302
    secret = session_cookie(client)
    _учётка(store, ROLE_VIEWER).role = "superuser"
    store.drop_user(ROLE_LOGINS[ROLE_VIEWER])

    ответ = client.post(
        LOGOUT_PATH,
        data={CSRF_FORM_FIELD: _токен(client, store)},
        headers=_headers(),
        follow_redirects=False,
    )
    assert ответ.status_code == 302, ответ.text[:200]
    record = store.find_by_secret(secret)
    assert record is not None, "после выхода сеанс пропал из репозитория"
    assert record.revoked_at is not None, "выход не отозвал сеанс"


def test_смена_роли_применяется_немедленно(client: TestClient, store: MemoryStore) -> None:
    """Роль читается из репозитория на каждый запрос: кэша прав в процессе нет.

    Администратор открыл раздел, затем его роль понизили. Следующий запрос обязан быть отказом — по
    той же причине, по которой §8.3 требует немедленной видимости отзыва сеанса: окно, в котором уже
    снятый с прав человек остаётся администратором, измеряется временем жизни процесса `web`.
    """
    assert _войти(client, ROLE_ADMIN).status_code == 302
    _поднять_до_full(client, store)
    first = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert first.status_code == 200
    assert ADMIN_USERS_NOTE in first.text, "администратору ответ обязан честно называть задачу"

    _учётка(store, ROLE_ADMIN).role = ROLE_VIEWER
    second = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert (
        second.status_code == 403
    ), "роль закэширована: смена применилась бы только после рестарта"

    профиль = client.get(SESSIONS_PATH, headers=_headers(), follow_redirects=False)
    assert профиль.status_code == 200, "понижение роли отняло доступ к собственному разделу профиля"


def test_уровни_допуска_привязаны_к_крайним_ступеням_лестницы(
    client: TestClient, store: MemoryStore
) -> None:
    """Разница между уровнями — только роль; всё остальное в цепочке одинаково.

    Один и тот же сеанс и один и тот же маршрут `/admin/users`: пока роль подходит — `200`, стоит
    понизить её до средней ступени лестницы — `403`. Проверка держит и привязку уровней к ролям:
    «любая роль» обязана быть младшей ступенью (`viewer`), «раздел администратора» — старшей
    (`admin`), а набор ролей в проверке — равным набору домена, иначе матрица прогоняется по
    устаревшему перечню.
    """
    assert CONSOLE_TIER == ROLE_VIEWER, (
        "уровень «любая роль» больше не младшей ступенью лестницы "
        "viewer ⊂ operator ⊂ admin: смотри §9.3 п. 4–5 и `ADR-017` п. 2"
    )
    assert ADMIN_TIER == ROLE_ADMIN, (
        "уровень раздела администрирования больше не старшая ступень: "
        "смотри §9.3 п. 6–10 и `ADR-017` п. 2"
    )
    assert set(ROLE_SEQUENCE) == ROLES, (
        "набор ролей в проверке больше не равен набору домена: "
        f"{sorted(ROLE_SEQUENCE)} против {sorted(ROLES)}"
    )

    assert _войти(client, ROLE_ADMIN).status_code == 302
    _поднять_до_full(client, store)
    _учётка(store, ROLE_ADMIN).role = ROLE_OPERATOR
    отказ = client.get(ADMIN_USERS_PATH, headers=_headers(), follow_redirects=False)
    assert отказ.status_code == 403, "средняя ступень лестницы прошла в раздел администратора"
    assert client.get(SESSIONS_PATH, headers=_headers(), follow_redirects=False).status_code == 200
