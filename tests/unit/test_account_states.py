"""Юнит-проверки состояний учётной записи и формата логина (TZ §1.2, §4.1, §9.3 п. 6;
`T-105`, срез `R7a`, `docs/adr/ADR-020`).

Что закрепляет этот файл. Строка `users` появляется с состоянием `invited` ещё до одобрения, и
если правила переходов нигде нет, то «одобрить», «заблокировать» и «архивировать» решают
каждый в своём обработчике — а ровно так и появляются состояния, из которых нельзя выйти, или
выходы, которых в контракте нет. Поэтому проверяется:

* **таблица переходов полна и замкнута**: её ключи — ровно домен `USER_STATES` (§4.1), а
  `archived` — терминальное состояние; нелегальный переход — исключение, а не тихое присваивание;
* **доступ решается состоянием, а не флагом**: `login_closed_reason` и `ensure_console_access`
  дают код для каждого состояния, а значение вне домена отвечает отказом (`outside_domain`) —
  тот же приём, что `role_rank` для ролей (`ADR-017` п. 4);
* **состояние и блокировка перебора независимы**: `suspended` — воля администратора,
  `locked_until` — счётчик `T-101`; одна не отменяет и не снимает другую;
* **отметки одобрения живут только в переходе одобрения**: ни блокировка, ни архивирование их не
  ставят и не стирают (§4.1: «кто одобрил и когда» — один факт, а не журнал изменений).

Учётные записи собираются конструктором ORM напрямую: машина состояний не создаёт аккаунты (это делает
`new_user`, и он проверен в `tests/unit/test_invitations.py`), а аргонный хэш для переходов не
нужен — здесь проверяются правила значения, а не стоимость пароля.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from packages.identity.authorization import RoleOutsideDomainError
from packages.identity.users import (
    ACCESS_CODES,
    CLOSED_STATES,
    CONSOLE_STATE,
    LOGIN_MAX_LEN,
    LOGIN_MIN_LEN,
    NO_ACCOUNT_CODE,
    ONBOARDING_STATES,
    STATE_TRANSITIONS,
    AccountAccessError,
    AccountStateError,
    LastAdministratorError,
    LoginFormatError,
    LoginLockedError,
    approve_account,
    archive_account,
    change_role,
    ensure_account_state,
    ensure_console_access,
    ensure_login_allowed,
    ensure_login_syntax,
    ensure_not_last_admin,
    ensure_role_change_keeps_admin,
    login_closed_reason,
    move_account_state,
    new_user,
    same_login,
    state_allows_login,
    suspend_account,
    unsuspend_account,
)
from packages.storage.models import USER_STATES, User

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

#: Не настоящий хэш, а значение нужной формы: CHECK схемы (`left(password_hash,10)='$argon2id$'`)
#: живёт в DDL, а переходы состояния хэш не читают. Настоящий Argon2id даёт `new_user`.
PLACEHOLDER_HASH = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

ADMIN_ID = UUID("00000000-0000-0000-0000-00000000000a")


def _account(state: str, *, login: str = "ivan.petrov") -> User:
    """Строка учётной записи в выбранном состоянии — так, как её прочитает слой доступа."""
    return User(
        id=uuid4(),
        login=login,
        email="ivan@example.ru",
        role="operator",
        state=state,
        password_hash=PLACEHOLDER_HASH,
        failed_attempts=0,
        locked_until=None,
    )


def _edges() -> list[tuple[str, str]]:
    return [(source, target) for source, targets in STATE_TRANSITIONS.items() for target in targets]


# ─── таблица переходов ────────────────────────────────────────────────────────────────────────


def test_таблица_покрывает_весь_домен_состояний() -> None:
    """Каждое состояние §4.1 обязано иметь строку в таблице: состояние без строки — это
    «переход не описан», и первый же обработчик решит его по своему усмотрению."""
    assert set(STATE_TRANSITIONS) == set(USER_STATES), "домен и таблица разъехались"
    for targets in STATE_TRANSITIONS.values():
        assert targets <= set(USER_STATES), "переход ведёт в состояние вне домена"


@pytest.mark.parametrize(("source", "target"), _edges())
def test_разрешённый_переход_работает(source: str, target: str) -> None:
    account = _account(source)
    move_account_state(account, to=target)
    assert account.state == target


@pytest.mark.parametrize(
    ("source", "target"),
    [
        # Приглашённый нельзя «одобрить», минуя очередь: в очередь ставит привязка 2FA (§1.2).
        ("invited", "active"),
        # Блокировка снимает уже открытый доступ: открывать было нечего.
        ("invited", "suspended"),
        ("awaiting_approval", "suspended"),
        # Откат назад по онбордингу означал бы «доступ был и внезапно испарился» без действия.
        ("active", "awaiting_approval"),
        ("active", "invited"),
        ("awaiting_approval", "invited"),
        # Разблокировка возвращает в `active` (там и был), а не в состояние до одобрения.
        ("suspended", "awaiting_approval"),
        ("suspended", "invited"),
        # Повторное действие поверх терминального перехода.
        ("archived", "active"),
        ("archived", "suspended"),
        ("archived", "invited"),
        ("archived", "awaiting_approval"),
        # То же состояние — не переход: повторный клик не должен «перезаписывать» состояние.
        ("active", "active"),
        ("invited", "invited"),
        ("awaiting_approval", "awaiting_approval"),
        ("suspended", "suspended"),
        ("archived", "archived"),
    ],
)
def test_несуществующий_переход_отклоняется(source: str, target: str) -> None:
    account = _account(source)
    with pytest.raises(AccountStateError):
        move_account_state(account, to=target)
    assert account.state == source, "отказ не должен менять состояние"


def test_архивирование_терминально() -> None:
    """§4.1: «удаление — только архивированием». Разархивирование — второе одобрение, которого
    в §1.2 нет, поэтому из `archived` нет ни одного выхода."""
    account = _account("active")
    archive_account(account)
    assert account.state == "archived"
    for target in USER_STATES:
        with pytest.raises(AccountStateError):
            move_account_state(account, to=target)
    assert account.state == "archived"


@pytest.mark.parametrize("corrupt", ["Active", "archiv", "активно", ""])
def test_постороннее_текущее_состояние_не_решается_молча(corrupt: str) -> None:
    """Строка, испорченная правкой руками или ревизией с четвёртым состоянием, обязана быть
    слышна: «неизвестно» не равно «заблокировано» и не равно «разрешено»."""
    account = _account(corrupt)
    with pytest.raises(AccountStateError):
        move_account_state(account, to="active")
    with pytest.raises(AccountStateError):
        ensure_account_state(corrupt)


def test_нормализации_состояния_нет() -> None:
    """Регистр и пробелы не «починятся» сами: CHECK `ck_users_state` отвергает их на записи,
    и второй источник правды о том, что такое «то же состояние», не нужен."""
    for value in ("Active", "ACTIVE ", "active "):
        with pytest.raises(AccountStateError):
            ensure_account_state(value)
    for value in USER_STATES:
        assert ensure_account_state(value) == value


def test_создание_учётной_записи_проверяет_домен_состояния() -> None:
    """`ck_users_state` отклонил бы значение ценой `IntegrityError` посреди операции (§8.8)."""
    with pytest.raises(AccountStateError):
        new_user(
            login="ivan.petrov", password="правильная-лошадь-2026", role="operator", state="active2"
        )
    assert (
        new_user(login="ivan.petrov", password="правильная-лошадь-2026", role="operator").state
        == "invited"
    )


# ─── действия администратора (§9.3 п. 6) ──────────────────────────────────────────────────────


def test_одобрение_ставит_отметки_и_только_из_очереди() -> None:
    account = _account("awaiting_approval")
    approve_account(account, approved_by=ADMIN_ID, now=NOW)
    assert account.state == CONSOLE_STATE
    assert account.approved_by == ADMIN_ID
    assert account.approved_at == NOW, "«когда одобрили» — момент перехода (§4.1)"
    ensure_console_access(account)


def test_одобрение_приглашённого_без_привязки_отклоняется() -> None:
    """§1.2: в очередь ставит подтверждённая привязка 2FA. Одобрить учётную запись, у которой
    второго фактора ещё нет, — значит выдать доступ тому, кто не прошёл второй шаг."""
    account = _account("invited")
    with pytest.raises(AccountStateError):
        approve_account(account, approved_by=ADMIN_ID, now=NOW)
    assert account.approved_by is None
    assert account.approved_at is None, "отказ не ставит отметок"
    with pytest.raises(AccountAccessError) as captured:
        ensure_console_access(account)
    assert captured.value.code == "invited"


def test_повторное_одобрение_не_перезаписывает_автора() -> None:
    account = _account("awaiting_approval")
    approve_account(account, approved_by=ADMIN_ID, now=NOW)
    with pytest.raises(AccountStateError):
        approve_account(account, approved_by=uuid4(), now=NOW + timedelta(minutes=1))
    assert account.approved_by == ADMIN_ID
    assert account.approved_at == NOW, "второй клик не двигает отметку и не меняет автора"


def test_первая_учётная_запись_одобряет_сама_себя() -> None:
    """`ADR-020` п. 5: закрытый клуб без администратора не заведётся. Единственная пара, где
    `approved_by` совпадает с `id` самой строки, — bootstrap; первичный ключ выдаёт приложение
    (UUIDv7), поэтому ссылка FK выполнима в одном `INSERT`."""
    account = new_user(login="root.admin", password="правильная-лошадь-2026", role="admin")
    # Единственный легальный источник для `active` — очередь, а bootstrap входит в неё явно.
    move_account_state(account, to="awaiting_approval")
    account.id = uuid4()
    approve_account(account, approved_by=account.id, now=NOW)
    assert account.state == CONSOLE_STATE
    assert account.approved_by == account.id
    ensure_console_access(account)


def test_блокировка_и_разблокировка() -> None:
    account = _account("active")
    account.approved_by = ADMIN_ID
    account.approved_at = NOW
    suspend_account(account)
    assert account.state == "suspended"
    assert login_closed_reason(account) == "suspended"
    with pytest.raises(AccountAccessError):
        ensure_console_access(account)
    unsuspend_account(account)
    assert account.state == CONSOLE_STATE
    assert account.approved_by == ADMIN_ID, "разблокировка не трогает автора одобрения (§4.1)"
    assert account.approved_at == NOW


def test_блокировка_из_очереди_ожидания_недоступна() -> None:
    account = _account("awaiting_approval")
    with pytest.raises(AccountStateError):
        suspend_account(account)
    with pytest.raises(AccountStateError):
        unsuspend_account(account)
    assert account.state == "awaiting_approval"


def test_блокировка_администратором_не_смешивается_с_блокировкой_перебора() -> None:
    """`locked_until`/`failed_attempts` (§8.1, `T-101`) — счётчик перебора; `suspended` — воля
    администратора. Одно не снимает другое: иначе одна неудачная попытка пароля «разблокировала»
    бы учётную запись, закрытую администратором."""
    account = _account("active")
    account.failed_attempts = 4
    account.locked_until = NOW + timedelta(minutes=15)
    suspend_account(account)
    assert account.failed_attempts == 4
    assert account.locked_until == NOW + timedelta(minutes=15)
    assert login_closed_reason(account) == "suspended"
    with pytest.raises(LoginLockedError):
        ensure_login_allowed(account, now=NOW)
    unsuspend_account(account)
    assert account.locked_until == NOW + timedelta(
        minutes=15
    ), "разблокировка состояния не трогает счётчик"
    assert login_closed_reason(account) is None


def test_архивирование_доступно_из_любого_неархивного_состояния() -> None:
    for state in ("invited", "awaiting_approval", "active", "suspended"):
        account = _account(state)
        archive_account(account)
        assert (
            account.state == "archived"
        ), f"архивирование из {state} обязательно доступно (§1.2, §4.1)"
        assert login_closed_reason(account) == "archived"
    already = _account("archived")
    with pytest.raises(AccountStateError):
        archive_account(already)


def test_архивирование_не_стирает_историю_одобрения() -> None:
    account = _account("awaiting_approval")
    approve_account(account, approved_by=ADMIN_ID, now=NOW)
    archive_account(account)
    assert account.approved_by == ADMIN_ID
    assert (
        account.approved_at == NOW
    ), "§4.1: строка не удаляется — следы решения нужны журналу и списку отзывов"


# ─── допуск: что решает состояние ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("state", "code"),
    [
        ("invited", None),
        ("awaiting_approval", None),
        (CONSOLE_STATE, None),
        ("suspended", "suspended"),
        ("archived", "archived"),
    ],
)
def test_вход_закрыт_только_состояниями_воли_администратора(state: str, code: str | None) -> None:
    """§1.2: «приглашение без одобрения не даёт ни сессии, ни прав» — прав не даёт проверка
    консоли, а пароль принять нужно, чтобы дойти до привязки 2FA (тот же порядок §1.2)."""
    assert login_closed_reason(_account(state)) == code
    assert state_allows_login(state) is (code is None)


def test_постороннее_состояние_отвечает_как_закрытое_но_кодом_отдельно() -> None:
    """Посетителю — то же «нельзя», что и закрытому состоянию; журналу — отдельный код, иначе
    повреждение данных растворится в обычных отказах (`ADR-017` п. 4)."""
    closed = login_closed_reason(_account("supervisor"))
    assert closed == "outside_domain"
    assert closed not in CLOSED_STATES
    assert closed in ACCESS_CODES
    assert not state_allows_login("supervisor")


def test_отсутствующая_строка_учётной_записи_тоже_закрыта() -> None:
    assert login_closed_reason(None) == NO_ACCOUNT_CODE


def test_коды_отказа_доступа_замкнуты() -> None:
    """Набор закрытый: по нему интерфейс выбирает объяснение, а правки «ещё один код»
    плодят состояния, которые никто не показывает."""
    for state in ("invited", "awaiting_approval", "suspended", "archived"):
        with pytest.raises(AccountAccessError) as captured:
            ensure_console_access(_account(state))
        assert captured.value.code == state
        assert captured.value.code in ACCESS_CODES
    with pytest.raises(AccountAccessError) as captured:
        ensure_console_access(_account("supervisor"))
    assert captured.value.code == "outside_domain"
    assert set(ACCESS_CODES) == ONBOARDING_STATES | CLOSED_STATES | {"outside_domain"}


def test_доступ_в_консоль_решается_на_каждом_запросе() -> None:
    """Одобрение и разблокировка применяются к живому сеансу немедленно: решение не кэшируется,
    и состояние читается заново (тот же довод, что у `enforce_role` в `ADR-017` п. 7)."""
    account = _account("awaiting_approval")
    with pytest.raises(AccountAccessError):
        ensure_console_access(account)
    approve_account(account, approved_by=ADMIN_ID, now=NOW)
    ensure_console_access(account)
    suspend_account(account)
    with pytest.raises(AccountAccessError):
        ensure_console_access(account)


def test_переход_в_очередь_ожидания_делает_привязка_а_не_одобрение() -> None:
    """`invited` → `awaiting_approval` — единственный способ попасть в очередь (§1.2:
    «привязывает TOTP → admin одобряет»), и он не даёт доступа."""
    account = _account("invited")
    move_account_state(account, to="awaiting_approval")
    assert account.state == "awaiting_approval"
    assert account.approved_by is None, "очередь — не одобрение"
    with pytest.raises(AccountAccessError):
        ensure_console_access(account)


# ─── логин как значение (§4.1 `citext`, граница длины) ────────────────────────────────────────


@pytest.mark.parametrize("login", ["ivan", "ivan.petrov", "abc", "a1b", "x" * LOGIN_MAX_LEN])
def test_формат_логина_проходит(login: str) -> None:
    assert ensure_login_syntax(login) == login


def test_формат_логина_проходит_с_границы_минимума() -> None:
    assert len("x" * LOGIN_MIN_LEN) == LOGIN_MIN_LEN
    assert ensure_login_syntax("x" * LOGIN_MIN_LEN) == "x" * LOGIN_MIN_LEN


@pytest.mark.parametrize(
    "login",
    [
        "",
        "   ",
        "ab",
        "x" * (LOGIN_MAX_LEN + 1),
        ".ivan",
        "-ivan",
        "_ivan",
        "ivan petrov",
        "ivan/petrov",
        "ivan?petrov",
        "ivan#petrov",
        "ivan&petrov",
        "ivan=petrov",
        "ivan%petrov",
        "ivan@petrov",
        "ivan+petrov",
        "иван.петров",
    ],
)
def test_формат_логина_отклоняется(login: str) -> None:
    with pytest.raises(LoginFormatError):
        ensure_login_syntax(login)


def test_логин_обрезается_по_краям_но_не_приводится_по_регистру() -> None:
    """`strip()` — техническая обрезка пробелов формы; регистра приведения нет, иначе домен и
    `citext` по-разному отвечали бы на вопрос «то же ли это имя»."""
    assert ensure_login_syntax("  Ivan.Petrov ") == "Ivan.Petrov"
    assert ensure_login_syntax("Ivan.Petrov") != "ivan.petrov"


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("ivan.petrov", "Ivan.Petrov", True),
        ("IVAN.PETROV", "ivan.petrov", True),
        ("ivan.petrov", "ivan.petrov2", False),
        ("ivan", "ivan.", False),
    ],
)
def test_равенство_имён_совпадает_с_правилом_citext(left: str, right: str, expected: bool) -> None:
    """Доменное сравнение (`casefold`) и уникальный индекс `uq_users_login` (`citext`) обязаны
    сходиться на алфавите `LOGIN_RE`, иначе «приглашение адресовано одному логину, а учётная
    запись создана под другим» стало бы возможным."""
    assert same_login(left, right) is expected


# ─── «не остаться без администратора» (§1.2, §4.1; ADR-020 п. 6) ──────────────────────────────


def test_закрытие_доступа_единственному_администратору_отклоняется() -> None:
    """Единственный `active` администратор, ушедший в `suspended`, оставил бы систему без того,
    кто способен включить её обратно: восстановление стало бы правкой таблицы под ролью-владельцем
    (`ADR-006`, `ADR-018`) — операцией без журнала и без отработанного порядка."""
    account = _account("active")
    account.role = "admin"
    with pytest.raises(LastAdministratorError):
        ensure_not_last_admin(account, active_admins_left=0)
    ensure_not_last_admin(account, active_admins_left=1)


def test_обычный_отказ_остаётся_отловимым_через_базовый_класс() -> None:
    """Обработчик, который ловит только `AccountStateError`, обязан удерживать и этот отказ:
    забыть про проверку «последний администратор» можно только молча, потеряв причину."""
    account = _account("active")
    account.role = "admin"
    with pytest.raises(AccountStateError):
        ensure_not_last_admin(account, active_admins_left=0)


def test_закрытие_доступа_оператору_счёт_не_мешает() -> None:
    """Для `operator` переход никогда не лишает систему администратора: проверять счёт для него
    — значит отказать зря. Поэтому роль смотрит домен, а не слой формы."""
    account = _account("active")
    assert account.role == "operator"
    ensure_not_last_admin(account, active_admins_left=0)


def test_архивированный_администратор_правом_не_является() -> None:
    """Счёт обязан считаться по `active`: администратор в `suspended` или `archived` не может ни
    пригласить кого-то, ни одобрить, поэтому «в таблице есть ещё один admin» — не право."""
    active_admin = _account("active")
    active_admin.role = "admin"
    blocked_admin = _account("suspended")
    blocked_admin.role = "admin"
    archived_admin = _account("archived")
    archived_admin.role = "admin"
    accounts = (active_admin, blocked_admin, archived_admin)
    counted = sum(
        1
        for account in accounts
        if account.role == "admin"
        and account.state == CONSOLE_STATE
        and account is not active_admin
    )
    assert counted == 0
    with pytest.raises(LastAdministratorError):
        ensure_not_last_admin(active_admin, active_admins_left=counted)


def test_отрицательный_счёт_ошибка_вызывающего() -> None:
    """`active_admins_left < 0` означает, что вызывающий перепутал порядок (посчитал после
    перехода): молча пропустить это — значит разрешить переход, который не проверялся."""
    account = _account("active")
    account.role = "admin"
    with pytest.raises(ValueError, match="отрицательным"):
        ensure_not_last_admin(account, active_admins_left=-1)


# ─── смена роли (§8.7 «изменение … роли», §9.3 п. 6; срез `R4` задачи `T-109`) ──────────────


def test_роль_меняется_через_домен_и_возвращает_было_ли_изменение() -> None:
    """`change_role` — единственная точка правки `users.role`; возврат отвечает на «было ли
    изменение»: `True` при новой роли и `False`, если значение совпало с текущим (§8.7 заводит
    `account.role_changed` на изменение, а не на попытку)."""
    account = _account("active")
    assert account.role == "operator"
    assert change_role(account, to_role="admin") is True
    assert account.role == "admin"
    assert change_role(account, to_role="admin") is False, (
        "та же роль не обязана считаться изменением: событие о том, чего не случилось, обесценивает "
        "журнал как доказательство"
    )
    assert account.role == "admin"


def test_роль_вне_закрытого_набора_отклоняется_без_правок() -> None:
    """Значение проверяется `ensure_role`: `Admin`, `ADMIN ` и `boss` (§1.1: ровно три роли) —
    отказ здесь, а не в `INSERT`: база держит тот же набор `CHECK`-ограничением `ck_users_role`
    (ревизия `0002`), и второго источника правды о том, что такое роль, быть не должно."""
    for значение in ("Admin", "ADMIN", "boss", ""):
        account = _account("active")
        with pytest.raises(RoleOutsideDomainError):
            change_role(account, to_role=значение)
        assert account.role == "operator", f"значение {значение!r} всё-таки записано"


def test_архивированной_записи_роль_не_меняется() -> None:
    """`archived` терминально (§1.2): менять роль мёртвой записи — значит записать в журнал
    изменение, которое ни на что не влияет; отказ — исключение, а не тихое «ничего не сделали»."""
    account = _account("archived")
    with pytest.raises(AccountStateError, match="терминально"):
        change_role(account, to_role="admin")
    assert account.role == "operator"


@pytest.mark.parametrize("state", ["invited", "awaiting_approval", "active", "suspended"])
def test_роль_меняется_у_любой_живой_записи(state: str) -> None:
    """Роль выбирается в приглашении (`ADR-020` п. 1) и правится до одобрения: без этого ошибка
    роли при выпуске исправлялась бы только переспуском приглашения и новой ссылкой (§1.2).

    `suspended` меняется намеренно: блокировка закрывает доступ состоянием, и роль при этом не
    часть допуска; оставить заблокированной записи роль, которую администратор назначит позже,
    значило бы запрещать решение, которое §9.3 п. 6 не запрещает.
    """
    account = _account(state)
    assert change_role(account, to_role="admin") is True
    assert account.role == "admin"
    assert account.state == state, "смена роли не имеет права трогать состояние"


def test_смена_роли_не_трогает_историю_одобрения() -> None:
    """`approved_by`/`approved_at` отвечают на вопрос «кто одобрил доступ» (§4.1), а не «какая у
    записи роль сейчас»: правка роли не имеет права стирать или подменять автора одобрения."""
    approver = uuid4()
    account = _account("active")
    account.approved_by = approver
    account.approved_at = NOW
    change_role(account, to_role="admin")
    assert account.approved_by == approver
    assert account.approved_at == NOW


def test_страж_смотрит_на_будущую_роль_и_не_трогает_запись() -> None:
    """Порядок стража — до правки, и это не стиль, а правило (§8.7, `ADR-020` п. 6).

    Понижение единственного живого администратора оставило бы систему без того, кто способен
    включить её обратно. `ensure_not_last_admin` смотрит на **текущую** роль, поэтому вызванный
    после `change_role` он молчит: роль уже не `admin` → ранний возврат. Проверка показывает обе
    половины: страж по будущей роли отказывает, а «проверить после правки» — проходит, то есть
    был бы дырой. Сам страж при этом ничего не меняет: решение принимает обработчик, а не проверка.
    """
    account = _account("active")
    account.role = "admin"
    with pytest.raises(LastAdministratorError):
        ensure_role_change_keeps_admin(account, to_role="operator", active_admins_left=0)
    assert account.role == "admin", "страж изменил запись, хотя решение не принято"

    change_role(account, to_role="operator")
    ensure_not_last_admin(account, active_admins_left=0)  # так проверка уже ничего не ловит


def test_страж_не_мешает_повышению_сохранению_и_второму_администратору() -> None:
    """Живых администраторов убавляет только понижение: повышение, оставление роли `admin` и
    понижение при втором живом администраторе проходят не глядя на счёт — отказать зря так же
    плохо, как пропустить случай, ради которого проверка заведена."""
    promoted = _account("awaiting_approval")
    ensure_role_change_keeps_admin(promoted, to_role="admin", active_admins_left=0)

    same = _account("active")
    same.role = "admin"
    ensure_role_change_keeps_admin(same, to_role="admin", active_admins_left=0)

    demoted = _account("active")
    demoted.role = "admin"
    ensure_role_change_keeps_admin(demoted, to_role="viewer", active_admins_left=1)


def test_страж_роли_тоже_ловится_базовым_классом() -> None:
    """`LastAdministratorError` остаётся подклассом `AccountStateError` и для смены роли:
    обработчик, который ловит только базовый класс, тоже удержит отказ — потерять можно только
    причину, но не сам отказ."""
    account = _account("active")
    account.role = "admin"
    with pytest.raises(AccountStateError):
        ensure_role_change_keeps_admin(account, to_role="viewer", active_admins_left=0)
    with pytest.raises(RoleOutsideDomainError):
        ensure_role_change_keeps_admin(account, to_role="суперuser", active_admins_left=0)
