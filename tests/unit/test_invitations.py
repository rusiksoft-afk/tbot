"""Юнит-проверки приглашений закрытого допуска (TZ §1.2, `REQ-identity-02`/`REQ-identity-03`,
`T-105`, срез `R7a`).

Живой базы здесь нет намеренно: всё, что проверяется, — правила значения и перехода, а не SQL.
Что именно нельзя сломать:

* в схеме живёт только хэш ссылки (`uq_invitations_token_hash`), и `IssuedInvitation.secret`
  обязан совпадать с тем значением, от которого он посчитан, — иначе выпущенная ссылка никогда
  не найдётся;
* срок 14 дней (§1.2) считается от выпуска, а просроченное приглашение **не** становится новым
  состоянием: признак живости один;
* причина закрытия различается кодом, и состояние важнее срока (использованная просроченная
  ссылка обязана отвечать «уже использовано»);
* приглашение адресовано кому-то: ни e-mail, ни логина — это не приглашение (§1.2);
* роль выдаёт приглашение, а не выбирает приглашённый (§1.1);
* `user_from_invitation` не размечает приглашение использованным: право решить «ссылка
  истрачена» у guarded-`UPDATE` слоя доступа (шапка `packages/identity/invitations.py`).

Значения `Invitation` собираются вызовами домена, а не конструктором ORM: иначе проверка
«домен не оставляет открытого значения в колонках» проверяла бы сам себя.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from packages.identity.authorization import RoleOutsideDomainError
from packages.identity.invitations import (
    EMAIL_MAX_LEN,
    INVITATION_TOKEN_BITS,
    INVITATION_TOKEN_RE,
    INVITATION_TTL,
    INVITATION_UNUSABLE_CODES,
    InvitationError,
    InvitationExpiredError,
    InvitationRevokedError,
    InvitationStateError,
    InvitationTargetError,
    InvitationUnusableError,
    InvitationUsedError,
    IssuedInvitation,
    MalformedInvitationTokenError,
    ensure_email_syntax,
    ensure_invitation_open,
    ensure_invitation_secret,
    invitation_is_open,
    invitation_secret,
    invitation_token_hash,
    new_invitation,
    revoke_invitation,
    user_from_invitation,
)
from packages.identity.passwords import ARGON2_HASH_PREFIX, PasswordPolicyError
from packages.identity.users import LOGIN_MAX_LEN, LOGIN_MIN_LEN, LoginFormatError
from packages.storage.models import INVITATION_STATES, Invitation, User

#: Фиксированный «сейчас»: срок 14 дней обязан быть проверяемым числом, а не «примерно две недели».
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

PASSWORD = "правильная-лошадь-2026"
ADMIN_ID = UUID("00000000-0000-0000-0000-00000000000a")


def _issued(
    *, role: str = "operator", email: str | None = "ivan@example.ru", login: str | None = None
) -> IssuedInvitation:
    """Выпущенное приглашение дефолтного вида."""
    return new_invitation(created_by=ADMIN_ID, role=role, email=email, login=login, now=NOW)


def _closed(record: Invitation, state: str, *, used_at: datetime | None = None) -> Invitation:
    """Приглашение в закрытом состоянии: так его оставит guarded-`UPDATE` слоя доступа."""
    record.state = state
    record.used_at = used_at
    return record


# ─── значение ссылки: форма, хэш, одноразовость выпуска ───────────────────────────────────────


def test_требование_срока_в_коде_равно_тз() -> None:
    """§1.2: «срок действия 14 дней» — константа, а не настройка."""
    assert timedelta(days=14) == INVITATION_TTL, "TZ §1.2 задаёт срок 14 дней"
    assert INVITATION_TOKEN_BITS == 256, "стойкость значения ссылки — 256 бит, как у значения куки"


def test_значение_ссылки_форма_длина_и_различие() -> None:
    """Форма та же, что у значения куки: 43 символа base64url, значения никогда не повторяются."""
    first = invitation_secret()
    second = invitation_secret()
    assert INVITATION_TOKEN_RE.fullmatch(first), "алфавит и длина значения ссылки"
    assert len(first) == 43, "256 бит в base64url без дополнения — ровно 43 символа"
    assert first != second, "два выпуска не могут дать одно значение"
    for forbidden in ("+", "/", "="):
        assert forbidden not in first, f"{forbidden} не входит в base64url: значение пойдёт в URL"


@pytest.mark.parametrize(
    "broken",
    [
        "a" * 42,  # обрезанное значение
        "a" * 44,  # лишние знаки
        "a" * 42 + "=",  # base64 с дополнением
        "a" * 41 + "+_",  # посторонний знак алфавита
        "",
        "x?y" * 14,
    ],
)
def test_форма_проверяется_до_обращения_к_базе(broken: str) -> None:
    """Обрезанную или постороннюю ссылку видно до запроса: иначе «приглашения нет» и «ссылку
    испортили при переносе» стали бы одним ответом."""
    with pytest.raises(MalformedInvitationTokenError):
        ensure_invitation_secret(broken)
    with pytest.raises(MalformedInvitationTokenError):
        invitation_token_hash(broken)


def test_в_схеме_только_хэш_и_он_выведен_из_выданного_значения() -> None:
    """`token_hash` посчитан ровно от того значения, которое вернулось наружу (UTF-8, SHA-256, hex)."""
    issued = _issued()
    expected = hashlib.sha256(issued.secret.encode("utf-8")).hexdigest()
    assert issued.record.token_hash == expected, "иначе выпущенная ссылка не найдётся никогда"
    assert len(issued.record.token_hash) == 64, "SHA-256 в hex — 64 знака"
    assert issued.record.token_hash == invitation_token_hash(issued.secret), "хэш детерминирован"
    assert issued.record.token_hash != issued.secret, "открытое значение в колонке недопустимо"


def test_ни_одна_колонка_приглашения_не_содержит_открытого_значения() -> None:
    """Утечка дампа не должна отдавать ссылку допуска: проверяем все текстовые поля строки."""
    issued = _issued(login="ivan.petrov")
    for column in Invitation.__table__.columns:
        value = getattr(issued.record, column.name)
        if isinstance(value, str):
            assert issued.secret not in value, f"открытое значение уехало в {column.name}"
        assert issued.secret not in repr(value), f"открытое значение в {column.name}"


def test_repr_оболочки_маскирует_значение() -> None:
    """Печать структуры данных — самый частый способ унести материал доступа в журнал."""
    issued = _issued()
    text = repr(issued)
    assert issued.secret not in text
    assert "скрыто" in text


# ─── выпуск: адресат, роль, состояние, срок ──────────────────────────────────────────────────


def test_выпуск_ставит_pending_срок_и_автора() -> None:
    issued = _issued(role="admin")
    record = issued.record
    assert record.state == "pending", "новое приглашение открыто (§1.2)"
    assert record.expires_at == NOW + INVITATION_TTL, "срок отсчитывается от момента выпуска"
    assert record.created_by == ADMIN_ID, "создаёт приглашение администратор (§9.3 п. 6)"
    assert record.used_at is None, "использования ещё нет"
    assert record.role == "admin", "роль выдаёт приглашение (§1.1)"


@pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
def test_роль_приглашения_из_закрытого_набора(role: str) -> None:
    assert _issued(role=role).record.role == role


@pytest.mark.parametrize("role", ["superuser", "Admin", "admin ", ""])
def test_роль_за_пределами_набора_отклоняется_до_базы(role: str) -> None:
    """CHECK `ck_invitations_role` отклонил бы её ценой `IntegrityError` посреди операции (§8.8)."""
    with pytest.raises(RoleOutsideDomainError):
        _issued(role=role)


def test_адресат_обязателен_хоть_один() -> None:
    """§1.2: «e-mail или логин». Оба сразу — можно, ни одного — нельзя."""
    assert _issued(email="ivan@example.ru").record.login is None
    assert _issued(email=None, login="ivan.petrov").record.email is None
    both = new_invitation(
        created_by=ADMIN_ID, role="viewer", email="ivan@example.ru", login="ivan.petrov", now=NOW
    )
    assert both.record.email is not None
    assert both.record.login is not None, "оба адресата сразу допустимы (§1.2)"
    with pytest.raises(InvitationTargetError):
        _issued(email=None, login=None)


@pytest.mark.parametrize("login", ["ivan.petrov", "I-Petrov", "ivan_petrov.2", "user1"])
def test_логин_приглашения_проходит_формат(login: str) -> None:
    assert _issued(email=None, login=login).record.login == login


@pytest.mark.parametrize(
    "login",
    [
        "ab",  # короче минимума
        "x" * (LOGIN_MAX_LEN + 1),
        "иван",  # не-ASCII: `citext` и `casefold()` сравнивают её по-разному
        "ivan petrov",
        "ivan/petrov",
        "ivan%petrov",
        "ivan?petrov",
        "ivan@petrov",
        "-ivan",
        "",
        "   ",
    ],
)
def test_логин_приглашения_отклоняется_по_формату(login: str) -> None:
    """Логин уходит в URL-метку `otpauth://`, в HTML и в список (§9.3 п. 6): алфавит ограничен."""
    with pytest.raises(LoginFormatError):
        _issued(email=None, login=login)


def test_границы_длины_логина_включены() -> None:
    assert len("x" * LOGIN_MIN_LEN) == LOGIN_MIN_LEN
    assert _issued(email=None, login="x" * LOGIN_MAX_LEN).record.login == "x" * LOGIN_MAX_LEN


@pytest.mark.parametrize("email", ["ivan@example.ru", "a.b@c.io", "ivan+bot@example.example.ru"])
def test_почтовая_метка_проходит(email: str) -> None:
    assert ensure_email_syntax(email) == email, "нормализации нет (§4.1 `citext`)"


@pytest.mark.parametrize(
    "email",
    [
        "no-at-sign",
        "a@b",  # нет зоны
        "@example.ru",
        "ivan@",
        "ivan @example.ru",
        "ivan@@example.ru",
        "x" * (EMAIL_MAX_LEN + 1),
        "",
    ],
)
def test_почтовая_метка_отклоняется(email: str) -> None:
    """Метка «кому выдано» не должна становиться мусорной строкой в списке и в правиле §8.1."""
    with pytest.raises(InvitationTargetError):
        ensure_email_syntax(email)


# ─── состояние и срок: можно ли принять ──────────────────────────────────────────────────────


def test_наборы_кодов_причин_закрытия_замкнуты() -> None:
    """По этим кодам интерфейс выбирает объяснение, а журнал различает исходы (§1.2)."""
    assert {"expired", "used", "revoked"} == INVITATION_UNUSABLE_CODES
    assert {
        InvitationExpiredError.code,
        InvitationUsedError.code,
        InvitationRevokedError.code,
    } == INVITATION_UNUSABLE_CODES
    assert "used" in INVITATION_STATES
    assert "revoked" in INVITATION_STATES
    assert (
        "expired" not in INVITATION_STATES
    ), "просрочено — не состояние: признак живости один (`expires_at` + часы)"


def test_открытое_приглашение_в_границе_срока() -> None:
    record = _issued().record
    ensure_invitation_open(record, now=NOW)
    assert invitation_is_open(record, now=NOW)
    # за секунду до границы — ещё открыто
    assert invitation_is_open(record, now=record.expires_at - timedelta(seconds=1))


def test_на_границе_срока_приглашение_уже_закрыто() -> None:
    """Граница смерти срока не включается: `expires_at <= сейчас` значит «истекло»."""
    record = _issued().record
    for moment in (record.expires_at, record.expires_at + timedelta(seconds=1)):
        with pytest.raises(InvitationExpiredError) as captured:
            ensure_invitation_open(record, now=moment)
        assert captured.value.code == "expired"
        assert captured.value.at == record.expires_at, "объяснение обязано называть сам момент"
    assert not invitation_is_open(record, now=record.expires_at)


def test_состояние_закрытия_важнее_срока() -> None:
    """Использованная и просроченная ссылка отвечает «уже использовано»: иначе администратору
    подсказали бы выпустить дубль по той же ссылке."""
    record = _closed(_issued().record, "used", used_at=NOW)
    with pytest.raises(InvitationUsedError) as captured:
        ensure_invitation_open(record, now=NOW + INVITATION_TTL * 2)
    assert captured.value.code == "used"
    assert captured.value.at == NOW, "момент использования уходит в объяснение и журнал"


def test_использованное_и_отозванное_закрыты() -> None:
    used = _closed(_issued().record, "used", used_at=NOW)
    revoked = _closed(_issued().record, "revoked")
    for record, code in ((used, "used"), (revoked, "revoked")):
        with pytest.raises(InvitationUnusableError) as captured:
            ensure_invitation_open(record, now=NOW)
        assert captured.value.code == code
        assert not invitation_is_open(record, now=NOW)


@pytest.mark.parametrize("state", ["expired", "pending ", "активно", ""])
def test_постороннее_состояние_это_повреждение_данных_а_не_отказ(state: str) -> None:
    """Значение вне домена §4.1 обязано быть слышно: молча решить его как «закрыто» или как
    «открыто» — значит изобрести поведение на испорченных данных."""
    record = _issued().record
    record.state = state
    with pytest.raises(InvitationStateError):
        ensure_invitation_open(record, now=NOW)
    with pytest.raises(InvitationStateError):
        invitation_is_open(record, now=NOW)
    with pytest.raises(InvitationStateError):
        revoke_invitation(record)


def test_отзыв_переводит_и_повтор_не_ошибается() -> None:
    record = _issued().record
    revoke_invitation(record)
    assert record.state == "revoked"
    with pytest.raises(InvitationRevokedError) as captured:
        ensure_invitation_open(record, now=NOW)
    assert captured.value.code == "revoked"
    revoke_invitation(record)  # повторное действие администратора ничего не меняет
    assert record.state == "revoked"


def test_использованное_приглашение_не_отзывается() -> None:
    """Стереть факт выдачи доступа — значит снять с журнала (`REQ-identity-03`) единственное,
    что он мог показать. Закрывает доступ переход учётной записи, а не правка ссылки."""
    record = _closed(_issued().record, "used", used_at=NOW)
    with pytest.raises(InvitationStateError):
        revoke_invitation(record)
    assert record.state == "used", "состояние не должно измениться при отказе"


# ─── принятое приглашение: какая учётная запись от него появляется ─────────────────────────────


def test_учётная_запись_берёт_роль_из_приглашения_и_состояние_invited() -> None:
    issued = _issued(role="operator", email="ivan@example.ru")
    user = user_from_invitation(issued.record, login="ivan.petrov", password=PASSWORD, now=NOW)
    assert isinstance(user, User)
    assert user.role == "operator", "роль выдаёт приглашение, а не выбирает приглашённый (§1.1)"
    assert user.state == "invited", "шага одобрения ещё нет (§1.2, §4.1)"
    assert user.email == "ivan@example.ru", "метка адреса переходит в учётную запись"
    assert user.login == "ivan.petrov"
    assert user.password_hash.startswith(ARGON2_HASH_PREFIX), "§8.1: Argon2id"
    assert user.password_updated_at == NOW
    assert user.approved_by is None, "одобрения ещё нет (§1.2)"
    assert user.approved_at is None
    assert user.failed_attempts == 0, "счётчик перебора обязан быть числом на новом объекте"


def test_приглашение_после_этого_остаётся_неотмеченным() -> None:
    """Право решить «ссылка истрачена» — у guarded-`UPDATE` слоя доступа, не у домена."""
    issued = _issued()
    user_from_invitation(issued.record, login="ivan.petrov", password=PASSWORD, now=NOW)
    assert issued.record.state == "pending"
    assert issued.record.used_at is None


def test_приглашение_по_логину_не_даёт_выбрать_другое_имя() -> None:
    """§1.2: приглашение адресовано логину — значит учётная запись создаётся под ним."""
    issued = _issued(email=None, login="Ivan.Petrov")
    same = user_from_invitation(issued.record, login="ivan.petrov", password=PASSWORD, now=NOW)
    assert same.login == "ivan.petrov", "регистр не создаёт другого человека (`citext`, §4.1)"
    with pytest.raises(InvitationTargetError):
        user_from_invitation(
            _issued(email=None, login="ivan.petrov").record,
            login="anna.sidorova",
            password=PASSWORD,
            now=NOW,
        )


def test_приглашение_по_e_mail_позволяет_выбрать_имя_но_не_любое() -> None:
    issued = _issued(email="anna@example.ru", login=None)
    user = user_from_invitation(issued.record, login="anna.sidorova", password=PASSWORD, now=NOW)
    assert user.login == "anna.sidorova"
    with pytest.raises(LoginFormatError):
        user_from_invitation(
            _issued(email="anna@example.ru").record,
            login="anna sidorova",
            password=PASSWORD,
            now=NOW,
        )


@pytest.mark.parametrize(
    "password",
    [
        "коротк",
        "ivan.petrov",  # пароль = логин (§8.1)
        "example.ru",  # пароль = домен из почтовой метки (§8.1)
        "",
    ],
)
def test_пароль_проходит_политику_до_создания_объекта(password: str) -> None:
    """Переходного состояния «учётная запись есть, а валидного хэша нет» быть не должно (§4.1)."""
    with pytest.raises(PasswordPolicyError):
        user_from_invitation(_issued().record, login="ivan.petrov", password=password, now=NOW)


@pytest.mark.parametrize(
    ("state", "code"),
    [("used", "used"), ("revoked", "revoked")],
)
def test_закрытое_приглашение_не_создаёт_учётную_запись(state: str, code: str) -> None:
    """Домен отказывает сам, даже если вызывающий забыл проверить открытость до строки."""
    record = _closed(_issued().record, state, used_at=NOW if state == "used" else None)
    with pytest.raises(InvitationUnusableError) as captured:
        user_from_invitation(record, login="ivan.petrov", password=PASSWORD, now=NOW)
    assert captured.value.code == code


def test_просроченное_приглашение_не_создаёт_учётную_запись() -> None:
    record = _issued().record
    with pytest.raises(InvitationExpiredError):
        user_from_invitation(
            record, login="ivan.petrov", password=PASSWORD, now=NOW + INVITATION_TTL
        )


def test_все_ошибки_приглашения_ловатся_одним_классом() -> None:
    """Слой представления обязан перехватить класс целиком: «забыли обработить одну ветку» —
    это `500` вместо объяснения (§9: состояние внятное)."""
    for error in (
        InvitationTargetError("…"),
        InvitationStateError("…"),
        InvitationExpiredError(NOW),
        InvitationUsedError(NOW),
        InvitationRevokedError(None),
    ):
        assert isinstance(error, InvitationError)
    assert not isinstance(MalformedInvitationTokenError("…"), InvitationUnusableError), (
        "испорченное значение и закрытое приглашение — разные ответы: у первого нет права "
        "объяснять посетителю состояние данных"
    )


def test_случайный_хэш_не_ищет_приглашение_зря() -> None:
    """Форма проверяется до обращения в базу: произвольное значение длиной 43 символа — тоже
    candidate, и «приглашения нет» обязан быть ответом базы, а не маски проверки формата."""
    candidate = "A" * 43
    ensure_invitation_secret(candidate)
    assert len(invitation_token_hash(candidate)) == 64


def test_новый_выпуск_каждый_раз_даёт_новую_ссылку() -> None:
    """Два выпуска одному адресату — две независимые ссылки; ни одна не «заменяет» другую."""
    first, second = _issued(), _issued()
    assert first.secret != second.secret
    assert first.record.token_hash != second.record.token_hash
    assert first.record is not second.record


def test_домен_не_читает_идентификатор_приглашения_до_записи() -> None:
    """Идентификатор строки выдаёт приложение, и до записи его не читают.

    Проверяется факт, на который опираются `§ADR-020` п. 3: ссылка письма не содержит
    `id` строки, поэтому перебирать идентификаторы подбором нельзя, а приём идёт по хэшу
    значения. Сам `id` появляется при `flush` (python-side default, §4.1: UUIDv7), и ни один
    доменный шаг от него не зависит — в отличие от привязки TOTP, где AAD построен по `id`
    и идентификатор нужна до шифрования (`ADR-014` п. 4). Поэтому приглашение
    создаётся без `id`, а не «на всякий случай».
    """
    record = _issued().record
    # Тип колонки — `Mapped[UUID]` (`NOT NULL`), но у объекта, ещё не прошедшего
    # `flush`, значения ещё нет: python-side default применяется при записи.
    # `cast` нужен, чтобы не спорить с объявленным типом схемы, а не «на всякий случай».
    assert (
        cast("object", record.id) is None
    ), "домена, который читал бы id приглашения до записи, здесь нет"
    column = Invitation.__table__.c.id
    assert column.primary_key
    assert (
        column.server_default is None
    ), "`id` обязан появляться на стороне приложения: серверный default отложил бы его до `INSERT`"
