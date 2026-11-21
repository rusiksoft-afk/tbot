"""Сессии входа: выпуск, проверка, шаг 2FA, пересоздание и отзыв (TZ §8.3, задача `T-102`).

Что закреплено этим модулем:

* значение куки — 256 случайных бит, наружу показывается один раз в момент выпуска; в базе живёт
  только SHA-256 от него (`sessions.token_hash`). §8.3 требует «случайный id 256 бит»: в UUID
  случайных бит меньше, а перебор UUID был бы перебором сессий;
* idle 30 минут и абсолютный срок 12 часов: `expires_at` = `min(сейчас + idle, созданная + abs)`.
  Idle отсчитывается от последней активности, абсолютный срок — от создания и активностью не
  сдвигается;
* `revoked_at` проверяется на каждом запросе (§8.3: «отзыв отражается немедленно»). Модуль не
  знает про кэш и не умеет «помнить», что сессия была жива;
* шаг входа (`auth_step`) живёт в базе, а не в куке: значение `'full'` нельзя получить подменой
  значения на клиенте;
* после критичных действий (§8.3: смена пароля, подключение токена, запуск в `production`) сессия
  пересоздаётся: старая отзывается, новая выходит из того же шага входа.

Чего здесь сознательно нет:

* соединений и транзакций: модуль меняет объекты ORM, а коммит и запись в `audit_log` делает
  вызывающий слой — иначе отзыв сессии и событие журнала (§8.7: «вход/выход/неудачные попытки»)
  могли бы разойтись по разным транзакциям;
* куки, заголовки, CSP/HSTS и CSRF-токена (`HttpOnly`/`Secure`/`SameSite=Lax`, `X-CSRF-Token`):
  это уровень `apps/web`, следующий срез `T-102` — здесь нет представления о HTTP-запросе;
* счётчика частоты запросов (§8.3: `/login` 10 запросов/мин/IP, `/totp` 10/мин/сессия и
  5/мин/IP, мутации 60/мин/пользователь): хранилища счётчика в схеме §4.1 нет, и это вопрос
  заказчику, а не то, что можно выдумать в коде;
* назначения промежуточного шага `'totp'`: его определяет `T-103`, здесь зафиксирован только
  порядок — «только вперёд».
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import ClassVar, Final
from uuid import UUID

from packages.common.clock import ensure_aware
from packages.common.ids import uuid7
from packages.identity.users import apply_new_password
from packages.storage.models import User, UserSession

# ─── параметры из §8.3 ───────────────────────────────────────────────────────────────────────

#: §8.3: «idle-таймаут 30 минут». Отсчитывается от последней активности, а не от создания.
IDLE_TIMEOUT: Final = timedelta(minutes=30)

#: §8.3: «абсолютный — 12 часов». Отсчитывается от создания и активностью не сдвигается.
ABSOLUTE_TIMEOUT: Final = timedelta(hours=12)

#: §8.3: «случайный id 256 бит».
SESSION_TOKEN_BITS: Final = 256
_TOKEN_BYTES: Final = SESSION_TOKEN_BITS // 8

#: Значение куки — base64url без «=» (43 символа на 256 бит). Алфавит безопасен для куки и не
#: требует экранирования, а длина постоянна: обрезанное клиентом значение видно сразу.
SESSION_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")

#: Порядок шагов входа (§8.2). Откат назад запрещён: «полностью вошедшую» сессию нельзя
#: понизить до «ждёт код» без нового входа — иначе одна неудачная операция снимала бы права с
#: уже аутентифицированной сессии, а это ровно то, что проверяют тесты маршрутов (`T-103`).
AUTH_STEP_ORDER: Final = ("password", "totp", "full")

#: Критичные действия из §8.3. Перечень закрытый: у каждого отзыва сессии обязана быть причина,
#: которую видно в журнале, а пересоздание «на всякий случай» плодит незадокументированные отзывы.
CRITICAL_ACTIONS: Final = frozenset({"password_change", "token_connect", "production_launch"})


# ─── ошибки ──────────────────────────────────────────────────────────────────────────────────


#: Коды причин недействительности сессии: интерфейс (§9: `/session-expired`) и журнал (§8.7)
#: опираются именно на них, поэтому набор закрытый и проверяется тестом на полноту.
SESSION_REASON_CODES: Final = frozenset({"revoked", "idle", "absolute", "not_yet"})


class SessionInvalidError(RuntimeError):
    """Сессия недействительна. `code` — код причины для интерфейса и журнала."""

    code: ClassVar[str] = "invalid"

    def __init__(self, at: datetime, detail: str) -> None:
        super().__init__(f"{detail} (граница: {at.isoformat()})")
        self.at = at


class SessionRevokedError(SessionInvalidError):
    """Сессию отозвали (§8.3: «отзыв отражается немедленно», `revoked_at` проверяется на запросе)."""

    code: ClassVar[str] = "revoked"

    def __init__(self, at: datetime) -> None:
        super().__init__(at, "сессия отозвана")


class SessionIdleExpiredError(SessionInvalidError):
    """Истёк idle-таймаут: сессия не использовалась дольше `IDLE_TIMEOUT`."""

    code: ClassVar[str] = "idle"

    def __init__(self, at: datetime) -> None:
        super().__init__(at, "сессия не использовалась дольше порога (§8.3, idle 30 минут)")


class SessionAbsoluteExpiredError(SessionInvalidError):
    """Истёк абсолютный срок: активность его не продлевает (§8.3, 12 часов)."""

    code: ClassVar[str] = "absolute"

    def __init__(self, at: datetime) -> None:
        super().__init__(at, "истёк абсолютный срок сессии (§8.3, 12 часов)")


class SessionNotValidYetError(SessionInvalidError):
    """Сессия создана «в будущем»: часы приложения и базы (или два приложения) разошлись.

    Молча считать такую сессию живой нельзя: её idle-таймаут ещё не начался, а запись о ней уже
    существует. Расхождение часов — инцидент, а не деталь реализации.
    """

    code: ClassVar[str] = "not_yet"

    def __init__(
        self,
        at: datetime,
        detail: str = "сессия создана позже текущего момента (расхождение часов)",
    ) -> None:
        super().__init__(at, detail)


class SessionStepError(RuntimeError):
    """Запрошен недопустимый переход шага входа."""


class MalformedSessionTokenError(ValueError):
    """Значение куки не похоже на выпущенное: обрезано, переслано частично или подставлено."""


# ─── значение куки и его хэш ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IssuedSession:
    """Выпущенная сессия: запись для базы и значение куки для ответа клиенту.

    Значение куки существует только здесь и только один раз: в базе — хэш, второго выпуска не
    будет. `repr` замаскирован: §8.4 требует, чтобы материал доступа не попадал в логи, а печать
    структуры данных — самый частый способ это сделать.
    """

    record: UserSession
    secret: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"IssuedSession(session_id={self.record.id}, step={self.record.auth_step!r}, "
            "secret='<скрыто>')"
        )


def token_secret() -> str:
    """Новое значение куки: 256 случайных бит (§8.3), base64url без «=»."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def ensure_token_syntax(secret: str) -> None:
    """Проверить форму значения куки до похода в базу.

    Проверка нужна не для красоты: обрезанное на 40 символов значение дало бы «сессия не
    найдена», но причина другая — куку испортили клиент, браузер или прокси, и отличить это
    нужно сразу.
    """
    if not SESSION_TOKEN_RE.fullmatch(secret):
        raise MalformedSessionTokenError(
            "значение куки не соответствует формату: ожидаем 43 символа base64url (§8.3)"
        )


def token_hash_of(secret: str) -> str:
    """SHA-256 от значения куки в hex (64 символа) — то, что живёт в `sessions.token_hash`.

    Хэшируются ровно те байты, что прислал браузер (UTF-8 от строки), иначе выпуск и проверка
    разойдутся.
    """
    ensure_token_syntax(secret)
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _aware(value: datetime | None, what: str) -> datetime:
    """Осознанный UTC из поля сессии с внятной ошибкой, если поле не заполнено.

    Схема объявляет `created_at`/`expires_at` как `NOT NULL`, но объект мог быть собран вручную и
    без них (например, в тесте). Молча сложить `None + timedelta` нельзя — ошибка должна
    объяснять, какое поле забыли.
    """
    if value is None:
        raise SessionNotValidYetError(ensure_aware(), f"у сессии не заполнено поле «{what}»")
    return ensure_aware(value)


def _expiry_bound(moment: datetime, created_at: datetime) -> datetime:
    """Граница `expires_at`: idle от последней активности, но не позже абсолютного срока."""
    return min(moment + IDLE_TIMEOUT, created_at + ABSOLUTE_TIMEOUT)


# ─── выпуск ──────────────────────────────────────────────────────────────────────────────────


def create_session(
    user_id: UUID,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    auth_step: str = "password",
    now: datetime | None = None,
) -> IssuedSession:
    """Выпустить сессию сразу после проверки пароля (§8.2: шаг входа начинается с `password`).

    `created_at` и `expires_at` ставятся явно, а не через `DEFAULT`: абсолютный срок вычисляется
    от создания и обязан быть известен до флаша. Это тот же класс ошибок, что со счётчиком неудач
    в `T-101`: у нового объекта SQLAlchemy значения из `DEFAULT` ещё `None`.

    `ip` и `user_agent` пишутся как получены: §8.3 показывает их пользователю в списке сессий,
    §8.7 требует IP входа в журнале, а уведомление «вход с нового IP/устройства» (§8.7) строится
    на сравнении этих значений.

    Первичный ключ ставится здесь, а не ожидается из `DEFAULT`: `id` нужен сразу — пересоздание
    сравнивает старые и новые сессии, отзыв работает со списком `except_ids`, а страница «мои
    устройства» помечает текущую сессию. У неотправленного объекта SQLAlchemy значения из
    `DEFAULT` ещё `None` (тот же урок, что и со счётчиком неудач в `T-101`).
    """
    moment = ensure_aware(now)
    if auth_step not in AUTH_STEP_ORDER:
        raise SessionStepError(f"неизвестный шаг входа {auth_step!r}: допустимо {AUTH_STEP_ORDER}")
    secret = token_secret()
    record = UserSession(
        id=uuid7(),
        user_id=user_id,
        token_hash=token_hash_of(secret),
        created_at=moment,
        last_seen_at=moment,
        expires_at=_expiry_bound(moment, moment),
        ip=ip,
        user_agent=user_agent,
        auth_step=auth_step,
        revoked_at=None,
    )
    return IssuedSession(record=record, secret=secret)


# ─── проверка на каждом запросе ──────────────────────────────────────────────────────────────


def absolute_deadline(session: UserSession) -> datetime:
    """Абсолютная граница сессии: создание + 12 часов (§8.3)."""
    return _aware(session.created_at, "created_at") + ABSOLUTE_TIMEOUT


def ensure_session_active(session: UserSession, *, now: datetime | None = None) -> None:
    """Проверить сессию до выполнения запроса; иначе — исключение с кодом причины.

    Порядок проверок важен: сначала отзыв (пользователь уже нажал «отозвать» — причина именно
    эта), затем «из будущего», затем абсолютный срок, затем idle. Иначе у сессии, у которой
    истекли оба срока, показана была бы «неактивность», а продлить её нельзя.
    """
    moment = ensure_aware(now)
    if session.revoked_at is not None:
        raise SessionRevokedError(ensure_aware(session.revoked_at))
    created_at = _aware(session.created_at, "created_at")
    if created_at > moment:
        raise SessionNotValidYetError(created_at)
    deadline = absolute_deadline(session)
    if moment >= deadline:
        raise SessionAbsoluteExpiredError(deadline)
    expires_at = _aware(session.expires_at, "expires_at")
    if moment >= expires_at:
        raise SessionIdleExpiredError(expires_at)


def session_is_active(session: UserSession, *, now: datetime | None = None) -> bool:
    """Жива ли сессия сейчас: не отозвана, idle и абсолютный срок не истекли."""
    try:
        ensure_session_active(session, now=now)
    except SessionInvalidError:
        return False
    return True


def register_session_activity(session: UserSession, *, now: datetime | None = None) -> None:
    """Продлить idle: `expires_at` = min(сейчас + 30 минут, создание + 12 часов).

    Мёртвую сессию продлить нельзя: проверка идёт до записи, иначе ошибка запроса «не заметила»
    отзыв, и отозванная сессия получила бы ещё 30 минут.

    Вызывающий вправе писать в базу не на каждом запросе (иначе каждый GET стоит UPDATE), но
    интервал пакетирования обязан быть заметно меньше `IDLE_TIMEOUT`, иначе сессия «протухнет» у
    пользователя, который работает. Это решение middleware (`apps/web`), а не здесь: здесь нет
    представления о запросах.
    """
    moment = ensure_aware(now)
    ensure_session_active(session, now=moment)
    session.last_seen_at = moment
    session.expires_at = _expiry_bound(moment, _aware(session.created_at, "created_at"))


# ─── шаг входа ───────────────────────────────────────────────────────────────────────────────


def advance_auth_step(session: UserSession, *, step: str, now: datetime | None = None) -> None:
    """Перевести сессию на следующий шаг входа (только вперёд).

    `password` → `full` допустим напрямую: вход резервным кодом (`T-104`) тоже даёт полный
    доступ, и требовать у такого пользователя несуществующую привязку TOTP означало бы оставить
    его без доступа вовсе. Промежуточное `'totp'` описывает `T-103`.
    """
    moment = ensure_aware(now)
    ensure_session_active(session, now=moment)
    if session.auth_step not in AUTH_STEP_ORDER or step not in AUTH_STEP_ORDER:
        raise SessionStepError(
            f"неизвестный шаг входа: было {session.auth_step!r}, просят {step!r}, "
            f"допустимо {AUTH_STEP_ORDER}"
        )
    if AUTH_STEP_ORDER.index(step) < AUTH_STEP_ORDER.index(session.auth_step):
        raise SessionStepError(
            f"шаг входа нельзя откатить: {session.auth_step!r} → {step!r} (§8.2, §8.3)"
        )
    session.auth_step = step


def ensure_full_auth(session: UserSession, *, now: datetime | None = None) -> None:
    """Пускать дальше только с `auth_step = 'full'` (§8.2: `'password'` — только страница кода)."""
    moment = ensure_aware(now)
    ensure_session_active(session, now=moment)
    if session.auth_step != "full":
        raise SessionStepError(f"нужен полный вход, а сессия на шаге {session.auth_step!r} (§8.2)")


# ─── отзыв ───────────────────────────────────────────────────────────────────────────────────


def revoke_session(session: UserSession, *, now: datetime | None = None) -> bool:
    """Отозвать сессию; `False`, если она уже отозвана — время первого отзыва не перетирается.

    Перетирать момент отзыва нельзя: по этому полю и по `audit_log` разбирают инцидент
    («сессию отзовут, а вход всё равно был»).
    """
    if session.revoked_at is not None:
        return False
    session.revoked_at = ensure_aware(now)
    return True


def revoke_sessions(
    session_list: Iterable[UserSession],
    *,
    except_ids: Iterable[UUID] = (),
    now: datetime | None = None,
) -> tuple[UserSession, ...]:
    """Отозвать несколько сессий (§8.3: «отзыв по одной/всех»), вернув фактически отозванные.

    Возвращаются объекты, а не число: вызывающий обязан написать в журнал по каждой отозванной
    сессии (`T-109`), и потерять строку журнала было бы хуже, чем вернуть счётчик.
    """
    moment = ensure_aware(now)
    excluded = set(except_ids)
    revoked: list[UserSession] = []
    for session in session_list:
        if session.id in excluded:
            continue
        if revoke_session(session, now=moment):
            revoked.append(session)
    return tuple(revoked)


# ─── пересоздание после критичных действий ──────────────────────────────────────────────────


def rotate_session(
    session: UserSession,
    *,
    reason: str,
    ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> IssuedSession:
    """Пересоздать сессию (§8.3: после критичных действий сессия пересоздаётся).

    Старая сессия отзывается, новая получает новое значение куки и новый абсолютный срок:
    пересоздание — это новая сессия, а не та же запись с другим токеном. Иначе прежнее значение
    куки, которое уже могло попасть в дамп, память браузера и логи прокси, осталось бы живым.

    Шаг входа сохраняется: критичное действие пользователь подтвердил (смена пароля требует
    текущий пароль **и** TOTP, §8.1), поэтому требовать код заново — значит наказывать
    пользователя за его же действие.

    `reason` обязан быть из перечня §8.3: у отзыва сессии всегда есть причина, и она обязана
    попасть в журнал.
    """
    moment = ensure_aware(now)
    if reason not in CRITICAL_ACTIONS:
        raise ValueError(
            f"причина пересоздания {reason!r} не входит в перечень §8.3: {sorted(CRITICAL_ACTIONS)}"
        )
    ensure_session_active(session, now=moment)
    issued = create_session(
        session.user_id,
        ip=session.ip if ip is None else ip,
        user_agent=session.user_agent if user_agent is None else user_agent,
        auth_step=session.auth_step,
        now=moment,
    )
    session.revoked_at = moment
    return issued


@dataclass(frozen=True)
class PasswordChangeResult:
    """Итог смены пароля: новая сессия (если текущая была) и фактически отозванные остальные.

    `issued is None` — это «текущей сессии не было» (например, сброс администратором, §8.1), а не
    «забыли пересоздать»: различать эти случая вызывающий обязан по факту, а не по догадке.
    """

    issued: IssuedSession | None
    revoked_others: tuple[UserSession, ...]


def change_password(
    user: User,
    new_password: str,
    *,
    current: UserSession | None,
    others: Iterable[UserSession] = (),
    now: datetime | None = None,
) -> PasswordChangeResult:
    """Сменить пароль так, как требуют §8.1 и §8.3.

    §8.1: «после смены все сессии, кроме текущей, отзываются»; §8.3: «после критичных действий
    сессия пересоздаётся». Значит, текущая сессия пересоздаётся (новое значение куки обязано
    появиться: украденное прежнее не должно пережить смену пароля), остальные отзываются.

    Порядок: сначала проверка живой ли текущая сессия (это не меняет состояние), затем пароль,
    затем пересоздание и отзывы. Отказ политики пароля не должен трогать чужие сессии; и наоборот
    — уже принятым паролем нельзя «доделывать» половину операции. Смена пароля блокировку перебора
    не снимает (`T-101`): разблокировка — отдельное действие.

    Отзыв сессий здесь — прикладной шаг; список сессий пользователя и записи в журнал делает
    вызывающий слой.
    """
    moment = ensure_aware(now)
    if current is not None:
        ensure_session_active(current, now=moment)
    apply_new_password(user, new_password, now=moment)
    issued = (
        None if current is None else rotate_session(current, reason="password_change", now=moment)
    )
    revoked = revoke_sessions(others, now=moment)
    return PasswordChangeResult(issued=issued, revoked_others=revoked)


# ─── список сессий для пользователя (§8.3) ──────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionDescriptor:
    """Строка списка устройств (§8.3).

    Ни значения куки, ни `token_hash` сюда не попадают: на странице, которую рендерит
    шаблонизатор, нужны устройство и срок, а не материал сессии.
    """

    id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    auth_step: str
    ip: str | None
    user_agent: str | None
    revoked_at: datetime | None
    is_current: bool
    is_active: bool


def describe_session(
    session: UserSession,
    *,
    current_id: UUID | None = None,
    now: datetime | None = None,
) -> SessionDescriptor:
    """Описать сессию для страницы «мои устройства» (§8.3)."""
    moment = ensure_aware(now)
    return SessionDescriptor(
        id=session.id,
        created_at=_aware(session.created_at, "created_at"),
        last_seen_at=_aware(session.last_seen_at, "last_seen_at"),
        expires_at=_aware(session.expires_at, "expires_at"),
        auth_step=session.auth_step,
        ip=session.ip,
        user_agent=session.user_agent,
        revoked_at=ensure_aware(session.revoked_at) if session.revoked_at is not None else None,
        is_current=current_id is not None and session.id == current_id,
        is_active=session_is_active(session, now=moment),
    )


def describe_sessions(
    session_list: Iterable[UserSession],
    *,
    current_id: UUID | None = None,
    now: datetime | None = None,
    only_active: bool = False,
) -> tuple[SessionDescriptor, ...]:
    """Список сессий пользователя: активные первыми, внутри группы — по последней активности.

    Просроченные и отозванные строки не выбрасываются молча: пользователь вправе увидеть, что с
    его аккаунта кто-то входил и когда именно сессия перестала быть живой.
    """
    moment = ensure_aware(now)
    rows = [
        describe_session(session, current_id=current_id, now=moment) for session in session_list
    ]
    if only_active:
        rows = [row for row in rows if row.is_active]
    # активные — выше; внутри группы по убыванию последней активности. Ключ именно
    # `(is_active, last_seen_at)`: «не активна» — это True, и при reverse=True она ушла бы наверх.
    rows.sort(key=lambda row: (row.is_active, row.last_seen_at), reverse=True)
    return tuple(rows)
