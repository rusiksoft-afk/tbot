"""Жизненный цикл привязки TOTP: создание, подтверждение, расход кода входа (`T-103`, TZ §8.2).

Модуль соединяет три уже существующих куска в один процесс: генерацию и защиту секрета
(`totp_secret`), проверку одноразовых кодов с защитой от повтора (`totp`) и строку
`totp_enrollments` (`storage`). Правила, которые живут только здесь:

1. **Одна активная привязка на учётку.** Незавершённая привязка может быть только одна, и повторная
   выдача секрета обязана сопровождаться отзывом предыдущей: частичный уникальный индекс
   `ix_totp_enrollments_user_active` (`WHERE revoked_at IS NULL`) не даёт нарушить это правило в
   базе, поэтому «выдать ещё один вариант» без отзыва означает `UniqueViolation` посреди HTTP-запроса
   (замер: 2026-11-21, живой прогон `tests/integration/test_totp_secret_storage_db.py`).
2. **Незавершённая привязка протухает.** Без срока строка `{confirmed_at = NULL, revoked_at = NULL}`
   остаётся активной для индекса навсегда и блокирует и повторную выдачу, и новую привязку. Срок —
   `PENDING_ENROLLMENT_TTL`, равный простою сеанса: привязка подтверждается из того же сеанса,
   который её начал, и переживает его ровно на одно окно (разбор — `docs/adr/ADR-015` п. 2).
3. **Подтверждение — два соседних шага.** `confirm_enrollment` требует два кода, и второй обязан быть
   ровно на один шаг новее первого: это держит `verify_totp_pair` (`ADR-013`). Два кода одного окна —
   один и тот же код, и второй отклоняется как повтор.
4. **Подтверждение привязки не даёт полного входа.** Шаг `totp` означает «привязка подтверждена в этом
   сеансе» и в консоль не пускает: код на странице кода — отдельное событие аутентификации, в котором
   код расходуется и записывается `last_used_step` (`ADR-015` п. 3).

Секрет привязки покидает модуль ровно одним способом — полем `NewEnrollment.secret` (`ADR-014` п. 6).
Второй точки вывода нет: для проверки кода ключ открывается внутри модуля и наружу не возвращается,
и `R4d` (QR-код) строит `otpauth://`-ссылку из того же значения, которое уже показал маршрут, а не
расшифровывает `secret_enc` повторно.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal
from uuid import UUID, uuid4

from packages.common.crypto import KeyRing
from packages.identity.sessions import IDLE_TIMEOUT
from packages.identity.totp import (
    TotpCheck,
    new_totp_secret,
    verify_totp_code,
    verify_totp_pair,
)
from packages.identity.totp_secret import open_totp_secret, protect_totp_secret
from packages.storage.models import TOTP_WINDOW_DEFAULT, TotpEnrollment

# ─── параметры, заданные кодом (не настройкой) ────────────────────────────────────────────────

#: Метка `issuer` — одна на всех привязках площадки.
#:
#: Это не «красивое имя для аутентикатора»: `issuer` входит и в `otpauth://`-ссылку (`R4d`), и в
#: колонку `issuer`, то есть определяет отпечаток привязки. Значение не становится настройкой
#: намеренно: два стенда с разными метками выдали бы разные привязки из одного секрета, а менять его
#: задним числом нельзя — метки, уже введённые в генераторах, перестанут совпадать с тем, что
#: показывает приложение.
TOTP_ISSUER: Final = "tbot"

#: Срок жизни незавершённой привязки. Совпадает с простоем сеанса (§8.3, 30 минут) и не имеет своего
#: числа: привязка подтверждается из того же сеанса, который её начал.
PENDING_ENROLLMENT_TTL: Final = IDLE_TIMEOUT

#: Число кодов, подтверждающих привязку (§8.2: «2 последовательных кода»).
CONFIRMATION_CODES: Final = 2

#: Окно допуска новой привязки — значение по умолчанию из схемы (`TOTP_WINDOW_DEFAULT`, ±1 шаг).
#: Своего числа здесь нет: колонка `verify_window` ограничена CHECK-ограничением, и число из кода,
#: отличное от схемы, разошлось бы с базой молча.
DEFAULT_VERIFY_WINDOW: Final = TOTP_WINDOW_DEFAULT

#: Состояние привязки для маршрута и для человека. `expired` — вывод, а не колонка: строка при этом
#: остаётся `{confirmed_at = NULL, revoked_at = NULL}` и для уникального индекса всё ещё активна,
#: поэтому протухшую привязку обязан предшествовать отзыв перед новой выдачей.
EnrollmentState = Literal["pending", "confirmed", "revoked", "expired"]


class TotpEnrollmentError(ValueError):
    """Привязка в состоянии, в котором операция невозможна (маршрут обязан проверить это заранее)."""


class EnrollmentNotConfirmableError(TotpEnrollmentError):
    """Подтверждать нечего: привязка уже подтверждена, отозвана или протухла."""


class EnrollmentNotUsableError(TotpEnrollmentError):
    """Код входа принимается только по подтверждённой и не отозванной привязке."""


@dataclass(frozen=True)
class NewEnrollment:
    """Созданная привязка и материал для её владельца.

    Поле `secret` — base32 секрет **открытым текстом**: его показывают один раз владельцу привязки
    (§8.2), и из него `R4d` соберёт `otpauth://`. В базу он не пишется (в базе только `secret_enc`),
    в журнал не уходит и больше ниоткуда не открывается (`ADR-014` п. 6).
    """

    enrollment: TotpEnrollment
    secret: str


# ─── состояние ────────────────────────────────────────────────────────────────────────────────


def enrollment_is_stale(
    enrollment: TotpEnrollment,
    *,
    now: datetime,
    ttl: timedelta = PENDING_ENROLLMENT_TTL,
) -> bool:
    """Незавершённая привязка создана давно и её надо заменить; у подтверждённой срока нет."""
    if enrollment.confirmed_at is not None or enrollment.revoked_at is not None:
        return False
    return enrollment.enrolled_at + ttl <= now


def enrollment_state(enrollment: TotpEnrollment, *, now: datetime) -> EnrollmentState:
    """Состояние привязки по строке: `revoked` → `confirmed` → `expired` → `pending`.

    Порядок проверок значим: отозванная подтверждённая привязка (сброс администратором, §8.2 случай
    2) остаётся отозванной, а не «действующей».
    """
    if enrollment.revoked_at is not None:
        return "revoked"
    if enrollment.confirmed_at is not None:
        return "confirmed"
    if enrollment_is_stale(enrollment, now=now):
        return "expired"
    return "pending"


def open_enrollment_key(enrollment: TotpEnrollment, *, ring: KeyRing) -> bytes:
    """Ключ привязки для проверки кода; значение остаётся внутри пакета.

    AAD собирается по `id` строки и владельцу, поэтому значение из чужой строки или от чужой учётки
    не расшифровывается (`ADR-014` п. 4), а права файла KEK проверяются при каждой загрузке набора
    ключей в `packages/common/crypto.py`.
    """
    return open_totp_secret(
        enrollment.secret_enc,
        enrollment_id=enrollment.id,
        user_id=enrollment.user_id,
        ring=ring,
    )


# ─── создание и отзыв ─────────────────────────────────────────────────────────────────────────


def new_enrollment(
    *,
    user_id: UUID,
    now: datetime,
    ring: KeyRing,
    issuer: str = TOTP_ISSUER,
) -> NewEnrollment:
    """Новая незавершённая привязка: секрет, конверт в `secret_enc`, значение для однократного показа.

    Строку создаёт этот модуль, а в базу её добавляет слой доступа (`store.add`): `identity` создаёт и
    меняет объекты, персистентность держит `storage`.

    Порядок «сначала `id`, потом шифрование, потом конструктор» здесь не стиль, а единственно возможный
    порядок: AAD привязан к `id` строки (`ADR-014` п. 4), поэтому шифровать до появления идентификатора
    нельзя; а сконструировать строку с пустым `secret_enc` и заполнить поле позже нельзя в принципе —
    валидатор модели отклоняет пустое значение ещё до запроса (`ADR-014` п. 6; замер 2026-11-22:
    `EnvelopeError: длина значения 0 байт меньше минимума конверта (95)`). Именно этот отказ и держит
    модель от записи открытого секрета, и он же делает невозможным «создать строку, а шифртекст
    дописать потом».
    """
    enrollment_id = uuid4()
    secret = new_totp_secret()
    secret_enc = protect_totp_secret(
        secret,
        enrollment_id=enrollment_id,
        user_id=user_id,
        ring=ring,
    )
    enrollment = TotpEnrollment(
        id=enrollment_id,
        user_id=user_id,
        secret_enc=secret_enc,
        issuer=issuer,
        enrolled_at=now,
        confirmed_at=None,
        revoked_at=None,
        verify_window=DEFAULT_VERIFY_WINDOW,
        last_used_step=None,
    )
    return NewEnrollment(enrollment=enrollment, secret=secret)


def revoke_enrollment(enrollment: TotpEnrollment, *, now: datetime) -> TotpEnrollment:
    """Отозвать привязку, не удаляя строку (§8.4: история привязок остаётся в таблице)."""
    enrollment.revoked_at = now
    return enrollment


# ─── подтверждение и код входа ────────────────────────────────────────────────────────────────

#: Функция, которая берёт на себя атомарность одноразовости: ей передают номер шага принятого кода, а
#: она отвечает `False`, если этот шаг (или более свежий) уже израсходован другим запросом. Реализует
#: её слой доступа guarded-`UPDATE` (`ADR-015` п. 5); здесь — только решение показать «повтор кода».
CounterClaim = Callable[[int], bool]


def confirm_enrollment(
    enrollment: TotpEnrollment,
    first_code: str,
    second_code: str,
    *,
    ring: KeyRing,
    now: datetime,
) -> TotpCheck:
    """Подтвердить привязку двумя последовательными кодами (§8.2) и записать `confirmed_at`.

    Успех — единственный момент, когда строка становится подтверждённой. Успех же фиксирует
    `last_used_step`: код, которым подтвердили привязку, не должен открывать вход (§8.2 «коды
    принимаются один раз» действует на обе половины процесса). Отказ — `confirmed_at` остаётся
    пустым, `last_used_step` не меняется, а учёт неудачи и блокировка входа живут слоя доступа:
    здесь нет ни базы, ни ленты `totp_failures`.
    """
    state = enrollment_state(enrollment, now=now)
    if state != "pending":
        raise EnrollmentNotConfirmableError(f"привязка в состоянии {state!r}: подтверждать нечего")
    key = open_enrollment_key(enrollment, ring=ring)
    result = verify_totp_pair(
        key,
        first_code,
        second_code,
        last_used_counter=enrollment.last_used_step,
        window=enrollment.verify_window,
        now=now,
    )
    if result.status == "accepted" and result.counter is not None:
        enrollment.confirmed_at = now
        enrollment.last_used_step = result.counter
    return result


def verify_enrollment_code(
    enrollment: TotpEnrollment,
    code: str,
    *,
    ring: KeyRing,
    now: datetime,
    claim: CounterClaim,
) -> TotpCheck:
    """Код входа по подтверждённой привязке с расходом шага (`ADR-013`).

    `claim` обязана быть атомарной операцией слоя доступа: проверка «шаг ещё не израсходован» и его
    запись должны быть одним `UPDATE`, иначе два параллельных запроса с одним кодом пройдут оба
    (`ADR-015` п. 5). Если `claim` отказала, результат превращается в `replay`: второй запрос не
    получает доступ и не узнаёт ничего лишнего, а поле `last_used_step` в памяти остаётся прежним —
    его не обновляют неудачной попыткой.
    """
    if enrollment.confirmed_at is None or enrollment.revoked_at is not None:
        raise EnrollmentNotUsableError(
            "код входа принимается только по подтверждённой и не отозванной привязке"
        )
    key = open_enrollment_key(enrollment, ring=ring)
    result = verify_totp_code(
        key,
        code,
        last_used_counter=enrollment.last_used_step,
        window=enrollment.verify_window,
        now=now,
    )
    if result.status != "accepted" or result.counter is None:
        return result
    if not claim(result.counter):
        return TotpCheck(status="replay", counter=result.counter, step_offset=result.step_offset)
    enrollment.last_used_step = result.counter
    return result
