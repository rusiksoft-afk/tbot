"""Юнит-блокировка перебора входа (TZ §9 и §8.2, `T-101`; обязательная `test_login_lockout`).

Живая база не нужна: счётчик и срок блокировки — поля объекта, а ограничения схемы
(`users.failed_attempts >= 0`, `TIMESTAMPTZ`) проверяет `tests/integration/*` там, где появится
запись через SQLAlchemy. Здесь проверяется порядок, который нельзя сломать: пока блокировка
активна, пароль не сравнивается; после истечения срока отсчёт начинается заново; блокировка не
снимается сменой пароля.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from packages.identity.passwords import ARGON2_HASH_PREFIX, PasswordPolicyError
from packages.identity.users import (
    LOCK_DURATION,
    MAX_FAILED_ATTEMPTS,
    LoginLockedError,
    active_lock_until,
    apply_new_password,
    clear_login_lock,
    ensure_login_allowed,
    new_user,
    register_login_failure,
    register_login_success,
)
from packages.storage.models import User

#: Фиксированный «сейчас»: время блокировки должно быть проверяемым, а не «примерно через 15 минут».
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


@pytest.fixture
def account() -> User:
    """Новая учётная запись на каждую проверку: счётчик мутирует объект, тесты не наследуют состояние."""
    return new_user(
        login="ivan.petrov", password="правильная-лошадь-2026", role="operator", now=NOW
    )


def test_login_lockout(account: User) -> None:
    """TZ §9 (сценарий входа) и §8.2: 5 неудач подряд → блокировка на 15 минут, 5-я попытка — последняя."""
    assert (
        MAX_FAILED_ATTEMPTS == 5
    ), "TZ §9: «неверный пароль (5 попыток) → блокировка с объяснением»"
    assert (
        timedelta(minutes=15) == LOCK_DURATION
    ), "срок блокировки выбран заказчиком (ask 633f8d2b)"

    ensure_login_allowed(account, now=NOW)

    for attempt in range(1, MAX_FAILED_ATTEMPTS):
        assert register_login_failure(account, now=NOW) is None
        assert account.failed_attempts == attempt
        ensure_login_allowed(account, now=NOW)

    until = register_login_failure(account, now=NOW)
    assert until == NOW + LOCK_DURATION
    assert account.locked_until == until
    assert (
        account.failed_attempts == 0
    ), "счётчик обнуляется при блокировке, иначе после срока он же и продолжится"

    with pytest.raises(LoginLockedError) as caught:
        ensure_login_allowed(account, now=NOW + timedelta(minutes=14))
    assert caught.value.until == until

    # Граница: ровно через 15 минут блокировка считается истёкшей.
    assert active_lock_until(account, now=until) is None
    ensure_login_allowed(account, now=until)


def test_истёкшая_блокировка_не_отличается_от_отсутствия(account: User) -> None:
    """Отдельного флага «разблокирован» в схеме нет: два источника правды неизбежно разъезжаются."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    assert account.locked_until is not None
    assert active_lock_until(account, now=NOW + LOCK_DURATION + timedelta(seconds=1)) is None
    assert active_lock_until(account, now=NOW + LOCK_DURATION - timedelta(seconds=1)) is not None


def test_после_истечения_срока_отсчёт_начинается_заново(account: User) -> None:
    """Иначе одна неудача через секунду после разблокировки блокировала бы вход снова."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    later = NOW + LOCK_DURATION
    ensure_login_allowed(account, now=later)

    assert register_login_failure(account, now=later) is None
    assert account.failed_attempts == 1
    for _ in range(MAX_FAILED_ATTEMPTS - 2):
        register_login_failure(account, now=later)
    assert register_login_failure(account, now=later) == later + LOCK_DURATION


def test_успешный_вход_обнуляет_счётчик_неудач(account: User) -> None:
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        register_login_failure(account, now=NOW)
    assert account.failed_attempts == MAX_FAILED_ATTEMPTS - 1
    register_login_success(account, now=NOW)
    assert account.failed_attempts == 0
    assert account.locked_until is None
    # следующая неудача — снова первая, а не пятая
    register_login_failure(account, now=NOW)
    assert account.failed_attempts == 1


def test_успех_во_время_активной_блокировки_это_ошибка_вызывающего(account: User) -> None:
    """Если счётчик блокировки активен, сравнивать пароль уже нельзя — и «успех» это заметит."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    with pytest.raises(LoginLockedError):
        register_login_success(account, now=NOW)
    assert account.failed_attempts == 0
    assert account.locked_until is not None, "ошибочный вызов не должен снимать блокировку"


def test_разблокировка_администратором_снимает_срок_и_счётчик(account: User) -> None:
    """Страница администратора «блокировка/разблокировка» (§9); событие обязано попасть в журнал (§8.7)."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    clear_login_lock(account)
    assert account.locked_until is None
    assert account.failed_attempts == 0
    ensure_login_allowed(account, now=NOW)


def test_смена_пароля_не_снимает_блокировку(account: User) -> None:
    """Иначе блокировка перебора обходится сменой пароля."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    apply_new_password(account, "новый-пароль-2026-год", now=NOW)
    with pytest.raises(LoginLockedError):
        ensure_login_allowed(account, now=NOW)


def test_смена_пароля_ставит_argon2id_и_отметку_времени(account: User) -> None:
    before = account.password_hash
    apply_new_password(account, "новый-пароль-2026-год", now=NOW + timedelta(days=1))
    assert account.password_hash.startswith(ARGON2_HASH_PREFIX)
    assert account.password_hash != before
    assert account.password_updated_at == NOW + timedelta(days=1)


def test_отклонённый_политикой_пароль_не_меняет_хэш(account: User) -> None:
    """Половина смены пароля хуже, чем отказ: хэш обязан остаться прежним."""
    before = account.password_hash
    with pytest.raises(PasswordPolicyError):
        apply_new_password(account, "ivan.petrov", now=NOW)
    assert account.password_hash == before
    assert account.password_updated_at == NOW


def test_наивное_время_отвергается(account: User) -> None:
    """§2.7: время без пояса недопустимо — иначе «15 минут» превращаются в неопределённость."""
    # наивное значение получается снятием пояса с осознанной константы: конструктор с tzinfo
    # здесь был бы самообманом, а линтер требует указывать пояс явно
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(ValueError, match="наивный datetime"):
        register_login_failure(account, now=naive)
    with pytest.raises(ValueError, match="наивный datetime"):
        active_lock_until(account, now=naive)


def test_новая_учётная_запись_без_блокировки_с_нулевым_счётчиком() -> None:
    account = new_user(
        login="ivan.petrov", password="правильная-лошадь-2026", role="operator", now=NOW
    )
    assert (
        account.state == "invited"
    ), "§1.2: начальное состояние — приглашение, шага одобрения ещё нет"
    assert account.failed_attempts == 0
    assert account.locked_until is None
    assert account.password_hash.startswith(ARGON2_HASH_PREFIX)
    assert account.password_updated_at == NOW


def test_о_блокировке_сообщают_срок_а_не_число_попыток(account: User) -> None:
    """§9: «счётчик попыток не показывается (чтобы не помогать перебору), но блокировка объясняется»."""
    for _ in range(MAX_FAILED_ATTEMPTS):
        register_login_failure(account, now=NOW)
    with pytest.raises(LoginLockedError) as caught:
        ensure_login_allowed(account, now=NOW)
    error = caught.value
    assert not hasattr(
        error, "attempts"
    ), "ошибка не должна отдавать число попыток слою отображения"
    assert error.until > NOW
    assert "заблокирован" in str(error)
