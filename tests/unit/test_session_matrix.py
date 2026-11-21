"""Юнит-матрица сессий входа (TZ §8.3, `T-102`; обязательная `test_session_matrix`).

Живая база не нужна: границы срока, шаг входа, пересоздание и смена пароля — это арифметика и
переходы состояний. Что здесь дорого: предельные значения (`30:00` и `12:00` — ровно на границе),
запрет продлевать мёртвую сессию и порядок смены пароля (отказ политики не должен трогать чужие
сессии). Проверки «revoked_at читается на каждом запросе» в базе — `tests/integration/*`.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from packages.identity.passwords import ARGON2_HASH_PREFIX, PasswordPolicyError
from packages.identity.sessions import (
    ABSOLUTE_TIMEOUT,
    AUTH_STEP_ORDER,
    CRITICAL_ACTIONS,
    IDLE_TIMEOUT,
    MalformedSessionTokenError,
    SessionAbsoluteExpiredError,
    SessionIdleExpiredError,
    SessionInvalidError,
    SessionRevokedError,
    SessionStepError,
    advance_auth_step,
    change_password,
    create_session,
    ensure_full_auth,
    ensure_session_active,
    register_session_activity,
    rotate_session,
    token_hash_of,
    token_secret,
)
from packages.identity.users import new_user
from packages.storage.models import User, UserSession

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
USER_ID = UUID("01a1fa1a-0000-7000-8000-000000000001")


def _session(*, step: str = "password", created_at: datetime = NOW) -> UserSession:
    """Сессия, выпущенная в фиксированный момент (значение куки тестом не используется)."""
    return create_session(
        USER_ID, ip="203.0.113.9", user_agent="Firefox/141", auth_step=step, now=created_at
    ).record


# ─── матрица сроков ──────────────────────────────────────────────────────────────────────────


def test_session_matrix() -> None:
    """Матрица §8.3: что живёт, а что уже нет, включая предельные значения ровно на границе."""
    sliding = _session()
    # активность каждые 10 минут — «скользящая» сессия, которая упирается в абсолютный срок
    for minute in range(10, 12 * 60, 10):
        register_session_activity(sliding, now=NOW + timedelta(minutes=minute))
    sliding_abs_boundary = sliding.expires_at

    revoked_early = _session()
    revoked_early.revoked_at = NOW + timedelta(minutes=5)

    created_in_future = create_session(USER_ID, now=NOW + timedelta(minutes=1)).record

    cases: list[tuple[str, UserSession, datetime, str | None]] = [
        ("свежая сессия сразу", _session(), NOW, None),
        (
            "29:59.999999 без активности",
            _session(),
            NOW + IDLE_TIMEOUT - timedelta(microseconds=1),
            None,
        ),
        ("ровно 30 минут без активности", _session(), NOW + IDLE_TIMEOUT, "idle"),
        (
            "30 минут, но была активность на 29-й",
            _slid_until(NOW + timedelta(minutes=29)),
            NOW + IDLE_TIMEOUT,
            None,
        ),
        (
            "скользящая: 11:59:59.999999 от создания",
            sliding,
            sliding_abs_boundary - timedelta(microseconds=1),
            None,
        ),
        ("скользящая: ровно 12:00:00 от создания", sliding, sliding_abs_boundary, "absolute"),
        ("активная сессия через 12 часов", _session(), NOW + ABSOLUTE_TIMEOUT, "absolute"),
        (
            "отозванная на 5-й минуте, проверка на 3-й",
            revoked_early,
            NOW + timedelta(minutes=3),
            "revoked",
        ),
        (
            "отозванная и с истёкшим idle — причина «отозвана»",
            revoked_early,
            NOW + ABSOLUTE_TIMEOUT,
            "revoked",
        ),
        ("запись создана «в будущем»", created_in_future, NOW, "not_yet"),
    ]

    for title, session, moment, expected in cases:
        if expected is None:
            ensure_session_active(session, now=moment)  # без исключений
            continue
        with pytest.raises(SessionInvalidError) as caught:
            ensure_session_active(session, now=moment)
        assert (
            caught.value.code == expected
        ), f"{title}: ожидался код {expected!r}, получен {caught.value.code!r}"


def _slid_until(moment: datetime) -> UserSession:
    session = _session()
    register_session_activity(session, now=moment)
    return session


def test_абсолютный_срок_не_продлевается_активностью() -> None:
    """§8.3: абсолютный срок отсчитывается от создания; никакой активности он не прощает."""
    session = _session()
    for minute in range(10, 12 * 60 + 1, 10):
        moment = NOW + timedelta(minutes=minute)
        if minute >= 12 * 60:
            with pytest.raises(SessionAbsoluteExpiredError):
                register_session_activity(session, now=moment)
            break
        register_session_activity(session, now=moment)
    assert session.expires_at == NOW + ABSOLUTE_TIMEOUT
    assert session.revoked_at is None, "истечение срока не должно записываться как отзыв"


def test_продление_не_может_уйти_за_абсолютный_срок() -> None:
    """`expires_at` = min(сейчас + idle, создание + abs): скользящий срок упирается в потолок.

    Активность обязательна каждые 20 минут: без неё сессия сначала умирает по idle, и проверить
    потолок было бы невозможно (это не баг, а ровно то, что требует §8.3).
    """
    session = _session()
    for minute in range(20, int(ABSOLUTE_TIMEOUT.total_seconds() // 60) - 4, 20):
        register_session_activity(session, now=NOW + timedelta(minutes=minute))
    register_session_activity(session, now=NOW + ABSOLUTE_TIMEOUT - timedelta(minutes=5))
    assert session.expires_at == NOW + ABSOLUTE_TIMEOUT


def test_нельзя_продлить_мёртвую_сессию_и_это_ничего_не_меняет() -> None:
    """Продление отозванной или просроченной сессии запрещено, и состояние остаётся прежним.

    Иначе ошибка запроса «не заметила» отзыв, и отозванная сессия получила бы ещё 30 минут —
    ровно тот случай, который §8.3 называет «отзыв отражается немедленно».
    """
    revoked = _session()
    revoke_moment = NOW + timedelta(minutes=3)
    revoked.revoked_at = revoke_moment
    before = (revoked.last_seen_at, revoked.expires_at)

    with pytest.raises(SessionRevokedError):
        register_session_activity(revoked, now=NOW + timedelta(minutes=4))
    assert (revoked.last_seen_at, revoked.expires_at) == before

    expired = _session()
    with pytest.raises(SessionIdleExpiredError):
        register_session_activity(expired, now=NOW + IDLE_TIMEOUT)
    assert (expired.last_seen_at, expired.expires_at) == (NOW, NOW + IDLE_TIMEOUT)


# ─── шаг входа ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("from_step", AUTH_STEP_ORDER)
@pytest.mark.parametrize("to_step", AUTH_STEP_ORDER)
def test_шаг_входа_только_вперёд(from_step: str, to_step: str) -> None:
    """Каждая пара переходов: вперёд разрешён, назад и «в неизвестность» — запрещены (§8.2)."""
    session = _session(step=from_step)
    forward = AUTH_STEP_ORDER.index(to_step) >= AUTH_STEP_ORDER.index(from_step)
    if forward:
        advance_auth_step(session, step=to_step, now=NOW)
        assert session.auth_step == to_step
    else:
        with pytest.raises(SessionStepError, match="нельзя откатить"):
            advance_auth_step(session, step=to_step, now=NOW)
        assert session.auth_step == from_step, "отказ не должен менять шаг"


def test_неизвестный_шаг_отвергается() -> None:
    session = _session()
    with pytest.raises(SessionStepError, match="неизвестный шаг"):
        advance_auth_step(session, step="admin", now=NOW)
    with pytest.raises(SessionStepError, match="неизвестный шаг"):
        create_session(USER_ID, auth_step="root", now=NOW)


def test_полный_доступ_только_на_шаге_full() -> None:
    """§8.2: шаг `password` даёт доступ только к странице кода и выходу."""
    session = _session()
    with pytest.raises(SessionStepError, match="нужен полный вход"):
        ensure_full_auth(session, now=NOW)
    advance_auth_step(session, step="full", now=NOW)
    ensure_full_auth(session, now=NOW)


# ─── выпуск и материал сессии ────────────────────────────────────────────────────────────────


def test_выпуск_ставит_шаг_password_и_обе_границы() -> None:
    issued = create_session(USER_ID, ip="198.51.100.7", user_agent="Safari/18", now=NOW)
    record = issued.record
    assert record.id is not None, "ключ нужен сразу: пересоздание и страница сессий сравнивают id"
    assert record.auth_step == "password", "шаг входа начинается с пароля (§8.2)"
    assert record.created_at == NOW
    assert record.last_seen_at == NOW
    assert record.expires_at == NOW + IDLE_TIMEOUT
    assert record.revoked_at is None
    assert (record.ip, record.user_agent) == ("198.51.100.7", "Safari/18")


def test_значение_куки_это_256_бит_а_в_базу_идёт_sha256() -> None:
    """§8.3 «случайный id 256 бит»: значение — base64url 43 символа, в `token_hash` — 64 hex."""
    seen_secrets: set[str] = set()
    seen_hashes: set[str] = set()
    for _ in range(24):
        secret = token_secret()
        assert re.fullmatch(
            r"[A-Za-z0-9_-]{43}", secret
        ), f"неожиданная форма значения куки: {secret!r}"
        digest = token_hash_of(secret)
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"хэш не 64 hex: {digest!r}"
        assert digest == hashlib.sha256(secret.encode("utf-8")).hexdigest()
        seen_secrets.add(secret)
        seen_hashes.add(digest)
    assert len(seen_secrets) == 24, "значения куки не случайны"
    assert len(seen_hashes) == 24, "хэши значений куки не случайны"


def test_форма_значения_куки_проверяется_до_похода_в_базу() -> None:
    """Обрезанная или подставленная кука — отдельная причина, а не «сессия не найдена»."""
    for bad in ("", "a" * 42, "a" * 44, "aaaa" + " " * 39, "a" * 42 + "=", "привет" + "a" * 37):
        with pytest.raises(MalformedSessionTokenError, match="43 символа"):
            token_hash_of(bad)


def test_значение_куки_не_попадает_в_repr() -> None:
    """§8.4: материал доступа не попадает в логи; `repr` структуры обязан его маскировать."""
    issued = create_session(USER_ID, now=NOW)
    rendered = repr(issued)
    assert issued.secret not in rendered
    assert issued.record.token_hash not in rendered
    assert "<скрыто>" in rendered


def test_наивное_время_отвергается_до_создания_объекта() -> None:
    """§2.7: время без пояса невозможно, и половина выпущенной сессии не остаётся."""
    with pytest.raises(ValueError, match="наивный datetime"):
        create_session(USER_ID, now=NOW.replace(tzinfo=None))
    session = _session()
    with pytest.raises(ValueError, match="наивный datetime"):
        register_session_activity(session, now=NOW.replace(tzinfo=None))


# ─── пересоздание после критичных действий ───────────────────────────────────────────────────


def test_пересоздание_требует_причину_из_перечня_8_3() -> None:
    for reason in sorted(CRITICAL_ACTIONS):
        session = _session()
        issued = rotate_session(session, reason=reason, now=NOW)
        assert session.revoked_at == NOW
        assert issued.record.user_id == session.user_id
        assert issued.record.token_hash != session.token_hash
        assert issued.secret != session.token_hash
    attempt = _session()
    with pytest.raises(ValueError, match="не входит в перечень"):
        rotate_session(attempt, reason="просто_так", now=NOW)
    assert attempt.revoked_at is None, "незнакомая причина не должна приводить к отзыву"


def test_пересоздание_сохраняет_шаг_но_меняет_и_значение_и_ключ() -> None:
    """Новая сессия — это новая запись: прежнее значение куки не должно пережить ротацию."""
    old = create_session(
        USER_ID, ip="203.0.113.9", user_agent="Edge/141", auth_step="full", now=NOW
    ).record
    issued = rotate_session(old, reason="token_connect", now=NOW + timedelta(minutes=1))
    assert issued.record.auth_step == "full"
    assert issued.record.id != old.id
    assert issued.record.token_hash != old.token_hash
    assert old.revoked_at == NOW + timedelta(minutes=1)
    assert issued.record.created_at == NOW + timedelta(minutes=1)
    assert issued.record.expires_at == NOW + timedelta(minutes=1) + IDLE_TIMEOUT


def test_пересоздание_по_мёртвой_сессии_отказывается() -> None:
    dead = _session()
    with pytest.raises(SessionIdleExpiredError):
        rotate_session(dead, reason="password_change", now=NOW + IDLE_TIMEOUT)
    assert dead.revoked_at is None, "отказ не должен оставлять следов"


# ─── смена пароля: §8.1 + §8.3 + строка матрицы §8.8 ─────────────────────────────────────────


@pytest.fixture
def account() -> User:
    return new_user(
        login="ivan.petrov", password="правильная-лошадь-2026", role="operator", now=NOW
    )


def test_смена_пароля_пересоздаёт_текущую_и_отзывает_остальные(account: User) -> None:
    """§8.1 «после смены все сессии, кроме текущей, отзываются» + §8.3 «текущая пересоздаётся»."""
    current = create_session(USER_ID, now=NOW).record
    other_a = create_session(USER_ID, now=NOW).record
    other_b = create_session(USER_ID, now=NOW).record

    result = change_password(
        account,
        "новая-лошадь-2026-год",
        current=current,
        others=[other_a, other_b],
        now=NOW,
    )

    assert account.password_hash.startswith(ARGON2_HASH_PREFIX)
    assert result.issued is not None
    assert result.issued.secret != ""
    assert current.revoked_at == NOW, "старая кука обязана перестать работать"
    assert other_a.revoked_at == NOW
    assert other_b.revoked_at == NOW
    assert result.revoked_others == (other_a, other_b)
    assert result.issued.record.id not in {current.id, other_a.id, other_b.id}


def test_отказ_политики_не_трогает_ни_пароль_ни_сессии(account: User) -> None:
    """Отказ §8.1 не должен отзывов чужих сессий и половины смены пароля."""
    current = create_session(USER_ID, now=NOW).record
    other = create_session(USER_ID, now=NOW).record
    before_hash = account.password_hash

    with pytest.raises(PasswordPolicyError):
        change_password(account, account.login, current=current, others=[other], now=NOW)

    assert account.password_hash == before_hash
    assert current.revoked_at is None
    assert other.revoked_at is None


def test_смена_пароля_без_текущей_сессии(account: User) -> None:
    """Сброс администратором (§8.1): пересоздавать нечего, остальные отзываются."""
    other = create_session(USER_ID, now=NOW).record
    result = change_password(
        account, "новая-лошадь-2026-год", current=None, others=[other], now=NOW
    )
    assert result.issued is None
    assert other.revoked_at == NOW


def test_смена_пароля_по_просроченной_сессии_не_начинается(account: User) -> None:
    """Если текущая сессия уже мертва, операцию нельзя выполнять «наполовину».

    Порядок «сначала проверка сессии, потом пароль» — сознательный: пароль уже принятый, его
    нельзя отменить задним числом, а доделывать отзывы после отказа было бы хуже.
    """
    current = create_session(USER_ID, now=NOW).record
    before_hash = account.password_hash
    with pytest.raises(SessionIdleExpiredError):
        change_password(account, "новая-лошадь-2026-год", current=current, now=NOW + IDLE_TIMEOUT)
    assert account.password_hash == before_hash


def test_смена_пароля_не_снимает_блокировку_перебора(account: User) -> None:
    """Напоминание о границе `T-101`: разблокировка — отдельное действие, не побочный эффект."""
    current = create_session(USER_ID, now=NOW).record
    assert account.locked_until is None
    assert account.failed_attempts == 0
    change_password(account, "новая-лошадь-2026-год", current=current, now=NOW)
    assert account.locked_until is None


def test_наивное_время_в_смене_пароля_не_мутирует_ничего(account: User) -> None:
    current = create_session(USER_ID, now=NOW).record
    other = create_session(USER_ID, now=NOW).record
    before_hash = account.password_hash
    with pytest.raises(ValueError, match="наивный datetime"):
        change_password(
            account,
            "новая-лошадь-2026-год",
            current=current,
            others=[other],
            now=NOW.replace(tzinfo=None),
        )
    assert account.password_hash == before_hash
    assert current.revoked_at is None
    assert other.revoked_at is None
