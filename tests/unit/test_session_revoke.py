"""Юнит-отзыв сессий (TZ §8.3, `T-102`; обязательная `test_session_revoke`).

§8.3: «Сессии видны пользователю (список устройств, отзыв по одной/всех), отзыв отражается
немедленно (проверка `sessions.revoked_at` на каждом запросе)». Здесь проверяется та часть,
которая не требует HTTP и базы: семантика самого отзыва (одна/все, повторный отзыв, момент
первого отзыва), немедленная видимость для слоя проверки и то, что страница «мои устройства»
не отдаёт наружу материал сессии.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from packages.identity.sessions import (
    IDLE_TIMEOUT,
    MalformedSessionTokenError,
    SessionRevokedError,
    advance_auth_step,
    create_session,
    describe_session,
    describe_sessions,
    register_session_activity,
    revoke_session,
    revoke_sessions,
    session_is_active,
    token_hash_of,
)
from packages.storage.models import UserSession

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
USER_ID = UUID("01a1fa1a-0000-7000-8000-000000000002")


def _session(*, created_at: datetime = NOW, ip: str = "203.0.113.9") -> UserSession:
    return create_session(USER_ID, ip=ip, user_agent="Firefox/141", now=created_at).record


def test_session_revoke() -> None:
    """Отзыв работает сразу: следующий запрос той же сессии уже невозможно выполнить."""
    session = _session()
    assert session_is_active(session, now=NOW)

    assert revoke_session(session, now=NOW + timedelta(minutes=1)) is True
    assert session.revoked_at == NOW + timedelta(minutes=1)
    assert session_is_active(session, now=NOW + timedelta(minutes=1)) is False

    with pytest.raises(SessionRevokedError) as caught:
        advance_auth_step(session, step="full", now=NOW + timedelta(minutes=2))
    assert caught.value.code == "revoked"
    assert session.auth_step == "password", "отказ не должен двигать шаг входа"


def test_повторный_отзыв_не_перетирает_момент_первого() -> None:
    """Момент отзыва — доказательство для разбора инцидента, перетирать его нельзя."""
    session = _session()
    first = NOW + timedelta(minutes=2)
    assert revoke_session(session, now=first) is True
    assert revoke_session(session, now=NOW + timedelta(hours=3)) is False
    assert session.revoked_at == first


def test_отзыв_всех_кроме_текущей() -> None:
    """§8.3 «отзыв по одной/всех»: страница «выйти везде, кроме этого браузера»."""
    current = _session()
    others = [_session(created_at=NOW + timedelta(minutes=1), ip="198.51.100.7") for _ in range(3)]
    revoked = revoke_sessions([current, *others], except_ids=[current.id], now=NOW)

    assert [item.id for item in revoked] == [item.id for item in others]
    assert current.revoked_at is None
    assert all(item.revoked_at == NOW for item in others)
    assert session_is_active(current, now=NOW)


def test_отзыв_возвращает_только_фактически_отозванные() -> None:
    """Возвращаются объекты, а не счётчик: по каждой отозванной обязательна запись в журнал (`T-109`)."""
    fresh = _session()
    already = _session()
    already.revoked_at = NOW - timedelta(days=1)

    revoked = revoke_sessions([fresh, already, already], now=NOW)
    assert [item.id for item in revoked] == [fresh.id]
    assert already.revoked_at == NOW - timedelta(days=1)


def test_отозванную_сессию_нельзя_продлить() -> None:
    """Продление idle после отзыва — ровно та ошибка, из-за которой отзыв стал бы фиктивным."""
    session = _session()
    revoke_session(session, now=NOW + timedelta(minutes=1))
    with pytest.raises(SessionRevokedError):
        register_session_activity(session, now=NOW + timedelta(minutes=2))
    assert session.last_seen_at == NOW
    assert session.expires_at == NOW + IDLE_TIMEOUT


def test_отзыв_не_зависит_от_того_был_ли_запрос_между_вызовами() -> None:
    """Слои проверки и отзыва не «помнят» сессию: эффект отзыва виден без промежуточных вызовов."""
    session = _session()
    assert session_is_active(session, now=NOW)
    revoke_session(session, now=NOW)
    assert session_is_active(session, now=NOW) is False
    assert session_is_active(session, now=NOW + timedelta(minutes=29)) is False


def test_страница_сессий_не_отдаёт_материал_сессии() -> None:
    """Ни значение куки, ни `token_hash` не попадают в описание — их рисует шаблонизатор (§8.3)."""
    issued = create_session(USER_ID, ip="203.0.113.9", user_agent="Edge/141", now=NOW)
    descriptor = describe_session(issued.record, current_id=issued.record.id, now=NOW)

    field_names = {item.name for item in descriptor.__dataclass_fields__.values()}
    assert field_names.isdisjoint({"token", "token_hash", "secret", "secret_hash"})
    rendered = str(descriptor)
    assert issued.secret not in rendered
    assert issued.record.token_hash not in rendered
    assert descriptor.is_current is True
    assert descriptor.is_active is True
    assert (descriptor.ip, descriptor.user_agent) == ("203.0.113.9", "Edge/141")


def test_список_сессий_активные_первыми_и_просроченные_показаны() -> None:
    """§8.3: пользователь вправе увидеть и отозванные, и просроченные входы; активные — выше.

    Все сессии созданы в прошлом относительно «сейчас»: сессия «из будущего» неактивна по
    другой причине (расхождение часов), и матрица порядка перестала бы быть матрицей.
    """
    # idle = 30 минут, поэтому у каждой сессии активность не позже получаса после создания:
    # иначе она неактивна по idle, и матрица порядка перестала бы быть матрицей
    older = _session(created_at=NOW - timedelta(minutes=50), ip="203.0.113.10")
    register_session_activity(older, now=NOW - timedelta(minutes=25))
    recent = _session(created_at=NOW - timedelta(minutes=20), ip="203.0.113.11")
    register_session_activity(recent, now=NOW - timedelta(minutes=5))
    stale = _session(created_at=NOW - timedelta(days=1), ip="198.51.100.9")
    revoke_session(stale, now=NOW - timedelta(hours=1))

    rows = describe_sessions([older, stale, recent], current_id=recent.id, now=NOW)
    assert [row.id for row in rows] == [recent.id, older.id, stale.id]
    assert [row.is_active for row in rows] == [True, True, False]
    assert [row.is_current for row in rows] == [True, False, False]

    only_active = describe_sessions([older, stale, recent], only_active=True, now=NOW)
    assert [row.id for row in only_active] == [recent.id, older.id]


def test_описание_просроченной_сессии_отличается_от_отозванной() -> None:
    """Обе неактивны, но причины разные: интерфейс обязан показать «истекло», а не «отозвано»."""
    expired = _session()
    revoked = _session()
    revoke_session(revoked, now=NOW + timedelta(minutes=1))

    expired_row = describe_session(expired, now=NOW + IDLE_TIMEOUT)
    revoked_row = describe_session(revoked, now=NOW + timedelta(minutes=2))

    assert expired_row.is_active is False
    assert revoked_row.is_active is False
    assert expired_row.revoked_at is None
    assert revoked_row.revoked_at == NOW + timedelta(minutes=1)


def test_наивное_время_в_отзыве_и_в_описании_отвергается() -> None:
    """§2.7: наивное время невозможно ни в отзыве, ни в описании."""
    session = _session()
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(ValueError, match="наивный datetime"):
        revoke_session(session, now=naive)
    assert session.revoked_at is None
    with pytest.raises(ValueError, match="наивный datetime"):
        describe_session(session, now=naive)


def test_отзыв_пустого_списка_безопасен() -> None:
    assert revoke_sessions([], now=NOW) == ()
    assert revoke_sessions([], except_ids=[uuid4()], now=NOW) == ()


def test_обрезанное_или_подставленное_значение_куки_отвергается_до_запроса() -> None:
    """Проверка формы значения идёт до похода в базу: «сессии нет» и «куку испортили» — разные причины."""
    broken_values = ("a" * 42, "a" * 44, "a" * 43 + "=", "a" * 42 + "й", "a" * 42 + " ", "")
    for value in broken_values:
        with pytest.raises(MalformedSessionTokenError, match="43 символа"):
            token_hash_of(value)
