"""Живая половина механизма лимитов: атомарный инкремент, чтение окна и чистка (T-102, срез `R3d`).

Схема счётчика (DDL, ограничения, роли) проверяется в `tests/integration/test_rate_buckets_db.py`.
Здесь — то, что может подтвердить только сервер, и именно про механизм:

* **инкремент не теряет обращений**: `INSERT … ON CONFLICT (scope, bucket_key, window_start)
  DO UPDATE SET attempts = attempts + 1 RETURNING attempts` под конкурентными сессиями обязан
  дать ровно столько попыток, сколько их было. `ADR-007` называет эту формулу единственно верной;
  «прочитали — прибавили — записали» на живом сервере теряет обращения, и лимит
  «10 запросов/мин/IP» превращается в «сколько процессов успели записать». Офлайновая половинка
  этого не видит: там один поток и нет сериализации обращений;
* **`RETURNING` возвращает счётчик после увеличения**, а не до: от этого зависит, на каком запросе
  наступит отказ (на одиннадцатом, а не на двенадцатом);
* **окна 60 и 300 секунд — разные строки**: счётчик неудач перебора (§8.2) не должен съедаться
  обычными запросами (§8.3), иначе адрес закрывался бы за действия, которые неудачами не были;
* **`newest_counted_window` берёт самое свежее подходящее окно**, не видит окон ниже порога и не
  видит окон за границей поиска: по нему слой входа выносит бан;
* **срок бана выводится из полей прочитанной строки** (`window_start + window_seconds +
  IP_BAN_DURATION`, `ADR-009`), а не из «сейчас»;
* **чистка удаляет только просроченные окна** (`window_start` старше суток) и не трогает ни свежие
  окна, ни соседние таблицы: `ADR-007` требует, чтобы окно жило сутки и потом удалялось, иначе
  таблица растёт бесконечно (в ней строка на связку «область × ключ × окно»).

Проверяются настоящим `SqlStore` и настоящим `apps.jobs.maintenance`, а не SQL-подобной
подделкой: расхождение между запросом к базе и тем, что знает `MemoryStore`, осталось бы
незамеченным до площадки.

Запуск: та же `TBOT_DB_URL`, что у остальных живых групп (шаг job'а `migrations`). Без переменной
группа пропускается — именно поэтому шаг и вызывается с `-rs`.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from apps.jobs.maintenance import (
    RATE_BUCKET_PURGE_INTERVAL_S,
    RATE_BUCKET_RETENTION,
    build_job_engine,
    purge_expired_rate_buckets,
)
from apps.web.security.rate_limit import (
    IP_BAN_DURATION,
    IP_BAN_SCOPE,
    IP_BAN_THRESHOLD,
    LOGIN_IP_SCOPE,
    align_window_start,
    ban_until,
)
from apps.web.store import SqlStore
from packages.common.config import Settings
from packages.common.db import sqlalchemy_url
from packages.storage.models import (
    RATE_BAN_WINDOW_SECONDS,
    RATE_WINDOW_SECONDS,
    RateBucket,
)

_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

#: Адреса TEST-NET-3 (RFC 5737) в диапазоне, который принадлежит только этой группе: чистка
#: выбирает свои строки по префиксу и не задевает чужие живые проверки в той же схеме.
_KEY_PREFIX = "203.0.113.2"
#: Момент для проверок, которым не важно «сейчас» (инкремент, раздельность окон): фиксирован,
#: чтобы сравнение строк не зависело от времени запуска группы.
_WINDOW_START = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)

_INSERT_BUCKET = (
    "INSERT INTO rate_buckets (scope, bucket_key, window_start, window_seconds, attempts) "
    "VALUES (:scope, :key, :start, :seconds, :attempts)"
)

#: Подсчёт соседних таблиц: имена зашиты в запросы, а не подставляются из переменной — проверка
#: не должна строить SQL из склейки.
_COUNT_QUERIES = {
    "users": "SELECT count(*) FROM users",
    "sessions": "SELECT count(*) FROM sessions",
    "audit_log": "SELECT count(*) FROM audit_log",
    "totp_failures": "SELECT count(*) FROM totp_failures",
    "backup_codes": "SELECT count(*) FROM backup_codes",
}


def _key(suffix: str) -> str:
    return f"{_KEY_PREFIX}{suffix}"


def _rows(engine: Engine, scope: str, key: str) -> list[tuple[datetime, int, int]]:
    """Содержимое счётчика по области и ключу: начало окна, длина окна, счётчик."""
    with Session(engine) as session:
        found = session.execute(
            select(RateBucket).where(RateBucket.scope == scope, RateBucket.bucket_key == key)
        ).scalars()
        return [(row.window_start, row.window_seconds, row.attempts) for row in found]


def _insert_buckets(engine: Engine, rows: Iterable[tuple[str, str, datetime, int, int]]) -> None:
    """Вставка окон счётчика чистым SQL: проверка чистки не зависит от механизма инкремента."""
    with engine.begin() as connection:
        for scope, key, start, seconds, attempts in rows:
            connection.execute(
                text(_INSERT_BUCKET),
                {
                    "scope": scope,
                    "key": key,
                    "start": start,
                    "seconds": seconds,
                    "attempts": attempts,
                },
            )


def _keys_present(engine: Engine, keys: Iterable[str]) -> set[str]:
    """Какие из ключей этой группы всё ещё лежат в таблице."""
    with engine.connect() as connection:
        found = connection.execute(
            text("SELECT bucket_key FROM rate_buckets WHERE bucket_key LIKE :prefix"),
            {"prefix": f"{_KEY_PREFIX}%"},
        ).fetchall()
    present = {str(row[0]) for row in found}
    return {key for key in keys if key in present}


def _table_counts(engine: Engine) -> dict[str, int]:
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for table, query in _COUNT_QUERIES.items():
            row = connection.execute(text(query)).fetchone()
            assert row is not None
            counts[table] = int(row[0])
    return counts


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок к той же базе, что поднимают шаги job'а `migrations`.

    Свой `create_engine` — только через `packages.common.db.sqlalchemy_url`: иначе DSN уедет в
    форму драйвера, которую проект не использует (единственный источник формата — `db.py`).
    """
    created = create_engine(sqlalchemy_url(_DB_URL))
    try:
        yield created
    finally:
        created.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine) as value:
        yield value


@pytest.fixture(autouse=True)
def _clean_buckets(engine: Engine) -> Iterator[None]:
    """До и после проверки убираются только строки этой группы.

    Строки счётчика коммитятся по-настоящему (иначе проверялась бы не та фиксация, что в слое
    входа), поэтому откат транзакта не спасает: без выборки по префиксу следующая проверка увидела
    бы чужие окна и решила бы, что лимит уже исчерпан.
    """
    _purge_group_rows(engine)
    yield
    _purge_group_rows(engine)


def _purge_group_rows(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM rate_buckets WHERE bucket_key LIKE :prefix"),
            {"prefix": f"{_KEY_PREFIX}%"},
        )


def _bump(
    store: SqlStore,
    *,
    scope: str = LOGIN_IP_SCOPE,
    key: str,
    window_start: datetime = _WINDOW_START,
    window_seconds: int = RATE_WINDOW_SECONDS,
) -> int:
    return store.bump_rate_bucket(
        scope=scope,
        bucket_key=key,
        window_start=window_start,
        window_seconds=window_seconds,
    )


# ─── инкремент: одна строка на окно, обращения не теряются ─────────────────────────────────────


def test_первый_инкремент_заводит_окно_а_второй_двигает_тот_же_счётчик(
    engine: Engine, session: Session
) -> None:
    """`INSERT … ON CONFLICT` на живом первичном ключе: второй вызов не создаёт вторую строку.

    Отдельно держится то, что возвращается значение **после** увеличения (`RETURNING`): на нём
    слой входа решает, наступил ли отказ, и сдвиг на единицу сдвинул бы границу отказа.
    """
    store = SqlStore(session)
    key = _key("1")

    assert _bump(store, key=key) == 1
    session.commit()
    assert _bump(store, key=key) == 2
    session.commit()
    assert _bump(store, key=key) == 3
    session.commit()

    rows = _rows(engine, LOGIN_IP_SCOPE, key)
    assert rows == [(_WINDOW_START, 60, 3)], (
        f"строки счётчика: {rows}; второй и третий вызовы создали новые окна вместо одного "
        "счётчика, и лимит перестал быть «10 запросов/мин/IP»"
    )


def test_окна_60_и_300_секунд_живут_раздельно(engine: Engine, session: Session) -> None:
    """Первичный ключ включает `window_start`: окно перебора §8.2 и окно лимита §8.3 — разные строки.

    Иначе неудачи перебора и обычные запросы складывались бы в один счётчик, и адрес закрывался бы
    за запросы, которые неудачами не были (§8.1 требует различать состояния отказа).
    """
    store = SqlStore(session)
    key = _key("2")
    for _ in range(4):
        _bump(store, key=key)
    for _ in range(2):
        _bump(store, scope=IP_BAN_SCOPE, key=key, window_seconds=RATE_BAN_WINDOW_SECONDS)
    session.commit()

    minute_rows = _rows(engine, LOGIN_IP_SCOPE, key)
    ban_rows = _rows(engine, IP_BAN_SCOPE, key)
    assert minute_rows == [(_WINDOW_START, 60, 4)], f"окно лимита: {minute_rows}"
    assert ban_rows == [(_WINDOW_START, 300, 2)], f"окно перебора: {ban_rows}"


def test_конкурентные_обращения_не_теряются(engine: Engine) -> None:
    """Главная проверка среза: сколько параллельных инкрементов, столько и попыток в итоге.

    Каждая нить держит свою сессию и фиксирует каждое обращение отдельно — как разные воркеры
    `web`. Стук в одну строку счётчика идёт одновременно; форма `INSERT … ON CONFLICT DO UPDATE`
    обязана сериализоваться на первичном ключе. Вариант «прочитали, прибавили, записали» на этом
    же наборе потерял бы обращения, а вместе с ними и лимит: перебор просто наращивал бы
    параллельность.
    """
    key = _key("3")
    threads, per_thread = 8, 10
    factory = sessionmaker(engine)

    def hammer(worker: int) -> list[int]:
        del worker
        with factory() as thread_session:
            thread_store = SqlStore(thread_session)
            values: list[int] = []
            for _ in range(per_thread):
                values.append(
                    thread_store.bump_rate_bucket(
                        scope=LOGIN_IP_SCOPE,
                        bucket_key=key,
                        window_start=_WINDOW_START,
                        window_seconds=RATE_WINDOW_SECONDS,
                    )
                )
                thread_session.commit()
            return values

    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = [list(values) for values in pool.map(hammer, range(threads))]

    total = threads * per_thread
    values = sorted(value for row in results for value in row)
    assert values == list(range(1, total + 1)), (
        f"набор значений {values[:5]}…{values[-5:]} при {total} обращениях: инкременты "
        "потерялись или посчитаны дважды"
    )
    rows = _rows(engine, LOGIN_IP_SCOPE, key)
    assert rows == [(_WINDOW_START, 60, total)], f"строка счётчика: {rows}"


# ─── чтение окна и срок бана (ADR-009) ─────────────────────────────────────────────────────────


def test_читается_самое_свежее_подходящее_окно(session: Session) -> None:
    """`newest_counted_window` берёт максимум по `window_start`, а не первую встреченную строку.

    Старые окна удаляются не мгновенно (чистка — раз в час и только за сутки), поэтому у адреса их
    несколько. Если слой входа возьмёт старое окно, срок бана уедет в прошлое, и адрес придётся
    закрывать заново на каждом запросе.
    """
    key = _key("4")
    store = SqlStore(session)
    older = _WINDOW_START
    newer = _WINDOW_START + timedelta(minutes=5)
    # В обоих окнах порог достигнут: иначе «самое свежее» пришлось бы выбирать из окон, где
    # неудач разное число, и проверка путала бы отсечку по порогу с отсечку по времени.
    for start in (older, older, older, newer, newer, newer):
        _bump(
            store,
            scope=IP_BAN_SCOPE,
            key=key,
            window_start=start,
            window_seconds=RATE_BAN_WINDOW_SECONDS,
        )
    session.commit()

    search_from = older - timedelta(days=1)
    row = store.newest_counted_window(
        scope=IP_BAN_SCOPE,
        bucket_key=key,
        min_attempts=IP_BAN_THRESHOLD,
        window_start_after=search_from,
    )
    assert row is not None, "окно с тремя неудачами не найдено"
    assert row.window_start == newer, f"взято не самое свежее окно: {row.window_start}"
    assert row.window_seconds == RATE_BAN_WINDOW_SECONDS, f"длина окна: {row.window_seconds}"
    assert row.attempts == IP_BAN_THRESHOLD, f"счётчик окна: {row.attempts}"

    # Порог не достигнут — окна нет: иначе первая же неудача закрывала бы адрес (§8.2 — 3 за 5 минут).
    # Порог: в этом окне ровно `IP_BAN_THRESHOLD` неудач, и на одну больше — уже нет окна.
    # Проверка «меньше порога» делается на отдельном ключе, где неудач ровно на одну меньше.
    assert (
        store.newest_counted_window(
            scope=IP_BAN_SCOPE,
            bucket_key=key,
            min_attempts=IP_BAN_THRESHOLD + 1,
            window_start_after=search_from,
        )
        is None
    ), "окно с числом неудач ниже порога посчитано достаточным"
    below = _key("4-threshold")
    for _ in range(IP_BAN_THRESHOLD - 1):
        _bump(
            store,
            scope=IP_BAN_SCOPE,
            key=below,
            window_start=older,
            window_seconds=RATE_BAN_WINDOW_SECONDS,
        )
    session.commit()
    assert (
        store.newest_counted_window(
            scope=IP_BAN_SCOPE,
            bucket_key=below,
            min_attempts=IP_BAN_THRESHOLD,
            window_start_after=search_from,
        )
        is None
    ), "окно с числом неудач ниже порога посчитано достаточным"

    # Граница поиска отсечает старые окна: иначе вчерашняя неудача до сих пор запрещала бы вход.
    assert (
        store.newest_counted_window(
            scope=IP_BAN_SCOPE,
            bucket_key=key,
            min_attempts=IP_BAN_THRESHOLD,
            window_start_after=newer,
        )
        is None
    ), "окно старше границы поиска попало в выборку"

    assert (
        store.newest_counted_window(
            scope=IP_BAN_SCOPE,
            bucket_key=_key("нет-такого-ключа"),
            min_attempts=1,
            window_start_after=search_from,
        )
        is None
    ), "в выборку попало окно чужого ключа"


def test_срок_бана_выведен_из_полей_живой_строки(engine: Engine, session: Session) -> None:
    """`ADR-009`: срок = `window_start + window_seconds + IP_BAN_DURATION`, а не «сейчас + 15 минут».

    Отправная точка — текущее пятиминутное окно, а момент чтения передаётся явно: иначе проверка
    зависела бы от того, сколько секунд прошло между вставкой и чтением. Ровно в срок бан снимается,
    а окно старше границы поиска не возвращает бан вовсе.
    """
    key = _key("5")
    store = SqlStore(session)
    moment = datetime.now(UTC).replace(microsecond=0)
    window_start = align_window_start(moment, RATE_BAN_WINDOW_SECONDS)
    for _ in range(IP_BAN_THRESHOLD):
        _bump(
            store,
            scope=IP_BAN_SCOPE,
            key=key,
            window_start=window_start,
            window_seconds=RATE_BAN_WINDOW_SECONDS,
        )
    session.commit()

    expected = window_start + timedelta(seconds=RATE_BAN_WINDOW_SECONDS) + IP_BAN_DURATION
    banned = ban_until(store, key, moment=moment)
    assert banned == expected, (
        f"срок бана {banned} не выведен из полей строки ({window_start.isoformat()} + "
        f"{RATE_BAN_WINDOW_SECONDS} с + {IP_BAN_DURATION}); ожидался {expected}"
    )
    # Ровно в срок — снимается: иначе «временный» бан становился бы постоянным.
    assert ban_until(store, key, moment=expected) is None, "бан не считается истёкшим после срока"
    # Адрес, о котором база ничего не знает, не закрыт.
    assert ban_until(store, _key("чистый-адрес"), moment=moment) is None

    # Просроченное окно (§8.2 считает перебор за 5 минут) за границей поиска не участвует:
    # вчерашние три неудачи не должны запрещать вход сегодня.
    stale_key = _key("6")
    stale_start = align_window_start(moment - timedelta(hours=20), RATE_BAN_WINDOW_SECONDS)
    _insert_buckets(engine, [(IP_BAN_SCOPE, stale_key, stale_start, RATE_BAN_WINDOW_SECONDS, 3)])
    assert (
        ban_until(store, stale_key, moment=moment) is None
    ), f"окно {stale_start.isoformat()} до сих пор закрывает адрес"


# ─── чистка окон (ADR-007: окно живёт сутки, потом удаляется) ──────────────────────────────────


def test_чистка_удаляет_только_просроченные_окна(engine: Engine) -> None:
    """Условие чистки — `window_start` (по нему в схеме индекс), граница — сутки.

    Граница проверяется парой «чуть раньше суток / чуть позже»: иначе потолок можно сдвинуть в
    любую сторону и остаться зелёным. Свежие окна обязаны выжить: удалить окно раньше, чем оно
    перестало влиять на лимит или бан, — значит сбросить лимит переборщику посреди атаки.
    """
    moment = datetime.now(UTC).replace(microsecond=0)
    stale_hour = align_window_start(moment - timedelta(hours=25), RATE_WINDOW_SECONDS)
    stale_ban = align_window_start(moment - timedelta(hours=25), RATE_BAN_WINDOW_SECONDS)
    just_stale = align_window_start(
        moment - RATE_BUCKET_RETENTION - timedelta(seconds=90), RATE_WINDOW_SECONDS
    )
    fresh_hour = align_window_start(moment - timedelta(hours=23), RATE_WINDOW_SECONDS)
    fresh_ban = align_window_start(moment - timedelta(hours=23), RATE_BAN_WINDOW_SECONDS)

    stale = (
        (LOGIN_IP_SCOPE, _key("7a"), stale_hour, RATE_WINDOW_SECONDS, 3),
        (IP_BAN_SCOPE, _key("7b"), stale_ban, RATE_BAN_WINDOW_SECONDS, 3),
        (LOGIN_IP_SCOPE, _key("7c"), just_stale, RATE_WINDOW_SECONDS, 1),
    )
    fresh = (
        (LOGIN_IP_SCOPE, _key("8a"), fresh_hour, RATE_WINDOW_SECONDS, 1),
        (IP_BAN_SCOPE, _key("8b"), fresh_ban, RATE_BAN_WINDOW_SECONDS, 3),
    )
    _insert_buckets(engine, [*stale, *fresh])

    removed = purge_expired_rate_buckets(engine, moment=moment)

    # `>=`, а не точное равенство: к моменту группы в этой же схеме живые файлы-соседи могли
    # оставить собственные просроченные окна. Значение имеют две проверки ниже — какие из наших
    # окон выжили и какие исчезли: они и есть условие чистки.
    assert removed >= len(
        stale
    ), f"чистка сообщает об удалении {removed} окон, ожидалось не меньше {len(stale)}"
    assert _keys_present(engine, (row[1] for row in fresh)) == {
        row[1] for row in fresh
    }, "чистка сняла свежие окна: лимит сбрасывается посреди атаки"
    assert (
        _keys_present(engine, (row[1] for row in stale)) == set()
    ), "просроченные окна остались: таблица счётчика будет расти бесконечно"


def test_чистка_не_трогает_соседние_таблицы(engine: Engine) -> None:
    """DELETE обязан остаться в таблице счётчика.

    Ошибочное условие (например сравнение по `attempts` вместо `window_start`) удалило бы сессии
    или учётные записи — потеря данных в фоновой задаче не бросилась бы в глаза.
    """
    before = _table_counts(engine)
    removed = purge_expired_rate_buckets(engine, moment=datetime.now(UTC))
    after = _table_counts(engine)
    assert set(before) == set(after)
    for table, count in before.items():
        assert after[table] == count, f"чистка ({removed} окон) изменила таблицу {table}"


def test_чистка_идемпотентна_и_регламент_закреплён(engine: Engine) -> None:
    """Повторный запуск ничего не удаляет: регламент — раз в час, ретеншен — сутки (`ADR-007`).

    Константы закреплены в job-реестре и здесь: иначе «окно живёт сутки» могло бы уехать молча, а
    вместе с ним и обещание ограниченного объёма таблицы.
    """
    assert timedelta(hours=24) == RATE_BUCKET_RETENTION
    assert RATE_BUCKET_PURGE_INTERVAL_S == 3600.0
    moment = datetime.now(UTC).replace(microsecond=0)
    purge_expired_rate_buckets(engine, moment=moment)
    second = purge_expired_rate_buckets(engine, moment=moment)
    assert second == 0, f"повторная чистка удалила ещё {second} окон"


def test_движок_задач_не_строится_без_адреса_базы() -> None:
    """Без `TBOT_DB_URL` `build_job_engine` возвращает `None`, а не половину движка.

    Тот же смысл, что в `apps/jobs/main.py`: при незаполненном адресе фоновой задачи нет, и `/readyz`
    обязан сказать об этом явно, а не делать вид, что регламент соблюдается.
    """
    assert build_job_engine(Settings(db_url=None)) is None
    built = build_job_engine(Settings(db_url=SecretStr(sqlalchemy_url(_DB_URL))))
    assert built is not None
    try:
        with built.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1
    finally:
        built.dispose()
