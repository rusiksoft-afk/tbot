"""Инструмент `make audit-verify` поверх живой базы (TZ §8.7, `AC-identity-04`, `ADR-025` п. 7, `T-109` `R3.1`).

Оффлайновая половинка — `tests/integration/test_audit_verify.py`: там коды возврата, границы
выборки и тексты вердикта на подставных строках. Здесь проверяется ровно то, что возможно только
над настоящей схемой:

* **ручная правка и вырез строки ролью-владельцем схемы находятся инструментом** — вторая
  половина `AC-identity-04` («изменённую вручную копию дампа обязано находить `audit-verify`»).
  Роль приложения прав на журнал не имеет (`deploy/postgres/roles.sql`), поэтому править его может
  только владелец схемы, и обнаружение подделки — единственный контрконтроль этого решения
  (`ADR-006`);
* **чтение не берёт атрибуты из identity map.** Отдельная половинка замера первого красного
  прогона (`CI 45163930282`, разбор — `docs/HANDOFF.md §1.61` п. 6): сессия, которая сама правила
  строку (или уже держит её ORM-объект), отдаёт прежние атрибуты, и разбор по ней показал бы
  целую цепочку на испорченной строке. Проверка намеренно держит в читающей сессии ORM-объект до
  правки: реализация, которая читала бы `select(AuditLogEntry)`, провалилась бы здесь, а не на
  площадке;
* **корректная ветка даёт код `0`**, причём ветка среза встраивается в существующую цепочку
  (`hash_prev` первой строки берётся из хвоста журнала, как это делает `SqlStore.append_audit`).
  Вторая запись с пустым `hash_prev` в середине журнала — законная находка `broken_link`, и
  оставлять её после проверок нельзя;
* **прогон ничего не дописывает.** Разбор только читает: событием находки является
  `integrity.audit_chain` (§8.7, `ADR-025` п. 9), и пишет его ежедневная `integrity-check`, а не
  ручной запуск, — иначе чекер дописывал бы строку до собственного пересчёта и обрывал бы цепочку,
  которую проверяет.

Почему почти все прогоны ограничены интервалом `id`. Хронологию журнала задаёт колонка `id`
(§4.1), и интервал по ней отделяет ветку среза от строк, вставленных другими шагами job'а:
полный разбор поверх журнала прогона читал бы чужие строки, а смысл этого файла — поведение
инструмента на известной ветке. Тот же механизм нужен и в бою: `--from-id`/`--to-id` и
`--since`/`--until` разбирают копию дампа и путь восстановления, где прочитана часть журнала,
и ложной находки «начала нет» такая выборка выдавать не должна (`ADR-025` п. 7 и п. 8).

Развилку цепочки (`duplicate_parent`) на живой базе изобразить нельзя: её держит частичный
уникальный индекс `ix_audit_log_hash_prev_linked` (ревизия `0007`), и это проверяет
`tests/integration/test_audit_chain_db.py`. Остаток формы — разбор копии дампа, где индекс мог не
восстановиться, — держит оффлайновая половинка.

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `миграции`).
Без переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной
базе — падает, а не пропускается. Уборка — по маркеру в `entity_id`, и возможна она только потому,
что тест идёт ролью владельца схемы (`ADR-018`): у приложения `DELETE` на журнале отозван.
"""

from __future__ import annotations

import io
import os
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy import Engine, create_engine, delete, func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from packages.common.db import sqlalchemy_url
from packages.identity.audit import build_audit_entry, make_record
from packages.storage.models import AuditLogEntry
from tests.paths import load_script

audit_verify = load_script("audit_verify")

# Читается до аутофикстуры `clean_tbot_env` (она убирает TBOT_* внутри теста): на уровне модуля
# решается, идти ли в группу целиком или пропустить её.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

#: Маркер строк этого файла: `entity_id` — текст (§4.1), и по нему строки убираются после теста.
_MARKER_PREFIX: Final = "t109r31"

#: Метка ветки среза. Фиксированная и заведомо в стороне от любого момента прогона: разбор
#: зависит от порядка `id`, а не от часов прогона, а проверки интервала по `at` не имеют права
#: зависеть от того, во сколько запущен job (окно в две секунды вокруг полуночи UTC время от
#: времени попадало бы на чужие вставки с `now()`). CHECK на `at` в схеме нет (§4.1: колонка с
#: `server_default now()`), поэтому метка выбирается, а не подстраивается под «сейчас».
_AT: Final = datetime(2077, 5, 5, 4, 4, 4, tzinfo=UTC)

#: Окно выборки по метке: шире, чем микросекунды строк ветки, и уже, чем любой соседний шаг job'а
#: (все чужие строки вставляются с `now()`, то есть с текущим временем прогона).
_WINDOW: Final = timedelta(seconds=2)

#: Значение колонки `hash`, не соответствующее содержимому строки: формат законный
#: (`CHECK hash_sha256` проходит), а пересчёт — нет. Именно так выглядит строка,
#: вставленная или исправленная в обход протокола приложения (`AC-identity-04`).
_FABRICATED_HASH: Final = "f" * 64

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `миграции`)",
)


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок владельца схемы: адрес обязан быть прогнан через `sqlalchemy_url` (`ADR-018`)."""
    created = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield created
    created.dispose()


@pytest.fixture
def writer(engine: Engine) -> Iterator[Session]:
    """Сессия, которая вносит строки ветки и «ручные» правки, и убирает их после теста.

    Уборка явная и по маркеру: права приложения на журнал — `SELECT`+`INSERT`, поэтому «само
    рассосётся» для этих строк не наступает, а повторный прогон job'а по той же базе увидел бы
    чужие строки в цепочке — и следующий шаг разбора получил бы находку не свою.
    """
    opened = sessionmaker(bind=engine, expire_on_commit=False)()
    yield opened
    # Откат перед чисткой: упавшая ассертом проверка оставляет транзакцию в состоянии «откатить»,
    # и финализор выдал бы PendingRollbackError вместо настоящего сообщения (замер `CI 45165930936`).
    opened.rollback()
    opened.execute(delete(AuditLogEntry).where(AuditLogEntry.entity_id.like(f"{_MARKER_PREFIX}%")))
    opened.commit()
    opened.close()


def _marker() -> str:
    return f"{_MARKER_PREFIX}-{uuid.uuid4().hex[:10]}"


def _tail_hash(session: Session) -> str | None:
    """Хэш последней записи журнала: та же точка привязки, что у `SqlStore.append_audit`.

    Без неё ветка среза стала бы второй «первой записью» в середине журнала, и полный разбор
    честно нашёл бы `broken_link` — на данных, которые испортили сами проверки.
    """
    return session.execute(
        select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1)
    ).scalar_one_or_none()


def _branch(session: Session, *, marker: str, count: int) -> list[int]:
    """Вставить ветку из `count` корректных записей; вернуть их `id` в порядке вставки.

    Хэш считается по протоколу (`make_record` → `build_audit_entry`), `id` выдаёт база (§4.1),
    поэтому идентификаторы читаются после `flush`.
    """
    hash_prev = _tail_hash(session)
    ids: list[int] = []
    for index in range(count):
        record = make_record(
            action="session.login",
            at=_AT + timedelta(microseconds=index + 1),
            entity="session",
            entity_id=f"{marker}-{index}",
            details={"index": index},
            ip="2001:db8::07",
            hash_prev=hash_prev,
        )
        entry = build_audit_entry(record)
        session.add(entry)
        session.flush()
        assert entry.id is not None
        ids.append(int(entry.id))
        hash_prev = record.content_hash()
    session.commit()
    return ids


def _range(ids: list[int]) -> list[str]:
    """Аргументы инструмента, ограничивающие разбор строками ветки."""
    return ["--from-id", str(ids[0]), "--to-id", str(ids[-1])]


def _verify(session: Session, argv: list[str]) -> tuple[int, str, str]:
    """Прогнать точку входа инструмента поверх живой базы; вернуть код, stdout и stderr.

    Сессия передаётся как фабрика: так проверка решает, каким соединением читают (тот же шов,
    что у `scripts/first_account.py`).
    """
    out = io.StringIO()
    err = io.StringIO()
    code = audit_verify.main(list(argv), session_factory=lambda: session, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _fabricated(session: Session, *, marker: str) -> int:
    """Строка журнала, вставленная сырым SQL с выдуманным `hash`; вернуть её `id`.

    Это не «ещё один способ вставить строку», а ровно та форма, которую цепочка обязана
    обнаружить: вставка в обход протокола приложения (§8.7, `ADR-025` п. 6) или правка
    владельца схемы. Формат хэша законный, поэтому `CHECK` такую строку пропускает — ловит
    только пересчёт.
    """
    row = session.execute(
        text(
            "INSERT INTO audit_log (at, action, entity, entity_id, details, hash_prev, hash) "
            "VALUES (:at, 'session.login', 'session', :entity_id, :details::jsonb, NULL, :hash) "
            "RETURNING id"
        ),
        {
            "at": _AT + timedelta(microseconds=900_000),
            "entity_id": f"{marker}-forged",
            "details": '{"reason": "forged"}',
            "hash": _FABRICATED_HASH,
        },
    ).fetchone()
    assert row is not None
    session.commit()
    return int(row[0])


def _reader(writer: Session) -> Session:
    """Свежая читающая сессия того же движка: чтение разбора не смешивается с писателем."""
    return sessionmaker(bind=writer.get_bind(), expire_on_commit=False)()


def _row_count(session: Session) -> int:
    return int(session.execute(select(func.count(AuditLogEntry.id))).scalar_one())


def _printed_range(printed: str) -> tuple[int, int]:
    """Прочитать напечатанную инструментом границу `[первая строка, последняя]`."""
    found = re.search(r"с (\d+) по (\d+)", printed)
    assert found is not None, printed
    return int(found.group(1)), int(found.group(2))


# ─── корректная цепочка: код ноль ────────────────────────────────────────────────────────────


def test_корректная_ветка_даёт_код_ноль(writer: Session) -> None:
    marker = _marker()
    ids = _branch(writer, marker=marker, count=3)
    code, printed, errors = _verify(writer, _range(ids))
    assert code == audit_verify.EXIT_OK, printed + errors
    assert "цепочка цела" in printed
    assert f"строк: 3, с {ids[0]} по {ids[-1]}" in printed


def test_чужие_строки_за_пределами_интервала_не_мешают_разбору(writer: Session) -> None:
    """Интервал по `id` разбирает только то, что внутри интервала.

    Тот же механизм нужен и в бою: копию дампа и путь восстановления (§4.1, `ADR-025` п. 7 и
    п. 8) разбирают по интервалу, и ложной находки «начала нет» такая выборка выдавать не
    должна. Здесь интервал отделяет ветку среза от строк журнала, которые к этому моменту
    принадлежат другим шагам job'а `миграции`.
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=2)
    code, printed, errors = _verify(writer, _range(ids))
    assert code == audit_verify.EXIT_OK, printed + errors
    assert "нарушена" not in printed
    assert _printed_range(printed) == (ids[0], ids[-1])


def test_выборка_по_метке_включает_ровно_строки_ветки(writer: Session) -> None:
    """Фильтр `at` (`ix_audit_log_at`) работает с `TIMESTAMPTZ` и не требует начала цепи.

    Значения интервала передаются без смещения — трактуются как UTC (`parse_moment`): иначе
    «выборка за смену» на dev-машине и на площадке читала бы разные строки, а ежедневная
    `integrity-check` сообщала бы о том, чего на самом деле не проверяла.
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=3)
    code, printed, errors = _verify(
        writer,
        [
            "--since",
            _AT.isoformat(),
            "--until",
            (_AT + _WINDOW).isoformat(),
        ],
    )
    assert code == audit_verify.EXIT_OK, printed + errors
    assert f"строк: 3, с {ids[0]} по {ids[-1]}" in printed
    assert "нарушена" not in printed


# ─── правка и вырез: вторая половина `AC-identity-04` ────────────────────────────────────────


def test_правка_строки_ролью_владельца_находится_как_content_mismatch(writer: Session) -> None:
    """Ручная правка содержимого без пересчёта `hash` — ровно то, что обязан найти инструмент.

    Правим ролью владельца схемы: у приложения `UPDATE` на журнале отозван, и именно поэтому
    цепочка хэшей существует (`AC-identity-04`, `ADR-006`).
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=3)
    writer.execute(
        update(AuditLogEntry)
        .where(AuditLogEntry.id == ids[1])
        .values(entity="user", details={"index": 99})
    )
    writer.commit()

    reader = _reader(writer)
    try:
        code, printed, errors = _verify(reader, _range(ids))
    finally:
        reader.close()
    assert code == audit_verify.EXIT_FINDINGS, printed + errors
    assert "content_mismatch" in printed
    assert f"строка {ids[1]}" in printed


def test_вырез_строки_находится_как_broken_link(writer: Session) -> None:
    """Вырезанная строка середины: следующая ссылается на предка, которого нет.

    Отдельного кода «цепочка стала короче» нет (`ADR-025` п. 7) — это ровно `broken_link`, и
    проверка держит именно этот код, а не «что-то не так».
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=4)
    writer.execute(delete(AuditLogEntry).where(AuditLogEntry.id == ids[1]))
    writer.commit()

    reader = _reader(writer)
    try:
        code, printed, errors = _verify(reader, _range(ids))
    finally:
        reader.close()
    assert code == audit_verify.EXIT_FINDINGS, printed + errors
    assert "broken_link" in printed
    assert f"строка {ids[2]}" in printed


def test_чтение_не_берёт_атрибуты_из_identity_map(writer: Session) -> None:
    """Читающая сессия держит ORM-объект строки до правки — разбор обязан увидеть новое значение.

    Это тот самый замер (`CI 45163930282`): `select(AuditLogEntry)` вернул бы объект из
    identity map с прежними атрибутами, и «цепочка цела» прозвучало бы на уже испорченной
    строке. Реализация читает колонками §4.1, поэтому проверка зелёная; стоит заменить чтение
    на сущностное — она краснеет здесь, а не на площадке.
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=3)

    reader = _reader(writer)
    loaded = reader.execute(select(AuditLogEntry).where(AuditLogEntry.id == ids[1])).scalar_one()
    assert loaded.entity == "session"

    writer.execute(update(AuditLogEntry).where(AuditLogEntry.id == ids[1]).values(entity="user"))
    writer.commit()

    try:
        code, printed, errors = _verify(reader, _range(ids))
    finally:
        reader.close()
    assert code == audit_verify.EXIT_FINDINGS, printed + errors
    assert "content_mismatch" in printed


def test_строка_вставленная_сырым_sql_тоже_находится(writer: Session) -> None:
    """Положительный контроль: разбор находит строку, вставленную в обход протокола приложения.

    Смысл цепочки — в том, чтобы подделку, сделанную не приложением, было видно (`AC-identity-04`).
    Строка вставляется сырым SQL ролью владельца схемы с законным по формату, но выдуманным
    `hash`: `CHECK hash_sha256` её пропускает, поэтому ловить обязан именно пересчёт, а не
    ограничение схемы.
    """
    marker = _marker()
    forged = _fabricated(writer, marker=marker)
    code, printed, errors = _verify(writer, ["--from-id", str(forged), "--to-id", str(forged)])
    assert code == audit_verify.EXIT_FINDINGS, printed + errors
    assert "content_mismatch" in printed
    assert f"строка {forged}" in printed


# ─── выборка и отсутствие записей ───────────────────────────────────────────────────────────


def test_выборка_не_с_начала_цепи_не_даёт_ложной_находки(writer: Session) -> None:
    """Отсечение слева: у первой строки выборки `hash_prev` есть по построению (`ADR-025` п. 7).

    `expect_genesis=False` нужен именно для этого: иначе каждый разбор «за период» или «по
    интервалу id» выдавал бы `missing_prefix`, и настоящая подделка утонула бы в постоянном шуме.
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=3)
    code, printed, errors = _verify(writer, ["--from-id", str(ids[1]), "--to-id", str(ids[-1])])
    assert code == audit_verify.EXIT_OK, printed + errors
    assert "missing_prefix" not in printed
    assert "нарушена" not in printed


def test_пустая_выборка_это_код_ноль_а_не_отказ(writer: Session) -> None:
    """Интервал без строк — «в этом интервале ничего нет», а не «проверка сломалась».

    Отказом считаются пустые интервалы вида `--from-id 9 --to-id 3` и неверный формат метки
    (оффлайновая половинка). Корректный интервал без попаданий обязан оставить вердикт
    «находок нет»: у ежедневной `integrity-check` за вчерашний день таких окон будет много.
    """
    marker = _marker()
    ids = _branch(writer, marker=marker, count=1)
    code, printed, errors = _verify(writer, ["--from-id", str(ids[0] + 1_000_000)])
    assert code == audit_verify.EXIT_OK, printed + errors
    assert "цепочка пуста" in printed


def test_прогон_не_дописывает_в_журнал_ни_чего(writer: Session) -> None:
    """Разбор только читает: событие находки пишет ежедневная `integrity-check`, а не этот запуск.

    Порядок жёсткий (`ADR-025` п. 9): чекер сначала читает журнал и выносит вердикт, и только
    потом дописывает строку о находке. Строка, вставленная до пересчёта, оборвала бы цепочку,
    которую проверяет сам чекер, и каждый следующий прогон находил бы её заново.
    """
    marker = _marker()
    _branch(writer, marker=marker, count=2)
    before = _row_count(writer)
    code, printed, errors = _verify(
        writer, ["--since", _AT.isoformat(), "--until", (_AT + _WINDOW).isoformat()]
    )
    assert code == audit_verify.EXIT_OK, printed + errors
    writer.expire_all()
    assert _row_count(writer) == before
