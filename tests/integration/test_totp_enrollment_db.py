"""Живой PostgreSQL и `totp_enrollments`: одна действующая привязка, занятый шаг и окно ленты попыток (TZ §8.2, §4.1, ADR-013 п. 4, `T-103` срез `R4c`).

Оффлайновая половинка — `tests/integration/test_web_totp_page.py`: те же правила на `MemoryStore`,
запускаемые на dev-машине, где PostgreSQL нет. Здесь проверяется ровно то, чего память показать не
может:

* **одну действующую привязку на учётку держит база** — частичный уникальный индекс
  `ix_totp_enrollments_user_active` (`WHERE revoked_at IS NULL`). Память повторяет предикат руками,
  и там «правило есть» неотличимо от «правила нет»: вторую строку обязан не пустить сервер, иначе у
  учётки появляется два одновременно действующих вторых фактора, а `active_enrollment` обязан был бы
  угадывать, какой из них настоящий;
* **слот занимает и подтверждённая строка**: предикат индекса — «не отозвана», а не «не
  подтверждена». Именно поэтому повторная первичная выдача отвечает `409`, а не «тихо заменила
  секрет»;
* **отзыв освобождает слот, но не стирает историю** (§8.4): строка остаётся в таблице, и новая
  выдача возможна только после неё. Порядок «отозвали прежнюю → вставили новую» диктует индекс,
  поэтому маршрут обязан отзывать любую незавершённую привязку, а не только протухшую;
* **одноразовость кода — один `UPDATE` с условием**, а не «прочитать, сравнить, записать»:
  `rowcount = 1` на первом занятии шага, отказ на повторе того же шага и на шаге ниже, значение
  видно второму соединению (то есть зафиксировано, а не живёт в транзакте текущего запроса);
* **состояние строки стоит в том же условии**: занять шаг на отозванной или неподтверждённой
  привязке нельзя, иначе доступ будет выдан по второму фактору, который уже отозван (между чтением
  привязки маршрутом и записью шага есть окно, и закрывается оно условием `UPDATE`);
* **шаг — `BIGINT`**: номер шага (секунды с эпохи, делённые на 30) доходит до значений выше
  `2^31 − 1`; в `integer` переполнение произошло бы молча в 2038 году — класс ошибки, который не
  виден ни на одном живом значении сегодня;
* **граница окна неудачных кодов уходит в SQL**, а не отфильтровывается в Python: лента растёт
  навсегда (записи не удаляются успехом), и «посчитать окно по всем строкам учётки» означает чтение
  всей ленты на каждый неудачный код (§8.2, `ADR-007`).

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `migrations`).
Без переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной
базе — падает, а не пропускается.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy import Engine, create_engine, delete, event, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from apps.web.store import SqlStore
from packages.common.crypto import KeyRing, parse_key_ring_document
from packages.common.db import sqlalchemy_url
from packages.identity.totp_enrollment import new_enrollment, revoke_enrollment
from packages.identity.users import new_user
from packages.storage.models import TotpEnrollment, TotpFailure, User, UserSession
from tests.integration.web_support import TEST_PASSWORD

# Читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

#: Учётки создаются на каждый тест со своим суффиксом: `users.login` уникален, а повторный прогон
#: job'а идёт по той же базе.
_LOGIN_PREFIX: Final = "t103r4c"

#: Тестовый KEK: значения площадки в проверках не участвуют (§8.4, ADR-004 — значения вносит только
#: `deploy/vps/secrets-setup.sh`).
_KEK_B64: Final = base64.b64encode(bytes([0x11]) * 32).decode("ascii")
_RING: Final[KeyRing] = parse_key_ring_document(
    f'{{"format_version": 1, "active_version": 1, '
    f'"keys": [{{"version": 1, "key": "{_KEK_B64}"}}]}}',
    source="тест",
)

#: Имя частичного уникального индекса: оно отличает «правило одной привязки» от обычного дубликата
#: первичного ключа.
_ACTIVE_INDEX: Final = "ix_totp_enrollments_user_active"

#: Верх `integer` в PostgreSQL. Номер шага обязан пережить его: это секунды с эпохи / 30, и граница
#: приходится на 2038 год (см. docstring модуля).
_INT4_MAX: Final = 2_147_483_647

#: Условная дата создаваемых привязок и ленты попыток. Микросекунды обнулены: сравнения
#: ниже опираются на точное совпадение границ, а `TIMESTAMPTZ` хранит микросекунды.
_NOW: Final = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

#: Адреса из документального диапазона RFC 5737: адреса площадки в проверках не участвуют,
#: но в связанных значениях запроса о ленте их текста быть не должно (§8.8).
_АДРЕС_СВОЙ: Final = "203.0.113.11"
_АДРЕС_ЧУЖОЙ: Final = "203.0.113.12"


# ─── фикстуры ──────────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок проверок — отдельный от соединения приложения, чтобы видеть зафиксированное.

    DSN обязательно прогоняется через `sqlalchemy_url`: в job'е `migrations` переменная стоит в
    прямой форме `postgresql://…`, а SQLAlchemy искала бы `psycopg2` (драйвер в проекте один).
    """
    created = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield created
    created.dispose()


@pytest.fixture
def captured(engine: Engine) -> Iterator[tuple[list[str], list[str]]]:
    """Тексты запросов и их связанные значения: фильтр, окно и условие обязаны быть в SQL."""
    statements: list[str] = []
    bound: list[str] = []

    def _collect(
        _conn: object, _cursor: object, statement: str, parameters: object, *_rest: object
    ) -> None:
        statements.append(statement)
        bound.append(repr(parameters))

    event.listen(engine, "before_cursor_execute", _collect)
    try:
        yield statements, bound
    finally:
        event.remove(engine, "before_cursor_execute", _collect)


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    """Соединение проверок. Очистка — по суффиксу учётки: `user_id` стоит `ON DELETE RESTRICT`."""
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    ids = list(session.scalars(select(User.id).where(User.login.like(f"{_LOGIN_PREFIX}%"))).all())
    if ids:
        session.execute(delete(TotpFailure).where(TotpFailure.user_id.in_(ids)))
        session.execute(delete(TotpEnrollment).where(TotpEnrollment.user_id.in_(ids)))
        session.execute(delete(UserSession).where(UserSession.user_id.in_(ids)))
        session.execute(delete(User).where(User.id.in_(ids)))
        session.commit()
    session.close()


# ─── помощники ─────────────────────────────────────────────────────────────────────────────────


def _учётка(db: Session, *, suffix: str) -> User:
    user = new_user(
        login=f"{_LOGIN_PREFIX}{suffix}{uuid.uuid4().hex[:6]}",
        password=TEST_PASSWORD,
        role="operator",
        state="active",
    )
    db.add(user)
    db.commit()
    return user


def _выдать(db: Session, user: User, *, now: datetime = _NOW) -> TotpEnrollment:
    """Незавершённая привязка, созданная доменом — тот же путь, что у `POST /mfa-enroll/start`."""
    созданная = new_enrollment(user_id=user.id, now=now, ring=_RING)
    db.add(созданная.enrollment)
    db.commit()
    return созданная.enrollment


def _подтвердить(db: Session, привязка: TotpEnrollment, *, now: datetime = _NOW) -> None:
    """Подтверждение строки без подбора пар кодов: здесь проверяется состояние, а не подбор.

    Право подтверждать привязку у доменного слоя есть только у `confirm_enrollment`, а
    вызывать её здесь означало бы проверять подбор пар кодов вместо состояния строки. Поэтому
    поле ставится атрибутом объекта и фиксируется `commit()`-ом: один `UPDATE` происходит до
    очистки перехваченных запросов, и после него объект не остаётся «грязным» — иначе проверка
    числа обновлений в тесте одноразовости посчитала бы и этот `UPDATE` тоже.
    """
    привязка.confirmed_at = now + timedelta(seconds=1)
    db.commit()


def _отозвать(db: Session, привязка: TotpEnrollment, *, now: datetime = _NOW) -> None:
    revoke_enrollment(привязка, now=now)
    db.commit()


def _строк_привязок(db: Session, user_id: uuid.UUID) -> int:
    """Сколько строк привязок у учётки в таблице, а не в identity map текущего запроса."""
    return int(
        db.scalar(
            select(func.count())
            .select_from(TotpEnrollment)
            .where(TotpEnrollment.user_id == user_id)
        )
        or 0
    )


def _шаг_из_базы(engine: Engine, привязка_id: uuid.UUID) -> int | None:
    """`last_used_step` вторым соединением: зафиксированное значение, а не identity map запроса."""
    with engine.connect() as соединение:
        значение = соединение.execute(
            text("SELECT last_used_step FROM totp_enrollments WHERE id = :id"),
            {"id": привязка_id},
        ).scalar_one()
    return None if значение is None else int(значение)


def _обновления_привязок(запросы: list[str]) -> list[str]:
    # Сравнение идёт по верхней границе регистра, потому что текст запроса нормализуется
    # (`lstrip().upper()`): писать `startswith("UPDATE totp_enrollments")` после `upper()` —
    # собственный дефект проверки: фильтр не находит ничего, цикл по пустому списку проходит,
    # и проверка превращается в пустую (замер: первый прогон CI, 2026-11-22).
    return [sql for sql in запросы if sql.lstrip().upper().startswith("UPDATE TOTP_ENROLLMENTS")]


# ─── одна действующая привязка на учётку (частичный уникальный индекс) ─────────────────────────


def test_индекс_одной_привязки_существует_с_предикатом_отзыва(db: Session) -> None:
    """Предикат индекса — «не отозвана»: без него правило §8.2 и история привязок несовместимы.

    Проверка начинается с индекса, а не с вставки: если индекс перестал быть частичным, остальные
    проверки группы продолжат проходить по другой причине (уникальность по всем строкам учётки), а
    «история привязок остаётся в таблице» сломается молча.
    """
    определение = db.execute(
        text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE tablename = 'totp_enrollments' AND indexname = :name"
        ),
        {"name": _ACTIVE_INDEX},
    ).scalar_one_or_none()
    assert определение is not None, f"индекс {_ACTIVE_INDEX} не найден у таблицы привязок"
    assert "UNIQUE" in определение.upper(), f"индекс не уникальный: {определение}"
    assert "revoked_at IS NULL" in определение, (
        f"у индекса нет предиката `revoked_at IS NULL`: отозванная привязка продолжала бы занимать "
        f"слот, и история привязок не могла бы накапливаться: {определение}"
    )


def test_вторую_неотозванную_привязку_база_не_пускает(db: Session) -> None:
    """Две незавершённые привязки на одну учётку — нарушение целостности, а не «две строки».

    Если бы это проходило, `active_enrollment` (`scalar_one_or_none`) падал бы на каждом входе, а
    страница кода не могла бы ответить, какой второй фактор действует.
    """
    user = _учётка(db, suffix="dup")
    _выдать(db, user)

    with pytest.raises(IntegrityError) as ошибка:
        _выдать(db, user)

    assert _ACTIVE_INDEX in str(ошибка.value), (
        "отказ пришёл не из индекса одной действующей привязки — значит слот никто не держит: "
        f"{ошибка.value}"
    )
    db.rollback()
    assert _строк_привязок(db, user.id) == 1, "после отказа осталась вторая строка"


def test_подтверждённая_привязка_тоже_занимает_слот(db: Session) -> None:
    """Предикат — «не отозвана», поэтому действующий второй фактор блокирует новую выдачу.

    Это оправдание ответа `409` на повторную первичную привязку (§8.2 случай 2): «тихая замена
    секрета» выглядит удобнее, но обнулила бы уже выпущенный второй фактор без отзыва.
    """
    user = _учётка(db, suffix="bound")
    привязка = _выдать(db, user)
    _подтвердить(db, привязка)

    with pytest.raises(IntegrityError) as ошибка:
        _выдать(db, user)
    assert _ACTIVE_INDEX in str(ошибка.value)
    db.rollback()
    assert _строк_привязок(db, user.id) == 1


def test_отзыв_освобождает_слот_и_сохраняет_историю(db: Session) -> None:
    """Новая выдача возможна только после отзыва прежней, а прежняя строка остаётся в таблице.

    Таблица читается заново, поэтому «объект в памяти поменялся» засчитан быть не может.
    """
    user = _учётка(db, suffix="restart")
    прежняя = _выдать(db, user)
    _отозвать(db, прежняя)

    новая = _выдать(db, user, now=_NOW + timedelta(minutes=5))

    прочитанная = SqlStore(db).active_enrollment(user.id)
    assert прочитанная is not None
    assert прочитанная.id == новая.id, "поиск вернул отозванную привязку"
    assert прочитанная.confirmed_at is None, "новая привязка обязана быть незавершённой"
    assert (
        _строк_привязок(db, user.id) == 2
    ), "отозванная привязка исчезла из таблицы (§8.4: история привязок остаётся)"


def test_чужая_привязка_не_находится_а_поиск_идёт_по_предикату(
    db: Session, captured: tuple[list[str], list[str]]
) -> None:
    """Условия `user_id` и `revoked_at IS NULL` уходят в SQL: чужая строка не читается вообще.

    Форма запроса проверяется отдельно: `revoked_at IS NULL` в `WHERE` — это попадание в частичный
    индекс. Без него поиск выродился бы в скан всех привязок учётки, и «индекс есть» перестал бы
    что-либо значить.
    """
    своя = _учётка(db, suffix="own")
    чужая = _учётка(db, suffix="other")
    _выдать(db, чужая)
    запросы, значения = captured
    запросы.clear()
    значения.clear()

    assert SqlStore(db).active_enrollment(своя.id) is None

    выборки = [sql for sql in запросы if "FROM totp_enrollments" in sql]
    assert выборки, "привязка не читалась из таблицы `totp_enrollments`"
    поиск = выборки[-1]
    assert "user_id" in поиск, f"в запросе нет условия по учётке: {поиск}"
    assert "revoked_at IS NULL" in поиск, f"в запросе нет предиката живой привязки: {поиск}"


# ─── занятый шаг кода: одноразовость и состояние строки ────────────────────────────────────────


def test_шаг_занимается_один_раз_и_только_выше_занятого(
    db: Session, engine: Engine, captured: tuple[list[str], list[str]]
) -> None:
    """Один `UPDATE` с условием: повтор шага и шаг ниже дают отказ, шаг выше — принят.

    Форма «прочитать `last_used_step`, сравнить в Python, записать» прошла бы оба параллельных
    запроса с одним кодом. Здесь на каждое занятие — ровно одно обращение `UPDATE`, и условие
    сравнения видно в его тексте.
    """
    user = _учётка(db, suffix="claim")
    привязка = _выдать(db, user)
    _подтвердить(db, привязка)
    слой = SqlStore(db)
    запросы, _ = captured
    запросы.clear()

    assert слой.claim_totp_step(привязка.id, step=100) is True
    assert слой.claim_totp_step(привязка.id, step=100) is False, "тот же шаг занят дважды"
    assert слой.claim_totp_step(привязка.id, step=99) is False, "шаг ниже принятого принят"
    assert слой.claim_totp_step(привязка.id, step=101) is True
    слой.commit()

    обновления = _обновления_привязок(запросы)
    assert len(обновления) == 4, (
        f"на четыре занятия шага пришлось {len(обновления)} обновлений из "
        f"{len(запросы)} перехваченных запросов: лишние обращения (например SELECT перед UPDATE) "
        "означают не-атомарную форму"
    )
    for sql in обновления:
        assert "last_used_step IS NULL OR" in sql, f"в `UPDATE` нет ветки NULL: {sql}"
        assert "last_used_step <" in sql, f"в `UPDATE` нет сравнения шага: {sql}"
    assert _шаг_из_базы(engine, привязка.id) == 101, "последний принятый шаг не зафиксирован"


def test_шаг_доживает_до_bigint(db: Session, engine: Engine) -> None:
    """`last_used_step` — `BIGINT`, и граница `integer` ему не мешает.

    Шаг — секунды с эпохи / 30: сегодня это ≈ 1.8·10⁹, до `2^31 − 1` остаётся несколько лет. В
    `integer` переполнение случилось бы молча и в момент, который невозможно проверить ни на одном
    текущем коде, — а вместе с переполнением пропало бы и правило одноразовости.
    """
    тип = db.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'totp_enrollments' AND column_name = 'last_used_step'"
        )
    ).scalar_one()
    assert тип == "bigint", f"`last_used_step` обязан быть bigint, а не {тип}"

    user = _учётка(db, suffix="int8")
    привязка = _выдать(db, user)
    _подтвердить(db, привязка)
    слой = SqlStore(db)

    assert слой.claim_totp_step(привязка.id, step=_INT4_MAX + 1) is True
    слой.commit()
    assert _шаг_из_базы(engine, привязка.id) == _INT4_MAX + 1


def test_на_отозванной_или_неподтверждённой_привязке_шаг_не_занимается(
    db: Session, engine: Engine
) -> None:
    """Состояние строки стоит в том же `UPDATE`, что и сравнение шага.

    Между чтением привязки маршрутом и записью шага привязку могут отозвать (сброс администратором,
    §8.2 случай 2). Условие только по шагу приняло бы код на мёртвой строке: шаг был бы израсходован,
    а сессия поднялась бы до `full` по второму фактору, которого уже нет.
    """
    user = _учётка(db, suffix="state")
    незавершённая = _выдать(db, user)
    assert (
        SqlStore(db).claim_totp_step(незавершённая.id, step=10) is False
    ), "незавершённая привязка дала занять шаг"

    чужая = _учётка(db, suffix="revoked")
    отозванная = _выдать(db, чужая)
    _подтвердить(db, отозванная)
    _отозвать(db, отозванная)

    assert SqlStore(db).claim_totp_step(отозванная.id, step=20) is False, "отозванная дала шаг"
    db.commit()
    assert _шаг_из_базы(engine, отозванная.id) is None, "на отозванной строке шаг всё-таки записан"


# ─── лента неудачных кодов: окно считается базой ───────────────────────────────────────────────


def test_окно_неудач_режется_в_sql_и_не_обнуляется_успехом(
    db: Session, captured: tuple[list[str], list[str]]
) -> None:
    """Граница окна и порядок задаёт запрос: лента растёт навсегда, и читать её целиком нельзя.

    Записи не удаляются успешным входом (иначе перебор «до блокировки» обнулялся бы успехом, §8.2),
    поэтому на каждый неудачный код приложение читает только строки окна. Проверяются и ответ, и
    текст запроса: `at >` в `WHERE` плюс `ORDER BY`.
    """
    user = _учётка(db, suffix="window")
    чужая = _учётка(db, suffix="windowother")
    #: Минуты относительно `_NOW`. Строка `ВНЕ_ОКНА` обязана быть отсеяна границей, а попытка
    #: чужой учётки попадает во временной интервал и обязана быть отсеяна условием по
    #: `user_id` (§8.8: чужую ленту нельзя читать даже ради подсчёта окна).
    ВНЕ_ОКНА = -10
    В_ОКНЕ = (-2, 0, 2)
    ЧУЖАЯ_В_ОКНЕ = -1
    for минута in (ВНЕ_ОКНА, *В_ОКНЕ):
        db.add(
            TotpFailure(
                user_id=user.id,
                at=_NOW + timedelta(minutes=минута),
                ip=_АДРЕС_СВОЙ,
                source="web",
            )
        )
    db.add(
        TotpFailure(
            user_id=чужая.id,
            at=_NOW + timedelta(minutes=ЧУЖАЯ_В_ОКНЕ),
            ip=_АДРЕС_ЧУЖОЙ,
            source="web",
        )
    )
    db.commit()
    запросы, значения = captured
    запросы.clear()
    значения.clear()

    граница = _NOW - timedelta(minutes=3)
    попытки = SqlStore(db).totp_failures(user.id, not_before=граница)

    assert len(попытки) == len(
        В_ОКНЕ
    ), f"в окне ожидалось {len(В_ОКНЕ)} попыток своей учётки, получено {len(попытки)}"
    assert all(
        попытка.user_id == user.id for попытка in попытки
    ), "в окно попали попытки чужой учётки"
    assert [попытка.at for попытка in попытки] == sorted(
        попытка.at for попытка in попытки
    ), "лента не упорядочена по времени"
    assert all(
        попытка.at > граница for попытка in попытки
    ), "за границу окна попали строки, которые база обязана была отсеять"

    выборки = [sql for sql in запросы if "FROM totp_failures" in sql]
    assert выборки, "лента неудач не читалась из таблицы `totp_failures`"
    окно = выборки[-1]
    assert "user_id" in окно, f"в запросе о ленте нет условия по учётке: {окно}"
    assert "at >" in окно, f"граница окна задана не в SQL: {окно}"
    assert "ORDER BY totp_failures.at" in окно, f"порядок ленты задан не в SQL: {окно}"
    assert all(
        "203.0.113" not in значение for значение in значения
    ), "адрес попытки ушёл в связанные значения запроса о ленте — §8.8 требует минимального набора"
