"""Живой PostgreSQL 16 и таблица `invitations`: guarded-переходы приёма и отзыва, ограничения
схемы и счётчик живых администраторов (TZ §1.2, §4.1, `ADR-020` п. 4 и 6, задача `T-105`, срез `R7b`).

Оффлайновая половинка — `tests/integration/test_invitation_repository_memory.py` (тот же протокол
`Store` на `MemoryStore`) и `tests/integration/test_invitation_flow.py` (те же правила через HTTP).
Здесь проверяется ровно то, чего память показать не может:

* **приём одной ссылки выигрывает один запрос.** `claim_invitation` — один `UPDATE` с условием
  `state = 'pending' AND expires_at > now`, и второй вызов обязан получить `rowcount = 0`. Память
  повторяет тот же предикат циклом в Python, и там «нашли — пометили» неотличимо от атомарного
  перехода: без условия в тексте запроса две параллельные попытки создали бы две учётные записи по
  одной одноразовой ссылке (`REQ-identity-02`, `ADR-020` п. 4);
* **отзыв не переписывает состоявшийся приём** — тот же предикат с другой стороны: иначе журнал
  показал бы доступ, которого по строке приглашения нет;
* **срок проверяется тем же условием `UPDATE`**, а не отдельным чтением: между `invitation_by_hash`
  и заявкой есть окно, и закрывается оно предикатом запроса;
* **одноразовость хэша значения держит база** (`uq_invitations_token_hash`): два выпуска с одним
  значением сделали бы приём неопределимым, а `invitation_by_hash` читал бы «первую попавшую»
  строку;
* **`CHECK`-выражения схемы** (`ck_invitations_state`, `ck_invitations_target_present`) — второй
  контур против состояния вне набора и против выпуска без адресата: доменные проверки их не
  заменяют, потому что запись, сделанная вне домена (правка таблицы при разборе инцидента, `T-109`),
  обязана упереться в базу;
* **приём и отзыв одной ссылки на двух соединениях дают ровно одно состояние**: оба перехода —
  `UPDATE` с предикатом `state = 'pending'`, и второй ждёт блокировки строки, чтобы перечитать
  состояние уже после первой фиксации. Итог «принято и отозвано» означал бы учётную запись,
  выпущенную по приглашению, которое журнал показывает отозванным;
* **сбой записи учётной записи откатывает и заявку ссылки** (церемония — одна фиксация): иначе
  «ссылка истрачена, доступа нет» остаётся фактом, а при повторном визите появляется вторая
  учётная запись по той же ссылке (`ADR-020` п. 4);
* **`ON DELETE RESTRICT`** на `invitations.created_by` и `users.approved_by`: учётная запись,
  выдававшая приглашения или одобрявшая доступ, не исчезает молча (§4.1 «удаление — только
  архивированием»);
* **порядок `ORDER BY created_at`, `WHERE` по состоянию и `LIMIT` уходят в SQL**: иначе список
  выпусков и очередь одобрения читали бы таблицу целиком, а потолок обрезал бы произвольную её
  часть, из-за чего ожидающий мог бы в очередь не попасть (§9.3 п. 4, потолок `ACCOUNTS_LIST_LIMIT`);
* **счётчик живых администраторов считает база** (`count(*)` с предикатами `role` и `state`): ошибка
  в предикате означает либо «закрыть доступ последнему», либо «отказать зря» (`ADR-020` п. 6).

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `migrations`). Без
переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной базе —
падает, а не пропускается.
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy import Engine, create_engine, delete, event, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from apps.web.store import SqlStore
from packages.common.db import sqlalchemy_url
from packages.identity.invitations import (
    INVITATION_TTL,
    invitation_secret,
    invitation_token_hash,
    new_invitation,
)
from packages.identity.users import new_user
from packages.storage.models import Invitation, User, UserSession
from tests.integration.web_support import TEST_PASSWORD

# Читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

#: Учётки создаются на каждый тест со своим суффиксом: `users.login` уникален (а `citext` делает
#: уникальность ещё и регистронезависимой), а повторный прогон job'а идёт по той же базе.
#: Суффиксы — только латиница и цифры: `ck_users_login_format` и `ensure_login_syntax` не
#: принимают кириллицу в логинах (§8.1), в том числе в логине адресата приглашения.
_LOGIN_PREFIX: Final = "t105r7b"

#: Условный момент выпуска. Микросекунды обнулены: границы срока сверяются точечно, а `TIMESTAMPTZ`
#: хранит микросекунды. Прикладные часы намеренно отличаются от «сейчас»: срок выхода считает
#: `new_invitation` от переданного момента, и с ним же сравнивает предикат `claim_invitation`.
_NOW: Final = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

#: Имена ограничений схемы: они отличают «правило есть в базе» от «правило есть в коде». Текст
#: отказа обязан сослаться именно на них, иначе отказ пришёл из другого места.
_UQ_TOKEN_HASH: Final = "uq_invitations_token_hash"
_CK_STATE: Final = "ck_invitations_state"
_CK_TARGET: Final = "ck_invitations_target_present"
_FK_CREATED_BY: Final = "fk_invitations_created_by_users"
_FK_APPROVED_BY: Final = "fk_users_approved_by_users"


# ─── фикстуры ──────────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок проверок — отдельный от соединения приложения, чтобы видеть зафиксированное.

    DSN обязательно прогоняется через `sqlalchemy_url`: в job'е `migrations` переменная стоит в
    прямой форме `postgresql://…`, а SQLAlchemy искала бы `psycopg2` (драйвер в проекте один —
    psycopg3, `packages/common/db.py`).
    """
    созданный = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield созданный
    созданный.dispose()


@pytest.fixture
def captured(engine: Engine) -> Iterator[tuple[list[str], list[str]]]:
    """Тексты запросов и их связанные значения: предикат, порядок и потолок обязаны быть в SQL."""
    тексты: list[str] = []
    значения: list[str] = []

    def _собрать(
        _conn: object, _cursor: object, statement: str, parameters: object, *_rest: object
    ) -> None:
        тексты.append(statement)
        значения.append(repr(parameters))

    event.listen(engine, "before_cursor_execute", _собрать)
    try:
        yield тексты, значения
    finally:
        event.remove(engine, "before_cursor_execute", _собрать)


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    """Соединение проверок. Очистка — по суффиксу учётки и в порядке, который держат FK.

    `approved_by` ссылается на `users` с `RESTRICT`, поэтому сначала снимается ссылка одобрения,
    затем удаляются выпуски (они ссылаются на выдавшего), потом сеансы, и только затем сами
    учётные записи. Иначе уборка упёрлась бы в ограничение, и красным стал бы тест уборки, а не
    проверяемое поведение.
    """
    сессия = sessionmaker(bind=engine, expire_on_commit=False)()
    yield сессия
    идентификаторы = list(
        сессия.scalars(select(User.id).where(User.login.like(f"{_LOGIN_PREFIX}%"))).all()
    )
    if идентификаторы:
        сессия.execute(
            update(User)
            .where(User.id.in_(идентификаторы))
            .values(approved_by=None)
            .execution_options(synchronize_session=False)
        )
        сессия.execute(delete(Invitation).where(Invitation.created_by.in_(идентификаторы)))
        сессия.execute(delete(UserSession).where(UserSession.user_id.in_(идентификаторы)))
        сессия.execute(delete(User).where(User.id.in_(идентификаторы)))
        сессия.commit()
    сессия.close()


# ─── помощники ─────────────────────────────────────────────────────────────────────────────────


def _учётка(db: Session, *, suffix: str, role: str = "operator", state: str = "active") -> User:
    """Учётная запись, созданная доменом (`new_user`), а не конструктором ORM.

    Тот же вход, что у боевого пути: `new_user` обязан применить политику пароля и доменную
    проверку роли, иначе проверялась бы схема, а приложение — нет.
    """
    учётка = new_user(
        login=f"{_LOGIN_PREFIX}{suffix}{uuid.uuid4().hex[:6]}",
        password=TEST_PASSWORD,
        role=role,
        state=state,
    )
    db.add(учётка)
    db.commit()
    return учётка


def _выпуск(
    db: Session, админ: User, *, suffix: str, created_at: datetime | None = None
) -> tuple[Invitation, str]:
    """Выпуск, сделанный доменом (`new_invitation`) — тот же путь, что у формы раздела.

    `created_at` проставляется явно только там, где проверяются порядок и потолок списка: база
    ставит `now()`, и выпуски, созданные в одной транзакции, получили бы одинаковую отметку —
    сортировка по такой колонке ничего не проверяет.
    """
    выпуск = new_invitation(
        created_by=_идентификатор(админ),
        role="operator",
        login=f"{_LOGIN_PREFIX}t{suffix}{uuid.uuid4().hex[:4]}",
        now=_NOW,
    )
    if created_at is not None:
        выпуск.record.created_at = created_at
    db.add(выпуск.record)
    db.commit()
    return выпуск.record, выпуск.secret


def _идентификатор(учётка: User) -> uuid.UUID:
    """`id` учётной записи после фиксации.

    Проверка обязательна: в живом репозитории значение выдаёт база, и `None` в `created_by`
    означало бы, что выпуск приписан неизвестно кому, — наружный ключ отклонил бы строку, и
    тест упал бы по чужой причине.
    """
    if учётка.id is None:
        raise AssertionError("у зафиксированной учётной записи нет id — фикстура сломана")
    return учётка.id


def _строка(db: Session, выпуск: Invitation) -> Invitation:
    """Перечитать строку новым соединением: зафиксировано или живёт в текущей транзакции."""
    новое = sessionmaker(bind=db.get_bind(), expire_on_commit=False)()
    try:
        return новое.execute(select(Invitation).where(Invitation.id == выпуск.id)).scalar_one()
    finally:
        новое.close()


def _учётка_по_идентификатору(db: Session, идентификатор: uuid.UUID) -> User | None:
    """Перечитать учётную запись новым соединением: что лежит в таблице после отката."""
    новое = sessionmaker(bind=db.get_bind(), expire_on_commit=False)()
    try:
        return новое.execute(select(User).where(User.id == идентификатор)).scalar_one_or_none()
    finally:
        новое.close()


def _число_выпусков(db: Session, админ: User) -> int:
    """Сколько строк выпусков у администратора в таблице, а не в identity map запроса."""
    return int(
        db.scalar(
            select(func.count()).select_from(Invitation).where(Invitation.created_by == админ.id)
        )
        or 0
    )


def _прямой_выпуск(
    база: Session, админ: User, *, suffix: str, state: str, адресат: bool
) -> Invitation:
    """Строка `invitations`, составленная мимо домена: проверяется ограничение схемы.

    Домен такие значения не создаёт намеренно — и именно поэтому у схемы есть второй контур:
    запись вне домена (правка таблицы при разборе инцидента, `T-109`) обязана упиреться в
    ограничение. Значение для хэша берётся у доменного генератора (`invitation_secret`), а не
    сочиняется: `invitation_token_hash` сам проверяет форму значения и на произвольной строке
    бросает `MalformedInvitationTokenError` (это и показал прогон job `миграции`), а смысл
    проверки в том, чтобы отказать строке, **некорректной только в измеряемом измерении** —
    состоянии или адресате. Хэш лежит в колонке `Text`, CHECK на его форму у выпусков нет:
    форму проверяет слой чтения (`is_sha256_hex`), и это держит офлайн-половинка.
    """
    строка = Invitation(
        login=f"{_LOGIN_PREFIX}{suffix}{uuid.uuid4().hex[:6]}" if адресат else None,
        email=None,
        role="operator",
        token_hash=invitation_token_hash(invitation_secret()),
        state=state,
        expires_at=_NOW + INVITATION_TTL,
        created_by=_идентификатор(админ),
    )
    база.add(строка)
    return строка


# ─── guarded-переходы: приём и отзыв ──────────────────────────────────────────────────────────


def test_приём_одной_ссылки_выигрывает_один_запрос(
    db: Session, engine: Engine, captured: tuple[list[str], list[str]]
) -> None:
    """Две попытки принять одну ссылку на двух соединениях — ровно одна заявка (§1.2, `REQ-identity-02`).

    Обязательная проверка среза `R7b` (`ADR-020` п. 4). Форма «прочитали выпуск → решили, что он
    живой → пометили использованным» зелёная на любом офлайн-репозитории и двойная под
    параллельными входами: оба чтения видят `state = 'pending'` и оба создают учётную запись по
    одной одноразовой ссылке. На базе переход закрывает один `UPDATE` с условием: строка
    блокируется на время перехода, вторая попытка перечитывает состояние уже после первой и не
    находит подходящей строки (`rowcount = 0`).

    Оба входа обязаны **одновременно** оказаться внутри перехода, иначе проверка сводится к
    последовательным запросам и прошла бы на не-атомарной реализации. Для этого барьер стоит между
    чтением выпуска (`invitation_of_id` — так же, как это делает маршрут приёма) и заявкой.

    Отдельно держится текст запроса: `UPDATE invitations … WHERE … state … expires_at …` и
    связанное значение `pending`. Если предикат уедет из запроса в Python-проверку «прочитали —
    решили — записали», между чтением и записью появится окно, и гонка вернётся молча.
    """
    админ = _учётка(db, suffix="race")
    выпуск, _значение = _выпуск(db, админ, suffix="race")
    фабрика = sessionmaker(bind=engine, expire_on_commit=False)

    оба_у_заявки = threading.Barrier(2)

    def попытка() -> bool:
        сессия = фабрика()
        try:
            слой = SqlStore(сессия)
            строка = слой.invitation_of_id(_идентификатор_выпуска(выпуск))
            if строка is None:
                # Выпуска не нашлось (само по себе это уже провал приёма). Барьер при этом обязан
                # быть снят, иначе второй вход дождётся таймаута, и настоящая причина отказа
                # исчезнет за `BrokenBarrierError`.
                оба_у_заявки.abort()
                return False
            # Оба входа дошли до заявки: транзакты открыты, выпуск прочитан обоими.
            оба_у_заявки.wait(timeout=20)
            успех = слой.claim_invitation(invitation_id=строка.id, now=_NOW)
            сессия.commit()
            return успех
        finally:
            сессия.close()

    with ThreadPoolExecutor(max_workers=2) as пул:
        будущие = [пул.submit(попытка), пул.submit(попытка)]
        исходы = [будущее.result() for будущее in будущие]

    assert sum(исходы) == 1, (
        f"одна ссылка принята {sum(исходы)} раз(а) при двух параллельных входах: {исходы} — "
        "guarded-`UPDATE` не атомарен, и по одной ссылке создаются две учётные записи"
    )

    актуальная = _строка(db, выпуск)
    assert актуальная.state == "used"
    assert (
        актуальная.used_at is not None
    ), "заявка ссылки не оставила штампа — журнал не увидит приём"

    заявки = [текст for текст in captured[0] if "update invitations" in текст.lower()]
    assert заявки, f"слой не отправил UPDATE по таблице приглашений: {captured[0]}"
    текст = заявки[-1]
    for предикат in ("where", "state", "expires_at"):
        assert предикат in текст.lower(), f"в тексте заявки нет предиката {предикат!r}: {текст}"
    assert any(
        "pending" in значение for значение in captured[1]
    ), "связанное значение 'pending' не ушло в запрос: предикат срока и состояния проверяется в Python"


def _идентификатор_выпуска(выпуск: Invitation) -> uuid.UUID:
    """`id` выпуска после фиксации: без него адрес заявки уходит в `WHERE id IS NULL`."""
    if выпуск.id is None:
        raise AssertionError("у зафиксированного выпуска нет id — фикстура сломана")
    return выпуск.id


def test_просроченный_выпуск_не_заявить_в_том_же_запросе(db: Session) -> None:
    """Срок проверяется условием `UPDATE`, а не отдельным чтением до него.

    Между `invitation_by_hash` и заявкой есть окно, и если бы срок проверялся только чтением,
    выпуск, закрытый в этом окне, всё равно был бы заявлен. Отдельно важно, что при отказе
    состояние строки остаётся `pending`: отказ не имеет права ничего менять (§1.2 — просроченный
    выпуск не становится «использованным»).
    """
    админ = _учётка(db, suffix="expiry")
    выпуск, _значение = _выпуск(db, админ, suffix="expiry")

    слой = SqlStore(db)
    позже_срока = _NOW + INVITATION_TTL + timedelta(seconds=1)
    assert not слой.claim_invitation(invitation_id=выпуск.id, now=позже_срока)
    db.commit()

    актуальная = _строка(db, выпуск)
    assert актуальная.state == "pending", "просроченный выпуск помечен использованным"
    assert актуальная.used_at is None, "отказ по сроку поставил штамп приёма"


def test_отзыв_не_переписывает_состоявшийся_приём(db: Session) -> None:
    """`revoke_invitation_row` после приёма обязан вернуть `False` и не тронуть строку.

    Второй конец той же гонки, что и в проверке выше: если отзыв переставит `used` в `revoked`,
    учётная запись останется созданной по приглашению, которое журнал показывает отозванным, —
    то есть доступ, которого по записи нет (`ADR-020` п. 4).
    """
    админ = _учётка(db, suffix="revafteruse")
    выпуск, _значение = _выпуск(db, админ, suffix="revafteruse")

    слой = SqlStore(db)
    assert слой.claim_invitation(invitation_id=выпуск.id, now=_NOW)
    db.commit()
    assert not слой.revoke_invitation_row(invitation_id=выпуск.id)
    db.commit()

    assert _строка(db, выпуск).state == "used", "отзыв переписал состоявшийся приём"


def test_повторный_отзыв_ничего_не_меняет(db: Session) -> None:
    """Отзыв идемпотентен на уровне SQL: второй вызов — `rowcount = 0`, а не второй успех.

    Разница с «молчаливым успехом» существенна для слоя представления: по результату выбирается
    объяснение («отозвали раньше» или «ссылкой уже воспользовались»), и обе попытки, помеченные
    успешными, лишили бы администратора этого различия (§9.3).
    """
    админ = _учётка(db, suffix="revtwice")
    выпуск, _значение = _выпуск(db, админ, suffix="revtwice")

    слой = SqlStore(db)
    assert слой.revoke_invitation_row(invitation_id=выпуск.id)
    db.commit()
    assert not слой.revoke_invitation_row(invitation_id=выпуск.id)
    db.commit()

    assert _строка(db, выпуск).state == "revoked"
    assert _число_выпусков(db, админ) == 1, "второй отзыв создал вторую строку"


def test_приём_и_отзыв_одной_ссылки_на_двух_соединениях_дают_одно_состояние(
    db: Session, engine: Engine
) -> None:
    """Параллельные приём и отзыв одной ссылки: выигрывает один переход, состояние — одно.

    Направление гонки, которое офлайн-зеркало показать не может вовсе: в `MemoryStore` два входа
    физически не приходят, и там «прочитали выпуск → пометили» проходит зелёно в любом порядке. На
    базе оба перехода — `UPDATE` с предикатом `state = 'pending'` по одной строке: второй ждёт
    блокировки, перечитывает состояние уже после первой фиксации и не находит подходящей строки
    (`rowcount = 0`). Ровно та же форма, что держит `test_backup_code_single_use` для резервных
    кодов.

    Оба входа обязаны **одновременно** оказаться внутри перехода: барьер стоит между чтением выпуска
    (`invitation_of_id` — так же, как делает маршрут отзыва) и мутацией.

    Важны оба исхода: «принято и отозвано» означало бы учётную запись, выпущенную по приглашению,
    которое журнал показывает отозванным, а «ни то и ни другое» — ссылку, застрявшую в `pending`
    после двух успешных операций.
    """
    админ = _учётка(db, suffix="claimrev")
    выпуск, _значение = _выпуск(db, админ, suffix="claimrev")
    фабрика = sessionmaker(bind=engine, expire_on_commit=False)

    оба_у_перехода = threading.Barrier(2)

    def попытка(действие: str) -> bool:
        сессия = фабрика()
        try:
            слой = SqlStore(сессия)
            строка = слой.invitation_of_id(_идентификатор_выпуска(выпуск))
            if строка is None:
                # Выпуска не нашлось — сам по себе это провал. Барьер обязан быть снят, иначе
                # второй вход дождётся таймаута, и настоящая причина исчезнет за
                # `BrokenBarrierError`.
                оба_у_перехода.abort()
                return False
            оба_у_перехода.wait(timeout=20)
            if действие == "приём":
                успех = слой.claim_invitation(invitation_id=строка.id, now=_NOW)
            else:
                успех = слой.revoke_invitation_row(invitation_id=строка.id)
            сессия.commit()
            return успех
        finally:
            сессия.close()

    with ThreadPoolExecutor(max_workers=2) as пул:
        будущие = [пул.submit(попытка, "приём"), пул.submit(попытка, "отзыв")]
        исходы = [будущее.result() for будущее in будущие]

    принят, отозван = исходы
    assert принят != отозван, (
        f"приём и отзыв одной ссылки закончились одинаково: {исходы} — по одной строке прошли "
        "оба перехода, и предикат `state = 'pending'` исполняет не база"
    )

    актуальная = _строка(db, выпуск)
    ожидаемое = "used" if принят else "revoked"
    assert (
        актуальная.state == ожидаемое
    ), f"итоговое состояние {актуальная.state!r}, ожидалось {ожидаемое!r}: переход не зафиксирован"
    if принят:
        assert актуальная.used_at is not None, "принятая ссылка без штампа приёма"
    else:
        assert актуальная.used_at is None, "отзыв поставил штамп приёма"


def test_сбой_записи_учётной_записи_откатывает_и_заявку_ссылки(db: Session) -> None:
    """Церемония приёма — одна фиксация: сбой второй записи откатывает и заявку ссылки.

    Порядок маршрута (`ADR-020` п. 4, закрепляет
    `tests/contract/test_web_invitation_ceremony_contract.py`): заявка ссылки → создание учётной
    записи → одна `commit`. Офлайн-зеркало этого не показывает: у `MemoryStore` нет отката, и там
    «ссылка истрачена, учётной записи нет» остаётся в памяти как совершившийся факт — ровно тот
    провал, который contract-тест называет «заявленная ссылка без учётной записи».

    На базе сбой `INSERT` учётной записи (логин занят — `citext`-уникальность) откатывает и
    `UPDATE` заявки: строка возвращается в `pending` без штампа, и человек может прийти по ссылке
    повторно. Обратный порядок (сначала учётная запись, затем заявка) при повторном визите дал бы
    вторую учётную запись по той же ссылке — поэтому проверяется откат пары, а не только текст
    вызова.
    """
    админ = _учётка(db, suffix="rbadmin")
    занятая = _учётка(db, suffix="rbtaken")
    выпуск, _значение = _выпуск(db, админ, suffix="rb")

    фабрика = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    with фабрика() as церемония:
        слой = SqlStore(церемония)
        assert слой.claim_invitation(
            invitation_id=_идентификатор_выпуска(выпуск), now=_NOW
        ), "заявка ссылки не прошла — церемонии вообще не происходит"
        # Та же учётная операция, что делает маршрут приёма, но с занятым логином.
        слой.add(new_user(login=_значение_логина(занятая), password=TEST_PASSWORD, role="operator"))
        with pytest.raises(IntegrityError):
            церемония.commit()
        церемония.rollback()

    актуальная = _строка(db, выпуск)
    assert актуальная.state == "pending", (
        "сбой записи учётной записи оставил ссылку истраченной: человек не сможет прийти по ней, "
        "а выпуска доступ не получил"
    )
    assert актуальная.used_at is None, "откат оставил штамп приёма"

    с_новой = sessionmaker(bind=db.get_bind(), expire_on_commit=False)()
    try:
        число = с_новой.scalar(
            select(func.count()).select_from(User).where(User.login == _значение_логина(занятая))
        )
    finally:
        с_новой.close()
    assert int(число or 0) == 1, f"по занятому логину появилось {число} учётных записей"


def _значение_логина(учётка: User) -> str:
    """Логин зафиксированной учётной записи: `citext` возвращает значение как текст."""
    if учётка.login is None:
        raise AssertionError("у зафиксированной учётной записи нет логина — фикстура сломана")
    return учётка.login


# ─── ограничения схемы ────────────────────────────────────────────────────────────────────────


def test_хэш_значения_ссылки_уникален_на_уровне_базы(db: Session) -> None:
    """Два выпуска с одним `token_hash` — нарушение `uq_invitations_token_hash`.

    Домен генерирует значение криптографически стойким (`invitation_secret`), и шанс совпадения —
    не предмет проверки. Предмет проверки то, что **база** не пустит вторую строку с тем же
    значением: иначе приём по ссылке был бы неопределим (какой из двух выпусков считать
    использованным), а `invitation_by_hash` читал бы «первую попавшую» строку.

    Дубликат создаётся напрямую через ORM, минуя домен: проверяется ограничение схемы, а не
    генератор значений.
    """
    админ = _учётка(db, suffix="hash")
    выпуск, значение = _выпуск(db, админ, suffix="hash")

    дубликат = Invitation(
        login=f"{_LOGIN_PREFIX}dup{uuid.uuid4().hex[:6]}",
        role="operator",
        token_hash=invitation_token_hash(значение),
        state="pending",
        expires_at=_NOW + INVITATION_TTL,
        created_by=_идентификатор(админ),
    )
    db.add(дубликат)
    # Нарушение держится на операторе, а не на коммите: psycopg3 получает ошибку вместе с ответом
    # на запрос, поэтому `pytest.raises` обёрнут вокруг одного обращения (`flush` отправляет
    # `INSERT`, не дожидаясь коммита).
    with pytest.raises(IntegrityError) as ошибка:
        db.flush()

    отказ = str(ошибка.value)
    assert _UQ_TOKEN_HASH in отказ, f"отказ пришёл не из ограничения хэша: {отказ}"
    db.rollback()
    assert _число_выпусков(db, админ) == 1, "после отказа в таблице осталась вторая строка"


def test_состояние_выпуска_держит_CHECK(db: Session) -> None:
    """Состояние вне набора `pending`/`used`/`revoked` отклоняет база (`ck_invitations_state`).

    Доменный переход такое состояние не создаст, но запись, сделанная вне домена, обязана упертся
    в схему: состояние — признак живости ссылки, и значение вне закрытого набора сделало бы
    поведение маршрутов неопределённым (`ADR-020` п. 3).
    """
    админ = _учётка(db, suffix="checkstate")
    _прямой_выпуск(db, админ, suffix="ckstate", state="accepted", адресат=True)
    with pytest.raises(IntegrityError) as ошибка:
        db.flush()

    отказ = str(ошибка.value)
    assert _CK_STATE in отказ, f"отказ пришёл не из CHECK состояния: {отказ}"
    db.rollback()
    assert _число_выпусков(db, админ) == 0, "строка с запрещённым состоянием всё-таки записана"


def test_выпуск_без_адресата_не_вставляется(db: Session) -> None:
    """Ни e-mail, ни логин — нарушение `ck_invitations_target_present` (§1.2).

    Домен требует адресата до `INSERT` (`InvitationTargetError`), и отдельной проверки в маршруте
    нет сознательно. Поэтому ограничение схемы — второй контур: оно защищает таблицу от записи вне
    домена, а без него в списке появился бы выпуск, который нельзя ни адресовать, ни объяснить.
    """
    админ = _учётка(db, suffix="notarget")
    _прямой_выпуск(db, админ, suffix="nobody", state="pending", адресат=False)
    with pytest.raises(IntegrityError) as ошибка:
        db.flush()

    отказ = str(ошибка.value)
    assert _CK_TARGET in отказ, f"отказ пришёл не из CHECK адресата: {отказ}"
    db.rollback()
    assert _число_выпусков(db, админ) == 0, "выпуск без адресата всё-таки записан"


def test_учётную_запись_с_выпущенным_приглашением_не_удалить(db: Session) -> None:
    """`ON DELETE RESTRICT` на `invitations.created_by` (§4.1 «удаление — только архивированием»).

    Выдавший приглашение остаётся ссылкой в списке выпусков и в журнале (`T-109` требует знать, кто
    выпустил доступ). Удаление строки оставило бы выпуск с висячей ссылкой или оборвало бы связь
    «кто дал доступ» — поэтому база обязана отказать, а не стереть выпуски каскадом.
    """
    админ = _учётка(db, suffix="restrictinv")
    _выпуск(db, админ, suffix="restrictinv")

    with pytest.raises(IntegrityError) as ошибка:
        db.execute(delete(User).where(User.id == _идентификатор(админ)))

    отказ = str(ошибка.value)
    assert _FK_CREATED_BY in отказ, f"удаление учётки не остановил FK выпусков: {отказ}"
    db.rollback()
    assert _число_выпусков(db, админ) == 1, "вместе с отказом пропали выпуски"


def test_одобренную_учётную_запись_нельзя_оставить_без_одобрившего(db: Session) -> None:
    """`ON DELETE RESTRICT` на `users.approved_by`: одобрившего удалить нельзя.

    `approved_by` — ответ на вопрос «кто открыл доступ» (§1.2 шаг 2), и именно его требует журнал
    (§10). Каскад обнулил бы автора задним числом, и «одобрено, но кем — неизвестно» стало бы
    обычным состоянием учётной записи.
    """
    одобряющий = _учётка(db, suffix="approver", role="admin")
    одобренный = _учётка(db, suffix="approved")
    одобренный.approved_by = _идентификатор(одобряющий)
    одобренный.approved_at = _NOW
    db.commit()

    with pytest.raises(IntegrityError) as ошибка:
        db.execute(delete(User).where(User.id == _идентификатор(одобряющий)))

    отказ = str(ошибка.value)
    assert _FK_APPROVED_BY in отказ, f"удаление одобрившего не остановил FK одобрения: {отказ}"
    db.rollback()

    перечитанный = _учётка_по_идентификатору(db, _идентификатор(одобренный))
    assert перечитанный is not None, "отказ удаления стер саму учётную запись"
    assert перечитанный.approved_by == _идентификатор(
        одобряющий
    ), "попытка удаления изменила отметку одобрения"


# ─── списки и счётчик: фильтр, порядок и потолок уходят в SQL ─────────────────────────────────


def test_список_выпусков_сортируется_в_базе_и_ограничивается_потолком(
    db: Session, captured: tuple[list[str], list[str]]
) -> None:
    """Порядок `ORDER BY created_at` и `LIMIT` читаются в тексте запроса, а не в Python.

    Список приглашений растёт вместе с числом выпусков, и «выбрать всё, потом отсортировать и
    обрезать» означало бы читать таблицу целиком на каждый заход в раздел (§8.1;
    `ACCOUNTS_LIST_LIMIT` — потолок, а не постраничность). Выпуски вставляются в перемешанном
    порядке: если сортировка держится только памятью, порядок совпадёт случайно.
    """
    админ = _учётка(db, suffix="listsort")
    старый, _ = _выпуск(db, админ, suffix="ls1", created_at=_NOW - timedelta(days=2))
    средний, _ = _выпуск(db, админ, suffix="ls2", created_at=_NOW - timedelta(days=1))
    свежий, _ = _выпуск(db, админ, suffix="ls3", created_at=_NOW)

    все = SqlStore(db).pending_invitations()
    показанные = [выпуск.id for выпуск in все if выпуск.created_by == _идентификатор(админ)]
    assert показанные == [
        старый.id,
        средний.id,
        свежий.id,
    ], f"порядок выпусков не по `created_at`: {показанные}"

    обрезанный = SqlStore(db).pending_invitations(limit=2)
    assert len(обрезанный) == 2, "потолок списка не применён"

    списки = [
        текст.lower()
        for текст in captured[0]
        if "from invitations" in текст.lower() and "select" in текст.lower()
    ]
    assert списки, "запрос списка выпусков не найден среди перехваченных"
    assert any("order by" in текст for текст in списки), f"в запросе нет ORDER BY: {списки}"
    assert any("limit" in текст for текст in списки), f"в запросе нет LIMIT: {списки}"


def test_список_учётных_записей_фильтруется_по_состоянию_в_базе(
    db: Session, captured: tuple[list[str], list[str]]
) -> None:
    """Фильтр по состоянию уходит в `WHERE`, а не отфильтровывается после выборки.

    Очередь одобрения — тот же запрос с `states=('awaiting_approval',)` (§9.3 п. 4): если
    состояние отфильтровывается в Python, в консоль читают всех, включая архивные записи, а
    потолок `LIMIT` обрезает не очередь, а произвольную часть таблицы — ожидающий мог бы в очередь
    не попасть вообще.
    """
    ожидающий = _учётка(db, suffix="queuewait", state="awaiting_approval")
    ожидающий.created_at = _NOW
    работающий = _учётка(db, suffix="queuework")
    работающий.created_at = _NOW + timedelta(minutes=1)
    db.commit()

    очередь = SqlStore(db).accounts(states=("awaiting_approval",))
    показанные = [учётка.id for учётка in очередь if учётка.login.startswith(_LOGIN_PREFIX)]
    assert показанные == [
        _идентификатор(ожидающий)
    ], f"в очереди оказались не только ожидающие: {показанные}"
    assert работающий.state == "active"

    запросы = [
        текст.lower()
        for текст in captured[0]
        if "from users" in текст.lower() and "select" in текст.lower()
    ]
    assert запросы, "запрос списка учётных записей не найден среди перехваченных"
    assert any(
        "where" in текст and "limit" in текст for текст in запросы
    ), f"запрос списка учётных записей не содержит фильтра и потолка: {запросы}"


def test_счётчик_живых_администраторов_исполняет_база(
    db: Session, captured: tuple[list[str], list[str]]
) -> None:
    """`active_admin_count` — `count(*)` с предикатами `role` и `state`, а не вычитание из списка.

    Расклад собран так, чтобы ошибка предиката была заметна: двое живых администраторов, один
    заблокированный, один архивный и один активный оператор. Считать «все строки с ролью `admin`» —
    значит разрешить закрыть доступ последнему живому (архивный администратор пригласить никого не
    может); считать «все живые учётные записи» — значит отказывать зря (`ADR-020` п. 6).

    Сравнение идёт с числом **до** создания записей: в базе job'а могли остаться строки других
    проверок, и абсолютное значение проверяло бы состояние чужих тестов, а не предикат счётчика.
    Отдельно держится `except_user_id`: счёт обязан исключать саму запись, иначе блокировка одного
    из двух живых администраторов посчитала бы обоих.
    """
    слой = SqlStore(db)
    было = слой.active_admin_count()

    живой_один = _учётка(db, suffix="adminone", role="admin")
    _учётка(db, suffix="admintwo", role="admin")
    _учётка(db, suffix="adminbad", role="admin", state="suspended")
    _учётка(db, suffix="adminarch", role="admin", state="archived")
    _учётка(db, suffix="operatoractive", role="operator")

    стало = слой.active_admin_count()
    кроме_одного = слой.active_admin_count(except_user_id=_идентификатор(живой_один))

    assert стало == было + 2, (
        f"счётчик живых администраторов: было {было}, стало {стало}; ожидались ровно два новых "
        "живых администратора — заблокированный и архивный считаться не должны"
    )
    assert (
        кроме_одного == стало - 1
    ), f"счёт без названной записи: {кроме_одного} вместо {стало - 1}"

    запросы = [
        текст.lower()
        for текст in captured[0]
        if "count(" in текст.lower() and "from users" in текст.lower()
    ]
    assert запросы, f"счёт исполнялся не базой: среди запросов нет count(*) по users: {captured[0]}"
    assert any(
        "role" in текст and "state" in текст for текст in запросы
    ), f"у запроса счётчика нет предикатов роли и состояния: {запросы}"


def test_счётчик_видит_свежий_переход(db: Session) -> None:
    """Счёт зависит от состояния, а не от порядка вызовов: блокировка меняет его немедленно.

    Проверка последнего живого администратора читает счёт перед переходом (`ADR-020` п. 6) — и
    обязана видеть уже зафиксированные переходы: если бы счёт зависел от кэшированного списка,
    второй закрытый доступ прошёл бы, потому что число осталось бы прежним.
    """
    слой = SqlStore(db)
    было = слой.active_admin_count()

    первый = _учётка(db, suffix="countone", role="admin")
    второй = _учётка(db, suffix="counttwo", role="admin")
    assert слой.active_admin_count(except_user_id=_идентификатор(первый)) == было + 1

    второй.state = "suspended"
    db.commit()
    assert слой.active_admin_count(except_user_id=_идентификатор(первый)) == было, (
        "после блокировки второго администратора счёт не изменился: проверка последнего "
        "администратора перестала ловить свой случай"
    )
