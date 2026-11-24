"""Прикладной путь к таблице `audit_log`: единственная точка добавления записи и чтение журнала.

Модуль живёт в общем слое, а не в `apps/web/store.py`, по одной причине: вторым писателем журнала
становится процесс `jobs` (ежедневная `integrity-check`, TZ §8.7, `ADR-025` п. 9 и
`ADR-026` п. 4, срез `T-109`
`R3.2`). Контракт `tests/contract/test_repo_layout.py` запрещает процессам импортировать друг
друга («процессы общаются через базу, а не друг через друга», TZ §02 §2.1), а общего слоя без этого
файла не осталось бы — и протокол добавления пришлось бы переписывать второй реализацией.

**Почему файл стоит в `packages/storage`, а не в `packages/identity`.** Путь к таблице исполняет
SQL: advisory-замок, `INSERT … RETURNING`, выбор колонок §4.1. Слой идентичности SQL не исполняет и
держит закрытый перечень внешних зависимостей (контракт
`test_identity_не_тянет_несогласованных_зависимостей`: любая новая зависимость — стоп-точка TZ §15,
обоснование + лицензия + advisory). Правила же цепочки — хэш, канонический JSON, закрытый реестр
событий, политики `details` — остались в `packages/identity/audit.py` и сюда не переезжали: здесь
только то, что требует соединения.

**Чем опасна вторая реализация.** Порядок «advisory-замок → чтение хвоста → вставка с `hash_prev`
→ откат целиком при любом отказе» (`ADR-025` п. 6) держит отсутствие развилки в цепочке. Два
файла с этим порядком расходятся при первой же правке: второй писатель начинает читать хвост до
замка, и база отвечает `23505` на `ix_audit_log_hash_prev_linked`, а откатанная транзакция
выглядит как сбой того процесса, а не как сломанный протокол. Отдельно расходится и ключ замка:
два разных ключа — два независимых замка над одной цепочкой.

**Что здесь не переехало.** Обязательства вызывающего (`Store.append_audit` в `apps/web/store.py`)
остались в слое входа: `at` снимается один раз на событие, `action` берётся из закрытого реестра,
`ip` и `request_id` подставляются из контекста запроса, событие состоявшегося изменения пишется
до `commit()` маршрута. Это правила маршрута, а не правила таблицы: у процесса `jobs` ни адреса,
ни `request_id` нет вовсе, и переносить их в общий слой значило бы выдумывать значения.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Final, cast
from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from packages.identity.audit import (
    AuditRecord,
    StoredRecord,
    audit_row_values,
    read_stored_record,
)
from packages.identity.notify import (
    GROUND_LOGIN,
    LoginNoticeState,
    NotifyDecision,
)
from packages.storage.models import AuditLogEntry, User, WebAuditOutbox

#: Ключ advisory-блокировки цепочки журнала (`pg_advisory_xact_lock`, `ADR-025` п. 6).
#: Значение выведено из ASCII-метки `tbot-aud` и записано константой: два процесса обязаны сойтись
#: на одном ключе, а «случайное число» дало бы два независимых замка над одной цепочкой. Метка
#: короче восьми байт намеренно: ключ `pg_advisory_xact_lock` — `bigint` со знаком, и восьмибайтное
#: значение вышло бы за верхнюю границу.
#:
#: Срез `R3.2` перенёс константу сюда из `apps/web/store.py`: с этого момента её читают два
#: процесса, и «одинаковый ключ» обязан быть обеспечен одним определением, а не двумя строками в
#: двух файлах.
AUDIT_CHAIN_LOCK_KEY: Final = 8_386_388_000_885_536_100

#: SQLSTATE «нарушение уникальности». Код состояния читают из `error.orig.sqlstate`, а не из текста:
#: psycopg3 поднимает `psycopg.errors.UniqueViolation`, и в его сообщении кода нет (замер
#: `CI 45165930936` — проверка искала подстроку `23505` в тексте и падала на правильном отказе).
SQLSTATE_UNIQUE_VIOLATION: Final = "23505"


class AuditAppendError(RuntimeError):
    """Запись журнала не добавлена; транзакция откатана целиком.

    Молча продолжить нельзя: события §8.7 нет, а разбор показывает недостающее событие как
    `broken_link`, то есть как подделку содержимого (`ADR-025` п. 7). В слое входа этому случаю
    соответствует `503` с фиксированным текстом: процесс жив, недоступна одна возможность; в
    процессе `jobs` этому случаю соответствует запись `job_failed` в журнале процесса.
    """


class AuditChainConflictError(AuditAppendError):
    """Хвост цепочки уже занят другой записью (`ix_audit_log_hash_prev_linked`, `23505`).

    Отдельный класс нужен затем, чтобы слой доступа отличал конфликт цепочки от прочих нарушений
    по коду состояния, а не по тексту сообщения (`ADR-025` п. 6). Повтор «дописать запись» не
    делается: повтор на том же хвосте — та же развилка, а повтор всей транзакции применил бы
    бизнес-изменение дважды.
    """


# ─── добавление записи: единственный путь в цепочку (§8.7, `ADR-025` п. 2/4/6) ───────────────


def lock_audit_chain(session: Session) -> None:
    """Взять advisory-замок цепочки журнала на время транзакции.

    Замок транзакционный, поэтому отдельно его снимать не нужно и нельзя: он держится ровно
    столько, сколько транзакция, добавившая запись, не зафиксирована. Ключ один на весь
    журнал — цепочка тоже одна.

    Замок обязан быть взят **до** чтения хвоста: `FOR UPDATE` последней строки на пустой таблице
    ничего не блокирует, и два процесса вставили бы по первой записи цепочки (обе с
    `hash_prev IS NULL`, а страж развилки таких пар не отклоняет — частичный индекс исключает
    `NULL`).
    """
    session.execute(select(func.pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)))


def tail_hash(session: Session) -> str | None:
    """Хэш последней записи журнала в порядке `id`, либо `None` у первой записи цепочки.

    Порядок задаёт `id`, а не `at`: моменты двух процессов могут прийти вразнобой, а хэш
    считается без `id` (колонку выдаёт база уже после расчёта — `ADR-025` п. 3).
    """
    return session.execute(
        select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1)
    ).scalar_one_or_none()


def append_audit_record(session: Session, record: AuditRecord) -> int:
    """Добавить запись журнала в транзакцию текущего вызывающего; вернуть выданный базой `id`.

    Порядок внутри функции фиксирован: замок → хвост → вставка. Вызывающий не выбирает `hash_prev`
    сам и не может его передать: привязка к хвосту — часть протокола, а не параметр.

    `ON CONFLICT DO NOTHING` здесь нет и появиться не может: такая конструкция вернулась бы без
    исключения и без возвращённой строки, то есть молча потеряла бы событие, а разбор показал бы
    его как `broken_link` — как подделку содержимого (`ADR-025` п. 4; живая проверка
    `test_обход_через_on_conflict_do_nothing_не_создаёт_строку`). Поэтому функция обязана смотреть
    на число строк, а не только на отсутствие ошибки.

    Фиксирует не функция, а вызывающий: событие состоявшегося изменения обязано уйти той же
    транзакцией, что и само изменение (`ADR-025` п. 6), а событие отказа — отдельной фиксацией
    сразу (`commit_now=True` у `Store.append_audit`). Возвращаемый `id` нужен не для протокола, а
    для проверок и для журнала процесса: это единственный идентификатор, который знает база.
    """
    lock_audit_chain(session)
    linked = replace(record, hash_prev=tail_hash(session))
    try:
        result = cast(
            "CursorResult[Any]",
            session.execute(
                insert(AuditLogEntry).values(audit_row_values(linked)).returning(AuditLogEntry.id)
            ),
        )
    except IntegrityError as error:
        # Откат целиком: «изменение зафиксировано, события нет» — ровно то состояние, из-за
        # которого журнал перестаёт быть доказательством (`ADR-025` п. 6).
        session.rollback()
        if str(getattr(error.orig, "sqlstate", "")) == SQLSTATE_UNIQUE_VIOLATION:
            raise AuditChainConflictError(
                "хвост цепочки журнала уже занят другой записью: "
                "ix_audit_log_hash_prev_linked отклонил вставку (23505)"
            ) from error
        raise
    # Число строк считается по возвращённым идентификаторам, а не по `Result.rowcount`.
    # Причина измерена первым прогоном среза `R2` (CI `45182752079`): то же выполнение через
    # `Session` (ORM-путь, а не `Connection`) отдаёт `rowcount = -1`, и проверка «ровно одна
    # строка» падала на корректной вставке. `RETURNING id` даёт то же число способом, не
    # зависящим от посредника, и попутно подтверждает, что идентификатор выдала база (§4.1:
    # `id` — identity, приложение его не назначает). Пустой список — это и есть тот случай
    # «вставки нет без ошибки», ради которого требование о числе строк и вводилось.
    inserted = result.scalars().all()
    if len(inserted) != 1:
        session.rollback()
        raise AuditAppendError(
            f"вставка в журнал вернула {len(inserted)} идентификаторов вместо одного: "
            f"событие {linked.action} не записано"
        )
    return int(inserted[0])


# ─── журнал решений порога уведомлений (§8.7, `T-116`, `ADR-028`) ─────────────────────────

#: SQLSTATE «нарушение ссылочной целостности» (`fk_web_audit_outbox_audit_id_audit_log`).
#: Читается кодом, а не текстом — по той же причине, что и `23505` выше: psycopg3 поднимает
#: `psycopg.errors.ForeignKeyViolation`, и сообщения с кодом состояния нет.
SQLSTATE_FOREIGN_KEY_VIOLATION: Final = "23503"


def read_login_notice_state(session: Session, *, user_id: UUID, dedup_key: str) -> LoginNoticeState:
    """Что уже известно о решениях по входу этой учётной записи: ключ встречался? когда уведомляли?

    Один вызов и **до** решения (`ADR-026` п. 4: сначала чтение, потом запись): состояние
    порога читается по той же таблице, в которую решение пишется, и второе чтение после вставки
    увидело бы собственную строку, чего порог учитывать не должен.

    «Пара встречалась» — это существование строки `notify` с тем же `dedup_key`: частичный
    уникальный индекс `ix_web_audit_outbox_dedup_key` покрывает ровно её, а `muted`-строки ключа
    не имеют намеренно (`ADR-028` п. 4). Иначе «промолчали вчера» выглядело бы как «ещё не
    уведомляли», и на каждое подавленное сочетание прилетало бы новое решение «уведомить».

    «Когда уведомляли в последний раз» — максимум `at` по основаниям входа этой учётной записи с
    вердиктом `notify`. Окно кулдауна считается по моменту **решения**, а не по моменту события
    входа: решение — то, что администратор уже видел.
    """
    seen = session.execute(
        select(WebAuditOutbox.id).where(WebAuditOutbox.dedup_key == dedup_key).limit(1)
    ).first()
    last_notify = session.execute(
        select(func.max(WebAuditOutbox.at)).where(
            WebAuditOutbox.ground == GROUND_LOGIN,
            WebAuditOutbox.user_id == user_id,
            WebAuditOutbox.outcome == "notify",
        )
    ).scalar_one_or_none()
    return LoginNoticeState(known_pair=seen is not None, last_notify_at=last_notify)


class NotifyAuditLinkError(RuntimeError):
    """Строка решения не добавлена: строки журнала с таким `audit_id` в этой транзакции нет.

    Отдельный класс нужен потому, что причина этого отказа — ошибка вызывающего порядка, а не
    состояние данных: решение обязано ссылаться на запись, которую этот же вызывающий уже добавил
    (`append_audit_record` возвращает `id`). Молча продолжить нельзя: событие §8.7 осталось бы
    без решения, а раздел администрирования показал бы «уведомлений нет» там, где порог не был
    спрошен.
    """


def append_notify_decision(
    session: Session,
    *,
    decision: NotifyDecision,
    audit_id: int,
    at: datetime,
) -> int | None:
    """Добавить строку решения порога в транзакцию вызывающего; вернуть `id` либо `None`.

    `at` передаётся, а не берётся `now()`: решение и событие снимаются одним моментом
    вызывающего, иначе разбор показал бы «решение раньше события» или «событие без решения»
    (`ADR-025` п. 2 о той же зависимости для журнала).

    `None` — нормальный ответ, а не отказ: ключ `dedup_key` уже занят другой строкой `notify`,
    то есть об этом основании уже уведомляли, и повторная рассылка отклонена индексом
    `ix_web_audit_outbox_dedup_key`. Отличить это от «строки нет вообще» вызывающий обязан
    именно по возврату, а не по `Result.rowcount`: ORM-путь даёт `-1` (замер среза `R2`,
    CI `45182752079`).

    Здесь, в отличие от журнала, есть `ON CONFLICT DO NOTHING`, и это не противоречие
    `ADR-025` п. 4, а его граница: на журнале такая конструкция молча теряет **событие**, и
    разбор показывает пропуск как подделку (`broken_link`); здесь она теряет **повторное
    уведомление**, то есть делает ровно то, что требует §8.7 («не спамить»). Различие держит
    контрактная проверка `tests/contract/test_audit_notify_contract.py`: `DO NOTHING` разрешён в
    функции решений и запрещён в `append_audit_record`.

    Цепочку `audit_id` держит внешний ключ с `ON DELETE RESTRICT` (ревизия `0006`): ссылка на
    несуществующую строку журнала — это `23503`, и она означает лишь одно: вызывающий нарушил
    порядок «сначала событие, потом решение» (`ADR-028` п. 9). Откат целиком обязателен и здесь:
    «событие зафиксировано, решения нет» — ровно то состояние, из-за которого рассылка теряет
    смысл.
    """
    values: dict[str, Any] = {
        "at": at,
        "ground": decision.ground,
        "outcome": decision.outcome,
        "reason": decision.reason,
        "audit_id": audit_id,
        "user_id": decision.user_id,
        "dedup_key": decision.dedup_key,
        "details": decision.details,
    }
    statement = (
        postgresql_insert(WebAuditOutbox)
        .values(**values)
        .on_conflict_do_nothing(
            index_elements=[WebAuditOutbox.dedup_key],
            index_where=WebAuditOutbox.dedup_key.isnot(None),
        )
        .returning(WebAuditOutbox.id)
    )
    try:
        row = session.execute(statement).scalar_one_or_none()
    except IntegrityError as error:
        session.rollback()
        if str(getattr(error.orig, "sqlstate", "")) == SQLSTATE_FOREIGN_KEY_VIOLATION:
            raise NotifyAuditLinkError(
                f"решение порога ссылается на отсутствующую строку журнала {audit_id}: "
                "сначала событие, потом решение (ADR-028 п. 9)"
            ) from error
        raise
    return None if row is None else int(row)


@dataclass(frozen=True)
class NotifyDecisionRow:
    """Строка журнала решений для раздела администрирования: колонки таблицы + логин повода.

    `login` — единственное значение, которое читает человек: `user_id` ему ни о чём не говорит, а
    адрес и устройство остаются в строке журнала (`ADR-028` п. 2). `dedup_key` в раздел не
    отдаётся: это материал стража повтора, а не сведения для администратора, и его показ был бы
    вторым выводом хэша сочетания адрес+устройство.
    """

    id: int
    at: datetime
    ground: str
    outcome: str
    reason: str
    audit_id: int
    user_id: UUID | None
    login: str | None


def read_notify_decisions(session: Session, *, limit: int) -> tuple[NotifyDecisionRow, ...]:
    """Последние решения порога — newest-first. Один путь чтения для раздела и для разбора.

    Порядок по `id` убывающий, а не по `at`: `id` выдаёт база в порядке вставки, и «последние»
    обязаны означать «последние записанные», иначе строки одного момента разошлись бы планом
    запроса (тот же порядок, что у чтения журнала по `id` ниже).

    `limit` обязателен: таблица append-only и растёт без участия приложения, поэтому «прочитать
    всё» на площадке через год означало бы выборку на порядок больше страницы. Порог отсекает по
    `id`, то есть по самым свежим строкам; индекс `ix_web_audit_outbox_at` здесь не участвует —
    он для разбора по интервалу времени.

    `User` подключается `outerjoin`-ом: у оснований общего уровня `user_id` нет вовсе, а у
    удалённой (архивной) учётной записи строка решения обязана оставаться читаемой — `RESTRICT`
    не даёт удалить учётную запись с живыми ссылками, но логин всё равно обязан появляться, когда
    учётная запись есть.
    """
    stmt = (
        select(
            WebAuditOutbox.id,
            WebAuditOutbox.at,
            WebAuditOutbox.ground,
            WebAuditOutbox.outcome,
            WebAuditOutbox.reason,
            WebAuditOutbox.audit_id,
            WebAuditOutbox.user_id,
            User.login,
        )
        .outerjoin(User, User.id == WebAuditOutbox.user_id)
        .order_by(WebAuditOutbox.id.desc())
        .limit(limit)
    )
    return tuple(
        NotifyDecisionRow(
            id=row.id,
            at=row.at,
            ground=row.ground,
            outcome=row.outcome,
            reason=row.reason,
            audit_id=row.audit_id,
            user_id=row.user_id,
            login=row.login,
        )
        for row in session.execute(stmt).all()
    )


# ─── чтение журнала: тот же разбор для ручной команды и для ежедневной проверки ──────────────


def read_audit_journal(
    session: Session,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    from_id: int | None = None,
    to_id: int | None = None,
) -> list[StoredRecord]:
    """Прочитать строки журнала колонками §4.1 в порядке `id`.

    Функция одна для `make audit-verify` (`scripts/audit_verify.py`) и для ежедневной
    `integrity-check` (`apps/jobs/integrity.py`) намеренно: ручная сверка копии дампа и
    автоматическая проверка обязаны видеть ровно один и тот же набор колонок и ровно тот же
    порядок. Расхождение здесь выглядит как «проверка сказала „цело“, а ручная команда —
    „нарушено“» на одних и тех же данных, и это худший из возможных исходов для инструмента
    поиска подделки (`ADR-025` п. 7).

    Порядок задаёт `id`, а не `at` (§4.1): моменты двух процессов могут прийти вразнобой, и
    переставить чтение по `at` — значит получить ложные `broken_link`.

    Границы выборки: `since`/`until` фильтруют по колонке `at` (`ix_audit_log_at`),
    `from_id`/`to_id` — по `id`. Интервал по `id` — то, чем разбирают копию дампа и путь
    восстановления, где прочитана часть журнала.

    Вызывающий обязан открыть **своё** соединение вне любой писавшей транзакции: ORM-сессия,
    правившая строку (или уже держащая её объект), отдаёт прежние атрибуты из identity map, и
    проверка «цепочка цела» на испорченной строке ничего не проверяла бы (замер первого красного
    прогона `CI 45163930282`, разбор — `docs/HANDOFF.md §1.61` п. 6).
    """
    stmt = select(
        AuditLogEntry.id,
        AuditLogEntry.at,
        AuditLogEntry.action,
        AuditLogEntry.actor,
        AuditLogEntry.entity,
        AuditLogEntry.entity_id,
        AuditLogEntry.details,
        AuditLogEntry.ip,
        AuditLogEntry.request_id,
        AuditLogEntry.hash_prev,
        AuditLogEntry.hash,
    ).order_by(AuditLogEntry.id)
    if since is not None:
        stmt = stmt.where(AuditLogEntry.at >= since)
    if until is not None:
        stmt = stmt.where(AuditLogEntry.at <= until)
    if from_id is not None:
        stmt = stmt.where(AuditLogEntry.id >= from_id)
    if to_id is not None:
        stmt = stmt.where(AuditLogEntry.id <= to_id)
    return [
        read_stored_record(
            row_id=row.id,
            at=row.at,
            action=row.action,
            actor=row.actor,
            entity=row.entity,
            entity_id=row.entity_id,
            details=row.details,
            ip=row.ip,
            request_id=row.request_id,
            hash_prev=row.hash_prev,
            stored_hash=row.hash,
        )
        for row in session.execute(stmt).all()
    ]
