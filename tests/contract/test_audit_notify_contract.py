"""Контракт порога уведомлений §8.7: где точка, что написано в схеме, чего написано быть не может.

Файл держит границы среза `T-116` (`ADR-028`) как проверки, а не как текст:

* **точки решения закрыты перечнем** — у повода ровно одно место в маршруте, где порог
  спрашивается, иначе число решений перестанет совпадать с числом событий (у входа две строки
  `session.login`: шаг пароля и шаг `full`);
* **запись решения исполняет общий слой**, и только там разрешён `ON CONFLICT DO NOTHING`: на
  журнале такой обход теряет событие (`ADR-025` п. 4), а на решениях он и есть требуемое
  поведение порога — одно «уведомить» на сочетание;
* **таблица решений не стала очередью доставки**: колонок `state`/`attempts`/`next_try_at`/
  `sent_at`/`error`/`channel`/`template` в ней нет, нет и второй цепочки хэшей. Иначе срез
  обещал бы канал, которого нет (`tgbot` не поднят, `T-714`), и создал бы второе состояние,
  расхождение которого пришлось бы обнаруживать;
* **домены совпадают в трёх местах**: модель, текст `CheckConstraint` в DDL и словарь причин
  доменного слоя;
* **раздел администрирования не обещает доставку и не выводит материал стража повтора**;
* **остаток зафиксирован явно**: три основания §8.7 без производителя перечислены с указанием
  задачи или вехи, а не удалены «как неиспользуемые»;
* **порог не переезжает в конфигурацию площадки**: число держится константой кода, иначе одна и
  та же сборка вела бы себя по-разному на стенде и на площадке, а `ADR-028` п. 6 описывает
  правило, а не настройку;
* **материал ключа не является значением учётных данных**, а адрес и устройство нормализуются той
  же функцией, что и колонки журнала и сеанса (`ADR-009`).

Живое поведение (частичный индекс, коды отказа, права роли приложения) — `tests/integration/
test_audit_notify_db.py` и шаг «права роли приложения» в `tests/integration/test_postgres_roles.py`;
пороги и ключи как функция — `tests/unit/test_audit_notify.py`; путь «маршрут → решение → строка →
страница» — `tests/integration/test_audit_notify_web.py`.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Final

from sqlalchemy import Index

from apps.web.routes.notifications import (
    ADMIN_NOTIFICATIONS_PATH,
    CHANNEL_NOTE,
    EMPTY_NOTE,
    NOTIFY_PAGE_ROWS,
    OUTCOME_LABELS,
)
from packages.identity.notify import (
    AUDIT_NOTIFY_LOGIN_COOLDOWN_S,
    AUDIT_NOTIFY_REASONS,
    AUTH_STEP_FULL,
    GROUND_BACKUP_CODE_SPENT,
    GROUND_LOGIN,
    grounds_without_producer,
)
from packages.storage.base import APPEND_ONLY_TABLES, Base
from packages.storage.models import (
    AUDIT_NOTIFY_GROUNDS,
    AUDIT_NOTIFY_OUTCOMES,
    SESSION_AUTH_STEPS,
)

_ROOT: Final = pathlib.Path(__file__).resolve().parents[2]
_ROUTES: Final = _ROOT / "apps" / "web" / "routes"
_MODELS: Final = _ROOT / "packages" / "storage" / "models.py"
_STORE: Final = _ROOT / "packages" / "storage" / "audit_store.py"
_WEB_STORE: Final = _ROOT / "apps" / "web" / "store.py"
_NOTIFY: Final = _ROOT / "packages" / "identity" / "notify.py"
_CONFIG: Final = _ROOT / "packages" / "common" / "config.py"
_ROUTE: Final = _ROUTES / "notifications.py"
_TEMPLATE: Final = _ROOT / "apps" / "web" / "templates" / "notifications.html"
_ADR: Final = _ROOT / "docs" / "adr" / "ADR-028-audit-notification-outbox.md"

TABLE: Final = "web_audit_outbox"

#: Колонок очереди доставки в таблице решений быть не может. `§4.8 notification_outbox` — таблица
#: вехи Telegram (`T-408`), здесь её нет намеренно (`ADR-028` п. 1, п. 2 и п. 4).
_DELIVERY_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "state",
        "attempts",
        "next_try_at",
        "sent_at",
        "delivered_at",
        "failed_at",
        "error",
        "channel",
        "channels",
        "template",
        "payload",
        "recipient",
    }
)

#: Вторая цепочка хэшей поверх того же множества событий не заводится (`ADR-025` п. 3).
_CHAIN_COLUMNS: Final[frozenset[str]] = frozenset({"hash", "hash_prev"})

#: Полный состав колонок. Сверяется множеством, а не «по списку ниже»: добавленная колонка
#: состояния — это ровно тот путь, которым срез тихо превращается в очередь доставки, и он обязан
#: покраснеть здесь, а не на ревью.
_OUTBOX_COLUMNS: Final[frozenset[str]] = frozenset(
    {"id", "at", "ground", "outcome", "reason", "audit_id", "user_id", "dedup_key", "details"}
)

#: Точки решения по входам в маршрутах. Числа — часть условия «одна точка на событие»: у входа
#: две строки `session.login` (шаг `'password'` и шаг `'full'`), и порога спрашивается только
#: вторая. `notifications.py` — ноль: раздел только читает (`ADR-028` п. 8).
NOTICE_LOGIN_CALLS: Final[dict[str, int]] = {
    "admin_users.py": 0,
    "invitations.py": 0,
    "login.py": 1,
    "notifications.py": 0,
    "profile.py": 0,
    "sessions.py": 0,
    "totp.py": 2,
}

#: Точка повода «расход резервного кода»: один вход расходом кода (§8.2, `ADR-016` п. 9).
NOTICE_BACKUP_CALLS: Final[dict[str, int]] = {
    "admin_users.py": 0,
    "invitations.py": 0,
    "login.py": 0,
    "notifications.py": 0,
    "profile.py": 0,
    "sessions.py": 0,
    "totp.py": 1,
}

#: Чтение решений маршрутом раздела — ровно одна точка, и она в разделе. Вторая точка чтения
#: означала бы два пути чтения («раздел сказал „пусто“, а разбор нашёл строки» — тот же порядок,
#: что у `ADR-025` п. 7 для журнала).
NOTICE_READ_CALLS: Final[dict[str, int]] = {
    "admin_users.py": 0,
    "invitations.py": 0,
    "login.py": 0,
    "notifications.py": 1,
    "profile.py": 0,
    "sessions.py": 0,
    "totp.py": 0,
}


def _route_modules() -> list[pathlib.Path]:
    return [path for path in sorted(_ROUTES.glob("*.py")) if path.name != "__init__.py"]


def _calls(path: pathlib.Path, attribute: str) -> int:
    """Число вызовов `.<attribute>(...)` по AST, а не по тексту.

    Докстринг или комментарий со словом `append_login_notice` не должен создавать ложный вызов:
    иначе проверка начала бы ловить собственное обоснование (тот же приём, что у `_audit_calls`
    в `tests/contract/test_web_security_contract.py`).
    """
    дерево = ast.parse(path.read_text(encoding="utf-8"))
    return sum(
        1
        for узел in ast.walk(дерево)
        if isinstance(узел, ast.Call)
        and isinstance(узел.func, ast.Attribute)
        and узел.func.attr == attribute
    )


def _strip(node: ast.AST, source: str) -> str:
    """Исходник узла без его собственного докстринга."""
    отрезок = ast.get_source_segment(source, node)
    assert отрезок is not None, f"не удалось выделить исходник {type(node).__name__}"
    тело = getattr(node, "body", None)
    if тело and isinstance(тело[0], ast.Expr):
        докстринг = ast.get_source_segment(source, тело[0])
        if докстринг is not None:
            return отрезок.replace(докстринг, "", 1)
    return отрезок


def _function_source(path: pathlib.Path, *, name: str) -> str:
    """Исходник одной модульной функции без докстринга.

    Проверка обязана касаться кода, а не обоснования: рядом с `append_notify_decision` стоит
    разбор того, почему `ON CONFLICT` разрешён здесь и запрещён на журнале, и текстовая проверка
    по всему файлу ловила бы объяснение вместо нарушения.
    """
    source = path.read_text(encoding="utf-8")
    for узел in ast.walk(ast.parse(source)):
        if isinstance(узел, ast.FunctionDef | ast.AsyncFunctionDef) and узел.name == name:
            return _strip(узел, source)
    raise AssertionError(f"в {path.name} нет функции {name}")


def _method_source(path: pathlib.Path, *, klass: str, name: str) -> str:
    """Исходник одного метода одного класса: соседние методы и комментарии к ним не входят."""
    source = path.read_text(encoding="utf-8")
    for узел in ast.walk(ast.parse(source)):
        if not isinstance(узел, ast.ClassDef) or узел.name != klass:
            continue
        for item in узел.body:
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name == name:
                return _strip(item, source)
        break
    raise AssertionError(f"в {path.name} нет метода {klass}.{name}")


def _class_source(path: pathlib.Path, *, name: str) -> str:
    """Исходник одного класса целиком (проверка по тексту DDL, а не по всему файлу)."""
    source = path.read_text(encoding="utf-8")
    for узел in ast.walk(ast.parse(source)):
        if isinstance(узел, ast.ClassDef) and узел.name == name:
            отрезок = ast.get_source_segment(source, узел)
            assert отрезок is not None, f"не удалось выделить класс {name}"
            return отрезок
    raise AssertionError(f"в {path.name} нет класса {name}")


def _source_without_docstrings(path: pathlib.Path) -> str:
    """Исходник файла без докстрингов: комментарии остаются, обоснования убираются.

    Нужно ровно для проверки «в разделе нет слов об отправке»: обоснование в докстринге
    `notifications.py` называет запрещённые надписи («отправлено», «доставлено») именно затем,
    чтобы объяснить, почему их быть не может. Текстовая проверка по всему файлу ловила бы
    собственное обоснование как нарушение.
    """
    source = path.read_text(encoding="utf-8")
    дерево = ast.parse(source)
    вырезание: list[str] = []
    for узел in ast.walk(дерево):
        if not isinstance(узел, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        тело = getattr(узел, "body", None)
        if not тело or not isinstance(тело[0], ast.Expr):
            continue
        значение = тело[0].value
        if not isinstance(значение, ast.Constant) or not isinstance(значение.value, str):
            continue
        отрезок = ast.get_source_segment(source, тело[0])
        if отрезок is not None:
            вырезание.append(отрезок)
    очищенный = source
    for отрезок in вырезание:
        очищенный = очищенный.replace(отрезок, "", 1)
    return очищенный


# ─── точки: где порог спрашивается и где он читается ───────────────────────────────────────────


def test_точки_решений_порога_в_маршрутах_закрыты_перечнем() -> None:
    """Число точек решения по каждому маршруту совпадает с перечнем.

    Опасность асимметрична и по одному ответу не видна: удалённая точка — это повод §8.7 без
    носителя (пустая таблица при работающем входе), а двойная точка — удвоенный счётчик поводов
    (у входа строки `session.login` с шагом `'password'` и с шагом `'full'`; вторую половину
    отсекает доменная граница `AUTH_STEP_FULL`, а не молчание маршрута). Перечень меняется только
    вместе с правкой `ADR-028`, поэтому новая точка обязана покраснеть здесь.
    """
    modules = _route_modules()
    login_calls = {path.name: _calls(path, "append_login_notice") for path in modules}
    backup_calls = {path.name: _calls(path, "append_backup_code_notice") for path in modules}
    read_calls = {path.name: _calls(path, "notify_decisions") for path in modules}

    assert login_calls == NOTICE_LOGIN_CALLS, (
        f"точки `append_login_notice` разошлись с перечнем: ожидалось {NOTICE_LOGIN_CALLS}, "
        f"получено {login_calls}"
    )
    assert backup_calls == NOTICE_BACKUP_CALLS, (
        f"точки `append_backup_code_notice` разошлись с перечнем: "
        f"ожидалось {NOTICE_BACKUP_CALLS}, получено {backup_calls}"
    )
    assert (
        read_calls == NOTICE_READ_CALLS
    ), f"чтение решений разошлось с перечнем: ожидалось {NOTICE_READ_CALLS}, получено {read_calls}"


def test_раздел_не_производит_решений_а_только_читает() -> None:
    """У адреса раздела нет мутации: просмотр не может «повторно уведомить».

    Раздел без права отправлять — не лень, а условие (`ADR-028` п. 8): страница, которая умеет
    отправлять, превратила бы просмотр в действие и обошла бы лимиты §10.1, а CSRF-токен в
    мутирующих формах был бы обязан появиться (`ADR-008`).
    """
    source = _ROUTE.read_text(encoding="utf-8")
    assert (
        "@router.get(ADMIN_NOTIFICATIONS_PATH" in source
    ), "у раздела нет читающего маршрута: журнал решений было бы нечем перечитать"
    assert "@router.post" not in source, (
        "у раздела появилась мутация через POST: просмотр страницы не имеет права производить "
        "действия, а мутирующий адрес потянул бы CSRF-политику (`ADR-008`)"
    )
    assert (
        "@router.put" not in source
    ), "у раздела появилась мутация через PUT: раздел остаётся читающим (`ADR-028` п. 8)"
    assert ADMIN_NOTIFICATIONS_PATH == "/admin/notifications", (
        "адрес раздела переехал: матрица допуска `tests/integration/test_web_role_matrix.py` "
        "проверяет этот адрес по литералу"
    )
    assert NOTIFY_PAGE_ROWS > 0, "граница страницы обязана быть положительным числом"


# ─── как записывается решение: общий слой и разрешённый обход ─────────────────────────────────


def test_запись_решения_исполняет_общий_слой_и_только_там_разрешён_on_conflict() -> None:
    """Писатель решений — `packages/storage/audit_store.py`; `ON CONFLICT` — только в нём.

    Разделение принципиально: на `audit_log` обход `DO NOTHING` теряет событие, и разбор показал
    бы его как `broken_link` — то есть как подделку (`ADR-025` п. 4); на `web_audit_outbox` тот же
    обход — требуемое поведение порога (одно «уведомить» на сочетание, `ADR-028` п. 5). Поэтому
    проверка держит обе половины: наличие в одной функции и отсутствие в другой.

    Обязательные признаки записи решения: обход привязан к частичному индексу (и по колонкам, и по
    предикату — иначе `ON CONFLICT` не нашёл бы индекс и упал бы на площадке), и строка читается
    через `RETURNING` (по нему писатель отличает «вставил» от «проглотил повтор»).
    """
    notify_writer = _function_source(_STORE, name="append_notify_decision")
    assert (
        "on_conflict_do_nothing" in notify_writer
    ), "писатель решений потерял обход повтора: повторный запрос породил бы `23505` и упавший вход"
    assert "index_elements" in notify_writer, (
        "`ON CONFLICT` не привязан к колонкам частичного индекса: на живой базе обход не нашёл бы "
        "индекса и дал бы отказ вместо решения"
    )
    assert "index_where" in notify_writer, (
        "`ON CONFLICT` не привязан к предикату `ix_web_audit_outbox_dedup_key`: на живой базе "
        "обход не нашёл бы индекса и дал бы отказ вместо решения"
    )
    assert "returning" in notify_writer, (
        "нет `RETURNING id`: писатель не отличил бы вставку от проглоченного повтора, и проверка "
        "«повторного уведомления нет» осталась бы недоказуемой"
    )

    journal_writer = _function_source(_STORE, name="append_audit_record")
    assert "on_conflict" not in journal_writer, (
        "`ON CONFLICT` появился в протоколе добавления журнала: потерянная строка журнала — дыра "
        "в доказательстве, а не «дедупликация» (`ADR-025` п. 4)"
    )
    assert (
        "lock_audit_chain" in journal_writer
    ), "протокол журнала перестал брать блокировку хвоста перед вставкой"
    assert "pg_advisory_xact_lock" in _function_source(_STORE, name="lock_audit_chain"), (
        "блокировка хвоста перестала быть блокировкой транзакции: об неё ломается вся цепочка "
        "(`ADR-025` п. 6)"
    )


def test_состояние_порога_читается_до_решения_и_до_вставки() -> None:
    """Порядок «ключ → состояние → решение → запись» соблюдён в слое входа.

    Второе чтение после вставки увидело бы собственную строку решения, и окно порога отсчитывалось
    бы от самого себя: каждое следующее событие молчало бы навсегда (о том же порядке — `ADR-026`
    п. 4 для ежедневной проверки).
    """
    метод = _method_source(_WEB_STORE, klass="SqlStore", name="append_login_notice")
    position_state = метод.find("read_login_notice_state")
    position_decide = метод.find("decide_login_notice")
    position_write = метод.find("append_notify_decision")
    assert position_state > 0, "метод не читает состояние порога"
    assert position_decide > 0, "метод не вызывает доменное решение"
    assert position_write > 0, "метод не пишет решение"
    assert (
        position_state < position_decide
    ), "чтение состояния идёт после решения: решение опиралось бы на уже записанную строку"
    assert (
        position_decide < position_write
    ), "решение принимается после вставки: окно порога отсчитывалось бы от самого себя"
    assert AUTH_STEP_FULL in SESSION_AUTH_STEPS, (
        "граница шага выхода за пределами закрытого домена шагов: уведомлений о входах не было бы "
        "вовсе, а пустая таблица выглядела бы корректной"
    )


# ─── что написано в схеме: таблица не является очередью доставки ──────────────────────────────


def test_таблица_решений_не_содержит_колонок_очереди_доставки_и_второй_цепочки() -> None:
    """Состав колонок совпадает с перечнем; колонок доставки и хэшей нет.

    Проверка по метаданным модели, а не по тексту: `Base.metadata` — то, из чего ревизия Alembic
    получает DDL, поэтому расхождение с файлом `0006_audit_notify_outbox.py` ловит
    `tests/contract/test_identity_schema.py`, а здесь держится смысл: состояние здесь — **решение
    порога**, а не прогресс доставки (`ADR-028` п. 4).

    Транспорт, когда появится, дописывает собственные строки (§4.9 `telegram_messages_log`) либо
    оформляет право `UPDATE` новым ADR и новой ревизией. Третьего пути база не оставляет: права на
    `UPDATE` у приложения отозваны, а таблица перечислена в `APPEND_ONLY_TABLES`.
    """
    table = Base.metadata.tables[TABLE]
    columns = frozenset(table.columns.keys())
    assert columns == _OUTBOX_COLUMNS, (
        f"состав колонок {TABLE} разошёлся с перечнем: лишние "
        f"{sorted(columns - _OUTBOX_COLUMNS)}, отсутствующие {sorted(_OUTBOX_COLUMNS - columns)}"
    )
    delivery = sorted(columns & _DELIVERY_COLUMNS)
    assert not delivery, (
        f"в {TABLE} появились колонки очереди доставки {delivery}: срез обещает канал, которого "
        "нет (`tgbot` не поднят, `T-714`), и создаёт второе состояние, расхождение которого "
        "пришлось бы обнаруживать"
    )
    chain = sorted(columns & _CHAIN_COLUMNS)
    assert not chain, (
        f"в {TABLE} появились колонки цепочки {chain}: вторая цепочка поверх тех же событий "
        "плодит расхождение вместо доказательств (`ADR-025` п. 3)"
    )
    assert TABLE in APPEND_ONLY_TABLES, (
        f"{TABLE} выпала из реестра append-only: `deploy/postgres/roles.sql` остаётся без "
        "REVOKE-строки, и приложение получает право стирать строки `muted`"
    )


def test_ссылки_и_индексы_соответствуют_решению_о_хранении() -> None:
    """`RESTRICT` на обе ссылки, страж повтора — частичный уникальный индекс.

    `RESTRICT` выбран вместо `CASCADE` намеренно (`ADR-028` п. 7): удаление строки журнала не
    должно оставлять «висячее» решение и не должно молча уносить решения вместе с событием —
    порядок уборки обязан быть явным (сначала решения, потом журнал), иначе разбор инцидента
    теряет половину доказательств.

    Частичность индекса — условие, а не оптимизация: у `muted`-строк ключа нет намеренно, и без
    предиката первая же строка молчания приклеила бы молчание к основанию навсегда.
    """
    table = Base.metadata.tables[TABLE]
    foreign = {
        constraint.name: (constraint.referred_table.name, constraint.ondelete)
        for constraint in table.foreign_key_constraints
    }
    assert foreign == {
        "fk_web_audit_outbox_audit_id_audit_log": ("audit_log", "RESTRICT"),
        "fk_web_audit_outbox_user_id_users": ("users", "RESTRICT"),
    }, f"ссылки {TABLE} разошлись с решением о хранении: {foreign}"

    guards: dict[str, Index] = {str(index.name): index for index in table.indexes}
    expected = {
        "ix_web_audit_outbox_dedup_key",
        "ix_web_audit_outbox_at",
        "ix_web_audit_outbox_user_ground",
    }
    assert set(guards) == expected, f"набор индексов {TABLE} разошёлся: {sorted(guards)}"
    dedup = guards["ix_web_audit_outbox_dedup_key"]
    assert dedup.unique, "индекс стража повтора перестал быть уникальным"
    assert [column.name for column in dedup.columns] == [
        "dedup_key"
    ], "страж повтора перестал считать сочетание: ключ перестал быть уникальным по одному полю"
    predicate = str(dedup.dialect_kwargs.get("postgresql_where", ""))
    assert "dedup_key IS NOT NULL" in predicate, (
        f"страж повтора потерял предикат ({predicate!r}): `muted`-строки попали бы в уникальный "
        "индекс, и молчание стало бы однократным на всё время"
    )


# ─── имена: модель, текст DDL и словарь причин ────────────────────────────────────────────────


def test_домены_имён_совпадают_с_кодом_приложения_и_текстом_ddl() -> None:
    """Основания и вердикты замкнуты в трёх местах одновременно.

    Модель (`AUDIT_NOTIFY_GROUNDS`/`AUDIT_NOTIFY_OUTCOMES`), текст `CheckConstraint` и константы
    доменного слоя обязаны совпадать: если домен «поедет» в одном месте, половина проверок
    останется зелёной, а требование §8.7 сузится до написанного (`ADR-028` п. 3).

    Словарь причин базой не перечислен (база держит только формат), поэтому его замкнутость
    проверяется здесь: иначе «причина появилась по ходу» осталась бы необнаруженной.
    """
    assert {GROUND_LOGIN, GROUND_BACKUP_CODE_SPENT} <= set(AUDIT_NOTIFY_GROUNDS)
    assert set(AUDIT_NOTIFY_OUTCOMES) == set(OUTCOME_LABELS), (
        f"подписи вердиктов разошлись с доменом: {sorted(OUTCOME_LABELS)} против "
        f"{sorted(AUDIT_NOTIFY_OUTCOMES)}"
    )
    ddl = _class_source(_MODELS, name="WebAuditOutbox")
    for ground in AUDIT_NOTIFY_GROUNDS:
        assert f"'{ground}'" in ddl, f"основание {ground} не перечислено в CheckConstraint DDL"
    for outcome in AUDIT_NOTIFY_OUTCOMES:
        assert f"'{outcome}'" in ddl, f"вердикт {outcome} не перечислен в CheckConstraint DDL"
    assert OUTCOME_LABELS == {
        "notify": "уведомить",
        "muted": "промолчать",
    }, "подписи вердиктов переписаны: страница раздела читалась бы иначе"
    assert {
        "new_pair",
        "login_cooldown",
        "known_pair",
        "backup_code_spent",
    } == set(AUDIT_NOTIFY_REASONS), "словарь причин перестал быть закрытым перечнем"


def test_остаток_зафиксирован_явно_основания_без_производителя_перечислены() -> None:
    """Три основания §8.7 стоят в домене без производителя — с указанием задачи или вехи.

    Проверка выводит «производитель есть» из фактического числа точек в маршрутах, а не из
    перечня: если кто-то уберёт точку из `login.py`, основание автоматически попадёт в «остаток»,
    и контракт покраснеет, потому что список «почему нет» этого не ожидает. Обратная сторона:
    удалить из домена `risk.limits_changed` / `token.revoked` / `risk.kill_switch_changed` нельзя,
    не сузив требование §8.7, — и база, и этот контракт на это не дадут.
    """
    produced: set[str] = set()
    modules = _route_modules()
    if any(_calls(path, "append_login_notice") for path in modules):
        produced.add(GROUND_LOGIN)
    if any(_calls(path, "append_backup_code_notice") for path in modules):
        produced.add(GROUND_BACKUP_CODE_SPENT)

    pending = grounds_without_producer()
    assert produced == {
        GROUND_LOGIN,
        GROUND_BACKUP_CODE_SPENT,
    }, f"набор оснований с производителем разошёлся с кодом маршрутов: {sorted(produced)}"
    assert (
        set(pending) == set(AUDIT_NOTIFY_GROUNDS) - produced
    ), f"перечень оснований без производителя разошёлся с доменом и кодом: {sorted(pending)}"
    for ground, причина in pending.items():
        assert "`" in причина or "M2" in причина or "M3" in причина, (
            f"причина отсутствия производителя у {ground} не называет ни задачи, ни вехи: остаток "
            "обязан быть проверяемым (`ADR-028` п. 3)"
        )


# ─── чего написано быть не может: страница и обещания ─────────────────────────────────────────


def test_раздел_не_обещает_доставку_и_не_выводит_материал_стража() -> None:
    """Ни слова об отправке, ни `details`, ни `dedup_key` в разметке раздела.

    Надпись «отправлено»/«доставлено» была бы неправдой: канала нет (`ADR-028` п. 8), и по такой
    надписи администратор судил бы, что он уже уведомлён. `details` — произвольный `jsonb`,
    вторая поверхность утечки после журнала (§8.4), а `dedup_key` — материал стража повторной
    рассылки, а не сведения для администратора; в `details` лежат отпечатки адреса и устройства, и
    вывод их на страницу означал бы второе носительство этих значений (`ADR-025` п. 2, публичный
    репозиторий по `ADR-019`).
    """
    route = _source_without_docstrings(_ROUTE)
    template = _TEMPLATE.read_text(encoding="utf-8")
    разметка = route + template

    for запрещённое in (
        "отправлено",
        "доставлено",
        "уведомление отправлено",
        "сообщение отправлено",
        "sent",
        "delivered",
    ):
        assert запрещённое not in разметка, (
            f"раздел упоминает доставку ({запрещённое!r}): канала доставки нет, и страница не "
            "имеет права создавать ощущение, что уведомление уже ушло"
        )
    assert "dedup_key" not in template, "ключ деидентификации выводится на странице раздела"
    assert "details" not in template, "`details` выводятся на странице раздела"
    assert "{{ row.ground }}" in template, "страница перестала показывать основание"
    assert "{{ row.outcome }}" in template, "страница перестала показывать вердикт"
    assert (
        "Канал доставки не заведён" in CHANNEL_NOTE
    ), "постоянная шапка перестала говорить правду о канале (`ADR-028` п. 8)"
    assert "расхода резервного кода" in EMPTY_NOTE, (
        "пустота раздела объяснена не теми поводами: перечислять основания без производителя "
        "значит обещать то, чего не завели"
    )
    assert "сочетание" in EMPTY_NOTE, (
        "пустота раздела объяснена не теми поводами: порог по сочетанию адрес/устройство — второй "
        "из двух заведённых поводов"
    )


# ─── материал ключа и значение порога ─────────────────────────────────────────────────────────


def test_ключ_не_строится_из_значений_учётных_данных() -> None:
    """Ключ кода — идентификатор строки, а не значение и не хэш значения.

    Резервный код — проверочное значение входа: его хэш хранится в `backup_codes.code_hash`
    (`ADR-016` п. 3–4), и попади он в ключ — журнал решений стал бы вторым носителем материала, по
    которому можно угадывать коды (репозиторий публичный, `ADR-019`).

    Отдельно держится, что решение проверяет `details` общей политикой журнала, а не своим списком:
    два списка запрещённых ключей неизбежно разошлись бы, и «значений учётных данных в деталях нет»
    перестало бы выполняться в одном из мест.
    """
    key_source = _function_source(_NOTIFY, name="backup_code_dedup_key")
    assert (
        "backup_code_id" in key_source
    ), "ключ расхода кода перестал опираться на идентификатор строки `backup_codes.id`"
    for forbidden in ("code_hash", "hash_backup_code", "new_backup_codes"):
        assert forbidden not in key_source, (
            f"ключ расхода кода опирается на {forbidden}: значение или хэш проверочного значения "
            "не должны попадать в журнал решений"
        )

    pair_source = _function_source(_NOTIFY, name="login_pair")
    assert "normalize_address_material" in pair_source, (
        "ключ сочетания перестал считать адрес той же нормализацией, что и колонки журнала и "
        "сеанса (`ADR-009`): одно соединение дало бы два ключа"
    )
    assert "normalize_device" in pair_source, (
        "ключ сочетания перестал считать устройство той же нормализацией, что и колонка журнала: "
        "одно соединение дало бы два ключа"
    )
    for forbidden in ("code_hash", "password", "secret"):
        assert forbidden not in pair_source, (
            f"в материал ключа сочетания попал {forbidden}: журнал решений не имеет права "
            "становиться вторым носителем значений учётных данных"
        )

    init = _method_source(_NOTIFY, klass="NotifyDecision", name="__post_init__")
    assert "validate_details" in init, (
        "политика `details` не общая с журналом: второй список запрещённых ключей разошёлся бы с "
        "`_DETAIL_KEY_DENYLIST` (`ADR-025` п. 2)"
    )


def test_порог_держится_константой_кода_а_не_настройкой_площадки() -> None:
    """Значение окна не является полем настроек и не читается из окружения.

    Порог, который можно поменять конфигурацией деплоя, перестаёт быть частью контракта: та же
    сборка вела бы себя по-разному на площадке и на стенде, а разбор по таблице решений
    объяснялся бы числом, которого никто не зафиксировал. `ADR-028` п. 6 описывает правило и
    называет число — значит оно живёт в коде, а изменение требует правки оформления.
    """
    config = _CONFIG.read_text(encoding="utf-8")
    for имя in ("cooldown", "notify", "notification", "outbox"):
        assert имя not in config.lower(), (
            f"в `packages/common/config.py` появилось {имя!r}: порог §8.7 не должен становиться "
            "переменной площадки"
        )
    assert AUDIT_NOTIFY_LOGIN_COOLDOWN_S == 300, (
        "окно порога изменено без правки `ADR-028` п. 6: число совпадает с окном перебора §8.2 "
        "сознательно, и менять его нужно вместе с оформлением"
    )
    source = _NOTIFY.read_text(encoding="utf-8")
    assert (
        "AUDIT_NOTIFY_LOGIN_COOLDOWN_S: Final = 300" in source
    ), "значение порога перестало быть константой `Final`: его можно переопределить по месту"


def test_adr_028_держит_те_же_имена_и_правила_что_код() -> None:
    """Оформление сверяется с кодом: имена оснований, вердиктов и форма ключа.

    Смысл проверки — не в «документация есть», а в том, чтобы код и оформление не разъехались: по
    этому ADR следующий срез (канал доставки) обязан понять, что править `web_audit_outbox`
    состоянием нельзя, а ключ сочетания — договорный материал: его изменение ломает уже
    записанные строки.
    """
    adr = _ADR.read_text(encoding="utf-8")
    for ground in AUDIT_NOTIFY_GROUNDS:
        assert ground in adr, f"основание {ground} не названо в `ADR-028`"
    for outcome in AUDIT_NOTIFY_OUTCOMES:
        assert outcome in adr, f"вердикт {outcome} не назван в `ADR-028`"
    for префикс in ("session.login:", "backup_code.spent:"):
        assert префикс in adr, f"форма ключа {префикс}… не зафиксирована в `ADR-028`"
    assert "ix_web_audit_outbox_dedup_key" in adr, "страж повтора не назван в `ADR-028`"
    assert (
        "APPEND_ONLY_TABLES" in adr
    ), "обязательный шаг прав после ревизии с новой журнальной таблицей не оформлен"
