#!/usr/bin/env python3
"""Завод первой учётной записи на площадке (`T-112`, `ADR-023`, `ADR-020` п. 5).

Зачем этот файл существует. Приглашение выпускает только администратор с полным сеансом
(`apps/web/routes/invitations.py`, `ADR-021`), а состояния `users` переводит раздел
администрирования (§1.2). Пока в таблице 0 строк, закрытый допуск не может создать первого
администратора: ни форма приёма приглашения, ни очередь одобрения недоступны без того, кого
ещё нет. Отсюда единственный легальный путь — операторская команда, которая исполняет ровно
тот же доменный порядок, что и церемония приглашения.

Почему обёртка над доменом, а не `INSERT` (решение заказчика 2026-11-22, ask
`3f998543-38fd-479f-86d2-e77ab16d014f`). Правило пароля §8.1 (длина ≥ 12, словарь слабых,
совпадение с логином и доменом) и параметры Argon2id (`m=64 MiB, t=3, p=4`) живут в
`packages/identity/passwords.py`, таблица переходов — в `STATE_TRANSITIONS`
(`packages/identity/users.py`), отметки одобрения — в `approve_account`. Ручная запись в таблицу
означала бы вторую реализацию тех же правил, и она разошлась бы с доменом в первый момент,
когда домен поправят: CHECK `left(password_hash, 10) = '$argon2id$'` отловил бы только грубый
случай, а неверную длину или пароль-логин — нет. Обёртка не добавляет ни одного правила: она
только вызывает домен в нужном порядке.

Что делает по шагам (шаг в шаг с §1.2 и `ADR-020` п. 5):

1. читает адрес базы из конфигурации приложения (`TBOT_DB_URL` или файл секрета `db_url` в
   `secrets_dir`, `packages/common/config.py`) — из аргументов командной строки адрес не
   читается ни при каких условиях;
2. считает учётные записи с ролью `admin` в состоянии, кроме `archived`: если такая есть,
   отказывает (защитный гейт — ниже);
3. без флага `--yes` останавливается на черновом прогоне: показывает отметку схемы, счётчик и
   план, ничего не пишет;
4. читает логин и e-mail со стандартного ввода — значения не попадают в `argv`, `ps`, историю
   оболочки и в текст вывода;
5. заводит запись: `new_user` → `enqueue_for_approval` → `approve_account` (собственный `id` в
   `approved_by`) → ровно один `commit()`.

Роль фиксирована — `admin`, флага выбора нет. Иначе закрытый допуск не смог бы выпустить первое
приглашение (`require_admin_role` на разделе администрирования, `ADR-017`), а `operator` и
`viewer` приходят по приглашению и проходят очередь одобрения; заводить их «в обход» некому —
администратора ещё нет.

Защитный гейт. Самособранное одобрение возможно ровно один раз: у первой учётной записи больше
некого ставить в `approved_by`. Если живой `admin` в базе уже есть, вторая запись, заведённая
этим скриптом, получила бы доступ без чьего-либо решения и без журнала — ровно то, что запрещают
§1.2 и `ADR-020` п. 5. Поэтому при любом живом администраторе (`active`, `suspended`,
`awaiting_approval`, `invited`) скрипт отказывает, а дальше работают только раздел
администрирования и церемония приглашения. `archived` в счёт не идёт: архивная строка права не
даёт (§4.1, «удаление — только архивированием»).

Пароль генерирует скрипт и показывает его ровно один раз (то же решение заказчика). Вывод —
единственный носитель значения: в базе лежит Argon2id-хэш, в файл, в журнал приложения, в
аргументы и в переменные окружения значение не пишется. Остаточные риски приняты осознанно и
описаны в `ADR-023` (прокрутка терминала, журналирование ssh-сессии, отсутствие принудительной
смены пароля при первом входе); компенсирующий контроль — обязательная привязка 2FA на первом
входе: консоль требует `auth_step='full'` (`apps/web/security/sessions.py`,
`require_full_session`), поэтому заведённая запись без второго фактора в консоль не попадёт.

Занятые логин и e-mail отвечают одинаково. `uq_users_login` (на `citext`) отклоняет повтор имени
при записи, а uniqueness почты схема не держит (§4.1), поэтому её проверяет скрипт. Оба отказа
печатают одно и то же предложение и выходят под одним и тем же кодом: по ответу нельзя узнать,
какое именно значение занято, и в тексте нет имён ограничений (они описывают схему, а не
положение дел оператора). Транзакция откатывается целиком, и в сообщении нет ни SQL, ни связанных
значений — то есть ни сгенерированного пароля, который был бы параметром `INSERT`.

Коды выхода (их сверяют проверки `tests/integration/test_first_account.py`):

* `0` — учётная запись заведена, пароль показан один раз;
* `1` — непредвиденная ошибка или противоречие генератора политике (текст вычищен);
* `2` — ошибка аргументов или формата введённого значения (argparse использует тот же код);
* `3` — черновой прогон: флага `--yes` не было, запись не выполнялась;
* `4` — отказ защитного гейта: живой администратор в базе уже есть;
* `5` — логин или e-mail уже заняты (откат, ничего не создано);
* `6` — конфигурация, база или схема недоступны (нет адреса, база не отвечает, таблицы нет).

Зависимости приложения (`sqlalchemy`, `psycopg`, `argon2-cffi`) обязательны: без них домен не
исполняется. На хосте площадки их нет, поэтому форма запуска — внутри образа `web`
(`docs/runbook/stand-deploy.md §12`).
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from collections.abc import Callable
from datetime import datetime
from typing import IO, Final

from _bootstrap import ensure_repo_root_on_path
from sqlalchemy import column, create_engine, func, select, table
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from packages.common.clock import utc_now
from packages.common.config import ConfigError, load_settings
from packages.common.db import sqlalchemy_url
from packages.common.ids import uuid7
from packages.identity.authorization import ROLE_ADMIN
from packages.identity.invitations import InvitationTargetError, ensure_email_syntax
from packages.identity.passwords import PasswordPolicyError, check_password_policy
from packages.identity.users import (
    LoginFormatError,
    approve_account,
    enqueue_for_approval,
    ensure_login_syntax,
    new_user,
)
from packages.storage.models import User

ROOT = ensure_repo_root_on_path()

# ─── коды выхода ─────────────────────────────────────────────────────────────────────────────

EXIT_OK: Final = 0
EXIT_UNEXPECTED: Final = 1
EXIT_USAGE: Final = 2
EXIT_DRY_RUN: Final = 3
EXIT_GATE: Final = 4
EXIT_TAKEN: Final = 5
EXIT_ENV: Final = 6

# ─── роль и состояние ────────────────────────────────────────────────────────────────────────

#: Роль заведённой записи: см. модульный докстринг и `ADR-023`.
BOOTSTRAP_ROLE: Final = ROLE_ADMIN

#: Состояние, с которого начинается цепочка (§1.2: приглашение принято, шага одобрения ещё нет).
#: Его ставит `new_user`, а дальше переход делает `enqueue_for_approval`.
START_STATE: Final = "invited"

#: Состояния, которые не считаются живым администратором. Только `archived`: `suspended` и
#: `awaiting_approval` — записи, которые ещё могут быть разблокированы или одобрены, и
#: самособранный доступ рядом с ними так же недопустим, как рядом с `active`.
NON_LIVE_ADMIN_STATES: Final[frozenset[str]] = frozenset({"archived"})

# ─── генератор значения пароля ───────────────────────────────────────────────────────────────

#: Алфавит значения. Из набора убраны `0`/`O` и `1`/`l`/`I`: их путают при наборе с консоли, а
#: набирать значение придётся вручную. Ограничений на состав символов §8.1 не ставит, поэтому
#: это удобство оператора, а не правило политики.
ALPHABET: Final = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"

#: Длина значения. §8.1 требует `MIN_PASSWORD_LENGTH` (12); берётся с запасом над словарём
#: слабых: самая длинная запись `WEAK_PASSWORDS` (основание + числовой хвост) короче этого числа,
#: поэтому совпадение со слабым паролем исключено по построению, а не вероятностью. Инвариант
#: держит проверка `test_длина_генератора_больше_словаря_слабых`.
GENERATED_LENGTH: Final = 20

#: Потолок текста ошибки наружу: сообщения драйвера многострочные, вывод читает человек в
#: терминале. Значение пароля вычищается до обрезки.
DETAIL_LIMIT: Final = 300

# Формы, в которых адрес базы может просочиться в текст исключения.
_URL_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"']+")
_CREDENTIALS_RE: Final = re.compile(r"[^\s:@/,]+:[^\s@/,]+@")

#: Единственный текст отказа по занятому значению. Имен ограничений в нём нет намеренно, как и
#: различения «логин»/«почта»: отказ обязан быть неотличим по сути, §8.8.
TAKEN_MESSAGE: Final = (
    "учётная запись не создана: значение логина или адреса почты уже занято; "
    "транзакция откачена, в таблице ничего не появилось"
)


class BootstrapError(RuntimeError):
    """Штатный отказ с готовым объяснением; код выхода держится в атрибуте `code`."""

    def __init__(self, code: int, detail: str = "") -> None:
        super().__init__(detail or "завод учётной записи остановлен")
        self.code = code
        self.detail = detail


class GeneratorConflictError(RuntimeError):
    """Генератор или цепочка завода противоречат политике/домену.

    Случай не «неудачная попытка», а расхождение: перебирать заново или промолчать значит прятать
    его. Запись при этом не создаётся, потому что `commit()` стоит после всех проверок.
    """


# ─── вывод, ввод, генерация ──────────────────────────────────────────────────────────────────


def safe_text(value: object, *, hidden: str | None = None) -> str:
    """Текст ошибки без адреса базы и без значения пароля.

    Нужно потому, что исключения SQLAlchemy и psycopg печатают и текст запроса, и его связанные
    значения: в них оказывается DSN, а на отказе записи — сгенерированное значение как параметр
    `INSERT`. Наружу выходят смысл отказа и имена таблиц/ограничений схемы, не более.
    """
    text = str(value)
    if hidden:
        text = text.replace(hidden, "[значение пароля скрыто]")
    text = _URL_RE.sub("[адрес базы скрыт]", text)
    text = _CREDENTIALS_RE.sub("[учётные данные скрыты]", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines)[:DETAIL_LIMIT]


def read_value(label: str, *, stream: IO[str], err: IO[str]) -> str:
    """Прочитать одно значение со стандартного ввода.

    Подсказка идёт в `stderr`, а не в `stdout`: stdout остаётся машиночитаемым (его сверяют
    проверки приёмки), а введённое значение не появляется в выводе скрипта — оно живёт только в
    терминале оператора.
    """
    print(f"{label}: ", end="", file=err, flush=True)
    line = stream.readline()
    if not line:
        raise BootstrapError(EXIT_USAGE, f"{label}: значение не получено — стандартный ввод закрыт")
    return line.strip()


def generate_value() -> str:
    """Собрать значение пароля по правилам политики, а не перебором.

    Длина `GENERATED_LENGTH` заведомо больше и `MIN_PASSWORD_LENGTH` (§8.1), и любой записи
    словаря слабых значений, поэтому правило «не совпадает со типовым слабым» выполняется
    конструкцией, а не проверкой. Источник случайности — `secrets` (генератор ОС): `random` для
    значения доступа не используется.

    Сравнение с логином и доменом (§8.1) зависит от значений оператора, поэтому его делает
    `check_password_policy` сразу после генерации: отказ считается противоречием генератора и
    политики, а не неудачной попыткой.
    """
    return "".join(secrets.choice(ALPHABET) for _ in range(GENERATED_LENGTH))


# ─── предстартовые проверки ──────────────────────────────────────────────────────────────────


def live_admin_count(session: Session) -> int:
    """Сколько в базе учётных записей с ролью `admin` в состоянии, кроме `archived`.

    Считает база (`count(*)` с предикатами роли и состояния) — тот же приём, что у
    `SqlStore.active_admin_count` в срезе `R7b`. Отличие намеренное: разделу администрирования
    нужен счёт «остался ли тот, кто может одобрить» (только `active`), а этому скрипту нужно
    «есть ли рядом живой администратор вообще» — рядом с `awaiting_approval` и `suspended`
    самособранный доступ недопустим так же, как рядом с `active`.
    """
    value = session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == ROLE_ADMIN, User.state.not_in(NON_LIVE_ADMIN_STATES))
    )
    return int(value or 0)


def email_taken(session: Session, email: str) -> bool:
    """Занята ли почта: uniqueness почты схема не держит (§4.1), поэтому спрашиваем таблицу.

    Сравнение ведёт `citext` колонки, а не `casefold()` в Python: правило «та же почта» у базы и у
    скрипта обязано быть одним, иначе отказ зависел бы от регистра, который набрал оператор.
    """
    value = session.scalar(select(func.count()).select_from(User).where(User.email == email))
    return bool(value)


def schema_version(session: Session) -> str:
    """Отметка Alembic одной строкой — для сверки с ожиданиями приёмки.

    Это справка, а не условие запуска: жёсткое значение отметки здесь не зашито сознательно
    (слот `0007` займёт журнал у `T-109`, `ADR-022`, и скрипт не должен устаревать вместе с
    нумерацией). Если таблицы нет или она не читается — так и пишется; настоящий признак
    readiness даёт гейт, который обращается к `users` и на неразвёрнутой схеме падает с
    внятным объяснением.
    """
    alembic_version = table("alembic_version", column("version_num"))
    try:
        rows = session.execute(select(alembic_version.c.version_num)).scalars().all()
    except SQLAlchemyError:
        session.rollback()
        return "не прочитано (схема не развёрнута или отметки нет)"
    if not rows:
        return "отметки нет"
    if len(rows) != 1:
        return f"несколько отметок: {sorted(rows)}"
    return str(rows[0])


# ─── доменная часть ──────────────────────────────────────────────────────────────────────────


def create_first_account(
    session: Session, *, login: str, email: str, password: str, moment: datetime
) -> User:
    """Завести запись доменом и зафиксировать одной транзакцией.

    Порядок — ровно тот, что у церемонии приглашения (§1.2, `ADR-020` п. 4 и 5):

    1. `new_user` — политика §8.1, проверка роли и состояния и Argon2id-хэш считаются до
       `INSERT`, поэтому переходного состояния «запись есть, а корректного хэша нет» не
       возникает;
    2. `enqueue_for_approval` — `invited → awaiting_approval` (созданная запись обязана быть в
       `invited`, поэтому переход совершается впервые и возвращает `True`);
    3. `approve_account(approved_by=<собственный id>)` — `awaiting_approval → active` плюс
       отметки `approved_by`/`approved_at`;
    4. один `commit()` — вся цепочка либо видна целиком, либо отсутствует.

    Идентификатор выдаёт приложение (`uuid7`, `packages/common/ids.py`), и он обязан быть известен
    **до** записи: у колонки `users.id` python-`default`, который SQLAlchemy применяет при
    `flush`, поэтому до фиксации `account.id` ещё `None` — и `approved_by` осталось бы пустым, а
    это значило бы «доступ открыт, но никто не одобривал». Собственная ссылка на строку
    выполняется в том же `INSERT`: `fk_users_approved_by_users` — immediate-ограничение, а
    ссылающаяся строка и есть та, на которую ссылаются.
    """
    account = new_user(
        login=login,
        password=password,
        role=BOOTSTRAP_ROLE,
        email=email,
        state=START_STATE,
        now=moment,
    )
    identifier = uuid7()
    account.id = identifier
    session.add(account)
    if not enqueue_for_approval(account):
        raise GeneratorConflictError(
            "переход invited → awaiting_approval не выполнен — цепочка завода нарушена"
        )
    approve_account(account, approved_by=identifier, now=moment)
    session.commit()
    return account


# ─── основной ход ─────────────────────────────────────────────────────────────────────────────


def build_session_factory(out: IO[str]) -> sessionmaker[Session] | None:
    """Движок и фабрика сессий из конфигурации приложения; `None` — адрес недоступен.

    Адрес читается только из конфигурации: переменная окружения `TBOT_DB_URL` или файл секрета
    `db_url` в `secrets_dir` (`packages/common/config.py`, TZ §14.3 и §14.9). Из аргументов
    командной строки он не берётся никогда: строка процесса видна в `ps` и в журналах сессии.
    Форма обязательно прогоняется через `sqlalchemy_url` (`packages/common/db.py`): на площадке
    файл лежит как `postgresql+psycopg://…`, а SQLAlchemy иначе искала бы psycopg2.

    Роль — из того же `db_url`, то есть роль приложения (`ADR-006`). Завода ролью-владельцем
    схемы здесь нет и быть не может, и прав `tbot_app` хватает: операции только DML, никакого
    DDL (`ADR-018`, `ADR-023`).
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"конфигурация отклонена: {safe_text('; '.join(exc.reasons))}", file=out)
        return None
    if settings.db_url is None:
        print(
            f"адрес базы не настроен: нужен TBOT_DB_URL или файл db_url в secrets_dir "
            f"({settings.secrets_dir})",
            file=out,
        )
        return None
    try:
        engine = create_engine(sqlalchemy_url(settings.db_url.get_secret_value()))
    except ValueError as exc:
        # `sqlalchemy_url` печатает разобранный адрес в сообщении — наружу он не идёт.
        print(f"адрес базы разобран неправильно: {safe_text(exc)}", file=out)
        return None
    return sessionmaker(bind=engine, expire_on_commit=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="first_account.py",
        description=(
            "завод первой учётной записи (admin) на площадке: обёртка над доменом identity "
            "(T-112, ADR-023)"
        ),
        epilog=(
            "логин и e-mail читаются со стандартного ввода; адрес базы — из TBOT_DB_URL или "
            "файла db_url; сгенерированный пароль показывается один раз"
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="подтвердить запись; без флага прогон черновой, ничего не пишется",
    )
    # Ловушка, а не возможность: кто привык передавать значения аргументами, обязан получить
    # причину отказа, а не сообщение «нераспознанный аргумент».
    parser.add_argument(
        "--login",
        default=None,
        help="не принимается: значение читается со стандартного ввода (argv видно в ps)",
    )
    parser.add_argument(
        "--email",
        default=None,
        help="не принимается: значение читается со стандартного ввода (argv видно в ps)",
    )
    return parser


def refuse_cli_supplied_values(args: argparse.Namespace, out: IO[str]) -> bool:
    """Отказать тем, кто передал логин или почту аргументами.

    Аргументы видны в `ps`, в `journalctl -u ssh` при включённом логировании сессии и в истории
    оболочки оператора. Значения логина и почты — данные оператора (`ADR-004`), и они не должны
    жить в командной строке.
    """
    if args.login is None and args.email is None:
        return False
    print(
        "логин и e-mail принимаются со стандартного ввода, а не аргументами: "
        "аргументы командной строки видны в ps и в журналах сессии",
        file=out,
    )
    return True


def run(*, yes: bool, session: Session, stdin: IO[str], out: IO[str], err: IO[str]) -> int:
    """Один прогон поверх готового соединения. Возвращает код выхода."""
    admins = live_admin_count(session)
    print(f"схема: {schema_version(session)}", file=out)
    print(f"живых администраторов (роль {BOOTSTRAP_ROLE}, не archived): {admins}", file=out)

    if admins > 0:
        print(
            f"в базе уже есть учётная запись с ролью {BOOTSTRAP_ROLE!r} в состоянии, кроме "
            "archived, — завод первой записи не выполняется (§1.2, ADR-020 п. 5). Дальше доступ "
            "выдаёт раздел администрирования: выпуск приглашения, приём ссылки, привязка 2FA и "
            "одобрение. Повторный запуск этого скрипта недопустим: самособранное одобрение "
            "возможно ровно один раз.",
            file=out,
        )
        session.rollback()
        return EXIT_GATE

    if not yes:
        print(
            "черновой прогон: запись не выполнялась. Порядок будет такой: new_user → "
            "enqueue_for_approval → approve_account(approved_by=<собственный id>) → один commit; "
            "роль — admin, состояние после завода — active, пароль будет сгенерирован и показан "
            "ровно один раз. Повторите с --yes.",
            file=out,
        )
        session.rollback()
        return EXIT_DRY_RUN

    login = ensure_login_syntax(read_value("логин", stream=stdin, err=err))
    email = ensure_email_syntax(read_value("e-mail", stream=stdin, err=err))

    if email_taken(session, email):
        print(TAKEN_MESSAGE, file=out)
        session.rollback()
        return EXIT_TAKEN

    password = generate_value()
    try:
        check_password_policy(password, login=login, email=email)
    except PasswordPolicyError as exc:
        print(
            "сгенерированное значение не проходит политику §8.1 "
            f"({safe_text(exc, hidden=password)}) — это противоречие генератора и политики, "
            "запись не создавалась",
            file=out,
        )
        session.rollback()
        return EXIT_UNEXPECTED

    try:
        account = create_first_account(
            session, login=login, email=email, password=password, moment=utc_now()
        )
    except IntegrityError:
        # Ни текста драйвера, ни имени ограничения, ни SQL со связанными значениями: отказ по
        # занятому логину обязан быть неотличим от отказа по занятой почте, а сообщение
        # IntegrityError содержит и запрос, и его параметры — то есть сгенерированный пароль.
        print(TAKEN_MESSAGE, file=out)
        session.rollback()
        return EXIT_TAKEN

    print(
        "\nпервая учётная запись заведена:"
        f"\n  id           = {account.id}"
        f"\n  login        = {account.login}"
        f"\n  role         = {account.role}"
        f"\n  state        = {account.state}"
        f"\n  approved_by  = {account.approved_by} (тот же id — bootstrap, ADR-020 п. 5)"
        f"\n  approved_at  = {account.approved_at}",
        file=out,
    )
    print(f"\nпароль (показывается ровно один раз, §8.1):\n  {password}\n", file=out)
    print(
        "это значение не сохранено нигде: в базе лежит только Argon2id-хэш (§8.1), в файл, в "
        "журнал приложения и в аргументы оно не пишется. Не переписали — значит потеряли: "
        "дальше только смена пароля (раздел консоли, ADR-012; порядок обращения со значениями "
        "на площадке — docs/runbook/secret-rotation.md). Первый вход под этой записью потребует "
        "привязку 2FA: консоль требует auth_step='full' (apps/web/security/sessions.py, "
        "require_full_session).",
        file=out,
    )
    return EXIT_OK


def main(
    argv: list[str] | None = None,
    *,
    session_factory: Callable[[], Session] | None = None,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Точка входа.

    `session_factory` и потоки подставляются проверками; в бою используются значения по
    умолчанию — конфигурация приложения и стандартные потоки процесса. Подстановка нужна, чтобы
    оффлайновая половинка проверок (`tests/integration/test_first_account.py`) исполняла тот же
    код без базы: живая половинка — `tests/integration/test_first_account_db.py`.
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    stream = stdin if stdin is not None else sys.stdin

    args = build_parser().parse_args(argv)
    if refuse_cli_supplied_values(args, out):
        return EXIT_USAGE

    factory = session_factory or build_session_factory(out)
    if factory is None:
        return EXIT_ENV

    session = factory()
    try:
        return run(yes=args.yes, session=session, stdin=stream, out=out, err=err)
    except BootstrapError as exc:
        if exc.detail:
            print(exc.detail, file=out)
        session.rollback()
        return exc.code
    except (LoginFormatError, InvitationTargetError) as exc:
        # Формат значения — ошибка оператора, а не состояние данных: объяснение печатается
        # целиком (значение оператор набрал сам), но сквозь `safe_text`.
        print(f"значение не принято: {safe_text(exc)}", file=out)
        session.rollback()
        return EXIT_USAGE
    except SQLAlchemyError as exc:
        print(
            f"база недоступна или схема не развёрнута: {safe_text(exc)} — сверьте адрес базы и "
            "что миграции выполнены (docs/runbook/stand-deploy.md §5)",
            file=out,
        )
        session.rollback()
        return EXIT_ENV
    except GeneratorConflictError as exc:
        print(f"{safe_text(exc)} — запись не создавалась", file=out)
        session.rollback()
        return EXIT_UNEXPECTED
    except Exception as exc:
        # Последний барьер: текст наружу вычищен (`safe_text`), потому что сообщение может
        # содержать запрос с параметрами. Лога у скрипта нет — вывод и есть единственный след.
        print(f"непредвиденная ошибка: {safe_text(exc)}", file=out)
        session.rollback()
        return EXIT_UNEXPECTED
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
