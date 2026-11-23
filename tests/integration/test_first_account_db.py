"""Живой PostgreSQL 16 и завод первой учётной записи (TZ §1.2, §4.1, `ADR-020` п. 5, `T-112`).

Оффлайновая половинка — `tests/integration/test_first_account.py` (тот же ход скрипта на
подставном соединении). Здесь проверяется ровно то, чего память и двойник соединения показать не
могут:

* **self-reference в `approved_by` выполняет настоящий FK.** `fk_users_approved_by_users` — со
  ссылкой на `users.id`. Скрипт заполняет её идентификатором той же строки, и только база решает,
  что ссылка выполнима в одном `INSERT`: у колонки `users.id` python-`default`, применяемый при
  `flush`, поэтому «одобривший» мог бы остаться пустым — а пустое значение ограничение принимает
  молча, то есть ловить надо значением, а не исключением;
* **ссылка работает и в обратную сторону:** когда заведённая запись становится одобрившей для
  другой строки, её нельзя удалить (`RESTRICT`) — след bootstrap переживает то, что будет дальше
  (§4.1 «строка не удаляется»);
* **защитный гейт считает состояния база.** `archived` заводу не мешает, `awaiting_approval` —
  мешает: разница живёт в предикате `count(*)` с условиями по роли и состоянию, а не в `if` на
  прочитанном значении;
* **повторный запуск отказывает,** а не заводит второго администратора: самособранное одобрение
  возможно ровно один раз (`ADR-020` п. 5);
* **`uq_users_login` на `citext` отклоняет повтор имени в другом регистре,** а занятая почва (её
  uniqueness схема не держит, §4.1) отклоняет скрипт. Оба отказа дают один и тот же текст и
  откатывают транзакцию: в таблице не появляется строка с «доступом без одобрившего», и
  соединение не остаётся с открытым транзактом;
* **хэш в колонке — Argon2id от показанного значения:** `verify_password` на показанном значении
  даёт `True`, на любом другом — `False`. Иначе «показали одно, записали другое» всплывёт на
  первом входе на площадке, а не в тесте;
* **адрес базы приходит из конфигурации процесса** (`TBOT_DB_URL` или файл `db_url`) и не
  попадает ни в аргументы, ни в вывод скрипта.

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `миграции`). Без
переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной базе —
падает, а не пропускается. Шаг job'а обязан вызывать pytest с `-rs`: молча пропущенная группа
неотличима от прошедшей (`test_каждая_живая_проверка_базы_имеет_свой_шаг_в_ci`).
"""

from __future__ import annotations

import io
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest
from sqlalchemy import Engine, create_engine, delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from packages.common.clock import utc_now
from packages.common.db import sqlalchemy_url
from packages.identity.passwords import verify_password
from packages.identity.sessions import SessionStepError, create_session, ensure_full_auth
from packages.identity.users import (
    approve_account,
    archive_account,
    enqueue_for_approval,
    new_user,
)
from packages.storage.models import BackupCode, TotpEnrollment, User, UserSession
from tests.integration.web_support import TEST_PASSWORD
from tests.paths import load_script

first_account = load_script("first_account")

# Читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

#: Логины завода — с префиксом: по нему работает уборка после каждого теста, а уникальный индекс
#: `users.login` (`citext`) не даёт смешать прогоны. Только логин из разрешённого алфавита
#: `ensure_login_syntax`: кириллицу он не принимает (§8.1), и база бы её приняла — расхождение
#: правил как раз и означало бы «приглашено одно имя, создана учётка с другим».
_PREFIX: Final = "t112boot"

#: Имена ограничений, которые обязаны назваться в отказе: они отличают «правило есть в базе» от
#: «правило есть в коде скрипта».
_UQ_LOGIN: Final = "uq_users_login"
_FK_APPROVED_BY: Final = "fk_users_approved_by_users"

#: Момент доменных переходов в фикстурах — осознанный UTC (§2.7), чтобы отметки фикстуры и
#: отметки скрипта можно было сравнивать по смыслу, а не «примерно сейчас».
_MOMENT: Final = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

#: Значение хэша для прямой пробы вставки: CHECK требует префикс `$argon2id$`, а настоящая
#: функция хэширования в этой пробе не нужна — проверяется уникальный индекс, а не пароль.
_FAKE_HASH: Final = "$argon2id$probe-not-a-real-hash-0000000000"


# ─── фикстуры ──────────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def движок() -> Iterator[Engine]:
    """Движок проверок: DSN обязательно через `sqlalchemy_url` (`packages/common/db.py`).

    В job'е `миграции` переменная стоит в прямой форме `postgresql://…`, а SQLAlchemy иначе
    искала бы psycopg2 — драйвер в проекте один, psycopg3.
    """
    созданный = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield созданный
    созданный.dispose()


@pytest.fixture
def база(движок: Engine) -> Iterator[Session]:
    """Соединение проверок с уборкой по префиксу логина.

    Порядок уборки держат FK: сначала снимается ссылка одобрения (в том числе self-reference
    bootstrap'а), затем удаляются сеансы, и только потом сами учётные записи. Иначе красным стал
    бы тест уборки, а не проверяемое поведение.
    """
    сессия = sessionmaker(bind=движок, expire_on_commit=False)()
    yield сессия
    идентификаторы = list(
        сессия.scalars(select(User.id).where(User.login.like(f"{_PREFIX}%"))).all()
    )
    if идентификаторы:
        сессия.execute(
            update(User)
            .where(User.id.in_(идентификаторы))
            .values(approved_by=None)
            .execution_options(synchronize_session=False)
        )
        сессия.execute(delete(UserSession).where(UserSession.user_id.in_(идентификаторы)))
        сессия.execute(delete(User).where(User.id.in_(идентификаторы)))
        сессия.commit()
    сессия.close()


@pytest.fixture
def секреты_пусты(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Каталог секретов, где файлов нет: адрес обязан прийти из переменной окружения."""
    каталог = tmp_path / "секреты-пусто"
    каталог.mkdir()
    monkeypatch.setenv("TBOT_SECRETS_DIR", str(каталог))
    return каталог


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _учётка(
    сессия: Session,
    *,
    метка: str,
    роль: str,
    почта: str | None = None,
    состояние: str = "invited",
) -> User:
    """Учётная запись, созданная доменом (`new_user`), а не конструктором ORM.

    Тот же вход, что у боевого пути: иначе проверялась бы схема, а приложение — нет. Роль у
    фикстуры свободная (`operator`/`viewer`), чтобы защитный гейт скрипта не срабатывал там, где
    это не измеряется.
    """
    запись = new_user(
        login=f"{_PREFIX}{метка}",
        password=TEST_PASSWORD,
        role=роль,
        email=почта,
        state=состояние,
        now=_MOMENT,
    )
    сессия.add(запись)
    сессия.commit()
    return запись


def _идентификатор(запись: User) -> uuid.UUID:
    """`id` зафиксированной строки: `None` означало бы сломанную фикстуру, а не проверку."""
    if запись.id is None:
        raise AssertionError("у зафиксированной учётной записи нет id — фикстура сломана")
    return запись.id


def _живых_администраторов(сессия: Session) -> int:
    """Живые администраторы — тем же запросом, что считает скрипт."""
    return int(first_account.live_admin_count(сессия))


def _до_завода(сессия: Session) -> None:
    """Предусловие «первой записи ещё нет».

    Проверяется, а не предполагается: другие живые файлы убирают свои строки по префиксу, и если
    этот порядок когда-нибудь нарушится, падать обязан именно этот тест — со списком виновников, а
    не «завод почему-то отказал».
    """
    лишние = сессия.scalars(
        select(User.login).where(User.role == "admin", User.state != "archived")
    ).all()
    assert not лишние, f"в таблице уже есть живые администраторы: {list(лишние)}"


def _запуск(
    *,
    логин: str,
    почта: str,
    движок: Engine | None = None,
    argv: list[str] | None = None,
) -> tuple[int, str, str]:
    """Прогон скрипта так, как его запускает оператор: stdin, флаги, вывод.

    `argv` и потоки передаются явно — это тестовый зазор точки входа. Адрес базы берётся либо из
    конфигурации процесса (`TBOT_DB_URL`), либо через фабрику сессий данного движка:
    `session_factory` не подставляется только там, где проверяется именно конфигурация.
    """
    аргументы = list(argv) if argv is not None else ["--yes"]
    вывод, ошибки = io.StringIO(), io.StringIO()
    фабрика = (
        None if движок is None else (lambda: sessionmaker(bind=движок, expire_on_commit=False)())
    )
    код = first_account.main(
        аргументы,
        session_factory=фабрика,
        stdin=io.StringIO(f"{логин}\n{почта}\n"),
        stdout=вывод,
        stderr=ошибки,
    )
    return int(код), вывод.getvalue(), ошибки.getvalue()


def _значение_из_вывода(вывод: str) -> str:
    """Показанное значение пароля из вывода скрипта.

    Ищется по строке-маркеру, а не по позиции: вывод — то, что человек читает с экрана, и проверка
    обязана читать его так же, как читает оператор.
    """
    строки = вывод.splitlines()
    for позиция, строка in enumerate(строки):
        if "пароль (показывается ровно один раз" in строка:
            for продолжение in строки[позиция + 1 :]:
                if продолжение.strip():
                    return продолжение.strip()
    raise AssertionError("в выводе нет блока с показанным значением пароля")


def _строка(движок: Engine, логин: str) -> User | None:
    """Перечитать учётную запись новым соединением: что реально лежит в таблице."""
    новое = sessionmaker(bind=движок, expire_on_commit=False)()
    try:
        return новое.execute(select(User).where(User.login == логин)).scalar_one_or_none()
    finally:
        новое.close()


def _число(сессия: Session) -> int:
    """Сколько строк завода осталось в таблице — доказательство отката."""
    return int(
        сессия.scalar(select(func.count()).select_from(User).where(User.login.like(f"{_PREFIX}%")))
        or 0
    )


# ─── завод: доменный порядок на живой схеме ───────────────────────────────────────────────────


def test_завод_создаёт_одобренную_запись_со_ссылкой_на_саму_себя(
    база: Session, движок: Engine
) -> None:
    """`approved_by = id` под настоящим FK, роль `admin`, состояние `active`.

    Ядро `T-112`: `ADR-020` п. 5 утверждает, что ссылка выполнима в одной операции, потому что
    первичный ключ выдаёт приложение. На живой схеме проверяется, что она действительно выполнима
    и что строка не осталась «одобренной по умолчанию» с пустым `approved_by`.
    """
    _до_завода(база)
    логин = f"{_PREFIX}first"
    код, вывод, ошибки = _запуск(логин=логин, почта="first@example.test", движок=движок)

    assert код == first_account.EXIT_OK, вывод + ошибки
    запись = _строка(движок, логин)
    assert запись is not None, "строка не зафиксирована"
    assert запись.role == "admin"
    assert запись.state == "active"
    assert запись.approved_by == запись.id
    assert запись.approved_at is not None
    assert запись.email is not None
    assert запись.email.casefold() == "first@example.test"
    assert запись.password_hash.startswith("$argon2id$")
    assert f"  id           = {_идентификатор(запись)}" in вывод
    assert f"  approved_by  = {_идентификатор(запись)}" in вывод
    assert вывод.count("живых администраторов") == 1
    # Отметка Alembic выведена та, что прочитана из живой базы, а не «не известна»: сверка
    # приёмки (§12 ранбука) идёт по этой строке, а само значение закреплено гейтом слотов
    # `tests/contract/test_identity_schema.py` — дублировать номер здесь смысла нет.
    отметка = [строка for строка in вывод.splitlines() if строка.startswith("схема: ")]
    assert len(отметка) == 1
    assert отметка[0] != "схема: не известна"


def test_показанное_значение_соответствует_хэшу_в_базе(база: Session, движок: Engine) -> None:
    """Человек, переписавший значение с экрана, сможет войти.

    Показ и хэш считаются в разных местах: значение печатает скрипт, а хэш считает `new_user` до
    `INSERT`. Расхождение («показали одно, записали другое») выглядело бы как «пароль не подходит»
    на первом входе — на площадке, а не в тесте.
    """
    _до_завода(база)
    логин = f"{_PREFIX}hash"
    код, вывод, _ошибки = _запуск(логин=логин, почта="hash@example.test", движок=движок)
    assert код == first_account.EXIT_OK

    значение = _значение_из_вывода(вывод)
    assert вывод.count(значение) == 1
    assert len(значение) == first_account.GENERATED_LENGTH

    запись = _строка(движок, логин)
    assert запись is not None
    assert запись.password_hash != значение
    assert значение not in запись.password_hash
    assert verify_password(password=значение, stored_hash=запись.password_hash)
    другое = значение[:-1] + ("a" if not значение.endswith("a") else "b")
    assert not verify_password(password=другое, stored_hash=запись.password_hash)


def test_повторный_запуск_отказывает_защитным_гейтом(база: Session, движок: Engine) -> None:
    """Второй завод невозможен: живых администраторов уже больше нуля.

    Важна отсутствие побочных эффектов: отказ обязан произойти до `INSERT`, чтобы повторный запуск
    не оставил в таблице второго «одобренного самим собой» администратора.
    """
    _до_завода(база)
    код, _вывод, _ошибки = _запуск(
        логин=f"{_PREFIX}again", почта="again@example.test", движок=движок
    )
    assert код == first_account.EXIT_OK
    было = _число(база)

    код_второй, вывод_второй, _ошибки_второй = _запуск(
        логин=f"{_PREFIX}second", почта="second@example.test", движок=движок
    )
    assert код_второй == first_account.EXIT_GATE
    assert "уже есть" in вывод_второй
    assert _число(база) == было, "повторный запуск создал строку"
    assert _строка(движок, f"{_PREFIX}second") is None
    assert _живых_администраторов(база) == 1


def test_архивированный_администратор_заводу_не_мешает(база: Session, движок: Engine) -> None:
    """`archived` в счётчик не входит: архивная строка права не даёт (§4.1).

    Иначе скрипт отказывал бы площадке, где первую запись вывели из состава, и ремонт сводился бы
    к правке таблицы под ролью-владельцем — операции без журнала и без отработанного порядка.
    """
    _до_завода(база)
    архив = _учётка(база, метка="arch", роль="admin", почта="arch@example.test", состояние="active")
    archive_account(архив)
    база.commit()
    assert архив.state == "archived"
    assert _живых_администраторов(база) == 0

    код, вывод, ошибки = _запуск(
        логин=f"{_PREFIX}afterarch", почта="after-arch@example.test", движок=движок
    )
    assert код == first_account.EXIT_OK, вывод + ошибки
    assert _живых_администраторов(база) == 1


def test_ожидающий_одобрения_администратор_завод_закрывает(база: Session, движок: Engine) -> None:
    """`awaiting_approval` — тоже живой администратор: рядом с ним самособранный доступ нельзя.

    Отличие от `ensure_not_last_admin` (`ADR-020` п. 6) намеренное: там считают только `active`,
    потому что вопросу «остался ли тот, кто может одобрить» состояние `awaiting_approval` не
    отвечает, а вопросу «есть ли рядом администратор вообще» — отвечает.
    """
    _до_завода(база)
    ожидает = _учётка(база, метка="queue", роль="admin", почта="queue@example.test")
    assert enqueue_for_approval(ожидает) is True
    база.commit()
    assert _строка(движок, f"{_PREFIX}queue") is not None
    assert _живых_администраторов(база) == 1

    код, вывод, _ошибки = _запуск(
        логин=f"{_PREFIX}blocked", почта="blocked@example.test", движок=движок
    )
    assert код == first_account.EXIT_GATE
    assert "живых администраторов (роль admin, не archived): 1" in вывод
    assert _число(база) == 1


# ─── занятые значения: неразличимость и откат ─────────────────────────────────────────────────


def test_отказ_по_почве_и_по_логину_неразличимы_и_откатаны(база: Session, движок: Engine) -> None:
    """Занятая почта (проверка скрипта) и занятый логин (`uq_users_login`, `citext`) — один ответ.

    Первый отказ скрипт снимает сам (uniqueness почты схема не держит, §4.1), второй отдаёт база
    при записи. На живой базе проверяется и откат: строки не появляется, а соединение проверки
    после всех прогонов способно читать таблицу — транзакт не остался открытым.
    """
    _до_завода(база)
    занятый = _учётка(база, метка="taken", роль="operator", почта="taken@example.test")
    assert занятый.role == "operator"

    # (а) почта занята: значение набрано в другом регистре — решает `citext` колонки
    код_почва, вывод_почва, ошибки_почва = _запуск(
        логин=f"{_PREFIX}fresh", почта="TAKEN@EXAMPLE.TEST", движок=движок
    )
    # (б) логин занят в другом регистре: решает уникальный индекс `uq_users_login` на `citext`
    код_логин, вывод_логин, ошибки_логин = _запуск(
        логин=f"{_PREFIX.upper()}TAKEN", почта="free@example.test", движок=движок
    )

    assert код_почва == код_логин == first_account.EXIT_TAKEN
    assert вывод_почва == вывод_логин, "отличимый ответ — это оракул про занятое значение (§8.8)"
    assert ошибки_почва == ошибки_логин
    assert first_account.TAKEN_MESSAGE in вывод_почва
    for текст in (вывод_почва, вывод_логин, ошибки_почва, ошибки_логин):
        assert "$argon2id$" not in текст
        assert "://" not in текст
    assert _UQ_LOGIN not in вывод_логин, "имя ограничения наружу не выходит"
    assert _число(база) == 1, "отказ оставил строку в таблице"
    assert _строка(движок, f"{_PREFIX}fresh") is None


def test_дубль_логина_в_другом_регистре_отклоняет_индекс(база: Session) -> None:
    """Прямая проба: дубль снимает именно база, а не проверка скрипта.

    Если бы логин был занят только «на взгляд скрипта», тот же `INSERT` прошёл бы. Проверка обязана
    назвать имя ограничения — иначе смысл предыдущего теста не доказан, а различие отказов осталось
    бы незамеченным.
    """
    _до_завода(база)
    _учётка(база, метка="unique", роль="operator", почта="unique@example.test")
    with pytest.raises(IntegrityError) as поднятое:
        база.execute(
            text(
                "insert into users (id, login, role, state, password_hash) "
                "values (:id, :login, 'viewer', 'invited', :hash)"
            ),
            {"id": uuid.uuid4(), "login": f"{_PREFIX.upper()}UNIQUE", "hash": _FAKE_HASH},
        )
    assert _UQ_LOGIN in str(поднятое.value)
    база.rollback()
    assert _число(база) == 1


def test_заведённая_запись_защищена_RESTRICT_когда_ею_одобрили(
    база: Session, движок: Engine
) -> None:
    """След bootstrap'а удалён быть не может: на него ссылается одобренная запись.

    `approved_by` заведённой строки указывает на неё саму, и именно эта строка становится
    одобрившей для всех, кто придёт дальше. `RESTRICT` — то, что не даёт «забыть», кто открыл
    доступ (§4.1: строка не удаляется, только архивирование).
    """
    _до_завода(база)
    код, _вывод, _ошибки = _запуск(
        логин=f"{_PREFIX}keeper", почта="keeper@example.test", движок=движок
    )
    assert код == first_account.EXIT_OK

    следующий = _учётка(база, метка="guest", роль="viewer", почта="guest@example.test")
    assert enqueue_for_approval(следующий) is True
    одобренный = база.execute(select(User).where(User.login == f"{_PREFIX}keeper")).scalar_one()
    approve_account(следующий, approved_by=_идентификатор(одобренный), now=_MOMENT)
    база.commit()

    # Строка, одобрившая доступ, удаляться не может: на неё ссылается и одобренная запись, и она
    # сама (self-reference bootstrap'а). `delete` — намеренно вне блока `raises`: поднимает не он,
    # а `flush`, то есть запрос `DELETE`, который база отклоняет по `RESTRICT`.
    база.delete(одобренный)
    with pytest.raises(IntegrityError) as поднятое:
        база.flush()
    assert _FK_APPROVED_BY in str(поднятое.value)
    база.rollback()


def test_первый_вход_настаивает_на_втором_факторе(база: Session, движок: Engine) -> None:
    """Заведённая запись приходит без второго фактора: привязывать придётся при первом входе.

    На этом компенсирующем контроле держится принятое в `ADR-023` решение не вводить
    принудительную смену пароля при первом входе: пока у учётной записи нет привязки, сессия под
    её паролём остаётся на шаге `password`, а `ensure_full_auth` (§8.2) дальше не пускает —
    консоль, раздел администрирования и выпуск приглашения закрыты. Поэтому проверка читает
    таблицу, а не предполагает: строк `totp_enrollments` и `backup_codes` у заведённой записи
    ровно ноль, и парольный шаг действительно отказывает.

    Параметризованную `test_route_requires_full_auth` здесь дублировать незачем: она идёт по
    реальным маршрутам консоли. Вопрос этого теста другой — что именно *эта* строка приходит
    пустой по обоим факторам, иначе оператор получил бы доступ, минуя привязку (`ADR-013` п. 4).
    """
    _до_завода(база)
    логин = f"{_PREFIX}twofa"
    код, _вывод, ошибки = _запуск(логин=логин, почта="twofa@example.test", движок=движок)
    assert код == first_account.EXIT_OK, ошибки

    запись = база.execute(select(User).where(User.login == логин)).scalar_one()
    идентификатор = _идентификатор(запись)
    assert запись.role == "admin"
    assert запись.state == "active"
    привязки = база.scalar(
        select(func.count())
        .select_from(TotpEnrollment)
        .where(TotpEnrollment.user_id == идентификатор)
    )
    коды = база.scalar(
        select(func.count()).select_from(BackupCode).where(BackupCode.user_id == идентификатор)
    )
    assert привязки == 0
    assert коды == 0

    выпущенная = create_session(
        идентификатор, user_agent="bootstrap-probe", auth_step="password", now=utc_now()
    )
    assert выпущенная.record.auth_step == "password"
    база.add(выпущенная.record)
    база.commit()

    with pytest.raises(SessionStepError):
        ensure_full_auth(выпущенная.record, now=utc_now())


# ─── адрес базы ───────────────────────────────────────────────────────────────────────────────


def test_адрес_берётся_из_конфигурации_и_не_показывается_в_выводе(
    база: Session, движок: Engine, секреты_пусты: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Без подставной фабрики: скрипт сам достаёт адрес из `TBOT_DB_URL`.

    Два факта сразу: адрес читается из окружения (не из аргументов и не «догадкой»), и его форма
    проходит через `sqlalchemy_url` — иначе SQLAlchemy искала бы psycopg2, а завод падал бы ещё
    до вопроса к таблице (`packages/common/db.py`). И ни в одном выводе адреса быть не должно.
    """
    _до_завода(база)
    monkeypatch.setenv("TBOT_DB_URL", _DB_URL)
    assert not (
        секреты_пусты / "db_url"
    ).exists(), "файл db_url появился: адрес мог прийти не из окружения, и проверка теряет смысл"
    код, вывод, ошибки = _запуск(логин=f"{_PREFIX}envdsn", почта="envdsn@example.test")
    assert код == first_account.EXIT_OK, вывод + ошибки
    for текст in (вывод, ошибки):
        assert "://" not in текст, "адрес базы не должен появляться в выводе"
        assert "psycopg" not in текст
    assert _строка(движок, f"{_PREFIX}envdsn") is not None
