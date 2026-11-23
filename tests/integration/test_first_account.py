"""Оффлайновая половинка завода первой учётной записи (`T-112`, `ADR-023`, `ADR-020` п. 5).

Живая половинка — `tests/integration/test_first_account_db.py` (её шаг стоит в job'е `миграции`).
Здесь базы нет: соединение подставляется наблюдателем, а два обращения к таблице
(`live_admin_count`, `email_taken`) и отметка схемы заменяются значениями прогона. Раздел
осознанный: тут проверяется **ход скрипта** — порядок доменных вызовов, отказ защитного гейта,
неразличимость отказа по занятому значению, ровно однократный показ пароля и то, что черновой
прогон не пишет. Сами запросы, `citext`, `uq_users_login`, FK `RESTRICT` и откат транзакции
проверяются на живом PostgreSQL — в памяти их не изобразить (тот же довод, что у пары
`test_invitations_db.py` и `test_invitation_repository_memory.py`).

Что держат эти проверки и почему это дороже «просто запустить скрипт»:

* **доменные вызовы ровно перечисленные.** Роль `admin`, состояние `invited`, затем
  `enqueue_for_approval`, затем `approve_account`, ровно один `commit()`. Самодеятельность вида
  `user.state = "active"` разошлась бы с `STATE_TRANSITIONS` и осталась невидимой для `ADR-020`
  п. 3;
* **одобрившим считается та же запись.** Если `approved_by` останется пустым, получится «доступ
  открыт, но кто его открыл — неизвестно», и FK `fk_users_approved_by_users` пустое значение
  принимает: ловить надо значением, а не ограничением;
* **защитный гейт.** При живом администраторе запись не создаётся вообще — ни `add`, ни `commit`;
* **неразличимость отказа.** Отказ по занятой почте (проверка скрипта) и по занятому логину
  (отказ базы, `IntegrityError`) печатают один и тот же текст под одним кодом. В тексте нет ни
  имён ограничений, ни SQL со связанными значениями: сообщение `IntegrityError` содержит
  параметры запроса, то есть сгенерированный пароль, и выпускать его наружу нельзя (§8.8);
* **пароль показывается ровно один раз,** а хэш — нигде и никогда.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest
from sqlalchemy.exc import IntegrityError

from packages.identity.passwords import (
    MIN_PASSWORD_LENGTH,
    WEAK_PASSWORDS,
    check_password_policy,
)
from packages.storage.models import USER_STATES, User
from tests.paths import load_script

first_account = load_script("first_account")

_LOGIN: Final = "ivan.petrov"
_EMAIL: Final = "ivan@example.test"

#: Момент завода подставляется вместо часов процесса: отметку `approved_at` сверяем точно.
_MOMENT: Final = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

#: Значение пароля подставляется вместо генератора, чтобы проследить его судьбу в выводе. Набор
#: знаков взят из `ALPHABET` скрипта, чтобы подставное значение проходило политику §8.1.
_GENERATED: Final = "Kp7rn3Qv9xt2Wm8dH4bc"

#: Форма адреса площадки без учётных данных: строку подключения с паролем в репозитории запрещает
#: контракт `tests/contract/test_no_forbidden_references.py`.
_DSN_FRAGMENT: Final = "postgresql+psycopg://tbot@127.0.0.1:5432/tbot_offline"

#: Имена доменных функций, вызов которых фиксируется.
_DOMAIN: Final = ("new_user", "enqueue_for_approval", "approve_account")


class _СессияНаблюдатель:
    """Минимальный двойник `Session`: записывает обращения и умеет отказывать при фиксации.

    `commit()` бросает подставленный `IntegrityError` — так офлайн проверяется путь «база
    отклонила запись по уникальности» без базы.
    """

    def __init__(self, *, ошибка_фиксации: Exception | None = None) -> None:
        self.вызовы: list[str] = []
        self._ошибка_фиксации = ошибка_фиксации

    def add(self, объект: object) -> None:
        del объект
        self.вызовы.append("add")

    def commit(self) -> None:
        if self._ошибка_фиксации is not None:
            raise self._ошибка_фиксации
        self.вызовы.append("commit")

    def rollback(self) -> None:
        self.вызовы.append("rollback")

    def close(self) -> None:
        self.вызовы.append("close")


@pytest.fixture
def вызовы_домена(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, tuple[object, ...], dict[str, object]]]:
    """Завернуть доменные функции скрипта, не подменяя их поведение.

    Подмена сама по себе ничего не проверяла бы: фиксируются порядок и аргументы, а переходы по
    -прежнему исполняет настоящий `packages/identity/users.py` — иначе проверялся бы макет, а не
    домен. Аргументы пишутся и позиционные, и именованные: `approve_account` получает учётную
    запись позиционно, а `approved_by` — по имени.
    """
    записанные: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def обернуть(имя: str) -> Callable[..., object]:
        подлинник = getattr(first_account, имя)

        def вызвать(*args: object, **kwargs: object) -> object:
            записанные.append((имя, args, dict(kwargs)))
            return подлинник(*args, **kwargs)

        return вызвать

    for имя in _DOMAIN:
        monkeypatch.setattr(first_account, имя, обернуть(имя))
    return записанные


@pytest.fixture
def стабильный_прогон(monkeypatch: pytest.MonkeyPatch) -> str:
    """Зафиксировать генератор, часы и отметку схемы: вывод становится сравнимым."""
    monkeypatch.setattr(first_account, "generate_value", lambda: _GENERATED)
    monkeypatch.setattr(first_account, "utc_now", lambda: _MOMENT)
    monkeypatch.setattr(first_account, "schema_version", lambda _session: "0004")
    return _GENERATED


def прогон(
    monkeypatch: pytest.MonkeyPatch,
    сессия: _СессияНаблюдатель,
    *,
    argv: list[str],
    stdin_text: str = f"{_LOGIN}\n{_EMAIL}\n",
    живых_администраторов: int = 0,
    почва_занята: bool = False,
) -> tuple[int, str, str]:
    """Один прогон скрипта поверх подставленного соединения: код и оба потока вывода."""
    monkeypatch.setattr(first_account, "live_admin_count", lambda _session: живых_администраторов)
    monkeypatch.setattr(first_account, "email_taken", lambda _session, _email: почва_занята)
    вывод, поток_ошибок = io.StringIO(), io.StringIO()
    код = first_account.main(
        argv,
        session_factory=lambda: сессия,
        stdin=io.StringIO(stdin_text),
        stdout=вывод,
        stderr=поток_ошибок,
    )
    return int(код), вывод.getvalue(), поток_ошибок.getvalue()


def _конфликт_уникальности() -> IntegrityError:
    """Отказ базы по занятому логину — в той форме, в какой его отдаёт SQLAlchemy.

    Форма важна: `str(IntegrityError)` печатает и SQL, и его связанные значения, поэтому в нём
    оказывается сгенерированный пароль. Проверки ниже и существуют, чтобы убедиться, что наружу
    этот текст не выходит.
    """
    return IntegrityError(
        "INSERT INTO users (id, login, password_hash) VALUES (%s, %s, %s)",
        {"p": _GENERATED},
        RuntimeError('duplicate key value violates unique constraint "uq_users_login"'),
    )


def _запись_из_вызова(
    вызов: tuple[str, tuple[object, ...], dict[str, object]],
) -> User:
    """Учётная запись из зафиксированного вызова доменной функции.

    Тип фиксированных аргументов — `object`, потому что обёртка пишет то, что ей передали, и не
    знает сигнатур. Сведение к `User` через `isinstance`, а не через `cast`: если скрипт начнёт
    передавать в `new_user` что-то другое, проверка обязана упасть здесь, а не разойтись
    молча.
    """
    запись = вызов[1][0]
    assert isinstance(запись, User)
    return запись


# ─── порядок домена ───────────────────────────────────────────────────────────────────────────


def test_порядок_доменных_вызовов_ровно_перечисленный_и_один_commit(
    monkeypatch: pytest.MonkeyPatch,
    вызовы_домена: list[tuple[str, tuple[object, ...], dict[str, object]]],
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, _вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"])

    assert код == first_account.EXIT_OK
    assert [имя for имя, _args, _kwargs in вызовы_домена] == list(_DOMAIN)
    assert сессия.вызовы == ["add", "commit", "close"]

    аргументы = вызовы_домена[0][2]
    assert аргументы["login"] == _LOGIN
    assert аргументы["email"] == _EMAIL
    assert аргументы["password"] == _GENERATED
    assert аргументы["role"] == first_account.BOOTSTRAP_ROLE == "admin"
    assert аргументы["state"] == first_account.START_STATE == "invited"
    assert аргументы["now"] == _MOMENT


def test_одобрившим_считается_та_же_запись(
    monkeypatch: pytest.MonkeyPatch,
    вызовы_домена: list[tuple[str, tuple[object, ...], dict[str, object]]],
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, _вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"])
    assert код == first_account.EXIT_OK

    учётка = _запись_из_вызова(вызовы_домена[2])
    одобрение = вызовы_домена[2][2]
    assert учётка.id is not None, "идентификатор обязан появиться до записи (ADR-020 п. 5)"
    assert одобрение["approved_by"] == учётка.id
    assert одобрение["now"] == _MOMENT
    assert учётка.state == "active"
    assert учётка.approved_by == учётка.id
    assert учётка.approved_at == _MOMENT


def test_состояние_после_завода_и_объяснение_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"])
    assert код == first_account.EXIT_OK
    assert "state        = active" in вывод
    assert "bootstrap, ADR-020" in вывод


# ─── пароль ───────────────────────────────────────────────────────────────────────────────────


def test_значение_пароля_показывается_ровно_один_раз(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, ошибки = прогон(monkeypatch, сессия, argv=["--yes"])
    assert код == first_account.EXIT_OK
    assert вывод.count(_GENERATED) == 1
    assert _GENERATED not in ошибки
    assert "$argon2id$" not in вывод
    assert "пароль (показывается ровно один раз" in вывод
    assert "docs/runbook/secret-rotation.md" in вывод
    assert "auth_step" in вывод, "предупреждение про обязательный второй фактор на первом входе"


def test_в_выводе_нет_ни_хэша_ни_значения_при_отказе_гейта(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, ошибки = прогон(monkeypatch, сессия, argv=["--yes"], живых_администраторов=1)
    assert код == first_account.EXIT_GATE
    for текст in (вывод, ошибки):
        assert _GENERATED not in текст
        assert "$argon2id$" not in текст


def test_длина_генератора_больше_словаря_слабых() -> None:
    """Совпадение со словарём слабых исключено по построению, а не вероятностью.

    Иначе `GENERATED_LENGTH` — просто число: при укорочении значения генератор начал бы
    конкурировать с `WEAK_PASSWORDS`, а отказ политики в скрипте трактуется как противоречие, то
    есть как павший на площадке завод.
    """
    потолок_словаря = max(len(значение) for значение in WEAK_PASSWORDS)
    assert потолок_словаря < first_account.GENERATED_LENGTH
    assert first_account.GENERATED_LENGTH >= MIN_PASSWORD_LENGTH


def test_генератор_проходит_политику_по_построению() -> None:
    """Каждое выданное значение проходит §8.1 и лежит в заявленном алфавите."""
    алфавит = first_account.ALPHABET
    выданные = [first_account.generate_value() for _ in range(50)]
    assert len(set(выданные)) == len(выданные), "значения не должны повторяться"
    for значение in выданные:
        assert len(значение) == first_account.GENERATED_LENGTH
        assert set(значение) <= set(алфавит)
        check_password_policy(значение, login=_LOGIN, email=_EMAIL)


# ─── защитный гейт ────────────────────────────────────────────────────────────────────────────


def test_при_живом_администраторе_запись_не_создаётся(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"], живых_администраторов=2)
    assert код == first_account.EXIT_GATE
    assert "уже есть" in вывод
    assert "самособранное одобрение" in вывод
    assert сессия.вызовы == ["rollback", "close"]
    assert f"живых администраторов (роль {first_account.BOOTSTRAP_ROLE}, не archived): 2" in вывод


def test_в_счёт_идут_все_состояния_кроме_archived() -> None:
    """Гейт обязан реагировать и на `awaiting_approval`, и на `suspended`.

    Иначе рядом с ожидающим или заблокированным администратором скрипт разрешил бы самособранный
    доступ, который `ADR-020` п. 5 допускает ровно один раз.
    """
    не_живые: set[str] = {"archived"}
    assert не_живые == set(first_account.NON_LIVE_ADMIN_STATES)
    # Против домена §4.1: все прочие состояния считаются живыми. Перечень берётся из
    # `USER_STATES`, а не переписывается здесь: если домен получит новое состояние, гейт обязан
    # отреагировать падением, а не молча его не заметить.
    живые: set[str] = {"active", "suspended", "awaiting_approval", "invited"}
    assert set(USER_STATES) - set(first_account.NON_LIVE_ADMIN_STATES) == живые


# ─── черновой прогон и способ передать значения ───────────────────────────────────────────────


def test_черновой_прогон_ничего_не_пишет(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, ошибки = прогон(monkeypatch, сессия, argv=[])
    assert код == first_account.EXIT_DRY_RUN
    assert сессия.вызовы == ["rollback", "close"]
    assert _GENERATED not in вывод
    assert "логин: " not in вывод
    assert "логин: " not in ошибки
    assert "--yes" in вывод


def test_значения_аргументами_не_принимаются(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    """`--yes` — единственный способ разрешить запись, и логин аргументом не принимается."""
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes", "--login", _LOGIN])
    assert код == first_account.EXIT_USAGE
    assert "стандартного ввода" in вывод
    # соединение не создаётся вовсе: отказ до обращения к базе
    assert сессия.вызовы == []


# ─── занятые значения ─────────────────────────────────────────────────────────────────────────


def test_занятые_логин_и_почва_отвечают_одинаково(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    """Один текст, один код, откат в обоих случаях.

    Первый отказ — проверка почты (её uniqueness схема не держит, §4.1), второй — `IntegrityError`
    на `INSERT` от `uq_users_login`. Ответы наружу совпадают посимвольно: по ответу нельзя
    различить, какое значение занято, и нельзя узнать имена ограничений схемы.
    """
    del стабильный_прогон

    по_почве = _СессияНаблюдатель()
    код_почва, вывод_почва, ошибки_почва = прогон(
        monkeypatch, по_почве, argv=["--yes"], почва_занята=True
    )

    по_логину = _СессияНаблюдатель(ошибка_фиксации=_конфликт_уникальности())
    код_логин, вывод_логин, ошибки_логин = прогон(monkeypatch, по_логину, argv=["--yes"])

    assert код_почва == код_логин == first_account.EXIT_TAKEN
    assert вывод_почва == вывод_логин
    assert ошибки_почва == ошибки_логин
    assert first_account.TAKEN_MESSAGE in вывод_почва

    for текст in (вывод_почва, вывод_логин, ошибки_почва, ошибки_логин):
        assert _GENERATED not in текст
        assert "uq_users_login" not in текст
        assert "$argon2id$" not in текст

    assert по_почве.вызовы == ["rollback", "close"]
    assert по_логину.вызовы == ["add", "rollback", "close"]


def test_текст_integrityerror_не_выходит_наружу(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    """Значение пароля живёт в параметрах запроса — а их печатает сообщение SQLAlchemy.

    Проверка отдельная, потому что соблазн «добавить причину отказа» равен утечке значения:
    `str(IntegrityError)` содержит и SQL, и связанные значения.
    """
    del стабильный_прогон
    сессия = _СессияНаблюдатель(ошибка_фиксации=_конфликт_уникальности())
    код, вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"])
    assert код == first_account.EXIT_TAKEN
    assert "parameters" not in вывод
    assert "INSERT" not in вывод


# ─── чистка текстов ошибок ────────────────────────────────────────────────────────────────────


def test_текст_ошибки_не_содержит_адрес_базы_и_значения() -> None:
    скрытый = first_account.safe_text(
        f"connection failed for {_DSN_FRAGMENT} под tbot_app:ppp@127.0.0.1 и {_GENERATED}",
        hidden=_GENERATED,
    )
    assert _GENERATED not in скрытый
    assert _DSN_FRAGMENT not in скрытый
    assert "tbot_app:ppp@" not in скрытый
    assert "[адрес базы скрыт]" in скрытый


def test_неверный_формат_значения_отклоняется_до_записи(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, _ошибки = прогон(
        monkeypatch, сессия, argv=["--yes"], stdin_text=f"ivan petrov!\n{_EMAIL}\n"
    )
    assert код == first_account.EXIT_USAGE
    assert "не принято" in вывод
    assert сессия.вызовы == ["rollback", "close"]


def test_закрытый_стандартный_ввод_даёт_код_использования(
    monkeypatch: pytest.MonkeyPatch,
    стабильный_прогон: str,
) -> None:
    del стабильный_прогон
    сессия = _СессияНаблюдатель()
    код, вывод, _ошибки = прогон(monkeypatch, сессия, argv=["--yes"], stdin_text="")
    assert код == first_account.EXIT_USAGE
    assert "не получено" in вывод
    assert сессия.вызовы == ["rollback", "close"]


# ─── адрес базы ───────────────────────────────────────────────────────────────────────────────


def test_адрес_базы_не_принимается_позиционным_аргументом() -> None:
    """Позиционный аргумент — не адрес: парсер его не знает, процесс уходит в отказ argparse."""
    with pytest.raises(SystemExit) as выход:
        first_account.main([_DSN_FRAGMENT])
    assert выход.value.code == first_account.EXIT_USAGE


def test_без_адреса_базы_завод_останавливается(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ни `TBOT_DB_URL`, ни файла `db_url` — отказ до обращения к таблице.

    `TBOT_SECRETS_DIR` переводится в несуществующий каталог: иначе проверка зависела бы от
    настоящих секретов машины, на которой она запущена.
    """
    monkeypatch.setenv("TBOT_SECRETS_DIR", str(tmp_path / "пусто"))
    вывод = io.StringIO()
    assert first_account.build_session_factory(вывод) is None
    текст = вывод.getvalue()
    assert "не настроен" in текст
    assert _DSN_FRAGMENT not in текст

    ошибки = io.StringIO()
    код = first_account.main(
        ["--yes"],
        stdin=io.StringIO(f"{_LOGIN}\n{_EMAIL}\n"),
        stdout=io.StringIO(),
        stderr=ошибки,
    )
    assert int(код) == first_account.EXIT_ENV
