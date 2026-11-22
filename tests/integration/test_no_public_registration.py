"""Самостоятельной регистрации нет: сканирование маршрутов (TZ §1.2, `REQ-identity-02`,
задача `T-105`, срез `R7a`, `ADR-020` п. 2).

У задачи `T-105` две проверки: `test_no_public_registration` (сканирование маршрутов) и
`test_invitation_flow`. Здесь первая. Вторая требует страницу принятия приглашения и маршруты
администратора и перенесена вместе с ними в срез `R7b` (`docs/HANDOFF.md` §2).

Почему проверка выглядит именно так.

* **Сканируется таблица маршрутов готового приложения, а не текст файлов.** Приложение строится
  боевым `create_app`, поэтому в списке оказываются маршруты, подключённые роутерами, и пути к ним
  уже сложены с префиксами. Читать исходники проще, но маршрут может быть объявлен в одном файле,
  а подключён в другом, и проверка по тексту его пропустила бы.
* **Источник — открытая схема (`app.openapi()`), а не внутренние списки
  маршрутов.** В FastAPI 0.165 подключение роутера лежит в `_IncludedRouter`, а полный путь
  достаётся через `effective_candidates()` — то есть через детали реализации, которые
  меняются от релиза к релизу. Проверка, которая падает на апдейте зависимости, а не на
  появлении маршрута регистрации, через полгода будет удалена — а запрет останется.
* **Порог — любой метод, а не только `POST`.** Открытая страница регистрации — это `GET` с формой:
  человек увидит её и без записи. Проверять только запись — значит проверить половину запрета §1.2.
* **Отсутствие проверяется и списком, и поведением.** Список маршрутов отвечает на вопрос «маршрута
  нет»; пустая таблица учётных записей после серии запросов — на вопрос «строка не появилась ни
  одним запросом». Второго в списке маршрутов нет: приложение без маршрута регистрации всё равно
  может создать строку, например из обработчика отказа входа.
* **Исключение будет, и оно будет записано явно.** §1.2 допускает путь, где человек сам задаёт
  пароль, — приём приглашения по одноразовой ссылке. Когда `R7b` добавит такой маршрут, сюда
  придётся вписать исключение, привязанное к **значению ссылки** в адресе: адрес, принимаемый без
  секрета, перестаёт быть приглашением и становится регистрацией (`ADR-020` п. 3).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI

from apps.web.main import create_app
from packages.common.config import Settings
from tests.integration.web_support import MemoryStore, build_client

#: Имена, означающие «самостоятельную регистрацию». Список собран из формулировки §1.2
#: («самостоятельной регистрации нет»), а не из того, что сейчас есть в приложении: маршрут могут
#: назвать `register`, `signup`, `join` или `new-account`, и проверка обязана поймать любой вариант.
OPEN_REGISTRATION_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)(?:register|registration|signup|sign-up|join|new-account|create-account"
    r"|account/new|accounts/new|invite-me|request-access)(?:/|$)",
    re.IGNORECASE,
)

#: Исключение, которого пока нет. Записано заранее и пустое намеренно: пустой список — часть
#: проверки, а не её отсутствие. Маршрут принятия приглашения попадёт сюда только вместе с
#: секретом в адресе (`ADR-020` п. 3), иначе он нарушает §1.2.
ACCEPTANCE_EXCEPTIONS: frozenset[str] = frozenset()

#: Публичные адреса, на которых пробуют зарегистрироваться. Отдельно от узора: список адресов ловит
#: маршрут, названный нетипично, но ведущий себя как регистрация, — узор его не поймает, а
#: успешный ответ поймает вторая проверка.
PROBED_PATHS: tuple[str, ...] = (
    "/register",
    "/registration",
    "/signup",
    "/join",
    "/account/new",
    "/accounts/new",
    "/create-account",
    "/invite-me",
    "/request-access",
    "/admin/users/new",
)


def _operations(app: FastAPI) -> Iterator[tuple[str, str]]:
    """Пары (`путь`, `метод`) из открытой схемы приложения.

    Схема — публичный контракт FastAPI, и она устойчива к версии: внутренние списки маршрутов
    (`app.routes`) в FastAPI 0.165 лежат в `_IncludedRouter` и раскрываются через
    `effective_candidates()`, то есть через детали реализации, которые меняются от релиза к релизу.
    Проверка, которая падает на апдейте зависимости, а не на появлении маршрута регистрации, — это
    проверка, которую через полгода удалят.

    Чего схема не показывает: маршрутов, объявленных с `include_in_schema=False`. Этот зазор
    закрывает отдельная проверка по исходникам ниже.
    """
    schema = app.openapi()
    for path, item in schema["paths"].items():
        for method in item:
            yield path, method.upper()


def test_в_схеме_маршрутов_нет_открытой_регистрации(settings: Settings) -> None:
    """`test_no_public_registration` в формулировке todo: «сканирование маршрутов» (§1.2)."""
    hits = [
        (path, method)
        for path, method in _operations(create_app(settings))
        if OPEN_REGISTRATION_RE.search(path) and path not in ACCEPTANCE_EXCEPTIONS
    ]
    assert not hits, f"маршруты открытой регистрации: {hits}"


def test_приложение_не_прячет_маршруты_от_схемы() -> None:
    """Зазор предыдущей проверки закрыт по исходникам: `include_in_schema=False` в `apps/web` нет.

    Без этого пункта маршрут `/register`, объявленный со `include_in_schema=False`, был бы невидим
    для схемы и зелёной проверки хватало бы, чтобы его пропустить. Правка сама по себе законна
    (скрывать служебный маршрут можно), но тогда она обязана быть замечена: текст ошибки говорит,
    что вместе с сокрытием нужно вписать адрес в явный список исключений.
    """
    root = Path(__file__).resolve().parents[2] / "apps" / "web"
    hidden = sorted(
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if re.search(r"include_in_schema\s*=\s*False", line)
    )
    assert not hidden, f"маршруты, скрытые от схемы: {hidden}"


@pytest.mark.parametrize("path", PROBED_PATHS)
def test_публичный_запрос_не_создаёт_учётную_запись(settings: Settings, path: str) -> None:
    """Ни один публичный адрес не создаёт строку `users`: пустой репозиторий остаётся пустым.

    Здесь проверяется ровно то, чего список маршрутов не доказывает: что ни один ответ не имеет
    побочного эффекта. Учётная запись в приложении создаётся только двумя путями — доменным
    `new_user` (из маршрута администратора) и `user_from_invitation` (из приёма ссылки), и оба
    обязаны требовать действие администратора или секрет ссылки (§1.2).
    """
    store = MemoryStore()
    client = build_client(store, settings)

    form = {"login": "self.served", "password": "Придуманный-пароль-2026", "email": "me@example.ru"}
    get_response = client.get(path)
    post_response = client.post(path, data=form, headers={"Origin": "https://testserver"})

    assert get_response.status_code in (
        404,
        405,
    ), f"{path}: форма отвечает {get_response.status_code}"
    assert post_response.status_code in (
        404,
        405,
    ), f"{path}: запись отвечает {post_response.status_code}"
    assert store.accounts() == (), f"{path}: появились учётные записи {store.accounts()}"
    assert store.commits == 0, "обработчик не обязан фиксировать транзакцию, ничего не создав"
