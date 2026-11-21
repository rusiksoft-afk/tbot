"""Смена пароля в `apps/web`: офлайновая половинка (репозиторий в памяти) — `T-102`, остаток среза `R3f`.

Закрывает последнюю незакрытую строку матрицы §8.8 — «смена пароля отзывает сессии» (уровень
«интеграционный»). До этого среза домен `packages.identity.sessions.change_password` был написан и
проверен юнитами (первый срез `T-102`), но вызвать его было некому: маршрута смены пароля в консоли
не существовал. Юнит подтверждает, что функция умеет; интеграционный — что приложение делает это по
запросу пользователя.

Что держит эта половинка (`web_support.MemoryStore`, тот же протокол `Store`, что у `SqlStore`):

* охрану маршрута целиком: живая сессия + шаг `'full'` (§8.2), CSRF-токен (§8.8), счётчик частоты
  пользователя (§8.3, `ADR-007`) — и то, что `GET` счётчик не расходует;
* порядок шагов (§8.1, §8.2, `T-101`): пустая форма и несовпадение повтора отказывают **до**
  сравнения текущего пароля; пока блокировка активна, текущий пароль не сравнивается вообще;
* неудачу: неверный текущий пароль двигает счётчик неудач учётной записи так же, как вход, иначе
  эта форма стала бы не ограниченным нигде способом подбирать текущий пароль;
* отказ политики нового пароля (§8.1): хэш и чужие сеансы остаются нетронутыми;
* успех (§8.1 + §8.3): текущий сеанс пересоздаётся с новым значением куки, прежний ключ перестаёт
  быть живым немедленно, прочие сеансы учётной записи отозваны, шаг входа сохранён, в списке
  устройств остаётся ровно один сеанс;
* смежные правила: смена пароля **не** снимает блокировку перебора (`T-101`) и не трогает чужую
  учётную запись (§8.8).

Что остаётся живой половинке — `tests/integration/test_web_sessions_db.py`, шаг job'а `миграции`:
что отзыв виден **новому соединению** (зафиксирован в таблице, а не в identity map), что
`password_hash` и `password_updated_at` изменились именно в строке, что поиск учётной записи уходит
в SQL по `id` (имя из формы в запросе не участвует), и что отозванные строки доживают до другого
соединения с заполненным `revoked_at`. Переносить эти проверки в память нельзя: память не знает ни
`INSERT`, ни ограничений схемы, ни фиксации транзакции.

Время здесь не замораживается: файлу нужны состояния «до/после смены пароля», а не переходы через
границы idle и окон счётчика. Проверки с границами времени — там, где они задуманы
(`test_web_sessions_page.py` с `Clock`, живые файлы с базой).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Final
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.routes.profile import (
    EMPTY_FORM_DETAIL,
    FIELD_CURRENT_PHRASE,
    FIELD_NEW_PHRASE,
    FIELD_REPEAT_PHRASE,
    PAGE_NOTE,
    POLICY_DETAIL_PREFIX,
    REPEAT_MISMATCH_DETAIL,
    WRONG_CURRENT_DETAIL,
)
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import (
    LOGIN_PATH,
    SECURITY_PATH,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    SESSIONS_PATH,
    Principal,
)
from packages.common.config import Settings
from packages.identity.passwords import verify_password
from packages.identity.sessions import advance_auth_step, create_session
from packages.identity.users import new_user, register_login_failure
from packages.storage.models import User, UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
)

#: Новый пароль обязан проходить §8.1 (длина, словарь, «пароль = логин/домен») и отличаться от
#: пароля фикстуры: иначе проверка «старый пароль больше не подходит» теряет смысл.
NEW_PASSWORD: Final = "Новый-рабочий-пароль-2026A"

#: Заведомо короткий: §8.1 требует не меньше 12 символов.
SHORT_PASSWORD: Final = "коротко-9"

#: Пароль, совпадающий с логином учётной записи фикстуры, — отдельное правило §8.1.
LOGIN_EQUAL_PASSWORD: Final = TEST_LOGIN

#: Пароль второй учётной записи: проверка изоляции обязана видеть, что он не изменился.
FOREIGN_PASSWORD: Final = "Чужой-пароль-для-проверки-2026"
FOREIGN_LOGIN: Final = "chuzhaya.r3f"

#: Маркер устройства входа: `user_agent` пишется в запись сессии как получен и печатается в списке
#: устройств (§8.3), поэтому по нему проверка узнаёт «наш» сеанс.
DEVICE_OWN: Final = "laptop-r3f"
DEVICE_OTHER: Final = "телефон-до-смены"


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    owner = memory.seed_user()
    # Первичный ключ заполняется явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не
    # срабатывает, и `user.id` остался бы `None`. С `None` проверка изоляции (§8.8) сравнивала бы
    # `None` с `None` и проходила бы молча — тот же урок, что с `failed_attempts` в `T-101`.
    owner.id = uuid.uuid4()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> Iterator[TestClient]:
    """Боевое приложение с репозиторием в памяти и щупом охраняемого маршрута.

    Щуп `probe-full` нужен, чтобы проверить «прежний ключ сеанса мёртв» тем же механизмом, каким
    охраняются боевые маршруты консоли, а не отдельной самодеятельной проверкой: направление отказа
    обязан давать общий слой входа (§8.3, срез `R3b`).
    """
    with build_client(store, settings, with_probe=True) as test_client:
        yield test_client


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _войти(client: TestClient) -> str:
    """Войти (шаг `'password'`) с маркером устройства и вернуть значение куки."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": "https://testserver", "User-Agent": DEVICE_OWN},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    assert secret, "после входа куки нет"
    return secret


def _сеанс(store: MemoryStore, secret: str) -> UserSession:
    record = store.find_by_secret(secret)
    assert record is not None, "сеанса с такой кукой в репозитории нет"
    return record


def _учётка(store: MemoryStore, record: UserSession) -> User:
    account = store.user_of_id(record.user_id)
    assert account is not None, "учётной записи сеанса в репозитории нет"
    return account


def _полный(store: MemoryStore, secret: str) -> UserSession:
    """Поднять шаг до `'full'`: страницы ввода кода нет до `T-103`.

    Правка идёт по объекту в репозитории, а не маршрутом: проверять несуществующий маршрут — значит
    проверять выдумку, а не охрану (§8.2).
    """
    record = _сеанс(store, secret)
    advance_auth_step(record, step="full")
    return record


def _выпустить(store: MemoryStore, user_id: UUID, *, device: str) -> UserSession:
    """Выпустить сеанс мимо HTTP (так его выпустит `T-117`) и положить в репозиторий.

    Шаг `'full'` задаётся сразу: до `T-103` поднять его маршрутом нельзя, а проверке нужен именно
    живой сеанс другого устройства, а не способ его охранять.
    """
    issued = create_session(
        user_id,
        ip="198.51.100.7",
        user_agent=device,
        auth_step="full",
        now=None,
    )
    issued.record.created_at -= timedelta(minutes=4)
    store.add(issued.record)
    return issued.record


def _чужая_учётка(store: MemoryStore) -> User:
    foreign = new_user(
        login=FOREIGN_LOGIN, password=FOREIGN_PASSWORD, role="operator", state="active"
    )
    foreign.id = uuid.uuid4()
    store.add(foreign)
    return foreign


def _токен(secret: str, record: UserSession) -> str:
    return expected_token(Principal(session=record, secret=secret))


def _смена(
    client: TestClient,
    secret: str,
    record: UserSession,
    *,
    current: str,
    new: str,
    repeat: str,
    origin: str = "https://testserver",
    presented: str | None = None,
) -> Response:
    """Отправить форму смены пароля так, как её отправляет браузер (urlencoded, `Origin`).

    Имя параметра — `presented`, а не `token="auto"`: анализатор читает параметр со значением по
    умолчанию как жёстко заданный секрет (S107), а выводимые CSRF-токены — как раз секреты (§8.4).
    """
    data = {
        CSRF_FORM_FIELD: _токен(secret, record) if presented is None else presented,
        FIELD_CURRENT_PHRASE: current,
        FIELD_NEW_PHRASE: new,
        FIELD_REPEAT_PHRASE: repeat,
    }
    response: Response = client.post(
        SECURITY_PATH, data=data, headers={"Origin": origin}, follow_redirects=False
    )
    return response


def _пустая_мутация(client: TestClient, presented: str) -> Response:
    """Запрос той же мутации с пустой формой: счётчик уже посчитан, дорогой работы нет."""
    ответ: Response = client.post(
        SECURITY_PATH,
        data={
            CSRF_FORM_FIELD: presented,
            FIELD_CURRENT_PHRASE: "",
            FIELD_NEW_PHRASE: "",
            FIELD_REPEAT_PHRASE: "",
        },
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    return ответ


def _живые(store: MemoryStore, user_id: UUID) -> tuple[UserSession, ...]:
    return tuple(
        row for row in store.sessions() if row.user_id == user_id and row.revoked_at is None
    )


# ─── охрана маршрута (§8.2, §8.8, §8.3) ──────────────────────────────────────────────────────


def test_без_живой_сессии_страницы_нет(client: TestClient) -> None:
    response = client.get(SECURITY_PATH, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == LOGIN_PATH


def test_шаг_password_не_рисует_форму(client: TestClient, store: MemoryStore) -> None:
    """§8.2: вход только с паролем не получает доступа к смене пароля.

    Токен на шаге `'password'` выводится (сессия есть), поэтому отказ не может держаться на CSRF:
    нужен именно шаг входа. Иначе «знаю пароль» означало бы «могу сменить пароль и выгнать все
    живые входы владельца» — отказ в обслуживании вместо защиты.
    """
    secret = _войти(client)
    assert _сеанс(store, secret).auth_step == "password"
    response = client.get(SECURITY_PATH, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == LOGIN_PATH
    assert FIELD_NEW_PHRASE not in response.text


def test_страница_на_шаге_full_несёт_форму_и_объяснение(
    client: TestClient, store: MemoryStore
) -> None:
    secret = _войти(client)
    _полный(store, secret)
    page = client.get(SECURITY_PATH)
    assert page.status_code == 200
    for name in (FIELD_CURRENT_PHRASE, FIELD_NEW_PHRASE, FIELD_REPEAT_PHRASE):
        assert f'name="{name}"' in page.text, f"поля {name} на странице нет"
    assert 'type="password"' in page.text, "поля обязаны быть type=password (§8.4)"
    assert CSRF_FORM_FIELD in page.text, "токен переносится скрытым полем (ADR-008)"
    assert PAGE_NOTE in page.text, "последствие смены пароля обязано быть видно до действия (§8.1)"


def test_страница_не_печатает_материал_сеанса(client: TestClient, store: MemoryStore) -> None:
    """§8.4: значение куки и его хэш в HTML не попадают."""
    secret = _войти(client)
    record = _полный(store, secret)
    page = client.get(SECURITY_PATH)
    assert secret not in page.text
    assert record.token_hash not in page.text


def test_get_не_расходует_счётчик_частоты(client: TestClient, store: MemoryStore) -> None:
    """§8.3: предел держит мутации; лимит на просмотр страницы — способ устроить отказ человеку,
    который обновил страницу."""
    secret = _войти(client)
    _полный(store, secret)
    for _ in range(3):
        assert client.get(SECURITY_PATH).status_code == 200
    assert not store.buckets(), "GET не обязан двигать окна счётчика"


def test_без_токена_403_и_пароль_не_изменён(client: TestClient, store: MemoryStore) -> None:
    """Матрица §8.8: мутация без CSRF-токена → 403, состояние не меняется."""
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    hash_before = account.password_hash
    other = _выпустить(store, record.user_id, device=DEVICE_OTHER)

    response = client.post(
        SECURITY_PATH,
        data={
            FIELD_CURRENT_PHRASE: TEST_PASSWORD,
            FIELD_NEW_PHRASE: NEW_PASSWORD,
            FIELD_REPEAT_PHRASE: NEW_PASSWORD,
        },
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 403, response.text
    assert account.password_hash == hash_before
    assert other.revoked_at is None, "отказ токена не имеет права отзывать сеансы"


def test_чужой_источник_отклонён_до_сравнения_пароля(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.3 «проверка origin»: запрос с чужого источника не меняет учётную запись (§8.8)."""
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    hash_before = account.password_hash

    response = _смена(
        client,
        secret,
        record,
        current=TEST_PASSWORD,
        new=NEW_PASSWORD,
        repeat=NEW_PASSWORD,
        origin="https://evil.example",
    )
    assert response.status_code == 403, response.text
    assert account.password_hash == hash_before


# ─── порядок шагов: пустая форма, повтор, блокировка (§8.1, §8.2, `T-101`) ────────────────────


def test_пустая_форма_400_и_живые_сеансы_не_трогаются(
    client: TestClient, store: MemoryStore
) -> None:
    secret = _войти(client)
    record = _полный(store, secret)
    other = _выпустить(store, record.user_id, device=DEVICE_OTHER)

    response = _смена(client, secret, record, current="", new="", repeat="")
    assert response.status_code == 400, response.text
    assert EMPTY_FORM_DETAIL in response.text
    assert other.revoked_at is None


def test_повтор_не_совпал_400_до_сравнения_текущего_и_без_счётчика_неудач(
    client: TestClient, store: MemoryStore
) -> None:
    """Опечатка в повторе — не неудача подбора: счётчик перебора её не двигает (§8.1, `T-101`).

    Состояние «текущий пароль не подошёл» двигает счётчик неудач, а несовпадение повтора — нет:
    иначе обычная опечатка пользователя приближала бы блокировку учётной записи.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    attempts_before = account.failed_attempts

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat="другое-значение"
    )
    assert response.status_code == 400, response.text
    assert REPEAT_MISMATCH_DETAIL in response.text
    assert account.failed_attempts == attempts_before
    assert verify_password(password=TEST_PASSWORD, stored_hash=account.password_hash)


def test_неверный_текущий_пароль_401_и_двигает_счётчик_неудач(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.1 «только с текущим паролем» + `T-101`: подбор текущего пароля ограничен, как вход.

    Иначе форма, доступная с живым сеансом, стала бы способом подбирать текущий пароль в обход
    счётчика входа.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    other = _выпустить(store, record.user_id, device=DEVICE_OTHER)

    response = _смена(
        client,
        secret,
        record,
        current="заведомо-не-этот-пароль",
        new=NEW_PASSWORD,
        repeat=NEW_PASSWORD,
    )
    assert response.status_code == 401, response.text
    assert WRONG_CURRENT_DETAIL in response.text
    assert account.failed_attempts == 1
    assert other.revoked_at is None, "отказ не имеет права отзывать чужие сеансы"
    assert verify_password(password=TEST_PASSWORD, stored_hash=account.password_hash)


def test_блокировка_мешает_сменить_пароль_и_пароль_не_сравнивается(
    client: TestClient, store: MemoryStore
) -> None:
    """Пятая неудача закрывает и этот маршрут; при активной блокировке сравнения нет вообще.

    Порядок тот же, что на входе (`T-101`): `ensure_login_allowed` **до** сравнения. Иначе
    блокировка оставляла бы канал для проверки угаданных текущих паролей — ровно то, ради чего её
    ставят.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)

    for _ in range(4):
        wrong = _смена(
            client, secret, record, current="заведомо-не-тот", new=NEW_PASSWORD, repeat=NEW_PASSWORD
        )
        assert wrong.status_code == 401

    fifth = _смена(
        client, secret, record, current="заведомо-не-тот", new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert fifth.status_code == 429, fifth.text
    assert "Retry-After" in fifth.headers, "ADR-007: срок ожидания — часть ответа"
    assert "заблокирован" in fifth.text, "отказ обязан объяснять состояние, а не молчать (§9)"
    assert "/locked?reason=attempts" in fifth.text, "ссылка на страницу состояния (§9)"

    correct_attempt = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert correct_attempt.status_code == 429, "пока блокировка активна, смена недоступна"
    assert not verify_password(password=NEW_PASSWORD, stored_hash=account.password_hash)


# ─── политика нового пароля (§8.1) ───────────────────────────────────────────────────────────


def test_слабый_новый_пароль_400_и_хэш_не_изменён(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    hash_before = account.password_hash

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=SHORT_PASSWORD, repeat=SHORT_PASSWORD
    )
    assert response.status_code == 400, response.text
    assert POLICY_DETAIL_PREFIX in response.text, "причину отказа политики показывать (§9)"
    assert "длина меньше" in response.text, "отказ обязан называть нарушенное правило §8.1"
    assert account.password_hash == hash_before


def test_пароль_совпадающий_с_логином_отклонён(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client)
    record = _полный(store, secret)
    response = _смена(
        client,
        secret,
        record,
        current=TEST_PASSWORD,
        new=LOGIN_EQUAL_PASSWORD,
        repeat=LOGIN_EQUAL_PASSWORD,
    )
    assert response.status_code == 400, response.text
    assert "с логином или доменом" in response.text


def test_отказ_политики_не_трогает_чужие_сеансы(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client)
    record = _полный(store, secret)
    other = _выпустить(store, record.user_id, device=DEVICE_OTHER)
    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=SHORT_PASSWORD, repeat=SHORT_PASSWORD
    )
    assert response.status_code == 400
    assert other.revoked_at is None


# ─── успех: §8.1 (отзыв остальных) + §8.3 (пересоздание после критичного действия) ────────────


def test_смена_пароля_отзывает_остальные_сеансы(client: TestClient, store: MemoryStore) -> None:
    """Строка §8.8 в офлайновой половинке: отзываем ровно тот набор, который видит страница.

    Живая половинка (тот же сценарий на PostgreSQL) проверяет, что `revoked_at` зафиксирован в
    таблице и виден новому соединению; здесь проверяются набор кандидатов и его видимость
    пользователю.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    other = _выпустить(store, record.user_id, device=DEVICE_OTHER)
    foreign = _чужая_учётка(store)
    foreign_session = _выпустить(store, foreign.id, device=DEVICE_OTHER)

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == SESSIONS_PATH, "результат виден на списке сеансов (§8.3)"

    assert other.revoked_at is not None, "прочие сеансы обязаны быть отозваны (§8.1)"
    assert _сеанс(store, secret).revoked_at is not None, "прежняя запись отзывается пересозданием"
    assert foreign_session.revoked_at is None, "чужая учётная запись не затронута (§8.8)"

    live = _живые(store, record.user_id)
    assert len(live) == 1, f"живых сеансов этой учётной записи должен быть один: {len(live)}"
    new_cookie = session_cookie(client)
    assert new_cookie, "новое значение куки не выставлено"
    assert new_cookie != secret, "значение куки обязано смениться (§8.3)"
    assert live[0].token_hash != record.token_hash


def test_прежний_ключ_сеанса_перестаёт_быть_живым_немедленно(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.3: украденное прежнее значение не должно пережить смену пароля.

    Проверка идёт через охрану маршрута (щуп), а не через прямой вызов домена: направление отказа
    обязан давать тот же механизм, который охраняет консоль, иначе «кто ушёл и куда» начало бы
    различаться в зависимости от пути дохода (`R3e`, §8.3).
    """
    secret = _войти(client)
    record = _полный(store, secret)
    _смена(client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD)

    client.cookies.set(SESSION_COOKIE_NAME, secret)
    guard = client.get("/probe-full", follow_redirects=False)
    assert guard.status_code == 302
    assert SESSION_EXPIRED_PATH in guard.headers["location"]
    assert "reason=revoked" in guard.headers["location"], "причина — отзыв, а не срок (§8.3)"


def test_новый_сеанс_жив_и_сохраняет_шаг_входа(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client)
    record = _полный(store, secret)
    _смена(client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD)

    new_cookie = session_cookie(client)
    assert new_cookie
    guard = client.get("/probe-full", follow_redirects=False)
    assert guard.status_code == 200, "новый сеанс обязан быть живым"
    assert guard.json()["step"] == "full", "шаг входа сохраняется: критичное действие подтверждено"

    issued = _сеанс(store, new_cookie)
    assert issued.user_id == record.user_id
    assert issued.user_agent == DEVICE_OWN, "устройство новой записи — то же (§8.3, список)"


def test_атрибуты_куки_после_смены_те_же_что_при_входе(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.3: HttpOnly/Secure/SameSite ставит один вывод куки, а не две реализации."""
    secret = _войти(client)
    record = _полный(store, secret)
    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    cookie = response.headers["set-cookie"]
    assert SESSION_COOKIE_NAME in cookie
    assert "httponly" in cookie.lower()
    assert "secure" in cookie.lower()
    assert "samesite=lax" in cookie.lower()


def test_старый_пароль_больше_не_подходит_а_новый_подходит(
    client: TestClient, store: MemoryStore, settings: Settings
) -> None:
    """Смена меняет хэш, а не только состояние сеансов: вход проверяется боевым маршрутом."""
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    _смена(client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD)

    assert verify_password(password=NEW_PASSWORD, stored_hash=account.password_hash)
    assert not verify_password(password=TEST_PASSWORD, stored_hash=account.password_hash)
    assert account.password_updated_at is not None, "момент смены пароля фиксируется (§8.1)"

    with build_client(store, settings) as другой:
        отказ = другой.post(
            "/login",
            data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
            headers={"Origin": "https://testserver"},
            follow_redirects=False,
        )
        assert отказ.status_code == 401, "старый пароль обязан быть неверным"

        вход = другой.post(
            "/login",
            data={"login": TEST_LOGIN, "password": NEW_PASSWORD},
            headers={"Origin": "https://testserver"},
            follow_redirects=False,
        )
        assert вход.status_code == 302, "новый пароль обязан войти"


def test_смена_пароля_не_снимает_блокировку_перебора(
    client: TestClient, store: MemoryStore
) -> None:
    """`T-101`: если смена пароля снимает блокировку, перебор обходится сменой пароля.

    Блокирующее окно здесь уже снято вручную (иначе маршрут ответил бы `429` и проверять было бы
    нечего), но счётчик неудач обязан остаться: «разблокировался сменой пароля» означало бы, что
    перебор можно чередовать со сменой пароля.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    account = _учётка(store, record)
    register_login_failure(account)
    register_login_failure(account)
    account.locked_until = None
    assert account.failed_attempts == 2

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text
    assert account.failed_attempts == 2, "счётчик неудач сменой пароля не обнуляется"


def test_чужая_учётная_запись_не_затронута(client: TestClient, store: MemoryStore) -> None:
    """§8.8: форма не содержит имени учётной записи, поэтому менять чужой пароль нечем."""
    secret = _войти(client)
    record = _полный(store, secret)
    foreign = _чужая_учётка(store)
    hash_before = foreign.password_hash

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302
    assert foreign.password_hash == hash_before
    assert not verify_password(password=NEW_PASSWORD, stored_hash=foreign.password_hash)
    assert store.user_of_id(foreign.id) is foreign


# ─── счётчик частоты (§8.3, `ADR-007`) ───────────────────────────────────────────────────────


def test_мутация_учтена_счётчиком_пользователя(client: TestClient, store: MemoryStore) -> None:
    """§8.3: 60 мутаций в минуту на пользователя; ключ — `id` учётной записи, а не адреса."""
    secret = _войти(client)
    record = _полный(store, secret)
    _пустая_мутация(client, _токен(secret, record))
    окна = {(scope, key): attempts for (scope, key, _start), attempts in store.buckets().items()}
    assert окна.get(("mutation_user", str(record.user_id))) == 1


def test_шестьдесят_первая_мутация_в_окне_отказывается_429(
    client: TestClient, store: MemoryStore
) -> None:
    """Предел счётчика достижим на настоящем маршруте, а не только на щупе.

    Форма заведомо пустая: отказ по пустоте дёшев (без сравнения Argon2id), а счётчик уже посчитан
    — ровно так же, как на входе в срезе `R3d`. Так проверка утверждает, что лимит стоит **до**
    дорогой работы.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    presented = _токен(secret, record)

    for попытка in range(60):
        ответ = _пустая_мутация(client, presented)
        assert ответ.status_code == 400, f"предел сработал раньше: попытка {попытка + 1}"

    сорок_первый = _пустая_мутация(client, presented)
    assert сорок_первый.status_code == 429, сорок_первый.text
    assert "Retry-After" in сорок_первый.headers


def test_список_сеансов_после_смены_показывает_один_сеанс(
    client: TestClient, store: MemoryStore
) -> None:
    """Видимый результат смены (§8.3, §9.3 п. 4): на списке остался ровно текущий сеанс."""
    secret = _войти(client)
    record = _полный(store, secret)
    _выпустить(store, record.user_id, device=DEVICE_OTHER)
    _смена(client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD)

    page = client.get(SESSIONS_PATH)
    assert page.status_code == 200
    assert DEVICE_OTHER not in page.text, "отозванный сеанс не должен оставаться в списке (§8.3)"
    assert DEVICE_OWN in page.text


def test_временной_шаг_не_влияет_на_набор_кандидатов_при_обычном_сценарии(
    client: TestClient, store: MemoryStore
) -> None:
    """Сеанс, выпущенный вне HTTP (`T-117`), отзывается наравне с выпущенным входом.

    Повтор `R3e` на материале смены пароля: §8.1 не делает различия между «вход с телефона» и
    «привязка Telegram» — отзываем все живые сеансы учётной записи, независимо от того, кем они
    выпущены.
    """
    secret = _войти(client)
    record = _полный(store, secret)
    link = _выпустить(store, record.user_id, device="telegram-link")
    assert link.user_agent == "telegram-link"

    response = _смена(
        client, secret, record, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302
    assert link.revoked_at is not None
