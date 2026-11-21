"""Лимиты частоты запросов и бан адреса на HTTP-уровне (TZ §8.2, §8.3; `T-102`, срез `R3d`).

Половинка в памяти: приложение боевое (`create_app`), репозиторий — `MemoryStore`. Проверяется
поведение слоя входа: порядок проверок, код `429`, заголовок `Retry-After`, код причины `rate`,
независимость счётчиков по адресам и пользователям, смена окна и истечение бана.

Время в проверках подменено (`Clock`): окна счётчика выравниваются по часам, и без подмены
проверки зависели бы от того, на какую секунду минутного окна пришлось выполнение теста, —
то есть стали бы нестабильными. Тот же приём, что у домена сессий («время берётся из `utc_now()`,
а тесты подменяют саму функцию»).

Атомарность инкремента (`INSERT … ON CONFLICT DO UPDATE`), закрытый перечень областей и окон,
длина ключа, срок бана из полей строки и сама чистка окон проверяются на живом PostgreSQL —
`tests/integration/test_rate_limit_mechanism_db.py` (job `migrations`). Переносить их в память
нельзя: память не проверяет ни `INSERT`, ни ограничения схемы, ни фиксацию транзакции.

Что держится этими проверками и почему именно так:

* **лимит считает запросы, а не неудачи** (§8.3 формулирует «10 запросов/мин/IP»): пустая форма и
  неверный пароль стоят одинаково, иначе лимит обходится мусорными запросами;
* **ключ — адрес из правого элемента `X-Forwarded-For`** (`ADR-007`, `ADR-009`): другой адрес —
  другой счётчик; адреса нет — счётчика нет (общий ключ «неизвестно кто» дал бы бан всем, у кого
  заголовка не было);
* **зона отказа — только слой входа** (ask `ba6a9076`): бан адреса не трогает уже аутентифицированные
  сессии и остальные маршруты;
* **отказ по частоте наступает до проверки пароля**, иначе лимит не защищает от того, ради чего
  он поставлен (стоимость Argon2id на перебор);
* **отказ CSRF не двигает счётчик мутаций** (`ADR-008`): иначе подделка запроса расходовала бы
  лимит жертвы.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.login as login_routes
import apps.web.routes.sessions as session_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.routes.login import EMPTY_FORM_DETAIL, GENERIC_FAILURE_DETAIL
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.headers import SECURITY_HEADERS
from apps.web.security.rate_limit import (
    IP_BAN_DURATION,
    IP_BAN_SCOPE,
    IP_BAN_THRESHOLD,
    LOGIN_IP_SCOPE,
    MUTATION_USER_SCOPE,
    RATE_LIMITS,
    TOTP_IP_SCOPE,
    TOTP_SESSION_SCOPE,
    align_window_start,
)
from apps.web.security.sessions import (
    LOCK_REASON_ATTEMPTS,
    LOCK_REASON_RATE,
    LOCKED_PATH,
    REASON_QUERY,
    Principal,
)
from packages.common.config import Settings
from packages.identity.sessions import advance_auth_step
from packages.identity.users import MAX_FAILED_ATTEMPTS
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
)
from tests.integration.web_support import (
    login as login_ok,
)

#: Адреса TEST-NET-3 (RFC 5737): не маршрутизируемые, не пересекаются с реальными стендами.
ADDR_A = "203.0.113.11"
ADDR_B = "203.0.113.12"
ORIGIN = "https://testserver"

LOGIN_LIMIT = RATE_LIMITS[LOGIN_IP_SCOPE]
MUTATION_LIMIT = RATE_LIMITS[MUTATION_USER_SCOPE]

#: Замороженный момент: текущее время с усечением до секунды, фиксация
#: один раз при импорте. Границы окон выводятся из него, а не задаются
#: буквально: иначе проверки зависели бы от того, на какую секунду минутного (и
#: пятиминутного) окна пришлось их выполнение, и «зелёное» прохождение
#: чередовалось бы с падением.
#:
#: Момент обязан остаться «сейчас или чуть раньше», а не браться из прошлого
#: года: там, где тест вызывает доменные функции напрямую (без подмены), домен
#: сравнивает `created_at` созданной приложением сессии с реальными часами и на
#: будущее расхождение реагирует отказом (`ensure_session_active`).
FROZEN = datetime.now(UTC).replace(microsecond=0)
MINUTE_WINDOW_START = FROZEN.replace(second=0)
MINUTE_WINDOW_END = MINUTE_WINDOW_START + timedelta(minutes=1)
BAN_WINDOW_START = align_window_start(FROZEN, 300)

#: `Retry-After` для отказа внутри текущего окна минуты: до его конца.
RETRY_AT_WINDOW = max(1, int((MINUTE_WINDOW_END - FROZEN).total_seconds()))
#: Срок бана выводится из строки: `window_start + 300 с + IP_BAN_DURATION` (`ADR-009`).
#: Отсюда он больше 900 ровно на остаток окна перебора: неудача, закрывшая
#: адрес, пришла не в начале окна, а само окно ещё не закрылось.
BAN_UNTIL = BAN_WINDOW_START + timedelta(seconds=300) + IP_BAN_DURATION
RETRY_AT_BAN = max(1, int((BAN_UNTIL - FROZEN).total_seconds()))


class Clock:
    """Подменённое «сейчас»: тест сам сдвигает время, когда имитирует смену окна."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def move_to(self, moment: datetime) -> None:
        """Переставить «сейчас» на нужный момент.

        Границы окон обязан задавать тест, а не момент его запуска: произвольный сдвиг на
        «минуту с запасом» проходил бы только при удачной секунде запуска и падал бы при другой,
        то есть был бы нестабильной проверкой.
        """
        self.now = moment


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях срезa, где он вызывается.

    Подменяются четыре модуля, а не один: момент берут маршрут входа, маршрут выхода, слой сессий
    (проверка срока и продление idle) и механизм лимитов (выравнивание окна). Пропуск любого из
    них означал бы, что половина проверок живёт в замораживаемом времени, а половина — в реальном,
    и вывод по ним был бы неотличим от случайности.
    """
    fake = Clock(FROZEN)
    for module in (login_routes, session_routes, security_sessions, rate_limit_module):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    memory.seed_user()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock) -> Iterator[TestClient]:
    # Каждая HTTP-проверка модуля обязана видеть тот же замороженный момент, из которого выведены
    # границы окон и значения `Retry-After` в ожиданиях: иначе проверка зависела бы от того, на
    # какую секунду минутного окна пришёлся её запуск. Поэтому `clock` — зависимость фикстуры,
    # а не параметр отдельных тестов.
    assert clock() == FROZEN, "момент фикстуры разошёлся с ожиданиями модуля"
    with build_client(store, settings, with_probe=True) as test_client:
        yield test_client


def _login(
    client: TestClient,
    address: str = ADDR_A,
    *,
    login_value: str = TEST_LOGIN,
    password: str = TEST_PASSWORD,
) -> Response:
    """POST `/login` с адресом в `X-Forwarded-For`: правый элемент — тот, кого лимитируем."""
    response: Response = client.post(
        "/login",
        data={"login": login_value, "password": password},
        headers={"Origin": ORIGIN, "X-Forwarded-For": address},
        follow_redirects=False,
    )
    return response


def _empty_form(client: TestClient, address: str) -> Response:
    """Пустая форма: `400`, счётчик запросов трогает, счётчик неудач — нет.

    Нужен там, где нужно израсходовать лимит частоты, не приближая бан адреса по §8.2.
    """
    response: Response = client.post(
        "/login",
        data={"login": "", "password": ""},
        headers={"Origin": ORIGIN, "X-Forwarded-For": address},
        follow_redirects=False,
    )
    return response


def _locked_link(reason: str) -> str:
    """Ссылка на страницу состояния (§9: у состояния обязан быть отдельный адрес)."""
    return f"{LOCKED_PATH}?{REASON_QUERY}={reason}"


def _attempts(store: MemoryStore, scope: str, key: str) -> int:
    """Сумма счётчиков по области и ключу (окна суммируются: окно одно, но проверка не хрупкая)."""
    return sum(
        attempts
        for (row_scope, row_key, _start), attempts in store.buckets().items()
        if row_scope == scope and row_key == key
    )


def _csrf_of(client: TestClient, store: MemoryStore) -> str:
    """CSRF-токен текущей сессии клиента: выводится из куки и `id` записи (`ADR-008`)."""
    secret = session_cookie(client)
    assert secret, "куки сессии нет — тест вошёл не туда"
    record = store.find_by_secret(secret)
    assert record is not None
    return expected_token(Principal(session=record, secret=secret))


# ─── предел частоты `/login` (§8.3: 10 запросов/мин/IP) ───────────────────────────────────────


def test_одиннадцать_запросов_с_одного_адреса_отвергаются(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.3: `/login` — 10 запросов/мин/IP. Одиннадцатый — `429`, `Retry-After`, объяснение.

    Отказ наступает на одиннадцатом, а не на десятом: лимит разрешает ровно десять запросов.
    Десять первых — пустые формы: они тратят частотный лимит и не двигают окно перебора §8.2,
    поэтому проверяется именно предел запросов, а не наступивший бан.
    """
    for index in range(LOGIN_LIMIT):
        response = _empty_form(client, ADDR_A)
        assert response.status_code == 400, f"запрос {index + 1} отвергнут раньше предела"

    denied = _login(client, ADDR_A)
    assert (
        denied.status_code == 429
    ), "одиннадцатый запрос не отвергнут по лимиту частоты (или лимит не сработал до пароля)"
    assert int(denied.headers["retry-after"]) == RETRY_AT_WINDOW
    assert _locked_link(LOCK_REASON_RATE) in denied.text, "нет ссылки на причину `rate`"
    assert "слишком много" in denied.text.lower(), "отказ не объяснён словами"
    assert (
        _attempts(store, LOGIN_IP_SCOPE, ADDR_A) == LOGIN_LIMIT + 1
    ), "счётчик не отражает реально принятые запросы, включая отказанный"
    assert store.buckets()[(LOGIN_IP_SCOPE, ADDR_A, MINUTE_WINDOW_START)] == LOGIN_LIMIT + 1
    assert (
        not store.sessions()
    ), "сессия выпущена до проверки лимита: отказ по частоте обязан наступать до пароля"
    assert not [
        key for (scope, key, _start) in store.buckets() if scope == IP_BAN_SCOPE
    ], "пустые формы посчитаны как неудачи перебора (§8.2 считает неудачи)"


def test_предел_считает_запросы_а_не_неудачи(client: TestClient, store: MemoryStore) -> None:
    """§8.3 ограничивает запросы: удачный вход стоит столько же, сколько отказ.

    Иначе обход тривиален: мусорные и «удачные» запросы расходуют лимит жертве, а счётчик
    сбрасывался бы каждым успешным входом. Заодно держится §8.1: успех не должен двигать счётчик
    неудач и блокировку.
    """
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None
    for index in range(LOGIN_LIMIT):
        response = _login(client, ADDR_B)
        assert response.status_code == 302, f"вход {index + 1} не прошёл"
    assert _login(client, ADDR_B).status_code == 429, "успешные входы не считались частотой"
    assert len(store.sessions()) == LOGIN_LIMIT, "сессии создаются не по одной на запрос"
    assert user.failed_attempts == 0, "успешные входы тронули счётчик неудач"
    assert user.locked_until is None
    assert len(store.sessions()) == LOGIN_LIMIT


def test_разные_адреса_имеют_разные_счётчики(client: TestClient) -> None:
    """Ключ счётчика — адрес из правого элемента `X-Forwarded-For` (`ADR-007`).

    Разные адреса не мешают друг другу: иначе лимит стал бы отказом для всех клиентов
    провайдерского NAT сразу, хотя §8.3 требует один адрес на подключение.
    """
    for _ in range(LOGIN_LIMIT):
        _empty_form(client, ADDR_A)
    assert _empty_form(client, ADDR_A).status_code == 429
    assert _login(client, ADDR_B).status_code == 302, "лимит адреса A повлиял на адрес B"


def test_ключом_считается_правый_элемент_заголовка(client: TestClient, store: MemoryStore) -> None:
    """Левый элемент присылает клиент, и он подделываем: ключ — правый, который добавил Caddy.

    Иначе перебор защитился бы от лимита, меняя левый элемент: независимых окон было бы столько,
    сколько вариантов заголовка придумано.
    """
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
        headers={"Origin": ORIGIN, "X-Forwarded-For": "198.51.100.1, 203.0.113.13"},
        follow_redirects=False,
    )
    assert response.status_code == 401
    keys = {key for (scope, key, _start) in store.buckets() if scope == LOGIN_IP_SCOPE}
    assert keys == {"203.0.113.13"}, f"ключом стал не правый элемент: {sorted(keys)}"
    # Та же сессия с другим левым элементом — тот же счётчик, а не новое окно.
    client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
        headers={"Origin": ORIGIN, "X-Forwarded-For": "192.0.2.9, 203.0.113.13"},
        follow_redirects=False,
    )
    assert _attempts(store, LOGIN_IP_SCOPE, "203.0.113.13") == 2


def test_без_адреса_счётчика_нет(client: TestClient, store: MemoryStore) -> None:
    """Нет `X-Forwarded-For` — нет ключа: приложение не выдумывает адрес (`ADR-009`).

    Общий ключ «пустой адрес» дал бы один глобальный лимит и общий бан всем, у кого заголовка не
    было (обращение к `web` из внутренней сети состава, отладка, проверки готовности). В боевом
    стенде такого пути нет: `web` наружу не публикуется (`ADR-003`).
    """
    for _ in range(LOGIN_LIMIT + 3):
        response = client.post(
            "/login",
            data={"login": "", "password": ""},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert response.status_code == 400, "без адреса включился какой-то общий счётчик"
    scopes = {scope for (scope, _key, _start) in store.buckets()}
    assert scopes == set(), f"счётчик заведён без адреса: {sorted(scopes)}"


def test_get_страницы_входа_не_расходует_лимит(client: TestClient, store: MemoryStore) -> None:
    """`ADR-007`: счётчик пишется один раз на запрос и не пишется на статике и `GET`.

    Иначе открыть страницу входа — способ израсходовать чужой лимит.
    """
    for _ in range(30):
        assert client.get("/login").status_code == 200
    assert not [key for (scope, key, _start) in store.buckets() if scope == LOGIN_IP_SCOPE]
    assert _login(client).status_code == 302


def test_новое_окно_считается_заново(client: TestClient, clock: Clock) -> None:
    """Отказ опирается на окно, а не на «всего запросов за вечер»: через минуту лимит чист.

    Часы сдвигает сам тест — иначе проверка зависела бы от того, на какую секунду минутного окна
    пришлось её выполнение.
    """
    address = "203.0.113.15"
    for _ in range(LOGIN_LIMIT):
        _empty_form(client, address)
    assert _empty_form(client, address).status_code == 429
    clock.move_to(MINUTE_WINDOW_END)
    after = _empty_form(client, address)
    assert after.status_code == 400, "отказ не снят после смены минутного окна"


# ─── бан адреса (§8.2: 3 неудачи с одного IP за 5 минут) ──────────────────────────────────────


def test_три_неудачи_с_одного_адреса_его_закрывают(client: TestClient, store: MemoryStore) -> None:
    """§8.2: 3 неудачные попытки с одного IP за 5 минут → временный бан адреса.

    Срок выводится из полей строки (`window_start + window_seconds + IP_BAN_DURATION`, `ADR-009`),
    поэтому он длиннее 15 минут ровно на остаток окна перебора: третья неудача случилась в 12:30:15,
    а окно перебора закончилось в 12:35:00.
    """
    for attempt in range(IP_BAN_THRESHOLD - 1):
        response = _login(client, password="не-тот-пароль-12345")
        assert response.status_code == 401, f"неудача {attempt + 1} закрыла адрес раньше срока"

    third = _login(client, password="не-тот-пароль-12345")
    assert third.status_code == 429, "третья неудача не закрыла адрес"
    assert _locked_link(LOCK_REASON_RATE) in third.text
    assert int(third.headers["retry-after"]) == RETRY_AT_BAN
    assert _attempts(store, IP_BAN_SCOPE, ADDR_A) == IP_BAN_THRESHOLD
    assert store.buckets()[(IP_BAN_SCOPE, ADDR_A, BAN_WINDOW_START)] == IP_BAN_THRESHOLD

    # Верный пароль не помогает: адрес закрыт, и пароль не проверяется вообще.
    assert _login(client).status_code == 429, "бан адреса не действует на верный пароль"


def test_бан_адреса_считает_и_неизвестные_логины(client: TestClient) -> None:
    """§8.2 говорит «3 неудачные попытки с одного IP», а не «по одной учётной записи».

    Иначе перебор обходит окно, меняя логины: попытка по чужому логину не трогает
    `users.failed_attempts` (учётки нет), и без окна адреса она была бы ничем не ограничена.
    """
    unknowns = ("нет-такой-учётки-01", "нет-такой-учётки-02", "нет-такой-учётки-03")
    for name in unknowns[: IP_BAN_THRESHOLD - 1]:
        response = _login(client, login_value=name)
        assert response.status_code == 401, "ответ различает существование учётной записи"
    assert (
        _login(client, login_value=unknowns[IP_BAN_THRESHOLD - 1]).status_code == 429
    ), "неудачи по разным логинам не сложились в бан адреса"


def test_бан_не_закрывает_уже_живую_сессию(client: TestClient, store: MemoryStore) -> None:
    """ask `ba6a9076`: бан держит маршрут входа, а не middleware на весь `web`.

    Иначе «бан IP» молча стал бы блокировкой всего сайта для всех, кто сидит за провайдерским NAT,
    а ложное срабатывание наказало бы не переборщика.
    """
    login_response = login_ok(client)
    assert login_response.status_code == 302
    record = store.sessions()[-1]
    advance_auth_step(record, step="full")
    store.commit()

    for _ in range(IP_BAN_THRESHOLD):
        _login(client, ADDR_A, password="не-тот-пароль-12345")
    assert _login(client, ADDR_A).status_code == 429, "адрес не закрыт"
    assert (
        client.get("/probe-full", follow_redirects=False).status_code == 200
    ), "бан адреса закрыл уже аутентифицированную сессию: зона отказа шире слоя входа"


def test_бан_адреса_истекает(client: TestClient, clock: Clock) -> None:
    """Бан — временный: после `window_start + окно + IP_BAN_DURATION` адрес снова пускается.

    Отдельно проверяется, что срок не растёт от новых попыток: иначе атакующий удерживал бы бан
    собственным стуком, а честный пользователь не попал бы обратно.
    """
    for _ in range(IP_BAN_THRESHOLD):
        _login(client, "203.0.113.17", password="не-тот-пароль-12345")
    first = _login(client, "203.0.113.17", password="не-тот-пароль-12345")
    second = _login(client, "203.0.113.17", password="не-тот-пароль-12345")
    assert first.status_code == second.status_code == 429
    assert (
        first.headers["retry-after"] == second.headers["retry-after"]
    ), "срок бана растёт от повторных попыток"

    clock.move_to(BAN_UNTIL + timedelta(seconds=1))
    assert _login(client, "203.0.113.17").status_code == 302, "бан не истёк"


def test_блокировка_учётки_объясняется_кодом_attempts(
    client: TestClient, store: MemoryStore
) -> None:
    """Два правила — два кода причины: `attempts` (закрыта учётка, `T-101`) против `rate`.

    Сроки совпадают (15 минут), состояния разные. Чтобы показать именно `attempts`, запросы идут
    без `X-Forwarded-For`: без адреса окно перебора не заводится, и остаётся блокировка учётки.
    """
    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post(
            "/login",
            data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None, "учётной записи нет в хранилище"
    assert user.locked_until is not None, "учётка не заблокирована (§8.1)"
    locked = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert locked.status_code == 429
    assert _locked_link(LOCK_REASON_ATTEMPTS) in locked.text, "подсказана не та причина блокировки"
    assert _locked_link(LOCK_REASON_RATE) not in locked.text
    assert store.buckets() == {}, "без адреса счётчик всё-таки заведён"


def test_при_неверном_пароле_ссылки_на_блокировку_нет(client: TestClient) -> None:
    """§9: ссылка на `/locked` появляется только там, где вход реально закрыт."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert LOCKED_PATH not in response.text
    assert GENERIC_FAILURE_DETAIL in response.text


def test_пустая_форма_не_приближает_бан_адреса(client: TestClient) -> None:
    """Неудачей считается проверка пароля: пустой ввод — `400`, а не попытка перебора (§8.1)."""
    address = "203.0.113.19"
    for _ in range(IP_BAN_THRESHOLD + 1):
        response = _empty_form(client, address)
        assert response.status_code == 400
    assert EMPTY_FORM_DETAIL in response.text
    assert _login(client, address).status_code == 302, "пустые формы посчитаны как неудачи"


# ─── предел мутаций пользователя (§8.3: 60 запросов/мин/пользователь) ──────────────────────────


def test_щуп_мутации_ограничен_пределом_пользователя(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.3: «все mutation-эндпоинты — 60 запросов/мин/пользователь» → `429` + `Retry-After`.

    Щуп зависит от той же композитной зависимости, что и реальный `/logout`, поэтому проверяется
    механизм, а не его имитация. Покрытие реальных мутаций держит контрактный тест.
    """
    assert login_ok(client).status_code == 302
    token = _csrf_of(client, store)
    for index in range(MUTATION_LIMIT):
        response = client.post(
            "/probe-mutation",
            data={CSRF_FORM_FIELD: token},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert response.status_code == 200, f"мутация {index + 1} отклонена раньше предела"

    denied = client.post(
        "/probe-mutation",
        data={CSRF_FORM_FIELD: token},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert denied.status_code == 429, "предел мутаций пользователя не сработал"
    assert int(denied.headers["retry-after"]) == RETRY_AT_WINDOW


def test_выход_двигает_счётчик_пользователя_один_раз(
    client: TestClient, store: MemoryStore
) -> None:
    """Настоящая мутация (`/logout`) попадает под счётчик ровно одной записью окна.

    `ADR-007` предупреждает: каждый лимитируемый запрос стоит запись в базу. Здесь видно, что слой
    входа не превращает один запрос в серию обращений к счётчику.
    """
    assert login_ok(client).status_code == 302
    token = _csrf_of(client, store)
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None
    logout = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: token},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert logout.status_code == 302
    windows = {
        key: attempts
        for (scope, key, _start), attempts in store.buckets().items()
        if scope == MUTATION_USER_SCOPE
    }
    assert windows == {str(user.id): 1}, f"выход породил не один счётчик: {windows}"


def test_отказ_csrf_не_двигает_счётчик_мутаций(client: TestClient, store: MemoryStore) -> None:
    """Порядок обязателен: сначала токен (`ADR-008`), потом счётчик частоты.

    Иначе подделанный запрос расходовал бы лимит пользователя, а отказ `403` — ответ, который
    вообще ничего не должен менять, — двигал бы счётчик.
    """
    assert login_ok(client).status_code == 302
    rejected = client.post("/logout", data={"любое": "поле"}, follow_redirects=False)
    assert rejected.status_code == 403
    assert not [key for (scope, key, _start) in store.buckets() if scope == MUTATION_USER_SCOPE]


# ─── окно: выравнивание и перечень областей ────────────────────────────────────────────────────


def test_окно_выровнено_и_не_зависит_от_момента_запроса() -> None:
    """Начало окна считает приложение (`ADR-007`): для 60 с — начало минуты, для 300 — пятиминутка.

    Без выравнивания один интервал дал бы несколько строк счётчика, и лимит перестал бы считаться.
    Именно об этом комментарий к колонке `window_start` в `packages/storage/models.py`.
    """
    moment = datetime(2026, 11, 21, 12, 3, 47, 505_005, tzinfo=UTC)
    assert align_window_start(moment, 60) == datetime(2026, 11, 21, 12, 3, tzinfo=UTC)
    assert align_window_start(moment, 300) == datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
    assert align_window_start(datetime(2026, 11, 21, 12, 3, tzinfo=UTC), 60) == datetime(
        2026, 11, 21, 12, 3, tzinfo=UTC
    )
    assert align_window_start(datetime(2026, 11, 21, 12, 2, 59, 999_999, tzinfo=UTC), 60) == (
        datetime(2026, 11, 21, 12, 2, tzinfo=UTC)
    )


def test_области_totp_описаны_до_появления_маршрута() -> None:
    """`T-103` подключит `/totp` вызовом механизма, а не изобретением лимита заново.

    Пределы §8.3 для ещё не существующего маршрута: 10 запросов в минуту на сессию и 5 на адрес.
    """
    assert RATE_LIMITS[TOTP_SESSION_SCOPE] == 10
    assert RATE_LIMITS[TOTP_IP_SCOPE] == 5


def test_отказ_по_лимиту_несёт_заголовки_безопасности(client: TestClient) -> None:
    """`429` на мутации создаёт обработчик исключения — политику ставит middleware (§8.3, срез `R3c`)."""
    for _ in range(LOGIN_LIMIT + 1):
        response = _empty_form(client, ADDR_A)
    assert response.status_code == 429
    for name in SECURITY_HEADERS:
        assert name in response.headers, f"{name}: отказ `429` отдан без политики"


def test_отказ_по_лимиту_не_создаёт_сессию(client: TestClient, store: MemoryStore) -> None:
    """Отказ по частоте не выпускает сессию и не трогает существующие (§8.3, §8.4)."""
    before = len(store.sessions())
    for _ in range(LOGIN_LIMIT + 5):
        _login(client, password="не-тот-пароль-12345")
    assert len(store.sessions()) == before
    assert _attempts(store, IP_BAN_SCOPE, ADDR_A) >= IP_BAN_THRESHOLD
