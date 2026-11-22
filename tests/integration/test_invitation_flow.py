"""Церемония приглашения по HTTP: выпуск → приём ссылки → привязка 2FA → очередь одобрения.

§1.2, `REQ-identity-02`, `ADR-020` п. 3–4, `ADR-021`; вторая обязательная проверка задачи
`T-105` — `test_invitation_flow`.

Файл идёт по адресам боевого приложения `create_app`, а не по доменным функциям. Выбор не
формальный: `docs/HANDOFF.md` §2 требует, чтобы `test_invitation_flow` шла по HTTP, потому что
половина `R7a` (домен и репозиторий) была зелёной и без единого вызывающего кода — то есть
«правило есть, а никто его не вызывает» офлайн-проверкой не обнаруживается вообще. Здесь
вызывается всё: `claim_invitation`, `user_from_invitation`, `ensure_invitation_open`,
`enqueue_for_approval`, охрана источника, предел частоты и разбор значения ссылки.

Что закреплено и почему именно так:

1. **Значение ссылки существует только в ответе выпуска.** В списке раздела его нет, повторный
   `GET` раздела его не возвращает, в репозитории лежит хэш (`ADR-020` п. 3). Считается, сколько
   раз значение встречается в ответе, а не «есть ли оно вообще».
2. **Одноразовость необратима для ссылки и обратима для значений поля.** Опечатка в пароле,
   занятый логин и «приглашение адресовано другому логину» — `400` без перехода `pending → used`
   (`ADR-021` п. 4). Порядок не выводился из `ADR-020` п. 4 автоматически, он был оформлен
   отдельным решением, поэтому проверяется состоянием выпуска после отказа, а не только кодом.
3. **Ответы адреса не служат оракулом существования.** Любое значение, которого нет среди выпусков,
   отвечает одинаково независимо от того, сколько выпусков в репозитории (§8.8). Различие «значение
   не разбирается» / «такого выпуска нет» текстом утечкой не является: форму значения человек
   принёс сам, а наличие строки в таблице ответ не выдаёт — это и фиксирует проверка ниже.
4. **Предел частоты — по адресу и только у мутации** (`ADR-007`): лимит на просмотр страницы дал
   бы способ не пустить человека, который просто открыл ссылку.
5. **Подтверждённая привязка второго фактора — то место, где появляется очередь одобрения.**
   Переход `invited → awaiting_approval` получается настоящим церемониалом привязки (KEK в
   песочнице, пара кодов из соседних окон), а не присваиванием состояния.

Граница честности. Репозиторий здесь — `MemoryStore`: он проверяет решения слоя входа и порядок
вызовов, но не атомарность перехода `pending → used` (два параллельных приёма одной ссылки
физически не приходят), не `uq_invitations_token_hash`, не `ck_invitations_state` и не сортировку
списков по `created_at`. Живую половину держит job `миграции` —
`tests/integration/test_invitations_db.py`; что она не потеряна и что в ней есть guarded-переход,
закрепляет `tests/contract/test_web_invitation_ceremony_contract.py`, чтобы офлайн-зелёный срез не
выдавался за закрытую задачу.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.routes import admin_users as admin_routes
from apps.web.routes import invitations as invitation_routes
from apps.web.routes import login as login_routes
from apps.web.routes import sessions as session_routes
from apps.web.routes import totp as totp_routes
from apps.web.routes.admin_users import (
    ADMIN_INVITATIONS_PATH,
    ADMIN_USERS_PATH,
    EMPTY_INVITATIONS_NOTE,
    EMPTY_QUEUE_NOTE,
    FIELD_ROLE,
    ISSUED_LINK_NOTE,
    STATE_LABELS,
)
from apps.web.routes.invitations import (
    ACCEPTED_NOTE,
    CLAIM_LOST_DETAIL,
    EMPTY_FORM_DETAIL,
    FIELD_REPEAT,
    LINK_CLOSED_STATUS,
    LINK_MISSING_STATUS,
    LOGIN_TAKEN_DETAIL,
    MISMATCH_DETAIL,
    SAME_LOGIN_DETAIL,
    TARGET_BY_EMAIL_NOTE,
    TARGET_BY_LOGIN_NOTE,
    UNUSABLE_EXPLANATIONS,
)
from apps.web.routes.totp import FIELD_CODE, FIELD_FIRST_CODE, FIELD_SECOND_CODE
from apps.web.security import rate_limit as rate_limit_module
from apps.web.security import sessions as security_sessions
from apps.web.security.authorization import ACCOUNT_STATE_EXPLANATIONS
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.rate_limit import LOGIN_IP_SCOPE, RATE_LIMITS
from apps.web.security.sessions import (
    INVITE_LINK_KEY,
    INVITE_PATH,
    LOGIN_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    SESSION_COOKIE_NAME,
    SESSIONS_PATH,
    TOTP_CODE_PATH,
)
from apps.web.store import Store
from packages.common.config import Settings
from packages.identity.invitations import (
    INVITATION_TOKEN_RE,
    INVITATION_TTL,
    INVITATION_UNUSABLE_CODES,
    InvitationTargetError,
    ensure_invitation_secret,
    invitation_token_hash,
    new_invitation,
)
from packages.identity.totp import TOTP_PERIOD_SECONDS, totp_code
from packages.storage.models import Invitation, User
from tests.integration.web_support import (
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
    set_kek_file,
)

# ─── окружение проверки ────────────────────────────────────────────────────────────────────────

#: Момент, от которого живёт файл. Основой служат реальные часы: `totp_code`, который тест считает
#: сам, обязан остаться в том же окне, что и код приложения (тот же приём, что у
#: `test_web_totp_page.py`: иначе часть проверок жила бы в реальном времени, а часть — в
#: замороженном, и вывод по ним был бы неотличим от случайности).
FROZEN: Final = datetime.now(UTC).replace(microsecond=0)

#: Адреса из резервных диапазонов RFC 5737. Предел частоты ключуется адресом, поэтому адрес обязан
#: быть явным: без него счётчики разных проверок сливаются в один, и «429» начинает появляться в
#: тестах, которые его не проверяют.
ADMIN_ADDRESS: Final = "203.0.113.21"
GUEST_ADDRESS: Final = "203.0.113.22"
OBSERVER_ADDRESS: Final = "203.0.113.23"
CROWD_ADDRESS: Final = "203.0.113.24"

ADMIN_LOGIN: Final = "ad.flow"
OUTSIDER_LOGIN: Final = "vw.flow"

#: Адресат выпуска. Значения не похожи на боевые и используются как канарейки в проверках утечки.
INVITED_LOGIN: Final = "iv.guest"
INVITED_EMAIL: Final = "guest@example.ru"
INVITED_PASSWORD: Final = "Принятый-пароль-2026"
INVITED_ROLE: Final = "operator"

#: Показанная ссылка (`/invite?token=<43 символа>`) и само значение. Разметка страницы выпуска
#: печатает значение текстом внутри `<code>`, а не ссылкой: переход по ссылке истратил бы выпуск.
LINK_BLOCK: Final = re.compile(r"<code>(/invite\?token=([A-Za-z0-9_-]{43}))</code>")

#: Длина значения ссылки в пробах: 43 символа base64url. Число повторяется здесь осознанно, но
#: пробы сверяются с самим доменным `INVITATION_TOKEN_RE`, а не с этим числом: иначе проверка
#: «значение подходящей формы / значение не разбирается» проверяла бы локальную константу.
TOKEN_CHARS: Final = 43
META_TOKEN: Final = re.compile(r'name="csrf-token" content="([^"]+)"')
SECRET_BLOCK: Final = re.compile(r"<code>([A-Z2-7]{16,128})</code>")
FORM_MARK: Final = '<button type="submit">Задать пароль и создать учётную запись</button>'
#: Строка объяснения отказа формы (§9.1): пустой `<p role="alert">` объяснением не является.
ALERT_LINE: Final = re.compile(r'<p role="alert">[^<]+</p>')


class Clock:
    """Задаваемое «сейчас» для слоя представления."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях, где его вызывают напрямую.

    Раздел администратора, приём ссылки, вход, сеансы, страница кода, механизм сеансов (выпуск,
    продление, разбор срока) и реестр адресов лимитов: пропуск любого из них означал бы, что часть
    проверок живёт в реальном времени, а часть — в замороженном.

    Пропуск `security_sessions` стоит отдельно отметить: он давал бы не «чуть неточные даты», а
    отказ, неотличимый от дефекта. Сеанс выпускается замороженными часами, а проверяется
    настоящими, и при сдвиге времени вперёд (его делает фикстура администратора: код входа
    берётся из окна на два периода позже привязки) «выпущен из будущего» превращается в
    `/session-expired?reason=not_yet`. Доменным модулям `packages/identity/*` момент передают
    параметром, поэтому их не подменяют (контракт среза `R2`: домен часы сам не читает).
    """
    fake = Clock(FROZEN)
    for module in (
        login_routes,
        session_routes,
        totp_routes,
        admin_routes,
        invitation_routes,
        security_sessions,
        rate_limit_module,
    ):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей KEK в песочнице — тот же формат, что пишет `deploy/vps/keys_setup.py`.

    Без него привязка второго фактора физически невозможна (`ADR-014` п. 5), а именно привязка
    ставит учётную запись в очередь одобрения.
    """
    path = tmp_path / "kek.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": base64.b64encode(secrets.token_bytes(32)).decode()}],
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def store() -> MemoryStore:
    """Действующий администратор и наблюдатель.

    `id` заполняются явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка не срабатывает, а
    `approved_by`, `created_by` и предикаты репозитория сравнивают `id`. С `None` проверки
    авторства одобрения и владения сравнивали бы `None` с `None` и проходили бы молча.
    """
    memory = MemoryStore()
    for login_value, role_value in ((ADMIN_LOGIN, "admin"), (OUTSIDER_LOGIN, "viewer")):
        account = memory.seed_user(login=login_value, role=role_value)
        account.id = uuid4()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock, kek: Path) -> Iterator[TestClient]:
    """Боевое приложение с репозиторием в памяти, файлом ключей и вошедшим администратором.

    Администратор входит и подтверждает привязку второго фактора по-настоящему (страница
    привязки, выдача секрета, пара кодов), а не подменой `auth_step` у объекта сеанса. Приём
    `test_web_role_matrix.py` (`_поднять_до_full`) для этого файла не годится: раздел
    администратора — отправная точка всей церемонии, и «шаг `'full'`» был бы здесь флагом,
    который никто не ставил, ровно той же дырой, из-за которой `R7a` осталась зелёной без
    вызывающего кода.
    """
    with build_client(store, settings) as test_client:
        set_kek_file(test_client, kek)
        вход = _войти(test_client, ADMIN_LOGIN, ADMIN_ADDRESS)
        assert вход.status_code == 302, вход.text[:300]
        assert session_cookie(test_client), "администратор вошёл без сеанса"
        _полный_вход(test_client, clock, ADMIN_ADDRESS)
        раздел = test_client.get(
            ADMIN_USERS_PATH, headers=_headers(ADMIN_ADDRESS), follow_redirects=False
        )
        assert раздел.status_code == 200, раздел.text[:300]
        yield test_client


# ─── помощники ─────────────────────────────────────────────────────────────────────────────────


def _headers(address: str, *, origin: str = "https://testserver") -> dict[str, str]:
    """`Origin` плюс адрес источника.

    Без первого отключён второй слой CSRF (§8.3), без второго — лимиты частоты (`ADR-009`: ключа
    нет — лимита нет). Оба заголовка тест посылает всегда, кроме проверок отказа по источнику.
    """
    return {"Origin": origin, "User-Agent": "invitation-flow", "X-Forwarded-For": address}


def _form_token(client: TestClient, address: str) -> str:
    """Значение meta-токена раздела администратора (скрытое поле форм — того же значения)."""
    ответ = client.get(ADMIN_USERS_PATH, headers=_headers(address), follow_redirects=False)
    assert ответ.status_code == 200, ответ.text[:300]
    находит = META_TOKEN.search(ответ.text)
    assert находит, "в разделе администратора нет meta токена"
    return находит.group(1)


def _войти(
    client: TestClient, login_value: str, address: str, *, password: str = TEST_PASSWORD
) -> Response:
    """Войти; кука остаётся в клиенте, `follow_redirects=False` — чтобы видеть сам ответ входа.

    Пароль — параметр: у записи, созданной по приглашению, его задал приглашённый
    (`INVITED_PASSWORD`), у записей фикстуры — общий `TEST_PASSWORD` двойника. Перепутать их
    значит получить `401` в проверках, которые про пароль ничего не проверяют.
    """
    ответ: Response = client.post(
        LOGIN_PATH,
        data={"login": login_value, "password": password},
        headers=_headers(address),
        follow_redirects=False,
    )
    return ответ


def _выпустить(client: TestClient, **поля: str) -> tuple[Response, str, str]:
    """Выпустить приглашение администратором: (ответ, ссылка, значение ссылки).

    Значение вынимается из ответа, а не из результата `new_invitation`: проверка обязана видеть
    ровно то, что видит администратор, и в том же виде — относительный путь с параметром запроса.
    """
    data = {CSRF_FORM_FIELD: _form_token(client, ADMIN_ADDRESS)} | поля
    выпущено: Response = client.post(
        ADMIN_INVITATIONS_PATH,
        data=data,
        headers=_headers(ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert выпущено.status_code == 200, выпущено.text[:400]
    находит = LINK_BLOCK.search(выпущено.text)
    assert находит, f"в ответе выпуска нет ссылки: {выпущено.text[:400]}"
    return выпущено, находит.group(1), находит.group(2)


def _пригласить(
    client: TestClient, *, адресат: str = "login", роль: str = INVITED_ROLE
) -> tuple[str, str]:
    """Выпустить выпуск с нужным адресатом: (ссылка, значение ссылки).

    Режим «оба адресата сразу» (письмо с указанием логина, §1.2) здесь не заведён сознательно:
    он нужен ровно одной проверке — `test_приём_создаёт_invited_и_не_выдаёт_доступ`, — и та
    вызывает `_выпустить` прямо, чтобы в тексте проверки было видно, какой выпуск она создаёт.
    """
    поля = {"role": роль}
    if адресат == "login":
        поля["login"] = INVITED_LOGIN
    else:
        поля["email"] = INVITED_EMAIL
    _, ссылка, значение = _выпустить(client, **поля)
    return ссылка, значение


def _принять(
    client: TestClient,
    ссылка: str,
    *,
    login_value: str = INVITED_LOGIN,
    password: str = INVITED_PASSWORD,
    repeat: str | None = None,
    address: str = GUEST_ADDRESS,
    origin: str = "https://testserver",
) -> Response:
    """Отправить форму приёма по ссылке на тот же адрес, куда ведёт ссылка (`action=""`).

    Адрес формы в разметке намеренно пустой: значение ссылки не печатается в теле ответа, поэтому
    и тест обязан отправлять на адрес со значением, а не на `INVITE_PATH` без параметра.
    """
    начало = f"{INVITE_PATH}?{INVITE_LINK_KEY}="
    assert ссылка.startswith(начало), f"выпущенная ссылка не начинается с {начало!r}: {ссылка}"
    ответ: Response = client.post(
        ссылка,
        data={
            "login": login_value,
            "password": password,
            FIELD_REPEAT: repeat if repeat is not None else password,
        },
        headers=_headers(address, origin=origin),
        follow_redirects=False,
    )
    return ответ


def _учётка(store: Store, login_value: str) -> User:
    account = store.user_by_login(login_value)
    assert account is not None, f"учётной записи {login_value!r} в репозитории нет"
    return account


def _открытый_выпуск(store: Store, индекс: int = 0) -> Invitation:
    rows = store.pending_invitations()
    assert len(rows) > индекс, f"открытого выпуска с индексом {индекс} нет"
    return rows[индекс]


def _привязать_второй_фактор(client: TestClient, address: str, clock: Clock) -> str:
    """Пройти привязку 2FA целиком и вернуть показанный секрет. Шаг сеанса после неё — `'totp'`.

    Тот же путь, что у `test_web_totp_page.py`: страница привязки даёт токен, мутация выдаёт
    секрет, подтверждение требует два кода из соседних окон (§8.2). Пара кодов считается от
    **текущего** момента часов фикстуры, а не от `FROZEN`: фикстура администратора сдвигает время,
    и коды, посчитанные от прежнего момента, попали бы в уже закрытые окна — отказ, неотличимый
    от дефекта приложения.

    Здесь привязка — шаг церемонии, а не предмет проверки, поэтому помощник короткий и тот файл
    не подменяет.
    """
    страница = client.get(MFA_ENROLL_PATH, headers=_headers(address), follow_redirects=False)
    assert страница.status_code == 200, страница.text[:300]
    токен = META_TOKEN.search(страница.text)
    assert токен, "на странице привязки нет meta токена"
    выдача: Response = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: токен.group(1)},
        headers=_headers(address),
        follow_redirects=False,
    )
    assert выдача.status_code == 200, выдача.text[:300]
    секрет = SECRET_BLOCK.search(выдача.text)
    assert секрет, f"мутация не показала секрет привязки: {выдача.text[:300]}"
    момент = clock()
    first = totp_code(секрет.group(1), момент)
    second = totp_code(секрет.group(1), момент + timedelta(seconds=TOTP_PERIOD_SECONDS))
    подтверждение = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={
            CSRF_FORM_FIELD: токен.group(1),
            FIELD_FIRST_CODE: first,
            FIELD_SECOND_CODE: second,
        },
        headers=_headers(address),
        follow_redirects=False,
    )
    assert подтверждение.status_code == 200, подтверждение.text[:300]
    return секрет.group(1)


def _дойти_до_full(client: TestClient, secret: str, clock: Clock, address: str) -> None:
    """Ввести код входа на странице кода: шаг `'full'` и доступ в консоль (§8.2, `ADR-013`).

    Без этого шага сеанс остаётся на `'totp'`, а маршруты консоли на этом шаге редиректят, не
    доходя до проверки состояния. Значит и объяснение состояния учётной записи («ждёт одобрения»,
    «заблокирована») было бы недостижимо, и проверки §9.3 проверяли бы редирект входа.

    Код берётся из текущего окна, поэтому часы сдвигаются на два периода: окна, израсходованные
    парой подтверждения, закрыты защитой от повтора (`ADR-013` п. 6), и код из них был бы отказом.
    """
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    страница = client.get(TOTP_CODE_PATH, headers=_headers(address), follow_redirects=False)
    assert страница.status_code == 200, страница.text[:300]
    токен = META_TOKEN.search(страница.text)
    assert токен, "на странице кода нет meta токена"
    ответ = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: токен.group(1), FIELD_CODE: totp_code(secret, clock())},
        headers=_headers(address),
        follow_redirects=False,
    )
    assert ответ.status_code == 302, f"код входа не принят: {ответ.status_code} {ответ.text[:300]}"


def _полный_вход(client: TestClient, clock: Clock, address: str) -> None:
    """Привязка + код входа: сеанс доводится до шага `'full'`. Возвращать нечего."""
    _дойти_до_full(client, _привязать_второй_фактор(client, address, clock), clock, address)


def _гость(client: TestClient) -> TestClient:
    """Отдельный браузер для приглашённого: свой jar кук, тот же репозиторий и приложение."""
    return TestClient(client.app, base_url="https://testserver")


# ─── выпуск (§9.3 п. 6 «создание приглашения») ─────────────────────────────────────────────────


def test_выпуск_показывает_ссылку_ровно_один_раз(client: TestClient, store: Store) -> None:
    """Значение ссылки существует только в ответе выпуска (§1.2, `ADR-020` п. 3).

    Три утверждения, и все три про то, что повторного показа нет: в ответе выпуска значение
    встречается ровно один раз; повторный `GET` раздела его не возвращает; в репозитории лежит
    хэш, а не значение. Без второго и третьего «один раз» осталось бы текстом шаблона.
    """
    выпущено, ссылка, значение = _выпустить(
        client, login=INVITED_LOGIN, email=INVITED_EMAIL, role=INVITED_ROLE
    )

    assert выпущено.text.count(значение) == 1, "значение показано больше одного раза"
    assert ISSUED_LINK_NOTE in выпущено.text, "ответ выпуска не объясняет одноразовость"
    assert INVITED_EMAIL in выпущено.text, "выпуск не называет адресата"

    раздел = client.get(ADMIN_USERS_PATH, headers=_headers(ADMIN_ADDRESS), follow_redirects=False)
    assert раздел.status_code == 200
    assert значение not in раздел.text, "список приглашений повторил значение ссылки"
    assert ссылка not in раздел.text, "список приглашений повторил ссылку целиком"
    assert INVITED_EMAIL in раздел.text, "в списке не видно, кому адресован выпуск"

    выпуск = _открытый_выпуск(store)
    assert выпуск.state == "pending"
    assert выпуск.token_hash == invitation_token_hash(значение)
    assert значение not in выпуск.token_hash
    assert INVITATION_TOKEN_RE.fullmatch(значение), "выпущено значение не по алфавиту домена"
    ensure_invitation_secret(значение)


def test_выпуск_без_адресата_отвергнут_и_объяснён(
    client: TestClient, store: Store, clock: Clock
) -> None:
    """Отказ формы выпуска приходит текстом домена, а не молчаливым `400` (§9.1).

    Три половины проверки ловят разные способы сломаться:

    * домен требует адресата (§1.2), и отдельной проверки «заполнен ли хотя бы один адресат» в
      обработчике нет сознательно: форма не имеет права знать это правило лучше домена;
    * формулировка отказа сравнивается с текстом, который даёт прямой вызов `new_invitation` с
      теми же значениями. Придумай слой свой текст — правило и объяснение разойдутся при первой
      же правке, и ловить это придётся человеку на площадке;
    * форма вообще без значений обязана объяснить отказ, а не вернуть раздел без строки
      состояния. Первым приходит отказ по роли: домен проверяет `ensure_role` раньше адресата,
      и это порядок домена, а не обработчика.

    Про счётчик транзакций: цепочка мутаций до обработчика двигает счётчик частоты (`ADR-007` —
    отказ обязан быть записан), поэтому «ноль коммитов» ожидаемым не является. Отсутствие строки
    выпуска — то единственное, что обязано быть.
    """
    admin_id = _учётка(store, ADMIN_LOGIN).id
    with pytest.raises(InvitationTargetError) as домен:
        new_invitation(created_by=admin_id, role=INVITED_ROLE, now=clock())

    без_адресата = client.post(
        ADMIN_INVITATIONS_PATH,
        data={CSRF_FORM_FIELD: _form_token(client, ADMIN_ADDRESS), FIELD_ROLE: INVITED_ROLE},
        headers=_headers(ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert без_адресата.status_code == 400, без_адресата.text[:300]
    assert (
        str(домен.value) in без_адресата.text
    ), "формулировка домена не дошла до человека: слой придумал собственный текст"
    assert EMPTY_INVITATIONS_NOTE in без_адресата.text, "отказ формы потерял раздел вместо отказа"
    assert store.pending_invitations() == (), "выпуск без адресата всё-таки записан"

    пусто = client.post(
        ADMIN_INVITATIONS_PATH,
        data={CSRF_FORM_FIELD: _form_token(client, ADMIN_ADDRESS)},
        headers=_headers(ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert пусто.status_code == 400
    assert ALERT_LINE.search(пусто.text), "пустая форма вернула раздел без объяснения"
    assert store.pending_invitations() == ()


def test_открытая_ссылка_даёт_форму_и_объясняет_адресата(client: TestClient) -> None:
    """Форма открывается только открытой ссылкой и объясняет, чьё имя подставлено (§9.3 п. 2).

    Два объяснения («адресовано логину» / «адресовано почте») нужны не для вежливости: в первом
    случае выбрать имя нельзя, и человек обязан узнать об этом до отправки формы, а не отказом.
    """
    ссылка, _ = _пригласить(client, адресат="login")
    ответ = client.get(ссылка, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert ответ.status_code == 200, ответ.text[:300]
    assert TARGET_BY_LOGIN_NOTE in ответ.text
    assert FORM_MARK in ответ.text, "открытая ссылка не дала форму приёма"
    assert f'value="{INVITED_LOGIN}"' in ответ.text, "логин адресата не подставлен в форму"

    вторая, _ = _пригласить(client, адресат="email")
    ответ = client.get(вторая, headers=_headers(OBSERVER_ADDRESS), follow_redirects=False)
    assert ответ.status_code == 200
    assert TARGET_BY_EMAIL_NOTE in ответ.text
    assert TARGET_BY_LOGIN_NOTE not in ответ.text, "оба объяснения оказались на странице сразу"


# ─── приём ссылки (§1.2 шаг 1) ────────────────────────────────────────────────────────────────


def test_значения_поля_не_сжигают_выпуск(client: TestClient, store: Store) -> None:
    """Опечатка в пароле не стоит человеку нового выпуска (`ADR-021` п. 4).

    Это и есть отличие порядка `R7b` от буквы `ADR-020` п. 4: значения полей проверяются до
    guarded-`UPDATE`, потому что заявка ссылки необратима, а поле обратимо. Проверка смотрит и на
    код, и на состояние выпуска: без второй половины «400» ничего не доказывает — ссылка могла
    быть истрачена и уже потом отвергнута.
    """
    ссылка, _ = _пригласить(client)
    выпуск = _открытый_выпуск(store)

    короткий = _принять(client, ссылка, password="короткий")
    assert короткий.status_code == 400, короткий.text[:300]
    assert "парол" in короткий.text.lower(), "отказ политики пароля не объяснён человеку"
    assert FORM_MARK in короткий.text, "отказ политики закрыл форму: править значение негде"

    невпопад = _принять(client, ссылка, password=INVITED_PASSWORD, repeat="иначе-2026!")
    assert невпопад.status_code == 400
    assert MISMATCH_DETAIL in невпопад.text

    пусто = _принять(client, ссылка, password="")
    assert пусто.status_code == 400
    assert EMPTY_FORM_DETAIL in пусто.text

    assert выпуск.state == "pending", "выпуск истрачен отказом формы"
    assert выпуск.used_at is None
    assert store.user_by_login(INVITED_LOGIN) is None, "по отвергнутой форме создана учётная запись"

    успех = _принять(client, ссылка)
    assert успех.status_code == 200, успех.text[:400]
    assert ACCEPTED_NOTE in успех.text
    assert успех.cookies.get(SESSION_COOKIE_NAME, "") == "", "ответ приёма выдал сеанс"


def test_приём_создаёт_invited_и_не_выдаёт_доступ(client: TestClient, store: Store) -> None:
    """Состояние созданной записи — `invited`; ни автора одобрения, ни сеанса (§1.2).

    Автодопуск — ровно та дыра, которую закрывает `ADR-021` п. 5: выдать сеанс тому, кто только
    что задал пароль, значило бы пропустить и второй фактор, и очередь одобрения. Поэтому
    проверяются четыре вещи: состояние, пустые `approved_by`/`approved_at`, роль из выпуска и
    отсутствие куки после приёма.
    """
    _, ссылка, значение = _выпустить(
        client, login=INVITED_LOGIN, email=INVITED_EMAIL, role=INVITED_ROLE
    )
    приём = _принять(client, ссылка)
    assert приём.status_code == 200, приём.text[:400]
    assert приём.cookies.get(SESSION_COOKIE_NAME, "") == "", "приём выдал сеанс (автодопуск)"

    account = _учётка(store, INVITED_LOGIN)
    assert account.state == "invited", "состояние после приёма не `invited`"
    assert account.role == INVITED_ROLE, "роль взята не из приглашения"
    assert account.approved_by is None, "запись одобрена при приёме (автор проставлен)"
    assert account.approved_at is None, "запись одобрена при приёме (штамп проставлен)"
    assert account.email == INVITED_EMAIL, "e-mail из приглашения не перешёл в учётную запись"

    assert store.pending_invitations() == (), "выпуск остался открытым после приёма"
    запись = store.invitation_by_hash(invitation_token_hash(значение))
    assert запись is not None
    assert запись.state == "used", "выпуск не помечен использованным"
    assert запись.used_at is not None, "у заявки ссылки нет штампа приёма"


def test_повторный_приём_объясняется_и_не_создаёт_вторую_запись(
    client: TestClient, store: Store
) -> None:
    """Второй приём той же ссылки — `410` с объяснением; учётных записей по-прежнему одна пара.

    Держатель ссылки вправе знать, что ссылка истрачена (`ADR-020` п. 5 ограничивает подбор
    значений, а не объяснение тому, кто значение уже предъявил). Важно и второе: форма приёма на
    закрытой ссылке не открывается, иначе страница предлагала бы действие без последствий (§9.1).
    """
    ссылка, _ = _пригласить(client)
    assert _принять(client, ссылка).status_code == 200
    записей = len(store.accounts())

    второй = _принять(client, ссылка)
    assert второй.status_code == LINK_CLOSED_STATUS
    assert UNUSABLE_EXPLANATIONS["used"] in второй.text
    assert (
        UNUSABLE_EXPLANATIONS["expired"] not in второй.text
    ), "объяснение не соответствует причине"
    assert FORM_MARK not in второй.text, "форма приёма доступна по истраченной ссылке"
    assert CLAIM_LOST_DETAIL not in второй.text
    assert len(store.accounts()) == записей, "появилась вторая учётная запись по истраченной ссылке"

    просмотр = client.get(ссылка, headers=_headers(OBSERVER_ADDRESS), follow_redirects=False)
    assert просмотр.status_code == LINK_CLOSED_STATUS


def test_битая_и_неизвестная_ссылки_не_открывают_форму(client: TestClient, store: Store) -> None:
    """Значение вне алфавита, значение, которого нет, и адрес без значения — `404` без формы.

    Именно здесь `/invite` перестаёт быть формой регистрации: адрес не смотрит на тело формы и не
    отвечает `400`/`422` на запрос без значения (§8.8, `ADR-021` п. 3). `422` от FastAPI тоже
    нельзя: он перечислил бы параметры адреса, то есть описал бы носитель доступа.
    """
    испорченное = "A" * (TOKEN_CHARS - 1) + "!"
    неизвестное = "B" * TOKEN_CHARS
    битая = f"{INVITE_PATH}?{INVITE_LINK_KEY}={испорченное}"
    нет_такой = f"{INVITE_PATH}?{INVITE_LINK_KEY}={неизвестное}"
    assert (
        INVITATION_TOKEN_RE.fullmatch(испорченное) is None
    ), "проба «испорченное значение» разбирается доменным алфавитом"
    assert INVITATION_TOKEN_RE.fullmatch(
        неизвестное
    ), "проба «такого выпуска нет» имеет форму мусора"

    for адрес in (битая, нет_такой, INVITE_PATH):
        ответ = client.get(адрес, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
        assert ответ.status_code == LINK_MISSING_STATUS, адрес
        assert FORM_MARK not in ответ.text, f"{адрес}: страница без ссылки принимает пароль"
        assert UNUSABLE_EXPLANATIONS["used"] not in ответ.text

    попытка = _принять(client, нет_такой, login_value="samozvanets")
    assert попытка.status_code == LINK_MISSING_STATUS, "форма принята по ссылке, которой нет"
    assert store.user_by_login("samozvanets") is None

    без_значения = client.post(
        INVITE_PATH,
        data={
            "login": "samozvanets-2",
            "password": INVITED_PASSWORD,
            FIELD_REPEAT: INVITED_PASSWORD,
        },
        headers=_headers(GUEST_ADDRESS),
        follow_redirects=False,
    )
    assert без_значения.status_code == LINK_MISSING_STATUS
    assert store.user_by_login("samozvanets-2") is None


def test_ответы_не_выдают_сколько_выпусков_существует(client: TestClient, store: Store) -> None:
    """Ответ на «такой ссылки нет» не зависит от того, сколько выпусков в репозитории (§8.8).

    Смысл проверки: `/invite` не становится оракулом «строка есть / строки нет». До выпуска и
    после него одно и то же выдуманное значение отвечает побайтово одним ответом, и два разных
    выдуманных значения отвечают одинаково. Различие «значение не разбирается» / «такого выпуска
    нет» относится к форме принесённого значения, а не к содержимому таблицы, — поэтому оно и
    остаётся, а проверяется здесь именно независимость от таблицы.
    """
    проба = f"{INVITE_PATH}?{INVITE_LINK_KEY}=" + "C" * TOKEN_CHARS

    до = client.get(проба, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert до.status_code == LINK_MISSING_STATUS
    assert store.pending_invitations() == ()

    _, _, значение = _выпустить(client, login=INVITED_LOGIN, role=INVITED_ROLE)
    assert len(store.pending_invitations()) == 1

    после = client.get(проба, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert после.status_code == LINK_MISSING_STATUS
    assert после.content == до.content, "ответ изменился оттого, что в таблице появился выпуск"

    сосед = client.get(
        f"{INVITE_PATH}?{INVITE_LINK_KEY}=" + "D" * TOKEN_CHARS,
        headers=_headers(GUEST_ADDRESS),
        follow_redirects=False,
    )
    assert сосед.content == до.content, "ответ различает выдуманные значения"
    assert значение not in после.text


def test_просроченная_и_отозванная_ссылки_объясняются_поразному(
    client: TestClient, store: Store, clock: Clock
) -> None:
    """Срок и отзыв объясняются разными текстами с `410` (§9.1 «объяснение состояния»).

    Просроченность получается сдвигом часов, а не правкой `expires_at` у строки: значение ссылки
    остаётся тем же, что выдал администратор, и решение принимает боевой предикат
    `ensure_invitation_open`, сравнивая срок с текущим моментом. Что срок сравнивается с
    `expires_at` внутри `SELECT`, держит job `миграции`.

    Различие объяснений — не косметика: «истекло» означает «попроси новую ссылку», «отозвана» —
    «администратор передумал», и путать их значит давать человеку совет, который ему не помог.
    """
    просрочена, _ = _пригласить(client, адресат="email")
    отозвана, _ = _пригласить(client, адресат="email")
    выпуск = _открытый_выпуск(store, индекс=0)
    второй = _открытый_выпуск(store, индекс=1)
    assert store.revoke_invitation_row(invitation_id=второй.id)

    clock.advance(seconds=INVITATION_TTL.total_seconds() + 120)
    assert выпуск.expires_at < clock(), "сдвиг часов не перевёл выпуски за срок"
    assert второй.expires_at < clock()

    ответ = client.get(просрочена, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert ответ.status_code == LINK_CLOSED_STATUS
    assert UNUSABLE_EXPLANATIONS["expired"] in ответ.text
    assert FORM_MARK not in ответ.text, "просроченная ссылка предложила задать пароль"

    отказ = _принять(client, просрочена)
    assert отказ.status_code == LINK_CLOSED_STATUS, "просроченная ссылка приняла форму"
    assert store.user_by_login(INVITED_LOGIN) is None

    ответ = client.get(отозвана, headers=_headers(OBSERVER_ADDRESS), follow_redirects=False)
    assert ответ.status_code == LINK_CLOSED_STATUS
    assert UNUSABLE_EXPLANATIONS["revoked"] in ответ.text, (
        "отозванная ссылка ответила «истекло»: порядок проверок домена (сначала состояние, "
        "потом срок) нарушен — оба условия уже выполнены"
    )
    assert UNUSABLE_EXPLANATIONS["expired"] not in ответ.text


def test_объяснения_состояния_ссылки_покрывают_набор_домена() -> None:
    """Словарь объяснений полон относительно кодов домена и не содержит лишнего.

    Код возвращает домен (`INVITATION_UNUSABLE_CODES`), а текст выбирает слой представления.
    Расхождение ловится здесь, а не на площадке: пропущенный код выражается пустым объяснением и
    предупреждением в журнал, то есть человек увидел бы страницу без причины отказа. `malformed` и
    `unknown` — коды слоя, их в доменном наборе нет намеренно: домен не знает про форму значения в
    адресе, и добавлять их в домен означало бы переносить разбирание адреса в ядро.
    """
    ожидаемые = set(INVITATION_UNUSABLE_CODES) | {"malformed", "unknown"}
    assert (
        set(UNUSABLE_EXPLANATIONS) == ожидаемые
    ), f"объяснения расходятся с кодами домена: {set(UNUSABLE_EXPLANATIONS) ^ ожидаемые}"
    assert all(текст.strip() for текст in UNUSABLE_EXPLANATIONS.values())


def test_занятый_логин_и_чужое_имя_не_тратят_выпуск(client: TestClient, store: Store) -> None:
    """Два правила имени объясняются прямо и не переводят выпуск в `used` (§8.1, §1.2).

    «Имя занято» и «приглашение адресовано другому логину» — ошибки поля, а не отказ допуска: у
    человека права не меньше, чем требует маршрут, у него значение не то. Третье следствие —
    выпуск остаётся открытым, и человек пробует другое имя сразу, без нового письма.
    """
    чужое, _ = _пригласить(client, адресат="login")
    отказ = _принять(client, чужое, login_value="drugoe-imya")
    assert отказ.status_code == 400
    assert SAME_LOGIN_DETAIL in отказ.text
    assert _открытый_выпуск(store).state == "pending", "отказ по имени истратил выпуск"

    по_почте, _ = _пригласить(client, адресат="email")
    занято = _принять(client, по_почте, login_value=OUTSIDER_LOGIN)
    assert занято.status_code == 400
    assert LOGIN_TAKEN_DETAIL in занято.text
    выпуски = store.pending_invitations()
    assert len(выпуски) == 2, "отказ по занятому логину закрыл выпуск"
    assert all(выпуск.state == "pending" for выпуск in выпуски)
    assert store.user_by_login(OUTSIDER_LOGIN) is not None, "занятый логин не существует"


def test_чужой_источник_отвергнут_до_обращения_к_выпуску(client: TestClient, store: Store) -> None:
    """Исключение из токена сеанса компенсировано проверкой источника (`ADR-021` п. 2).

    `/invite` — единственная мутация кроме входа, у которой нет скрытого поля токена: сеанса ещё
    нет, а токен `ADR-008` выводится из пары «значение куки + `id` сеанса». Без `ensure_same_origin`
    это было бы дырой, а не заменой защиты, поэтому отказ обязан случиться до любых обращений к
    выпуску: ни заявка ссылки, ни создание учётной записи не состоялись.
    """
    ссылка, _ = _пригласить(client, адресат="email")
    отказ = _принять(client, ссылка, origin="https://evil.example")
    assert отказ.status_code == 403, отказ.text[:300]
    assert _открытый_выпуск(store).state == "pending"
    assert store.user_by_login(INVITED_LOGIN) is None

    снятие = _принять(client, ссылка)
    assert снятие.status_code == 200, "отказ по источнику истратил выпуск"


def test_предел_частоты_по_адресу_а_просмотр_страницы_без_лимита(
    client: TestClient, store: Store
) -> None:
    """Мутация считается адресом до стоимости Argon2id, `GET` лимита не имеет (§8.3, `ADR-007`).

    Предел — вторая половина компенсации за отсутствующий токен (`ADR-021` п. 2). Отказ обязан
    идти с `Retry-After`, иначе и браузер, и проверки теряют ориентир (§8.3).

    Вторая половина проверки не менее важна: лимит на просмотр страницы дал бы способ устроить
    отказ человеку, который просто открыл ссылку, — а счётчик при этом вырос бы у всех, кто сидит
    за адресом того же провайдера.
    """
    ссылка, _ = _пригласить(client, адресат="email")
    предел = RATE_LIMITS[LOGIN_IP_SCOPE]

    отказ: Response | None = None
    for попытка in range(1, предел + 3):
        ответ = _принять(client, ссылка, password="", address=CROWD_ADDRESS)
        if ответ.status_code == 429:
            отказ = ответ
            break
        assert ответ.status_code == 400, f"попытка {попытка}: {ответ.status_code}"
    assert отказ is not None, f"предел {предел} не исчерпан за {предел + 2} попыток"
    assert "Retry-After" in отказ.headers, "429 без Retry-After (§8.3)"
    assert _открытый_выпуск(store).state == "pending", "отказ частоты истратил выпуск"

    for _ in range(предел * 2):
        просмотр = client.get(ссылка, headers=_headers(CROWD_ADDRESS), follow_redirects=False)
        assert просмотр.status_code == 200, "GET приёма приглашения попал под счётчик частоты"

    другой_адрес = _принять(client, ссылка, password="", address=OBSERVER_ADDRESS)
    assert другой_адрес.status_code == 400, "предел по одному адресу закрыл доступ всем"


# ─── привязка второго фактора и очередь одобрения (§1.2 шаг 2) ────────────────────────────────


def test_привязка_второго_фактора_ставит_в_очередь_одобрения(
    client: TestClient, store: Store, clock: Clock
) -> None:
    """`invited → awaiting_approval` делает подтверждённая привязка, а не приём ссылки.

    Цепочка идёт по адресам: вход созданной записи, страница кода, страница привязки, выдача
    секрета, подтверждение парой кодов. Держатся и состояния, и направление отказа: до привязки
    запись `invited`, после — `awaiting_approval`. Объяснение состояния проверяется на шаге
    `'full'`, а не на `'totp'`: на промежуточном шаге маршруты консоли редиректят, не доходя до
    проверки состояния (§8.2), и путать эти два отказа нельзя — редирект говорит о незавершённом
    входе, страница «доступ закрыт» — о решении администратора (§9.3, `ADR-020` п. 6).

    Отдельно проверяется, что объяснение состояния не называет чужих логинов: «дождитесь
    одобрения» без имён — и потому, что §8.7 запрещает показывать чужие учётные записи, и потому,
    что имя одобрившего — будущая запись журнала (`T-109`), а не текст объяснения.
    """
    ссылка, _ = _пригласить(client)
    assert _принять(client, ссылка).status_code == 200

    гость = _гость(client)
    вход = _войти(гость, INVITED_LOGIN, GUEST_ADDRESS, password=INVITED_PASSWORD)
    assert вход.status_code == 302, вход.text[:300]
    assert вход.cookies.get(SESSION_COOKIE_NAME, ""), "вход созданной записи не выдал сеанс"
    assert вход.headers["location"] == TOTP_CODE_PATH, "после пароля шаг не страница кода"
    assert _учётка(store, INVITED_LOGIN).state == "invited"

    консоль = гость.get(SESSIONS_PATH, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert (
        консоль.status_code == 302
    ), "страница консоли открыта учётной записи на шаге `'password'`"
    assert консоль.headers["location"] == TOTP_CODE_PATH

    секрет = _привязать_второй_фактор(гость, GUEST_ADDRESS, clock)
    assert _учётка(store, INVITED_LOGIN).state == "awaiting_approval"
    # Привязка администратора (её делает фикстура) состояние `active` не тронула:
    # `enqueue_for_approval` идемпотентен и не трогает учётные записи с уже открытым доступом.
    assert _учётка(store, ADMIN_LOGIN).state == "active"

    промежуточно = гость.get(SESSIONS_PATH, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert промежуточно.status_code == 302, "шаг `'totp'` открыл консоль без кода входа"
    assert промежуточно.headers["location"] == TOTP_CODE_PATH

    _дойти_до_full(гость, секрет, clock, GUEST_ADDRESS)
    ожидание = гость.get(SESSIONS_PATH, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert ожидание.status_code == 200, ожидание.text[:300]
    assert ACCOUNT_STATE_EXPLANATIONS["awaiting_approval"] in ожидание.text
    assert ACCOUNT_STATE_EXPLANATIONS["invited"] not in ожидание.text
    for чужое in (ADMIN_LOGIN, OUTSIDER_LOGIN):
        assert чужое not in ожидание.text, "объяснение состояния называет чужую учётную запись"


def test_одобрение_открывает_доступ_и_проставляет_автора(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Одобрение — переход `awaiting_approval → active` с отметкой автора (§1.2 шаг 2).

    Отметки `approved_by`/`approved_at` ставит домен, и проверяется именно автор (запись того
    самого администратора, а не «что-то непустое»): на `approved_by` стоит FK
    `fk_users_approved_by_users`, и неверное значение означало бы битую связь в журнале
    (`REQ-identity-03`, `T-109`).

    Третья часть — доступ: до одобрения консоль объясняла ожидание, после — работает, а очередь в
    разделе опустела. Разница двух ответов и есть смысл очереди, и она же доказывает, что
    состояние применяется сразу, без перезапуска `web` (`ADR-020` п. 6).
    """
    ссылка, _ = _пригласить(client)
    assert _принять(client, ссылка).status_code == 200
    гость = _гость(client)
    вход = _войти(гость, INVITED_LOGIN, GUEST_ADDRESS, password=INVITED_PASSWORD)
    assert вход.status_code == 302, вход.text[:300]
    _полный_вход(гость, clock, GUEST_ADDRESS)
    account = _учётка(store, INVITED_LOGIN)
    assert account.state == "awaiting_approval"
    assert account.approved_by is None

    очередь = client.get(ADMIN_USERS_PATH, headers=_headers(ADMIN_ADDRESS), follow_redirects=False)
    assert очередь.status_code == 200
    assert INVITED_LOGIN in очередь.text, "запись не попала в очередь одобрения"
    assert STATE_LABELS["awaiting_approval"] in очередь.text, "очередь не подписала состояние"
    assert EMPTY_QUEUE_NOTE not in очередь.text
    токен = META_TOKEN.search(очередь.text)
    assert токен is not None

    одобрение: Response = client.post(
        f"{ADMIN_USERS_PATH}/{account.id}/approve",
        data={CSRF_FORM_FIELD: токен.group(1)},
        headers=_headers(ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert одобрение.status_code == 302
    assert "note=approved" in одобрение.headers["location"]
    assert store.commits >= 1

    assert account.state == "active", "состояние не перешло после одобрения"
    assert (
        account.approved_by == _учётка(store, ADMIN_LOGIN).id
    ), "автор одобрения — не тот администратор"
    assert account.approved_at is not None

    консоль = гость.get(SESSIONS_PATH, headers=_headers(GUEST_ADDRESS), follow_redirects=False)
    assert консоль.status_code == 200, консоль.text[:300]
    assert ACCOUNT_STATE_EXPLANATIONS["awaiting_approval"] not in консоль.text

    раздел = client.get(ADMIN_USERS_PATH, headers=_headers(ADMIN_ADDRESS), follow_redirects=False)
    assert EMPTY_QUEUE_NOTE in раздел.text, "после одобрения очередь осталась непустой"
    assert (
        STATE_LABELS["active"] in раздел.text
    ), "список учётных записей не показал новое состояние"
