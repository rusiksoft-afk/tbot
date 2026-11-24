"""Сброс второго фактора учётной записи администратором — срез `R4b` задачи `T-109` (§8.1, §8.2,
§8.7 «отзыв 2FA» и «неудачные попытки 2FA», §9.3 п. 6 «сброс 2FA», `ADR-013`, `ADR-016` п. 6,
`ADR-027`).

Здесь закрывается последнее имя реестра §8.7 раздела identity без производителя. Предмет проверки —
не «появилась ещё одна страница раздела», а четыре правила, которые без этой страницы остаются
невыполнимыми:

* **Действие требует код второго фактора администратора, а не только полный шаг сеанса** (§8.1
  «сброс администратора требует TOTP администратора» при отказе по e-mail). Полный шаг был
  выполнен при входе; если системе достаточно шага, поле кода на странице — декорация. Поэтому
  проверяются пустое поле, неверный код и повтор уже израсходованного шага: расход кода — свойство
  `ADR-013` п. 4 (`last_used_step`), а не «эта цель уже обработана».
* **Сброс не оставляет ни одного следа прежнего второго фактора**: вместе с привязкой отзываются
  живые сеансы цели и аннулируются неиспользованные резервные коды (`ADR-016` п. 6). Кука,
  выпущенная под вторым фактором, и код из пачки, выданной тем же вторым фактором, — это вход без
  фактора, который администратор только что снял (§8.2 «политика `mfa_required=true`, отключить
  нельзя»).
* **Отказ не трогает ничего**, включая шаг второго фактора администратора там, где проверять
  нечего: отказ по состоянию и отказ по коду обязаны быть разными ответами (§9.1), иначе
  безобидный просмотр сжигал бы шаг и двигал ленту неудач.
* **Строка журнала ровно одна** и она про действие, а не про объект: субъект — администратор,
  объект — цель, в деталях — причина, состояние привязки и число закрытых сеансов и кодов, без
  секретов (`ADR-025` п. 6: реестр §8.7 даёт на такое решение одно имя `totp.revoked`, а не пучок
  `session.revoke`).

Помощники привязки (`_войти`, `_начать_привязку`, `_подтвердить`, `_пара`) повторяют
`tests/integration/test_web_totp_page.py`, а не импортируются из него: тесты смежного среза не
импортируют друг друга. Повтор здесь означает, что администратор входит и привязывается **тем же
путём страницы**, что и обычный пользователь (§9.2 «взаимодействие — формы браузера»): сеанс
администратора не заводится в обход системы входа, иначе «есть полный шаг» ничего бы не значило.
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
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.routes import admin_users as admin_routes
from apps.web.routes import invitations as invitation_routes
from apps.web.routes import login as login_routes
from apps.web.routes import profile as profile_routes
from apps.web.routes import sessions as session_routes
from apps.web.routes import totp as totp_routes
from apps.web.routes.totp import (
    FIELD_CODE,
    FIELD_FIRST_CODE,
    FIELD_SECOND_CODE,
)
from apps.web.security import rate_limit as rate_limit_module
from apps.web.security import sessions as security_sessions
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.sessions import (
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    SESSION_EXPIRED_PATH,
    TOTP_CODE_PATH,
)
from packages.common.config import Settings
from packages.common.crypto import KeyRing, load_key_ring
from packages.identity.backup_codes import BACKUP_CODE_COUNT, hash_backup_code, new_backup_codes
from packages.identity.sessions import create_session
from packages.identity.totp import TOTP_PERIOD_SECONDS, totp_code
from packages.identity.totp_enrollment import new_enrollment
from packages.storage.models import AuditLogEntry, TotpEnrollment, User, UserSession
from tests.integration.web_support import (
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
    set_kek_file,
)

#: Момент, который подменён в `utc_now` (§2.2 «тестовое время только через инъекцию»; в CI `sleep`
#: запрещён `.github/workflows/ci.yml`).
FROZEN: Final = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)

ADMIN_LOGIN: Final = "admin.srez-r4b"
TARGET_LOGIN: Final = "op.cel-r4b"
OTHER_LOGIN: Final = "op.sosed-r4b"

#: Адреса из резервных диапазонов RFC 5737: лента неудач, окно перебора и пределы частоты
#: привязаны к адресу (§8.3), поэтому адрес обязан быть явным и разным у разных попыток.
ADMIN_ADDRESS: Final = "203.0.113.71"
STRANGER_ADDRESS: Final = "203.0.113.72"
BAD_CODE_ADDRESS: Final = "203.0.113.73"
BAD_CODE_ADDRESS_2: Final = "203.0.113.74"

ADMIN_ROLE: Final = "admin"
OPERATOR_ROLE: Final = "operator"

META_TOKEN: Final = re.compile(r'name="csrf-token" content="([^"]+)"')
SECRET_BLOCK: Final = re.compile(r"<code>([A-Z2-7]{16,128})</code>")
#: Показные формы выпущенной пачки (`ABCDE-FGHJK`): успешное подтверждение обязано показать
#: все `BACKUP_CODE_COUNT` значений в одном ответе (`ADR-016` п. 2 и п. 11).
ISSUED_BLOCK: Final = re.compile(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>")
NOTE_IN_LOCATION: Final = re.compile(rf"\b{admin_routes.NOTE_QUERY}=([a-z_]+)")


class Clock:
    """Задаваемое «сейчас» для слоя входа, раздела и лимитов (тот же приём, что в `R3f`)."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замороженное время во всех модулях, где `utc_now()` вызывают напрямую (§2.2).

    К набору `test_web_totp_page.py` добавлен сам раздел: сброс пишет审定ку и метки отзыва
    моментом из `admin_users.py`, и пропуск этого модуля означал бы, что часть проверок живёт в
    реальном времени.
    """
    fake = Clock(FROZEN)
    for module in (
        login_routes,
        session_routes,
        totp_routes,
        invitation_routes,
        profile_routes,
        admin_routes,
        security_sessions,
        rate_limit_module,
    ):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def kek(tmp_path: Path) -> Path:
    """Файл ключей в песочнице: тот же формат, что пишет `deploy/vps/keys_setup.py` (`ADR-014` п. 5).

    Режим ставится явно: на Linux файл получил бы 0644, и боевая политика прав отказала бы ему,
    поэтому отказ пришёл бы из-за прав, а не из-за проверяемого. На Windows битов POSIX нет — этот
    дефект виден только на Linux-ветке прогона.
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
def ring(kek: Path) -> KeyRing:
    """Кольцо KEK тем же кодом загрузки, что у приложения: привязки целей строятся настоящим
    конвертом, а не подделанной строкой (`ADR-014` п. 5)."""
    return load_key_ring(kek)


@pytest.fixture
def store(ring: KeyRing) -> MemoryStore:
    """Администратор и две живые цели: привязка, сеанс на шаге `full` и пачка резервных кодов у каждой.

    Привязки и сеансы целей заводятся напрямую — проверяется отзыв, а не выпуск; состояние
    «привязка подтверждена» ставится одним полем, как тесты раздела ставят `state` учётки.
    Администратор же заводится **без** привязки и **без** сеанса: их создаёт `администратор()` тем
    же путём страницы, что и обычный пользователь, иначе «у администратора полный шаг» не значило
    бы ничего.

    Целей две намеренно: «мутация не тронула лишних строк» (§8.8, `ADR-017` п. 5) проверяется на
    живом соседнем объекте, а не отсутствием второй записи в списке.
    """
    memory = MemoryStore()
    admin = _учётка(memory, ADMIN_LOGIN, role=ADMIN_ROLE)
    assert admin.id is not None
    for login_value in (TARGET_LOGIN, OTHER_LOGIN):
        target = _учётка(memory, login_value, role=OPERATOR_ROLE)
        assert target.id is not None
        привязка = new_enrollment(user_id=target.id, now=FROZEN, ring=ring).enrollment
        привязка.confirmed_at = FROZEN
        memory.add(привязка)
        memory.insert_backup_code_hashes(
            target.id, [hash_backup_code(code) for code in new_backup_codes()]
        )
        # `expires_at` ставит сам `create_session` (idle 30 минут от момента): переписывать его
        # локальной константой здесь нечем, а расхождение с доменной границей сделало бы
        # «сеанс жив» непроверяемым свойством домена.
        issued = create_session(
            target.id, user_agent=f"агент {login_value}", auth_step="full", now=FROZEN
        )
        memory.seed_session(issued)
    memory.commit()
    return memory


def _учётка(store: MemoryStore, login_value: str, *, role: str) -> User:
    """Живая учётная запись с паролем фикстур входа и проставленным `id`.

    В памяти нет `INSERT`, поэтому движковый `DEFAULT` первичного ключа не срабатывает и `id`
    остался бы `None`: с `None` сравнивались бы субъект журнала, `user_id` привязки и предикаты
    репозитория, и проверка авторства проходила бы молча (тот же урок, что у
    `test_web_admin_accounts.py`).
    """
    user = store.seed_user(login=login_value, password=TEST_PASSWORD, role=role)
    user.id = uuid4()
    return user


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock, kek: Path) -> Iterator[TestClient]:
    assert clock() == FROZEN, "фикстура сдвинула время, а тест ждёт `FROZEN`"
    with build_client(store, settings) as test_client:
        set_kek_file(test_client, kek)
        yield test_client


# ─── помощники: путь страницы, а не API (§9.2) ───────────────────────────────────────────────


def _заголовки(*, address: str | None = None, origin: str = "https://testserver") -> dict[str, str]:
    headers = {"Origin": origin, "User-Agent": "totp-reset-test"}
    if address is not None:
        headers["X-Forwarded-For"] = address
    return headers


def _статус(response: Response) -> int:
    """Код ответа типизированно: у `httpx` он объявлен как `Any`, сравнение нужно с `int`."""
    status: int = response.status_code
    return status


def _токен(client: TestClient) -> str:
    """CSRF-токен из метаданных страницы привязки (§8.3, `ADR-008`).

    Страница привязки отдаёт `200` на шагах `'password'` и `'totp'`, поэтому токен доступен и до
    подтверждения привязки, и до перехода сеанса на `full` (тот же приём, что в
    `test_web_totp_page.py`).
    """
    ответ = client.get(MFA_ENROLL_PATH, headers=_заголовки(address=ADMIN_ADDRESS))
    assert _статус(ответ) == 200, ответ.text[:300]
    добыча = META_TOKEN.search(ответ.text)
    assert добыча is not None, f"в странице нет meta токена: {ответ.text[:300]}"
    return добыча.group(1)


def _токен_раздела(client: TestClient, *, address: str = ADMIN_ADDRESS) -> str:
    """CSRF-токен со страницы раздела: он нужен мутациям раздела, где сеанс уже на шаге `full`."""
    ответ = client.get(admin_routes.ADMIN_USERS_PATH, headers=_заголовки(address=address))
    assert _статус(ответ) == 200, ответ.text[:300]
    добыча = META_TOKEN.search(ответ.text)
    assert добыча is not None, "страница раздела не отдала токен формы"
    return добыча.group(1)


def _пара(secret: str, момент: datetime) -> tuple[str, str]:
    """Два кода из соседних окон: подтверждение привязки требует именно их (§8.2, `ADR-013`)."""
    return (
        totp_code(secret, момент),
        totp_code(secret, момент + timedelta(seconds=TOTP_PERIOD_SECONDS)),
    )


def _пользователь(store: MemoryStore, login_value: str) -> User:
    user = store.user_by_login(login_value)
    assert user is not None, f"учётной записи {login_value!r} нет"
    assert user.id is not None, f"у записи {login_value!r} нет идентификатора"
    return user


def _привязка(store: MemoryStore, user_id: UUID) -> TotpEnrollment:
    """Действующая привязка, гарантированно существующая.

    Проверки обращаются к её полям (`revoked_at`, `confirmed_at`, `last_used_step`), и писать
    `_привязка(store, ...).revoked_at` значило бы просить mypy поверить в то, чего тип не
    доказывает: `active_enrollment` возвращает `None`, когда привязки нет. Здесь отсутствие
    привязки — провал проверки с именем учётной записи, а не `AttributeError` в середине теста.
    """
    row = store.active_enrollment(user_id)
    assert row is not None, f"действующей привязки у {user_id} нет"
    return row


def _привязки(store: MemoryStore, user_id: UUID) -> tuple[TotpEnrollment, ...]:
    return tuple(row for row in store.enrollments() if row.user_id == user_id)


def _попытки(store: MemoryStore, user_id: UUID, clock: Clock) -> int:
    return len(store.totp_failures(user_id, not_before=clock() - timedelta(minutes=15)))


def _журнал(store: MemoryStore, action: str) -> list[AuditLogEntry]:
    return [row for row in store.audit_rows if row.action == action]


def _событие(store: MemoryStore, action: str) -> AuditLogEntry:
    """Ровно одна строка с этим именем: вторая — удвоенное событие, ноль — событие без носителя."""
    rows = _журнал(store, action)
    assert (
        len(rows) == 1
    ), f"ожидается ровно одна строка {action!r}, получено {len(rows)}: {[r.action for r in store.audit_rows]}"
    return rows[0]


def _живые_сеансы(store: MemoryStore, user_id: UUID, clock: Clock) -> tuple[UserSession, ...]:
    return store.user_sessions(user_id, not_expired_before=clock())


def администратор(client: TestClient, store: MemoryStore, clock: Clock) -> str:
    """Полный путь администратора: пароль → выдача секрета → подтверждение → код → шаг `full`.

    Возвращается секрет генератора: он нужен, чтобы вычислять коды для самого действия (§8.1), и
    больше ни для чего — в журнал, в форму и в лог он не попадает (`ADR-014` п. 6, `ADR-025` п. 3).

    Сдвиги часов между шагами церемонии — не «запас на всякий случай»: `claim_totp_step`
    расходует окно монотонно (`ADR-013` п. 4). Пара подтверждения занимает окно, следующее за
    первым кодом, поэтому код входа обязан прийти из **следующего** за парой окна (сдвиг на два
    окна: одно — второе значение пары, второе — сам код), а код самого сброса — из окна после
    кода входа. Тот же расчёт в `test_web_totp_page.py` держит проверка «блокировка не расходует
    код».
    """
    ответ = login(client, login_value=ADMIN_LOGIN, password=TEST_PASSWORD)
    assert _статус(ответ) == 302, ответ.text[:300]

    старт = client.post(
        MFA_ENROLL_START_PATH,
        data={CSRF_FORM_FIELD: _токен(client)},
        headers=_заголовки(address=ADMIN_ADDRESS),
    )
    assert _статус(старт) == 200, старт.text[:300]
    добыча = SECRET_BLOCK.search(старт.text)
    assert добыча is not None, "страница привязки не показала секрет"
    secret = добыча.group(1)

    первый, второй = _пара(secret, clock())
    подтверждение = client.post(
        MFA_ENROLL_VERIFY_PATH,
        data={
            CSRF_FORM_FIELD: _токен(client),
            FIELD_FIRST_CODE: первый,
            FIELD_SECOND_CODE: второй,
        },
        headers=_заголовки(address=ADMIN_ADDRESS),
        follow_redirects=False,
    )
    # Успешное подтверждение — `200` с пачкой резервных кодов, а не `302` (`ADR-016` п. 2 и п. 11):
    # значения показываются ровно один раз и ровно в этом ответе. Проверка держит и показ пачки
    # целиком: без неё администратор остался бы без кодов восстановления, а дальше тест проверял бы
    # состояние, которого боевой путь не производит.
    assert _статус(подтверждение) == 200, подтверждение.text[:300]
    assert (
        len(ISSUED_BLOCK.findall(подтверждение.text)) == BACKUP_CODE_COUNT
    ), "ответ подтверждения не показал пачку резервных кодов целиком"
    assert _привязка(store, _пользователь(store, ADMIN_LOGIN).id).confirmed_at is not None

    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    код = client.post(
        TOTP_CODE_PATH,
        data={CSRF_FORM_FIELD: _токен(client), FIELD_CODE: totp_code(secret, clock())},
        headers=_заголовки(address=ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert _статус(код) in (302, 303), "администратор не переведён на шаг `full`"
    # Окно кода входа тоже занято: код сброса обязан прийти из следующего, иначе отказ по
    # повтору шага (`ADR-013` п. 4) наступил бы раньше проверяемого действия.
    clock.advance(seconds=2 * TOTP_PERIOD_SECONDS)
    return secret


def _адрес_сброса(user_id: UUID | str) -> str:
    return admin_routes.ADMIN_ACCOUNT_TOTP_RESET_PATH.replace("{user_id}", str(user_id))


def _сброс(
    client: TestClient,
    user_id: UUID | str,
    код: str,
    *,
    address: str = ADMIN_ADDRESS,
    токен: str | None = "подойдёт",
) -> Response:
    """POST сброса (§9.3 п. 6). `токен=None` — поле защиты не отправляется вовсе (§8.3)."""
    payload: dict[str, str] = {}
    if токен is not None:
        payload[CSRF_FORM_FIELD] = (
            токен if токен != "подойдёт" else _токен_раздела(client, address=address)
        )
    if код:
        payload[FIELD_CODE] = код
    ответ: Response = client.post(
        _адрес_сброса(user_id),
        data=payload,
        headers=_заголовки(address=address),
        follow_redirects=False,
    )
    return ответ


def _заметка(ответ: Response) -> str | None:
    """Код исхода из адреса перенаправления; `None` — кода нет."""
    добыча = NOTE_IN_LOCATION.search(ответ.headers.get("location", ""))
    return добыча.group(1) if добыча else None


# ─── страница: кому, что будет и какой код нужен (§9.1, §9.3 п. 6) ────────────────────────────


def test_страница_называет_объект_следствие_и_требуемый_код_и_ничего_не_меняет(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """До действия страница обязана сказать, кому, что будет и какой код требуется.

    §9.3 п. 6 требует «с TOTP администратора и предупреждением». Если предупреждения о сеансах,
    резервных кодах и повторной привязке нет, оператор жмёт кнопку, не зная последствий, а
    «сообщение объясняет причину» (§9.1) превращается в постфактум. `GET` при этом ничего не
    меняет: двухшаблонность (§9.2) — это не только кнопки, но и то, что просмотр не исполняет
    действие.
    """
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None

    ответ = client.get(_адрес_сброса(target.id), headers=_заголовки(address=ADMIN_ADDRESS))

    assert _статус(ответ) == 200, ответ.text[:300]
    страница = ответ.text
    assert TARGET_LOGIN in страница, "страница не назвала объект (§9.1)"
    assert admin_routes.TOTP_BOUND_LABEL in страница, "состояние привязки цели не объяснено"
    assert admin_routes.TOTP_RESET_WARNING in страница, "нет предупреждения о сеансах и кодах"
    assert admin_routes.TOTP_RESET_CODE_NOTE in страница, "нет предупреждения о требуемом коде"
    assert f'name="{FIELD_CODE}"' in страница, "поле кода администратора пропало"
    assert f'action="{_адрес_сброса(target.id)}"' in страница, "форма ведёт не на действие"
    assert store.active_enrollment(target.id) is not None
    assert _привязка(store, target.id).revoked_at is None
    assert all(row.revoked_at is None for row in _живые_сеансы(store, target.id, clock))
    assert not _журнал(store, "totp.revoked"), "чтение страницы записало отзыв"


def test_страница_не_предлагает_действие_если_привязки_нет(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """У записи без привязки кнопки нет, но страница объясняет почему (§9.1, §9.2 «без JS»)."""
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None
    прежняя = store.active_enrollment(target.id)
    assert прежняя is not None
    прежняя.revoked_at = clock()

    страница = client.get(_адрес_сброса(target.id), headers=_заголовки(address=ADMIN_ADDRESS)).text

    assert admin_routes.TOTP_NONE_LABEL in страница
    assert admin_routes.TOTP_NOT_BOUND_HINT in страница
    assert "<button" not in страница, "страница предлагает действие, которое сервер отвергнет"


def test_чужой_сеанс_страницу_не_получает_и_привязку_не_трогает(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Оператор на шаге `full` страницы не видит: раздел закрыт ролью (§8.5, `ADR-017` п. 2).

    Шаг у операторского сеанса заведомо `full` (он создан так же, как сеанс администратора),
    поэтому отказ даёт именно роль, а не шаг: проверка матрицы допуска и проверка состояния —
    разные проверки, и здесь держится первая. Обратная половина важна не меньше: чужая попытка не
    отозвала привязку цели (§8.8).
    """
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None
    # Сеанс цели заводится на шаге `full` и надевается на клиента кукой: иначе проверялся бы шаг
    # `'totp'` (приложение вместо страницы раздела показывает страницу кода, §9.2), а не роль.
    client.cookies.clear()
    issued = create_session(
        target.id, user_agent="чужой полный сеанс", auth_step="full", now=clock()
    )
    store.seed_session(issued)
    client.cookies.set(security_sessions.SESSION_COOKIE_NAME, issued.secret)

    ответ = client.get(_адрес_сброса(target.id), headers=_заголовки(address=STRANGER_ADDRESS))

    assert _статус(ответ) == 403, ответ.text[:300]
    assert store.active_enrollment(target.id) is not None
    assert _привязка(store, target.id).revoked_at is None


# ─── второй фактор администратора обязателен (§8.1) ───────────────────────────────────────────


def test_POST_без_токена_ничего_не_меняет(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Отказ по защите (§8.3, `ADR-008`) опережает и проверку состояния, и проверку кода."""
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None

    ответ = _сброс(client, target.id, "000000", токен=None)

    assert _статус(ответ) == 403, ответ.text[:300]
    # Ответ — общий отказ допуска, а не страница действия: по различию ответов подбором
    # узнавалось бы, где живёт запрошенный контур (`ADR-008`). Причина отказа при этом уходит в
    # журнал отдельным событием (§8.7), и здесь это проверяется: отказ, не оставивший события,
    # неотличим от отказа, которого не было.
    assert "csrf" not in ответ.text.lower()
    assert TARGET_LOGIN not in ответ.text
    assert admin_routes.TOTP_RESET_WARNING not in ответ.text
    assert _журнал(store, "auth.csrf_rejected"), "отказ по защите не записан в журнал (§8.7)"
    assert _привязка(store, target.id).revoked_at is None
    assert all(row.revoked_at is None for row in _живые_сеансы(store, target.id, clock))
    assert not _журнал(store, "totp.revoked")
    assert not _журнал(store, "totp.verify_failed")


def test_без_кода_сброс_не_исполняется(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Пустое поле кода — отказ с объяснением; привязка и сеансы цели целы (§9.1, §8.2, §8.1).

    Если бы система довольствовалась полным шагом сеанса, §8.1 («сброс администратора требует TOTP
    администратора») оставался бы невыполненным, а поле кода на странице — декорацией. Отдельно
    держится, что отказ не записал отзыв: «привязка снята» и «привязку не удалось снять» — разные
    события реестра §8.7.
    """
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None

    ответ = _сброс(client, target.id, "")

    assert _статус(ответ) == 400, ответ.text[:300]
    assert totp_routes.EMPTY_CODE_DETAIL in ответ.text, "отказ без объяснения причины (§9.1)"
    assert _привязка(store, target.id).revoked_at is None
    assert all(row.revoked_at is None for row in _живые_сеансы(store, target.id, clock))
    assert all(code.used_at is None for code in store.backup_code_rows(target.id))
    assert not _журнал(store, "totp.revoked")


def test_неверный_код_отказывается_и_двигает_ленту_а_стадия_строки_особая(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Неверный код: `401`, запись в ленту `totp_failures`, строка `totp.verify_failed` (§8.1, §8.7).

    Стадия строки — `admin_totp_reset`, а не `login_code`: код вводит администратор на опасном
    админском действии, и разбор (§8.7) обязан отличать этот перебор от перебора кода входа, а
    субъект строки — администратор, а не цель: журнал описывает действие, а не объект.
    """
    администратор(client, store, clock)
    admin = _пользователь(store, ADMIN_LOGIN)
    target = _пользователь(store, TARGET_LOGIN)
    assert admin.id is not None
    assert target.id is not None

    ответ = _сброс(client, target.id, "000000", address=BAD_CODE_ADDRESS)

    assert _статус(ответ) == 401, ответ.text[:300]
    assert _попытки(store, admin.id, clock) == 1, "отказ не попал в ленту неудач (§8.2)"
    строка = _событие(store, "totp.verify_failed")
    детали = строка.details
    assert детали is not None
    assert детали["stage"] == admin_routes.TOTP_RESET_STAGE
    assert str(строка.actor) == str(admin.id), "субъект отказа — не администратор"
    assert _привязка(store, target.id).revoked_at is None
    assert not _журнал(store, "totp.revoked")


def test_повтор_израсходованного_кода_на_второй_цели_не_срабатывает(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Один и тот же код не сбрасывает две учётные записи: шаг расходуется монотонно (`ADR-013` п. 4).

    Проверка нужна именно на втором объекте: отказ по повтору — свойство расхода шага
    (`claim_totp_step`), а не «эта цель уже обработана». Иначе одна подсмотренная последовательность
    кодов давала бы сброс сразу всем записям раздела, а §8.2 («код одноразовый») не выполнялся бы.
    """
    secret = администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    other = _пользователь(store, OTHER_LOGIN)
    assert target.id is not None
    assert other.id is not None
    код = totp_code(secret, clock())

    первый = _сброс(client, target.id, код)
    assert _статус(первый) in (302, 303), первый.text[:300]

    второй = _сброс(client, other.id, код)

    assert _статус(второй) in (401, 403), "тот же шаг второго фактора приняли второй раз"
    assert store.active_enrollment(other.id) is not None
    assert _привязка(store, other.id).revoked_at is None
    assert all(row.revoked_at is None for row in _живые_сеансы(store, other.id, clock))
    assert len(_журнал(store, "totp.revoked")) == 1


# ─── исполнение: привязка, сеансы и резервные коды закрываются вместе ─────────────────────────


def test_сброс_отзывает_привязку_сеансы_и_неиспользованные_коды(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Ни одного следа прежнего второго фактора (§8.2 «отключить нельзя», `ADR-016` п. 6).

    Отзыв без сеансов оставил бы живую куку: вход по ней шёл бы без второго фактора, который
    администратор только что снял. Отзыв без резервных кодов оставил бы пачку, выданную тем же
    вторым фактором: код из неё — тоже вход без фактора. Обе половины правила перечислены в
    предупреждении страницы, поэтому проверяются на состоянии базы, а не на тексте.
    """
    secret = администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None
    было_кодов = store.backup_code_rows(target.id)
    assert len(было_кодов) == BACKUP_CODE_COUNT
    assert all(code.used_at is None for code in было_кодов)

    ответ = _сброс(client, target.id, totp_code(secret, clock()))

    assert _статус(ответ) in (302, 303), ответ.text[:300]
    assert _заметка(ответ) == "totp_reset"
    assert store.active_enrollment(target.id) is None, "привязка осталась действующей"
    снятые = [row for row in _привязки(store, target.id) if row.revoked_at is not None]
    assert len(снятые) == 1
    assert снятые[0].confirmed_at is not None, "у снятой строки пропала отметка подтверждения"
    сеансы = _живые_сеансы(store, target.id, clock)
    assert сеансы == (), "после сброса остались живые сеансы цели"
    after = store.backup_code_rows(target.id)
    assert len(after) == BACKUP_CODE_COUNT, "аннулирование удалило строки кодов, а не пометило"
    assert all(code.used_at is not None for code in after)
    # Привязка администратора цела: действие касалось цели, а не того, кто его выполнил (§8.8).
    assert store.active_enrollment(_пользователь(store, ADMIN_LOGIN).id) is not None


def test_сброс_не_трогает_чужие_привязки_сеансы_и_коды(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Один вызов — одна цель: у второй записи сохранены привязка, сеансы и пачка кодов (§8.8)."""
    secret = администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    other = _пользователь(store, OTHER_LOGIN)
    assert target.id is not None
    assert other.id is not None

    ответ = _сброс(client, target.id, totp_code(secret, clock()))

    assert _статус(ответ) in (302, 303)
    assert store.active_enrollment(other.id) is not None
    assert all(row.revoked_at is None for row in _живые_сеансы(store, other.id, clock))
    assert all(code.used_at is None for code in store.backup_code_rows(other.id))


def test_сброс_чужой_записи_не_отзывает_сеанс_администратора(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Раздел остаётся доступным: администратор действовал не над собой (§9.3 п. 6)."""
    secret = администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None

    assert _статус(_сброс(client, target.id, totp_code(secret, clock()))) in (302, 303)

    assert _статус(client.get(admin_routes.ADMIN_USERS_PATH)) == 200


def test_свой_сброс_отзывает_и_сеанс_администратора(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Сняв собственный второй фактор, администратор теряет доступ (§8.2, §4.1).

    Страница обещает это до действия; если бы сеанс остался живым, раздел висел бы открытым без
    второго фактора — ровно то, чего §8.2 не допускает («отключить нельзя»). Проверка идёт через
    последующий `GET`: именно так человек увидит исход, а не через число отозванных строк.
    """
    secret = администратор(client, store, clock)
    admin = _пользователь(store, ADMIN_LOGIN)
    assert admin.id is not None

    ответ = _сброс(client, admin.id, totp_code(secret, clock()))

    assert _статус(ответ) in (302, 303), ответ.text[:300]
    assert store.active_enrollment(admin.id) is None
    assert (
        _живые_сеансы(store, admin.id, clock) == ()
    ), "сеанс администратора пережил снятие фактора"
    следом = client.get(admin_routes.ADMIN_USERS_PATH, follow_redirects=False)
    assert _статус(следом) in (302, 303)
    assert SESSION_EXPIRED_PATH in str(следом.headers.get("location", ""))


# ─── состояния, в которых сбрасывать нечего (§8.2) ────────────────────────────────────────────


def test_без_привязки_сбрасывать_нечего_а_код_администратора_не_сгорает(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Отказ по отсутствующей привязке не двигает шаг второго фактора администратора и ленту.

    Иначе повторная попытка после уже сделанного сброса сжигала бы шаг и писала неудачу, а
    «отказ по состоянию» стал бы неотличим от «отказа по коду» (§9.1 требует объяснять причину).
    """
    secret = администратор(client, store, clock)
    admin = _пользователь(store, ADMIN_LOGIN)
    target = _пользователь(store, TARGET_LOGIN)
    assert admin.id is not None
    assert target.id is not None
    прежняя = store.active_enrollment(target.id)
    assert прежняя is not None
    прежняя.revoked_at = clock()
    шаг_до = _привязка(store, admin.id).last_used_step

    ответ = _сброс(client, target.id, totp_code(secret, clock()))

    assert _статус(ответ) in (302, 303)
    assert _заметка(ответ) == "refused_no_totp"
    assert _привязка(store, admin.id).last_used_step == шаг_до, "отказ израсходовал шаг"
    assert _попытки(store, admin.id, clock) == 0, "отказ по состоянию записал неудачу"
    assert not _журнал(store, "totp.revoked")
    assert not _журнал(store, "totp.verify_failed")


def test_архивированной_записи_формы_нет_а_POST_отказывается_причиной(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Архив — терминальное состояние: кнопки нет, а `POST` отвечает причиной, а не кодом (§8.2)."""
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None
    target.state = "archived"

    страница = client.get(_адрес_сброса(target.id), headers=_заголовки(address=ADMIN_ADDRESS)).text
    ответ = _сброс(client, target.id, "123456")

    assert admin_routes.TOTP_ARCHIVED_HINT in страница
    assert "<button" not in страница, "архивной записи предложено действие"
    assert _статус(ответ) in (302, 303)
    assert _заметка(ответ) == "refused_totp_state"
    assert _привязка(store, target.id).revoked_at is None
    assert not _журнал(store, "totp.revoked")


# ─── журнал: ровно одна строка, и в ней нет секретов (§8.7, срез `R3` задачи `T-109) ──────────


def test_сброс_пишет_одну_строку_с_причиной_и_числом_закрытых_строк(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """`totp.revoked`: субъект — администратор, объект — цель, детали — следствия без секретов.

    Числа закрытых сеансов и аннулированных кодов уходят в детали вместо отдельных строк
    `session.revoke`: реестр §8.7 даёт на такое решение одно имя (`ADR-025` п. 6), и ровно так же
    устроена строка `account.state_changed` (срез `R3`). Детали — счётчики и состояние привязки:
    ни кодов, ни секретов, ни значений резервных кодов в них нет, и проверка перечисляет ключи,
    чтобы новое поле не притащило материал входа (§8.7, `ADR-004`, `ADR-019`).
    """
    secret = администратор(client, store, clock)
    admin = _пользователь(store, ADMIN_LOGIN)
    target = _пользователь(store, TARGET_LOGIN)
    assert admin.id is not None
    assert target.id is not None
    прежняя = store.active_enrollment(target.id)
    assert прежняя is not None

    ответ = _сброс(client, target.id, totp_code(secret, clock()))

    assert _статус(ответ) in (302, 303)
    строка = _событие(store, "totp.revoked")
    assert str(строка.actor) == str(admin.id)
    assert строка.entity == "user"
    assert str(строка.entity_id) == str(target.id)
    assert строка.at == clock(), "момент строки не совпадает с моментом действия"
    assert строка.hash, "у строки нет хэша цепочки — разбору (§8.7) не на чем работать"
    детали = строка.details
    assert детали is not None
    assert детали["reason"] == "admin_reset"
    assert детали["confirmed"] is True
    assert детали["enrollment_id"] == str(прежняя.id)
    assert детали["sessions_revoked"] == 1
    assert детали["backup_codes_invalidated"] == BACKUP_CODE_COUNT
    assert set(детали) == {
        "reason",
        "confirmed",
        "enrollment_id",
        "sessions_revoked",
        "backup_codes_invalidated",
    }, f"в деталях появились новые поля: {sorted(детали)}"
    assert secret not in json.dumps(детали, ensure_ascii=False), "секрет привязки ушёл в журнал"
    assert len(_журнал(store, "session.revoke")) == 0, "отзыв сеансов расщеплён на отдельные строки"


def test_отказ_по_коду_пишет_отдельное_имя_а_не_отзыв(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Неудачная попытка кода — отдельное событие реестра, а не «отзыв без привязки» (§8.7)."""
    администратор(client, store, clock)
    target = _пользователь(store, TARGET_LOGIN)
    assert target.id is not None

    assert _статус(_сброс(client, target.id, "000000", address=BAD_CODE_ADDRESS_2)) == 401

    assert not _журнал(store, "totp.revoked")
    assert len(_журнал(store, "totp.verify_failed")) == 1
