"""События отказов слоя входа в журнале аудита (TZ §8.7, §4.1; `T-109`, срез `R2`, `ADR-009` п. 4).

Половинка в памяти: приложение боевое (`create_app`), репозиторий — `MemoryStore` из
`tests/integration/web_support.py`. Проверяется **факт записи и её содержание**: какое событие
порождает каждый отказ, с каким субъектом, объектом и причиной. Живая половинка —
`tests/integration/test_audit_append_db.py` (job `миграции`): там протокол добавления, блокировка
хвоста, код состояния `23505` и откат транзакции. Переносить это в память нельзя: у памяти нет ни
индексов, ни транзакций, ни advisory-замка, ни `sqlstate`.

Что держится этими проверками и почему именно так:

* **отказ CSRF пишется и на маршрутах без токена** (`/login`, `/invite` — `ADR-008`): если бы
  событие писала только зависимость `require_csrf`, половина отказов §8.7 осталась бы без
  носителя, и журнал входа разошёлся бы с журналом отказов;
* **отказ допуска различается причиной только в журнале** (`ADR-017` п. 4, `AC-identity-01`):
  ответ посетителю остаётся одним и тем же `403`, а разбор видит `role` и `no_account`;
* **причина «учётной записи сеанса больше нет» записывается один раз**: её решает `load_account`,
  а `enforce_role` перехватывает общий отказ — вторая строка на ту же причину исказила бы счётчик
  отказов при разборе;
* **`actor` есть у отказа допуска и отсутствует у отказов до аутентификации** (CSRF, частота):
  журнал не должен содержать выдуманного субъекта (`ADR-025` п. 2);
* **у каждого отказа ровно одна строка с его именем** (`ADR-025` п. 6): точка добавления одна на
  каждое событие, а вторая копия искажает счётчик при разборе так же, как отсутствующая. Сверяется
  имя события, а не весь журнал целиком: срез `R2b` той же задачи `T-109` даёт маршрутам события
  мутаций (вход порождает `session.login`), и они относятся к другому действию, а не к удвоенному
  отказу. Закрытый перечень порождаемых имён держит контракт
  `test_имена_событий_identity_группы_имеют_производителя`;
* **оффлайновая копия журнала строит цепочку так же, как боевой слой** (`hash_prev` из последней
  строки): набор незацепленных хэшей неотличим от повреждённого журнала, поэтому связь записей
  проверяется и здесь.

Чего здесь сознательно нет: проверок `ip` и `request_id` в колонках. Их заполняет контекст
запроса, который в памяти не строится (репозиторий подменяется целиком), и держит их живая
половинка — там же, где настоящая колонка `INET` и настоящая нормализация адреса (`ADR-009`).
"""

from __future__ import annotations

from collections.abc import Iterator
from itertools import pairwise
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.identity.audit import AuditRecordError
from packages.identity.authorization import ADMIN_TIER, DENIAL_NO_ACCOUNT, DENIAL_ROLE
from packages.identity.sessions import advance_auth_step
from packages.storage.audit_store import AuditAppendError
from packages.storage.models import AuditLogEntry
from tests.integration.web_support import (
    TEST_LOGIN,
    MemoryStore,
    build_client,
    login,
    session_cookie,
)

#: Раздел администрирования: оператор туда ходит по матрице §8.8 и получает `403`.
ADMIN_PATH = "/admin/users"
#: Консольный раздел: доступен любой из трёх ролей, поэтому отказ из него — только про
#: отсутствующую строку учётной записи.
CONSOLE_PATH = "/profile/sessions"
#: Чужой источник: проверка `Sec-Fetch-Site`/`Origin` отклоняет такой запрос до разбора формы.
FOREIGN_ORIGIN = "https://evil.example"


@pytest.fixture
def store() -> MemoryStore:
    """Операторская учётная запись: не администратор, поэтому отказ по роли достижим (§8.8)."""
    memory = MemoryStore()
    user = memory.seed_user()
    # `id` проставляет проверка: память не делает `flush`, а прикладной default первичного ключа
    # (`packages/storage/models.py`) срабатывает только на вставке. Без идентификатора субъект
    # отказа был бы `None` и проверка «у отказа допуска субъект есть» теряла бы предмет.
    # Тот же приём, что у среза `R6` (раздел администрирования).
    user.id = uuid4()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> Iterator[TestClient]:
    with build_client(store, settings) as test_client:
        yield test_client


def _full_session(client: TestClient, store: MemoryStore) -> None:
    """Войти и довести сеанс до полного входа.

    Шаг `'full'` ставится доменным переходом по тому же объекту, на который указывает кука:
    второй фактор (`T-103`) и резервный код (`T-104`) в этом срезе не участвуют — проверяется
    отказ допуска, а не механика 2FA. Тот же приём, что у среза `R3d` (лимы частоты).
    """
    response = login(client)
    assert response.status_code in (200, 302, 303), f"вход не состоялся: {response.status_code}"
    secret = session_cookie(client)
    assert secret, "куки сессии нет — тест вошёл не туда"
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")


def _rows(store: MemoryStore) -> list[AuditLogEntry]:
    """Страницы журнала оффлайновой копии в порядке добавления."""
    return list(store.audit_rows)


def _only(store: MemoryStore, action: str) -> AuditLogEntry:
    """Ровно одна строка с этим событием: вторая на тот же отказ — удвоенное событие (§8.7).

    Фильтр по имени, а не «весь журнал»: вход в приложении порождает и собственное событие (§8.7,
    срез `R2b`), оно обязано оставаться видимым, поэтому проверка отказа не подменяется проверкой
    входа и наоборот.
    """
    rows = [row for row in _rows(store) if row.action == action]
    assert len(rows) == 1, (
        f"ожидается одна журнальная строка {action!r}, получено {len(rows)}: "
        f"{[row.action for row in _rows(store)]}"
    )
    return rows[0]


# ─── `auth.csrf_rejected` (§8.7, `ADR-008`) ──────────────────────────────────────────────────


def test_отказ_по_отсутствию_токена_пишет_причину(client: TestClient, store: MemoryStore) -> None:
    """Мутация без токена: `403` посетителю и `auth.csrf_rejected` с причиной в журнале.

    Причина в `details` — ровно та же строка, что уходит в лог процесса: по ней разбор отличает
    «токена нет» от «токен не совпал» и от чужого источника, не подсовывая это различие
    посетителю (`ADR-008`, §9).
    """
    login(client)
    response = client.post("/logout", data={"любое": "поле"}, follow_redirects=False)

    assert response.status_code == 403
    row = _only(store, "auth.csrf_rejected")
    assert row.entity == "request"
    assert row.entity_id == "/logout"
    assert row.details == {"reason": "токена нет"}
    assert row.actor is None, "субъекта у отказа CSRF нет: проверка идёт до опознания сеанса"


def test_чужой_источник_на_маршруте_без_токена_тоже_пишет_отказ(
    client: TestClient, store: MemoryStore
) -> None:
    """`/login` не принимает `csrf_token` (`ADR-008`), но отказ источника пишет событие.

    Если бы событие писала только зависимость `require_csrf`, этот случай остался бы без носителя:
    журнал показал бы «ни одной попытки межсайтового входа», хотя попытки были.
    """
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль"},
        headers={"Origin": FOREIGN_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 403
    row = _only(store, "auth.csrf_rejected")
    assert row.entity_id == "/login"
    details = row.details
    assert details is not None
    assert "Origin" in str(details["reason"]), (
        "в причине отказа нет имени заголовка: разбор не отличит чужой источник от поддельного "
        "токена"
    )


def test_несовпавший_токен_пишет_отдельную_причину(client: TestClient, store: MemoryStore) -> None:
    """Токен предъявлен, но не тот: причина «токен не совпал», а не «токена нет».

    Различие причин нужно разбору (§8.7): попытка подобрать токен и запрос без токена — разные
    признаки, и отвечать они должны одинаково наружу, но по-разному в журнале.
    """
    login(client)
    response = client.post(
        "/logout",
        data={"csrf_token": "Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdefGHIJK"},
        follow_redirects=False,
    )

    assert response.status_code == 403
    row = _only(store, "auth.csrf_rejected")
    assert row.details == {"reason": "токен не совпал"}


# ─── `auth.access_denied` (§8.7, `ADR-017` п. 4) ─────────────────────────────────────────────


def test_отказ_по_роли_пишет_причину_требуемую_роль_и_актора(
    client: TestClient, store: MemoryStore
) -> None:
    """Оператор в разделе администрирования: ответ безликий, журнал различает причину.

    `DENIAL_BODY` не сообщает ни требуемую роль, ни имя маршрута (`AC-identity-01`), но разбор
    обязан видеть и то, и другое: без `required` «роль ниже требуемой» неотличима от «человек
    залез не туда» (§8.7).
    """
    _full_session(client, store)
    response = client.get(ADMIN_PATH)

    assert response.status_code == 403
    row = _only(store, "auth.access_denied")
    assert row.details == {"reason": DENIAL_ROLE, "required": ADMIN_TIER}
    assert row.actor is not None, "у отказа допуска субъект обязан быть: сеанс опознан"
    assert row.entity == "user"


def test_отказ_без_строки_учётной_записи_пишется_один_раз(
    client: TestClient, store: MemoryStore
) -> None:
    """Сеанс живой, а строки учётной записи нет: `no_account` ровно один раз.

    Двойная запись — типичная ошибка этой схемы: `load_account` решает причину, а `enforce_role`
    перехватывает тот же отказ общим `except`. Удвоенное событие не ломает цепочку, но делает
    счётчик отказов недостоверным, а разбору показывает два отказа там, где был один.
    """
    _full_session(client, store)
    dropped = store.drop_user(TEST_LOGIN)
    assert dropped is not None, "учётная запись не создана — проверка теряет смысл"

    response = client.get(CONSOLE_PATH)

    assert response.status_code == 403
    row = _only(store, "auth.access_denied")
    assert row.details == {"reason": DENIAL_NO_ACCOUNT}
    assert row.actor is not None


# ─── цепочка и закрытый реестр в оффлайновой копии ───────────────────────────────────────────


def test_копия_журнала_связана_так_же_как_боевая_цепочка(
    client: TestClient, store: MemoryStore
) -> None:
    """Два отказа подряд дают две связанные строки: `hash_prev` второй равен `hash` первой.

    Проверяется та же форма связи, что и на площадке: память не показывает блокировку хвоста и
    отказ стража, но обязана показывать связь. Набор строк с несвязанными хэшами при разборе
    неотличим от вырезанного куска журнала (`ADR-025` п. 7).
    """
    _full_session(client, store)
    first = client.post("/logout", data={"любое": "поле"}, follow_redirects=False)
    second = client.get(ADMIN_PATH)

    assert (first.status_code, second.status_code) == (403, 403)
    rows = _rows(store)
    assert [row.action for row in rows] == [
        "session.login",
        "auth.csrf_rejected",
        "auth.access_denied",
    ], (
        "цепочка начинается со входа (`session.login`, срез `R2b`), дальше — по одной строке на "
        "отказ; удвоенное событие или событие чужого действия меняют перечень"
    )
    assert rows[0].hash_prev is None, "первая запись цепочки обязана быть без предка"
    for earlier, later in pairwise(rows):
        assert later.hash_prev == earlier.hash, (
            f"строка {later.action} не связана с предыдущей: набор незацепленных хэшей при разборе "
            "неотличим от вырезанного куска журнала"
        )


def test_несостоявшаяся_запись_отвечает_503_а_не_успехом(
    client: TestClient, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Если журнал не записан, ответ обязан сказать об этом, а не «всё в порядке».

    `ADR-025` п. 6: откат вместе с бизнес-изменением — половина требования; вторая половина —
    не выдать незафиксированное состояние за успешное. Разбор недостающую строку покажет как
    `broken_link`, то есть как подделку содержимого, поэтому наблюдателю нужен и ответ, и след в
    логе процесса.

    Здесь проверяется только отображение отказа в ответ (код, тело, заголовки политики): настоящая
    причина отказа — конфликт цепочки или недоступная база — относится к живой половинке
    `tests/integration/test_audit_append_db.py`. Двойник репозитория взрывается намеренно: у
    памяти нет ни замка хвоста, ни `23505`, а обработчик исключения проверяется тот же, что и в
    бою.
    """

    def _boom(**_kwargs: object) -> None:
        raise AuditAppendError("журнал недоступен (состояние моделирует проверка)")

    _full_session(client, store)
    monkeypatch.setattr(store, "append_audit", _boom)

    response = client.get(ADMIN_PATH)

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "detail": "журнал аудита недоступен, изменение не выполнено",
    }, "ответ не говорит ни о причине, ни о том, что изменение не выполнено"
    assert response.headers["content-security-policy"], (
        "отказ 503 ушёл без заголовков политики: middleware обязан накрывать и ответы "
        "обработчиков исключений (§8.3)"
    )


def test_имя_вне_реестра_отклоняется_и_в_оффлайновой_копии(store: MemoryStore) -> None:
    """Закрытый реестр держит и память: выдуманное имя не записывается нигде.

    Если бы `AUDIT_ACTIONS` проверялся только в боевом слое, оффлайновая половинка приняла бы
    любое имя, и сверка «события §8.7 ↔ реестр» перестала бы быть проверкой (`ADR-025` п. 10).
    """
    with pytest.raises(AuditRecordError, match="реестр"):
        store.append_audit(
            action="session.something_new",
            at=utc_now(),
            entity="session",
            entity_id="t109r2-offline",
        )
    assert _rows(store) == []
