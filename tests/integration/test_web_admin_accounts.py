"""Действия администратора по учётным записям и выпускам по HTTP (§9.3 п. 6, `ADR-020` п. 6).

Срез `T-105 R7b`. Половина `R7a` доказала правила перехода и guarded-операции слоя доступа
вызовом из кода; здесь те же правила проверяются маршрутами: страница подтверждения, сама
мутация, отзыв живых сеансов, защита последнего живого администратора, отзыв выпуска и то, каким
ответом слой отвечает на отсутствующий объект.

Границы проверки, и почему они именно такие:

* Сеансы выпускаются `create_session` и кладутся в репозиторий напрямую, а не церемонией входа со
  вторым фактором. Предмет файла — поведение раздела над *полным* сеансом (`auth_step='full'`);
  сама церемония входа держит `test_web_totp_page.py`, а путь приглашённого человека через
  приглашение, привязку и очередь — `test_invitation_flow.py`. Повторять их здесь означало бы
  иметь две проверки одного и того же, расходящиеся при первой правке.
* Хранилище офлайновое (`MemoryStore`). Оно не доказывает `SELECT … FOR UPDATE`, частичный
  уникальный индекс и `CHECK` — живая половина держится файлом `test_invitations_db.py`
  (job «миграции»). Здесь проверяется порядок вызовов и форма ответа.
* Отметки `approved_by`/`approved_at` в фикстуре задаются вручную там, где состояние ставится
  вручную же: тест не делает вид, что прошёл одобрение маршрутом, там, где это не проверяется.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.forms import FIELD_LOGIN, FIELD_PHRASE
from apps.web.routes.admin_users import (
    ACTION_NOTES,
    ADMIN_ACCOUNT_APPROVE_PATH,
    ADMIN_ACCOUNT_ARCHIVE_PATH,
    ADMIN_ACCOUNT_SUSPEND_PATH,
    ADMIN_ACCOUNT_UNSUSPEND_PATH,
    ADMIN_INVITATION_REVOKE_PATH,
    ADMIN_INVITATIONS_PATH,
    ADMIN_USERS_PATH,
    ARCHIVE_WARNING,
    EMPTY_INVITATIONS_NOTE,
    EMPTY_QUEUE_NOTE,
    FIELD_EMAIL,
    FIELD_ROLE,
    NOTE_QUERY,
    REVOKE_WARNING,
    STATE_LABELS,
    SUSPEND_WARNING,
)
from apps.web.routes.invitations import (
    LINK_CLOSED_STATUS,
    UNUSABLE_EXPLANATIONS,
)
from apps.web.routes.login import GENERIC_FAILURE_DETAIL
from apps.web.security.authorization import (
    ACCOUNT_STATE_EXPLANATIONS,
    OBJECT_GONE_BODY,
)
from apps.web.security.csrf import CSRF_FORM_FIELD
from apps.web.security.sessions import (
    INVITE_LINK_KEY,
    INVITE_PATH,
    LOGIN_PATH,
    REASON_QUERY,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    SESSIONS_PATH,
    display_reason_codes,
)
from packages.common.config import Settings
from packages.identity.invitations import new_invitation
from packages.identity.sessions import IssuedSession, create_session
from packages.storage.models import Invitation, User
from tests.integration.web_support import (
    TEST_PASSWORD,
    MemoryStore,
    build_client,
)

#: Отсчёт сеансов. Замораживать часы маршрутам не нужно: отзыв проверяется по `revoked_at`,
#: а не по сроку, а все сеансы фикстуры заканчиваются через два часа после запуска.
FROZEN: Final = datetime.now(UTC).replace(microsecond=0)
SESSION_TTL: Final = timedelta(hours=2)

ADMIN_LOGIN: Final = "adm.accounts"
SECOND_ADMIN_LOGIN: Final = "adm.second"
TARGET_LOGIN: Final = "op.target"
OUTSIDER_LOGIN: Final = "obs.outsider"
QUEUE_LOGIN: Final = "op.queue"
INVITED_LOGIN: Final = "op.invited"

#: Адреса по RFC 5737: счётчики частоты привязаны к адресу (§8.3), и тесты не должны съедать
#: бюджет друг у друга.
ADMIN_ADDRESS: Final = "203.0.113.31"
STRANGER_ADDRESS: Final = "203.0.113.32"
TARGET_ADDRESS: Final = "203.0.113.33"
ISSUE_ADDRESS: Final = "203.0.113.34"

OPERATOR_ROLE: Final = "operator"
#: Значение `id` в адресе: «кривое» и несуществующее обязаны отвечать одинаково.
MALFORMED_ID: Final = "not-a-uuid"

CSRF_META: Final = re.compile(r'name="csrf-token" content="([^"]+)"')
STATUS_LINE: Final = re.compile(r'<p role="status">([^<]*)</p>')
REVOKE_LINK: Final = re.compile(re.escape(ADMIN_INVITATIONS_PATH) + r"/([0-9a-fA-F-]{36})/revoke")
INVITED_LINK: Final = re.compile(
    re.escape(f"{INVITE_PATH}?{INVITE_LINK_KEY}=") + r"([A-Za-z0-9_-]{43})"
)
NOTE_IN_LOCATION: Final = re.compile(rf"\b{NOTE_QUERY}=([a-z_]+)")


def _учётка(
    store: MemoryStore,
    login: str,
    *,
    role: str,
    state: str = "active",
    approved_by: UUID | None = None,
) -> User:
    """Завести учётную запись нужного состояния и сразу проставить ей `id`.

    В живом репозитории `id` выдаёт база при вставке; в памяти `INSERT` нет, и движковый `DEFAULT`
    не срабатывает. Значение проставляется здесь же, до выпуска сеанса и до построения адреса
    действия: `/admin/users/None/suspend` проверяет не маршрут, а опечатку теста (тот же урок,
    что и `uuid4()` в фикстуре `test_invitation_flow.py`). С `None` сравнивались бы `approved_by`
    и предикаты репозитория, и проверка авторства проходила бы молча.

    Отметки одобрения проставляются только у записей, которые обязаны быть одобренными: у
    ожидающего они пустые по контракту, и тест сверяет, что ни блокировка, ни разблокировка их не
    портят и не создают там, где их быть не должно.
    """
    user = store.seed_user(login=login, password=TEST_PASSWORD, role=role)
    user.id = uuid4()
    user.state = state
    user.approved_by = approved_by
    user.approved_at = FROZEN if approved_by is not None else None
    store.commit()
    return user


def _сеанс(
    store: MemoryStore, user_id: UUID, *, device: str, client: TestClient | None = None
) -> IssuedSession:
    """Выпустить полный сеанс; при указанном клиенте — надеть на него куку.

    `auth_step='full'` сознательно: раздел администратора и мутации доступны только полному
    сеансу, и выпуск мимо HTTP нужен ровно для того, чтобы проверить мутацию над живым сеансом
    (модульный докстринг объясняет, почему церемония входа здесь не повторяется).

    Кука надевается только на того клиента, которому сеанс принадлежит: администратор и цель
    действия живут в разных клиентах, иначе «отозван ли чужой сеанс» проверялся бы на собственном.

    Возвращается `IssuedSession`, а не запись: значение куки существует только здесь и только один
    раз (в базе — хэш), а проверять «перестала ли отозванная кука пускать в консоль» нужно именно
    значением (`test_web_totp_page.py` и `test_web_sessions_page.py` работают так же).
    """
    issued = create_session(user_id, user_agent=device, auth_step="full", now=FROZEN)
    issued.record.expires_at = FROZEN + SESSION_TTL
    store.seed_session(issued)
    if client is not None:
        client.cookies.set(SESSION_COOKIE_NAME, issued.secret)
    return issued


def _заголовки(address: str) -> dict[str, str]:
    return {"X-Forwarded-For": address}


def _сосед(admin_client: TestClient) -> TestClient:
    """Клиент того же приложения без куки (человек, у которого сейчас нет доступа)."""
    return TestClient(admin_client.app, base_url="https://testserver")


def _токен(client: TestClient, *, address: str = ADMIN_ADDRESS) -> str:
    """Значение токена формы из метаданных страницы раздела (`ADR-008`)."""
    ответ = client.get(ADMIN_USERS_PATH, headers=_заголовки(address))
    assert ответ.status_code == 200, ответ.text[:300]
    добыча = CSRF_META.search(ответ.text)
    assert добыча is not None, "страница раздела не отдала токен формы"
    return добыча.group(1)


def _мутация(
    client: TestClient,
    url: str,
    token: str,
    *,
    address: str = ADMIN_ADDRESS,
    data: dict[str, str] | None = None,
) -> Response:
    """POST мутации раздела: токен формы плюс заголовок адреса (§8.3)."""
    payload = {CSRF_FORM_FIELD: token}
    payload.update(data or {})
    ответ: Response = client.post(
        url, data=payload, headers=_заголовки(address), follow_redirects=False
    )
    return ответ


def _заметка(ответ: Response) -> str | None:
    """Код исхода из адреса перенаправления; `None` — кода нет."""
    добыча = NOTE_IN_LOCATION.search(ответ.headers.get("location", ""))
    return добыча.group(1) if добыча else None


def _выпустить(client: TestClient, *, email: str, role: str = OPERATOR_ROLE) -> Response:
    """Выпустить приглашение формой раздела и вернуть ответ страницы выпуска."""
    токен = _токен(client, address=ISSUE_ADDRESS)
    return _мутация(
        client,
        ADMIN_INVITATIONS_PATH,
        токен,
        address=ISSUE_ADDRESS,
        data={FIELD_EMAIL: email, FIELD_ROLE: role},
    )


@pytest.fixture
def store() -> MemoryStore:
    """Репозиторий в памяти (`ADR-010` п. 2: офлайновое зеркало структуры для офлайн-тестов).

    Живого контура БД здесь нет сознательно: `CHECK`-выражения, частичные уникальные индексы и
    гонку guarded-`UPDATE` офлайновое зеркало не доказывает — их держит
    `test_invitations_db.py` (job «миграции»). Предмет этого файла — маршруты, порядок их вызовов
    и форма ответа, и всё это проверяется без PostgreSQL.
    """
    return MemoryStore()


def _окошки_одобрения(страница: Response, user_id: UUID) -> int:
    """Сколько раз форма одобрения этой записи попала в страницу раздела.

    Раздел рисует форму одобрения дважды: в очереди одобрения и в полном списке учётных записей.
    Поэтому `2` — запись ждёт решения, `1` — ждать перестала, но из списка не исчезла (§4.1: строка
    остаётся навсегда).

    Считать нужно форму, а не вхождение логина: логин любой учётной записи виден в списке всегда,
    и проверка «исчез из очереди» по логину была бы ложной, а по разметке разделов — хрупкой
    (заголовки таблиц нигде не закреплены константами).
    """
    return страница.text.count(f'action="{ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=user_id)}"')


@pytest.fixture
def accounts(store: MemoryStore) -> dict[str, User]:
    """Администратор, второй администратор в очереди, цель действия и сторонний оператор.

    Второй администратор заведён в `awaiting_approval`: счётчик живых администраторов считает
    только `active`, поэтому такая строка правом «есть кому включить систему» не является — и
    отказ единственного живого администратора обязан сработать именно при таком раскладе.
    """
    admin = _учётка(store, ADMIN_LOGIN, role="admin")
    second = _учётка(store, SECOND_ADMIN_LOGIN, role="admin", state="awaiting_approval")
    target = _учётка(store, TARGET_LOGIN, role=OPERATOR_ROLE, approved_by=admin.id)
    outsider = _учётка(store, OUTSIDER_LOGIN, role=OPERATOR_ROLE, approved_by=admin.id)
    return {"admin": admin, "second": second, "target": target, "outsider": outsider}


@pytest.fixture
def admin_client(
    store: MemoryStore, settings: Settings, accounts: dict[str, User]
) -> Iterator[TestClient]:
    """Клиент администратора с полным сеансом; кука надета, токен берётся со страницы раздела."""
    with build_client(store, settings) as client:
        _сеанс(store, accounts["admin"].id, device="but-admin", client=client)
        yield client


def test_подтверждение_называет_объект_а_POST_без_токена_ничего_не_меняет(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Опасное действие сначала показывает страницу, а POST без токена формы не делает ничего.

    Страница подтверждения обязана назвать объект (§9.1): «заблокировать» и «разблокировать»
    различаются одной ссылкой, и человек обязан видеть, над кем действие, — логин, роль и
    текущее состояние, плюс предупреждение. Проверка сверяется с `STATE_LABELS`: подпись состояния
    берётся из того же набора, что и список раздела.

    POST без токена отклоняется до всякого перехода: отказ безликий (`ADR-008`: `403` без причины и
    без указания объекта) и ничего не меняет — состояние цели остаётся `active`, её живой сеанс
    остаётся живым. Так проверка отличает «маршрут есть, но он под охраной» от «действие всё-таки
    исполнилось», и по телу отказа нельзя узнать, над какой записью колдуют.
    """
    цель = accounts["target"]
    сеанс = _сеанс(store, цель.id, device="but-target")
    url = ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=цель.id)

    страница = admin_client.get(url, headers=_заголовки(ADMIN_ADDRESS))
    assert страница.status_code == 200, страница.text[:400]
    assert SUSPEND_WARNING in страница.text, страница.text[:400]
    assert цель.login in страница.text, "страница подтверждения не называет объект"
    assert f"роль {цель.role}, {STATE_LABELS[цель.state]}" in страница.text, страница.text[:400]
    assert f'action="{url}"' in страница.text, "форма отправляет не на то действие"
    assert цель.state == "active", "GET подтверждения изменил состояние"
    assert сеанс.record.revoked_at is None, "GET подтверждения отозвал сеанс"

    отказ = admin_client.post(
        url,
        data={CSRF_FORM_FIELD: ""},
        headers=_заголовки(ADMIN_ADDRESS),
        follow_redirects=False,
    )
    assert отказ.status_code == 403, отказ.text[:300]
    assert отказ.json()["status"] == "forbidden", отказ.text[:300]
    assert (
        цель.login not in отказ.text
    ), "отказ формы назвал объект, над которым пытались действовать"
    assert str(цель.id) not in отказ.text, "отказ формы назвал id объекта"
    assert цель.state == "active", "POST без токена изменил состояние"
    assert сеанс.record.revoked_at is None, "POST без токена отозвал чужой сеанс"


def test_блокировка_отзывает_живые_сеансы_и_объясняет_состояние(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Блокировка закрывает сеансы немедленно, а состояние объясняется человеку словами.

    Порядок `ADR-020` п. 6: отзыв живых сеансов — сразу после перехода, одним `commit()`-ом с ним.
    Поэтому после успешной мутации сеанс цели отозван, и её же кука больше не пускает в консоль:
    запрос уходит на страницу истёкшего сеанса, а код причины взят из закрытого набора и говорит
    «отозвано», а не «истекло» (`ADR-010`, §9) — по различию этих ответов человек понимает, звать
    ли администратора или просто войти заново.

    Дальше — второй контур (`ensure_console_access`): сеанс, до которого отзыв не дошёл (другой
    экземпляр `web`, отставший репозиторий). Консоль обязана объяснить состояние словами, а не
    ответить безликим `403`: без объяснения человек не узнает, что делать, и проверка второго
    контура превратится в проверку молчания.

    Третья половина — вход: попытка войти под заблокированной записью с верным паролем отвечает
    ровно тем же, что вход под активной записью с неверным паролем. Закрытое состояние не должно
    быть различимо снаружи (§8.8), иначе маршрут входа подтверждает существование учётной записи
    и её статус.

    Для сравнения используется другая учётная запись: два неудачных входа подряд под одной
    записью приближают блокировку по числу неудач (`MAX_FAILED_ATTEMPTS`), и проверка начала бы
    ловить её вместо отказа по состоянию.
    """
    цель = accounts["target"]
    сеанс = _сеанс(store, цель.id, device="but-target")
    url = ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=цель.id)

    ответ = _мутация(admin_client, url, _токен(admin_client))
    assert ответ.status_code == 302, ответ.text[:300]
    assert _заметка(ответ) == "suspended"
    assert цель.state == "suspended"
    assert сеанс.record.revoked_at is not None, "живой сеанс не отозван немедленно (§1.2)"

    консоль = _сосед(admin_client)
    консоль.cookies.set(SESSION_COOKIE_NAME, сеанс.secret)
    мёртвая = консоль.get(SESSIONS_PATH, headers=_заголовки(TARGET_ADDRESS), follow_redirects=False)
    assert мёртвая.status_code == 302, мёртвая.text[:300]
    адрес = мёртвая.headers["location"]
    assert адрес.startswith(
        f"{SESSION_EXPIRED_PATH}?{REASON_QUERY}="
    ), "отозванная кука не отправлена на страницу объяснения причины"
    код = адрес.split("=", 1)[1]
    assert код in display_reason_codes(), "причина отказа не из закрытого набора кодов"
    assert код == "revoked", "человек видит «истёк», хотя его сеанс отозвали"

    # Второй контур (`ADR-020` п. 6): сеанс, до которого отзыв не дошёл, — консоль обязана отказать
    # объяснением, а не безликим `403`. Такой сеанс появляется ровно тогда, когда закрывающее
    # действие его не увидело (другой экземпляр `web`, отставший репозиторий), и молчаливый отказ
    # оставил бы человека без понимания, что произошло.
    уцелевший = _сеанс(store, цель.id, device="but-target-old", client=консоль)
    объяснение = консоль.get(
        SESSIONS_PATH, headers=_заголовки(TARGET_ADDRESS), follow_redirects=False
    )
    assert объяснение.status_code == 200, объяснение.text[:300]
    assert ACCOUNT_STATE_EXPLANATIONS["suspended"] in объяснение.text, объяснение.text[:400]
    assert (
        уцелевший.record.revoked_at is None
    ), "второй контур сам отозвал сеанс — порядок перепутан"

    заблокированная = _сосед(admin_client).post(
        LOGIN_PATH,
        data={FIELD_LOGIN: цель.login, FIELD_PHRASE: TEST_PASSWORD},
        headers=_заголовки(TARGET_ADDRESS),
        follow_redirects=False,
    )
    чужой_пароль = _сосед(admin_client).post(
        LOGIN_PATH,
        data={FIELD_LOGIN: accounts["outsider"].login, FIELD_PHRASE: f"{TEST_PASSWORD}-нет"},
        headers=_заголовки(STRANGER_ADDRESS),
        follow_redirects=False,
    )
    assert заблокированная.status_code == 401
    assert GENERIC_FAILURE_DETAIL in заблокированная.text
    assert (
        заблокированная.text == чужой_пароль.text
    ), "закрытое состояние различимо снаружи: ответ отличается от неверного пароля"


def test_разблокировка_сохраняет_отметки_одобрения_и_не_оживляет_сеансы(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Разблокировка возвращает доступ, но не стирает автора решения и не возвращает сеанс.

    `approved_by`/`approved_at` отвечают на вопрос «кто открыл доступ», а не «когда его включили
    снова» (`unsuspend_account`): стереть их — значит потерять автора решения, который §10 требует
    видеть в журнале. Отметки задаются в фикстуре и сверяются после пары действий.

    Вторая половина: прежний сеанс остаётся отозванным. Разблокировка ничего не выпускает, и
    человеку приходится войти заново — это единственное, чем она отличается от «ничего не было».
    Проверка держит и порядок перехода: разблокировать можно только заблокированного, иначе
    «разблокировка» активного человека стала бы вторым одобрением без второго шага.
    """
    цель = accounts["target"]
    кто_одобрил, когда_одобрили = цель.approved_by, цель.approved_at
    assert кто_одобрил is not None
    assert когда_одобрили is not None
    сеанс = _сеанс(store, цель.id, device="but-target")
    токен = _токен(admin_client)

    assert _заметка(
        _мутация(admin_client, ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=цель.id), токен)
    ) == ("suspended")
    ответ = _мутация(admin_client, ADMIN_ACCOUNT_UNSUSPEND_PATH.format(user_id=цель.id), токен)
    assert ответ.status_code == 302, ответ.text[:300]
    assert _заметка(ответ) == "unsuspended"
    assert цель.state == "active"
    assert цель.approved_by == кто_одобрил, "разблокировка стёрла автора одобрения"
    assert цель.approved_at == когда_одобрили
    assert сеанс.record.revoked_at is not None, "разблокировка оживила отозванный сеанс"

    повторно = _мутация(admin_client, ADMIN_ACCOUNT_UNSUSPEND_PATH.format(user_id=цель.id), токен)
    assert _заметка(повторно) == "refused_transition", "разблокировка живого человека прошла"
    assert цель.state == "active"

    вход = _сосед(admin_client).post(
        LOGIN_PATH,
        data={FIELD_LOGIN: цель.login, FIELD_PHRASE: TEST_PASSWORD},
        headers=_заголовки(TARGET_ADDRESS),
        follow_redirects=False,
    )
    assert вход.status_code == 302, вход.text[:300]
    assert сеанс.record.revoked_at is not None, "новый вход отменил отзыв прежнего сеанса"


def test_архивирование_терминально_и_требует_подтверждения(
    admin_client: TestClient, accounts: dict[str, User]
) -> None:
    """Архивирование закрывает доступ навсегда: ни разблокировать, ни одобрить нельзя (§4.1).

    Терминальность — часть контракта: «разархивировать» означало бы второе одобрение без второго
    шага, то есть переход, которого в контракте нет. Поэтому проверяются две попытки отменить
    действие: обе обязаны объяснить отказ (`refused_transition`) и оставить `archived`.

    Страница подтверждения обязательна: это самое необратимое действие раздела, и предупреждение
    на ней — единственный способ не сделать его одним переходом по ссылке (разметка раздела
    намеренно показывает все кнопки, а не только допустимые).
    """
    цель = accounts["outsider"]
    url = ADMIN_ACCOUNT_ARCHIVE_PATH.format(user_id=цель.id)

    страница = admin_client.get(url, headers=_заголовки(ADMIN_ADDRESS))
    assert страница.status_code == 200, страница.text[:400]
    assert ARCHIVE_WARNING in страница.text, страница.text[:400]
    assert цель.state == "active", "GET подтверждения изменил состояние"

    ответ = _мутация(admin_client, url, _токен(admin_client))
    assert ответ.status_code == 302, ответ.text[:300]
    assert _заметка(ответ) == "archived"
    assert цель.state == "archived"

    токен = _токен(admin_client)
    for путь in (ADMIN_ACCOUNT_UNSUSPEND_PATH, ADMIN_ACCOUNT_APPROVE_PATH):
        отказ = _мутация(admin_client, путь.format(user_id=цель.id), токен)
        assert отказ.status_code == 302, отказ.text[:300]
        assert (
            _заметка(отказ) == "refused_transition"
        ), f"{путь}: архивную запись оказалось возможно открыть"
        assert цель.state == "archived"


def test_последний_живой_администратор_защищён_а_второй_защищает(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Единственный живой администратор себе доступ не закрывает, а при двух — закрывает.

    Отказ нужен, когда живой `admin` один: вторая строка с ролью `admin` в очереди
    (`awaiting_approval`) правом не является — счётчик считает только `active`, а заблокированный
    или ожидающий пригласить никого не может (`ensure_not_last_admin`).

    Вторая половина не менее важна: при двух живых администраторах действие обязано пройти. Счёт,
    снятый после перехода и без `except_user_id`, дал бы тот же ноль и отказал зря — то есть
    проверка ловит не только потерю защиты, но и неработающий раздел. Порядок «счёт до перехода»
    держится здесь же: после успеха живой администратор остаётся ровно один, и его сеанс жив.
    """
    админ, второй = accounts["admin"], accounts["second"]
    сеанс_второго = _сеанс(store, второй.id, device="but-second")
    url = ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=админ.id)
    токен = _токен(admin_client)

    отказ = _мутация(admin_client, url, токен)
    assert отказ.status_code == 302, отказ.text[:300]
    assert _заметка(отказ) == "refused_last_admin", отказ.headers.get("location")
    assert админ.state == "active", "единственный живой администратор оказался заблокирован"

    одобрение = _мутация(admin_client, ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=второй.id), токен)
    assert _заметка(одобрение) == "approved"
    assert второй.state == "active"
    assert второй.approved_by == админ.id, "одобрение не записало автора (§1.2)"
    assert второй.approved_at is not None

    действие = _мутация(admin_client, url, токен)
    assert _заметка(действие) == "suspended", "второй живой администратор не позволил заблокировать"
    assert админ.state == "suspended"
    assert второй.state == "active", "система осталась без живого администратора"
    assert сеанс_второго.record.revoked_at is None, "блокировка одной записи отозвала чужие сеансы"


def test_одобрение_работает_только_из_очереди_и_очередь_пустеет(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Одобрить можно только ожидающего; после одобрения человек уходит из очереди.

    Прямого перехода `invited → active` нет (§1.2): между ними обязана быть привязка второго
    фактора. Одобрение, которое этот шаг пропускает, открывает доступ человеку без 2FA — поэтому
    маршрут обязан отказать и не тронуть ни состояние, ни отметки одобрения («почти одобренная»
    запись выглядела бы готовой к входу).

    Тот же код отказа получает попытка одобрить уже активную запись: молчаливого «ничего не
    случилось» в разделе быть не должно, администратор видел список и нажал кнопку.

    Последняя половина — очередь: пока ожидающий не одобрен, строка «очереди нет» не показывается,
    а после последнего одобрения очередь обязана опустеть. Способ счёта — форма одобрения записи
    (см. `_окошки_одобрения`): раздел рисует её дважды для ожидающего и один раз для остальных, и
    именно это отличает очередь от полного списка записей.
    """
    новичок = _учётка(store, INVITED_LOGIN, role=OPERATOR_ROLE, state="invited")
    ожидающий = _учётка(store, QUEUE_LOGIN, role=OPERATOR_ROLE, state="awaiting_approval")
    токен = _токен(admin_client)

    отказ = _мутация(admin_client, ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=новичок.id), токен)
    assert отказ.status_code == 302, отказ.text[:300]
    assert _заметка(отказ) == "refused_transition"
    assert новичок.state == "invited", "одобрение обошло очередь привязки"
    assert новичок.approved_by is None
    assert новичок.approved_at is None

    живой = _мутация(
        admin_client, ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=accounts["outsider"].id), токен
    )
    assert _заметка(живой) == "refused_transition", "одобрение активной записи прошло"
    assert accounts["outsider"].state == "active"

    до = admin_client.get(ADMIN_USERS_PATH, headers=_заголовки(ADMIN_ADDRESS))
    assert EMPTY_QUEUE_NOTE not in до.text, "очередь оказалась пустой до одобрения"
    assert _окошки_одобрения(до, ожидающий.id) == 2, "ожидающий не показан в очереди"
    assert (
        _окошки_одобрения(до, accounts["second"].id) == 2
    ), "второй администратор пропал из очереди"

    одобрение = _мутация(
        admin_client, ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=ожидающий.id), токен
    )
    assert _заметка(одобрение) == "approved"
    assert ожидающий.state == "active"
    assert ожидающий.approved_by == accounts["admin"].id
    assert ожидающий.approved_at is not None

    после = admin_client.get(ADMIN_USERS_PATH, headers=_заголовки(ADMIN_ADDRESS))
    assert _окошки_одобрения(после, ожидающий.id) == 1, "одобренный остался в очереди одобрения"
    assert EMPTY_QUEUE_NOTE not in после.text, "очередь опустела, хотя ждёт ещё кто-то"

    второй = _мутация(
        admin_client, ADMIN_ACCOUNT_APPROVE_PATH.format(user_id=accounts["second"].id), токен
    )
    assert _заметка(второй) == "approved"
    пустая = admin_client.get(ADMIN_USERS_PATH, headers=_заголовки(ADMIN_ADDRESS))
    assert EMPTY_QUEUE_NOTE in пустая.text, "очередь не опустела после последнего одобрения"


def test_отзыв_выпуска_закрывает_ссылку_а_повтор_объясняется(
    admin_client: TestClient, store: MemoryStore, accounts: dict[str, User]
) -> None:
    """Отозванный выпуск перестаёт быть ссылкой, а исходы отзыва различаются объяснением.

    Отзыв идёт по адресу строки списка, а не по адресу ссылки (значение ссылки в раздел не
    попадает): `id` берётся из самой страницы раздела, иначе тест проверял бы маршрут, которого
    человек не видит.

    После отзыва страница приглашения отвечает закрытой ссылкой с объяснением отзыва, выпуск
    исчезает из списка открытых, а повторный отзыв даёт `invitation_already_revoked`: исход обязан
    различать «отозвали раньше» и «ссылкой уже воспользовались», потому что администратору нужно
    понимать — человек пришёл по ссылке или нет. Использованный выпуск заведён напрямую: предмет
    проверки — исход отзыва, а сам приём ссылки проверяет `test_invitation_flow.py`.
    """
    адресат = "withdrawn.accounts@example.test"
    выпуск = _выпустить(admin_client, email=адресат)
    assert выпуск.status_code == 200, выпуск.text[:400]
    строки = store.pending_invitations()
    assert len(строки) == 1, "выпуск не записан в репозиторий"

    страница = admin_client.get(ADMIN_USERS_PATH, headers=_заголовки(ADMIN_ADDRESS))
    добыча = REVOKE_LINK.search(страница.text)
    assert добыча is not None, "в списке нет адреса отзыва этого выпуска"
    assert UUID(добыча.group(1)) == строки[0].id, "ссылка отзыва ведёт на другой выпуск"
    значение = INVITED_LINK.search(выпуск.text)
    assert значение is not None, "страница выпуска не показала ссылку"

    отзыв_url = ADMIN_INVITATION_REVOKE_PATH.format(invitation_id=строки[0].id)
    подтверждение = admin_client.get(отзыв_url, headers=_заголовки(ADMIN_ADDRESS))
    assert подтверждение.status_code == 200, подтверждение.text[:400]
    assert REVOKE_WARNING in подтверждение.text, подтверждение.text[:400]
    assert адресат in подтверждение.text, "подтверждение отзыва не называет адресата"

    ответ = _мутация(admin_client, отзыв_url, _токен(admin_client))
    assert _заметка(ответ) == "invitation_revoked"
    assert строки[0].state == "revoked"

    раздел = admin_client.get(ADMIN_USERS_PATH, headers=_заголовки(ADMIN_ADDRESS))
    assert EMPTY_INVITATIONS_NOTE in раздел.text, "отозванный выпуск остался в списке открытых"

    приглашение = _сосед(admin_client)
    закрытая = приглашение.get(
        f"{INVITE_PATH}?{INVITE_LINK_KEY}={значение.group(1)}",
        headers=_заголовки(TARGET_ADDRESS),
        follow_redirects=False,
    )
    assert закрытая.status_code == LINK_CLOSED_STATUS, закрытая.text[:300]
    assert UNUSABLE_EXPLANATIONS["revoked"] in закрытая.text, закрытая.text[:400]

    повтор = _мутация(admin_client, отзыв_url, _токен(admin_client))
    assert _заметка(повтор) == "invitation_already_revoked"

    использованный = _использованный_выпуск(store, accounts["admin"].id)
    занятый = _мутация(
        admin_client,
        ADMIN_INVITATION_REVOKE_PATH.format(invitation_id=использованный.id),
        _токен(admin_client),
    )
    assert (
        _заметка(занятый) == "invitation_used"
    ), "использованный выпуск оказалось возможно отозвать"
    assert использованный.state == "used"


def _использованный_выпуск(store: MemoryStore, admin_id: UUID) -> Invitation:
    """Выпуск, по которому учётную запись уже создали.

    Домен + `state='used'`, а не сочинённая строка: переход `pending → used` делает слой доступа,
    и здесь важна только его метка — сам приём ссылки проверяет flow-файл.
    """
    issued = new_invitation(created_by=admin_id, role=OPERATOR_ROLE, login="op.used", now=FROZEN)
    issued.record.state = "used"
    issued.record.used_at = FROZEN
    store.add(issued.record)
    store.commit()
    return issued.record


def test_кривой_несуществующий_и_чужой_id_отвечают_одинаково(admin_client: TestClient) -> None:
    """Отсутствующий объект отвечает одним телом и не различает кривой `id` и пустой.

    Разных ответов на «нет такого», «`id` кривой» и «`id` другой категории» быть не должно: по
    разнице ответов подбирающий идентификаторы наблюдатель узнавал бы, какие объекты существуют, а
    `422` от разбора пути описывал бы ещё и структуру адреса. Поэтому все четыре ответа сверяются
    с одним телом `404` (`OBJECT_GONE_BODY`) — и для учётных записей, и для выпусков: тело на весь
    раздел одно.

    Тот же порядок держит страница подтверждения: `GET` по несуществующему объекту отвечает `404`,
    а не рисует форму действия в никуда, и `POST` отвечает то же самое без перенаправления.
    """
    токен = _токен(admin_client)
    ответы = [
        admin_client.get(
            ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=MALFORMED_ID),
            headers=_заголовки(ADMIN_ADDRESS),
        ),
        admin_client.get(
            ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=uuid4()), headers=_заголовки(ADMIN_ADDRESS)
        ),
        _мутация(admin_client, ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=MALFORMED_ID), токен),
        _мутация(admin_client, ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=uuid4()), токен),
    ]
    for ответ in ответы:
        assert ответ.status_code == 404, ответ.text[:300]
        assert ответ.json() == OBJECT_GONE_BODY, ответ.text[:300]

    выпуски = [
        admin_client.get(
            ADMIN_INVITATION_REVOKE_PATH.format(invitation_id=MALFORMED_ID),
            headers=_заголовки(ADMIN_ADDRESS),
        ),
        _мутация(admin_client, ADMIN_INVITATION_REVOKE_PATH.format(invitation_id=uuid4()), токен),
    ]
    for ответ in выпуски:
        assert ответ.status_code == 404, ответ.text[:300]
        assert ответ.json() == OBJECT_GONE_BODY, ответ.text[:300]

    assert (
        len({ответ.text for ответ in ответы + выпуски}) == 1
    ), "разные отсутствующие объекты отвечают по-разному"


def test_код_исхода_из_адреса_печатается_а_произвольный_текст_нет(admin_client: TestClient) -> None:
    """Объяснение берётся из закрытого набора кодов, а не из адреса запроса (§9.4).

    `?note=` — единственный способ передать исход после перенаправления, и это данные браузера:
    напечатает слой их как есть — человек получит возможность вписать текст от имени
    административной страницы. Поэтому проверяются три расклада: известный код печатает свой
    текст из `ACTION_NOTES`, неизвестный код не печатает строку состояния вовсе, а значение с
    разметкой не попадает в ответ ни в каком виде.

    Отдельная тонкость: код обязан быть ровно кодом, а не подстрокой. Проверка берёт значение,
    которое начинается с уже известного кода (`approved_by_intruder`), — карта поиска по подстроке
    или `startswith` дали бы объяснение там, где его быть не должно.
    """
    известный = admin_client.get(
        f"{ADMIN_USERS_PATH}?{NOTE_QUERY}=approved", headers=_заголовки(ADMIN_ADDRESS)
    )
    assert известный.status_code == 200
    строка = STATUS_LINE.search(известный.text)
    assert строка is not None
    assert строка.group(1) == ACTION_NOTES["approved"]

    неизвестный = admin_client.get(
        f"{ADMIN_USERS_PATH}?{NOTE_QUERY}=approved_by_intruder", headers=_заголовки(ADMIN_ADDRESS)
    )
    assert неизвестный.status_code == 200
    assert "approved_by_intruder" not in неизвестный.text
    assert STATUS_LINE.search(неизвестный.text) is None, "неизвестный код дал строку состояния"

    разметка = admin_client.get(
        f"{ADMIN_USERS_PATH}?{NOTE_QUERY}=%3Cscript%3Eobserve%3C%2Fscript%3E",
        headers=_заголовки(ADMIN_ADDRESS),
    )
    assert разметка.status_code == 200
    assert (
        "observe" not in разметка.text
    ), "значение из адреса попало в ответ — размеченным или текстом"
    assert STATUS_LINE.search(разметка.text) is None


def test_собственная_запись_предупреждает_что_доступ_закроется(
    admin_client: TestClient, accounts: dict[str, User]
) -> None:
    """Подтверждение собственной блокировки говорит, что администратор останется без входа.

    Запрещать себе блокировку при втором живом администраторе никто не вправе — но действие
    закрывает и собственный вход, и это следствие человек обязан увидеть до подтверждения
    (§9.1). Поэтому проверяется не только предупреждение для чужой записи (нет), но и его наличие
    для своей, и то, что страница при этом остаётся страницей подтверждения с формой.

    Формулировка сверяется по признаку «собственная учётная запись», а не дословно: договор
    требует называть следствие, а не конкретную фразу; дословная сверка заставила бы править тест
    ради стилистики текста.
    """
    своя = accounts["admin"]
    чужая = accounts["target"]

    своя_страница = admin_client.get(
        ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=своя.id), headers=_заголовки(ADMIN_ADDRESS)
    )
    assert своя_страница.status_code == 200, своя_страница.text[:400]
    assert "собственная учётная запись" in своя_страница.text, своя_страница.text[:400]
    assert f'action="{ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=своя.id)}"' in своя_страница.text

    чужая_страница = admin_client.get(
        ADMIN_ACCOUNT_SUSPEND_PATH.format(user_id=чужая.id), headers=_заголовки(ADMIN_ADDRESS)
    )
    assert (
        "собственная учётная запись" not in чужая_страница.text
    ), "предупреждение о собственной записи показано для чужой учётной записи"
