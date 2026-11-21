"""Куки сессии и проверка сессии на каждом запросе (TZ §8.3, `T-102`).

Что закреплено этим модулем (домен сроков, шага входа и отзыва — в
`packages/identity/sessions.py`; здесь только HTTP):

* **атрибуты куки из §8.3**: `HttpOnly`, `Secure`, `SameSite=Lax`, путь `/`. Имя куки —
  `tbot_session`: §8.3 имени не задаёт, но имя обязано быть константой, потому что его проверяют
  интеграционные тесты и его видит пользователь в настройках браузера;
* **у куки нет `Max-Age`/`Expires`** — это кука уровня сессии браузера. Срок живёт в базе
  (`expires_at`, `created_at`, `revoked_at`), и делать куку долговременной означало бы хранить в
  браузере значение, которое сервер уже считает мёртвым: «билет», переживающий закрытие браузера, —
  это ровно то, что §8.3 запрещает держать дольше, чем живёт сессия;
* **наружу значение показывается один раз**: только в ответе выпуска; в базе лежит SHA-256 (§8.3),
  и ни один шаблон его не печатает;
* **поиск по `token_hash`, а не по `id`** (§8.3) — см. `store.session_by_token_hash`;
* **отзыв отражается немедленно**: `revoked_at` проверяется на каждом запросе, кэша «сессия была
  жива» нет;
* **idle продляется на каждом аутентифицированном запросе**. Это осознанный обмен: ADR-007
  предупреждает, что каждый лимитируемый запрос стоит запись в базу, — здесь та же цена. Ленивое
  пакетирование возможно, но интервал обязан оставаться заметно меньше `IDLE_TIMEOUT` (30 минут),
  иначе сессия «протухнет» у пользователя, который работает. Сейчас шаг простой, и неверно
  посчитанный интервал не может оставить пользователя без объяснения.

Ещё одно правило этого модуля, важное для безопасности: **у зависимостей нет параметров, которые
FastAPI мог бы взять из запроса** (кроме `Request` и репозитория). Параметр `now: datetime` в
сигнатуре зависимости превратился бы в необязательный query-параметр `?now=…`, то есть пользователь
смог бы сам выбрать момент, относительно которого проверяется срок сессии. Время берётся из
`utc_now()`, а тесты подменяют саму функцию.

Что здесь есть помимо домена сессий: коды причин блокировки входа (`attempts`/`rate`) объявлены
здесь и используются страницей `/locked` (срез `R3c`), а сам счётчик частоты запросов живёт в
`apps/web/security/rate_limit.py` (срез `R3d`, `docs/adr/ADR-007`). Заголовки §8.3 — в
`apps/web/security/headers.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import Depends, Request, Response

from apps.web.security.clients import client_address
from apps.web.store import Store, get_store
from packages.common.clock import utc_now
from packages.identity.sessions import (
    SESSION_REASON_CODES,
    MalformedSessionTokenError,
    SessionInvalidError,
    SessionStepError,
    ensure_full_auth,
    ensure_session_active,
    ensure_token_syntax,
    register_session_activity,
    token_hash_of,
)
from packages.storage.models import UserSession

# ─── контракт куки (§8.3) ─────────────────────────────────────────────────────────────────────

#: Имя куки сессии. §8.3 его не задаёт; константа нужна, потому что её проверяют тесты и её видит
#: пользователь в настройках браузера — «имя как получится» делает проверку недостижимой.
SESSION_COOKIE_NAME: Final = "tbot_session"

#: §8.3: «путь `/`». Уже не путь раздела: куку читает и вход, и консоль, и отзывы сессий.
COOKIE_PATH: Final = "/"

#: §8.3: `SameSite=Lax`. Не `Strict`: в консоль приходят по ссылке из письма и мессенджера, и
#: `Strict` ломает эти переходы, не добавляя защиты против CSRF (переход по ссылке — `GET`, а
#: мутации под `Lax` не приходят).
COOKIE_SAMESITE: Final = "lax"

#: §8.3: `Secure`. Ставится безусловно, а не «если запрос по HTTPS»: наружу работает только Caddy
#: с TLS (TZ §8.5, ADR-003), и условие «запрос пришёл по http» означает обращение к `web` мимо
#: прокси, то есть обход периметра, а не легальный сценарий.
COOKIE_SECURE: Final = True

#: §8.3: `HttpOnly`. Смысл этого флага сохраняет ADR-008: CSRF-токен выводится из значения куки, а
#: не кладётся в HTML рядом с ним.
COOKIE_HTTP_ONLY: Final = True

# ─── пути, на которые смотрит этот модуль ─────────────────────────────────────────────────────

LOGIN_PATH: Final = "/login"
LOGOUT_PATH: Final = "/logout"
SESSION_EXPIRED_PATH: Final = "/session-expired"

#: Страница «вход заблокирован» (`docs/tz/09-web-ui-and-design.md` §9: состояния внятные).
LOCKED_PATH: Final = "/locked"

#: Список сессий пользователя (§8.3 «сессии видны пользователю», карта страниц §9.3 п. 4).
#: Адрес — подпуть `/profile`, а не корневой `/sessions`: карта §9.3 держит список активных сессий
#: **внутри** профиля (п. 4 «список активных сессий (IP, устройство, время) с отзывом»), а
#: подпуть профиля уже принят той же картой для раздела безопасности (п. 5 `/profile/security`).
#: Так страница появляется сейчас, не подменяя собой будущую страницу профиля целиком (имя, e-mail,
#: дата последнего входа — её содержательные поля, и придумывать их здесь значит решить чужую
#: задачу молча).
SESSIONS_PATH: Final = "/profile/sessions"

#: Отзыв одной сессии: `GET` — страница подтверждения, `POST` — сама мутация (§9.1: разрушающее
#: действие подтверждается с указанием объекта).
SESSION_REVOKE_PATH: Final = f"{SESSIONS_PATH}/{{session_id}}/revoke"

#: Отзыв всех живых сессий учётной записи, включая текущую (§8.3 «отзыв по одной/всех»).
#: Конкатенация вместо f-строки: в f-строке `{` пришлось бы удваивать, и адрес стал бы
#: нечитаемым.
SESSIONS_REVOKE_ALL_PATH: Final = SESSIONS_PATH + "/revoke-all"

#: Страница «Профиль и безопасность» со сменой пароля (§9.3 п. 5, срез `R3f`).
#: Адрес держится рядом с прочими адресами консоли, а не внутри маршрутизатора: на него ссылаются
#: два модуля — обработчик смены пароля и ссылка со списка сеансов. Один адрес на два модуля —
#: единственная причина, по которой константа не живёт в `routes/profile.py`.
SECURITY_PATH: Final = "/profile/security"

#: Куда попадает пользователь, успешно прошедший парольный шаг. Страницы ввода кода ещё нет
#: (её вводит `T-103`, `apps/web/routes/totp.py`), поэтому редирект идёт на корневую страницу
#: каркаса M0. Константа названа, а не вписана в обработчик: у `T-103` будет ровно одна правка —
#: направление этой стрелки, и контрактный тест требует, чтобы пометка про `T-103` осталась.
POST_LOGIN_REDIRECT: Final = "/"

#: Параметр, по которому страница состояния объясняет причину. Значение проверяется по закрытому
#: набору (`display_reason_codes`), поэтому подставить в него произвольный текст из запроса нельзя.
REASON_QUERY: Final = "reason"

#: Коды причины блокировки входа для страницы `/locked` (`LOCK_EXPLANATIONS` в
#: `apps/web/routes/sessions.py`). Различие принципиально: `attempts` — закрыта учётная запись
#: после неудачных паролей (`T-101`, `LOCK_DURATION`), `rate` — закрыт адрес: предел частоты §8.3
#: либо бан окна перебора §8.2 (`IP_BAN_DURATION`, срез `R3d`). Сроки этих правил совпадают
#: (15 минут), но решения разные, поэтому разные и коды, и константы (ask `ba6a9076`).
LOCK_REASON_ATTEMPTS: Final = "attempts"
LOCK_REASON_RATE: Final = "rate"

#: Отдельный отображаемый случай: значение куки пришло, а записи сессии в базе нет. Его нет в
#: доменных кодах, потому что домен смотрит уже найденную запись и о «пропавшей» строке не знает
#: (обычно её удалила ретенция, либо значение принесено извне).
UNKNOWN_SESSION_REASON: Final = "unknown"


def display_reason_codes() -> frozenset[str]:
    """Закрытый набор причин, которые страница состояния готова объяснить.

    Доменные коды (`revoked`, `idle`, `absolute`, `not_yet`) замкнуты и проверяются контрактом
    `test_sessions_contract.py` — здесь к ним добавлен ровно один случай уровня HTTP.
    """
    return SESSION_REASON_CODES | {UNKNOWN_SESSION_REASON}


#: Зависимость репозитория в форме `Annotated`, а не `= Depends(...)` в значении по умолчанию:
#: второй вариант ругает B008 из набора `B`, который проект держит в `ruff` как часть контракта
#: качества, а добавлять подавления (бюджет 14, job `suppress-growth`) под идиому FastAPI нельзя.
StoreDep = Annotated[Store, Depends(get_store)]


# ─── идентичность запроса ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Principal:
    """Кто выполняет запрос: найденная запись сессии и предъявленное значение куки.

    `secret` нужен ровно одному месту — выводу CSRF-токена по ADR-008. В шаблоны, логи и журнал он
    не попадает, а `repr` маскируется по той же причине, что и `IssuedSession.secret`: печать
    структуры данных — самый частый способ унести материал доступа.
    """

    session: UserSession
    secret: str

    def __repr__(self) -> str:
        return (
            f"Principal(session_id={self.session.id}, step={self.session.auth_step!r}, "
            "secret='<скрыто>')"
        )


class SessionRedirect(Exception):
    """Сессия не подходит: ответ — редирект на страницу состояния, а не текст ошибки.

    `reason` — отображаемая причина (`display_reason_codes()`) либо `None` для случаев, когда
    объяснять нечего: куки нет вовсе или её значение нельзя разобрать. Различие принципиально для
    мутаций: если сессии нет, запрос отклоняется молча (`403`, ADR-008), а если сессия была и
    перестала быть живой — пользователь обязан увидеть объяснение (§9, `/session-expired`).

    `clear_cookie` — «сотри куку»: её ставят сломанные значения (обрезал прокси, подставили
    постороннее). Оставлять такое в браузере нельзя: объяснение показывалось бы бесконечно, пока
    пользователь не сотрёт куку руками.
    """

    def __init__(
        self,
        location: str,
        *,
        reason: str | None = None,
        clear_cookie: bool = False,
    ) -> None:
        super().__init__(f"редирект на {location!r} (причина: {reason or 'не объясняется'})")
        self.location = location
        self.reason = reason
        self.clear_cookie = clear_cookie


# ─── контракт куки: выпуск, чтение, стирание ──────────────────────────────────────────────────


def issue_session_cookie(response: Response, secret: str) -> None:
    """Выдать куку сессии с атрибутами §8.3.

    `max_age`/`expires` не передаются намеренно (см. модульный докстринг): срок держит база.
    Форма значения проверяется до выдачи: отдать браузер обрезанное или постороннее значение —
    значит выпустить куку, которую следующая проверка честно назовёт испорченной, и причина будет
    потеряна.
    """
    ensure_token_syntax(secret)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=secret,
        path=COOKIE_PATH,
        secure=COOKIE_SECURE,
        httponly=COOKIE_HTTP_ONLY,
        samesite=COOKIE_SAMESITE,
    )


def clear_session_cookie(response: Response) -> None:
    """Стереть куку сессии.

    Атрибуты обязаны совпадать с выдачей: браузер удаляет куку по совпадению имени, пути и области
    видимости. Пытаться убрать куку, выпущенную на пути `/`, удалением на пути `/login` — значит
    оставить её живой, а «отзыв отражается немедленно» (§8.3) при этом перестаёт быть правдой для
    браузера.
    """
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path=COOKIE_PATH,
        secure=COOKIE_SECURE,
        httponly=COOKIE_HTTP_ONLY,
        samesite=COOKIE_SAMESITE,
    )


def read_session_cookie(request: Request) -> str | None:
    """Предъявленное значение куки либо `None`, если куки нет (или она пустая)."""
    value = request.cookies.get(SESSION_COOKIE_NAME)
    if value is None or value == "":
        return None
    return value


# ─── проверка сессии на запросе ───────────────────────────────────────────────────────────────


def authenticate(request: Request, store: StoreDep) -> Principal:
    """Найти сессию по предъявленной куке; иначе — редирект с объяснением либо молча.

    Порядок проверок и его последствия:

    1. куки нет → `SessionRedirect(/login, reason=None)`: пользователь не входил, объяснять нечего;
    2. значение не разбирается как выпущенное (§8.3: 43 символа base64url) →
       `SessionRedirect(/login, reason=None, clear_cookie=True)`: причина не «сессии нет», а
       «значение испорчено», и идти в базу с мусорным значением незачем;
    3. записи с такой хэш-суммой нет → `SessionRedirect(/session-expired, reason='unknown')`;
    4. запись есть, но не живая (отзыв, idle, абсолютный срок, «из будущего») → редирект с кодом
       причины из закрытого набора домена;
    5. иначе — `Principal`.

    В базу уходит SHA-256 от значения, а не само значение (§8.3).
    """
    cookie = read_session_cookie(request)
    if cookie is None:
        raise SessionRedirect(LOGIN_PATH)
    try:
        ensure_token_syntax(cookie)
    except MalformedSessionTokenError as exc:
        raise SessionRedirect(LOGIN_PATH, clear_cookie=True) from exc
    record = store.session_by_token_hash(token_hash_of(cookie))
    if record is None:
        raise SessionRedirect(SESSION_EXPIRED_PATH, reason=UNKNOWN_SESSION_REASON)
    try:
        ensure_session_active(record, now=utc_now())
    except SessionInvalidError as exc:
        raise SessionRedirect(SESSION_EXPIRED_PATH, reason=exc.code) from exc
    return Principal(session=record, secret=cookie)


def require_session(request: Request, store: StoreDep) -> Principal:
    """Маршрут требует живую сессию (любого шага входа).

    §8.2: на шаге `'password'` доступны страница кода и `/logout`, остальное — только с `'full'`.
    Для `T-102` это значит, что `/logout` охраняется этой зависимостью, а список устройств —
    `require_full_session`.

    Живую сессию продлевает: §8.3 считает idle от последней активности, и маршрут, который бы
    продление обошёл, тихо отзывал бы сессию у пользователя, который работает.
    """
    principal = authenticate(request, store)
    touch_session(store, principal)
    return principal


def require_full_session(request: Request, store: StoreDep) -> Principal:
    """Маршрут требует полный вход (`auth_step='full'`, §8.2).

    Шаг хранится в базе, а не в куке, поэтому «поднять» его подменой значения на клиенте нельзя.
    До `T-103` пользователь, застрявший на `'password'`, возвращается на страницу входа: страницы
    ввода кода ещё нет, и вести его в несуществующий маршрут — значит показать `404` человеку,
    который только что ввёл верный пароль.

    Проверка «ни один боевой маршрут не пускает без `'full'`» — параметризованная
    `test_route_requires_full_auth` из `T-103`: она появится, когда появятся сами маршруты.
    """
    principal = require_session(request, store)
    try:
        ensure_full_auth(principal.session, now=utc_now())
    except SessionStepError as exc:
        raise SessionRedirect(LOGIN_PATH) from exc
    return principal


def touch_session(store: Store, principal: Principal) -> None:
    """Продлить idle и зафиксировать продление.

    `last_seen_at` в модели имеет `onupdate=now()`: если значение не выставить явно, база подставит
    своё время коммита вместо времени запроса, а список устройств (§8.3) обязан показывать момент
    обращения пользователя.
    """
    register_session_activity(principal.session, now=utc_now())
    store.commit()


def session_ip(request: Request) -> str | None:
    """Значение `sessions.ip` для выпускаемой сессии (§8.3 показывает его в списке устройств).

    Источник — `clients.client_address` (правый элемент `X-Forwarded-For`, проставленный Caddy).
    Та же функция даёт ключ счётчика лимитов и окна перебора (`security/rate_limit.py`, срез
    `R3d`): адрес «того, кого блокируем», и адрес «того, кого показываем», обязаны считаться
    одинаково, иначе §8.2 не срабатывал бы вообще.
    """
    return client_address(request)
