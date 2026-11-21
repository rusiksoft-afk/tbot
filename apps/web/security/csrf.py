"""CSRF-токен, выводимый из сессии (TZ §8.3, `docs/adr/ADR-008`, матрица §8.8).

Схема зафиксирована ADR-008 и повторена здесь без отклонений:

```
ключ   = HMAC-SHA256(key=b"tbot-csrf-v1", msg=<байты значения куки>)
токен  = base64url(HMAC-SHA256(key=ключ, msg=<строка id сессии>))   # 32 байта → 43 символа
```

Почему именно так, а не «значение куки в скрытом поле» (что было бы буквальным чтением §8.3):
значение куки `HttpOnly`, JavaScript его не видит, значит «токен сессии» пришлось бы напечатать в
HTML — и любой XSS получил бы вместе с токеном материал сессии, то есть `HttpOnly` перестал бы
что-либо защищать. Здесь в HTML попадает производное значение, из которого значение куки не
восстанавливается.

Что держит этот модуль:

* **токена нет в базе** — он выводится из того, что процесс `web` и так знает: значения куки (нужно
  для поиска сессии по `token_hash`) и `sessions.id`. Ни колонки, ни ревизии, ни лишнего секрета в
  `/etc/tbot/secrets` (ADR-006: вывод от значения куки не даёт «корня», которым можно подписать
  токены для всех сессий сразу);
* **пересоздание сессии меняет токен само**: `rotate_session` создаёт новую строку `sessions` с
  новым `id`, и старый токен перестаёт подходить без «пересчёта CSRF»;
* **сверка — `hmac.compare_digest`**, а не `==`: обычное сравнение оставляет тайминг-канал, и в
  этом файле он ровно про секрет;
* **отказ — `403` без подробностей** (ADR-008): странице незачем знать, по какому именно признаку
  отклонён запрос. Причина отказа уходит в лог процесса, а не в ответ;
* **`Origin`/`Sec-Fetch-Site` — второй слой**, а не замена токена: если браузер не прислал `Origin`
  (старые браузеры, не-браузерные клиенты), токен всё равно обязателен, и запрос без него
  отклоняется.

Единственная мутация без токена — сам `/login`: токен выводится из сессии, а сессии до входа ещё
нет. Для него включена проверка origin (см. `apps/web/routes/login.py` и `docs/adr/ADR-009`):
альтернатива в виде «пре-сесссионной» куки добавила бы второй материал сессии в браузере ради
одной страницы.

Чего здесь нет: счётчика частоты запросов — он в `security/rate_limit.py` (срез `R3d`, `ADR-007`),
и заголовков CSP/HSTS — они в `security/headers.py` (срез `R3c`). Порядок для мутаций: отказ CSRF
наступает **до** счётчика частоты (`ADR-008`), иначе подделка запроса расходовала бы лимит жертвы.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from fastapi import Request

from apps.web.forms import form_fields
from apps.web.security.sessions import Principal, SessionRedirect, StoreDep, authenticate
from packages.identity.sessions import ensure_token_syntax

#: Метка вывода. ADR-008: сменить способ вывода — значит поменять эту метку и получить `403` на
#: всех открытых страницах до перезагрузки; миграции здесь нет намеренно.
CSRF_LABEL: Final = b"tbot-csrf-v1"

#: Имя поля формы (§8.3 «токен сессии во всех mutation-запросах»). Форма обязана передавать токен
#: телом, а не строкой запроса: в URL секрет утёк бы в `Referer`, в историю браузера и в логи Caddy.
CSRF_FORM_FIELD: Final = "csrf_token"

#: Заголовок HTMX (§8.3 называет его явно): `hx-headers='{"X-CSRF-Token": …}'`.
CSRF_HEADER: Final = "X-CSRF-Token"

#: `<meta name="csrf-token">`, из которого JS берёт значение для заголовка.
CSRF_META_NAME: Final = "csrf-token"

#: Методы, которым токен не нужен. `TRACE` здесь отсутствует сознательно: разведочные методы
#: отключены на периметре (ADR-003, Caddyfile), и «безопасный метод» из них делать нельзя.
SAFE_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Значение `Sec-Fetch-Site`, которое означает «запрос пришёл с того же источника».
SAME_ORIGIN_SITE: Final = "same-origin"

SEC_FETCH_SITE_HEADER: Final = "Sec-Fetch-Site"
ORIGIN_HEADER: Final = "Origin"

_DEFAULT_PORTS: Final = {"http": 80, "https": 443}


class CsrfRejected(Exception):
    """Отказ мутации: токена нет, токен не тот, источник не тот.

    Сообщение существует только для лога процесса. В ответ оно не уходит: ADR-008 требует `403`
    без подробностей, иначе страница начала бы различать «куки нет», «токен не совпал» и «источник
    чужой» — а это ровно то, что помогает подбором найти живой контур.
    """


# ─── вывод токена (ADR-008) ───────────────────────────────────────────────────────────────────


def _session_key(secret: str) -> bytes:
    """Первый HMAC: ключ уровня сессии из значения куки.

    Значение куки — 256 случайных бит (§8.3), поэтому отдельный секрет процесса для подписи не
    нужен и заводить его негде: в `/etc/tbot/secrets` его быть не должно (ADR-006).
    """
    return hmac.new(CSRF_LABEL, secret.encode("utf-8"), hashlib.sha256).digest()


def csrf_token_for(secret: str, session_id: UUID) -> str:
    """Токен для пары (значение куки, `id` сессии): base64url без «=», 43 символа.

    Форма base64url выбрана не для экономии символов: её не портит экранирование Jinja2
    (`autoescape=true` везде, §8.3), поэтому значение можно вписать в скрытое поле и в `<meta>`
    без `|safe` — а `|safe` для пользовательских строк запрещён.
    """
    ensure_token_syntax(secret)
    digest = hmac.new(
        _session_key(secret), str(session_id).encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def expected_token(principal: Principal) -> str:
    """Ожидаемый токен текущего запроса.

    Идентичность берётся из записи сессии, найденной по хэшу значения куки, а не из «текущей
    сессии процесса»: два запроса с разными куками обязаны давать разные ожидаемые значения.
    """
    return csrf_token_for(principal.secret, principal.session.id)


def token_matches(candidate: str, expected: str) -> bool:
    """Сверка с `hmac.compare_digest` (§ADR-008: «обычное `==` оставляет тайминг-канал»)."""
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def csrf_context(principal: Principal | None) -> dict[str, str]:
    """Значение для шаблонов: скрытое поле `csrf_token` и `<meta name="csrf-token">`.

    `Principal` отсутствует — пустая строка. Форма входа её не заполняет (токен выводится из
    сессии, которой до входа нет), и шаблоны обязаны отличать «токена нет» от «токена не передали»,
    а не падать на `StrictUndefined`.
    """
    return {"csrf_token": "" if principal is None else expected_token(principal)}


# ─── проверка на маршруте ─────────────────────────────────────────────────────────────────────


def ensure_same_origin(request: Request) -> None:
    """Проверить источник запроса (§8.3: «проверка origin»).

    Сначала `Sec-Fetch-Site`: он не подделывается скриптом с чужого источника и даёт точный
    ответ «тот же источник или нет». Если заголовка нет (старые браузеры, `curl`, интеграционные
    тесты), смотрим `Origin`. Если нет и `Origin` — проверка источника просто не сработала: токен
    это не отменяет, он обязателен в любом случае.

    Нормализация обязательна: `http://host` и `http://host:80` — один источник, а разные строки, и
    сравнение без нормализации отклоняло бы легитимные запросы.
    """
    site = request.headers.get(SEC_FETCH_SITE_HEADER)
    if site is not None and site.lower() != SAME_ORIGIN_SITE:
        raise CsrfRejected(f"{SEC_FETCH_SITE_HEADER}={site!r}")
    origin = request.headers.get(ORIGIN_HEADER)
    if origin is None:
        return
    if _normalize_origin(origin) != _request_origin(request):
        raise CsrfRejected(f"{ORIGIN_HEADER}={origin!r}")


def _normalize_origin(value: str) -> tuple[str, str, int | None]:
    """Схема, хост и ненулевой для схемы порт; регистр не значим."""
    scheme, separator, rest = value.partition("://")
    if not separator:
        return (value.strip().lower(), "", None)
    authority = rest.rstrip("/").lower()
    host, port_marker, port_text = authority.partition(":")
    if not port_marker:
        return (scheme, host, None)
    try:
        port = int(port_text)
    except ValueError:
        return (scheme, host, None)
    if _DEFAULT_PORTS.get(scheme) == port:
        return (scheme, host, None)
    return (scheme, host, port)


def _request_origin(request: Request) -> tuple[str, str, int | None]:
    """Источник самого запроса — из него, а не из заголовков, которые проверяются."""
    return _normalize_origin(f"{request.url.scheme}://{request.url.netloc}")


async def presented_token(request: Request) -> str | None:
    """Токен, который предъявил клиент: заголовок HTMX, затем скрытое поле формы.

    Порядок фиксирован: заголовок читается раньше, потому что разбор тела стоит дороже, и потому
    что HTMX не отправляет форму вовсе. Поле из строки запроса не читается никогда — ADR-008
    запрещает токен в URL.

    Разбор тела — свой (`apps/web/forms.py`): штатный `request.form()` требует `python-multipart`,
    а это новая зависимость runtime-слоя, которую по TZ §15 обязан согласовать заказчик. Тело
    кэшируется в `request.state`, поэтому обработчик маршрута читает те же поля повторно и
    «зависимость съела тело» не происходит.

    Слишком большое тело не превращается в отказ CSRF: ему соответствует `413` общим обработчиком,
    иначе превышение размера выглядело бы как подозрение на подделку токена.
    """
    header = request.headers.get(CSRF_HEADER)
    if header is not None and header != "":
        return header
    field = (await form_fields(request)).get(CSRF_FORM_FIELD)
    if field is not None and field != "":
        return field
    return None


async def require_csrf(request: Request, store: StoreDep) -> Principal:
    """Зависимость мутационного маршрута: токен обязан быть, иначе `403`.

    Порядок проверок закреплён под требованиями матрицы §8.8 («CSRF обязателен для всех
    POST/PUT/DELETE, тест «без токена → 403»») и §9 (объяснение, если сессия истекла):

    1. источник: `Sec-Fetch-Site`/`Origin` не тот → `403`;
    2. токена нет вовсе → `403` немедленно, до обращения к базе: ровно этот случай требует §8.8, и
       он обязан оставаться отказом даже при отсутствии куки;
    3. сессии нет (куки нет, значение испорчено, записи нет) → `403`: сверять нечем, объяснять
       нечего, а редирект на страницу входа для мутации означал бы «попробуй ещё раз» вместо
       отказа;
    4. сессия была и перестала быть живой → редирект на страницу состояния: это не подозрение, а
       известная причина, и пользователь обязан её увидеть (§9, `/session-expired`);
    5. токен не совпал → `403` без подробностей.

    Отказ ничего не меняет в состоянии: незавершённый транзакт откатывается закрытием соединения
    (`store.get_store`), поэтому «полумутация» невозможна.
    """
    ensure_same_origin(request)
    token = await presented_token(request)
    if token is None:
        raise CsrfRejected("токена нет")
    try:
        principal = authenticate(request, store)
    except SessionRedirect as exc:
        if exc.reason is None:
            raise CsrfRejected("сессии нет") from exc
        raise
    if not token_matches(token, expected_token(principal)):
        raise CsrfRejected("токен не совпал")
    return principal


@dataclass(frozen=True)
class MutationRoute:
    """Строка таблицы «все мутационные маршруты слоя входа».

    Контрактный тест сверяет её с маршрутами реального приложения: ADR-008 прямо предупреждает,
    что типовая дыра этого дизайна — забыть эндпоинт, который принимает `X-CSRF-Token`, но не
    проверяет его. Таблица, которая расходится с `app.routes`, даёт красный тест, а не тихую дыру.
    """

    path: str
    methods: tuple[str, ...]
    csrf_required: bool
    reason: str
