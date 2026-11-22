"""Точка входа процесса `web` (M0: каркас, health/metrics; M1: вход и сессии).

Что гарантируется на M0 и что добавлено срезом `R3a`/`R3b` задачи `T-102`:

* конфигурация загружается и проверяется до старта (ошибка конфигурации — не запуск с дефолтами, а
  падение процесса);
* `/healthz` отвечает, пока процесс жив; `/readyz` — только при исправной базе;
* `/metrics` отдаёт базовый набор метрик с `tbot_build_info`;
* сервер не слушает внешний интерфейс без явного указания (в конфиге по умолчанию 127.0.0.1;
  наружу выход даёт только Caddy с TLS — TZ §14.5);
* вывод в HTML — Jinja2 с явным `autoescape=True` и `StrictUndefined` (TZ §8.3: «autoescape=true
  везде»). Значение ставится явно, а не «как получится у шаблонизатора по умолчанию», потому что
  у Jinja2 по умолчанию экранирование **выключено**;
* политика отказов слоя входа собрана в обработчиках исключений, а не размазана по маршрутам:
  `SessionRedirect` → `302` на страницу состояния, отказ CSRF → `403` без подробностей, отказ
  допуска по роли (§1.1, срез `R6`) → `403` тем же фиксированным текстом без имён и счётчиков,
  слишком большое тело формы → `413`, нет адреса базы → `503`, повреждённый хэш пароля → `503`,
  предел частоты по адресу и бан адреса → `429` с `Retry-After` (§8.2, §8.3), недоступный файл
  ключей KEK → `503` с объяснением (срез `R4c`, `ADR-014`). Один
  обработчик на случай нужен не для красоты: «отзыв отражается немедленно» (§8.3) и «CSRF
  обязателен для всех мутаций» (§8.8) теряются ровно тогда, когда каждый маршрут объясняет
  состояние по-своему.

Заголовки CSP/HSTS/`Referrer-Policy`/`X-Content-Type-Options`/`Permissions-Policy` ставит
middleware самого приложения (срез `R3c`): значения побайтово совпадают с `deploy/caddy/Caddyfile`, а
расхождение ловит контракт. Срез `R3d` добавил отказ `429` — пределы частоты §8.3 и бан адреса §8.2.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from starlette.templating import Jinja2Templates

from apps.web.forms import FormBodyTooLarge
from apps.web.routes import admin_users as admin_routes
from apps.web.routes import invitations as invitation_routes
from apps.web.routes import login as login_routes
from apps.web.routes import profile as profile_routes
from apps.web.routes import sessions as session_routes
from apps.web.routes import totp as totp_routes
from apps.web.security.authorization import handle_access_denied, handle_account_state
from apps.web.security.csrf import CsrfRejected, csrf_context
from apps.web.security.headers import apply_security_headers
from apps.web.security.keys import (
    TWO_FACTOR_UNAVAILABLE_DETAIL,
    TwoFactorUnavailableError,
)
from apps.web.security.rate_limit import RateLimitExceeded
from apps.web.security.sessions import REASON_QUERY, SessionRedirect, clear_session_cookie
from apps.web.store import LoginTiming, StoreUnavailableError, build_session_factory
from packages.common import metrics
from packages.common.clock import utc_now
from packages.common.config import ConfigError, Settings, load_settings
from packages.common.db import psycopg_dsn
from packages.common.health_server import CheckResult
from packages.common.ids import new_trace_id
from packages.common.logging import (
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
)
from packages.identity.authorization import AccessDeniedError
from packages.identity.passwords import MalformedPasswordHashError
from packages.identity.users import AccountAccessError

log = get_logger("web")

APP_NAME = "web"
_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}

#: Шаблоны лежат рядом с кодом процесса, а не в `configs/`: `deploy/Dockerfile` копирует `apps` в
#: `/srv/tbot` целиком, поэтому путь относительно `__file__` работает и в образе, и в тестах.
TEMPLATES_SUBDIR: str = "templates"


def check_database(settings: Settings) -> CheckResult:
    """Проверка доступности PostgreSQL (только для `/readyz`)."""
    if settings.db_url is None:
        return False, "db_url не настроен (секретный файл или TBOT_DB_URL)"
    dsn = psycopg_dsn(settings.db_url.get_secret_value())
    try:
        with (
            psycopg.connect(dsn, connect_timeout=3) as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
    except psycopg.Error as exc:
        return False, f"postgres недоступен: {type(exc).__name__}"
    if row is None:
        return False, "postgres не вернул результат"
    return True, "postgres доступен"


def readiness_checks(settings: Settings) -> list[tuple[str, Any]]:
    """Набор проверок готовности web-процесса."""
    return [("database", lambda: check_database(settings))]


def _render_templates(templates_dir: Path) -> Jinja2Templates:
    """Один шаблонизатор на приложение с экранированием, включённым явно (§8.3).

    `autoescape=True` указан, а не унаследован: у `jinja2.Environment` экранирование по умолчанию
    выключено, и «работает же» в этом случае означает, что страница с подстановкой пользовательской
    строки станет исполняемой (§8.8: «XSS в полях не исполняется»).

    `StrictUndefined` — чтобы опечатка в имени переменной была ошибкой рендеринга, а не пустым
    местом в тексте, который читает пользователь. Требование осознанное: все контексты обязаны
    передаваться полностью, и проверка `test_web_security_contract.py` держит оба значения.
    """
    return Jinja2Templates(
        env=Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=True,
            undefined=StrictUndefined,
        )
    )


def create_app(settings: Settings) -> FastAPI:
    """Фабрика приложения: зависимости передаются явно, глобалов у обработчиков нет."""

    app = FastAPI(
        title="tbot web-консоль",
        version=_BUILD["version"],
        docs_url=None,  # документация не публикуется наружу: доступ к консоли — из allowlist
        redoc_url=None,
        openapi_url=None,
    )

    app.state.templates = _render_templates(Path(__file__).resolve().parent / TEMPLATES_SUBDIR)
    app.state.engine, app.state.session_factory = build_session_factory(settings)
    #: Стоимость Argon2id для ветки «логина нет»: держится приложением, а не глобалом, чтобы два
    #: приложения в одном процессе (например, в тестах) не делили состояние молча.
    app.state.login_timing = LoginTiming()
    # Путь файла ключей KEK (§8.4, `ADR-014` п. 5): единственная настройка, которую читают
    # маршруты кода и привязки. Имя атрибута держит константой `apps/web/security/keys.py`
    # (`KEK_FILE_STATE`): набор ключей при каждом запросе открывает этот же модуль, а
    # интеграционные проверки подменяют путь временным файлом.
    app.state.kek_file = settings.kek_file

    app.include_router(login_routes.router)
    app.include_router(session_routes.router)
    app.include_router(profile_routes.router)
    app.include_router(totp_routes.router)
    app.include_router(invitation_routes.router)
    app.include_router(admin_routes.router)

    @app.middleware("http")
    async def _trace_middleware(request: Any, call_next: Any) -> Any:
        trace_id = request.headers.get("X-Trace-Id") or new_trace_id()
        bind_request_context(trace_id=trace_id, path=request.url.path)
        try:
            response = await call_next(request)
        finally:
            clear_request_context()
        response.headers["X-Trace-Id"] = trace_id
        return response

    @app.middleware("http")
    async def _security_headers_middleware(request: Any, call_next: Any) -> Any:
        """Закрытый набор заголовков безопасности на любом ответе (§8.3).

        Middleware, а не каждый маршрут: отказные ответы (`403` CSRF, `413` тела, `503` без базы,
        редирект «сессия не подходит») создаются обработчиками исключений, и маршрут их не видит.
        Значения те же, что у периметра в `deploy/caddy/Caddyfile` — расхождение двух политик
        браузер пересёк бы, а не выбрал.

        Порядок: этот middleware идёт внутри `ServerErrorMiddleware`, поэтому необработанный
        `500` (plain text от Starlette) заголовков не получает — это единственная ветка без
        политики, и она не должна отдавать текст стека наружу (§8.4).
        """
        return apply_security_headers(await call_next(request))

    @app.exception_handler(SessionRedirect)
    async def _session_redirect(request: Request, exc: SessionRedirect) -> Response:
        """Единая политика «сессия не подходит» (§8.3, §9).

        Причина передаётся параметром запроса и берётся только из закрытого набора
        (`display_reason_codes`): страница состояния читает её по таблице, а не печатает как есть,
        поэтому в адрес не подставляется произвольный текст.
        """
        location = exc.location
        if exc.reason is not None:
            location = f"{location}?{REASON_QUERY}={exc.reason}"
        response = RedirectResponse(location, status_code=status.HTTP_302_FOUND)
        if exc.clear_cookie:
            clear_session_cookie(response)
        log.info(
            "session_redirect",
            path=request.url.path,
            reason=exc.reason or "not_explained",
            clear_cookie=exc.clear_cookie,
        )
        return response

    @app.exception_handler(CsrfRejected)
    async def _csrf_rejected(_request: Request, exc: CsrfRejected) -> JSONResponse:
        """`403` без подробностей (ADR-008).

        В ответе нет ни причины, ни признака, по которому запрос отклонён: по различию ответов
        подбором находилось бы, где именно живёт запрошенный контур. Причина уходит в лог
        процесса, а в `audit_log` её же переведёт задача `T-109`.
        """
        log.warning("csrf_rejected", detail=str(exc))
        return JSONResponse(
            {"status": "forbidden", "detail": "запрос отклонён"},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    @app.exception_handler(AccessDeniedError)
    async def _access_denied(request: Request, exc: AccessDeniedError) -> JSONResponse:
        """`403` единым текстом для любого отказа допуска (§1.1, §8.8, `ADR-017` п. 4).

        Ответ не зависит ни от причины (роль ниже требуемой, роль вне закрытого набора, у сеанса
        пропала строка учётной записи), ни от маршрута: `AC-identity-01` требует `403` без утечки
        списка пользователей, а тот же принцип «не быть оракулом» уже принят для резервных кодов
        (`ADR-016` п. 5). Обработчик один, потому что отказ поднимают зависимости охраны, а не
        обработчики: иначе «забыли перехватить» появилось бы ровно там, где его не проверяли.
        """
        return handle_access_denied(request, exc)

    @app.exception_handler(AccountAccessError)
    async def _account_state_denied(request: Request, exc: AccountAccessError) -> Response:
        """Страница «доступ закрыт состоянием учётной записи» (§9.3, §1.2, `ADR-020` п. 6).

        Отдельный ответ, а не общий отказ допуска: безликий `403` нужен там, где иначе проставился
        бы лик чужой учётной записи, а объяснение состояния получает владелец **своей** записи,
        которой вход закрыт (§9.1 требует внятного состояния). Обработчик один и регистрируется
        здесь, а не в маршрутах: исключение поднимает зависимость `enforce_role`, то есть до тела
        обработчика, и «перехватить в каждом маршруте» физически невозможно — тот же приём, что у
        `AccessDeniedError` и отказов CSRF (`ADR-017` п. 3).

        Состояние проверяется на каждый охраняемый запрос, поэтому блокировка и одобрение
        применяются к живому сеансу немедленно, а не после перезапуска `web`.
        """
        return handle_account_state(request, exc)

    @app.exception_handler(FormBodyTooLarge)
    async def _form_too_large(_request: Request, exc: FormBodyTooLarge) -> JSONResponse:
        """`413`, а не `403`: превышение размера — не подозрение в подделке токена.

        Предел тела держит периметр (ADR-003: `max_header_size`, `request_body max_size`), но `web`
        принимает соединения и из внутренней сети состава, а ложный `Content-Length` при
        chunked-кодировании обманывает проверку заявленного размера — поэтому предел ставит и сама
        форма (`apps/web/forms.py`).
        """
        log.warning("form_body_too_large", detail=str(exc))
        return JSONResponse(
            {"status": "too_large", "detail": "слишком большое тело формы"},
            status_code=413,
        )

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        """`429` с `Retry-After` для мутаций, у которых нет своей объясняющей страницы.

        Политика отказа зафиксирована решением заказчика (ask `ba6a9076`): код обязан быть именно
        `429`, а не `403` и не `200` с текстом — `Retry-After` часть ответа, по нему ориентируются и
        браузер, и интеграционные проверки.

        Маршруты входа этот ответ не отдают: им нужна ссылка на страницу состояния `/locked` (§9),
        поэтому они ловят исключение сами и объясняют его HTML-страницей. Один обработчик на
        остальные мутации нужен потому, что иначе «429 без Retry-After» появилось бы ровно там, где
        никто не проверял. Запись в `audit_log` (§8.7) здесь не делается осознанно: имена событий и
        цепочка хэшей — `T-109`, перенос зафиксирован `docs/adr/ADR-009`.
        """
        log.warning("rate_limited", path=request.url.path, scope=exc.scope)
        return JSONResponse(
            {
                "status": "rate_limited",
                "detail": "слишком много запросов, повторите позже",
            },
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
        )

    @app.exception_handler(StoreUnavailableError)
    async def _store_unavailable(_request: Request, _exc: StoreUnavailableError) -> JSONResponse:
        """`503` теми же словами, что и `/readyz`: адрес базы не настроен."""
        return JSONResponse(
            {
                "status": "not_ready",
                "detail": "db_url не настроен (секретный файл или TBOT_DB_URL)",
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(MalformedPasswordHashError)
    async def _malformed_password_hash(
        request: Request, exc: MalformedPasswordHashError
    ) -> JSONResponse:
        """Хэш в базе не является кодировкой Argon2id.

        Молча ответить «неверный пароль» нельзя: пользователь не сможет войти, а причина исчезнет
        (`packages/identity/passwords.py` требует не скрывать этот случай). Для пользователя текст
        нейтральный, для оператора — ошибка в логе с путём запроса; содержимое хэшей не пишется.
        """
        log.error("malformed_password_hash", path=request.url.path, detail=str(exc))
        return JSONResponse(
            {
                "status": "unavailable",
                "detail": "данные учётной записи повреждены, обратитесь к администратору",
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(TwoFactorUnavailableError)
    async def _two_factor_unavailable(request: Request, exc: TwoFactorUnavailableError) -> Response:
        """`503`: файл ключей недоступен — страница кода и привязки не могут работать.

        Три причины, по которым этот случай нельзя сводить к «неверный код» (`401`), к отказу доступа
        (`403`) или к редиректу на страницу входа:

        1. состояние площадки, а не пользователя: отсутствующий, нечитаемый или неразобранный
           `/etc/tbot/keys/kek.json` означает, что шифровать и расшифровывать привязку нечем
           (`ADR-014` п. 5, `docs/runbook/kek-keys.md`);
        2. счётчик неудач (§8.2) при этом не двигается — и это проверка, а не случайность: учётная
           запись не должна блокироваться из-за операционной поломки, и маршруты вызывают
           `request_key_ring` **до** каких-либо записей о попытке;
        3. вход по паролю остаётся живым (парольный шаг KEK не читает), поэтому формулировка обязана
           говорить правду: доступ в консоль закрыт, а не «приложение упало».

        Причина исключения (путь, режим файла, текст разбора) уходит в лог процесса в самом
        `apps/web/security/keys.py`, в ответе — фиксированный текст без внутренней подробности
        площадки (§8.4). Код `503`, а не `500`: процесс жив и отвечает, а недоступна одна возможность;
        `/readyz` про файл ключей не врёт намеренно — проверка готовности остаётся про базу, а
        пригодность файла проверяет `keys_setup.py --check` при деплое.
        """
        log.error("two_factor_unavailable", path=request.url.path, detail=str(exc))
        page: Response = request.app.state.templates.TemplateResponse(
            request,
            "mfa_unavailable.html",
            {
                "page_title": "Двухфакторная проверка недоступна",
                "detail": TWO_FACTOR_UNAVAILABLE_DETAIL,
            }
            | csrf_context(None),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        return page

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Liveness: процесс обслуживает запросы; внешних проверок здесь нет намеренно."""
        return JSONResponse({"status": "alive", "app": APP_NAME, "ts": utc_now().isoformat()})

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness: исправна база и конфиг пригоден; иначе 503 с перечислением причин."""
        results = {name: check() for name, check in readiness_checks(settings)}
        ready = all(ok for ok, _ in results.values())
        payload = {
            "status": "ready" if ready else "not_ready",
            "app": APP_NAME,
            "contour": settings.contour.value,
            "checks": {
                name: {"ok": ok, "detail": detail} for name, (ok, detail) in results.items()
            },
        }
        return JSONResponse(
            payload,
            status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        return Response(content=metrics.render(), media_type=metrics.content_type())

    @app.get("/")
    def root() -> JSONResponse:
        """Служебная заглушка каркаса: интерфейс управления появится на вехе M1 (docs/tz/09).

        Сюда попадает сессия полного входа (`POST_CODE_REDIRECT`): страниц вехи M1 ещё нет,
        поэтому домашней остаётся корневая, и ответ её честно говорит про веху M1. Сессия шага
        `'password'` сюда не попадает: парольный шаг ведёт на страницу кода
        (`POST_LOGIN_REDIRECT`, §9.3 п. 1–2), а охраняемые маршруты консоли требуют шаг `'full'`
        (`require_full_session` и параметризованная `test_route_requires_full_auth`, срез `R4c`).
        """
        return JSONResponse(
            {
                "app": APP_NAME,
                "build": _BUILD,
                "contour": settings.contour.value,
                "note": "веб-консоль будет добавлена на вехе M1",
            }
        )

    return app


def run() -> int:  # pragma: no cover — запуск uvicorn в составе образа
    """Запуск процесса `web` (используется и как entry point образа).

    Само приложение (`create_app`, маршруты, проверки готовности) покрыто интеграционными
    тестами через TestClient; здесь только обвязка запуска, которую проверяет `compose-smoke`.
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"конфигурация отклонена: {exc}", flush=True)  # логгер ещё не настроен
        return 2
    configure_logging(settings.log_level, json_output=settings.log_json)
    metrics.set_build_info(**_BUILD)
    if settings.contour.value == "production":
        log.warning("production_contour_web", detail="боевой контур: только после приёмки M1")
    import uvicorn

    uvicorn.run(
        create_app(settings),
        host=settings.web_host,
        port=settings.web_port,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover — точка запуска образа
    raise SystemExit(run())
