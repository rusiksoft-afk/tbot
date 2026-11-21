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
  `SessionRedirect` → `302` на страницу состояния, отказ CSRF → `403` без подробностей, слишком
  большое тело формы → `413`, нет адреса базы → `503`, повреждённый хэш пароля → `503`. Один
  обработчик на случай нужен не для красоты: «отзыв отражается немедленно» (§8.3) и «CSRF
  обязателен для всех мутаций» (§8.8) теряются ровно тогда, когда каждый маршрут объясняет
  состояние по-своему.

Заголовки CSP/HSTS/`Referrer-Policy`/`X-Content-Type-Options`/`Permissions-Policy` здесь ещё не
ставятся — это следующий срез `T-102` (`R3c`), и контракт на них появится вместе с ними.
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
from apps.web.routes import login as login_routes
from apps.web.routes import sessions as session_routes
from apps.web.security.csrf import CsrfRejected
from apps.web.security.headers import apply_security_headers
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
from packages.identity.passwords import MalformedPasswordHashError

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

    app.include_router(login_routes.router)
    app.include_router(session_routes.router)

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

        Сюда же попадает пользователь после успешного парольного шага: страницы ввода кода 2FA ещё
        нет (её вводит `T-103`), поэтому `POST_LOGIN_REDIRECT` ведёт на корневую страницу. Это
        честное состояние «пароль принят, второго фактора ещё нет»: запись сессии остаётся на шаге
        `'password'`, и охраняемые маршруты её не пустят (проверка —
        `require_full_session` и параметризованная `test_route_requires_full_auth` из `T-103`).
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
