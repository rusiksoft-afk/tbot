"""Точка входа процесса `web` (M0: каркас, health/metrics; интерфейс входа — веха M1).

Что уже гарантируется на M0:

* конфигурация загружается и проверяется до старта (ошибка конфигурации — не запуск с
  дефолтами, а падение процесса);
* `/healthz` отвечает, пока процесс жив; `/readyz` — только при исправной базе;
* `/metrics` отдаёт базовый набор метрик с `tbot_build_info`;
* сервер не слушает внешний интерфейс без явного указания (в конфиге по умолчанию 127.0.0.1;
  наружу выход даёт только Caddy с TLS — TZ §14.5).
"""

from __future__ import annotations

from typing import Any

import psycopg
from fastapi import FastAPI, Response, status
from fastapi.responses import JSONResponse

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

log = get_logger("web")

APP_NAME = "web"
_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}


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


def create_app(settings: Settings) -> FastAPI:
    """Фабрика приложения: зависимости передаются явно, глобалов у обработчиков нет."""

    app = FastAPI(
        title="tbot web-консоль",
        version=_BUILD["version"],
        docs_url=None,  # документация не публикуется наружу: доступ к консоли — из allowlist
        redoc_url=None,
        openapi_url=None,
    )

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
        """Служебная заглушка: страница входа появится в M1 (docs/tz/09)."""
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
