"""HTTP-эндпоинты состояния для процессов без web-интерфейса (TZ §12.4).

`engine`, `tgbot` и `jobs` не содержат пользовательского веб-слоя, но обязаны отдавать
`/healthz`, `/readyz` и `/metrics`, чтобы `docker compose` и мониторинг видели разницу между
«процесс жив» и «процесс готов работать». Реализация — стандартная библиотека: лишних
зависимостей и лишней поверхности атаки у фоновых процессов быть не должно.

Разделение смыслов:

* `/healthz` — 200, пока процесс обслуживает запросы (liveness). Никаких внешних проверок:
  иначе падение базы приведёт к перезапуску контейнера без пользы;
* `/readyz` — 200, только когда пройдены все проверки готовности; иначе 503 с перечислением
  причин;
* `/metrics` — текстовый формат Prometheus.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from packages.common import metrics
from packages.common.clock import ms_timestamp
from packages.common.logging import get_logger

type CheckResult = tuple[bool, str]
type Check = tuple[str, Callable[[], CheckResult]]

_log = get_logger("health")


class _HealthHandler(BaseHTTPRequestHandler):
    """Обработчик путей состояния. Классовые поля задаются при создании сервера."""

    app_name: str = "unknown"
    checks: Sequence[Check] = ()
    server_version = "tbot-health/1"

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _respond_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._respond(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/healthz":
            self._respond_json(200, {"status": "alive", "app": self.app_name})
            return
        if path == "/readyz":
            results = {name: _run_check(perform) for name, perform in self.checks}
            ready = all(ok for ok, _ in results.values())
            self._respond_json(
                200 if ready else 503,
                {
                    "status": "ready" if ready else "not_ready",
                    "app": self.app_name,
                    "checks": {
                        name: {"ok": ok, "detail": detail} for name, (ok, detail) in results.items()
                    },
                },
            )
            return
        if path == "/metrics":
            self._respond(200, metrics.render(), metrics.content_type())
            return
        if path == "/":
            self._respond_json(
                200,
                {
                    "app": self.app_name,
                    "endpoints": ["/healthz", "/readyz", "/metrics"],
                    "ts_ms": ms_timestamp(),
                },
            )
            return
        self._respond_json(404, {"status": "not_found", "path": path})

    def log_message(self, format: str, *args: object) -> None:
        _log.debug("health_http", message=format % args, client=str(self.address_string()))


def _run_check(perform: Callable[[], CheckResult]) -> CheckResult:
    """Выполнить проверку, превратив исключение в «не готово», а не в 500."""
    try:
        return perform()
    except Exception as exc:
        return False, f"exception: {type(exc).__name__}: {exc}"


class HealthServer:
    """HTTP-сервер состояния в отдельном потоке; порт 0 означает «выбрать свободный»."""

    def __init__(
        self, *, app_name: str, checks: Sequence[Check], host: str = "127.0.0.1", port: int
    ) -> None:
        handler_type = type(
            "_BoundHealthHandler",
            (_HealthHandler,),
            {"app_name": app_name, "checks": tuple(checks)},
        )
        self._server = ThreadingHTTPServer((host, port), handler_type)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name=f"health-{app_name}", daemon=True
        )

    @property
    def port(self) -> int:
        """Фактический порт (важно при `port=0` в тестах)."""
        address = self._server.server_address
        return int(address[1])  # сервер создан с AF_INET → (host, port)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> HealthServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
