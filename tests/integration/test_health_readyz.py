"""Эндпоинты состояния фоновых процессов (TZ §12.4): разделение liveness и readiness."""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from packages.common import metrics
from packages.common.health_server import HealthServer


@pytest.fixture
def server() -> Iterator[HealthServer]:
    def ok_check() -> tuple[bool, str]:
        return True, "всё в порядке"

    def failing_check() -> tuple[bool, str]:
        return False, "внешний канал недоступен"

    def exploding_check() -> tuple[bool, str]:
        msg = "проверка упала"
        raise RuntimeError(msg)

    with HealthServer(
        app_name="engine",
        checks=[("db", ok_check), ("telegram", failing_check), ("broker", exploding_check)],
        host="127.0.0.1",
        port=0,
    ) as instance:
        yield instance


def _get(server: HealthServer, path: str) -> httpx.Response:
    return httpx.get(f"http://127.0.0.1:{server.port}{path}", timeout=5)


def test_healthz_отвечает_несмотря_на_непрошедшие_проверки(server: HealthServer) -> None:
    """Liveness не зависит от внешних зависимостей: иначе база роняла бы контейнер зря."""
    response = _get(server, "/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "alive"
    assert payload["app"] == "engine"


def test_readyz_возвращает_503_с_перечислением_причин(server: HealthServer) -> None:
    response = _get(server, "/readyz")
    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["checks"]["db"]["ok"] is True
    assert payload["checks"]["telegram"]["detail"] == "внешний канал недоступен"
    # Упавшая проверка не должна ронять сам эндпоинт состояния.
    assert payload["checks"]["broker"]["ok"] is False
    assert "RuntimeError" in payload["checks"]["broker"]["detail"]


def test_readyz_200_когда_все_проверки_пройчены() -> None:
    with HealthServer(
        app_name="jobs", checks=[("db", lambda: (True, "ok"))], host="127.0.0.1", port=0
    ) as instance:
        response = _get(instance, "/readyz")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


def test_metrics_содержит_метаданные_сборки(server: HealthServer) -> None:
    metrics.set_build_info(version="0.0.0", revision="ci-1234", build_time="2026-11-19T00:00:00Z")
    response = _get(server, "/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert 'revision="ci-1234"' in response.text


def test_неизвестный_путь_это_404_без_лишней_информации(server: HealthServer) -> None:
    response = _get(server, "/debug/secrets")
    assert response.status_code == 404
    assert response.json() == {"status": "not_found", "path": "/debug/secrets"}


def test_корень_сообщает_какие_пути_есть(server: HealthServer) -> None:
    payload = _get(server, "/").json()
    assert payload["app"] == "engine"
    assert set(payload["endpoints"]) == {"/healthz", "/readyz", "/metrics"}


def test_сервер_останавливается_корректно() -> None:
    instance = HealthServer(app_name="web", checks=[], host="127.0.0.1", port=0)
    instance.start()
    port = instance.port
    assert port > 0
    assert httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200
    instance.stop()
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2)
