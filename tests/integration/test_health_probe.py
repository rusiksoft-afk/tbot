"""Проба эндпоинта состояния (healthcheck контейнеров) против реального HTTP-сервера.

Проверка идёт по loopback-адресу: `probe` обязан корректно различать 200, 503, недоступный
порт и неподдерживаемую схему — именно по этим кодам `docker` решает, готов контейнер.
"""

from __future__ import annotations

import pytest

from packages.common.health_probe import main, probe
from packages.common.health_server import HealthServer


@pytest.fixture
def ready_server() -> HealthServer:
    server = HealthServer(
        app_name="probe-target",
        checks=[("ok", lambda: (True, "всё в порядке"))],
        host="127.0.0.1",
        port=0,
    )
    server.start()
    return server


@pytest.fixture
def failing_server() -> HealthServer:
    server = HealthServer(
        app_name="probe-target",
        checks=[("broken", lambda: (False, "нет подключения к базе"))],
        host="127.0.0.1",
        port=0,
    )
    server.start()
    return server


def _stop(*servers: HealthServer) -> None:
    for server in servers:
        server.stop()


def test_готовый_эндпоинт_даёт_200(ready_server: HealthServer) -> None:
    try:
        status, detail = probe(f"http://127.0.0.1:{ready_server.port}/readyz")
        assert status == 200
        assert "всё в порядке" in detail
    finally:
        _stop(ready_server)


def test_неготовый_эндпоинт_даёт_503(failing_server: HealthServer) -> None:
    try:
        status, detail = probe(f"http://127.0.0.1:{failing_server.port}/readyz")
        assert status == 503
        assert "нет подключения к базе" in detail
    finally:
        _stop(failing_server)


def test_закрытый_порт_это_недоступность(ready_server: HealthServer) -> None:
    port = ready_server.port
    _stop(ready_server)
    status, detail = probe(f"http://127.0.0.1:{port}/readyz", timeout_s=2.0)
    assert status == -1
    assert "недоступен" in detail


def test_схема_адреса_проверяется() -> None:
    status, detail = probe("ftp://127.0.0.1:21/readyz")
    assert status == -1
    assert "неподдерживаемая схема" in detail

    status, detail = probe("127.0.0.1:9101/readyz")
    assert status == -1
    assert "неподдерживаемая схема" in detail


def test_тело_ответа_ограничено_по_объёму(ready_server: HealthServer) -> None:
    try:
        _status, detail = probe(f"http://127.0.0.1:{ready_server.port}/metrics")
        assert len(detail) <= 400
    finally:
        _stop(ready_server)


def test_код_возврата_скрипта(ready_server: HealthServer, failing_server: HealthServer) -> None:
    try:
        assert main(["--url", f"http://127.0.0.1:{ready_server.port}/readyz"]) == 0
        assert main(["--url", f"http://127.0.0.1:{failing_server.port}/readyz"]) == 1
        # Для /healthz важен сам факт ответа: процесс жив, но ещё не готов.
        assert main(["--liveness", "--url", f"http://127.0.0.1:{failing_server.port}/healthz"]) == 0
        assert main(["--liveness", "--url", "http://127.0.0.1:1/healthz"]) == 1
    finally:
        _stop(ready_server, failing_server)
