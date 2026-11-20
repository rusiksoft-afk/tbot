"""Web-процесс M0: конфигурация, разделение health/readiness, метрики, trace_id (TZ §12.4)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.web.main import APP_NAME, create_app
from packages.common.config import Contour, Settings


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), base_url="http://testserver")


@pytest.fixture
def client_with_db(secrets_dir: Path) -> TestClient:
    """Клиент с настроенным адресом базы: проверка `database` доходит до драйвера.

    Форма адреса — ровно та, что лежит на площадке в секретном файле `db_url`
    (`postgresql+psycopg://…`, TZ §14.9): с «плюсовой» схемой `psycopg.connect` падает ещё до
    соединения с сервером, и тест на обычной схеме этого бы не поймал.
    """
    from pydantic import SecretStr

    settings = Settings(
        secrets_dir=secrets_dir,
        db_url=SecretStr("postgresql+psycopg://tbot:secretvalue@postgres:5432/tbot"),
    )
    return TestClient(create_app(settings), base_url="http://testserver")


def test_корень_сообщает_что_веб_консоль_ещё_не_готова(client: TestClient) -> None:
    """Заглушка вместо «красивой» страницы входа: интерфейс появится в M1 (docs/tz/09)."""
    payload = client.get("/").json()
    assert payload["app"] == APP_NAME
    assert "M1" in payload["note"]


def test_healthz_всегда_отвечает(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_readyz_не_готов_без_настроенной_базы(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert "db_url" in payload["checks"]["database"]["detail"]


def test_readyz_готов_при_исправной_базе(
    client_with_db: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Cursor:
        def __enter__(self) -> _Cursor:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def execute(self, _sql: str) -> None:
            return None

        def fetchone(self) -> tuple[int]:
            return (1,)

    class _Connection:
        def __enter__(self) -> _Connection:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def cursor(self) -> _Cursor:
            return _Cursor()

    подключено: list[str] = []

    def _connect(dsn: str, **_kw: object) -> _Connection:
        подключено.append(dsn)
        return _Connection()

    monkeypatch.setattr("apps.web.main.psycopg.connect", _connect)
    response = client_with_db.get("/readyz")
    assert response.status_code == 200
    assert response.json()["checks"]["database"]["ok"] is True
    # Что именно ушло в драйвер: форма SQLAlchemy для psycopg3 неподъёмна, прямое
    # подключение обязано получить `postgresql://…` (замер на площадке 2026-11-20:
    # ProgrammingError «missing "=\"» и нездоровый `web`).
    assert подключено == ["postgresql://tbot:secretvalue@postgres:5432/tbot"]


def test_readyz_не_готов_при_ошибке_базы(
    client_with_db: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psycopg

    def _fail(*_a: object, **_k: object) -> None:
        msg = "connection refused"
        raise psycopg.OperationalError(msg)

    monkeypatch.setattr("apps.web.main.psycopg.connect", _fail)
    response = client_with_db.get("/readyz")
    assert response.status_code == 503
    assert "postgres недоступен" in response.json()["checks"]["database"]["detail"]


def test_metrics_отдаёт_базовый_набор(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "tbot_build_info" in response.text
    assert "tbot_process_heartbeat_timestamp_seconds" in response.text


def test_trace_id_приходит_из_заголовка_и_возвращается(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Trace-Id": "trace-abc-123"})
    assert response.headers["X-Trace-Id"] == "trace-abc-123"


def test_trace_id_генерируется_если_его_не_передали(client: TestClient) -> None:
    response = client.get("/healthz")
    trace = response.headers["X-Trace-Id"]
    assert len(trace) == 32
    assert trace.isascii()


def test_документация_api_не_публикуется(client: TestClient) -> None:
    """Консоль доступна из allowlist, но справочники API наружу не отдаются (docs/tz/08 §8.9)."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_контур_пробрасывается_в_readiness(secrets_dir: Path) -> None:
    settings = Settings(secrets_dir=secrets_dir, contour=Contour.PAPER)
    client = TestClient(create_app(settings), base_url="http://testserver")
    assert client.get("/readyz").json()["contour"] == "paper"
