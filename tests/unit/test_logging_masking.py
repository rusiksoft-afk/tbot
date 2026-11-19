"""REQ-sec-06 / TZ §12.1: секретные значения не попадают в логи (канареечные значения)."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Callable, Iterator

import pytest
import structlog

from packages.common.logging import (
    MASKED_MARKER,
    configure_logging,
    get_logger,
    mask_event_dict,
    mask_secret_value,
    mask_text,
)

# Канареечные значения и контексты, в которых они обязаны замаскироваться. Контекст важен:
# замаскировать «голый» пароль произвольного текста нельзя, не слоги при этом нормальные
# сообщения логов; маскирование работает по структурным признакам (токен, URI с учётными
# данными, заголовок, поле `key: значение`) и по именам полей.
CANARY_BOT_TOKEN = "1234567890:AAHkAnArYvAlUe-abcdefghij_klmnopqrstu"
CANARY_SOCKS_URL = "socks5h://tgbot:localParol1234567890@127.0.0.1:10800"
CANARY_SS_URL = "ss://SGVsbG8tV29ybGQtQ2FuYXJ5LWtleQ==@rusiksoft.ru:443"
CANARY_VLESS_URL = "vless://11111111-2222-3333-4444-555555555555@rusiksoft.ru:443?encryption=none"
CANARY_PASSWORD = "hunter2-SuperSecret-Passw0rd"
CANARY_BEARER = "eyJhbGciOiJIUzI1NiJ9.CaNaRyIsZeSsIg.T3R0ZXItSG9ja0V4YWN0"
CANARY_COOKIE_VALUE = "c0ffee-c0ffee-c0ffee"
CANARY_DB_URL = "postgresql://tbot:dbParol1234567890@127.0.0.1:5432/tbot"
CANARY_PEM = "-----BEGIN PRIVATE KEY-----\nTUfSKCANARYdGF0aW9u\n-----END PRIVATE KEY-----"

MASKING_CASES: tuple[tuple[str, str], ...] = (
    (CANARY_BOT_TOKEN, f"запрос к https://api.telegram.org/bot{CANARY_BOT_TOKEN}/getMe"),
    (CANARY_SOCKS_URL, f"подключение к {CANARY_SOCKS_URL} не удалось"),
    (CANARY_SS_URL, f"строка клиента: {CANARY_SS_URL}"),
    (CANARY_VLESS_URL, f"строка клиента: {CANARY_VLESS_URL}"),
    (CANARY_PASSWORD, f"password={CANARY_PASSWORD}"),
    (CANARY_PASSWORD, f'"passphrase": "{CANARY_PASSWORD}"'),
    (CANARY_BEARER, f"Authorization: Bearer {CANARY_BEARER}"),
    (CANARY_COOKIE_VALUE, "Set-Cookie: sessionid-c0ffee-c0ffee-c0ffee; Path=/"),
    (CANARY_DB_URL, f"строка подключения: {CANARY_DB_URL}"),
    (CANARY_PEM, f"в буфере ключа: {CANARY_PEM}"),
)

ALL_CANARIES: tuple[str, ...] = (
    CANARY_BOT_TOKEN,
    CANARY_SOCKS_URL,
    CANARY_SS_URL,
    CANARY_VLESS_URL,
    CANARY_PASSWORD,
    CANARY_BEARER,
    CANARY_COOKIE_VALUE,
    CANARY_DB_URL,
    CANARY_PEM,
)


@pytest.mark.parametrize(("canary", "context"), MASKING_CASES, ids=range(len(MASKING_CASES)))
def test_каждый_шаблон_маскируется(canary: str, context: str) -> None:
    masked = mask_text(context)
    assert canary not in masked
    assert MASKED_MARKER in masked or "…" in masked


def test_маска_сохраняет_узнаваемую_форму() -> None:
    masked = mask_secret_value(CANARY_BOT_TOKEN)
    assert CANARY_BOT_TOKEN not in masked
    assert masked.startswith(CANARY_BOT_TOKEN[:6])
    assert masked.endswith(CANARY_BOT_TOKEN[-4:])
    assert mask_secret_value("коротк") == "***"


def test_ключевые_поля_заменяются_целиком() -> None:
    event: dict[str, object] = {"event": "login", "password": CANARY_PASSWORD, "user_id": 7}
    masked = mask_event_dict(dict(event))
    assert masked["password"] == "***"
    assert masked["user_id"] == 7


def test_вложенные_структуры_маскируются() -> None:
    event: dict[str, object] = {
        "event": "http_call",
        "request": {
            "headers": {
                "Authorization": f"Bearer {CANARY_BEARER}",
                "Cookie": f"sessionid={CANARY_COOKIE_VALUE}",
            }
        },
        "attempts": [{"url": CANARY_SOCKS_URL}],
    }
    masked = mask_event_dict(dict(event))
    rendered = json.dumps(masked, ensure_ascii=False)
    for canary in (CANARY_BEARER, CANARY_COOKIE_VALUE, CANARY_SOCKS_URL):
        assert canary not in rendered


@pytest.fixture
def json_logs() -> Iterator[Callable[[], list[str]]]:
    """Строки лога, прошедшие тем же конвейером и тем же `Formatter`, что и процесс.

    Приёмник подменяется буфером в памяти: pytest переставляет обработчики `logging` на каждом
    этапе теста, поэтому проверка «ушло ли в stdout» зависела бы от порядка его плагинов, а не
    от того, что именно проверяется — от форматирования и маскирования.
    """
    stream = io.StringIO()
    configure_logging("DEBUG", json_output=True, stream=stream)

    def readout() -> list[str]:
        return [line for line in stream.getvalue().splitlines() if line.strip()]

    yield readout
    logging.getLogger().handlers.clear()
    structlog.reset_defaults()


def test_лог_приложения_не_содержит_канареек(json_logs: Callable[[], list[str]]) -> None:
    log = get_logger("test.subject")
    log.info("probe", token=CANARY_BOT_TOKEN, proxy=CANARY_SOCKS_URL)
    log.warning("connect_failed", detail=f"не удалось подключиться: {CANARY_SS_URL}")
    log.error("auth", message=f"password={CANARY_PASSWORD}")

    lines = json_logs()
    assert len(lines) >= 3
    for line in lines:
        parsed = json.loads(line)
        assert parsed["level"] in {"info", "warning", "error"}
        assert "ts" in parsed
        assert "logger" in parsed
        assert "event" in parsed
    captured = "\n".join(lines)
    for canary in ALL_CANARIES:
        assert canary not in captured


def test_логи_сторонних_библиотек_тоже_маскируются(json_logs: Callable[[], list[str]]) -> None:
    """Записи `logging` (uvicorn, psycopg, httpx) идут через тот же конвейер маскирования."""
    logging.getLogger("uvicorn.error").warning("proxy handshake %s", CANARY_SOCKS_URL)
    logging.getLogger("psycopg.client").error("connection string %s", CANARY_DB_URL)

    captured = "\n".join(json_logs())
    assert captured, "записи сторонних логгеров не дошли до обработчика"
    assert CANARY_SOCKS_URL not in captured
    assert CANARY_DB_URL not in captured
    assert "dbParol1234567890" not in captured
    assert "localParol1234567890" not in captured


def test_значение_поля_с_именем_секрет_не_восстанавливается_косвенно(
    json_logs: Callable[[], list[str]],
) -> None:
    log = get_logger("test.secret_field")
    log.info("db_config", db_url=CANARY_DB_URL, tg_bot_token=CANARY_BOT_TOKEN)
    captured = "\n".join(json_logs())
    assert "***" in captured
    for canary in (CANARY_DB_URL, CANARY_BOT_TOKEN):
        assert canary not in captured
    # Для полей из перечня секретов маска полная: ни начала, ни конца значения.
    assert "dbParol" not in captured
    assert "lmnopqrstu" not in captured
