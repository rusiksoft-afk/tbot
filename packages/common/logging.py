"""Структурированное логирование с маскированием секретов (TZ §12.1, docs/tz/08 §8.7).

Гарантии модуля:

* формат записи — JSON с полями `ts` (UTC, ISO-8601), `level`, `logger`, `event`, `trace_id`;
* секретные значения не попадают в вывод ни из логов приложения, ни из логов сторонних библиотек
  (uvicorn, psycopg, httpx) — маскирование применяется и к чужим записям;
* маска сохраняет первые 6 и последние 4 символа, чтобы значение можно было опознать, но нельзя
  было использовать;
* `trace_id` привязывается один раз на запрос/цикл и попадает во все вложенные записи.

Маскирование — последняя линия защиты. Первичная линия: секреты не берутся из YAML, не печатаются
в аргументах команд и не попадают в репозиторий (`docs/runbook/telegram-token.md`).
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Callable, Sequence
from typing import TextIO, cast

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

# Рекурсивный тип «то, что попадает в JSON-выгрузку логов». Используется вместо `Any`, чтобы
# маскирование было полным, а аннотации — проверяемыми (mypy --strict).
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]

# Какие значения считаются секретами. Перечень открыт и дополняется вместе с новыми внешними
# сервисами; тест `test_logging_masking` проверяет каждый шаблон отдельно.
# Токен бота: `<цифры>:<38 символов>`. Граница `\b` не подошла бы: в URL `/bot1234567890:...`
# цифра стоит сразу после буквы, а `\b` между буквой и цифрой не возникает. Поэтому защита от
# «часть более длинного числа» сделана отрицательным просмотром назад.
BOT_TOKEN_RE = re.compile(r"(?<![0-9])\d{8,11}:[A-Za-z0-9_-]{30,64}")
CREDENTIALED_URI_RE = re.compile(
    r"\b(?:ss|vless|trojan|vmess|socks5|socks5h|redis|postgres(?:ql)?|amqp)://[^\s\"'<>]{4,}"
)
# `ключ: значение` / `ключ=значение`. Необязательные кавычки вокруг ключа и значения нужны для
# JSON-выгрузок (`"passphrase": "…"`) и для `password="…"`: без них секрет оставался бы открытым.
KEY_VALUE_RE = re.compile(
    r"(?i)\b(token|passphrase|password|passwd|pass|secret|api_?key|access_?key|refresh_?token|"
    r"authorization|cookie|set-cookie|private_?key)\b"
    r"[\"']?(\s*[=:]\s*)[\"']?(?P<value>[^\s,;}\"']+)"
)
BEARER_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]{3,40}-----.*?-----END [A-Z ]{3,40}-----", re.DOTALL)
COOKIE_RE = re.compile(r"(?i)\b(_?session[_-]?id|csrftoken|jsessionid)\b(\s*[=:]\s*)([^\s,;]+)")

MASKED_MARKER = "***"  # публичный маркер: используется тестами и скриптами
_MASK_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "private_key",
        "kek",
        "dek",
        "db_url",
        "tg_bot_token",
        "tg_socks_password",
        "backup_codes",
        # Имя поля формы резервного кода (`FIELD_BACKUP_CODE` в `routes/totp.py`): значение кода —
        # секрет входа, оно живёт в HTTP-ответе ровно один показ (`ADR-016` п. 2) и обязано
        # маскироваться, если попадёт в запись журнала. Множественное число `backup_codes` рядом
        # держится на случай коллективной передачи пачки — маскируются обе формы имени.
        "backup_code",
        "totp_secret",
    }
)


def mask_secret_value(value: str) -> str:
    """Форма маскировки: первые 6 и последние 4 символа; короткие значения — целиком."""
    stripped = value.strip()
    if len(stripped) <= 12:
        return MASKED_MARKER
    return f"{stripped[:6]}…{stripped[-4:]}"


def _mask_key_value(match: re.Match[str]) -> str:
    value = match.group("value") or ""
    return f"{match.group(1)}{match.group(2)}{mask_secret_value(value)}"


def mask_text(text: str) -> str:
    """Применить все шаблоны маскирования к произвольному тексту."""
    result = PEM_RE.sub(f"-----BEGIN …{MASKED_MARKER}…-----", text)
    result = BOT_TOKEN_RE.sub(lambda m: mask_secret_value(m.group(0)), result)
    result = CREDENTIALED_URI_RE.sub(
        lambda m: f"{m.group(0).split('://', 1)[0]}://{MASKED_MARKER}", result
    )
    result = BEARER_RE.sub(lambda m: f"{m.group(0).split()[0]} {MASKED_MARKER}", result)
    result = KEY_VALUE_RE.sub(_mask_key_value, result)
    return COOKIE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASKED_MARKER}", result)


def _mask_value(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {
            key: (MASKED_MARKER if str(key).lower() in _MASK_KEYS else _mask_value(item))
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_mask_value(item) for item in value]
    return value


def mask_event_dict(event_dict: EventDict) -> EventDict:
    """Замаскировать значения полей и сообщение. Изменяет переданный словарь на месте."""
    for key, value in list(event_dict.items()):
        if key in _MASK_KEYS:
            event_dict[key] = MASKED_MARKER
        else:
            event_dict[key] = _mask_value(value)
    return event_dict


def _mask_processor(_logger: WrappedLogger, _method_name: str, event_dict: EventDict) -> EventDict:
    """Процессор structlog: применяет маскирование к записи до форматирования.

    Он обрабатывает и текст сообщения (ключ `event`), поэтому подстановки `%s` из записей
    сторонних библиотек тоже закрываются: для чужих записей тот же процессор стоит в
    `foreign_pre_chain`, а сообщение в них уже собрано с аргументами.
    """
    return mask_event_dict(event_dict)


def configure_logging(
    level: str = "INFO", *, json_output: bool = True, stream: TextIO | None = None
) -> None:
    """Настроить structlog + stdlib-логирование одним конвейером.

    `foreign_pre_chain` обеспечивает маскирование записей сторонних библиотек, которые пишут
    напрямую через `logging` (uvicorn, psycopg, httpx).

    `stream` задан явно, потому что приёмник логов в проде — не stdout в понятном смысле
    (jsonl в контейнере, ротация на площадке, позже — sidecar-агрегатор). Формат и конвейер
    при этом одни и те же, и тесты проверяют ровно тот же путь, что и процесс.
    """
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts")
    renderer: Processor = (
        structlog.processors.JSONRenderer(ensure_ascii=False)
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            renderer,
        ],
        foreign_pre_chain=[
            _mask_processor,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            timestamper,
        ],
    )
    handler = logging.StreamHandler(sys.stdout if stream is None else stream)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            _mask_processor,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            # Дальше запись уходит в stdlib-логгер, где её форматирует ProcessorFormatter
            # (тот же самый объект, что стоит на обработчике). Это документированный способ
            # провести и собственные записи, и записи сторонних библиотек через один конвейер.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Логгер приложения; вызывается после `configure_logging`."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))


def bind_request_context(trace_id: str, **fields: JsonValue) -> None:
    """Привязать `trace_id` и поля контекста ко всем записям текущего потока/задачи."""
    structlog.contextvars.bind_contextvars(trace_id=trace_id, **fields)


def clear_request_context() -> None:
    structlog.contextvars.unbind_contextvars("trace_id")


def masked_arguments(arguments: Sequence[str]) -> list[str]:
    """Для логов запуска процессов: аргументы с замаскированными секретами."""
    masker: Callable[[str], str] = mask_text
    return [masker(argument) for argument in arguments]
