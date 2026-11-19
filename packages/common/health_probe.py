"""Проба эндпоинта состояния: её вызывают healthcheck'и контейнеров и скрипты площадки.

Реализация — стандартная библиотека и `http.client`, чтобы пробе не требовался ни Python-пакет
приложения, ни даже curl в образе. Ошибок не бросает: healthcheck обязан получить код возврата и
короткую деталь.
"""

from __future__ import annotations

import argparse
import http.client
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_S = 5.0
MAX_BODY_CHARS = 400
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def probe(url: str, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> tuple[int, str]:
    """Вернуть пару (код HTTP или -1 при недоступности, деталь).

    Для эндпоинтов состояния любой код, кроме 200, означает «не готово»: `/readyz` отдаёт 503
    именно тогда, когда что-то из проверок не пройдено. Схема адреса проверяется явно: проба
    ходит по локальному адресу, и «случайный» переход в другую схему здесь нежелателен.
    """
    target = urlsplit(url)
    if target.scheme not in _ALLOWED_SCHEMES:
        return -1, f"неподдерживаемая схема адреса: {target.scheme or '(пусто)'}"
    host = target.hostname or "127.0.0.1"
    port = target.port or (443 if target.scheme == "https" else 80)
    path = target.path or "/"
    if target.query:
        path = f"{path}?{target.query}"
    connection_class: type[http.client.HTTPConnection]
    connection_class = (
        http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_class(host, port, timeout=timeout_s)
    try:
        connection.request("GET", path, headers={"host": host, "connection": "close"})
        response = connection.getresponse()
        status = int(response.status)
        body = response.read(MAX_BODY_CHARS * 2).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException) as exc:
        return -1, f"недоступен: {type(exc).__name__}"
    finally:
        connection.close()
    return status, body[:MAX_BODY_CHARS].replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="проверить эндпоинт состояния процесса")
    parser.add_argument("--url", required=True, help="полный адрес /healthz или /readyz")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument(
        "--liveness",
        action="store_true",
        help="считать успехом любой ответ HTTP (для /healthz: процесс жив, но не готов)",
    )
    arguments = parser.parse_args(argv)

    status, detail = probe(arguments.url, timeout_s=arguments.timeout)
    ok = status == 200 or (arguments.liveness and status > 0)
    print(f"{'OK' if ok else 'FAIL'} {arguments.url} status={status} {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
