"""Заголовки безопасности ответа (TZ §8.3; `T-102`, срез `R3c`).

Зачем слой заголовков в приложении, если периметр уже ставит их же в `deploy/caddy/Caddyfile`
(контракт `test_caddyfile_pinned_tls_headers_and_443`):

1. **`web` доступен не только через Caddy.** В составе он слушает `127.0.0.1`, но job
   `compose-smoke` и отладочный прогон внутри сети состава ходят в него напрямую по http. Ответ без
   CSP и `nosniff` «внутри» не отличается от ответа без периметра, а §8.3 требует заголовков у
   ответа приложения, а не у конкретного узла.
2. **Значения не должны разойтись.** Если приложение начнёт отдавать «свою» версию CSP, а Caddy —
   свою, браузер применит оба политика одновременно (несколько `Content-Security-Policy`
   пересекаются), и расхождение проявится на приёмке, а не в тесте. Поэтому значения здесь —
   **те же байты**, что в `Caddyfile`: контрактная проверка
   `tests/contract/test_web_security_contract.py` сверяет константы модуля со строками из
   `Caddyfile`, и правка в одном артефакте обязана потребовать правку в другом.
3. **Отказные ответы — тоже ответы.** `403` CSRF, `413` тела формы, `503` без базы и редирект
   «сессия не подходит» создаются обработчиками исключений, а не маршрутом: заголовки навешивает
   middleware, поэтому ни одна ветка отказа не остаётся без политики.

Чего здесь сознательно нет: `Report-Only`-вариант CSP, `Expect-CT`, `X-XSS-Protection` (устарел и
в ТЗ его нет), `Cross-Origin-*` (консоль одноисточниковая, внешних запросов §8.3 запрещает той же
политикой `connect-src 'self'`). Отдельно: `preload` в HSTS не добавляется — ТЗ требует ровно
`max-age=63072000; includeSubDomains`, а `preload` означает попадание в список браузеров и
невозможность вернуть http когда-либо, то есть это решение заказчика, а не оформителя.

Порядок middleware: постановка заголовков идёт в пользовательском middleware, то есть **внутри**
`ServerErrorMiddleware`. Значит заголовки получает любой ответ, созданный маршрутом или
обработчиком исключений (`ExceptionMiddleware`), но не ответ «необработанная ошибка» (plain-text
`500` от `ServerErrorMiddleware`): там заголовки не помогут, а текст стека наружу не отдаётся по
`docs/tz/08-security-auth-2fa.md` §8.4 (и этот случай проверяется отдельно).
"""

from __future__ import annotations

from typing import Final

from starlette.responses import Response

#: CSP — ровно строка `Caddyfile` (она включает TZ-набор и самохостящиеся `img-src`/`font-src`,
#: плюс явные `frame-src`/`object-src`). Внешних источников нет ни в одном источнике.
CSP_POLICY: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
    "frame-src 'none'; object-src 'none'"
)

#: HSTS §8.3: два года и поддомены, без `preload` (см. модульный докстринг).
HSTS_POLICY: Final = "max-age=63072000; includeSubDomains"

#: §8.3: `same-origin`, а не `no-referrer` — значение берётся из ТЗ как контракт.
REFERRER_POLICY: Final = "same-origin"

#: Запрет на определение типа содержимого «на глаз» браузером.
CONTENT_TYPE_OPTIONS: Final = "nosniff"

#: Дублирующая `frame-ancestors 'none'` защита: старые клиенты понимают `X-Frame-Options`,
#: а §8.3 требует, чтобы консоль нельзя было встроить в чужую страницу (кликджекинг).
FRAME_OPTIONS: Final = "DENY"

#: «Минимум» из §8.3: панель не использует геолокацию, камеру, микрофон и платёжные API.
#: Разрешений нет ни у какого источника — перечислены именно те, о которых спрашивают.
PERMISSIONS_POLICY: Final = "geolocation=(), camera=(), microphone=(), payment=()"

#: Заголовок → значение. Порядок значим только для читаемости: набор полный и закрытый.
SECURITY_HEADERS: Final[dict[str, str]] = {
    "Content-Security-Policy": CSP_POLICY,
    "Strict-Transport-Security": HSTS_POLICY,
    "Referrer-Policy": REFERRER_POLICY,
    "X-Content-Type-Options": CONTENT_TYPE_OPTIONS,
    "X-Frame-Options": FRAME_OPTIONS,
    "Permissions-Policy": PERMISSIONS_POLICY,
}


def apply_security_headers(response: Response) -> Response:
    """Поставить закрытый набор заголовков, не затирая уже выставленные.

    Не затираем: обработчик, которому нужен ответ со своим CSP (например, страница с жёсткой
    политикой для будущего отчёта из §8.3 про файлы отчётов), обязан иметь возможность это сделать.
    Молчаливая подмена сверху вниз как раз и создала бы тот случай, когда «политика в коде есть, а
    в ответе её нет».

    Ответ мутируется на месте и возвращается для удобства вызова: middleware Starlette отдаёт
    объект ответа наружу как есть.
    """
    for name, value in SECURITY_HEADERS.items():
        if name not in response.headers:
            response.headers[name] = value
    return response
