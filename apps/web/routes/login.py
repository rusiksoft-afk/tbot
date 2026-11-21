"""Страница входа и парольный шаг (TZ §8.1, §8.2, §8.3; задача `T-102`, срез `R3a`).

Граница зафиксирована решением заказчика (ask `c53daa01`): минимальный `/login` входит в `T-102`, а
ввод кода 2FA остаётся за `T-103`. Причина не в удобстве: без живой маршрутизированной точки входа
нечем проверять атрибуты куки (§8.3), `403` без CSRF-токена (§8.8) и объясняющие страницы (§9) —
эти проверки остались бы на тестовом маршруте, которого в репозитории нет, и следующая сессия
смогла бы «соответствовать ТЗ» без единого работающего входа.

Что здесь есть: страница входа и её обработка — проверка пароля Argon2id (`T-101`), блокировка
перебора (§8.1: `ensure_login_allowed` до сравнения пароля, `register_login_failure` после неудачи),
выпуск сессии на шаге `'password'` (`packages/identity/sessions.create_session`) и выдача куки с
атрибутами §8.3.

Чего здесь сознательно нет:

* `/totp` и перевода на шаг `'full'` — это `T-103`; направление редиректа после успеха держит
  константа `POST_LOGIN_REDIRECT`, и у `T-103` будет одна правка;
* резервных кодов (`T-104`);
* проверки `users.state` («какие состояния учётной записи пускаются на вход») — состояния относятся
  к допуска (`T-105`) и ролям (`T-106`), и придумывать это правило здесь значит решить чужую задачу
  молча;
* счётчика частоты запросов и окна перебора `ip_ban` (§8.2/§8.3) — срез `R3d` (`ADR-007`);
* записей `audit_log` о попытках и блокировках (§8.7) — имена событий и цепочка хэшей относятся к
  `T-109`, а планировщик записей с цепочкой перенесён в `R3d` решением `c53daa01`.

CSRF. У `/login` токена нет, и это не забывчивость: токен выводится из сессии (`ADR-008`), а сессии
до входа не существует. Вместо него включена проверка источника (`ensure_same_origin`) и работает
`SameSite=Lax` как второй слой (§8.3). Альтернатива — «пре-сесссионная» CSRF-кука — добавила бы в
браузер второй материал сессии ради одной страницы; она разобрана в `ADR-009`.

Ответы: успех — `302` на `POST_LOGIN_REDIRECT` и кука; неверные данные — `401` с общей
формулировкой без различия «нет логина»/«неверный пароль»; активная блокировка — `429` с
`Retry-After` и объяснением (§9: счётчик попыток не показывается, но блокировка объясняется);
пустая форма — `400` и, главное, без изменения счётчика неудач.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.web.forms import form_fields, login_pair
from apps.web.security.csrf import csrf_context, ensure_same_origin
from apps.web.security.sessions import (
    LOGIN_PATH,
    POST_LOGIN_REDIRECT,
    StoreDep,
    issue_session_cookie,
    session_ip,
)
from apps.web.store import clamp_user_agent
from packages.common.clock import utc_now
from packages.identity.passwords import verify_password
from packages.identity.sessions import create_session
from packages.identity.users import (
    LoginLockedError,
    ensure_login_allowed,
    register_login_failure,
    register_login_success,
)

router = APIRouter()

USER_AGENT_HEADER: Final = "User-Agent"

#: Формулировка для неверных данных. Различия «нет такой учётной записи» и «неверный пароль» в
#: ответе нет намеренно: страница входа — публичная, и по ответу нельзя было бы проверять
#: существование учётной записи, что противоречит закрытому допуску (§1.2) и контуру перебора (§8.1).
GENERIC_FAILURE_DETAIL: Final = "Неверный логин или пароль."

#: Пустая форма. Отдельный ответ нужен, чтобы не тратить стоимость Argon2id на пустой ввод и не
#: приближать блокировку: пользователь, дважды нажавший «Войти» с пустыми полями, не должен
#: получить блокировку учётной записи, а переборщик — возможности размывать счётчик неудач.
EMPTY_FORM_DETAIL: Final = "Нужно указать логин и пароль."


def _lock_detail(until: datetime) -> str:
    """Объяснение блокировки (§9): причина и срок, но не число оставшихся попыток."""
    return (
        "Вход заблокирован: слишком много неудачных попыток. "
        f"Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _retry_after(until: datetime, moment: datetime) -> int:
    """Секунды до разблокировки: не меньше одной, иначе клиент решит, что можно немедленно."""
    seconds = math.ceil((until - moment).total_seconds())
    return max(seconds, 1)


def _render_login(request: Request, detail: str, status_code: int) -> HTMLResponse:
    """Страница входа с объяснением. `csrf_token` пустой — см. модульный докстринг про ADR-008."""
    context = {"page_title": "Вход", "detail": detail} | csrf_context(None)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "login.html", context, status_code=status_code
    )
    return response


@router.get(LOGIN_PATH, response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    """Страница входа. Сессии не требует и репозитория не трогает: форма пустая по смыслу."""
    return _render_login(request, detail="", status_code=200)


@router.post(LOGIN_PATH, response_class=Response)
async def login_submit(request: Request, store: StoreDep) -> Response:
    """Обработка парольного шага.

    Порядок шагов закреплён за §8.1 и §8.2:

    1. источник запроса (§8.3 «проверка origin») — до всего остального, в том числе до стоимости
       Argon2: запрос с чужого источника не должен тратить ресурсы учётной записи;
    2. пустая форма — отказ без изменения счётчика;
    3. `ensure_login_allowed` **до** сравнения пароля: пока блокировка активна, пароль не
       проверяется вообще, иначе блокировка оставляет канал для проверки угаданных паролей
       (`T-101`);
    4. сравнение пароля; у неизвестного логина всё равно тратится стоимость хэширования
       (`LoginTiming`), чтобы ответ по времени не различал существование учётной записи;
    5. успех: снимается счётчик неудач, выпускается сессия на шаге `'password'`, фиксируется
       транзакция и только потом выдаётся кука — кука не должна пережить незафиксированную запись.

    Значения `ip` и `user_agent` пишутся в запись сессии как получены (с ограничением длины): §8.3
    показывает их в списке устройств, §8.7 требует IP входа в журнале, а уведомление «вход с нового
    IP/устройства» строится на сравнении этих значений.
    """
    ensure_same_origin(request)
    fields = await form_fields(request)
    login, password = login_pair(fields)
    moment = utc_now()

    # Проверка на пустоту через истинностное значение, а не сравнением с пустой строкой:
    # `login_pair` уже обрезает значения, а сравнение поля с именем `password` с литералом
    # читается статическим анализатором как «жёстко заданный пароль» (B105) и маскирует
    # настоящий смысл проверки — «пользователь ничего не ввёл».
    if not login or not password:
        return _render_login(request, detail=EMPTY_FORM_DETAIL, status_code=400)

    user = store.user_by_login(login)
    if user is None:
        request.app.state.login_timing.burn(password)
        return _render_login(request, detail=GENERIC_FAILURE_DETAIL, status_code=401)

    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        response = _render_login(request, detail=_lock_detail(exc.until), status_code=429)
        response.headers["Retry-After"] = str(_retry_after(exc.until, moment))
        return response

    if not verify_password(password=password, stored_hash=user.password_hash):
        locked_until = register_login_failure(user, now=moment)
        store.commit()
        if locked_until is not None:
            response = _render_login(request, detail=_lock_detail(locked_until), status_code=429)
            response.headers["Retry-After"] = str(_retry_after(locked_until, moment))
            return response
        return _render_login(request, detail=GENERIC_FAILURE_DETAIL, status_code=401)

    register_login_success(user, now=moment)
    issued = create_session(
        user.id,
        ip=session_ip(request),
        user_agent=clamp_user_agent(request.headers.get(USER_AGENT_HEADER)),
        auth_step="password",
        now=moment,
    )
    store.add(issued.record)
    store.commit()

    redirect = RedirectResponse(POST_LOGIN_REDIRECT, status_code=302)
    issue_session_cookie(redirect, issued.secret)
    return redirect
