"""Страница входа и парольный шаг (TZ §8.1, §8.2, §8.3; задача `T-102`, срезы `R3a` и `R3d`).

Граница зафиксирована решением заказчика (ask `c53daa01`): минимальный `/login` входит в `T-102`, а
ввод кода 2FA остаётся за `T-103`. Причина не в удобстве: без живой маршрутизированной точки входа
нечем проверять атрибуты куки (§8.3), `403` без CSRF-токена (§8.8) и объясняющие страницы (§9) —
эти проверки остались бы на тестовом маршруте, которого в репозитории нет, и следующая сессия
смогла бы «соответствовать ТЗ» без единого работающего входа.

Что здесь есть: страница входа и её обработка — проверка пароля Argon2id (`T-101`), блокировка
перебора (§8.1: `ensure_login_allowed` до сравнения пароля, `register_login_failure` после неудачи),
выпуск сессии на шаге `'password'` (`packages/identity/sessions.create_session`) и выдача куки с
атрибутами §8.3, а срезом `R3d` — лимит частоты по адресу (§8.3: 10 запросов/мин/IP) и окно перебора
`ip_ban` с баном адреса (§8.2, `docs/adr/ADR-007`).

Чего здесь сознательно нет:

* `/totp` и перевода на шаг `'full'` — это `T-103`; направление редиректа после успеха держит
  константа `POST_LOGIN_REDIRECT`, и у `T-103` будет одна правка. Области `totp_session`/`totp_ip`
  описаны в `security/rate_limit.py` заранее, чтобы `T-103` подключил их вызовом, а не механизмом;
* резервных кодов (`T-104`);
* проверки `users.state` («какие состояния учётной записи пускаются на вход») — состояния относятся
  к допуска (`T-105`) и ролям (`T-106`), и придумывать это правило здесь значит решить чужую задачу
  молча;
* записей `audit_log` о попытках, блокировках и отказах `429` (§8.7) — имена событий и цепочка
  хэшей относятся к `T-109`, перенос зафиксирован `docs/adr/ADR-009` (ask `c53daa01`); компенсирующие
  контроля на месте: блокировка живёт в `users.locked_until`, бан адреса — в `rate_buckets`, а
  пользователю отказ объясняется сразу (`429` + `Retry-After` + ссылка на `/locked`).

CSRF. У `/login` токена нет, и это не забывчивость: токен выводится из сессии (`ADR-008`), а сессии
до входа не существует. Вместо него включена проверка источника (`ensure_same_origin`) и работает
`SameSite=Lax` как второй слой (§8.3). Альтернатива — «пре-сесссионная» CSRF-кука — добавила бы в
браузер второй материал сессии ради одной страницы; она разобрана в `ADR-009`.

Ответы: успех — `302` на `POST_LOGIN_REDIRECT` и кука; неверные данные — `401` с общей
формулировкой без различия «нет логина»/«неверный пароль»; пустая форма — `400` и, главное, без
изменения счётчика неудач; активная блокировка учётной записи или бан адреса — `429` с `Retry-After`
и объяснением (§9: счётчик попыток не показывается, но блокировка объясняется и ведёт на `/locked`).
Код причины у этих двух отказов разный: `attempts` — закрыта учётная запись, `rate` — закрыт адрес
(`ADR-007`, ask `ba6a9076`), и путать их нельзя: «пароль не тот», «учётку заблокировали» и «адрес
закрыт» — три разных состояния для человека.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.web.forms import form_fields, login_pair
from apps.web.security.csrf import csrf_context, ensure_same_origin
from apps.web.security.rate_limit import (
    LOGIN_IP_SCOPE,
    RateLimitExceeded,
    ban_until,
    enforce_scope,
    register_address_failure,
    retry_after_seconds,
)
from apps.web.security.sessions import (
    LOCK_REASON_ATTEMPTS,
    LOCK_REASON_RATE,
    LOCKED_PATH,
    LOGIN_PATH,
    POST_LOGIN_REDIRECT,
    REASON_QUERY,
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
    login_closed_reason,
    register_login_failure,
    register_login_success,
)

router = APIRouter()

USER_AGENT_HEADER: Final = "User-Agent"

#: Формулировка для неверных данных. Различия «нет такой учётной записи» и «неверный пароль» в
#: ответе нет намеренно: страница входа — публичная, и по ответу нельзя было бы проверять
#: существование учётной записи, что противоречит закрытому допуску (§1.2) и контуру перебора (§8.1).
GENERIC_FAILURE_DETAIL: Final = "Неверный логин или пароль."

#: Пустая форма. Отдельный ответ нужен чтобы не тратить стоимость Argon2id на пустой ввод и не
#: приближать блокировку: пользователь, дважды нажавший «Войти» с пустыми полями, не должен
#: получить блокировку учётной записи, а переборщик — возможности размывать счётчик неудач.
#: Частотный лимит при этом всё равно считается: §8.3 ограничивает запросы, а не неудачи.
EMPTY_FORM_DETAIL: Final = "Нужно указать логин и пароль."


def _lock_detail(until: datetime) -> str:
    """Объяснение блокировки учётной записи (§9): причина и срок, но не число оставшихся попыток."""
    return (
        "Вход заблокирован: слишком много неудачных попыток. "
        f"Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _rate_detail(until: datetime) -> str:
    """Объяснение отказа по адресу (§9): предел частоты либо бан адреса.

    Число попыток не называется намеренно: §9 требует внятного состояния, а подсказка «сколько
    ещё попыток осталось» — это карта для переборщика. Формулировка не утверждает, что блокировка
    наступила именно сейчас: отказ возможен и по пределу запросов в минуту, и по активному бану.
    """
    return (
        "С этого адреса было слишком много попыток входа. "
        f"Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _render_login(
    request: Request,
    detail: str,
    status_code: int,
    locked_reason: str | None = None,
) -> HTMLResponse:
    """Страница входа с объяснением. `csrf_token` пустой — см. модульный докстринг про ADR-008.

    `locked_reason` ставится только на отказе «вход закрыт на время»: страница входа обязана дать
    отдельный адрес состояния (`/locked`, `docs/tz/09-web-ui-and-design.md` §9), а не прятать
    объяснение в коротком абзаце над формой. Для прочих отказов ссылки нет: «пароль не тот» и
    «вход заблокирован» — разные состояния, и показывать ссылку на блокировку при неверном пароле
    значит подставлять пользователю неверный диагноз.
    """
    locked_url = f"{LOCKED_PATH}?{REASON_QUERY}={locked_reason}" if locked_reason else None
    context = {
        "page_title": "Вход",
        "detail": detail,
        "locked_url": locked_url,
    } | csrf_context(None)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "login.html", context, status_code=status_code
    )
    return response


def _denied(
    request: Request, detail: str, until: datetime, reason: str, moment: datetime
) -> HTMLResponse:
    """Отказ «вход закрыт до срока»: `429`, `Retry-After` и ссылка на страницу состояния.

    Код именно `429`, а не `403` и не `200` с текстом (`ADR-007`, ask `ba6a9076`): `Retry-After` —
    часть ответа, и по нему ориентуются и браузер, и интеграционные проверки. Один помощник на три
    ветки (блокировка учётной записи, предел частоты, бан адреса) нужен потому, что различие между
    ними — только в коде причины и тексте: разные способы отдать `Retry-After` разошлись бы при
    правке, а проверка «у отказа есть заголовок» осталась бы на одной ветке.
    """
    response = _render_login(request, detail=detail, status_code=429, locked_reason=reason)
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


@router.get(LOGIN_PATH, response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    """Страница входа. Сессии не требует и репозитория не трогает: форма пустая по смыслу.

    Счётчика частоты на `GET` нет намеренно: §8.3 ограничивает запросы входа (мутации), а
    лимитирование отрисовки формы означало бы отказ человеку, который просто открыл страницу, и
    открыло бы способ расходовать лимит жертве (`ADR-007` — «писать счётчик один раз на запрос и
    не делать этого на статике и `GET` вне лимитируемых путей»).
    """
    return _render_login(request, detail="", status_code=200)


@router.post(LOGIN_PATH, response_class=Response)
async def login_submit(request: Request, store: StoreDep) -> Response:
    """Обработка парольного шага.

    Порядок шагов закреплён за §8.1, §8.2 и §8.3, и он не «как получилось»:

    1. источник запроса (§8.3 «проверка origin») — до всего остального, в том числе до стоимости
       Argon2 и до обращений в базу: запрос с чужого источника не должен тратить ресурсы учётной
       записи и не обязан ничего записывать;
    2. активный бан адреса (§8.2) — проверка чтения: адрес уже закрыт, и заводить новые окна,
       считать Argon2id и трогать учётную запись незачем;
    3. предел частоты по адресу (§8.3: 10 запросов/мин/IP) — тоже до стоимости Argon2id, иначе
       лимит не защищает от того, ради чего его ставят;
    4. пустая форма — отказ без изменения счётчика неудач (частотный счётчик при этом уже
       посчитан: запрос был);
    5. `ensure_login_allowed` **до** сравнения пароля: пока блокировка активна, пароль не
       проверяется вообще, иначе блокировка оставляет канал для проверки угаданных паролей
       (`T-101`);
    6. сравнение пароля; у неизвестного логина всё равно тратится стоимость хэширования
       (`LoginTiming`), чтобы ответ по времени не различал существование учётной записи;
       состояние учётной записи закрывает вход ровно тем же ответом (`login_closed_reason`,
       §1.2, `ADR-020` п. 6): «заблокирована администратором» и «архивирована» неотличимы от
       неверного пароля (§8.8), и неудача при этом считается, потому что доступ не открыт;
    7. неудача: счётчик неудач учётной записи и окно перебора по адресу (`ip_ban`, §8.2). Окно
       адреса считается и при неизвестном логине: §8.2 говорит «3 неудачные попытки с одного IP»,
       а не «по одной учётной записи», иначе переборщик обходил бы окно, меняя логины;
    8. успех: снимается счётчик неудач, выпускается сессия на шаге `'password'`, фиксируется
       транзакция и только потом выдаётся кука — кука не должна пережить незафиксированную запись.

    Значения `ip` и `user_agent` пишутся в запись сессии как получены (с ограничением длины): §8.3
    показывает их в списке устройств, §8.7 требует IP входа в журнале, а уведомление «вход с нового
    IP/устройства» строится на сравнении этих значений. Один и тот же `address` идёт и в запись
    сессии, и в ключи счётчиков: «кого показываем» и «кого блокируем» — обязательно один адрес
    (`docs/adr/ADR-009`, пункт про `X-Forwarded-For`).
    """
    ensure_same_origin(request)
    fields = await form_fields(request)
    login, password = login_pair(fields)
    moment = utc_now()
    address = session_ip(request)

    banned = ban_until(store, address, moment=moment)
    if banned is not None:
        return _denied(request, _rate_detail(banned), banned, LOCK_REASON_RATE, moment)

    try:
        enforce_scope(store, LOGIN_IP_SCOPE, address, moment=moment)
    except RateLimitExceeded as exc:
        return _denied(request, _rate_detail(exc.until), exc.until, LOCK_REASON_RATE, moment)

    # Проверка на пустоту через истинностное значение, а не сравнением с пустой строкой:
    # `login_pair` уже обрезает значения, а сравнение поля с именем `password` с литералом
    # читается статическим анализатором как «жёстко заданный пароль» (B105) и маскирует
    # настоящий смысл проверки — «пользователь ничего не ввёл».
    if not login or not password:
        return _render_login(request, detail=EMPTY_FORM_DETAIL, status_code=400)

    user = store.user_by_login(login)
    if user is None:
        request.app.state.login_timing.burn(password)
        banned = register_address_failure(store, address, moment=moment)
        if banned is not None:
            return _denied(request, _rate_detail(banned), banned, LOCK_REASON_RATE, moment)
        return _render_login(request, detail=GENERIC_FAILURE_DETAIL, status_code=401)

    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _denied(request, _lock_detail(exc.until), exc.until, LOCK_REASON_ATTEMPTS, moment)

    # Состояние записи проверяется тем же отказом, что и неверный пароль: различать
    # «заблокировали» и «пароль не тот» ответом нельзя (§8.8: отказ не должен быть оракулом
    # состояния учётной записи), поэтому отдельной ветки с другим текстом здесь нет вовсе.
    # Неудача считается и когда пароль верный: `register_login_success` сбросил бы счётчик
    # неудач у записи, которой вход запрещён, и оставила бы её живой для следующего перебора.
    closed = login_closed_reason(user)
    if not verify_password(password=password, stored_hash=user.password_hash) or (
        closed is not None
    ):
        locked_until = register_login_failure(user, now=moment)
        store.commit()
        banned = register_address_failure(store, address, moment=moment)
        if locked_until is not None:
            return _denied(
                request, _lock_detail(locked_until), locked_until, LOCK_REASON_ATTEMPTS, moment
            )
        if banned is not None:
            return _denied(request, _rate_detail(banned), banned, LOCK_REASON_RATE, moment)
        return _render_login(request, detail=GENERIC_FAILURE_DETAIL, status_code=401)

    register_login_success(user, now=moment)
    issued = create_session(
        user.id,
        ip=address,
        user_agent=clamp_user_agent(request.headers.get(USER_AGENT_HEADER)),
        auth_step="password",
        now=moment,
    )
    store.add(issued.record)
    store.commit()

    redirect = RedirectResponse(POST_LOGIN_REDIRECT, status_code=302)
    issue_session_cookie(redirect, issued.secret)
    return redirect
