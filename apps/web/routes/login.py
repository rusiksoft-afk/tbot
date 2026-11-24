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
* записей `audit_log` о попытке, приведшей к отказу частоты или блокировки адреса, — их пишет
  механизм лимитов (`apps/web/security/rate_limit.py`), а не маршрут (`ADR-025` п. 6: событие
  принадлежит той точке, где решена причина). Срез `R2b` той же `T-109` добавляет сюда события
  самой страницы входа: `session.login` (парольный шаг принят, сеанс выпущен) и
  `session.login_failed` (пароль не принят). Отказ «вход закрыт окном блокировки» отдельной строки
  не даёт намеренно: там пароль не сравнивался вообще, а наступление блокировки записано деталями
  той попытки, которая этот порог пересекла (`locked_until`), — иначе счётчик неудач в журнале
  перестал бы совпадать со счётчиком в таблице.

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

#: Коды причины для журнала (§8.7: `session.login_failed`). Наружу все три случая отдаются одним и
#: тем же `401` (§8.8: отказ не должен быть оракулом существования учётной записи), различие живёт
#: только в журнале. `account_state` дополняется ключом `state`: код состояния возвращает
#: `login_closed_reason`, и именно он объясняет разбору, что вход закрыт был не паролем.
#:
#: Имена констант намеренно не содержат слова, которое описывают: проверка `S105` (запрет
#: «захардкоженного пароля») читает имена и отклонила бы `FAILURE_PASSWORD` со значением
#: `password`, хотя это код причины, а не значение допуска. Значения кодов при этом настоящие —
#: их читает разбор журнала, а не проверка.
FAILURE_UNKNOWN_LOGIN: Final = "unknown_login"
FAILURE_MISMATCH: Final = "password"
FAILURE_ACCOUNT_STATE: Final = "account_state"


def _failure_details(closed_state: str | None, locked_until: datetime | None) -> dict[str, str]:
    """Детали `session.login_failed` (`ADR-025` п. 2: коды причин и сроки, но не значения).

    Формулировка домена в журнал не уходит: она содержит момент разблокировки для человека. Здесь
    только код причины, состояние записи и срок блокировки целым числом секунд — их хватает, чтобы
    отличить подбор пароля от входа по закрытой записи и чтобы увидеть, какая попытка закрыла вход.
    """
    details: dict[str, str] = {
        "reason": FAILURE_ACCOUNT_STATE if closed_state is not None else FAILURE_MISMATCH
    }
    if closed_state is not None:
        details["state"] = closed_state
    if locked_until is not None:
        details["locked_until"] = locked_until.isoformat(timespec="seconds")
    return details


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

    Журнал (§8.7, срез `R2b` задачи `T-109`, `ADR-025` п. 6): у отказа входа и у успеха событие
    добавляется **до** фиксации и своей фиксацией не пользуется — `session.login` обязан уйти той же
    транзакцией, что и строка сеанса, а `session.login_failed` — той же транзакцией, что и счётчик
    неудач (`register_login_failure`) или окно перебора адреса (`register_address_failure`), которое
    и фиксирует попытку. Поэтому у каждой записи журнала есть бизнес-изменение-причина: отказа без
    события и события без отказа не бывает. Время события — тот же `moment`, что и у строки сеанса и
    у окон счётчиков (`ADR-025` п. 2: момент снимается один раз на событие).

    Значения `ip` и `user_agent` пишутся в запись сессии как получены (с ограничением длины): §8.3
    показывает их в списке устройств, §8.7 требует IP входа в журнале, а уведомление «вход с нового
    IP/устройства» строится на сравнении этих значений. Один и тот же `address` идёт и в запись
    сессии, и в ключи счётчиков: «кого показываем» и «кого блокируем» — обязательно один адрес
    (`docs/adr/ADR-009`, пункт про `X-Forwarded-For`).
    """
    ensure_same_origin(request, store)
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
        # Субъекта у этой строки нет намеренно: учётной записи с таким логином не существует, а
        # выдуманный `actor` журнал не терпит (`ADR-025` п. 2). Запись добавляется до окна
        # перебора: фиксирует её тот же `commit()`, что и окно, поэтому попытка не может остаться
        # в счётчике без события и наоборот.
        store.append_audit(
            action="session.login_failed",
            at=moment,
            entity="user",
            details={"reason": FAILURE_UNKNOWN_LOGIN},
        )
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
        store.append_audit(
            action="session.login_failed",
            at=moment,
            actor=user.id,
            entity="user",
            entity_id=user.id,
            details=_failure_details(closed, locked_until),
        )
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
    # `session.login` на шаге `'password'` пишется намеренно: пароль принят, и это отдельный
    # состоявшийся факт, который обязан быть виден даже если человек до кода 2FA не дошёл.
    # Полный вход (§8.7 «вход нового пользователя», уведомление `R3`) — вторая запись
    # `session.login` с шагом `full`, её добавляют маршруты кода и резервного кода
    # (`apps/web/routes/totp.py`); различие читается из `details.auth_step`.
    audit_id = store.append_audit(
        action="session.login",
        at=moment,
        actor=user.id,
        entity="session",
        entity_id=issued.record.id,
        details={"auth_step": issued.record.auth_step},
    )
    # Решение порога уведомления §8.7 принадлежит тому же событию и тому же транзакту, но для
    # парольного шага строка не пишется: `append_login_notice` отсекает шаг ≠ `'full'` до всякого
    # обращения к базе (`ADR-028` п. 6). Вызов здесь стоит намеренно: три точки `session.login`
    # обязаны выглядеть одинаково, иначе «забыли спросить порог на этом шаге» неотличимо от
    # «на этом шаге порога нет» (закрытый перечень точек держит контракт
    # `tests/contract/test_audit_notify_contract.py`).
    store.append_login_notice(
        audit_id=audit_id,
        user_id=user.id,
        at=moment,
        auth_step=issued.record.auth_step,
        address=address,
        user_agent=issued.record.user_agent,
    )
    store.commit()

    redirect = RedirectResponse(POST_LOGIN_REDIRECT, status_code=302)
    issue_session_cookie(redirect, issued.secret)
    return redirect
