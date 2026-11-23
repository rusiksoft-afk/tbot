"""Страница профиля и смены пароля (TZ §9.3 п. 5, `T-102` — остаток среза `R3f`).

Что закрывает этот файл. Матрица §8.8 требует **интеграционную** проверку «смена пароля отзывает
сессии», и до этого среза она не могла существовать: домен `packages/identity/sessions.py`
умеет менять пароль по §8.1+§8.3 (`change_password`: текущая сессия пересоздаётся, остальные
отзываются) с `T-102` первого среза, но вызвать этот домен было некому — маршрута смены пароля в
`apps/web` не было, а страница профиля (§9.3 п. 5 — «/profile/security … смена пароля») относится
к `T-111`. Пока нет вызывающей стороны, проверка «отзыв дошёл до таблицы» остаётся юнит-уровнем:
она подтверждает, что функция умеет, но не подтверждает, что приложение это делает.

Чего здесь сознательно нет.

* «**и** TOTP» из §8.1 в момент самой смены пароля: страницы ввода кода нет до `T-103`, поэтому
  требование держится шагом входа `'full'` — тот, кто знает только пароль, до маршрута не доходит
  (`§8.2`: на шаге `'password'` доступны только страница кода и `/logout`). Формально это слабее
  буквального «показать код ещё раз при смене пароля», и `T-103` обязан это различие закрыть;
* записи `audit_log` о смене пароля и об отзыве каждой сессии (§8.7, события
  `account.password_changed` и `session.revoke`) — остаток `T-109`: реестр имён и протокол
  добавления её срезы `R1` и `R2` уже дали, а вызова здесь нет (перенос зафиксирован `ADR-009`);
* статус 2FA, привязка и резервные коды — `T-103`/`T-104`; привязка Telegram — `T-409`; поля
  профиля из §9.3 п. 4 (имя, роль, e-mail, дата последнего входа) — `T-111`. Страница начинается с
  той половины, для которой домен готов.

Зависимости охраны берутся из `routes/sessions.py` (`ConsoleSession`, `ConsoleMutation`), а не
переписываются: цепочка «CSRF-токен → счётчик частоты → шаг `'full'` → роль»
обязана быть одной и той же для всех мутаций консоли, иначе порядок проверок
начнёт расходиться между маршрутами, а контрактный тест сверяет именно имена
зависимостей у каждого маршрутизатора пакета. Роль в эту цепочку поставил срез `R6`
(`T-106`): раздел «Профиль и безопасность» карта §9.3 держит доступным любой роли, поэтому
уровень — `CONSOLE_TIER`, а не `admin` (`docs/adr/ADR-017` п. 5).

С этого же среза здесь нет отдельной ветки «учётной записи сеанса больше нет» (`404
`account_not_found`): тот же случай отклоняет охрана роли — одним ответом, как и нехватка
прав (`ADR-017` п. 4). Дву точек отказа на одно состояние быть не может, а учётную запись
обработчик теперь получает из `load_account`, где `None` уже превращен в отказ.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.web.forms import form_fields
from apps.web.routes.sessions import ConsoleMutation, ConsoleSession
from apps.web.security.authorization import load_account
from apps.web.security.csrf import csrf_context
from apps.web.security.rate_limit import retry_after_seconds
from apps.web.security.sessions import (
    LOCK_REASON_ATTEMPTS,
    LOCKED_PATH,
    REASON_QUERY,
    SECURITY_PATH,
    SESSION_EXPIRED_PATH,
    SESSIONS_PATH,
    Principal,
    SessionRedirect,
    StoreDep,
    issue_session_cookie,
)
from packages.common.clock import utc_now
from packages.identity.passwords import PasswordPolicyError, verify_password
from packages.identity.sessions import SessionInvalidError, change_password
from packages.identity.users import LoginLockedError, ensure_login_allowed, register_login_failure

router = APIRouter()

#: Адрес страницы — из общего реестра адресов консоли (`security/sessions.py`): на него ссылается
#: ещё и список сеансов. Смена пароля живёт на этом же адресе: `GET` рисует форму, `POST` её
#: исполняет — ровно как `/login` в срезе `R3a`.

#: Имена полей формы. В именах констант нет слова «пароль» по той же причине, что и в
#: `apps/web/forms.py`: S105 смотрит на имя переменной, и константа с именем `*_PASSWORD`
#: со строковым значением читается статическим анализатором как захардкоженный секрет. Значения —
#: то, что отправляет браузер, и они совпадают с `name` в шаблоне `security.html`.
FIELD_CURRENT_PHRASE: Final = "current_password"
FIELD_NEW_PHRASE: Final = "new_password"
FIELD_REPEAT_PHRASE: Final = "repeat_password"

#: Верхняя граница поля с паролем — та же, что у формы входа (`login_pair`): стоимость Argon2id
#: растёт с длиной входа, поэтому «сколько напечатал» не должно превращаться в способ занять
#: процессор. Политика паролей (`packages/identity/passwords.py`) отвечает за минимум §8.1.
MAX_PHRASE_CHARS: Final = 1024

#: Что страница обязана сказать до ввода: последствие смены пароля (§8.1 «после смены все сессии,
#: кроме текущей, отзываются») человек обязан увидеть **до** действия, а не узнавать о нём из
#: исчезнувших входов на других устройствах.
PAGE_NOTE: Final = (
    "Смена пароля завершает все остальные сеансы этой учётной записи. Текущий сеанс продолжится "
    "заново, с новым значением сеансового ключа."
)

EMPTY_FORM_DETAIL: Final = "Нужно заполнить текущий пароль, новый пароль и его повтор."
REPEAT_MISMATCH_DETAIL: Final = "Новый пароль и его повтор не совпадают. Пароль не изменён."
WRONG_CURRENT_DETAIL: Final = "Текущий пароль не подошёл. Пароль не изменён."
POLICY_DETAIL_PREFIX: Final = "Новый пароль не проходит правила: "


def _lock_detail(until: datetime) -> str:
    """Отказ «учётка заблокирована»: причина и срок, но не число оставшихся попыток (§9).

    Формулировка не предлагает «попробовать другой текущий пароль»: при активном блокировочном
    окне пароль не сравнивается вообще (`T-101`), и подсказка про количество попыток была бы
    картой для того, кто перебирает текущие пароли.
    """
    return (
        "Смена пароля недоступна: вход в учётную запись заблокирован после нескольких неверных "
        f"попыток. Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _render(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    status_code: int,
    locked_url: str | None = None,
) -> HTMLResponse:
    """Одна разметка на страницу и на все отказные ветки: форма остаётся на месте.

    Отказ не «страница ошибки»: человеку нужно показать, что именно не прошло (поля не совпали,
    пароль не подошёл, политика не приняла), и при этом не заставлять вводить всё заново вслепую.
    `csrf_token` выводит `ADR-008`; материал сеанса в контекст не попадает.
    """
    context = {
        "page_title": "Профиль и безопасность",
        "note": PAGE_NOTE,
        "detail": detail,
        "locked_url": locked_url,
        "security_url": SECURITY_PATH,
        "sessions_url": SESSIONS_PATH,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "security.html", context, status_code=status_code
    )
    return response


def _denied_locked(
    request: Request, principal: Principal, detail: str, until: datetime, moment: datetime
) -> HTMLResponse:
    """Отказ по блокировке учётной записи: `429` + `Retry-After` + ссылка на `/locked` (`ADR-007`).

    Тот же способ отдать отказ, что и на входе: различие только в тексте. Отдельный код под
    «заблокировано при смене пароля» породил бы два места, где надо не забыть `Retry-After`.
    """
    response = _render(
        request,
        principal,
        detail=detail,
        status_code=429,
        locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={LOCK_REASON_ATTEMPTS}",
    )
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


@router.get(SECURITY_PATH, response_class=HTMLResponse)
def security_page(request: Request, principal: ConsoleSession) -> HTMLResponse:
    """Страница «Профиль и безопасность» (§9.3 п. 5).

    Охрана — шаг `'full'` (§8.2) и любая из трёх ролей (§1.1, §9.3 п. 5 «любая роль»), как у
    списка устройств (`R3e`): смена пароля — действие, завершающее чужие входы, и доступ к
    нему с пароля без кода 2FA означал бы отказ в обслуживании для владельца. Роль здесь
    не различает роли по смыслу, но отвергает значение вне закрытого набора и сеанс
    без строки учётной записи (`ADR-017` п. 2).

    Счётчик частоты на `GET` не тратится на тех же основаниях, что и у списка и подтверждения
    отзыва (§8.3 считает запросы-мутации; лимит на просмотр страницы дал бы способ устроить отказ
    человеку, который обновил страницу).
    """
    return _render(request, principal, detail="", status_code=200)


@router.post(SECURITY_PATH, response_class=Response)
async def change_password_submit(
    request: Request, principal: ConsoleMutation, store: StoreDep
) -> Response:
    """Сменить пароль так, как требуют §8.1 и §8.3.

    Порядок шагов закреплён за §8.1, §8.2, §8.3 и §8.8, и он не «как получилось»:

    1. токен (`require_csrf`), счётчик частоты пользователя, шаг `'full'` и роль — цепочкой
       зависимостей (`ADR-008`, `ADR-007`, §8.2, `ADR-017` п. 3): отказ токена не должен стоить
       обращений в базу и расхода лимита жертвы, а роль проверяется последней — до
       первого чтения объекта маршрута;
    2. пустая форма и несовпадение повтора — отказ до проверки текущего пароля: оба случая ничего
       не меняют и не должны тратить стоимость сравнения Argon2id;
    3. `ensure_login_allowed` **до** сравнения: пока блокировка активна, пароль не проверяется
       вообще (`T-101`) — иначе блокировка оставляла бы канал для проверки угаданных паролей;
    4. сравнение текущего пароля (§8.1 «только с текущим паролем»); неудача двигает счётчик
       неудач учётной записи ровно так же, как вход, — иначе эта форма стала бы не ограниченным
       нигде способом подбирать текущий пароль;
    5. политика нового пароля (§8.1) внутри `change_password` — до записи хэша: отказ политики не
       трогает ни хэш, ни чужие сеансы;
    6. доменный `change_password`: текущая сессия пересоздаётся (§8.3 «после критичных действий»),
       остальные живые сеансы этой учётной записи отзываются (§8.1). Тот же вызов, что и для
       страницы отзыва: двух веток записи «отзыв» в приложении быть не может;
    7. `commit()` — и только потом новое значение куки: кука не должна пережить незафиксированную
       запись, а прежнее значение обязано перестать быть живым сразу после смены (§8.3).

    Значения `ip` и `user_agent` новой записи домен наследует от прежней сессии (`rotate_session`
    держит `ip=session.ip`): список устройств (§8.3, §9.3 п. 4) показывает устройство входа,
    а не «устройство последнего изменения пароля».

    Запись `audit_log` о событии `account.password_changed` и об отзыве каждого сеанса (§8.7)
    здесь не пишется: это остаток `T-109` — реестр имён и протокол добавления сделаны её срезами
    `R1` и `R2`, а вызова в маршруте нет (перенос зафиксирован `ADR-009`).
    """
    fields = await form_fields(request)
    current = fields.get(FIELD_CURRENT_PHRASE, "")[:MAX_PHRASE_CHARS]
    new = fields.get(FIELD_NEW_PHRASE, "")[:MAX_PHRASE_CHARS]
    repeat = fields.get(FIELD_REPEAT_PHRASE, "")[:MAX_PHRASE_CHARS]
    moment = utc_now()

    if not current or not new or not repeat:
        return _render(request, principal, detail=EMPTY_FORM_DETAIL, status_code=400)
    if new != repeat:
        return _render(request, principal, detail=REPEAT_MISMATCH_DETAIL, status_code=400)

    user = load_account(store, principal)

    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _denied_locked(request, principal, _lock_detail(exc.until), exc.until, moment)

    if not verify_password(password=current, stored_hash=user.password_hash):
        locked_until = register_login_failure(user, now=moment)
        store.commit()
        if locked_until is not None:
            return _denied_locked(
                request, principal, _lock_detail(locked_until), locked_until, moment
            )
        return _render(request, principal, detail=WRONG_CURRENT_DETAIL, status_code=401)

    candidates = store.user_sessions(user.id, not_expired_before=moment)
    try:
        outcome = change_password(
            user, new, current=principal.session, others=candidates, now=moment
        )
    except PasswordPolicyError as exc:
        return _render(request, principal, detail=f"{POLICY_DETAIL_PREFIX}{exc}", status_code=400)
    except SessionInvalidError as exc:
        # Сеанс перестал быть живым между охраной маршрута и самой сменой (отзыв другим входом,
        # граница idle): это известная причина, и пользователь обязан увидеть страницу состояния,
        # а не отказ без объяснения (§9). Пароль при этом не изменён: домен меняет его последним.
        raise SessionRedirect(SESSION_EXPIRED_PATH, reason=exc.code) from exc

    issued = outcome.issued
    if issued is None:
        # Инвариант, а не ветка поведения: `current` передан домену, значит `change_password`
        # обязан пересоздать сеанс (§8.3). `None` означает, что домен перестал пересоздавать
        # сеанс после критичного действия — оставить браузеру прежнее значение куки нельзя
        # (§8.3: после смены пароля ключ сеанса обязан быть новым), поэтому ответ — отказ процесса,
        # а не «пользовательская» страница состояния: пользователю при таком коде говорить нечего.
        raise RuntimeError(
            "смена пароля без пересоздания сеанса: домен обязан вернуть новую запись (§8.3)"
        )
    store.add(issued.record)
    store.commit()

    redirect = RedirectResponse(SESSIONS_PATH, status_code=302)
    issue_session_cookie(redirect, issued.secret)
    return redirect
