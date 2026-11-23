"""Выход, страница состояния сессии, список устройств и отзыв (TZ §8.3, §9; `T-102`, срезы `R3a`…`R3e`).

Границы файла:

* `/logout` — мутация: охраняется `require_csrf` (матрица §8.8: «без токена → 403»), а живость
  сессии проверяется внутри него. §8.2 разрешает выход на шаге `'password'`: пользователь, который
  ввёл пароль, но не прошёл код, обязан иметь возможность выйти;
* `/session-expired` — объясняющая страница (§9). Она не охраняется сессией: показывать её нужно
    ровно тогда, когда живой сессии нет, и охрана страницы состояния редиректом на саму себя
    дала бы петлю;
* `/profile/sessions` (срез `R3e`) — список живых сессий учётной записи, `/profile/sessions/{id}/revoke`
    и `/profile/sessions/revoke-all` — подтверждение и сам отзыв (§8.3 «сессии видны пользователю,
    список устройств, отзыв по одной/всех»).

Что решил срез `R3e` (в ТЗ этих решений нет, они оформлены `docs/adr/ADR-010-session-list-and-revocation.md`):

* **адрес — подпуть профиля, а не корневой `/sessions`** (карта §9.3 п. 4 держит список сессий
  внутри `/profile`, а подпуть `/profile/security` уже стоит в карте п. 5); страница появляется
  сейчас, не подменяя будущую страницу профиля целиком;
* **список охраняется шагом `'full'`, и отзывы — тоже** (§8.2). Ошибка была бы двоякая: пустить
  шаг `'password'` — значит дать тому, кто знает только пароль, способ выгнать все живые входы
  владельца (отказ в обслуживании), а не пустить — лишить страницу смысла;
* **«отозвать все» включает текущую сессию.** «Все», которое экономит одну строку, пока украденный
  вход мог остаться живым, — не «все». Пользователь уходит со всех устройств, в том числе с этого,
  и попадает на `/session-expired?reason=revoked` (объяснение, а не форма входа: он просил отозвать
  все сеансы, а не выйти из одного);
* **подтверждение — серверная страница, а не JS-модалка.** §9.1 требует подтверждения с указанием
  объекта; `script-src 'self'` без `'unsafe-inline'` запрещает инлайновый скрипт, а слоя статики
  (`web/static/*`, §9.2) в репозитории ещё нет. `GET` подтверждения ничего не меняет — отзыв
  делает только `POST`;
* **чужой, кривой и уже завершившийся `id` отвечают одним и тем же `404`** (§8.8: «чужие данные →
    403/404 без утечки»). Различие «есть, но не твоё» и «уже завершилось» ответом не выдаётся.



Срез `R6` (`T-106`) добавляет в цепочку профиля проверку роли: раздел «Профиль и безопасность»
карта §9.3 держит как доступный **любой роли**, поэтому уровень допуска — `CONSOLE_TIER`, а не
`admin`. Меняется не направление отказа (редиректы §8.2 остаются), а его источник: роль решает
зависимость маршрута, а не разметка страницы (`REQ-identity-01`). Основание и перечень того, что
ролями не решается, — `docs/adr/ADR-017`.

Почему страница объясняет причину кодом из закрытого набора: §9 требует внятных состояний, а набор
причин замкнут (`packages/identity/sessions.SESSION_REASON_CODES` плюс `unknown` уровня HTTP).
Текст из параметра запроса на страницу не попадает никогда — иначе страница состояния стала бы
каналом для чужого текста, а проверка «XSS в полях не исполняется» (§8.8) начинала бы ломаться об
собственный шаблон.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from apps.web.security.authorization import (
    enforce_role,
    require_console_role,
)
from apps.web.security.csrf import csrf_context, require_csrf
from apps.web.security.rate_limit import MUTATION_USER_SCOPE, enforce_scope
from apps.web.security.sessions import (
    LOCK_REASON_ATTEMPTS,
    LOCK_REASON_RATE,
    LOCKED_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    REASON_QUERY,
    SECURITY_PATH,
    SESSION_EXPIRED_PATH,
    SESSION_REVOKE_PATH,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    UNKNOWN_SESSION_REASON,
    Principal,
    SessionRedirect,
    StoreDep,
    clear_session_cookie,
    display_reason_codes,
    require_full_session,
)
from apps.web.store import Store
from packages.common.clock import to_msk, utc_now
from packages.identity.authorization import (
    CONSOLE_TIER,
    owner_matches,
)
from packages.identity.sessions import (
    SessionDescriptor,
    SessionRevokedError,
    SessionStepError,
    describe_session,
    describe_sessions,
    ensure_full_auth,
    revoke_session,
    revoke_sessions,
)
from packages.storage.models import UserSession

router = APIRouter()

#: Зависимость «живая сессия + обязательный CSRF-токен» (матрица §8.8: мутация без токена → `403`).
CsrfPrincipal = Annotated[Principal, Depends(require_csrf)]


def require_mutation_rate_limit(principal: CsrfPrincipal, store: StoreDep) -> Principal:
    """Мутация пользователя учтена счётчиком частоты (§8.3: 60 запросов/мин/пользователь).

    Ключ — `id` пользователя, а не сессии и не адреса: §8.3 держит предел «на пользователя»,
    и тогда перебор одного пользователя с нескольких сессий лимит не размывает, а несколько
    пользователей за провайдерским NAT не мешают друг другу (`ADR-007`).

    Порядок обязан быть «сначала токен, потом счётчик»: отказ CSRF не должен стоить обращений в
    базу и двигать счётчик (`ADR-008`), иначе подделка запроса ещё и расходует лимит жертвы.
    Проверка покрытия — контрактная: каждая мутация либо зависит от этой зависимости, либо
    поименована с обоснованием, как и в матрице CSRF.
    """
    enforce_scope(store, MUTATION_USER_SCOPE, str(principal.session.user_id))
    return principal


#: Мутация «живая сессия + токен + счётчик частоты».
RateLimitedMutation = Annotated[Principal, Depends(require_mutation_rate_limit)]

#: Маршрут требует полного входа (§8.2: `'password'` даёт доступ только к странице кода и к `/logout`).
FullSession = Annotated[Principal, Depends(require_full_session)]


def require_full_mutation(principal: RateLimitedMutation) -> Principal:
    """Мутация полного входа: токен (§8.8), счётчик частоты (§8.3) и шаг `'full'` (§8.2).

    Порядок закреплён за §8.2 и §8.3 и он не «как получилось»: шаг проверяется **после** токена и
    счётчика, потому что порядок задаёт цепочка зависимостей (`require_csrf` →
    `require_mutation_rate_limit` → здесь). Следствие осознанное: попытка мутации с шага
    `'password'` тоже стоит обращения счётчику, и это верно — §8.3 считает запросы пользователя, а
    не удачные запросы.

    Зачем нужна именно отдельная зависимость, а не `require_full_session` рядом с
    `RateLimitedMutation`: иначе сессия проверялась бы дважды (два обращения в базу на один запрос),
    и два обращения могли бы увидеть разные состояния сессии.

    Смысл правила: тот, кто знает только пароль (без кода 2FA), не получает возможность отзывать чужие
    входы — иначе §8.2 («на шаге `'password'` доступны только страница кода и `/logout`») стал бы
    способом устроить владельцу отказ в обслуживании.
    """
    try:
        ensure_full_auth(principal.session, now=utc_now())
    except SessionStepError as exc:
        raise SessionRedirect(LOGIN_PATH) from exc
    return principal


#: Мутация списка устройств: токен + счётчик + полный вход.
FullMutation = Annotated[Principal, Depends(require_full_mutation)]


def require_console_role_mutation(principal: FullMutation, store: StoreDep) -> Principal:
    """Мутация раздела «Профиль и безопасность»: цепочка `FullMutation` + роль (§1.1, §9.3 п. 4–5).

    Роль ставится последним шагом — сразу после шага `'full'` и перед любым чтением объектов
    (`ADR-017` п. 3): отказ, вынесенный до поиска, не может сказать, существует ли объект. Отдельная
    зависимость, а не `require_console_role` рядом с `FullMutation`: иначе живой сеанс проверялся бы
    дважды (CSRF-цепочка и охрана роли), а два обращения к строке сеанса могли бы увидеть разное
    состояние — отзыв другим входом между ними.
    """
    enforce_role(store, principal, required=CONSOLE_TIER)
    return principal


#: Мутация профиля: токен + счётчик + полный вход + любая из трёх ролей.
ConsoleMutation = Annotated[Principal, Depends(require_console_role_mutation)]

#: GET профиля и списка устройств: полный вход + любая из трёх ролей (§9.3 п. 4–5 «любая роль».
ConsoleSession = Annotated[Principal, Depends(require_console_role)]

#: Объяснения по закрытому набору причин. Формулировки адресованы человеку (TZ §9: состояния должны
#: быть внятными), а не оператору: коды и числовые границы в текст не выносятся — страница,
#: объясняющая, какой именно срок истёк, подсказывает, что именно подбирать.
EXPLANATIONS: Final[dict[str, str]] = {
    "revoked": "Этот сеанс отозван. Если вы его не отзывали, смените пароль и посмотрите список "
    "устройств.",
    "idle": "Вы долго не действовали, и сеанс завершился. Войдите заново — стратегии и отчёты на "
    "месте.",
    "absolute": "С момента входа прошло двенадцать часов: сеанс завершается независимо от того, "
    "насколько активно вы работали.",
    "not_yet": "Сеанс выпущен отметкой времени из будущего — так обычно расходятся часы приложения "
    "и базы данных. Вход нужно повторить, а расхождение часов показать администратору.",
    UNKNOWN_SESSION_REASON: "Сеанс больше не найден: возможно, запись удалена по сроку хранения, "
    "или вход был совершён с другого устройства.",
}

#: Что показать, если причины нет в закрытом наборе: прямой заход на страницу, параметр не из
#: редиректа, или код, который появится позже.
GENERIC_EXPLANATION: Final = "Сеанс завершён. Войдите заново, чтобы продолжить работу."

#: Объяснения заблокированного входа (`docs/tz/09-web-ui-and-design.md` §9: `/locked`).
#: Набор закрыт и не совпадает с набором причин сеанса: блокировка входа и завершение сеанса —
#: разные состояния, и путать их в тексте нельзя (у первого нет «войти заново» прямо сейчас).
#: Код `rate` ставит срез `R3d` (`docs/adr/ADR-007`): предел частоты по адресу и бан окна
#: перебора §8.2. Он был включён сюда заранее, потому что страница обязана объяснять причину,
#: а не отказывать в объяснении.
LOCK_EXPLANATIONS: Final[dict[str, str]] = {
    LOCK_REASON_ATTEMPTS: "Вход в эту учётную запись временно заблокирован после нескольких неверных "
    "попыток ввести пароль. Блокировка снимается сама — попробуйте позже, менять ничего не нужно.",
    LOCK_REASON_RATE: "С этого адреса было слишком много попыток входа за короткое время. Предел держится "
    "на адресе, а не на учётной записи: повторите позже.",
}

#: Общее объяснение для прямого захода на страницу или для кода, которого в наборе ещё нет.
GENERIC_LOCK_EXPLANATION: Final = (
    "Вход временно заблокирован. Если вы не пытались войти и блокировки не ожидали, "
    "сообщите администратору."
)


@router.get(SESSION_EXPIRED_PATH, response_class=HTMLResponse)
def session_expired(
    request: Request, reason: Annotated[str | None, Query(alias=REASON_QUERY)] = None
) -> HTMLResponse:
    """Страница «сеанс завершён» с объяснением причины (§9).

    Имя параметра обязано совпадать с `REASON_QUERY`, которым его подставляет редирект: контрактная
    проверка сверяет оба, иначе страница начала бы игнорировать причину молча.

    Значение вне закрытого набора не подставляется в текст: показывается общий абзац.
    """
    explanation = EXPLANATIONS[reason] if reason in display_reason_codes() else GENERIC_EXPLANATION
    # `csrf_token` в контексте обязателен: база-шаблон несёт `<meta name="csrf-token">`, а окружение
    # рендеринга — `StrictUndefined` (§8.8), поэтому отсутствующая переменная упала бы ошибкой
    # рендеринга, а не пустым значением. Здесь живой сессии нет — значение пустое (`ADR-009`).
    context = {"page_title": "Сеанс завершён", "explanation": explanation} | csrf_context(None)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "session_expired.html", context
    )
    return response


@router.get(LOCKED_PATH, response_class=HTMLResponse)
def login_locked(
    request: Request, reason: Annotated[str | None, Query(alias=REASON_QUERY)] = None
) -> HTMLResponse:
    """Страница «вход заблокирован» (`docs/tz/09-web-ui-and-design.md` §9).

    Существование страницы — не косметика: объяснение блокировки в ответе `429` короткое, а
    человеку нужен отдельный адрес, куда он может вернуться и где состояние описано спокойно
    (§9: состояния внятные). Отдельный адрес нужен и для ссылки из письма-уведомления (`T-117`).

    Страница не охраняется сессией по той же причине, что и `/session-expired`: она показывается,
    когда живой сессии нет, а охрана привела бы к петле редиректов. Причина берётся из закрытого
    набора `LOCK_EXPLANATIONS`; значение параметра в текст не подставляется никогда.
    """
    explanation = LOCK_EXPLANATIONS.get(reason or "", GENERIC_LOCK_EXPLANATION)
    context = {"page_title": "Вход заблокирован", "explanation": explanation} | csrf_context(None)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "locked.html", context
    )
    return response


@router.post(LOGOUT_PATH, response_class=Response)
def logout(
    principal: RateLimitedMutation,
    store: StoreDep,
) -> Response:
    """Выйти: отозвать текущую сессию и стереть куку (§8.3).

    Это единственный охраняемый маршрут без проверки роли, и он поименован в перечне
    `_ROLE_EXEMPT` контрактной проверки (`ADR-017` п. 6). Основание: выход ничего не даёт
    посетителю и ровно убирает доступ, поэтому требовать роль для «выйти» значило бы оставить
    живой вход у того, кто просит его закрыть — при роли вне закрытого набора (§1.1) или при
    удалённой строке учётной записи отказ в выходе был бы наказанием за испорченные данные.
    Охрана остаётся полной: токен (§8.8), счётчик пользователя (§8.3) и живость сеанса.

    Отзыв — это запись в базу (`revoked_at`), а не только удаление куки: §8.3 требует немедленной
    видимости отзыва, и запрос с сохранённой копией куки обязан быть отклонён. Порядок «сначала
    отозвали и зафиксировали, потом стёрли куку» принципиален: обратный порядок оставил бы живую
    сессию для того, кто куку уже отправил.

    Повторный выход (сессия уже отозвана) ничего не меняет: `revoke_session` возвращает `False` и
    момент первого отзыва не перетирается — по нему разбирают инцидент (`T-109`).

    Запись `audit_log` о выходе пишется здесь же (§8.7, `session.logout`, срез `R2b` `T-109`):
    событие принадлежит этому маршруту, потому что здесь решён факт «человек закрыл свой вход»;
    в той же транзакции, что и `revoked_at` (свойством `commit_now` такой факт не фиксируется).
    """
    moment = utc_now()
    revoke_session(principal.session, now=moment)
    store.append_audit(
        action="session.logout",
        at=moment,
        actor=principal.session.user_id,
        entity="session",
        entity_id=principal.session.id,
        details={"auth_step": principal.session.auth_step},
    )
    store.commit()
    response = RedirectResponse(LOGIN_PATH, status_code=302)
    clear_session_cookie(response)
    return response


# ─── список устройств и отзыв (§8.3, карта страниц §9.3 п. 4; срез `R3e`) ────────────────────

#: Пояснение над списком. Граница честности: страница не обещает «историю входов» — журнал аудита
#: (§8.7) делает `T-109`, и обещать в UI то, чего в консоли ещё нет, нельзя.
SESSIONS_NOTE: Final = (
    "Здесь показаны живые сеансы этой учётной записи: тот, с которого вы смотрите, и остальные "
    "устройства. Завершённые по сроку и уже отозванные не перечисляются — отозвать их нечем."
)

#: Подпись над перечнем на странице подтверждения «отзыв всех». Отличается от подписи списка:
#: здесь перечень обязывает — показаны ровно те объекты, которые уйдут, включая скрытые в списке.
REVOKE_ALL_NOTE: Final = (
    "Ниже перечислены сеансы, которые будут отозваны этим подтверждением. В список «Сеансы» "
    "попадает меньше: строку, которую система уже считает завершившейся, там не видно, но отзыв "
    "снимет и её."
)

#: Для сессии без `user_agent`: значение присылает браузер, и его может не быть (`curl`, ссылка
#: включения Telegram из `T-117`). Пустая ячейка читается как «строка потерялась в шаблоне».
UNKNOWN_DEVICE_LABEL: Final = "устройство не определено"

#: Для сессии без адреса: `sessions.ip` заполняется из `X-Forwarded-For`, а обращения к `web`
#: внутри сети состава идут без заголовка (`ADR-009`), и приложение адрес не выдумывает.
UNKNOWN_ADDRESS_LABEL: Final = "адрес не определён"

#: Пометка своей сессии: без неё список неотличим от перечня чужих входов, а §8.3 требует, чтобы
#: пользователь видел, где он сейчас и находится.
CURRENT_SESSION_LABEL: Final = "текущий сеанс"

#: Что подтверждается на странице отзыва. Текст обязан называть объект (§9.1: «модальное
#: подтверждение с указанием объекта») и обязан называть последствие для того, кто подтверждает.
REVOKE_OTHER_WARNING: Final = (
    "Сеанс будет отозван немедленно: с перечисленного устройства вход придётся выполнять заново. "
    "Отменить отзыв задним числом нельзя."
)
REVOKE_CURRENT_WARNING: Final = (
    "Это тот же сеанс, с которого вы подтверждаете отзыв. Страница откроется уже без входа, и "
    "вход придётся выполнить заново — на этом устройстве тоже."
)
REVOKE_ALL_WARNING: Final = (
    "Будут отозваны все живые сеансы учётной записи, включая текущий: вход потеряют все "
    "устройства, в том числе то, с которого вы подтверждаете. Отменить задним числом нельзя."
)

#: Один ответ на «такого `id` нет», `id` чужой, `id` кривой и «сеанс уже завершился» (§8.8:
#: «чужие данные → 403/404 без утечки»). Различие этих случаев ответом не выдаётся намеренно:
#: иначе страница отзыва стала бы способом проверять, чьи идентификаторы существуют.
GONE_DETAIL: Final = "живого сеанса с таким идентификатором нет"


@dataclass(frozen=True)
class SessionRow:
    """Строка списка в том виде, как её печатает шаблон: готовые подписи, без логики в разметке.

    Значения полей уже строки, а не объекты: шаблон не должен ни форматовать даты, ни разбирать
    колонку `INET` (§8.3: вывод — автоэкранирование, а не конкатенация; `docs/adr/ADR-009` про
    чтение `INET`). Материала сессии — значения куки и `token_hash` — здесь нет и быть не может:
    страница печатает устройство и сроки, а не билет.
    """

    device: str
    address: str
    started: str
    last_seen: str
    expires_at: str
    is_current: bool
    revoke_url: str


#: Подпись вместо времени в колонке «Последняя активность». Значение формулирует причину пустоты,
#: а не ставит прочерк: человек, видящий «отозван в 07:56:40» и «последняя активность — не
#: сохранилась», понимает, что второе время просто совпало бы с первым (замер §7.3 приёмки
#: `docs/acceptance/prod-accept-t106-auth-half.md`), а не что сеансом не пользовались вовсе.
LAST_ACTIVITY_UNRECORDED: Final = "не сохранилась (отметка перезаписана отзывом)"


def _human_moment(moment: datetime) -> str:
    """Мгновение для человека: `ДД.ММ.ГГГГ ЧЧ:ММ` и подпись часового пояса (§9.1).

    Подпись обязательна: `docs/HANDOFF.md` фиксирует, что часы площадки — UTC, а §9.1 требует
    времени по Москве с явной подписью. Момент, показанный без подписи, читается как местный и
    расходится с журналом, который ведёт площадка.
    """
    return f"{to_msk(moment):%d.%m.%Y %H:%M} МСК"


def _to_row(descriptor: SessionDescriptor) -> SessionRow:
    """Описание сессии из доменного слоя → строка списка.

    `user_agent` печатается как обычная строка: значение контролирует клиент (и оно обрезано до
    `USER_AGENT_MAX_LEN` в `apps/web/store.py`), экранирование включено, `|safe` запрещён — проверка
    «XSS в полях не исполняется» (§8.8) держит и это поле.

    Адрес берётся из `str(...)`: живой PostgreSQL читает колонку `INET` объектом `ipaddress`
    (`ADR-009`), а наружу обязан уходить канонический текст — ровно та форма, которая является
    значением колонки и ключом счётчика лимитов.

    Колонка активности читает `last_activity_at`, а не `last_seen_at`: у отозванной строки вторая
    колонка — момент отзыва, а не момент последней работы (`ADR-025`, «что из этого следует»;
    замер §7.3 приёмки). Модель не правится, правится только вывод — решение заказчика от
    2026-11-23 (ask `81d7a432`).
    """
    return SessionRow(
        device=descriptor.user_agent or UNKNOWN_DEVICE_LABEL,
        address=str(descriptor.ip) if descriptor.ip is not None else UNKNOWN_ADDRESS_LABEL,
        started=_human_moment(descriptor.created_at),
        last_seen=(
            _human_moment(descriptor.last_activity_at)
            if descriptor.last_activity_at is not None
            else LAST_ACTIVITY_UNRECORDED
        ),
        expires_at=_human_moment(descriptor.expires_at),
        is_current=descriptor.is_current,
        revoke_url=f"{SESSIONS_PATH}/{descriptor.id}/revoke",
    )


def _live_rows(
    store: Store, principal: Principal, moment: datetime
) -> tuple[SessionDescriptor, ...]:
    """Живые сессии пользователя: кандидатов берёт запрос, живость решает домен.

    Разделение обязано быть именно таким: репозиторий отсекает строки, которые заведомо не могут
    быть живыми (отозванные и с просрочком в прошлом), а `describe_sessions(only_active=True)`
    применяет правила §8.3 — отзыв, idle, абсолютный срок и «сессия из будущего». Если оставить
    только доменную половину, страница читала бы все строки пользователя когда-либо; если оставить
    только запрос — страница показывала бы сеансы, которые отозваны, но ещё не успели устареть.
    """
    return describe_sessions(
        store.user_sessions(principal.session.user_id, not_expired_before=moment),
        current_id=principal.session.id,
        now=moment,
        only_active=True,
    )


def _revocation_rows(
    store: Store, principal: Principal, moment: datetime
) -> tuple[SessionDescriptor, ...]:
    """Объекты отзыва: тот же запрос, что у списка, но без доменной фильтрации по живости.

    Разница с `_live_rows` ровно та, которую держит `ADR-010`: набор, который будет отозван, шире
    списка. В него входят строки, которые домен признал завершившимися (например, `expires_at` в
    будущем из-за сдвига часов на выпустившем устройстве), но которые запрос ещё считает
    пригодными для отзыва. Обратная ошибка опаснее: пропущенная строка означала бы «я отозвал все
    устройства», под которой осталась живая сессия.

    Поэтому страница подтверждения перечисляет именно этот набор, а не отображаемый список: §9.1
    требует подтверждения с указанием объекта, и «показали одно, а отозвали другое» этому
    требованию не отвечает.
    """
    return describe_sessions(
        store.user_sessions(principal.session.user_id, not_expired_before=moment),
        current_id=principal.session.id,
        now=moment,
        only_active=False,
    )


def _render_sessions(
    request: Request,
    principal: Principal,
    rows: tuple[SessionDescriptor, ...],
    *,
    confirm_all: bool,
    note: str,
) -> HTMLResponse:
    """Одна разметка на список и на подтверждение «отозвать все».

    Второй таблицы в репозитории не будет: список и подтверждение отличаются предупреждением,
    наличием формы `POST` и подписью над перечнем. Перечень на подтверждении выводит тот же метод
    строк, что и список: иначе страница подтверждения рисовала бы «свой» набор, и показанное
    перестало бы совпадать с отзываемым (§9.1).
    """
    context = {
        "page_title": "Отзыв всех сеансов" if confirm_all else "Сеансы",
        "note": note,
        "rows": [_to_row(row) for row in rows],
        "current_label": CURRENT_SESSION_LABEL,
        "sessions_url": SESSIONS_PATH,
        "revoke_all_url": SESSIONS_REVOKE_ALL_PATH,
        "security_url": SECURITY_PATH,
        "confirm_all": confirm_all,
        "warning": REVOKE_ALL_WARNING if confirm_all else "",
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "sessions.html", context
    )
    return response


@router.get(SESSIONS_PATH, response_class=HTMLResponse)
def sessions_page(request: Request, principal: ConsoleSession, store: StoreDep) -> HTMLResponse:
    """Список сессий пользователя (§8.3: «сессии видны пользователю»).

    `GET` счётчика частоты не имеет: §8.3 ограничивает мутации, а лимит на просмотр страницы дал бы
    способ устроить отказ человеку, который просто открыл страницу (`ADR-007`, та же логика, что у
    `GET /login`).

    Пустого состояния здесь не бывает по построению: список охраняется живой сессией, а она сама
    входит в перечень. Просить шаблон «объяснить пустоту» значило бы держать ветку, в которую нет
    пути.
    """
    moment = utc_now()
    return _render_sessions(
        request,
        principal,
        _live_rows(store, principal, moment),
        confirm_all=False,
        note=SESSIONS_NOTE,
    )


@router.get(SESSIONS_REVOKE_ALL_PATH, response_class=HTMLResponse)
def revoke_all_confirm(
    request: Request, principal: ConsoleSession, store: StoreDep
) -> HTMLResponse:
    """Подтверждение «отозвать все»: показывает, что именно будет отозвано (§9.1).

    Метод `GET` ничего не меняет. Это не формальность: ссылка подтверждения может быть открыта
    повторно, по истории браузера или ботом, и безопасный метод обязан уметь открывать страницу
    отзыва без последствия. Отзыв делает `POST` с CSRF-токеном.

    Перечисляется набор отзыва (`_revocation_rows`), а не отображаемый список: показанное обязано
    совпадать с отзываемым, включая строки, которые страница «Сеансы» скрывает как завершившиеся
    (`ADR-010`).
    """
    moment = utc_now()
    return _render_sessions(
        request,
        principal,
        _revocation_rows(store, principal, moment),
        confirm_all=True,
        note=REVOKE_ALL_NOTE,
    )


def _owned_live_session(store: Store, principal: Principal, raw_id: str) -> UserSession | None:
    """Найти отзываемую сессию так, чтобы чужая строка не нашлась никогда.

    Разбор `id` — ручной, а не через тип параметра маршрута: FastAPI на неразбираемом значении
    отвечает `422` с перечнем полей, и тогда «ввели мусор в адрес» отличался бы от «сессии нет»,
    а страница отзыва начала бы рассказывать про внутренности схемы параметров. Нужен один ответ на
    все четыре случая (§8.8).

    Владение проверяется двумя контурами, и оба обязаны отвечать одинаково (`ADR-017` п. 4):
    основной — предикат `user_id` внутри самого `SELECT` (`SqlStore.session_of_user`), он чужую
    строку не найдёт; второй — `owner_matches` уже по найденной строке, на случай если предикат
    репозитория когда-нибудь потеряется. Второй контур не имеет права ответить иначе, чем
    «не нашлось»: §8.8 требует «`operator` к чужим данным → 403/404 без утечки», то есть ответ
    не вправе сообщать, что объект существует, но чужой.
    """
    try:
        target = UUID(raw_id)
    except ValueError:
        return None
    record = store.session_of_user(
        session_id=target, user_id=principal.session.user_id, not_expired_before=utc_now()
    )
    if record is not None and not owner_matches(principal.session.user_id, record.user_id):
        return None
    return record


def _session_gone() -> JSONResponse:
    """`404` без подробностей: тот же ответ для чужого, кривого и завершившегося идентификатора."""
    return JSONResponse({"status": "not_found", "detail": GONE_DETAIL}, status_code=404)


def _revoke_finished(*, current_ended: bool) -> Response:
    """Ответ после отзыва: обратно к списку, либо на страницу состояния, если ушёл текущий сеанс.

    Направление выбрано не для красоты: оно совпадает с тем, что сама охрана маршрута сделала бы с
    отозванной кукой (`SessionRedirect(SESSION_EXPIRED_PATH, reason='revoked')`). Поэтому здесь тот
    же адрес и та же причина, а не «страница входа, потому что это выход»:

    * `/logout` — человек сам вышел, и следующее, что ему нужно, — форма входа;
    * отзыв — сеанс завершён как решение безопасности, и человек обязан увидеть состояние
      «отозван», иначе «отозвать все» выглядит как сбой, а не как его собственное действие.

    Кука стирается всегда, когда ушла текущая сессия: оставлять в браузере билет, который база уже
    считает мёртвым, §8.3 запрещает.
    """
    if current_ended:
        location = f"{SESSION_EXPIRED_PATH}?{REASON_QUERY}={SessionRevokedError.code}"
        response = RedirectResponse(location, status_code=302)
        clear_session_cookie(response)
        return response
    return RedirectResponse(SESSIONS_PATH, status_code=302)


@router.get(SESSION_REVOKE_PATH, response_class=HTMLResponse)
def revoke_confirm(
    request: Request, session_id: str, principal: ConsoleSession, store: StoreDep
) -> Response:
    """Страница подтверждения отзыва одной сессии (§9.1: подтверждение с указанием объекта).

    Серверная страница вместо JS-модалки — следствие того же ТЗ: `script-src 'self'` без
    `'unsafe-inline'` запрещает инлайновый скрипт (§8.3), а слоя статики консоли (`web/static/`,
    §9.2) в репозитории ещё нет. Пока модалки нет, подтверждение обязано быть серверным: «кнопка и
    надежда на аккуратность» для отзыва чужого входа — не подтверждение.

    Тип возврата — `Response`, а не `HTMLResponse`: ветка «идентификатор не подходит» отвечает
    `404` телом (`_session_gone`), и это тот же ответ, что дают отказные ветки мутаций.
    """
    record = _owned_live_session(store, principal, session_id)
    if record is None:
        return _session_gone()
    moment = utc_now()
    descriptor = describe_session(record, current_id=principal.session.id, now=moment)
    context = {
        "page_title": "Отзыв сеанса",
        "warning": REVOKE_CURRENT_WARNING if descriptor.is_current else REVOKE_OTHER_WARNING,
        "row": _to_row(descriptor),
        "current_label": CURRENT_SESSION_LABEL,
        "sessions_url": SESSIONS_PATH,
        "revoke_url": f"{SESSIONS_PATH}/{descriptor.id}/revoke",
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "session_revoke.html", context
    )
    return response


@router.post(SESSION_REVOKE_PATH, response_class=Response)
def revoke_one(session_id: str, principal: ConsoleMutation, store: StoreDep) -> Response:
    """Отозвать одну сессию (§8.3: «отзыв по одной»).

    Порядок: токен (`require_csrf`) → счётчик частоты → шаг `'full'` → роль (`ADR-017` п. 3) →
    поиск с ограничением по учётной записи → отзыв → `commit()` → ответ. Ограничение `user_id` в самом запросе — то, что
    делает отзыв чужой сессии невозможным, а не «нашли и сверили»: одна ошибка в сверке оставила бы
    дыру, а запрос её не оставит (§8.8).

    Повторный отзыв (страница подтверждения открыта дважды, нажаты две вкладки) вторично ничего не
    меняет: `revoked_at` уже заполнен, строка больше не попадает в перечень живых — ответ будет
    `404`, а момент первого отзыва не перетрётся.

    Запись `audit_log` (§8.7, `session.revoke`, срез `R2b` `T-109`) добавляется этим маршрутом до
    `commit()`: событие и `revoked_at` фиксируются одной транзакцией, поэтому отзыв не может
    зафиксироваться без события (§8.5 «отзыв токена» для разбора требует инициатора).
    """
    record = _owned_live_session(store, principal, session_id)
    if record is None:
        return _session_gone()
    moment = utc_now()
    revoke_session(record, now=moment)
    store.append_audit(
        action="session.revoke",
        at=moment,
        actor=principal.session.user_id,
        entity="session",
        entity_id=record.id,
        details={"is_current": "yes" if record.id == principal.session.id else "no"},
    )
    store.commit()
    return _revoke_finished(current_ended=record.id == principal.session.id)


@router.post(SESSIONS_REVOKE_ALL_PATH, response_class=Response)
def revoke_all(principal: ConsoleMutation, store: StoreDep) -> Response:
    """Отозвать все живые сессии учётной записи, включая текущую (§8.3: «отзыв по одной/всех»).

    «Все» включает текущую сессию осознанно: отзыв, который бережёт ровно тот вход, с которого его
    делают, не является ответом на подозрение в компрометации — украденный вход мог быть ровно тем
    самым. Следствие приняло и направление редиректа: пользователь уходит и с этого устройства, и
    попадает на объяснение «сеанс отозван», а не на форму входа.

    Набор — кандидаты отзыва (тот же, что перечисляет страница подтверждения), а не «все строки
    таблицы когда-либо» и не отображаемый список: отзывать строки, у которых срок уже истёк, нечем,
    и такая правка только заполнила бы `revoked_at` у записей, которые и так не используются
    (`ADR-010`, `T-109` читает это поле как признак отзыва). При этом набор сознательно шире списка:
    строку, которую домен признал завершившейся, но которую запрос ещё считает отзываемой, снимают
    вместе с остальными — поэтому страница подтверждения перечисляет кандидатов, а не список.

    Текущая сессия входит в набор по построению: охрана маршрута только что продлила её. Проверка
    `any(...)` держит это как факт кода, а не как догадку: если набор окажется без текущей сессии,
    пользователь должен остаться внутри, а не получить редирект «вы отозваны».

    Журнал (§8.7, `session.revoke_all`): одна строка на решение, с числом закрытых сеансов в
    `details`. Имя реестра под этим действием одно, а набор закрытых строк восстанавливается по
    `revoked_at` самих записей `sessions` — построчный дубль сделал бы событие удвоенным. Если
    отзываемых строк нет, события нет: запись «отозвано ноль» утверждала бы о состоявшемся
    факте, которого не было.
    """
    moment = utc_now()
    candidates = store.user_sessions(principal.session.user_id, not_expired_before=moment)
    revoked = revoke_sessions(candidates, now=moment)
    if revoked:
        # Одна строка на решение, а не по строке на каждую сессию: имя реестра одно
        # (`session.revoke_all`), а набор закрытых строк восстанавливается по `revoked_at` самих
        # записей сеансов — дублировать его в журнале значило бы удвоить событие (§8.7).
        store.append_audit(
            action="session.revoke_all",
            at=moment,
            actor=principal.session.user_id,
            entity="user",
            entity_id=principal.session.user_id,
            details={"count": len(revoked)},
        )
    store.commit()
    return _revoke_finished(current_ended=any(row.id == principal.session.id for row in revoked))
