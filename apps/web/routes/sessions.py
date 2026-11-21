"""Выход, страница состояния сессии и (в срезе `R3e`) список устройств (TZ §8.3, §9; `T-102`).

Границы файла:

* `/logout` — мутация: охраняется `require_csrf` (матрица §8.8: «без токена → 403»), а живость
  сессии проверяется внутри него. §8.2 разрешает выход на шаге `'password'`: пользователь, который
  ввёл пароль, но не прошёл код, обязан иметь возможность выйти;
* `/session-expired` — объясняющая страница (§9). Она не охраняется сессией: показывать её нужно
    ровно тогда, когда живой сессии нет, и охрана страницы состояния редиректом на саму себя
    дала бы петлю;
* списка устройств и отзывов по одной/всех здесь ещё нет — это срез `R3e` этой же задачи, файл
  будет расширен, а не переписан.

Почему страница объясняет причину кодом из закрытого набора: §9 требует внятных состояний, а набор
причин замкнут (`packages/identity/sessions.SESSION_REASON_CODES` плюс `unknown` уровня HTTP).
Текст из параметра запроса на страницу не попадает никогда — иначе страница состояния стала бы
каналом для чужого текста, а проверка «XSS в полях не исполняется» (§8.8) начинала бы ломаться об
собственный шаблон.
"""

from __future__ import annotations

from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.web.security.csrf import csrf_context, require_csrf
from apps.web.security.sessions import (
    LOGIN_PATH,
    LOGOUT_PATH,
    REASON_QUERY,
    SESSION_EXPIRED_PATH,
    UNKNOWN_SESSION_REASON,
    Principal,
    StoreDep,
    clear_session_cookie,
    display_reason_codes,
)
from packages.common.clock import utc_now
from packages.identity.sessions import revoke_session

router = APIRouter()

#: Зависимость «живая сессия + обязательный CSRF-токен» (матрица §8.8: мутация без токена → `403`).
CsrfPrincipal = Annotated[Principal, Depends(require_csrf)]

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


@router.post(LOGOUT_PATH, response_class=Response)
def logout(
    principal: CsrfPrincipal,
    store: StoreDep,
) -> Response:
    """Выйти: отозвать текущую сессию и стереть куку (§8.3).

    Отзыв — это запись в базу (`revoked_at`), а не только удаление куки: §8.3 требует немедленной
    видимости отзыва, и запрос с сохранённой копией куки обязан быть отклонён. Порядок «сначала
    отозвали и зафиксировали, потом стёрли куку» принципиален: обратный порядок оставил бы живую
    сессию для того, кто куку уже отправил.

    Повторный выход (сессия уже отозвана) ничего не меняет: `revoke_session` возвращает `False` и
    момент первого отзыва не перетирается — по нему разбирают инцидент (`T-109`).

    Запись `audit_log` о выходе (§8.7) здесь ещё не пишется: имена событий и цепочка хэшей — задача
    `T-109`, перенос зафиксирован `ADR-009` (ask `c53daa01`).
    """
    revoke_session(principal.session, now=utc_now())
    store.commit()
    response = RedirectResponse(LOGIN_PATH, status_code=302)
    clear_session_cookie(response)
    return response
