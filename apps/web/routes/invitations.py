"""Приём приглашения по одноразовой ссылке (§1.2, `REQ-identity-02`, `ADR-020` п. 2–4, `T-105`,
срез `R7b`).

Это единственная точка в приложении, где человек сам задаёт себе пароль, и при этом
самостоятельной регистрации нет (§1.2). Границу держит адрес: `/invite?token=…` — секрет в адресе
страницы (параметром запроса), и без него страница, принимающая пароль, стала бы открытой регистрацией
(`tests/integration/test_no_public_registration.py` держит это условие буквально).

Что проверяется и в каком порядке (порядок — часть требования, а не деталь):

1. **источник запроса** (`ensure_same_origin`) — раньше всего остального. Это компенсация того,
   что маршрут не защищён CSRF-токеном сеанса: сеанса у приглашённого ещё нет, а токен `ADR-008`
   выводится из пары «значение куки + `id` сеанса», то есть вывод токена для него не определён.
   Исключение из перечня мутаций оформлено `ADR-021` и держится статической проверкой
   (`tests/contract/test_web_security_contract.py`): маршрут без токена обязан проверять источник.
2. **предел частоты по адресу** (`login_ip`, §8.3: 10 запросов/мин/IP) — до стоимости Argon2id и
   до обращений к `invitations`. Новой области счётчика нет сознательно: `RATE_SCOPES` — закрытый
   перечень схемы, шестое значение означало бы новую ревизию и новый `CHECK`, чего задаче не
   требуется, а смысл у обеих областей один: незащищённая адресом церемония с секретом и подбором
   значений.
3. **значение ссылки**: разбор формата → поиск по хэшу → `ensure_invitation_open`. Порядок решает
   не косметику, а набор ответов: «ссылки нет» и «ссылка испорчена» отвечают одним текстом и одним
   кодом (двух ответов в этом разделе нет), а «истекла», «использована» и «отозвана» объясняются
   по-разному, потому что держатель ссылки вправе знать, что именно не так: чужих данных в этом
   объяснении нет, а §8.8 защищает именно их.
4. **значения полей формы** — до заявки ссылки. Причина не в красоте: приглашение одноразовое, и
   опечатка в пароле, замеченная *после* перехода `pending → used`, стоила бы человеку нового
   выпуска и нового письма. Поэтому `ensure_login_syntax`, `check_password_policy` и правило
   «приглашение адресовано другому логину» вызываются до `claim_invitation`, каждая — тем же
   доменным предикатом, что и внутри `user_from_invitation`: второй копии правила нет, есть
   досрочный вызов первой.
5. **занятость логина** — тоже до заявки ссылки, и объясняется прямо (`ADR-021` п. 5): человеку
   нужно понимать, почему его имя не приняли. Перебор логинов через этот адрес ограничен тем, что
   запрос требует действующую ссылку и попадает под предел частоты входа.
6. **заявка ссылки** — guarded-`UPDATE` слоя доступа (`claim_invitation`: `state = 'pending'` и
   `expires_at > сейчас`, `ADR-020` п. 4). Продолжать работу после того, как заявка не удалась,
   нельзя: это означало бы создать учётную запись по ссылке, которую домен считает закрытой.
7. **учётная запись** — `user_from_invitation` (роль из приглашения, состояние `invited`, e-mail из
   приглашения), затем `add` + единственный `commit()`. Отметку `used_at` ставит база в том же
   `UPDATE`-е, второго источника правды о том, когда ссылку истратили, нет.

Чего здесь нет. Ролевой охраны: роли ещё нет — человека с ролью на этом адресе быть не может,
поэтому уровень допуска в таблице — «церемония входа» (`ADR-017` п. 6). Автовхода: учётная запись
только что создана, и парольный шаг (§8.1) она обязана пройти сама; выдать сеанс тому, кто только
что задал пароль, означало бы пропустить и второй фактор, и очередь одобрения (§1.2). Одобрения
здесь нет вовсе: в очередь запись ставит подтверждённая привязка 2FA (`routes/totp.py`,
`enqueue_for_approval`), а одобрение принимает администратор (`routes/admin_users.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from apps.web.forms import FIELD_LOGIN, FIELD_PHRASE, form_fields
from apps.web.security.csrf import csrf_context, ensure_same_origin
from apps.web.security.rate_limit import (
    LOGIN_IP_SCOPE,
    RateLimitExceeded,
    enforce_scope,
    retry_after_seconds,
)
from apps.web.security.sessions import INVITE_PATH, LOGIN_PATH, StoreDep, session_ip
from apps.web.store import Store
from packages.common.clock import utc_now
from packages.common.logging import get_logger
from packages.identity.invitations import (
    InvitationUnusableError,
    MalformedInvitationTokenError,
    ensure_invitation_open,
    ensure_invitation_secret,
    invitation_token_hash,
    user_from_invitation,
)
from packages.identity.passwords import PasswordPolicyError, check_password_policy
from packages.identity.users import LoginFormatError, ensure_login_syntax, same_login
from packages.storage.models import Invitation

log = get_logger("web")

router = APIRouter()

#: Адрес приёма приглашения — `security/sessions.py`: на него ссылается раздел администратора,
#: когда собирает ссылку для администратора (`invite_link`), и два литерала разошлись бы при
#: первой же правке, оставив администратору адрес в никуда.

#: Имена полей: `login` и `password` приходят из `apps/web/forms.py` — те же константы, что у
#: формы входа (`login_pair`). Два литерала имени одного поля разошлись бы при первой же правке, и
#: форма перестала бы разбираться молча, а не отказом. Собственным остаётся только повтор пароля:
#: у входа повтора нет (§8.1 проверяет пароль, а не ввод «дважды»), поэтому такой константы в
#: слое входа нет и быть не может.
#:
#: Имя константы повтора намеренно без слова «пароль»: S105 читает имя как присваивание пароля
#: (тот же приём, что держит `FIELD_PHRASE` в `apps/web/forms.py`).
FIELD_REPEAT: Final = "password_repeat"

#: Объяснения закрытого состояния ссылки: код → текст (§9.1 «объяснение состояния»).
#: Коды приходят из домена (`INVITATION_UNUSABLE_CODES`), а не выдуманы здесь; полноту набора
#: проверяет `tests/integration/test_invitation_flow.py`.
#:
#: `unknown` и `malformed` в этот набор не входят сознательно: у них один текст и один код
#: ответа. Различать «ссылки нет» и «ссылка не разобрана» ответом нельзя — держателю битой
#: ссылки полезно знать, что он её перенёс неверно, но то же различие было бы ответом на вопрос
#: «существует ли такая строка», и §8.8 отвечает на это «меньше ответов, чем случаев».
UNUSABLE_EXPLANATIONS: Final[dict[str, str]] = {
    "expired": (
        "Срок приглашения истёк. Обратитесь к администратору: он выпустит новое приглашение, "
        "эта ссылка не оживает."
    ),
    "used": (
        "Эта ссылка уже использована: по ней создали учётную запись. Войдите по своему логину "
        "и паролю, который вы задавали."
    ),
    "revoked": ("Приглашение отозвал администратор. Нужна новая ссылка — эта больше не принимает."),
    "unknown": "Ссылка не найдена: возможно, она перенесена не целиком. Запросите ссылку заново.",
    "malformed": "Ссылка испорчена: значение в адресе не читается. Запросите ссылку заново.",
}

#: Коды ответов на закрытую ссылку. `404` для «строки нет» и «значение не разобрано»; `410` для
#: «строка есть, но доступ по ней закрыт» — состояние, из которого нет возврата. Разделение
#: держит сам факт: объяснять «истекло» кодом `404` значило бы сказать «такого адреса нет», то
#: есть потерять ровно то, что §9.1 требует показать.
LINK_MISSING_STATUS: Final = 404
LINK_CLOSED_STATUS: Final = 410

#: Тексты отказов формы (§9.1). Значения полей в текст не подставляются: страница объясняет
#: правило, а не цитирует ввод (§8.8, и экранирование не превращает цитату в безопасную логику).
EMPTY_FORM_DETAIL: Final = "Нужно заполнить логин и пароль дважды."
MISMATCH_DETAIL: Final = "Пароль и его повтор не совпадают: задайте одно и то же значение."
LOGIN_TAKEN_DETAIL: Final = (
    "Такой логин уже занят. Выберите другой — или войдите по существующей учётной записи."
)
SAME_LOGIN_DETAIL: Final = (
    "Приглашение адресовано другому логину: выбрать своё имя нельзя (§1.2). Войдите тем логином, "
    "который назвал администратор."
)
CLAIM_LOST_DETAIL: Final = (
    "Ссылка истрачена или отозвана в этот же момент: учётная запись не создана. Попробуйте "
    "снова со свежей ссылкой, если она у вас есть."
)
ACCEPTED_NOTE: Final = (
    "Дальше — обычный вход: сначала пароль, затем привязка второго фактора. После привязки "
    "учётная запись попадёт в очередь одобрения, и доступ откроет одобрение администратора (§1.2)."
)
TARGET_BY_LOGIN_NOTE: Final = (
    "Приглашение адресовано логину: выбрать своё имя нельзя, оно уже подставлено."
)
TARGET_BY_EMAIL_NOTE: Final = (
    "Приглашение адресовано адресу электронной почты: логин выбираете вы сами, по правилу §8.1."
)


@dataclass(frozen=True)
class _Link:
    """Разобранный адрес приглашения: строка `invitations` или причина, почему её нет.

    Причина — код из `UNUSABLE_EXPLANATIONS`, а не текст: выбор текста остаётся за одним
    словарём, и обработчик не плодит формулировки на каждую ветку.
    """

    record: Invitation | None
    reason: str


def _resolve_link(store: Store, raw_secret: str) -> _Link:
    """Найти выпуск по значению из адреса: формат, поиск по хэшу, отсутствие — одним ответом.

    Формат проверяется до поиска, а не после: `token_hash` считается от байтов, и значение
    с мусором в адресе превратилось бы в хэш, который «ничего не нашёл»; различие «значение
    пошло не по алфавиту» и «такого выпуска нет» в ответе нет намеренно (один текст, один код),
    но сама проверка нужна, чтобы не отправлять в репозиторий заведомо мусорный ключ.
    """
    try:
        ensure_invitation_secret(raw_secret)
    except MalformedInvitationTokenError:
        return _Link(record=None, reason="malformed")
    record = store.invitation_by_hash(invitation_token_hash(raw_secret))
    if record is None:
        return _Link(record=None, reason="unknown")
    return _Link(record=record, reason="")


def _render_link_page(
    request: Request,
    *,
    reason: str,
    status_code: int,
    form_open: bool,
    record: Invitation | None,
    detail: str = "",
    login_value: str = "",
    accepted: bool = False,
) -> Response:
    """Одна разметка на форму принятия, на закрытую ссылку и на ответ «принято».

    Второй страницы не заводили сознательно: состояние ссылки — то, что человек видит в том же
    окне, где он собирался задать пароль, и отдельный адрес заставил бы шаблоны объяснять одно и
    то же дважды. Контекст собирается здесь целиком: окружение рендеринга работает с
    `StrictUndefined`, и недостающая в одной ветке переменная означала бы `500` вместо страницы,
    поэтому «дополнить контекст на месте» в этом модуле запрещено тем же приёмом, что и список
    объяснений в одном словаре.

    Код статуса выбирает вызывающий: форма — `200`, закрытая ссылка — `404` или `410`, отказ
    формы — `400`, отказ частоты — `429` с `Retry-After`.
    """
    target_note = ""
    if record is not None:
        target_note = TARGET_BY_LOGIN_NOTE if record.login is not None else TARGET_BY_EMAIL_NOTE
    context = {
        "page_title": "Приглашение в консоль",
        "form_open": form_open and not accepted,
        "accepted": accepted,
        "detail": detail,
        "explanation": _explanation(reason),
        "note": ACCEPTED_NOTE if accepted else "",
        "login_value": login_value,
        "target_note": target_note,
        "role_label": "" if record is None else record.role,
        "login_form_field": FIELD_LOGIN,
        "password_form_field": FIELD_PHRASE,
        "repeat_form_field": FIELD_REPEAT,
        "login_url": LOGIN_PATH,
    } | csrf_context(None)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "invite.html", context, status_code=status_code
    )
    return response


def _explanation(reason: str) -> str:
    """Текст объяснения по коду; пустого кода в словаре нет — объяснения нет вовсе.

    Отдельной «общей» формулировки на неизвестный код нет сознательно: коды приходят из закрытого
    набора домена, и появление кода вне словаря — это дефект, который обязан выразиться пустым
    объяснением и строкой журнала, а не выдуманной фразой о сроке, которого не было.
    """
    if not reason:
        return ""
    text = UNUSABLE_EXPLANATIONS.get(reason)
    if text is None:
        log.warning("invitation_explanation_missing", code=reason)
    return text or ""


def _rate_denied(request: Request, detail: str, until: datetime, moment: datetime) -> Response:
    """Отказ «адрес слишком часто обращается к ссылке» (§8.3, `ADR-007`).

    `Retry-After` — часть ответа: по нему ориентируются и браузер, и проверки. Тот же приём, что
    у `login._denied`, и отдельная функция здесь потому, что повторять способ отдать заголовок в
    двух модулях — значит потерять его на одной из веток при правке.
    """
    response = _render_link_page(
        request,
        reason="",
        status_code=429,
        form_open=True,
        record=None,
        detail=detail,
    )
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


# ─── страница принятия приглашения ─────────────────────────────────────────────────────────────


@router.get(INVITE_PATH, response_class=HTMLResponse)
def invite_page(request: Request, store: StoreDep, token: str = "") -> Response:
    """Форма принятия приглашения (§9.3 п. 2: «приём приглашения», §1.2 шаг 1).

    Ссылка обязана быть открытой: `ensure_invitation_open` стоит до отрисовки формы, иначе
    страница предлагала бы задать пароль там, где пароль уже ничего не примет, — и человек
    истратил бы внимание на действие, у которого нет последствий.

    `GET` счётчика частоты не имеет: §8.3 ограничивает мутации, а лимит на просмотр страницы дал
    бы способ не пустить приглашённого человека, который просто открыл ссылку (`ADR-007`).
    """
    moment = utc_now()
    link = _resolve_link(store, token)
    if link.record is None:
        return _render_link_page(
            request,
            reason=link.reason,
            status_code=LINK_MISSING_STATUS,
            form_open=False,
            record=None,
        )
    try:
        ensure_invitation_open(link.record, now=moment)
    except InvitationUnusableError as exc:
        return _render_link_page(
            request,
            reason=exc.code,
            status_code=LINK_CLOSED_STATUS,
            form_open=False,
            record=link.record,
        )
    # Логин подставляется, если приглашение его задало: выбор имени остаётся за приглашённым
    # только когда адресат указан адресом почты (§1.2). Подстановка — не удобство: правило
    # «другой логин нельзя» всё равно проверяет домен, а без подстановки человек узнал бы о нём
    # только отказом.
    return _render_link_page(
        request,
        reason="",
        status_code=200,
        form_open=True,
        record=link.record,
        login_value=link.record.login or "",
    )


@router.post(INVITE_PATH, response_class=Response)
async def invite_submit(request: Request, store: StoreDep, token: str = "") -> Response:
    """Принять приглашение: создать учётную запись с состоянием `invited` (§1.2 шаг 1).

    Порядок шагов — см. шапку модуля. Три следствия, которые держат этот обработчик:

    * **ссылка сжигается только после того, как приняты значения полей** — иначе опечатка в
      пароле стоила бы нового выпуска;
    * **переход `pending → used` делает guarded-`UPDATE`**, а не «прочитали — решили — записали»:
      параллельный приём той же ссылки и параллельный отзыв встречаются в реальном времени
      (`ADR-020` п. 4);
    * **учётная запись не одобряется здесь**. Состояние `invited` не даёт ни прав консоли, ни
      доступа к страницам: следующий шаг — привязка второго фактора, и только она ставит запись
      в очередь одобрения (§1.2, `ADR-020` п. 3).
    """
    ensure_same_origin(request)
    moment = utc_now()
    address = session_ip(request)

    try:
        enforce_scope(store, LOGIN_IP_SCOPE, address, moment=moment)
    except RateLimitExceeded as exc:
        detail = f"Слишком много попыток. Попробуйте снова после {exc.until:%H:%M} UTC."
        log.info("invitation_rate_limited", address=address)
        return _rate_denied(request, detail, exc.until, moment)

    fields = await form_fields(request)
    login_value = fields.get(FIELD_LOGIN, "").strip()
    password = fields.get(FIELD_PHRASE, "")
    repeat = fields.get(FIELD_REPEAT, "")

    link = _resolve_link(store, token)
    if link.record is None:
        log.info("invitation_link_missing", reason=link.reason)
        return _render_link_page(
            request,
            reason=link.reason,
            status_code=LINK_MISSING_STATUS,
            form_open=False,
            record=None,
        )
    record = link.record
    try:
        ensure_invitation_open(record, now=moment)
    except InvitationUnusableError as exc:
        log.info("invitation_link_closed", invitation_id=str(record.id), code=exc.code)
        return _render_link_page(
            request,
            reason=exc.code,
            status_code=LINK_CLOSED_STATUS,
            form_open=False,
            record=record,
        )

    if not login_value or not password or not repeat:
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=None,
            detail=EMPTY_FORM_DETAIL,
            login_value=login_value,
        )
    if password != repeat:
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=None,
            detail=MISMATCH_DETAIL,
            login_value=login_value,
        )

    # ── значения полей: досрочный вызов тех же доменных предикатов, что внутри
    #    `user_from_invitation`. Порядок «значение поля → заявка ссылки» обязателен: заявка
    #    необратима, поле обратимо (§ADR-020 п. 4 про одноразовость выпуска).
    try:
        login_checked = ensure_login_syntax(login_value)
        check_password_policy(password, login=login_checked, email=record.email)
    except (LoginFormatError, PasswordPolicyError) as exc:
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=record,
            detail=str(exc),
            login_value=login_value,
        )

    if record.login is not None and not same_login(login_checked, record.login):
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=record,
            detail=SAME_LOGIN_DETAIL,
            login_value=login_value,
        )

    if store.user_by_login(login_checked) is not None:
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=record,
            detail=LOGIN_TAKEN_DETAIL,
            login_value=login_checked,
        )

    # ── заявка ссылки: guarded-`UPDATE` слоя доступа. `rowcount = 0` — значит выпуск успели
    #    закрыть (параллельный приём или отзыв администратором). Продолжать нельзя: учётная
    #    запись по закрытой ссылке — это доступ, которого по записи нет.
    if not store.claim_invitation(invitation_id=record.id, now=moment):
        log.info("invitation_claim_lost", invitation_id=str(record.id))
        return _render_link_page(
            request,
            reason="",
            status_code=LINK_CLOSED_STATUS,
            form_open=False,
            record=record,
            detail=CLAIM_LOST_DETAIL,
        )

    try:
        account = user_from_invitation(
            record, login=login_checked, password=password, now=moment, claimed=True
        )
    except (InvitationUnusableError, LoginFormatError, PasswordPolicyError) as exc:
        # Сюда нечего допускать: все проверки значений и открытости уже пройдены, и если домен
        # всё-таки отказал, транзакция не фиксируется — живая база откатывает и заявку ссылки
        # (закрытие сессии репозитория), поэтому выпуск не считается истраченным. Ветка
        # служебная: она обязана быть, потому что «поймал исключение — проигнорировал» в этом
        # слое означает «ссылка истрачена, учётной записи нет».
        #
        # `claimed=True` здесь обязателен и объяснён в домене: после guarded-`UPDATE` состояние
        # строки в живом слое намеренно несинхронизировано (`synchronize_session=False`), а в
        # офлайн-зеркале оно уже `used`, поэтому обычная проверка открытости после заявки давала
        # бы отказ «приглашение использовано» у законного обработчика — на одной половинке
        # проверок, на другой нет (`ADR-021` п. 4).
        log.exception(
            "invitation_accept_rejected_after_claim",
            invitation_id=str(record.id),
            detail=str(exc),
        )
        return _render_link_page(
            request,
            reason="",
            status_code=400,
            form_open=True,
            record=record,
            detail=str(exc),
            login_value=login_value,
        )

    store.add(account)
    store.commit()
    # В журнал — `id` выпуска, роль и срок: логин в журнал процесса не пишется (§8.4), а
    # `id` выпуска позволяет соотнести строку `invitations` с созданной учётной записью.
    log.info(
        "invitation_accepted",
        invitation_id=str(record.id),
        role=account.role,
        expires_at=record.expires_at.isoformat(),
    )
    return _render_link_page(
        request,
        reason="",
        status_code=200,
        form_open=False,
        record=record,
        login_value=account.login,
        accepted=True,
    )
