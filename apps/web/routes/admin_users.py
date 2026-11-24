"""Раздел администрирования: учётные записи, очередь одобрения, приглашения (§9.3 п. 6, `T-105`,
срез `R7b`).

Адрес был занят допуском с `R6` (`ADR-017`), содержимое строит этот срез. Что именно делает
страница и почему именно так:

* **одна страница на три списка** — очередь одобрения, учётные записи (все состояния, включая
  архивные) и список открытых приглашений. Карта §9.3 п. 6 перечисляет их пунктами одного
  раздела; разводить три адреса значило бы завести три охраны и три строки таблицы допуска там,
  где уровень допуска один (`admin`);
* **приглашение выпускается здесь, а принимается по адресу с секретом** (`/invite?token=…` в
  `routes/invitations.py`). Значение ссылки показывается ровно один раз — в ответе выпуска
  (`ADR-020` п. 3: в базе только хэш, второго способа достать значение нет);
* **действие администратора — переход состояния учётной записи, а не правка поля**. Маршруты
  вызывают доменные действия (`approve_account`, `suspend_account`, `unsuspend_account`,
  `archive_account`), а не пишут в `users.state`: правило переходов живёт в
  `packages/identity/users.STATE_TRANSITIONS`, и вторая копия правила в обработчике разошлась бы
  при первой же правке (`ADR-020` п. 1: «маршруты не знают правил перехода»);
* **смена роли — единственное действие раздела, которое правит поле, а не состояние**: таблицы
  переходов для ролей нет (любое из трёх значений §1.1 доступно любой видимой записи, кроме
  архивированной), и правило «роль меняется только через домен» держит `change_role`
  (`packages/identity/users.py`). Страж последнего живого администратора смотрит при этом на
  **будущую** роль (`ensure_role_change_keeps_admin` — до правки): вызванный после правки
  `ensure_not_last_admin` смотрит на текущую роль и понижения бы не увидел (§8.7, `ADR-020` п. 6);
* **кнопки показаны для каждой учётной записи**: недопустимый переход отвергает сервер и
  объясняет причину на той же странице. «Показывать только разрешённые кнопки» означало бы
  продублировать таблицу переходов в разметке — ровно та дыра, из-за которой скрытая кнопка
  оставляет маршрут открытым (`ADR-017` п. 1);
* **подтверждение опасного действия — серверная страница** (`GET` подтверждения), а не
  JS-подтверждение: `script-src 'self'` без `'unsafe-inline'` (§8.3) и отсутствие слоя статики
  (§9.2) — тот же довод, что у отзыва сеансов в `ADR-010`. `GET` ничего не меняет;
* **имя действия — сегмент адреса, а не параметр**. `POST /admin/users/{id}` без имени действия
  маршрута не имеет вовсе, поэтому «действие в теле/в параметре» здесь физически нечем принять:
  второй способ вызвать то же решение разными значениями — это два места, где нужно держать
  охрану, и второе всегда забывается.

Три обязательных порядка в обработчиках мутаций (основание — `ADR-020` п. 4 и п. 6):

1. **закрытие доступа**: счёт `active_admin_count(except_user_id=…)` **до** перехода, затем
   `ensure_not_last_admin`, и только затем сам переход. Наоборот — нельзя: после перехода поле
   `state` уже изменено, и тот же счёт вернул бы ноль при любом раскладе, то есть проверка
   «не остаться без администратора» перестала бы что-либо проверять;
2. **отзыв живых сеансов** (`revoke_sessions`) следует сразу за переходом и до `commit()`:
   §8.3 требует немедленного применения отзыва, иначе заблокированный человек остаётся в консоли
   до истечения сеанса. Второй контур — `ensure_console_access` внутри `enforce_role`
   (`ADR-020` п. 6): он держит ответ на случай, если отзыв по какой-то причине не случился;
3. **роль и состояние проверяются до поиска объекта** (`ADR-017` п. 3): цепочка
   `require_csrf` → счётчик частоты → шаг `'full'` → `require_admin_role_mutation` стоит у каждой
   мутации, поэтому «забыть охрану» в этом файле невозможно без падения контрактной проверки
   покрытия (`tests/contract/test_web_roles_contract.py`).

Чего здесь нет специально. Ни колонки «последний вход», ни колонок 2FA и Telegram (§9.3 п. 6) — это
данные `T-109`, `T-103` и `T-409`, и выдумывать их источник означало бы решить эти задачи молча. Ни
сброса 2FA администратором: имя `totp.revoked` из реестра §8.7 пока без производителя, доменную
половину (`revoke_enrollment`) вызывает только перепривязка самого человека, а маршрут без решения о
том, что делать с живыми сеансами, заводить нельзя — это срез `R4b` задачи `T-109`. Ни приглашения
«по выбору администратора» без адресата: §1.2 требует e-mail или логин, и это держит домен
(`InvitationTargetError`), а не форма.

Срез `R2b` задачи `T-109` добавляет в раздел записи `audit_log` о состоявшихся действиях
(§8.7, `ADR-025` п. 6): `invitation.issued`, `invitation.revoked`, `account.approved` и
`account.state_changed`. Точка вызова — сам обработчик: он знает, чьё решение привело к переходу
(`actor` — администратор, а не автор приглашения), какое состояние было до перехода и сколько
сеансов закрыл `suspend`/`archive`. Все эти события идут той же транзакцией, что и переход
(свойство `commit_now` у них не ставится): «состояние изменилось, а события нет» — ровно то
состояние, из-за которого журнал перестаёт быть доказательством. Значений адресата (§1.2: e-mail
или логин) в журнале нет — как и в журнале процесса (§8.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.web.forms import FIELD_LOGIN, form_fields
from apps.web.routes.sessions import FullMutation
from apps.web.routes.totp import FIELD_CODE, confirm_second_factor
from apps.web.security.authorization import (
    enforce_role,
    object_gone_response,
    require_admin_role,
)
from apps.web.security.csrf import csrf_context
from apps.web.security.keys import request_key_ring
from apps.web.security.sessions import Principal, StoreDep, invite_link, session_ip
from apps.web.store import ACCOUNTS_LIST_LIMIT, Store
from packages.common.clock import to_msk, utc_now
from packages.common.logging import get_logger
from packages.identity.authorization import (
    ADMIN_TIER,
    ROLE_ADMIN,
    ROLE_LADDER,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    RoleOutsideDomainError,
)
from packages.identity.invitations import (
    InvitationTargetError,
    invitation_is_open,
    new_invitation,
    revocation_outcome,
)
from packages.identity.sessions import revoke_sessions
from packages.identity.totp_enrollment import revoke_enrollment
from packages.identity.users import (
    AccountStateError,
    LastAdministratorError,
    LoginFormatError,
    approve_account,
    archive_account,
    change_role,
    ensure_not_last_admin,
    ensure_role_change_keeps_admin,
    suspend_account,
    unsuspend_account,
)
from packages.storage.models import Invitation, TotpEnrollment, User

log = get_logger("web")

router = APIRouter()

# ─── адреса раздела ────────────────────────────────────────────────────────────────────────────

#: Адрес раздела из карты §9.3 п. 6. Литералы адреса живут здесь, а не в реестре
#: (`security/sessions.py`): на них ссылается только этот раздел, а реестр держит адреса,
#: которые переходят друг другу разные модули (вход, сеанс, привязка, приём приглашения).
ADMIN_USERS_PATH: Final = "/admin/users"

#: Адрес выпуска приглашения. Отдельным адресом, а не действием на адресе раздела: выпуск
#: обязан отвечать своей страницей (значение ссылки живёт только в этом ответе), и общий адрес
#: с действием в параметре открыл бы второй способ вызвать то же решение (§8.8 требует, чтобы
#: ответов было меньше, чем случаев).
ADMIN_INVITATIONS_PATH: Final = "/admin/users/invitations"

#: Параметр-идентификатор приглашения в адресах раздела.
INVITATION_ID_PARAM: Final = "invitation_id"

#: Отзывы и переводы учётных записей: имя действия — сегмент адреса, идентификатор — параметр.
#: Имена сегментов — глаголы домена (`approve`/`suspend`/`unsuspend`/`archive`), а не
#: абстракция уровня HTTP: администратор читает адрес так же, как читает карточку §9.3.
ADMIN_INVITATION_REVOKE_PATH: Final = f"{ADMIN_INVITATIONS_PATH}/{{{INVITATION_ID_PARAM}}}/revoke"

#: Параметр-идентификатор учётной записи в адресах раздела.
USER_ID_PARAM: Final = "user_id"
ADMIN_ACCOUNT_APPROVE_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/approve"
ADMIN_ACCOUNT_SUSPEND_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/suspend"
ADMIN_ACCOUNT_UNSUSPEND_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/unsuspend"
ADMIN_ACCOUNT_ARCHIVE_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/archive"

#: Смена роли (§9.3 п. 6 «смена роли», §8.7 «изменение … роли»). Отдельное окно со списком
#: значений, а не общий `admin_confirm.html`: у того нет поля выбора, и подтверждение, которое не
#: показывает, какой именно ролью человек подтверждает запись, не называет следствия (§9.1).
ADMIN_ACCOUNT_ROLE_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/role"

#: Сброс второго фактора администратором (§9.3 п. 6 «сброс 2FA», §8.1 случай «без второго фактора
#: восстановления по почте»). Маршрут живёт в этом разделе, а машина кода — в `routes/totp.py`:
#: проверять код обязаны одним и тем же порядком (расход шага, лента `totp_failures`, окно адреса,
#: строка `totp.verify_failed`), и второй копии этого порядка в разделе не должно быть.
ADMIN_ACCOUNT_TOTP_RESET_PATH: Final = f"{ADMIN_USERS_PATH}/{{{USER_ID_PARAM}}}/totp-reset"

#: Имена действий: они же — сегменты адресов выше, они же — ключи выбора доменного действия, они
#: же — код действия в деталях `audit_log` (§8.7). Один список на все употребления, иначе адрес,
#: действие и журнал разошлись бы при добавлении перехода.
ACTION_SUSPEND: Final = "suspend"
ACTION_UNSUSPEND: Final = "unsuspend"
ACTION_ARCHIVE: Final = "archive"

# ─── охрана ────────────────────────────────────────────────────────────────────────────────────

#: Зависимость раздела для `GET`: живой сеанс полного входа + роль `admin` (§9.3 п. 6–10).
AdminSession = Annotated[Principal, Depends(require_admin_role)]


def require_admin_role_mutation(principal: FullMutation, store: StoreDep) -> Principal:
    """Мутация раздела администратора: токен + счётчик частоты + шаг `'full'` + роль `admin`.

    Отдельная зависимость, а не `require_admin_role` рядом с `FullMutation`: иначе живой сеанс
    проверялся бы дважды, и два обращения к строке сеанса могли бы увидеть разное состояние
    (сеанс отозвали другим входом между ними). Роль — последним шагом цепочки и до всякого
    обращения к учётной записи, ради которой существует маршрут (`ADR-017` п. 3): отказ,
    вынесенный до поиска объекта, не может сказать, существует ли объект.
    """
    enforce_role(store, principal, required=ADMIN_TIER)
    return principal


#: Зависимость раздела для мутаций: вся цепочка допуска плюс роль `admin`.
AdminMutation = Annotated[Principal, Depends(require_admin_role_mutation)]

# ─── тексты раздела ────────────────────────────────────────────────────────────────────────────

#: Что видит администратор над списками. Текст объясняет раздел, а не прячет его: человек,
#: открывший адрес по ссылке из карты §9.3, вправе понять, что здесь происходит и почему
#: разрешён не любой переход. Формулировка не содержит имён учётных записей и чисел: тот же
#: текст остаётся на странице, и проверка `AC-identity-01` сверяет, что в *отказе* роли нет ни
#: имён, ни счётчиков (`DENIAL_BODY` — отдельное значение, не этот текст).
ADMIN_USERS_NOTE: Final = (
    "закрытый допуск: учётная запись появляется по приглашению администратора, доступ открывает "
    "одобрение, обратного перехода из архива не предусмотрено"
)

#: Подпись под перечнем действий. Правило перехода решается доменом, поэтому кнопки показаны
#: для любой записи, а недопустимый переход отвергается сервером с объяснением.
ACTION_COLUMN_NOTE: Final = (
    "действие принимается сервером: переход разрешён не всегда, при недопустимом переходе отказ "
    "объясняется на этой же странице"
)

#: Подпись под списком приглашений. Значение ссылки не показывается повторно сознательно: в базе
#: хранится только хэш, и второй показ был бы второй точкой утечки (`ADR-020` п. 3).
INVITATIONS_NOTE: Final = (
    "значение ссылки показывается один раз сразу после выпуска и повторно не восстанавливается; "
    "просроченный выпуск остаётся в списке, пока его не отозвали"
)

#: Объяснение на странице выпуска. Текст держится в коде, а не в разметке:
#: на него ссылается проверка «значение показывается ровно один раз»
#: (`tests/integration/test_invitation_flow.py`), и сверять её надо с тем же источником, что видит
#: человек.
ISSUED_LINK_NOTE: Final = (
    "Значение ссылки показывается один раз сразу после выпуска: в базе хранится "
    "только её хэш, поэтому повторно достать значение нельзя. Перешлите его "
    "адресату способом, который ему доступен; если ссылка потеряна, выпустите "
    "новую, а старая останется в списке открытой, пока её не отозвали."
)

#: Предупреждение на подтверждении опасного действия (§9.1: подтверждение обязано называть
#: объект и следствие). Разница между блокировкой и архивированием — в обратимости, и она же
#: причина, почему у одобрения и разблокировки подтверждающей страницы нет.
SUSPEND_WARNING: Final = (
    "Вход будет закрыт, живые сеансы этой учётной записи будут отозваны этим же действием. "
    "Разблокировка возможна и возвращает доступ."
)
ARCHIVE_WARNING: Final = (
    "Архивирование — конец жизни учётной записи: обратного перехода нет. Строка остаётся в базе, "
    "потому что на неё ссылаются сеансы, привязки, приглашения и журнал (§4.1); так же отказывают "
    "учётной записи, которая ждёт одобрения (§1.2)."
)
REVOKE_WARNING: Final = (
    "После отзыва ссылка перестанет принимать учётную запись. Выпуск, по которому уже создали "
    "учётную запись, отзыв не закроет: для этого есть блокировка или архивирование самой записи "
    "(§1.2)."
)

#: Поля формы выпуска приглашения. `login` — общее имя с формой входа (`apps/web/forms.py`):
#: два литерала имени одного поля разошлись бы при первой же правке. `email` и `role` принадлежат
#: этому разделу — в слое входа таких полей нет, и заводить их там означало бы сделать форму входа
#: зависимой от админского раздела.
FIELD_EMAIL: Final = "email"
FIELD_ROLE: Final = "role"

#: Значения списка ролей в форме — тот же порядок, что у лестницы допуска §1.1 (`ROLE_LADDER`),
#: а не собственный перечень: список, который показывает форма, и лестница, по которой решение
#: принимает сервис, обязаны читаться одним источником.
ISSUE_ROLE_CHOICES: Final[tuple[str, ...]] = ROLE_LADDER

#: Параметр запроса, которым мутация сообщает о своём исходе. Значение — код из закрытого набора
#: `ACTION_NOTES`, а не текст: страница никогда не печатает то, что прислал браузер (иначе
#: объяснение стало бы каналом для чужого текста — тот же довод, что у `REASON_QUERY` в
#: `routes/sessions.py`).
NOTE_QUERY: Final = "note"

#: Исходы мутаций раздела: код → объяснение (§9.1 «объяснение состояния»). Набор закрыт, равность
#: набора объяснениям проверяет `tests/integration/test_invitation_flow.py`.
ACTION_NOTES: Final[dict[str, str]] = {
    "invitation_revoked": "Приглашение отозвано: ссылка больше не принимает учётную запись.",
    "invitation_already_revoked": "Это приглашение было отозвано раньше — ничего не изменилось.",
    "invitation_used": (
        "По этому приглашению уже создали учётную запись: отзывать выпуск поздно. Закрывать "
        "доступ нужно состоянием самой учётной записи — блокировкой или архивированием."
    ),
    "invitation_refused": (
        "Приглашение не отозвано: состояние выпуска изменилось одновременно с вашим действием. "
        "Список ниже показывает актуальное состояние."
    ),
    "approved": "Учётная запись одобрена: доступ открыт, автор и время одобрения проставлены.",
    "suspended": (
        "Учётная запись заблокирована: вход закрыт, живые сеансы отозваны этим же действием."
    ),
    "unsuspended": "Блокировка снята: вход и страницы консоли снова доступны.",
    "archived": (
        "Учётная запись архивирована: вход закрыт, живые сеансы отозваны. Обратный переход не "
        "предусмотрен (§1.2)."
    ),
    "refused_transition": (
        "Переход не выполнен: из текущего состояния учётной записи такого перехода нет (§1.2). "
        "Состояние в списке ниже — актуальное."
    ),
    "refused_last_admin": (
        "Действие отклонено: это последняя учётная запись с ролью администратора, у которой "
        "доступ открыт. Сначала передайте права другой учётной записи, иначе система останется "
        "без того, кто способен включить её обратно."
    ),
    "role_changed": (
        "Роль изменена. Живые сеансы этой записи не отозваны: новая роль проверяется на каждом "
        "следующем охраняемом запросе (ADR-017 п. 7)."
    ),
    "role_same": "Роль не изменилась: выбранное значение совпадает с текущим.",
    "refused_role_state": (
        "Роль не изменена: архивированная запись роль не меняет — состояние терминально (§1.2)."
    ),
    "totp_reset": (
        "Второй фактор сброшен: живые сеансы учётной записи отозваны, неиспользованные резервные "
        "коды аннулированы, при следующем входе привязку нужно пройти заново (§8.1, §9.3 п. 6)."
    ),
    "refused_no_totp": (
        "Сброс не выполнен: у учётной записи нет активной привязки — сбрасывать нечего. Список "
        "ниже показывает актуальное состояние."
    ),
    "refused_totp_state": (
        "Сброс не выполнен: архивированная запись вход не откроет, живых сеансов и резервных кодов "
        "у неё нет (§1.2), а событие о том, что ни на что не влияет, размывает журнал (§8.7)."
    ),
}

#: Метки состояний учётной записи для человека (§9.1). Значения держит домен §4.1; метка вне
#: набора печатается как есть: собственные CHECK схемы и `ensure_account_state` таких значений
#: не пропускают, а значит это испорченные данные, и прятать их за домыслом нельзя.
STATE_LABELS: Final[dict[str, str]] = {
    "invited": "приглашение принято, первого входа ещё не было",
    "awaiting_approval": "ждёт одобрения",
    "active": "доступ открыт",
    "suspended": "заблокирована администратором",
    "archived": "архивирована",
}

#: Метки состояния выпуска. Открытость решает домен (`invitation_is_open`), а не сравнение дат в
#: шаблоне: второй календарь в разметке разошёлся бы с доменным (§2.7).
INVITATION_OPEN_LABEL: Final = "открыта"
INVITATION_EXPIRED_LABEL: Final = "срок истёк"

#: Подпись над очередью одобрения, когда её нет. Пустое состояние обязано быть объяснено:
#: администратор, который только что запустил площадку, должен понять, что записей ещё нет, а не
#: что список сломался.
EMPTY_QUEUE_NOTE: Final = "Учётных записей, которые ждут одобрения, нет."
EMPTY_ACCOUNTS_NOTE: Final = "Учётных записей ещё нет: пригласите первую ссылку ниже."
EMPTY_INVITATIONS_NOTE: Final = "Открытых приглашений нет."

# ─── смены роли: подписи и предупреждения (§9.3 п. 6) ───────────────────────────────────────

#: Подписи ролей для человека (§1.1: «администратор, оператор, наблюдатель»). Набор равен `ROLES`:
#: равность проверяет `tests/contract/test_web_roles_contract.py` — метка вне набора означала бы
#: «роль есть в списке выбора, но база её отвергает». Метки держит представление: домен §1.1
#: оперирует значениями ролей, а не словами.
ROLE_LABELS: Final[dict[str, str]] = {
    ROLE_VIEWER: "наблюдатель",
    ROLE_OPERATOR: "оператор",
    ROLE_ADMIN: "администратор",
}

#: Предупреждение на окне смены роли (§9.1: подтверждение обязано называть следствие). Главное
#: следствие здесь — не новое значение, а набор открывающихся разделов, и отдельно сказано про
#: сеансы: в отличие от блокировки их не отзывают (ADR-017 п. 7), и иначе это заметили бы только
#: после действия.
ROLE_WARNING: Final = (
    "Роль решает, какие разделы и действия доступны учётной записи. Живые сеансы при смене роли не "
    "отзываются: новая роль проверяется на каждом следующем охраняемом запросе."
)

#: Тот же смысл про собственную запись: понижение закрывает доступ к разделу администратора, и
#: возвращать роль придётся другому живому администратору (`ADR-020` п. 6 оставляет такое действие
#: возможным, если в системе есть второй живой администратор).
ROLE_SELF_WARNING: Final = (
    "Это ваша собственная учётная запись: после понижения раздел администрирования станет "
    "недоступен, и возвращать роль придётся другому живому администратору."
)

#: Подсказка, когда цель — единственный живой администратор. Отказ предсказуем до `POST`, поэтому
#: он показывается здесь, а не после попытки: человек сэкономит действие, а проверка останется той
#: же (`ensure_role_change_keeps_admin` смотрит на будущую роль до правки).
ROLE_LAST_ADMIN_HINT: Final = (
    "Это единственный живой администратор: понизить его нельзя, пока права не получит другая "
    "запись. Оставить администратором или повысить другую запись — можно (§8.7, ADR-020 п. 6)."
)

#: Почему у архивированной записи нет кнопки подтверждения: §1.2 делает `archived` терминальным, и
#: показывать действие, которое заведомо отвергается, означало бы заставлять человека подтверждать
#: то, чего система не сделает.
ROLE_ARCHIVED_HINT: Final = (
    "Архивированная запись роль не меняет: состояние терминально (§1.2), и менять её роль — значит "
    "записать в журнал изменение, которое ни на что не влияет."
)

# ─── сброс второго фактора: подписи и предупреждения (§9.3 п. 6, §8.1) ─────────────────────

#: Подписи состояния привязки цели (§9.1: страница объясняет состояние). Различать «подтверждён» и
#: «начата, но не подтверждена» нужно потому, что у этих состояний разные носители: у
#: неподтверждённой привязки нет ни второго фактора входа, ни пачки резервных кодов, и сброс такой
#: привязки — не «удаление действующего фактора» (§8.7), а снятие незавершённой попытки.
TOTP_BOUND_LABEL: Final = "второй фактор подтверждён"
TOTP_PENDING_LABEL: Final = "привязка начата, но не подтверждена"
TOTP_NONE_LABEL: Final = "привязки нет"

#: Последствие сброса, названное до подтверждения (§9.3 п. 6 «с предупреждением», §9.1). Сеансы и
#: резервные коды закрываются вместе с привязкой намеренно: и то, и другое выдано тем же вторым
#: фактором (`ADR-016` п. 6 аннулирует остатки пачки при перевыпуске привязки), и оставить их
#: означало бы, что после сброса в консоль по-прежнему пускает либо украденная кука, либо код из
#: старой пачки — то есть второй фактор, который администратор только что снял.
TOTP_RESET_WARNING: Final = (
    "Сброс закрывает второй фактор учётной записи. Её живые сеансы отзываются, неиспользованные "
    "резервные коды аннулируются, а при следующем входе привязку нужно пройти заново (§8.1)."
)

#: Требование кода администратора (§8.1: «сброс администратора требует TOTP администратора», §9.3
#: п. 6: «с TOTP администратора»). Полный шаг сеанса его не заменяет: шаг доказывает, что код
#: ввели когда-то при входе, а код на этой странице доказывает, что устройство разблокировки в
#: руках ровно в момент опасного действия.
TOTP_RESET_CODE_NOTE: Final = (
    "Действие требует код вашего второго фактора: без него сброс не исполняется (§8.1, §9.3 п. 6). "
    "Неудачная попытка движет ту же ленту неудач, что и вход (§8.2)."
)

#: Собственная запись: сброс своей привязки допустим (раздел не запрещает), но он закрывает и
#: собственный вход. Тот же порядок, что у самоблокировки в `ADR-020` п. 6: запрет не правило, а
#: предупреждение о последствиях.
TOTP_RESET_SELF_WARNING: Final = (
    "Это ваша собственная учётная запись: после сброса будут отозваны и ваши сеансы, а следующий "
    "вход потребует привязать генератор заново."
)

#: Почему у записи без привязки кнопки нет: §8.7 называет «отзыв 2FA» удалением действующего
#: фактора, а не строкой «попробовали снять то, чего нет».
TOTP_NOT_BOUND_HINT: Final = (
    "У учётной записи нет активной привязки: сбрасывать нечего. Незавершённую привязку отменяет её "
    "владелец — раздел показывает актуальное состояние."
)

TOTP_ARCHIVED_HINT: Final = (
    "Архивированной записи второй фактор не сбрасывают: вход закрыт состоянием (§1.2), живых "
    "сеансов у неё нет, а событие о действии без последствий размывает журнал (§8.7)."
)

# ─── строки списков ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AccountRow:
    """Строка списка учётных записей: значения подготовлены в коде, шаблон их только печатает.

    Дата форматируется здесь, а не в Jinja2: часы площадки — UTC, §9.1 требует московского
    времени с явной подписью, и разметка, которая сама считает пояс, неминуемо забудет подпись на
    одном из мест.
    """

    user_id: str
    login: str
    role: str
    state: str
    state_label: str
    created: str
    approved: str
    is_self: bool
    approve_url: str
    suspend_url: str
    unsuspend_url: str
    archive_url: str
    role_url: str
    totp_reset_url: str


@dataclass(frozen=True)
class InvitationRow:
    """Строка списка приглашений. Значения ссылки здесь нет и быть не может (`ADR-020` п. 3)."""

    invitation_id: str
    target: str
    role: str
    created: str
    expires: str
    status: str
    revoke_url: str


def _human_moment(moment: datetime | None) -> str:
    """Мгновение для человека с подписью часового пояса (§9.1).

    Параметр объявлен принимающим `None` не для красного словца: у объекта, который не проходил
    `INSERT` (офлайн-двойник репозитория в проверках), серверного значения `created_at` нет, и в
    память оно приходит пустым, хотя колонка объявлена непустой. Отсутствующую дату нельзя печатать
    пустотой: строка выглядела бы как запись с нулевой датой, поэтому здесь стоит знак «нет
    данных». Живая база всегда даёт значение (`server_default now()`).
    """
    if moment is None:
        return "—"
    return f"{to_msk(moment):%d.%m.%Y %H:%M} МСК"


def _state_label(state: str) -> str:
    """Метка состояния; неизвестное значение печатается как есть, а не подменяется домыслом."""
    return STATE_LABELS.get(state) or f"вне описанного набора: {state}"


def _is_self(account: User, principal: Principal) -> bool:
    """Принадлежит ли строка списка той же учётной записи, что смотрит на неё.

    Пометка обязательна: без неё администратор не отличит «заблокировать другого» от
    «заблокировать себя», а второе закрывает ему собственный вход (`ADR-020` п. 6 оставляет
    такое действие возможным, если в системе есть второй живой администратор).
    """
    return account.id == principal.session.user_id


def _account_row(principal: Principal, account: User) -> AccountRow:
    """Собрать строку списка из объекта учётной записи."""
    identifier = str(account.id)
    return AccountRow(
        user_id=identifier,
        login=account.login,
        role=account.role,
        state=account.state,
        state_label=_state_label(account.state),
        created=_human_moment(account.created_at),
        approved=_human_moment(account.approved_at),
        is_self=_is_self(account, principal),
        approve_url=f"{ADMIN_USERS_PATH}/{identifier}/approve",
        suspend_url=f"{ADMIN_USERS_PATH}/{identifier}/suspend",
        unsuspend_url=f"{ADMIN_USERS_PATH}/{identifier}/unsuspend",
        archive_url=f"{ADMIN_USERS_PATH}/{identifier}/archive",
        role_url=f"{ADMIN_USERS_PATH}/{identifier}/role",
        totp_reset_url=f"{ADMIN_USERS_PATH}/{identifier}/totp-reset",
    )


def _invitation_row(record: Invitation, *, moment: datetime) -> InvitationRow:
    """Собрать строку списка приглашений; открытость решает домен, а не шаблон."""
    return InvitationRow(
        invitation_id=str(record.id),
        target=record.email or record.login or "—",
        role=record.role,
        created=_human_moment(record.created_at),
        expires=_human_moment(record.expires_at),
        status=(
            INVITATION_OPEN_LABEL
            if invitation_is_open(record, now=moment)
            else INVITATION_EXPIRED_LABEL
        ),
        revoke_url=f"{ADMIN_INVITATIONS_PATH}/{record.id}/revoke",
    )


def _note_text(request: Request) -> str:
    """Объяснение исхода предыдущей мутации: текст берётся по коду из закрытого набора.

    Значение параметра в разметку не уходит никогда: если кода в наборе нет, объяснения нет
    вовсе. Иначе страница состояния стала бы каналом для произвольного текста из адреса (§8.8), и
    проверка «XSS в полях не исполняется» ломалась бы об собственный шаблон.
    """
    return ACTION_NOTES.get(request.query_params.get(NOTE_QUERY, ""), "")


def _render_section(
    request: Request,
    principal: Principal,
    store: Store,
    *,
    detail: str,
    status_code: int,
    moment: datetime,
) -> HTMLResponse:
    """Одна разметка на список раздела и на отказ формы выпуска.

    Второй страницы раздела не будет: форма выпуска живёт над списками, и отказ формы обязан
    показать те же списки с той же формой, иначе «не приняли значение» выглядело бы как потеря
    раздела.
    """
    context = {
        "page_title": "Пользователи и приглашения",
        "note": _note_text(request),
        "section_note": ADMIN_USERS_NOTE,
        "detail": detail,
        "queue": [
            _account_row(principal, account)
            for account in store.accounts(states=("awaiting_approval",))
        ],
        "accounts": [
            _account_row(principal, account)
            for account in store.accounts(limit=ACCOUNTS_LIST_LIMIT)
        ],
        "invitations": [
            _invitation_row(record, moment=moment)
            for record in store.pending_invitations(limit=ACCOUNTS_LIST_LIMIT)
        ],
        "empty_queue_note": EMPTY_QUEUE_NOTE,
        "empty_accounts_note": EMPTY_ACCOUNTS_NOTE,
        "empty_invitations_note": EMPTY_INVITATIONS_NOTE,
        "role_choices": ISSUE_ROLE_CHOICES,
        "issue_url": ADMIN_INVITATIONS_PATH,
        "users_url": ADMIN_USERS_PATH,
        "action_note": ACTION_COLUMN_NOTE,
        "invitations_note": INVITATIONS_NOTE,
        "field_login": FIELD_LOGIN,
        "field_email": FIELD_EMAIL,
        "field_role": FIELD_ROLE,
        "self_label": "это ваша учётная запись",
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "admin_users.html", context, status_code=status_code
    )
    return response


def _redirect(note_code: str) -> RedirectResponse:
    """Вернуться к разделу с кодом исхода.

    `302`, а не `303`: тот же код, что используют все мутации слоя (§8.3); различать их здесь
    нечем — тела у ответа нет, а адрес следующий.
    """
    return RedirectResponse(f"{ADMIN_USERS_PATH}?{NOTE_QUERY}={note_code}", status_code=302)


def _uuid_or_none(raw: str) -> UUID | None:
    """Разобрать `id` из адреса вручную, а не типом параметра маршрута.

    FastAPI на неразбираемом значении отвечает `422` с перечнем полей — и тогда «ввели мусор в
    адрес» отличался бы от «такой записи нет», а раздел начал бы рассказывать про внутренности
    схемы параметров. Нужен один ответ на оба случая (§8.8, `ADR-017` п. 4).
    """
    try:
        return UUID(raw)
    except ValueError:
        return None


def _account_or_none(store: Store, raw_id: str) -> User | None:
    """Учётная запись по `id` из адреса: кривой и несуществующий `id` дают одно и то же."""
    target_id = _uuid_or_none(raw_id)
    if target_id is None:
        return None
    return store.user_of_id(target_id)


def _invitation_or_none(store: Store, raw_id: str) -> Invitation | None:
    """Выпуск приглашения по `id` из адреса; значение ссылки в этом пути не участвует.

    `id` приходит из формы и сам по себе ничего не даёт: подобрать его перебором нельзя
    (`ADR-020` п. 3: идентификаторы выдаёт приложение), а значение ссылки для отзыва не нужно —
    отзыв закрывает строку, а не пересобирает адрес.
    """
    invitation_id = _uuid_or_none(raw_id)
    if invitation_id is None:
        return None
    return store.invitation_of_id(invitation_id)


def _render_confirm(
    request: Request,
    principal: Principal,
    *,
    title: str,
    warning: str,
    object_kind: str,
    object_label: str,
    object_state: str,
    action_url: str,
    extra: str = "",
) -> Response:
    """Страница подтверждения опасного действия (§9.1: подтверждение с указанием объекта).

    Объект называется прямо: «заблокировать учётную запись» без имени было бы подтверждением
    действия, которое администратор не может проверить. `GET` ничего не меняет — изменение делает
    только `POST` с токеном.
    """
    context = {
        "page_title": title,
        "warning": warning,
        "object_kind": object_kind,
        "object_label": object_label,
        "object_state": object_state,
        "extra": extra,
        "action_url": action_url,
        "cancel_url": ADMIN_USERS_PATH,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "admin_confirm.html", context
    )
    return response


def _self_warning(target: User, principal: Principal) -> str:
    """Предупреждение на подтверждении, когда объект — собственная запись администратора.

    Запретительной проверки здесь нет сознательно: правило «не остаться без администратора»
    проверяется отдельно (`ensure_not_last_admin`), и при втором живом администраторе человек
    вправе закрыть себе доступ сам. Но действие закрывает и его собственный вход, поэтому
    предупреждение обязано быть: §9.1 требует, чтобы подтверждение называло объект и следствия.
    """
    if not _is_self(target, principal):
        return ""
    return (
        "Это ваша собственная учётная запись: после подтверждения вы останетесь без доступа и без "
        "живых сеансов."
    )


# ─── страница раздела ──────────────────────────────────────────────────────────────────────────


@router.get(ADMIN_USERS_PATH, response_class=HTMLResponse)
def admin_users_page(request: Request, principal: AdminSession, store: StoreDep) -> Response:
    """Учётные записи, очередь одобрения и открытые приглашения (§9.3 п. 6).

    `GET` счётчика частоты не имеет намеренно: §8.3 ограничивает мутации, а лимит на просмотр
    страницы дал бы способ устроить отказ человеку, который просто открыл раздел (`ADR-007` —
    «не тратить счётчик там, где запрос ничего не меняет»).

    Ни один из трёх списков не обязан быть непустым: пустое состояние объясняется текстом, а не
    таблицей без строк (§9.1).
    """
    return _render_section(
        request,
        principal,
        store,
        detail="",
        status_code=200,
        moment=utc_now(),
    )


# ─── выпуск приглашения (§9.3 п. 6: «создание приглашения») ───────────────────────────────────


@router.post(ADMIN_INVITATIONS_PATH, response_class=HTMLResponse)
async def issue_invitation(request: Request, principal: AdminMutation, store: StoreDep) -> Response:
    """Выпустить приглашение и показать ссылку ровно один раз (§1.2, `ADR-020` п. 3).

    Порядок: форма → домен (`new_invitation`) → `add` + `commit` → показ значения. Значение
    существует только в этом ответе: в базе лежит хэш, поэтому редирект «на список приглашений»
    выбросил бы то, ради чего действие делалось, а повторный показ был бы второй точкой утечки.
    Отдельная страница, а не тот же шаблон раздела, поэтому и нужна: раздел можно открыть
    повторно, а выпуск — нет.

    Ошибки значений (`LoginFormatError`, `InvitationTargetError`, `RoleOutsideDomainError`) —
    ошибки поля формы, а не отказ допуска: они возвращаются той же страницей с `400` и с
    формулировкой домена («e-mail не похож на адрес»), потому что вторая формулировка в слое
    представления разошлась бы с проверкой при первой же правке. Отдельной проверки «заполнен ли
    хотя бы один адресат» в обработчике нет: её держит домен, и форма не имеет права знать это
    правило лучше домена.
    """
    fields = await form_fields(request)
    moment = utc_now()
    login_value = fields.get(FIELD_LOGIN, "").strip()
    email_value = fields.get(FIELD_EMAIL, "").strip()
    role_value = fields.get(FIELD_ROLE, "").strip()
    try:
        issued = new_invitation(
            created_by=principal.session.user_id,
            role=role_value,
            email=email_value or None,
            login=login_value or None,
            now=moment,
        )
    except (LoginFormatError, InvitationTargetError, RoleOutsideDomainError) as exc:
        # В журнал — только факт отказа и кто его допустил: формулировка домена содержит значение
        # поля (адресат), а значения адресата в журнале процесса быть не должно (§8.4).
        log.info("invitation_issue_rejected", admin_id=str(principal.session.user_id))
        return _render_section(
            request,
            principal,
            store,
            detail=str(exc),
            status_code=400,
            moment=moment,
        )

    store.add(issued.record)
    # `audit_log` (§8.7): событие принадлежит этому обработчику — здесь решено, какой роли и на
    # какой срок выпуск открывается. Добавляется до `commit()` и одной транзакцией с строкой
    # `invitations`. Адресата в деталях нет по той же причине, что и в журнале процесса (§8.4).
    store.append_audit(
        action="invitation.issued",
        at=moment,
        actor=principal.session.user_id,
        entity="invitation",
        entity_id=issued.record.id,
        details={"role": issued.record.role},
    )
    store.commit()
    # В журнал — `id` выпуска, роль и срок: `id` достаточно, чтобы соотнести строку с таблицей
    # `invitations`, а адресат (§1.2: e-mail или логин) в журнал не пишется (§8.4).
    log.info(
        "invitation_issued",
        invitation_id=str(issued.record.id),
        role=issued.record.role,
        admin_id=str(principal.session.user_id),
        expires_at=issued.record.expires_at.isoformat(),
    )
    context = {
        "page_title": "Приглашение выпущено",
        "link": invite_link(issued.secret),
        "target": issued.record.email or issued.record.login or "—",
        "role": issued.record.role,
        "expires": _human_moment(issued.record.expires_at),
        "issued_note": ISSUED_LINK_NOTE,
        "users_url": ADMIN_USERS_PATH,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "admin_invitation_issued.html", context
    )
    return response


# ─── отзыв приглашения (§1.2 «отзыв по действию администратора», §9.3 п. 6) ────────────────────


@router.get(ADMIN_INVITATION_REVOKE_PATH, response_class=HTMLResponse)
def revoke_invitation_confirm(
    request: Request, invitation_id: str, principal: AdminSession, store: StoreDep
) -> Response:
    """Подтверждение отзыва: показывает, какой именно выпуск будет закрыт (§9.1).

    `GET` ничего не меняет — ссылка подтверждения открывается браузером и повторно, и из
    истории. Переход делает `POST` с токеном.
    """
    record = _invitation_or_none(store, invitation_id)
    if record is None:
        return object_gone_response()
    return _render_confirm(
        request,
        principal,
        title="Отозвать приглашение",
        warning=REVOKE_WARNING,
        object_kind="приглашение",
        object_label=record.email or record.login or "—",
        object_state=f"роль {record.role}, срок до {_human_moment(record.expires_at)}",
        action_url=f"{ADMIN_INVITATIONS_PATH}/{record.id}/revoke",
    )


@router.post(ADMIN_INVITATION_REVOKE_PATH, response_class=Response)
def revoke_invitation_submit(
    invitation_id: str, principal: AdminMutation, store: StoreDep
) -> Response:
    """Отозвать выпуск guarded-`UPDATE`-ом слоя доступа (`ADR-020` п. 4).

    Разница с доменным `revoke_invitation` принципиальная: переход делает один запрос слоя
    доступа с условием `state = 'pending'`, иначе отзыв выиграл бы гонку у уже состоявшегося
    приёма ссылки, и учётная запись осталась бы созданной по «отозванному» приглашению — то есть
    журнал показал бы доступ, которого по записи нет.

    Чем является «строка уже не открыта» — ошибкой, «уже отозвано» или отказом, — решает домен
    (`revocation_outcome`), а не обработчик: вторая копия правила разошлась бы с
    `revoke_invitation` при первой же правке. Исходы различаются объяснением, и все они ведут
    обратно к разделу, а не на страницу ошибки: администратору нужен список, а не тупик.
    """
    record = _invitation_or_none(store, invitation_id)
    if record is None:
        return object_gone_response()
    moment = utc_now()

    outcome = revocation_outcome(record)
    if outcome == "already_revoked":
        return _redirect("invitation_already_revoked")
    if outcome == "used":
        return _redirect("invitation_used")
    if outcome != "revocable":
        log.warning("invitation_revocation_outside_domain", invitation_id=str(record.id))
        return _redirect("invitation_refused")

    if not store.revoke_invitation_row(invitation_id=record.id):
        # Гонка: между чтением и `UPDATE` выпуск успели использовать или отозвать. Решение
        # принимается по актуальной строке, а не по той, что держали в руках, и никогда —
        # повторной попыткой «дописать» состояние: переход уже принадлежит слою доступа.
        fresh = store.invitation_of_id(record.id) or record
        race = revocation_outcome(fresh)
        log.info("invitation_revocation_race", invitation_id=str(record.id), outcome=race)
        if race == "already_revoked":
            return _redirect("invitation_already_revoked")
        if race == "used":
            return _redirect("invitation_used")
        return _redirect("invitation_refused")

    store.append_audit(
        action="invitation.revoked",
        at=moment,
        actor=principal.session.user_id,
        entity="invitation",
        entity_id=record.id,
    )
    store.commit()
    log.info(
        "invitation_revoked",
        invitation_id=str(record.id),
        admin_id=str(principal.session.user_id),
    )
    return _redirect("invitation_revoked")


# ─── одобрение (§1.2 шаг 2, §9.3 п. 6 «одобрение») ────────────────────────────────────────────


@router.post(ADMIN_ACCOUNT_APPROVE_PATH, response_class=Response)
def approve_account_submit(user_id: str, principal: AdminMutation, store: StoreDep) -> Response:
    """Одобрить учётную запись: `awaiting_approval → active` (`ADR-020` п. 3).

    Подтверждающей страницы нет сознательно: одобрение открывает доступ тому, кто уже прошёл
    пароль и второй фактор, и принимается оно из очереди, где объект виден в момент решения.
    Опасные действия (`suspend`, `archive`) подтверждения требуют, и различие держит не
    вежливость, а обратимость: архивирование — конец жизни записи (§1.2).

    Отметки `approved_by`/`approved_at` ставит домен, а не обработчик: они существуют ровно в
    одном переходе, и запись их вне перехода дала бы состояние «активно, но не одобрено».
    """
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    state_before = target.state
    moment = utc_now()
    try:
        approve_account(target, approved_by=principal.session.user_id, now=moment)
    except AccountStateError as exc:
        log.info("account_approve_refused", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_transition")
    store.append_audit(
        action="account.approved",
        at=moment,
        actor=principal.session.user_id,
        entity="user",
        entity_id=target.id,
        details={"from": state_before, "to": target.state, "role": target.role},
    )
    store.commit()
    log.info(
        "account_approved",
        user_id=str(target.id),
        approved_by=str(principal.session.user_id),
    )
    return _redirect("approved")


# ─── блокировка, разблокировка, архивирование (§9.3 п. 6) ──────────────────────────────────────


def _close_access(
    store: Store, target: User, principal: Principal, *, action: str, moment: datetime
) -> Response:
    """Закрыть доступ: счёт администраторов → переход → отзыв живых сеансов → фиксация.

    Порядок — не стиль кодирования, а требование `ADR-020` п. 6:

    1. `active_admin_count(except_user_id=…)` **до** перехода. После перехода `state` уже
       изменён, и тот же счёт вернул бы ноль при любом раскладе — проверка перестала бы ловить
       единственный случай, ради которого она заведена;
    2. `ensure_not_last_admin` тоже до перехода: система не должна остаться без единого живого
       администратора, потому что поднимать её пришлось бы правкой таблицы под ролью-владельцем,
       то есть операцией без журнала и без отработанного порядка (`ADR-006`, `ADR-018`);
    3. `revoke_sessions` сразу после перехода и до `commit()`: §8.3 требует немедленного
       применения отзыва; отложенный отзыв означал бы, что заблокированный человек работает в
       консоли до истечения сеанса. Второй контур — `ensure_console_access` внутри `enforce_role`
       (`ADR-020` п. 6), он держит ответ на случай, если отзыв не случился;
    4. один `commit()` на всё: переход состояния и отзыв сеансов — одно решение, и полураспавшееся
       состояние («заблокирована, но ходит») недопустимо. Строка `audit_log`
       (`account.state_changed`, §8.7) добавляется прямо перед этой фиксацией и той же транзакцией:
       событие описывает то же решение, что и переход, и включает число закрытых сеансов в детали —
       отдельного `session.revoke` на каждую закрытую строку здесь нет намеренно (реестр §8.7 даёт
       под действием одно имя, а закрытые строки различаются по `revoked_at` в `sessions`).

    `action` выбирает доменное действие: `suspend` — временная мера, `archive` — конец жизни
    записи. Оба требуют тех же четырёх шагов, и вторая копия порядка в двух обработчиках
    разошлась бы при первой же правке. Исключение `LastAdministratorError` разбирается раньше
    `AccountStateError`: первый является вторым, и порядок `except` здесь определяет, получит ли
    человек объяснение «вы последний администратор» или общее «переход невозможен».
    """
    state_before = target.state
    admins_left = store.active_admin_count(except_user_id=target.id)
    try:
        ensure_not_last_admin(target, active_admins_left=admins_left)
        if action == ACTION_SUSPEND:
            suspend_account(target)
        else:
            archive_account(target)
    except LastAdministratorError as exc:
        log.info("account_last_admin_guard", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_last_admin")
    except AccountStateError as exc:
        log.info("account_close_refused", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_transition")

    revoked = revoke_sessions(store.user_sessions(target.id, not_expired_before=moment), now=moment)
    store.append_audit(
        action="account.state_changed",
        at=moment,
        actor=principal.session.user_id,
        entity="user",
        entity_id=target.id,
        details={
            "action": action,
            "from": state_before,
            "to": target.state,
            "sessions_revoked": len(revoked),
        },
    )
    store.commit()
    log.info(
        "account_access_closed",
        user_id=str(target.id),
        state=target.state,
        action=action,
        admin_id=str(principal.session.user_id),
        sessions_revoked=len(revoked),
    )
    return _redirect("suspended" if action == ACTION_SUSPEND else "archived")


@router.get(ADMIN_ACCOUNT_SUSPEND_PATH, response_class=HTMLResponse)
def suspend_confirm(
    request: Request, user_id: str, principal: AdminSession, store: StoreDep
) -> Response:
    """Подтверждение блокировки: имя записи, её роль и состояние (§9.1)."""
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    return _render_confirm(
        request,
        principal,
        title="Заблокировать учётную запись",
        warning=SUSPEND_WARNING,
        object_kind="учётная запись",
        object_label=target.login,
        object_state=f"роль {target.role}, {_state_label(target.state)}",
        action_url=f"{ADMIN_USERS_PATH}/{target.id}/suspend",
        extra=_self_warning(target, principal),
    )


@router.post(ADMIN_ACCOUNT_SUSPEND_PATH, response_class=Response)
def suspend_submit(user_id: str, principal: AdminMutation, store: StoreDep) -> Response:
    """Заблокировать доступ (§9.3 п. 6 «блокировка»)."""
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    return _close_access(store, target, principal, action=ACTION_SUSPEND, moment=utc_now())


@router.post(ADMIN_ACCOUNT_UNSUSPEND_PATH, response_class=Response)
def unsuspend_submit(user_id: str, principal: AdminMutation, store: StoreDep) -> Response:
    """Снять блокировку: `suspended → active` (§9.3 п. 6 «разблокировка»).

    Подтверждающей страницы нет: действие открывает доступ, а не закрывает. Отметки
    `approved_by`/`approved_at` не меняются: они отвечают на вопрос «кто открыл доступ», а не
    «когда его включили снова» (`ADR-020` п. 3). Отзыва сеансов здесь нет по той же причине, по
    какой его нет у одобрения: живых сеансов у заблокированной записи не осталось — их отозвало
    закрывающее действие, и повторный отзыв нечего отзывало бы.

    Журнал (§8.7): `account.state_changed` с тем же кодом действия, что и сегмент адреса
    (`unsuspend`), добавляется до `commit()` и одной транзакцией с переходом.

    Вызов `unsuspend_account` без предварительной проверки состояния — не «авось домен разберётся»,
    а намеренный отказ от второго правила: домен проверяет исходное состояние сам
    (`_ensure_state_is`), и копия той же проверки в обработчике означает две формулировки одного
    правила, из которых одна отстаёт.
    """
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    state_before = target.state
    moment = utc_now()
    try:
        unsuspend_account(target)
    except AccountStateError as exc:
        log.info("account_unsuspend_refused", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_transition")
    store.append_audit(
        action="account.state_changed",
        at=moment,
        actor=principal.session.user_id,
        entity="user",
        entity_id=target.id,
        details={"action": ACTION_UNSUSPEND, "from": state_before, "to": target.state},
    )
    store.commit()
    log.info(
        "account_unsuspended",
        user_id=str(target.id),
        admin_id=str(principal.session.user_id),
    )
    return _redirect("unsuspended")


@router.get(ADMIN_ACCOUNT_ARCHIVE_PATH, response_class=HTMLResponse)
def archive_confirm(
    request: Request, user_id: str, principal: AdminSession, store: StoreDep
) -> Response:
    """Подтверждение архивирования: переход терминальный (§1.2, `ADR-020` п. 3)."""
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    return _render_confirm(
        request,
        principal,
        title="Архивировать учётную запись",
        warning=ARCHIVE_WARNING,
        object_kind="учётная запись",
        object_label=target.login,
        object_state=f"роль {target.role}, {_state_label(target.state)}",
        action_url=f"{ADMIN_USERS_PATH}/{target.id}/archive",
        extra=_self_warning(target, principal),
    )


@router.post(ADMIN_ACCOUNT_ARCHIVE_PATH, response_class=Response)
def archive_submit(user_id: str, principal: AdminMutation, store: StoreDep) -> Response:
    """Архивировать запись и закрыть доступ (§4.1 «удаление — только архивированием»)."""
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    return _close_access(store, target, principal, action=ACTION_ARCHIVE, moment=utc_now())


# ─── смена роли (§9.3 п. 6 «смена роли», §8.7 «изменение … роли») ────────────────────────────


def _role_options(current: str) -> list[tuple[str, str, bool]]:
    """Строки выбора роли: значение, подпись, признак «это текущее значение».

    Порядок — лестница `ROLE_LADDER` (§1.1: `viewer ⊂ operator ⊂ admin`), а не алфавит: список
    читается снизу вверх так же, как читаются права, и переставить его местами значит изменить то,
    что человек видит первым, не изменив ничего в допуске.

    Текущее значение помечается, а не скрывается и не блокируется: «оставить как было» — тоже
    осмысленный ответ формы, и обработчик отвечает на него кодом `role_same`, а не молчанием.
    """
    return [(role, ROLE_LABELS.get(role, role), role == current) for role in ROLE_LADDER]


def _render_role_confirm(
    request: Request, principal: Principal, target: User, *, hints: list[str]
) -> Response:
    """Окно смены роли: объект, текущее значение, выбор нового и следствия (§9.1).

    Кнопка подтверждения есть только когда действие возможно: для архивированной записи показывать
    «подтвердить» и заведомо отказать в `POST` означало бы завести действие без шансов исполниться.
    При этом сам `GET` остаётся доступен для любой видимой записи (§4.1: архивная строка видна
    всегда) — страница объясняет, почему действия нет.
    """
    context = {
        "page_title": "Сменить роль",
        "warning": ROLE_WARNING,
        "hints": hints,
        "object_kind": "учётная запись",
        "object_label": target.login,
        "object_state": (
            f"роль {ROLE_LABELS.get(target.role, target.role)}, {_state_label(target.state)}"
        ),
        "roles": _role_options(target.role),
        "field_role": FIELD_ROLE,
        "change_allowed": target.state != "archived",
        "archived_hint": ROLE_ARCHIVED_HINT,
        "action_url": f"{ADMIN_USERS_PATH}/{target.id}/role",
        "cancel_url": ADMIN_USERS_PATH,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "admin_role_change.html", context
    )
    return response


@router.get(ADMIN_ACCOUNT_ROLE_PATH, response_class=HTMLResponse)
def role_confirm(
    request: Request, user_id: str, principal: AdminSession, store: StoreDep
) -> Response:
    """Показать окно смены роли: текущее значение, три роли и следствия (§9.1).

    Предупреждения считаются здесь, а не в шаблоне: «единственный ли это живой администратор» —
    вопрос к репозиторию (`active_admin_count`), а разметка счёт вести не должна (второй календарь
    и второй счётчик разошлись бы с доменом при первой же правке).
    """
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    hints: list[str] = []
    if _is_self(target, principal):
        hints.append(ROLE_SELF_WARNING)
    if (
        target.state == "active"
        and target.role == ROLE_ADMIN
        and store.active_admin_count(except_user_id=target.id) == 0
    ):
        hints.append(ROLE_LAST_ADMIN_HINT)
    return _render_role_confirm(request, principal, target, hints=hints)


@router.post(ADMIN_ACCOUNT_ROLE_PATH, response_class=Response)
async def role_submit(
    request: Request, user_id: str, principal: AdminMutation, store: StoreDep
) -> Response:
    """Сменить роль учётной записи (§9.3 п. 6 «смена роли», §8.7 «изменение … роли»).

    Порядок тот же, что `_close_access` держит для состояний (`ADR-020` п. 6 пункты 1–2): счёт
    живых администраторов **до** правки, страж последнего администратора — до правки, сама правка —
    из доменной функции `change_role`, а не присваиванием поля в обработчике, строка `audit_log` —
    той же транзакцией, один `commit()` на всё.

    Порядок стража принципиален: `ensure_not_last_admin` смотрит на **текущую** роль, поэтому после
    `change_role` понижение он бы не увидел (роль уже не `admin` → ранний возврат). Отсюда
    `ensure_role_change_keeps_admin` до правки — она проверяет будущую роль и вызывает тот же
    доменный страж, не заводя второго правила в обработчике.

    Живые сеансы цели не отзываются: роль читается из репозитория на каждый охраняемый запрос
    (`ADR-017` п. 7), поэтому понижение видно следующему же запросу, а §8.3 требует немедленного
    отзыва только при блокировке и архивировании. Именно это отличие написано на окне подтверждения
    (`ROLE_WARNING`): иначе его заметили бы только после действия.

    Значение роли вне набора §1.1 — ошибка поля, а не отказ допуска: ответ — страница раздела с
    `400` и формулировкой домена, как у выпуска приглашения. Вторая формулировка в представлении
    разошлась бы с проверкой `ensure_role` при первой же правке. В журнал процесса формулировка не
    уходит: она содержит значение поля.
    """
    fields = await form_fields(request)
    moment = utc_now()
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    wanted = fields.get(FIELD_ROLE, "").strip()
    role_before = target.role
    admins_left = store.active_admin_count(except_user_id=target.id)
    try:
        ensure_role_change_keeps_admin(target, to_role=wanted, active_admins_left=admins_left)
        changed = change_role(target, to_role=wanted)
    except LastAdministratorError as exc:
        # Порядок `except` принципиален: `LastAdministratorError` является `AccountStateError`, и
        # иначе человек получил бы общее «состояние не позволяет» вместо объяснения про последнего
        # администратора (тот же довод, что у `_close_access`).
        log.info("account_last_admin_guard", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_last_admin")
    except RoleOutsideDomainError as exc:
        log.info(
            "account_role_value_rejected",
            user_id=str(target.id),
            admin_id=str(principal.session.user_id),
        )
        return _render_section(
            request,
            principal,
            store,
            detail=str(exc),
            status_code=400,
            moment=moment,
        )
    except AccountStateError as exc:
        log.info("account_role_change_refused", user_id=str(target.id), detail=str(exc))
        return _redirect("refused_role_state")

    if not changed:
        # Отдельной строки журнала нет: §8.7 заводит `account.role_changed` на изменение роли, а
        # здесь изменения не было — заполнять журнал тем, что не случилось, означало бы обесценить
        # его как доказательство.
        log.info(
            "account_role_unchanged",
            user_id=str(target.id),
            admin_id=str(principal.session.user_id),
        )
        return _redirect("role_same")

    store.append_audit(
        action="account.role_changed",
        at=moment,
        actor=principal.session.user_id,
        entity="user",
        entity_id=target.id,
        details={"from": role_before, "to": target.role, "state": target.state},
    )
    store.commit()
    log.info(
        "account_role_changed",
        user_id=str(target.id),
        role_from=role_before,
        role_to=target.role,
        admin_id=str(principal.session.user_id),
    )
    return _redirect("role_changed")


# ─── сброс второго фактора администратором (§9.3 п. 6 «сброс 2FA», §8.1, §8.7 «отзыв 2FA») ────

#: Стадия неудачной попытки кода для журнала (§8.7 «неудачные попытки 2FA»). Рядом со стадиями
#: `login_code` и `enrollment_confirm` из `routes/totp.py` значение нужно затем, чтобы разбор
#: отличал перебор кода входа от перебора кода на опасном админском действии: субъекты разные —
#: код вводит администратор, а не владелец записи.
TOTP_RESET_STAGE: Final = "admin_totp_reset"


def _totp_state_label(enrollment: TotpEnrollment | None) -> str:
    """Подпись состояния привязки цели: подтверждена, начата или её нет (§9.1)."""
    if enrollment is None:
        return TOTP_NONE_LABEL
    if enrollment.confirmed_at is None:
        return TOTP_PENDING_LABEL
    return TOTP_BOUND_LABEL


def _render_totp_reset(
    request: Request,
    principal: Principal,
    target: User,
    enrollment: TotpEnrollment | None,
    *,
    detail: str = "",
    status_code: int = 200,
) -> HTMLResponse:
    """Страница сброса: объект, состояние привязки, следствия и поле кода администратора.

    Поле кода — не «дополнительная предосторожность»: §8.1 («сброс администратора требует TOTP
    администратора») и §9.3 п. 6 («с TOTP администратора и предупреждением») требуют код, и
    страница обязана сказать это до действия, а не после отказа. Кнопки нет, когда действие
    невозможно (архив, привязки нет): показывать подтверждение действия, которое сервер заведомо
    отвергнет, — тот же дефект, что у страницы смены роли.
    """
    hints = [TOTP_RESET_WARNING, TOTP_RESET_CODE_NOTE]
    if _is_self(target, principal):
        hints.append(TOTP_RESET_SELF_WARNING)
    if target.state == "archived":
        hints.append(TOTP_ARCHIVED_HINT)
    if enrollment is None:
        hints.append(TOTP_NOT_BOUND_HINT)
    context = {
        "page_title": "Сбросить второй фактор",
        "object_kind": "учётная запись",
        "object_label": target.login,
        "object_state": _state_label(target.state),
        "totp_state": _totp_state_label(enrollment),
        "hints": hints,
        "detail": detail,
        "field_code": FIELD_CODE,
        "change_allowed": target.state != "archived" and enrollment is not None,
        "action_url": f"{ADMIN_USERS_PATH}/{target.id}/totp-reset",
        "cancel_url": ADMIN_USERS_PATH,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "admin_totp_reset.html", context, status_code=status_code
    )
    return response


@router.get(ADMIN_ACCOUNT_TOTP_RESET_PATH, response_class=HTMLResponse)
def totp_reset_confirm(
    request: Request, user_id: str, principal: AdminSession, store: StoreDep
) -> Response:
    """Показать страницу сброса второго фактора (§9.1: объект, следствие, требуемый код)."""
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()
    return _render_totp_reset(request, principal, target, store.active_enrollment(target.id))


@router.post(ADMIN_ACCOUNT_TOTP_RESET_PATH, response_class=Response)
async def totp_reset_submit(
    request: Request, user_id: str, principal: AdminMutation, store: StoreDep
) -> Response:
    """Сбросить второй фактор учётной записи (§9.3 п. 6, §8.1, §8.7 «отзыв 2FA»).

    Порядок и его основания:

    1. **«Есть ли что сбрасывать» — до кода администратора.** Иначе система сжигала бы шаг второго
       фактора (а при неверном коде — двигала бы ленту `totp_failures`) на действии, которое не
       будет исполнено, и отказ по состоянию был бы неотличим от отказа по коду (§9.1 требует
       объяснять причину). Обоих проверяющих хватает после цепочки допуска: роль `admin` и шаг
       `full` проверены зависимостями, поэтому сведения о привязке не видны постороннему.
    2. **Код администратора** — `confirm_second_factor` из `routes/totp.py`: тот же расход шага
       (`ADR-013`), та же лента неудач и окно адреса, та же строка `totp.verify_failed` той же
       фиксацией (`ADR-025` п. 6). Второй копии этого порядка в разделе нет намеренно.
    3. **Отзыв привязки → отзыв живых сеансов → аннулирование неиспользованных резервных кодов →
       строка `totp.revoked` → один `commit()`.** Сеансы и коды закрываются вместе с привязкой,
       потому что и то, и другое выдано тем же вторым фактором: оставить их — значит позволить
       чужой куке или коду из старой пачки войти без фактора, который администратор только что
       снял (§8.2 «политика `mfa_required=true`, отключить нельзя», `ADR-016` п. 6 аннулирует
       остатки пачки при перевыпуске привязки). Один `commit()` на всё: «привязка снята, а сеансы
       живы» — ровно то полуисполненное решение, которого журнал потом не объяснит.
    4. **Порядок «сначала цель, потом код, потом мутация»** отличается от `_close_access` только
       проверяемым свойством: там счёт администраторов берётся до перехода, здесь код берётся после
       проверки состояния цели, потому что неверный код не имеет права испортить ни ленту, ни
       привязку.

    Отдельных `session.revoke` на каждую закрытую строку нет (`ADR-025` п. 6): реестр §8.7 даёт на
    такое решение одно имя `totp.revoked`, а число закрытых строк уходит в детали — ровно как у
    `account.state_changed`.
    """
    fields = await form_fields(request)
    moment = utc_now()
    target = _account_or_none(store, user_id)
    if target is None:
        return object_gone_response()

    if target.state == "archived":
        return _redirect("refused_totp_state")
    enrollment = store.active_enrollment(target.id)
    if enrollment is None:
        return _redirect("refused_no_totp")

    actor = store.user_of_id(principal.session.user_id)
    if actor is None:
        # Строка администратора есть всегда: §4.1 не удаляет записи, а сеанс живёт ровно столько,
        # сколько его учётная запись. Отсутствующая строка — испорченные данные, и отвечать на них
        # исполнением действия нельзя.
        return object_gone_response()

    denial = confirm_second_factor(
        store,
        actor,
        session_ip(request),
        fields.get(FIELD_CODE, ""),
        ring=request_key_ring(request),
        moment=moment,
        audit_stage=TOTP_RESET_STAGE,
        render=lambda detail, code: _render_totp_reset(
            request, principal, target, enrollment, detail=detail, status_code=code
        ),
        denied=lambda detail, _until, _reason: _render_totp_reset(
            request, principal, target, enrollment, detail=detail, status_code=403
        ),
    )
    if denial is not None:
        return denial

    confirmed = enrollment.confirmed_at is not None
    revoke_enrollment(enrollment, now=moment)
    revoked = revoke_sessions(store.user_sessions(target.id, not_expired_before=moment), now=moment)
    codes_invalidated = store.invalidate_unused_backup_codes(target.id)
    store.append_audit(
        action="totp.revoked",
        at=moment,
        actor=principal.session.user_id,
        entity="user",
        entity_id=target.id,
        details={
            "reason": "admin_reset",
            "enrollment_id": str(enrollment.id),
            "confirmed": confirmed,
            "sessions_revoked": len(revoked),
            "backup_codes_invalidated": codes_invalidated,
        },
    )
    store.commit()
    log.info(
        "totp_reset_by_admin",
        target=str(target.id),
        admin_id=str(principal.session.user_id),
        enrollment_id=str(enrollment.id),
        sessions_revoked=len(revoked),
        backup_codes_invalidated=codes_invalidated,
    )
    return _redirect("totp_reset")
