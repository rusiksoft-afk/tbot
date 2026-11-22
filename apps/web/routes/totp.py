"""Страница ввода кода 2FA, первичная привязка TOTP и расход резервного кода
(TZ §8.2, §8.3, §9.3 п. 2–3; `T-103` срез `R4c`, `T-104` срез `R5c`).

Здесь закрывается вторая половина входа, о которой `R3a`–`R3f` говорили как о границе: у сессии шага
`'password'` появляется страница кода (§8.2 шаг (2)), а у учётной записи без привязки — страница
первичной привязки (§9.3 п. 3). Пока этих двух адресов не было, правило §8.2 «на шаге пароля доступен
только ввод кода и `/logout`» проверялось на тестовом щупе.

Что здесь есть: `GET/POST /totp` (код входа и перевод на шаг `'full'`), `GET /mfa-enroll` (состояние
привязки), `POST /mfa-enroll/start` (выдать секрет), `POST /mfa-enroll/verify` (подтвердить двумя
кодами и выпустить пачку резервных кодов) и `GET/POST /mfa-recovery` (расход резервного кода,
§9.3 п. 3). Лимиты — все три, которые требует §8.3: `totp_session` (10/мин/сессия), `totp_ip`
(5/мин/IP) и общий предел мутаций на пользователя (60/мин, `ADR-007`). Окно перебора по адресу
`ip_ban` (§8.2) здесь читается и двигается на тех же основаниях, что и на входе: §8.2 говорит «3
неудачные попытки с одного IP», а попытка кода — такая же попытка.

Почему `/mfa-recovery` лежит в этом модуле, а не в отдельном. Резервный код — вторая форма того же
второго фактора, а не самостоятельная страница: у него тот же охраняющий шаг (`CODE_PAGE_STEPS`), та
же цепочка «токен → счётчик мутаций → шаг страницы», те же две области §8.3, то же окно перебора по
адресу и та же лента неудач `totp_failures` (`ADR-016` п. 8: раздельные счётчики дали бы 5 + 5
попыток и обошли бы блокировку чередованием полей). Разнести эти две формы по разным модулям —
значит завести вторую копию `_register_failure_and_lock`, `_rejection_answer` и `_code_denied`, а
расхождение копий не ловилось бы ничем: счётчики снова считались бы по-разному ровно там, где §8.2
требует одного счёта. Общая разметка при этом остаётся своей — у страницы своя форма и свой шаблон.

Резервные коды: выдача, расход и семидневный срок (`ADR-016`). Пачка из 10 кодов выпускается ровно
один раз — в ответе `POST /mfa-enroll/verify`, рядом с подтверждением привязки (решение заказчика от
2026-11-22, ask `2f6bab2b`, `ADR-016` п. 2), и больше нигде: открытые значения существуют ровно между
генерацией и показом, в базе остаются только хэши (п. 3 того же ADR). Порядок обращений к слою
доступа значим: «аннулирование неиспользованных остатков → вставка новой пачки»; обратный порядок
оставляет учётную запись без единого рабочего кода, и это проверяет живой файл
`tests/integration/test_backup_codes_db.py`.

Расход кода (`POST /mfa-recovery`) поднимает сессию до `'full'`: это шаг полной аутентификации, а не
промежуточное состояние (§8.2 «расход кода = шаг полной аутентификации», `ADR-016` п. 9), поэтому у
полной сессии эта страница уже не открывается. Семидневный срок перевыпуска (§8.2) держит переход
«пароль + код 2FA», а не состояние сессии: при просрочке `POST /totp` отказывает до криптографии, а
резервный путь остаётся открытым, пока есть хотя бы одна строка с `used_at IS NULL` (решение заказчика
там же, `ADR-016` п. 6). Активные сессии просрочка не отзывает. Отдельного признака «коды выпущены»
не вводится: состояние выводится из `recovery_state` и из наличия неиспользованных строк.

Файл ключей на резервном пути не читается: коду нечего расшифровывать, и в этом его смысл — он
остаётся доступным и тогда, когда страница кода отвечает `503` из-за недоступного `kek.json`
(`ADR-015` п. 7).

Чего здесь сознательно нет:

* **перепривязки и сброса привязки.** Привязка и перепривязка со страницы `/profile/security` (§9.3
  п. 5) и сброс администратором (§8.2 случай 2, §9.3 п. 6) требуют действующего кода текущей сессии и
  админского допуска — это маршруты зоны профиля и администрирования, а не зоны входа. Ограничение
  видно по коду: `POST /mfa-enroll/start` отказывает `409`, если у учётной записи есть подтверждённая
  привязка, то есть «перетереть привязку» со страницы первичной привязки нельзя;
* **перевыпуска пачки по требованию.** Выпуск привязан к подтверждению привязки, отдельной команды
  «выпустить ещё коды» на `/profile/security` (§9.3 п. 5) пока нет — это остаток `T-104`. Следствие
  осознанное и названо в предупреждении на странице: обязательство §8.2 («выпустить новые в течение
  7 дней») нельзя выполнить изнутри входа, пока этой команды нет, и следующий срез обязан
  закрыть её раньше, чем площадка начнёт тратить резервные коды;
* **счётчика попыток** на странице кода (§9.3 п. 2: «счётчик попыток не показывается, но блокировка
  объясняется») — за это отвечает `LOCK_NOTE`, в котором правило описано, а состояние нет; на
  странице резервного кода показывается не счётчик попыток, а состояние набора (`spare`) — это
  собственные данные учётной записи, а не карта для переборщика;
* **алерта администратору о расходе кода** (§8.2 «+ алерт администратору»): доставка уведомлений —
  `T-716`, в этом срезе остаётся именованное событие журнала `backup_code_spent`;
* **записей `audit_log`** о привязке, подтверждении, выпуске и расходе кодов, блокировках и отказах
  `429` (§8.7): имена событий и цепочка хэшей относятся к `T-109` (перенос зафиксирован `ADR-009`).
  Компенсирующие контроля на месте: состояние привязки — в `totp_enrollments`, попытки — в
  `totp_failures`, коды и их расход — в `backup_codes`, блокировка — в `users.locked_until`, бан
  адреса — в `rate_buckets`, и всё это объясняется человеку сразу.

Шаг `'totp'` и почему он не даёт доступа. Подтверждение привязки переводит сессию на шаг `'totp'`, и
это **не** полный вход: полный даёт только ввод кода (§8.2 шаг (2)) либо расход резервного кода
(`ADR-016` п. 9). Различие не формальное: секрет привязки выдаёт тому же владельцу то же приложение,
чью сессию оно защищает. Сессия, которая может попросить секрет, показать два кода и «подтвердить»
привязку, не должна автоматически оказываться внутри консоли, — иначе второй фактор сводится к одному
паролю. Поэтому у входа остаётся отдельное событие: код, который расходуется (`last_used_step`) и
поднимает сессию до `'full'` (`ADR-015` п. 3).

Одноразовость и коды подтверждения. Подтверждение привязки расходует свои два кода (`ADR-013`): после
успешного `verify` страница кода ждёт **новый** код из следующего окна, и шаблон говорит об этом
прямо. Тот же шаг кода, которым подтвердили привязку, вход не откроет — это держат и домен, и
guarded-`UPDATE` в `store.claim_totp_step` (живая проверка —
`tests/integration/test_totp_enrollment_db.py`). У резервного кода одноразовость держит тот же
приём: guarded-`UPDATE` в `store.spend_backup_code` (живая `test_backup_code_single_use`).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from apps.web.forms import form_fields
from apps.web.qrcode import QrBuildError, QrGraphic, qr_graphic
from apps.web.routes.sessions import RateLimitedMutation
from apps.web.security.csrf import csrf_context
from apps.web.security.keys import request_key_ring
from apps.web.security.rate_limit import (
    TOTP_IP_SCOPE,
    TOTP_SESSION_SCOPE,
    RateLimitExceeded,
    ban_until,
    enforce_scope,
    register_address_failure,
    retry_after_seconds,
)
from apps.web.security.sessions import (
    CODE_PAGE_STEPS,
    CONSOLE_PATH,
    LOCK_REASON_ATTEMPTS,
    LOCK_REASON_RATE,
    LOCKED_PATH,
    MFA_ENROLL_PATH,
    MFA_ENROLL_START_PATH,
    MFA_ENROLL_VERIFY_PATH,
    MFA_RECOVERY_PATH,
    POST_CODE_REDIRECT,
    REASON_QUERY,
    TOTP_CODE_PATH,
    Principal,
    SessionRedirect,
    StoreDep,
    require_code_page_session,
    session_ip,
    touch_session,
)
from apps.web.store import Store
from packages.common.clock import utc_now
from packages.common.logging import get_logger
from packages.identity.backup_codes import (
    BACKUP_CODE_LENGTH,
    RECOVERY_REGENERATION_WINDOW,
    BackupCodeFormatError,
    RecoveryState,
    display_backup_code,
    hash_backup_code,
    new_backup_codes,
    recovery_state,
)
from packages.identity.sessions import advance_auth_step
from packages.identity.totp import (
    TOTP_FAILURE_HORIZON,
    TOTP_MAX_FAILED_CODES,
    TOTP_PERIOD_SECONDS,
    register_totp_code_failure,
    totp_provisioning_uri,
    totp_step,
)
from packages.identity.totp_enrollment import (
    TotpEnrollmentError,
    confirm_enrollment,
    enrollment_state,
    new_enrollment,
    revoke_enrollment,
    verify_enrollment_code,
)
from packages.identity.users import LoginLockedError, ensure_login_allowed
from packages.storage.models import User

log = get_logger("web")

router = APIRouter()

#: Зависимость GET-страниц страницы кода и привязки (§8.2, `ADR-015` п. 3): живая сессия шага
#: `'password'` или `'totp'`; сессия полного входа уходит на домашнюю страницу консоли.
CodeSession = Annotated[Principal, Depends(require_code_page_session)]


def require_code_page_mutation(principal: RateLimitedMutation) -> Principal:
    """Мутация страницы кода и привязки: токен, счётчик пользователя и шаг страницы.

    Порядок закреплён за §8.2, §8.3 и `ADR-008` и он не «как получилось»: цепочка зависимостей
    (`require_csrf` → `require_mutation_rate_limit` → здесь) ставит отказ токена **до** обращений в
    базу и до расхода лимита жертвы, а шаг проверяется последним — как и у `require_full_mutation` в
    `routes/sessions.py`. Следствие осознанное: попытка мутации с шагом `'full'` тоже стоит обращения
    счётчику (§8.3 считает запросы пользователя, а не удачные запросы).

    Отдельная зависимость, а не `require_code_page_session` рядом с `RateLimitedMutation`: иначе сессия
    проверялась бы дважды (два обращения в базу на один запрос), и два обращения могли бы увидеть
    разное состояние сессии.
    """
    if principal.session.auth_step not in CODE_PAGE_STEPS:
        raise SessionRedirect(CONSOLE_PATH)
    return principal


#: Мутация страницы кода/привязки: токен + счётчик пользователя + шаг страницы.
CodeMutation = Annotated[Principal, Depends(require_code_page_mutation)]

# ─── имена полей форм ──────────────────────────────────────────────────────────────────────────

#: Имена полей не содержат слов «пароль» и «секрет» по той же причине, что и в `forms.py`: S105
#: смотрит на имя переменной, а форма привязки оперирует секретом осознанно.
FIELD_CODE: Final = "code"
FIELD_FIRST_CODE: Final = "first_code"
FIELD_SECOND_CODE: Final = "second_code"

#: Ограничение длины предъявленного кода. Держит приложение, а не шаблон: `maxlength` в форме обходят
#: подменой тела, а `verify_totp_code` принимает любую строку и называет «не шесть цифр» отдельным
#: исходом. Граница заведомо больше шести цифр, чтобы «6 цифр и перевод строки» остался ошибкой кода,
#: а не «слишком длинным полем», и заведомо меньше предела тела формы (`apps/web/forms.py`), чтобы
#: отказ был про код, а не про размер запроса.
MAX_CODE_CHARS: Final = 16

# ─── имена и границы поля резервного кода (§8.2, `T-104`, срез `R5c`) ───────────────────────

#: Имя поля формы резервного кода. Оно же — имя ключа маскировки журнала (`_MASK_KEYS` в
#: `packages/common/logging.py`): совпадение намеренное, а не «историческое». Значение резервного
#: кода — секрет входа, и шанс, что оно окажется в записи журнала, закрывается в двух местах:
#: маршруты его не логируют, а маска не даёт сделать это случайно.
FIELD_BACKUP_CODE: Final = "backup_code"

#: Ограничение длины предъявленного резервного кода. Держит приложение, а не шаблон, по той же
#: причине, что и `MAX_CODE_CHARS`: `maxlength` обходят подменой тела. Граница заведомо больше
#: 10 знаков: показ разбит группами (`display_backup_code`), человек переносит код с дефисом,
#: тире и пробелами, а `normalize_backup_code` их убирает. И заведомо меньше предела тела формы
#: (`apps/web/forms.py`), чтобы отказ был про код, а не про размер запроса.
MAX_BACKUP_CODE_CHARS: Final = 32

# ─── тексты состояний (§9: состояние внятное, объяснение — без пользы для переборщика) ─────────

#: Общая формулировка отказа кода. Различий «не тот код», «повтор кода» и «не похоже на код» в ответе
#: нет намеренно: по различию ответов подбором находилось бы, израсходовано ли окно, и живёт ли у
#: учётной записи привязка. Различие уходит в лог процесса (исход `TotpCheck`) и различимо по строкам
#: `totp_failures`-ленты только косвенно: §8.2 требует ленту по порогу и адресу, а не по причинам.
CODE_FAILURE_DETAIL: Final = "Код не подходит. Возьмите новый код из следующего окна."

EMPTY_CODE_DETAIL: Final = "Нужно ввести шестизначный код из генератора."

#: Правило блокировки — без счётчика попыток (§9.3 п. 2: «счётчик попыток не показывается, но
#: блокировка объясняется»). Текст описывает правило, а не текущее состояние: «осталось N попыток»
#: было бы картой для того, кто перебирает коды. Про уведомление (§8.2 «+ уведомление») здесь не
#: говорится: очередь уведомлений — отдельная задача вехи M2, и обещать её со страницы нельзя.
LOCK_NOTE: Final = (
    f"После {TOTP_MAX_FAILED_CODES} неверных кодов подряд вход в учётную запись закрывается на "
    "15 минут. Коды принимаются один раз: код из уже пройденного окна не подойдёт."
)

#: Про коды подтверждения привязки (§8.2: «2 последовательных кода»). Отдельный текст нужен, что
#: второй код берётся из следующего окна, то есть через 30 секунд: без этой фразы человек вводит
#: одно и то же значение дважды и получает «повтор кода», не понимая почему. Формулировка обязана
#: сказать и обратное: коды подтверждения израсходованы, для входа нужен новый.
CONFIRM_NOTE: Final = (
    "Введите два кода подряд: первый — текущий, второй — из следующего окна (через "
    f"{TOTP_PERIOD_SECONDS} секунд). Коды подтверждения привязки расходуются: для входа понадобится "
    "новый код."
)

#: Привязка уже есть. Объяснение, а не «отказ без объяснения»: у учётной записи с подтверждённой
#: привязкой первичная привязка не запрашивается, и человек обязан понять, куда идти дальше.
ALREADY_BOUND_DETAIL: Final = (
    "Привязка к генератору кодов уже выполнена. Повторить её с этой страницы нельзя: перепривязка "
    "требует действующий код и выполняется в разделе безопасности профиля."
)

#: Секрет показывают один раз (§8.2: «в UI больше не показывается»). Текст объясняет, почему страница
#: с начатой привязкой не может показать секрет второй раз: повторный вывод был бы вторым выводом
#: секрета, а §8.2 разрешает ровно один.
ENROLL_ONCE_DETAIL: Final = (
    "Секрет привязки показывается один раз и не повторяется. Если он не сохранён, начните привязку "
    "заново: предыдущая будет отозвана, а секрет создан новый."
)

NO_ENROLLMENT_DETAIL: Final = (
    "Привязки ещё нет: начните привязку, затем подтвердите её двумя кодами из генератора."
)

STALE_ENROLLMENT_DETAIL: Final = (
    "Срок незавершённой привязки истёк. Начните привязку заново: старая запись будет отозвана."
)

#: Форма отказа «учётной записи сессии больше нет» — та же, что у `_account_gone` в
#: `routes/profile.py`: FOREIGN KEY `RESTRICT` не даёт удалить учётку с живыми сессиями, поэтому
#: случай означает повреждение данных, а не состояние пользователя.
ACCOUNT_GONE_DETAIL: Final = "account_gone"

#: Постоянная подпись к таймеру окна (§9.3 п. 2: «таймер окна»). Живого обратного отсчёта здесь нет:
#: он требует JS-тикера (vendored JS — отдельная работа вехи M1 с политикой CSP §8.3), а честная
#: серверная половина отвечает на вопрос «сколько ещё живёт этот код» на момент отрисовки.
WINDOW_NOTE: Final = "Код действителен 30 секунд. Если код не подошёл, возьмите новый."


# ─── мелочь, которую иначе разносят по трём местам ─────────────────────────────────────────────


# ─── резервные коды: тексты состояний (§8.2, `ADR-016` п. 5, 6, 9) ────────────────────────

#: Общая формулировка отказа резервного кода. Различий «не тот код», «уже израсходован» и «код
#: другой учётной записи» в ответе нет намеренно (`ADR-016` п. 3, п. 5): по различию ответов
#: подбором находилось бы, какой код у этой учётной записи уже потрачен. Различие уходит только в
#: лог процесса (`found` — «нашли неиспользованный, но guarded-переход отказал»).
RECOVERY_FAILURE_DETAIL: Final = (
    "Резервный код не подходит. Каждый код используется один раз: возьмите следующий из списка."
)

#: Отказ по формату можно показать прямо: он не отвечает на вопрос «есть ли такое значение у этой
#: учётной записи» и экономит человеку попытку из лимита на заведомо бессмысленном вводе
#: (`ADR-016` п. 5). Значения в тексте нет: сообщение об отказе уходит в журнал.
RECOVERY_FORMAT_DETAIL: Final = (
    f"Резервный код — {BACKUP_CODE_LENGTH} символов из алфавита без похожих знаков: в нём нет "
    "I, L, O, 0 и 1. Разделители вводить можно, они игнорируются."
)

EMPTY_BACKUP_CODE_DETAIL: Final = "Нужно ввести резервный код."

#: Постоянное объяснение страницы резервного кода. Срок блокировки здесь не назван числом минут
#: намеренно: его ставит `LOCK_DURATION`, и вторая копия числа разошлась бы с кодом (для страницы
#: кода это держит отдельная контрактная проверка).
RECOVERY_NOTE: Final = (
    f"Каждый резервный код используется один раз. После первого расхода нужно выпустить новые "
    f"коды: на это {RECOVERY_REGENERATION_WINDOW.days} суток. Неудачные попытки ввода резервных "
    f"кодов считаются вместе с кодами 2FA: после {TOTP_MAX_FAILED_CODES} неудачных кодов подряд "
    "вход в учётную запись закрывается."
)

#: Успех расхода: код принят, доступ открыт, и повторить расход нечем (`ADR-016` п. 9).
RECOVERY_SPENT_DETAIL: Final = "Код принят: вход выполнен. Этот резервный код израсходован."

#: Отказ перехода «пароль + код 2FA» при просроченном семидневном сроке (§8.2: «иначе учётная
#: запись блокируется на вход, не на торговлю»). Текст обязан назвать и выход: пока есть
#: неиспользованный резервный код, войти можно им (`ADR-016` п. 6, решение заказчика от 2026-11-22,
#: ask `2f6bab2b`). Блокировка живёт ровно на этом переходе, а не в состоянии сессии: активные
#: сессии просрочка не отзывает (п. 6 там же).
GRACE_EXPIRED_DETAIL: Final = (
    "Срок перевыпуска резервных кодов истёк: вход по паролю и коду 2FA закрыт. Войти можно "
    "резервным кодом, пока хотя бы один не израсходован, — и сразу после этого выпустить новые."
)

#: Состояние «неиспользованных кодов не осталось». При просроченном сроке это принятый риск
#: (`ADR-016` п. 6): путь перевыпуска закрыт вместе со входом, и снимает его только сброс
#: привязки администратором (§9.3 п. 6, задача `T-106` не сделана). Но то же состояние бывает и
#: до истечения срока — человек истратил все десять кодов, а обязательство перевыпустить пачку
#: ещё не просрочено, и вход по коду 2FA для него открыт. Поэтому текст не утверждает, что вход
#: закрыт: он описывает состояние и называет выход для обеих веток. Формулировка обязана говорить
#: правду, а не оставлять форму с заведомо неверным ответом.
NO_SPARE_CODE_DETAIL: Final = (
    "Неиспользованных резервных кодов не осталось: войти резервным кодом нельзя. Новая пачка "
    "выпускается только при подтверждении привязки, а привязку можно пройти только изнутри "
    "входа. Если при этом истёк срок перевыпуска и вход по коду 2FA закрыт, обратитесь к "
    "администратору: он выполнит сброс привязки."
)


def _recovery_note(state: RecoveryState) -> str:
    """Предупреждение о перевыпуске (§8.2) для страницы кода и страницы резервного кода.

    Пустая строка означает «обязательства перевыпустить нет»: коды никогда не расходовались либо
    после расхода уже выпущена новая пачка (`recovery_state`, `ADR-016` п. 6). Текст строится по
    состоянию набора, а не по факту конкретного запроса: предупреждение обязано оставаться и на
    следующем входе, иначе обязательство §8.2 забывается вместе со страницей, на которой код был
    потрачен.

    Число неиспользованных кодов показывается самому владельцу его собственного набора — страница
    охранена шагом `'password'`/`'totp'`, то есть доступна тому, кто уже ввёл пароль. На ответ
    отказа это не влияет: «своего», «чужого» и «израсходованного» кода страница не различает
    (§8.8), а `unused` описывает набор учётной записи целиком, а не предъявленное значение.
    """
    deadline = state.regeneration_deadline
    if not state.needs_regeneration or deadline is None:
        return ""
    moment_text = deadline.strftime("%d.%m.%Y %H:%M")
    if state.login_blocked:
        return (
            f"Срок перевыпуска резервных кодов истёк {moment_text} UTC. Вход по паролю и коду 2FA "
            f"закрыт; неиспользованных кодов осталось: {state.unused}."
        )
    return (
        f"Нужно выпустить новые резервные коды: срок до {moment_text} UTC, неиспользованных "
        f"кодов осталось: {state.unused}."
    )


def _recovery_warning_after_spend(spare_left: int, moment: datetime) -> str:
    """Предупреждение §8.2 в том же ответе, где код был истрачен.

    Дедлайн здесь — только текст для человека: решение о просрочке принимает `recovery_state` по
    датам из таблицы, а момент расхода ставит база (`used_at = now()`, `ADR-016` п. 7, п. 11).

    Пересчитывать состояние по объектам текущего запроса нельзя: guarded-`UPDATE` расхода идёт с
    `synchronize_session=False` (`SqlStore.spend_backup_code`), и строка в identity map осталась
    бы с прежним `used_at`, а `expire_on_commit=False` не сбрасывает её после коммита. Поэтому
    остаток считается арифметикой от снимка, сделанного **до** расхода.
    """
    deadline = (moment + RECOVERY_REGENERATION_WINDOW).strftime("%d.%m.%Y %H:%M")
    if spare_left <= 0:
        return (
            "Это был последний неиспользованный резервный код. Новые коды нужно выпустить до "
            f"{deadline} UTC: после истечения срока вход будет закрыт полностью, а снимает его "
            "только сброс привязки администратором."
        )
    return (
        f"Новые резервные коды нужно выпустить до {deadline} UTC. Неиспользованных осталось: "
        f"{spare_left}; после истечения срока вход по паролю и коду 2FA закрывается."
    )


def _qr_of_enrollment(secret: str, login: str, issuer: str) -> QrGraphic | None:
    """QR-картинка привязки: из того же значения, которое уже показал этот ответ.

    `secret` — одноразовое значение `NewEnrollment.secret` (`ADR-014` п. 6): `secret_enc`
    повторно не расшифровывается, поэтому точек вывода материала привязки остаётся ровно
    столько же, сколько было до `R4d` — одна (`ADR-015` п. 6). Метка аккаунта — логин учётной
    записи, `issuer` — значение из строки привязки (`TOTP_ISSUER`), чтобы картинка, ручной ключ
    и колонка `issuer` не разошлись: по метке генератор различает учётные записи.

    Отказ кодировщика ловится здесь, а не на странице: страница привязки обязана остаться
    рабочей даже без картинки (§8.2 требует QR **и** ручной ввод), а привязка к этому моменту
    уже создана и зафиксирована. В лог уходят только причина и длина ссылки: в
    `otpauth://`-строке лежит секрет, и наружу она не выводится ни в каком виде.
    """
    uri = totp_provisioning_uri(secret, account_name=login, issuer=issuer)
    try:
        return qr_graphic(uri)
    except QrBuildError as exc:
        log.warning("totp_qr_unavailable", detail=str(exc), payload_chars=len(uri))
        return None


def _window_line(moment: datetime) -> str:
    """Строка таймера окна (§9.3 п. 2) для шаблона.

    Отсчёт ведётся от того же номера шага, что использует `verify_totp_code` (`totp_step`): иначе
    страница и проверка разошлись бы по «какому сейчас окну», и подсказка «возьмите новый код»
    появилась бы на 30 секунд раньше или позже самого окна. Часовой пояс не показывается: остаток —
    длительность, а не момент, и путаница «в котором часу» дороже пользы.
    """
    return f"До смены кода осталось {TOTP_PERIOD_SECONDS - (totp_step(moment) % TOTP_PERIOD_SECONDS)} с."


def _codes_of(fields: dict[str, str]) -> tuple[str, str, str]:
    """Предъявленные значения форм: код входа и пара кодов подтверждения.

    Пустая строка означает «поля не заполнены»: отказ `400` до всякой криптографии и **без** записи в
    ленту неудач — по той же причине, что и пустая форма входа: отправивший пустую форму не должен
    приближать блокировку, а переборщик — получать способ размывать счётчик неудач (§8.2 считает
    попытки, а не пустые отправления).

    Пара значений возвращается одним вызовом, потому что оба поля приходят из одной формы, а
    `form_fields` уже читает тело ровно один раз (`apps/web/forms.py`).
    """
    code = fields.get(FIELD_CODE, "").strip()[:MAX_CODE_CHARS]
    first = fields.get(FIELD_FIRST_CODE, "").strip()[:MAX_CODE_CHARS]
    second = fields.get(FIELD_SECOND_CODE, "").strip()[:MAX_CODE_CHARS]
    return code, first, second


def _account_gone() -> JSONResponse:
    """`404` без подробностей: учётной записи сессии больше нет в таблице."""
    return JSONResponse({"status": ACCOUNT_GONE_DETAIL}, status_code=404)


def _lock_explanation(until: datetime) -> str:
    """Блокировка учётной записи: причина и срок, но не число оставшихся попыток (§9.3 п. 2)."""
    return (
        "Вход в учётную запись заблокирован: слишком много неверных кодов. "
        f"Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _address_explanation(until: datetime) -> str:
    """Отказ по адресу: предел частоты §8.3 либо активный бан окна перебора §8.2."""
    return (
        "С этого адреса было слишком много попыток подтверждения. "
        f"Попробуйте снова после {until.strftime('%H:%M')} UTC."
    )


def _register_failure_and_lock(
    store: Store, user: User, address: str | None, *, moment: datetime
) -> tuple[datetime | None, datetime | None]:
    """Неудача кода целиком: лента `totp_failures`, окно `ip_ban`, сроки блокировки и бана.

    Возвращает пару сроков — «учётная запись закрыта до» и «адрес закрыт до» (`None`, если не
    закрыто). Один помощник нужен, чтобы ни одна из двух веток (§8.2 блокировка учётной записи и
    §8.2/§8.3 бан окна перебора по адресу) не потерялась на очередном отказе: они ставятся вместе, и
    порядок фиксирован — сначала лента учётной записи, потом окно адреса.

    Строка ленты добавляется в транзакцию и фиксируется сразу: неудача обязана пережить ответ
    (§8.1–§8.2), а счётчики окон фиксируются своим `commit()`-ом по правилу `ADR-007` («каждый
    лимитируемый запрос и каждая неудача стоят запись»).
    """
    failures = store.totp_failures(user.id, not_before=moment - TOTP_FAILURE_HORIZON)
    row, locked_until = register_totp_code_failure(user, failures, ip=address, now=moment)
    store.add(row)
    store.commit()
    banned = register_address_failure(store, address, moment=moment)
    return locked_until, banned


def _render_code(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    status_code: int,
    moment: datetime,
    note: str = LOCK_NOTE,
    recovery_note: str = "",
    locked_url: str | None = None,
) -> HTMLResponse:
    """Страница кода: форма ввода кода плюс объяснение состояния.

    `note` — постоянная часть (правило блокировки и одноразовости), `detail` — что произошло в этом
    запросе. Разделение нужно, чтобы отказ не вытеснял объяснение правил: человеку нужен и ответ на
    «что не так», и понимание, что будет дальше (§9). Материал сеанса в контекст не попадает.
    """
    context = {
        "page_title": "Код подтверждения",
        "detail": detail,
        "note": note,
        "window": _window_line(moment),
        "locked_url": locked_url,
        "code_url": TOTP_CODE_PATH,
        "enroll_url": MFA_ENROLL_PATH,
        "recovery_url": MFA_RECOVERY_PATH,
        "recovery_note": recovery_note,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "totp.html", context, status_code=status_code
    )
    return response


def _render_enroll(
    request: Request,
    principal: Principal,
    *,
    state: str,
    detail: str,
    status_code: int,
    moment: datetime,
    note: str = "",
    secret: str | None = None,
    qr: QrGraphic | None = None,
    codes: Sequence[str] = (),
    locked_url: str | None = None,
) -> HTMLResponse:
    """Страница первичной привязки в одном из состояний.

    `state` выбирает, какой блок формы показать: `start` — «начать привязку», `confirm` — форма двух
    кодов, `bound` — «привязка уже есть», `stale` — срок незавершённой привязки истёк. Состояние
    приходит из кода, а не из запроса: позволить параметром выбрать, какое объяснение показать, —
    значит попросить пользователя нарисовать себе чужое состояние.

    `secret` непустой ровно в одной ветке — сразу после `POST /mfa-enroll/start` (§8.2: «в UI больше не
    показывается»). Проверка «секрет выводит ровно один шаблон и ровно в одном месте» — контрактная.

    `qr` — картинка привязки (`R4d`), и она бывает непустой ровно там же, где и `secret`: в контекст
    кладутся только геометрия (`qr_path`, `qr_modules`), а не `otpauth://`-ссылка. Ни `GET`-страница
    привязки, ни состояние `stale`/`bound` картинки не получают: их сборка означала бы повторное
    расшифровывание `secret_enc` и второй вывод материала (§8.2, `ADR-015` п. 6).
    """
    context = {
        "page_title": "Привязка генератора кодов",
        "state": state,
        "detail": detail,
        "note": note,
        "secret": secret or "",
        "qr_path": qr.path_d if qr is not None else "",
        "qr_modules": qr.modules if qr is not None else 0,
        "window": _window_line(moment),
        "locked_url": locked_url,
        "start_url": MFA_ENROLL_START_PATH,
        "verify_url": MFA_ENROLL_VERIFY_PATH,
        "enroll_url": MFA_ENROLL_PATH,
        "code_url": TOTP_CODE_PATH,
        # Показные формы пачки резервных кодов (`ABCDE-FGHJK`): разделители — только показ, хэш
        # считается по канону (`ADR-016` п. 4). Непустым `codes` бывает ровно одно состояние
        # страницы — `issued`, то есть ответ `POST /mfa-enroll/verify` (`ADR-016` п. 2), и это
        # держит контрактная проверка.
        "codes": tuple(display_backup_code(code) for code in codes),
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "mfa_enroll.html", context, status_code=status_code
    )
    return response


def _code_denied(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    until: datetime,
    reason: str,
    moment: datetime,
) -> HTMLResponse:
    """Отказ «вход закрыт до срока» на странице кода: `429` + `Retry-After` + ссылка на `/locked`.

    Та же форма отказа, что на входе и при смене пароля (`ADR-007`, ask `ba6a9076`): различие только в
    тексте и в коде причины (`attempts` — закрыта учётная запись, `rate` — закрыт адрес). Один помощник
    нужен, чтобы `Retry-After` не «забывался» на очередной ветке, а код причины не брался из запроса:
    страница `/locked` объясняет оба состояния по закрытому набору (`display_reason_codes`).
    """
    response = _render_code(
        request,
        principal,
        detail=detail,
        status_code=429,
        moment=moment,
        locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={reason}",
    )
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


def _enroll_denied(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    until: datetime,
    reason: str,
    moment: datetime,
) -> HTMLResponse:
    """Тот же отказ на странице привязки: `429`, `Retry-After`, ссылка на `/locked`.

    Разница с `_code_denied` только в разметке: у страницы привязки своя форма, и отдать вместо неё
    страницу кода означало бы предложить человеку ввести код там, где привязки ещё нет.
    """
    response = _render_enroll(
        request,
        principal,
        state="bound",
        detail=detail,
        status_code=429,
        moment=moment,
        locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={reason}",
    )
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


def _rejection_answer(
    store: Store,
    user: User,
    address: str | None,
    *,
    moment: datetime,
    render: Callable[[str, int], HTMLResponse],
    denied: Callable[[str, datetime, str], HTMLResponse],
    failure_detail: str = CODE_FAILURE_DETAIL,
) -> Response:
    """Один ответ на любую неудачу кода: лента, окно адреса, затем — блокировки по порядку.

    `render` и `denied` выбирают страницу (код входа или привязка): тексты и коды отказов общие,
    разметки разные. `failure_detail` — текст «кода нет» для своей страницы: для резервного кода
    «возьмите новый код из окна» было бы неправдой (окна у него нет, а код одноразовый), и при этом
    сам отказ обязан оставаться одним для чужого, израсходованного и несуществующего значения
    (§8.8, `ADR-016` п. 5) — различаются подсказки, но не факт отказа. Порядок отказов закреплён и не «как получилось»: блокировка учётной записи важнее
    бана адреса, потому что у неё меньшая зона (одна учётная запись против адреса, за которым могут
    сидеть другие люди — `ADR-007` предупреждает, что коллективный ключ наказывает соседей), и человеку
    важнее узнать про свою учётную запись.

    Отдельно держится, что неудача зафиксирована **до** формирования ответа: `_register_failure_and_lock`
    двигает ленту и окна с их `commit()`-ами (счётчик обязан пережить запрос, §8.1–§8.2), а «полунеудача»
    невозможна, поскольку незакрытый транзакт откатывается закрытием соединения.
    """
    locked_until, banned = _register_failure_and_lock(store, user, address, moment=moment)
    if locked_until is not None:
        return denied(_lock_explanation(locked_until), locked_until, LOCK_REASON_ATTEMPTS)
    if banned is not None:
        return denied(_address_explanation(banned), banned, LOCK_REASON_RATE)
    return render(failure_detail, 401)


@router.get(TOTP_CODE_PATH, response_class=HTMLResponse)
def code_page(request: Request, principal: CodeSession, store: StoreDep) -> Response:
    """Страница ввода кода (§9.3 п. 2).

    Порядок:

    1. живая сессия шага `'password'`/`'totp'` — зависимостью `require_code_page_session`;
    2. подтверждённой привязки нет → редирект на первичную привязку: §9.3 держит `/mfa-enroll` во
       входной зоне ровно для этого случая, а предлагать вводить код учётной записи, которой нечего
       вводить, — значит показать страницу с заведомо неверным ответом навсегда;
    3. учётная запись заблокирована → та же страница кода с объяснением и ссылкой на `/locked`, но
       **без** `429`: этот код отвечает на запрос *войти*, а не на открытие страницы (у `GET /login`
       правило то же);
    4. счётчика частоты на `GET` нет: §8.3 ограничивает запросы-мутации, иначе одно обновление
       страницы расходовало бы лимит человека, который просто смотрит на форму.
    """
    moment = utc_now()
    enrollment = store.active_enrollment(principal.session.user_id)
    if enrollment is None or enrollment.confirmed_at is None:
        raise SessionRedirect(MFA_ENROLL_PATH)
    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    # Состояние резервных кодов читается и на `GET`: предупреждение §8.2 обязано быть видно до
    # попытки, а не только после отказа. Отдельного флага «коды выпущены» для этого нет —
    # состояние выводится из строк набора (`ADR-016` п. 6 и раздел «Решения заказчика» п. 1).
    grace = recovery_state(store.backup_code_rows(user.id), now=moment)
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _render_code(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            status_code=200,
            moment=moment,
            recovery_note=_recovery_note(grace),
            locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={LOCK_REASON_ATTEMPTS}",
        )
    detail = CONFIRM_NOTE if principal.session.auth_step == "totp" else ""
    return _render_code(
        request,
        principal,
        detail=detail,
        status_code=200,
        moment=moment,
        recovery_note=_recovery_note(grace),
    )


@router.post(TOTP_CODE_PATH, response_class=Response)
async def code_submit(request: Request, principal: CodeMutation, store: StoreDep) -> Response:
    """Код входа: проверка, расход шага, перевод на `'full'` (§8.2 шаг (2), `ADR-013`).

    Порядок шагов закреплён за §8.2, §8.3 и `ADR-008`/`ADR-007` и виден по цепочке зависимостей и по
    строкам ниже:

    1. токен (`require_csrf`) и предел частоты пользователя (`require_mutation_rate_limit`) —
       зависимостями: отказ токена не должен стоить обращений в базу и расхода лимита жертвы;
    2. шаг страницы (`require_code_page_mutation`) — последним, как у `require_full_mutation`;
    3. активный бан адреса (§8.2) — проверка чтения до всего остального;
    4. `totp_session` (10/мин/сессия) и `totp_ip` (5/мин/IP) — обе области §8.3, обе **до** криптографии:
       лимит, поставленный после проверки кода, от перебора не защищает;
    5. `ensure_login_allowed` до проверки кода: при активном блокировочном окне код не проверяется
       вообще (то же правило, что `T-101` держит для пароля);
    6. состояние привязки: кода без подтверждённой привязки не бывает → редирект на `/mfa-enroll`;
    7. пустое поле → `400` без записи в ленту неудач;
    8. проверка кода и **занятие шага одним guarded-`UPDATE`** (`store.claim_totp_step`) — два запроса
       с одним кодом не пройдут оба (§8.2 «коды принимаются один раз», `ADR-013`);
    9. успех: лента не чистится (`ADR-013` п. 4), шаг сессии поднимается до `'full'`, idle продляется,
       транзакция фиксируется, и только потом редирект.

    Файл ключей недоступен → `TwoFactorUnavailableError`, обработчик приложения отдаёт `503` с
    объяснением: неисправность площадки не должна выглядеть как «неверный код» и не имеет права
    двигать счётчик неудач учётной записи.
    """
    fields = await form_fields(request)
    code, _, _ = _codes_of(fields)
    moment = utc_now()
    address = session_ip(request)

    banned = ban_until(store, address, moment=moment)
    if banned is not None:
        return _code_denied(
            request,
            principal,
            detail=_address_explanation(banned),
            until=banned,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )
    try:
        enforce_scope(store, TOTP_SESSION_SCOPE, str(principal.session.id), moment=moment)
        enforce_scope(store, TOTP_IP_SCOPE, address, moment=moment)
    except RateLimitExceeded as exc:
        return _code_denied(
            request,
            principal,
            detail=_address_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )

    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _code_denied(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_ATTEMPTS,
            moment=moment,
        )

    enrollment = store.active_enrollment(user.id)
    if enrollment is None or enrollment.confirmed_at is None:
        raise SessionRedirect(MFA_ENROLL_PATH)

    # Просроченный семидневный срок перевыпуска блокирует именно этот переход — «пароль + код 2FA»,
    # и блокирует **до** криптографии: код не проверяется и не расходуется, потому что при просрочке
    # вход закрыт правилом §8.2, а не потому, что код неверный (`ADR-016` п. 6, решение заказчика от
    # 2026-11-22, ask `2f6bab2b`). Резервный путь эта проверка не перекрывает: он открыт ровно
    # тогда, когда есть неиспользованные строки, и проверяет это сам (`POST /mfa-recovery`).
    grace = recovery_state(store.backup_code_rows(user.id), now=moment)
    if grace.login_blocked:
        log.warning(
            "recovery_grace_expired",
            path=request.url.path,
            session_id=str(principal.session.id),
            deadline=(
                grace.regeneration_deadline.isoformat()
                if grace.regeneration_deadline is not None
                else ""
            ),
            spare=grace.unused,
        )
        return _render_code(
            request,
            principal,
            detail=GRACE_EXPIRED_DETAIL,
            status_code=403,
            moment=moment,
            recovery_note=_recovery_note(grace),
        )

    if not code:
        return _render_code(
            request, principal, detail=EMPTY_CODE_DETAIL, status_code=400, moment=moment
        )

    ring = request_key_ring(request)

    def claim(step: int) -> bool:
        """Занять шаг кода в той же транзакции запроса (`ADR-013`)."""
        return store.claim_totp_step(enrollment.id, step=step)

    result = verify_enrollment_code(enrollment, code, ring=ring, now=moment, claim=claim)
    if result.status != "accepted":
        log.warning(
            "totp_code_rejected",
            path=request.url.path,
            reason=result.status,
            session_id=str(principal.session.id),
        )
        return _rejection_answer(
            store,
            user,
            address,
            moment=moment,
            render=lambda detail, status_code: _render_code(
                request, principal, detail=detail, status_code=status_code, moment=moment
            ),
            denied=lambda detail, until, reason: _code_denied(
                request,
                principal,
                detail=detail,
                until=until,
                reason=reason,
                moment=moment,
            ),
        )

    advance_auth_step(principal.session, step="full", now=moment)
    touch_session(store, principal)
    return RedirectResponse(POST_CODE_REDIRECT, status_code=302)


# ─── первичная привязка ────────────────────────────────────────────────────────────────────────


@router.get(MFA_ENROLL_PATH, response_class=HTMLResponse)
def enroll_page(request: Request, principal: CodeSession, store: StoreDep) -> Response:
    """Страница первичной привязки (§9.3 п. 3) — состояние, а не действие.

    `GET` ничего не меняет: секрет не выдаётся, привязка не создаётся и не отзывается. Это не
    осторожность ради осторожности: страница открывает секрет наружу, поэтому единственный способ его
    получить — явная мутация `POST /mfa-enroll/start` с токеном (§8.3, `ADR-008`). Проверка
    «`GET /mfa-enroll` не содержит секрета» существует именно поэтому, и держит её контрактный тест.
    """
    moment = utc_now()
    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    enrollment = store.active_enrollment(user.id)
    state = enrollment_state(enrollment, now=moment) if enrollment is not None else "none"
    if state == "confirmed":
        return _render_enroll(
            request,
            principal,
            state="bound",
            detail=ALREADY_BOUND_DETAIL,
            status_code=200,
            moment=moment,
        )
    if state == "pending":
        return _render_enroll(
            request,
            principal,
            state="confirm",
            detail=ENROLL_ONCE_DETAIL,
            status_code=200,
            moment=moment,
            note=CONFIRM_NOTE,
        )
    if state == "expired":
        return _render_enroll(
            request,
            principal,
            state="stale",
            detail=STALE_ENROLLMENT_DETAIL,
            status_code=200,
            moment=moment,
        )
    return _render_enroll(
        request, principal, state="start", detail="", status_code=200, moment=moment
    )


@router.post(MFA_ENROLL_START_PATH, response_class=Response)
def enroll_start(request: Request, principal: CodeMutation, store: StoreDep) -> Response:
    """Выдать секрет привязки: создать привязку или заменить незавершённую (§8.2).

    Порядок:

    1. токен и предел частоты пользователя — зависимостями; шаг страницы — последней зависимостью;
    2. `ensure_login_allowed` до шифрования: при активном блокировочном окне новая привязка не
       создаётся (окно означает, что учётную запись подбирают);
    3. подтверждённая привязка есть → `409`: первичная привязка не служит перепривязкой. «Просто
       выдать новый секрет» означало бы сбросить второй фактор без действующего кода, а §8.2 требует
       для сброса администратора с записью в журнал — это маршрут зоны администрирования (§9.3 п. 6,
       допуск `T-106`);
    4. любая незавершённая привязка отзывается перед новой выдачей (и протухшая тоже — срок лишь
       причина менять её, но не условие отзыва). Без отзыва новый `INSERT` дал бы `UniqueViolation` по
       частичному индексу `ix_totp_enrollments_user_active` прямо посреди HTTP-запроса (замер
       2026-11-21, живая база);
    5. файл ключей открывается здесь, а не на `GET`: без него шифровать нечем, и отказ обязан быть у
       действия, а не у страницы.

    Секрет уходит в ответ ровно один раз: в базу он не пишется (там `secret_enc`), в лог не попадает и
    повторно этим маршрутом не выводится (§8.2 «в UI больше не показывается»).
    """
    moment = utc_now()
    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _enroll_denied(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_ATTEMPTS,
            moment=moment,
        )

    active = store.active_enrollment(user.id)
    if active is not None and active.confirmed_at is not None:
        return _render_enroll(
            request,
            principal,
            state="bound",
            detail=ALREADY_BOUND_DETAIL,
            status_code=409,
            moment=moment,
        )

    ring = request_key_ring(request)
    if active is not None:
        # Подтверждённой привязки здесь уже нет (она отклонена выше), поэтому отзыв обязателен в любом
        # случае: двух неотозванных привязок на учётку не бывает по частичному уникальному индексу
        # `ix_totp_enrollments_user_active`, и повторная выдача секрета без отзыва дала бы
        # `UniqueViolation` посреди HTTP-запроса (замер 2026-11-21 на живой базе). Протухшая запись
        # отзывается тем же вызовом: срок — только причина, по которой её стоит менять, но не условие
        # отзыва. Для пользователя это ещё и единственный способ начать заново: секрет повторно не
        # показывается (§8.2 «в UI больше не показывается»).
        revoke_enrollment(active, now=moment)
        store.commit()

    created = new_enrollment(user_id=user.id, now=moment, ring=ring)
    store.add(created.enrollment)
    store.commit()
    # Картинка строится из `created.secret` — того же значения, которое этот ответ показывает
    # для ручного ввода (`ADR-015` п. 6); порядок аргументов прямой, чтобы контракт не путал
    # передачу значения в картинку с передачей его в контекст страницы. Порядок «сначала
    # зафиксировали привязку, потом картинку» значим: отказ кодировщика не должен отменять уже
    # созданную привязку, а картинка — удобство, которого может не оказаться (§8.2 требует QR
    # и ручной ввод, а не вместо него).
    return _render_enroll(
        request,
        principal,
        state="confirm",
        detail="",
        status_code=200,
        moment=moment,
        note=CONFIRM_NOTE,
        secret=created.secret,
        qr=_qr_of_enrollment(created.secret, user.login, created.enrollment.issuer),
    )


@router.post(MFA_ENROLL_VERIFY_PATH, response_class=Response)
async def enroll_verify(request: Request, principal: CodeMutation, store: StoreDep) -> Response:
    """Подтвердить привязку двумя последовательными кодами (§8.2) и поднять шаг до `'totp'`.

    Порядок повторяет порядок страницы кода: бан адреса, обе области §8.3 (попытка подтверждения —
    тоже попытка перебора по коду), предел пользователя зависимостью, шаг страницы, блокировка
    учётной записи до криптографии, состояние привязки, пустая форма — и только потом два кода.

    Успех не даёт доступа в консоль намеренно (§8.2 шаг (2), `ADR-015` п. 3): сессия переходит на
    `'totp'` и уходит на страницу кода за **новым** кодом, потому что коды подтверждения израсходованы
    тем же механизмом одноразовости, что и вход.

    Неудача двигает ленту `totp_failures` и окно `ip_ban` на тех же основаниях, что и неудача входа:
    §8.2 считает попытки кода, а не «попытки на конкретной странице».
    """
    fields = await form_fields(request)
    _, first, second = _codes_of(fields)
    moment = utc_now()
    address = session_ip(request)

    banned = ban_until(store, address, moment=moment)
    if banned is not None:
        return _enroll_denied(
            request,
            principal,
            detail=_address_explanation(banned),
            until=banned,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )
    try:
        enforce_scope(store, TOTP_SESSION_SCOPE, str(principal.session.id), moment=moment)
        enforce_scope(store, TOTP_IP_SCOPE, address, moment=moment)
    except RateLimitExceeded as exc:
        return _enroll_denied(
            request,
            principal,
            detail=_address_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )

    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _enroll_denied(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_ATTEMPTS,
            moment=moment,
        )

    enrollment = store.active_enrollment(user.id)
    if enrollment is None:
        return _render_enroll(
            request,
            principal,
            state="start",
            detail=NO_ENROLLMENT_DETAIL,
            status_code=400,
            moment=moment,
        )
    if enrollment.confirmed_at is not None:
        return _render_enroll(
            request,
            principal,
            state="bound",
            detail=ALREADY_BOUND_DETAIL,
            status_code=409,
            moment=moment,
        )
    if enrollment_state(enrollment, now=moment) == "expired":
        return _render_enroll(
            request,
            principal,
            state="stale",
            detail=STALE_ENROLLMENT_DETAIL,
            status_code=400,
            moment=moment,
        )
    if not first or not second:
        return _render_enroll(
            request,
            principal,
            state="confirm",
            detail=EMPTY_CODE_DETAIL,
            status_code=400,
            moment=moment,
            note=CONFIRM_NOTE,
        )

    ring = request_key_ring(request)
    try:
        result = confirm_enrollment(enrollment, first, second, ring=ring, now=moment)
    except TotpEnrollmentError as exc:
        # Состояние изменилось между чтением и проверкой (привязку отобрали параллельно): это не
        # неудача подбора, а исчезновение объекта — редирект на страницу привязки без записи в ленту.
        log.info("totp_enrollment_vanished", path=request.url.path, detail=str(exc))
        raise SessionRedirect(MFA_ENROLL_PATH) from exc

    if result.status != "accepted":
        log.warning(
            "totp_confirm_rejected",
            path=request.url.path,
            reason=result.status,
            session_id=str(principal.session.id),
        )
        return _rejection_answer(
            store,
            user,
            address,
            moment=moment,
            render=lambda detail, status_code: _render_enroll(
                request,
                principal,
                state="confirm",
                detail=detail,
                status_code=status_code,
                moment=moment,
                note=CONFIRM_NOTE,
            ),
            denied=lambda detail, until, reason: _enroll_denied(
                request,
                principal,
                detail=detail,
                until=until,
                reason=reason,
                moment=moment,
            ),
        )

    # Пачка резервных кодов выпускается здесь и больше нигде (§8.2, `ADR-016` п. 2, решение
    # заказчика от 2026-11-22, ask `2f6bab2b`): значения показываются ровно в этом ответе, а в базе
    # остаются только хэши. Порядок обращений к слою доступа значим: сначала аннулирование
    # неиспользованных остатков прежней пачки, затем вставка новой. Наоборот — нельзя: аннулирование
    # идёт по предикату `used_at IS NULL` и, вызванное после вставки, задевает и новую пачку,
    # то есть оставляет учётную запись без единого рабочего кода. Это проверяет живой файл
    # `tests/integration/test_backup_codes_db.py` (job `миграции`).
    #
    # Открытые значения в слой не передаются никогда: хэши считаются здесь, между генерацией и
    # показом (`ADR-016` п. 3, п. 7). `superseded == 0` при первом выпуске — норма, а не ошибка:
    # прежней пачки ещё нет.
    codes = new_backup_codes()
    superseded = store.invalidate_unused_backup_codes(user.id)
    store.insert_backup_code_hashes(user.id, tuple(hash_backup_code(code) for code in codes))
    log.info(
        "backup_codes_issued",
        user_id=str(user.id),
        session_id=str(principal.session.id),
        count=len(codes),
        superseded=superseded,
    )

    advance_auth_step(principal.session, step="totp", now=moment)
    touch_session(store, principal)
    # Не редирект, а страница: значения пачки живут только в этом ответе, а redirect обязан был бы
    # либо выбросить их, либо выести в параметр адреса (след в access-логе прокси и в истории
    # браузера — `ADR-016` п. 11 про «показ обязан быть один раз»). Шаг `'totp'` при этом подняан,
    # и ссылка на странице ведёт на `GET /totp` за **новым** кодом входа: коды подтверждения
    # израсходованы (`ADR-015` п. 3).
    return _render_enroll(
        request,
        principal,
        state="issued",
        detail="",
        status_code=200,
        moment=moment,
        note=CONFIRM_NOTE,
        codes=codes,
    )


# ─── резервный код входа (§9.3 п. 3, `ADR-016` п. 6, 7, 9; `T-104`, срез `R5c`) ────────────


def _render_recovery(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    status_code: int,
    note: str = RECOVERY_NOTE,
    warning: str = "",
    spare: int = 0,
    spent: bool = False,
    form: bool = True,
    locked_url: str | None = None,
) -> HTMLResponse:
    """Страница расхода резервного кода (§9.3 п. 3: «расход резервного кода + предупреждение»).

    `spare` — сколько неиспользованных кодов у этой учётной записи. Это описание её набора, а не
    предъявленного значения: различий «кода нет» / «код чужой» / «код уже потрачен» в ответе на
    отказ нет намеренно (§8.8, `ADR-016` п. 5), и `spare` их не вносит.

    `spent` — успех: форма больше не нужна (сессия уже на шаге `'full'`, и повторить расход нечем),
    а предупреждение §8.2 обязано остаться в том же ответе, где код был истрачен: редирект в
    консоль выбросил бы его, а консоль в вехе M1 ещё не построена (§9.3 п. 3 держит предупреждение
    именно на этой странице).
    """
    context = {
        "page_title": "Резервный код входа",
        "detail": detail,
        "note": note,
        "warning": warning,
        "spare": spare,
        "spent": spent,
        "form": form,
        "recovery_url": MFA_RECOVERY_PATH,
        "code_url": TOTP_CODE_PATH,
        "console_url": POST_CODE_REDIRECT,
        "locked_url": locked_url,
    } | csrf_context(principal)
    response: HTMLResponse = request.app.state.templates.TemplateResponse(
        request, "mfa_recovery.html", context, status_code=status_code
    )
    return response


def _recovery_denied(
    request: Request,
    principal: Principal,
    *,
    detail: str,
    until: datetime,
    reason: str,
    moment: datetime,
    spare: int = 0,
) -> HTMLResponse:
    """Тот же отказ «вход закрыт до срока» на странице резервного кода: `429` + `Retry-After`.

    Форма отказа общая со страницей кода и входа (`ADR-007`, ask `ba6a9076`): различие только в
    разметке, потому что отдать вместо этой формы страницу кода означало бы предложить человеку
    вводить код из генератора там, где генератор у него как раз и не работает.
    """
    response = _render_recovery(
        request,
        principal,
        detail=detail,
        status_code=429,
        spare=spare,
        locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={reason}",
    )
    response.headers["Retry-After"] = str(retry_after_seconds(until, moment))
    return response


@router.get(MFA_RECOVERY_PATH, response_class=HTMLResponse)
def recovery_page(request: Request, principal: CodeSession, store: StoreDep) -> Response:
    """Страница резервного кода (§9.3 п. 3) — состояние, а не действие.

    Порядок — как у страницы кода, и основания те же:

    1. живая сессия шага `'password'`/`'totp'` — зависимостью `require_code_page_session`; полная
       сессия уходит в консоль: расход кода и есть шаг полной аутентификации (`ADR-016` п. 9),
       повторить его нечем;
    2. подтверждённой привязки нет → редирект на `/mfa-enroll`: у учётной записи без привязки не
       бывает выпущенной пачки, и предлагать форму с заведомо неверным ответом нельзя;
    3. блокировка перебором → объяснение без `429` (тот же порядок, что у `GET /totp`: этот код
        отвечает на запрос *войти*, а не на открытие страницы);
    4. неиспользованных кодов нет → форма не показывается: вводить нечего, а состояние обязано
       быть объяснено (§9), в том числе с принятым риском `ADR-016` п. 6;
    5. счётчики частоты на `GET` не тратятся (§8.3 считает мутации).

    Файл ключей здесь не читается намеренно: резервному коду нечего расшифровывать, и это его
    смысл — путь остаётся работающим и тогда, когда страница кода отвечает `503` из-за недоступного
    `kek.json` (`ADR-015` п. 7).
    """
    moment = utc_now()
    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    enrollment = store.active_enrollment(user.id)
    if enrollment is None or enrollment.confirmed_at is None:
        raise SessionRedirect(MFA_ENROLL_PATH)
    state = recovery_state(store.backup_code_rows(user.id), now=moment)
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _render_recovery(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            status_code=200,
            warning=_recovery_note(state),
            spare=state.unused,
            locked_url=f"{LOCKED_PATH}?{REASON_QUERY}={LOCK_REASON_ATTEMPTS}",
        )
    if state.unused == 0:
        return _render_recovery(
            request,
            principal,
            detail=NO_SPARE_CODE_DETAIL,
            status_code=200,
            warning=_recovery_note(state),
            spare=0,
            form=False,
        )
    return _render_recovery(
        request,
        principal,
        detail="",
        status_code=200,
        warning=_recovery_note(state),
        spare=state.unused,
    )


@router.post(MFA_RECOVERY_PATH, response_class=Response)
async def recovery_submit(request: Request, principal: CodeMutation, store: StoreDep) -> Response:
    """Расход резервного кода: канон, поиск среди неиспользованных, guarded-переход, `'full'`.

    Начало порядка общее со страницей кода: токен и предел мутаций пользователя — зависимостью,
    шаг страницы — последней зависимостью, затем активный бан адреса (§8.2), обе области лимита
    кода (§8.3), блокировка учётной записи и состояние привязки. Основания для общих счётчиков —
    `ADR-016` п. 8: §8.2 считает попытки **второго фактора**, а не поля формы, и раздельные
    счётчики дали бы 5 + 5 попыток с обходом блокировки чередованием полей.

    Дальше — сам расход, в порядке `ADR-016` п. 7:

    1. пустая форма и отказ по формату — `400` **без** строки в ленте неудач: пустое поле и набор
       знаков вне алфавита не являются попыткой угадать значение, и не должны приближать
       блокировку (§8.2, `ADR-016` п. 5);
    2. канон и хэш (`hash_backup_code` сам вызывает `normalize_backup_code`) — иначе «тот же код,
       перенесённый из показа `ABCDE-FGHJK`» сжёг бы попытку (п. 4 там же);
    3. поиск строго среди неиспользованных строк своей учётной записи
       (`find_unused_backup_code`) — иначе страница различила бы «такого кода нет» и «такой код
       уже потрачен», то есть стала бы оракулом для того, кто подсмотрел экран при выпуске пачки
       (п. 3 и п. 5);
    4. guarded-`UPDATE` расхода (`spend_backup_code`), успех только при `rowcount == 1` — «нашёл,
       пометил» в двух запросах израсходовало бы один код дважды (п. 7; обязательная живая
       `test_backup_code_single_use`). Отказ перехода неотличим для человека от «кода нет»,
       различие уходит в лог (`found`);
    5. перевод сессии на `'full'` — шаг полной аутентификации (§8.2 «расход кода = шаг полной
       аутентификации», `ADR-016` п. 9), не промежуточное состояние: `password` → `full` допустим
       прямо (`packages/identity/sessions.advance_auth_step`).

    Просроченный семидневный срок здесь **не** блокирует запрос: блокировка живёт на переходе
    «пароль + код 2FA» (`code_submit`), а резервный путь открыт ровно тогда, когда есть
    неиспользованные строки, — это проверяет поиск на шаге 3, а не отдельный флаг (решение
    заказчика от 2026-11-22, ask `2f6bab2b`, `ADR-016` п. 6).

    Отдельно: счётчики `totp_session`/`totp_ip` — те же области, что у страницы кода. Новой
    области в закрытом перечне схемы (`packages.storage.models.RATE_SCOPES`, CHECK `0003`) нет, и
    заводить её под резервный код нельзя без новой ревизии и отдельного решения заказчика: §8.3
    называет лимиты для `/totp`, а резервный код — та же попытка второго фактора (п. 8 того же
    ADR), значит и частота общая.
    """
    fields = await form_fields(request)
    raw = fields.get(FIELD_BACKUP_CODE, "").strip()[:MAX_BACKUP_CODE_CHARS]
    moment = utc_now()
    address = session_ip(request)

    banned = ban_until(store, address, moment=moment)
    if banned is not None:
        return _recovery_denied(
            request,
            principal,
            detail=_address_explanation(banned),
            until=banned,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )
    try:
        enforce_scope(store, TOTP_SESSION_SCOPE, str(principal.session.id), moment=moment)
        enforce_scope(store, TOTP_IP_SCOPE, address, moment=moment)
    except RateLimitExceeded as exc:
        return _recovery_denied(
            request,
            principal,
            detail=_address_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_RATE,
            moment=moment,
        )

    user = store.user_of_id(principal.session.user_id)
    if user is None:
        return _account_gone()
    try:
        ensure_login_allowed(user, now=moment)
    except LoginLockedError as exc:
        return _recovery_denied(
            request,
            principal,
            detail=_lock_explanation(exc.until),
            until=exc.until,
            reason=LOCK_REASON_ATTEMPTS,
            moment=moment,
        )

    enrollment = store.active_enrollment(user.id)
    if enrollment is None or enrollment.confirmed_at is None:
        raise SessionRedirect(MFA_ENROLL_PATH)

    if not raw:
        return _render_recovery(
            request, principal, detail=EMPTY_BACKUP_CODE_DETAIL, status_code=400
        )
    try:
        code_hash = hash_backup_code(raw)
    except BackupCodeFormatError as exc:
        # Значения в журнале нет: текст отказа их не содержит (`ADR-016` п. 4), а в лог уходит
        # только причина.
        log.info(
            "backup_code_format_rejected",
            path=request.url.path,
            session_id=str(principal.session.id),
            detail=str(exc),
        )
        return _render_recovery(request, principal, detail=RECOVERY_FORMAT_DETAIL, status_code=400)

    # Снимок набора до расхода: он нужен и для объяснения страницы, и для честного остатка после
    # guarded-`UPDATE` (после него строка в identity map не обновляется — см.
    # `_recovery_warning_after_spend`).
    spare = recovery_state(store.backup_code_rows(user.id), now=moment).unused

    row = store.find_unused_backup_code(user_id=user.id, code_hash=code_hash)
    spent = row is not None and store.spend_backup_code(code_id=row.id, user_id=user.id)
    if not spent:
        log.warning(
            "backup_code_rejected",
            path=request.url.path,
            session_id=str(principal.session.id),
            # `found=True` означает «неиспользованный найден, но guarded-переход отказал»: его
            # израсходовали параллельно. Для человека это тот же отказ, для разбора — другая
            # причина, и она не должна уезжать в ответ (§8.8).
            found=row is not None,
        )
        return _rejection_answer(
            store,
            user,
            address,
            moment=moment,
            render=lambda detail, status_code: _render_recovery(
                request,
                principal,
                detail=detail,
                status_code=status_code,
                spare=spare,
            ),
            denied=lambda detail, until, reason: _recovery_denied(
                request,
                principal,
                detail=detail,
                until=until,
                reason=reason,
                moment=moment,
                spare=spare,
            ),
            failure_detail=RECOVERY_FAILURE_DETAIL,
        )

    advance_auth_step(principal.session, step="full", now=moment)
    touch_session(store, principal)
    spare_left = max(spare - 1, 0)
    log.info(
        "backup_code_spent",
        user_id=str(user.id),
        session_id=str(principal.session.id),
        spare_left=spare_left,
    )
    return _render_recovery(
        request,
        principal,
        detail=RECOVERY_SPENT_DETAIL,
        status_code=200,
        warning=_recovery_warning_after_spend(spare_left, moment),
        spare=spare_left,
        spent=True,
    )
