"""Механизм прикладных лимитов частоты запросов (TZ §8.2, §8.3; `docs/adr/ADR-007`; `T-102`, срез `R3d`).

Таблица счётчика (`rate_buckets`, ревизия `0003`) была готова раньше — этот модуль подключает её к
HTTP-слою: области, окно, инкремент, отказ `429` с `Retry-After` и бан адреса из §8.2. Ни одного
счётчика в памяти процесса здесь нет, и это не стиль, а требование `ADR-007`: память обнуляется при
`docker restart` и не согласуется между процессами, то есть «10 запросов в минуту на IP» перестаёт
быть лимитом по IP.

Что закреплено модулем:

* **области — закрытый перечень схемы** (`packages.storage.models.RATE_SCOPES`). Значение
  `ip_ban` к лимитам §8.3 не относится: это окно перебора §8.2, и держит его приложение
  (ask `abb0151c`). «Добавить новую область» без ревизии нельзя — CHECK схемы отклонит запись.
* **окно выравнивает приложение** (`ADR-007`, комментарий к колонке `window_start`). Без
  выравнивания один и тот же интервал дал бы несколько строк, и счётчик перестал бы считаться.
  Для 60 секунд это начало минуты, для 300 — пятиминутка от полуночи UTC: эпоха кратна обеим
  длительностям, поэтому граница окна не зависит от момента запуска процесса.
* **адрес — из правого элемента `X-Forwarded-For`** (см. `apps/web/security/clients.py`). Ключ
  счётчика и значение `sessions.ip` считает одна функция, иначе «блокируем» один адрес, а
  «смотрим» другой.
* **ключа нет — лимита нет.** Если адрес не определён (запрос без `X-Forwarded-For`, то есть
  обращение к `web` мимо Caddy), счётчик не заводится: общий ключ «пустой адрес» означал бы бан
  всех, у кого заголовка не было (`ADR-009`). В боевом стенде такого пути нет — `web` наружу не
  публикуется, и проверка этого входит в контрактные тесты деплой-артефактов.
* **срок бана — не колонка** (`ADR-009`, ask `c53daa01`): он выводится из строки как
  `window_start + window_seconds + IP_BAN_DURATION`. Следствие осознанное: бан, выданный в начале
  окна, длится дольше 15 минут (окно ещё не закрылось) — от 15 до 20 минут. Колонку `ban_until`
  добавлять нельзя без нового решения заказчика.
* **счётчик фиксируется сразу** (`store.commit()` внутри инкремента). Отказ, который не записан в
  счётчик, — это отказ, который ничего не стоил атакующему; кроме того, оператор обязан видеть
  реальный объём попыток в таблице, а не «до последнего успешного запроса».
* **отказ частоты и бан адреса пишутся в журнал здесь** (`ADR-007`, `ADR-009` п. 4, `T-109`
  срез `R2`): имена `auth.rate_limited` и `auth.address_banned` из закрытого реестра §8.7. Место —
  этот модуль, а не обработчики `429` в `apps/web/main.py`: маршруты входа и 2FA ловят
  `RateLimitExceeded` сами и отвечают страницей `/locked`, поэтому у обработчика «все остальные
  маршруты» события бы не было ни для одной попытки входа. Запись идёт сразу после `commit()`
  счётчика и своей отдельной фиксацией: `ADR-025` п. 6 требует, чтобы «попытка, приведшая к
  отказу» не зависела от бизнес-транзакции, которая в этом случае ничего не меняла.

Чего здесь сознательно нет:

* `/totp` — маршрута ещё нет (`T-103`). Области `totp_session` и `totp_ip` с лимитами §8.3 уже
  описаны в `RATE_LIMITS`, чтобы у `T-103` была одна правка: вызов `enforce_scope` в маршруте,
  а не изобретение механизма заново;
* проверки бана в middleware: зона отказа — только слой входа (ask `ba6a9076`), иначе «бан IP»
  молча превратился бы в блокировку всего сайта для всех, кто сидит за провайдерским NAT.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

from apps.web.store import Store
from packages.common.clock import to_utc, utc_now
from packages.storage.models import (
    RATE_BAN_WINDOW_SECONDS,
    RATE_WINDOW_SECONDS,
    RATE_WINDOWS,
)

# ─── области и пределы (§8.3, §8.2) ────────────────────────────────────────────────────────────

#: Области из §8.3: `/login` — 10 запросов/мин/IP, `/totp` — 10/мин/сессия и 5/мин/IP, все
#: mutation-эндпоинты — 60/мин/пользователь. Ключи обязаны совпадать с `RATE_SCOPES` схемы
#: (проверка `tests/contract/test_rate_limit_mechanism.py`): расхождение дало бы `23514` на первом
#: же запросе, и выяснилось бы это на площадке.
LOGIN_IP_SCOPE: Final = "login_ip"
TOTP_SESSION_SCOPE: Final = "totp_session"
TOTP_IP_SCOPE: Final = "totp_ip"
MUTATION_USER_SCOPE: Final = "mutation_user"

#: Окно перебора §8.2 («3 неудачные попытки с одного IP за 5 минут»). К лимитам частоты
#: отношения не имеет: это условие блокировки, а не предел запросов в минуту.
IP_BAN_SCOPE: Final = "ip_ban"

#: Пределы по областям. Считаются запросы, а не неудачи: §8.3 формулирует лимиты как «запросов»,
#: и пустая форма, и отказ CSRF стоят обращения — иначе счётчик обходят мусорными запросами.
#: Значения взяты из текста §8.3 буквально и проверяются контрактным тестом по ТЗ.
RATE_LIMITS: Final[Mapping[str, int]] = {
    LOGIN_IP_SCOPE: 10,
    TOTP_SESSION_SCOPE: 10,
    TOTP_IP_SCOPE: 5,
    MUTATION_USER_SCOPE: 60,
}

#: §8.2: «3 неудачные попытки с одного IP за 5 минут → временный бан IP». Порог — число попыток,
#: при котором бан наступает (сравнение `attempts >= IP_BAN_THRESHOLD`).
IP_BAN_THRESHOLD: Final = 3

#: Домен объекта для строки журнала (`ADR-025` п. 2: `entity` — домен действия, `entity_id` —
#: идентификатор внутри домена). Ключ счётчика и есть тот объект, которого коснулся отказ: у
#: `login_ip` и `totp_ip` это адрес, у `totp_session` — сеанс, у `mutation_user` — учётная запись.
#: Без этого поля строка «отказано в лимите» не отвечала бы на вопрос, кому именно (§8.7 требует
#: субъекта и объекта).
RATE_AUDIT_ENTITY: Final[Mapping[str, str]] = {
    LOGIN_IP_SCOPE: "ip",
    TOTP_IP_SCOPE: "ip",
    TOTP_SESSION_SCOPE: "session",
    MUTATION_USER_SCOPE: "user",
}

#: Срок бана адреса — 15 минут (ask `ba6a9076`). Отдельная константа, а не `LOCK_DURATION`
#: из `packages/identity/users.py`: значения совпадают намеренно, но это два разных решения
#: (блокировка учётной записи и бан адреса), и правка одного не должна молча менять другое.
#: Константа кода, а не настройка — то же правило, что у сроков сессий
#: (`test_sessions_contract.py`, «константы сроков не являются настройкой»).
IP_BAN_DURATION: Final = timedelta(minutes=15)

#: Самое широкое окно из допустимых схемой: нижняя граница поиска банов считается по нему, чтобы
#: не отбросить строку, у которой окно больше (точный пересчёт — по `window_seconds` строки).
_WIDEST_WINDOW_SECONDS: Final = max(RATE_WINDOWS)


# ─── окно ──────────────────────────────────────────────────────────────────────────────────────


class RateLimitExceeded(Exception):
    """Предел области исчерпан либо адрес закрыт баном (§8.2, §8.3).

    `until` — момент, после которого попытка снова законна; `retry_after` — те же секунды целым
    числом для заголовка `Retry-After` (`ADR-007`: код обязан быть именно `429`, а заголовок —
    частью ответа, по нему и UI, и тесты видят, сколько ждать).
    """

    def __init__(self, *, scope: str, until: datetime, retry_after: int) -> None:
        super().__init__(f"предел области {scope!r} исчерпан; повторно после {until.isoformat()}")
        self.scope = scope
        self.until = until
        self.retry_after = retry_after


def align_window_start(moment: datetime, window_seconds: int) -> datetime:
    """Начало окна длительности `window_seconds`, содержащего `moment`.

    Ровняет приложение (`ADR-007`, комментарий к колонке `window_start`): схема начало окна не
    выбирает, и если бы его подставлял каждый запрос, один интервал дал бы несколько строк — лимит
    перестал бы считаться. Микросекунды отбрасываются: граница окна не может быть «между» двумя
    запросами одного момента.
    """
    if window_seconds <= 0:
        raise ValueError(f"длительность окна обязана быть положительной: {window_seconds}")
    moment = to_utc(moment)
    epoch_seconds = int(moment.timestamp())
    return datetime.fromtimestamp(epoch_seconds - (epoch_seconds % window_seconds), UTC)


def retry_after_seconds(until: datetime, moment: datetime) -> int:
    """Секунды до `until`: не меньше одной, иначе клиент решит, что повторить можно немедленно."""
    return max(math.ceil((to_utc(until) - to_utc(moment)).total_seconds()), 1)


# ─── лимиты частоты (§8.3) ─────────────────────────────────────────────────────────────────────


def enforce_scope(
    store: Store,
    scope: str,
    bucket_key: str | None,
    *,
    moment: datetime | None = None,
) -> None:
    """Увеличить окно области и отказать, если счётчик превысил предел.

    Лимит разрешает ровно `RATE_LIMITS[scope]` запросов в окне: отказ наступает на следующем
    (`attempts > limit`), а не на последнем разрешённом.

    Вызывается **до** того, как обработчик изменил состояние: инкремент фиксируется своим
    `commit()`-ом и попутно фиксирует всё, что уже накоплено в транзакции. Порядок выключен
    намеренно — иначе отказ «лимит исчерпан» ничего не стоил бы атакующему (см. модульный
    докстринг).

    Отказ остаётся в журнале (`auth.rate_limited`, §8.7) до того, как поднято исключение:
    событие фиксируется отдельной транзакцией (`commit_now=True`) и тем же моментом `now`, что и
    окно счётчика, — разбор должен показывать ту же попытку, что и строка `rate_buckets`, а не
    попытку на микросекунду позже (`ADR-025` п. 2: момент снимается один раз на событие).
    `actor` у строки отсутствует намеренно: отказ частоты случается до аутентификации, а
    выдуманного субъекта журнал не терпит (`ADR-025` п. 2: `NULL` для событий без субъекта).
    """
    limit = RATE_LIMITS[scope]
    if bucket_key is None:
        # Адрес (или субъект) не определён — счётчика нет. Общего ключа «неизвестно кто» нет
        # намеренно: он дал бы один глобальный лимит и бан всех причастных (`ADR-009`).
        return
    now = moment or utc_now()
    window_start = align_window_start(now, RATE_WINDOW_SECONDS)
    attempts = store.bump_rate_bucket(
        scope=scope,
        bucket_key=bucket_key,
        window_start=window_start,
        window_seconds=RATE_WINDOW_SECONDS,
    )
    store.commit()
    if attempts > limit:
        window_end = window_start + timedelta(seconds=RATE_WINDOW_SECONDS)
        store.append_audit(
            action="auth.rate_limited",
            at=now,
            entity=RATE_AUDIT_ENTITY[scope],
            entity_id=bucket_key,
            # Для адресных областей адрес счётчика и есть адрес события: §8.7 требует IP в
            # строке, а `ADR-009` — чтобы «кого блокируем» и «кого показываем» были одним адресом.
            # Для `totp_session` и `mutation_user` ключ адресом не является, и там адрес подставит
            # контекст запроса (`apps/web/store.py`).
            ip=bucket_key if RATE_AUDIT_ENTITY[scope] == "ip" else None,
            details={
                "scope": scope,
                "attempts": attempts,
                "limit": limit,
                "window_start": window_start.isoformat(timespec="seconds"),
                "retry_after": retry_after_seconds(window_end, now),
            },
            commit_now=True,
        )
        raise RateLimitExceeded(
            scope=scope,
            until=window_end,
            retry_after=retry_after_seconds(window_end, now),
        )


# ─── бан адреса (§8.2) ─────────────────────────────────────────────────────────────────────────


def _ban_search_boundary(moment: datetime) -> datetime:
    """Нижняя граница `window_start` при поиске банов.

    Граница берётся по самому широкому допустимому окну, чтобы не отбросить строку с бо́льшим
    окном; решение о том, актуален ли бан, принимается по `window_seconds` самой строки.
    """
    return moment - IP_BAN_DURATION - timedelta(seconds=_WIDEST_WINDOW_SECONDS)


def ban_until(
    store: Store, address: str | None, *, moment: datetime | None = None
) -> datetime | None:
    """До какого момента адрес закрыт на вход, либо `None`, если бан не активен.

    Активное окно — то, где счётчик неудач не меньше `IP_BAN_THRESHOLD` и где ещё не истёк срок,
    посчитанный от самой строки: `window_start + window_seconds + IP_BAN_DURATION` (`ADR-009`).
    Отдельной колонки со сроком в схеме нет, и добавлять её нельзя без нового решения заказчика.

    Смысл проверки именно в чтении базы: бан обязан переживать рестарт контейнера и действовать для
    запросов, попавших в другой процесс.
    """
    if address is None:
        return None
    now = moment or utc_now()
    window = store.newest_counted_window(
        scope=IP_BAN_SCOPE,
        bucket_key=address,
        min_attempts=IP_BAN_THRESHOLD,
        window_start_after=_ban_search_boundary(now),
    )
    if window is None:
        return None
    until = window.window_start + timedelta(seconds=window.window_seconds) + IP_BAN_DURATION
    return until if until > now else None


def register_address_failure(
    store: Store, address: str | None, *, moment: datetime | None = None
) -> datetime | None:
    """Учесть неудачу входа с адреса в окне `ip_ban` (300 с) и вернуть срок бана, если он наступил.

    Считаются **неудачи**, а не запросы: успешный вход не должен приближать блокировку адреса.
    Неудача по неизвестному логину тоже считается (§8.2 говорит «3 неудачные попытки с одного IP»,
    не «по одной учётной записи») — иначе переборщик обходил бы окно, меняя логины.

    Срок возвращается по текущему окну, и повторного чтения не требуется: у окон одной области
    одинаковая длительность, а `window_start` текущего окна самый свежий, поэтому его срок и есть
    ближайший «когда разбанят».

    Само наступление бана пишется в журнал (`auth.address_banned`, §8.7, `ADR-009` п. 4) ровно
    один раз на окно — в момент пересечения порога. Писать на каждую последующую неудачу
    означало бы множить строки о событии, которое уже произошло: срок бана при этом не меняется,
    а разбор показал бы «забанен снова» там, где бан просто продолжается.
    """
    if address is None:
        return None
    now = moment or utc_now()
    window_start = align_window_start(now, RATE_BAN_WINDOW_SECONDS)
    attempts = store.bump_rate_bucket(
        scope=IP_BAN_SCOPE,
        bucket_key=address,
        window_start=window_start,
        window_seconds=RATE_BAN_WINDOW_SECONDS,
    )
    store.commit()
    if attempts < IP_BAN_THRESHOLD:
        return None
    until = window_start + timedelta(seconds=RATE_BAN_WINDOW_SECONDS) + IP_BAN_DURATION
    if attempts == IP_BAN_THRESHOLD:
        store.append_audit(
            action="auth.address_banned",
            at=now,
            entity="ip",
            entity_id=address,
            details={
                "scope": IP_BAN_SCOPE,
                "attempts": attempts,
                "threshold": IP_BAN_THRESHOLD,
                "until": until.isoformat(timespec="seconds"),
            },
            commit_now=True,
        )
    return until


__all__ = [
    "IP_BAN_DURATION",
    "IP_BAN_SCOPE",
    "IP_BAN_THRESHOLD",
    "LOGIN_IP_SCOPE",
    "MUTATION_USER_SCOPE",
    "RATE_AUDIT_ENTITY",
    "RATE_LIMITS",
    "TOTP_IP_SCOPE",
    "TOTP_SESSION_SCOPE",
    "RateLimitExceeded",
    "align_window_start",
    "ban_until",
    "enforce_scope",
    "register_address_failure",
    "retry_after_seconds",
]
