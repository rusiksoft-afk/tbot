"""Порог уведомлений §8.7: когда событие заслуживает «уведомить», а когда — промолчать.

Второй абзац TZ §8.7 требует уведомлений администратору по пяти поводам: «вход нового
пользователя (новый IP/устройство), расход резервного кода, изменение лимитов риска, отзыв
токена, включение kill-switch». Порогов техзадание не формулирует, а §10.1 требует агрегации при
массовых событиях. Этот модуль и есть то место, где пороги формулируются: здесь нет ни SQL, ни
HTTP, ни колонок — только решение («уведомить» или «промолчать»), причина решения и ключ
деидентификации повода (`ADR-028` п. 5–6).

**Почему правила живёт здесь, а не в слое доступа.** У порога два исполнителя путей: запись
решения делает общий слой `packages/storage/audit_store.py` (его читают и `web`, и `jobs`), а
решение принимает домен. Если бы порог сидел в слое доступа, второй писатель (процесс `jobs`,
когда транспорт появится) пересчитал бы его второй реализацией — а расхождение двух порогов
выглядит как «то же событие в разных местах дало разные решения», и обнаруживается это только
разбором таблицы. Тот же порядок, что с правилами цепочки журнала: правила — в
`packages/identity/audit.py`, SQL — в `packages/storage/audit_store.py`.

**Почему решение — пара «вердикт + причина», а не одно слово.** Строка `muted` обязана
существовать: без неё «порог промолчал» неотличимо от «события не было», и раздел
администрирования не смог бы показать, что шум подавлен намеренно (`ADR-028` п. 4). Причина —
код из закрытого словаря (`AUDIT_NOTIFY_REASONS`): свободный текст сделал бы перечень причин
нечитаемым, а формат кода держит база (`ck_web_audit_outbox_reason_code`).

**Чего здесь сознательно нет.** Порога на расход резервного кода (§8.7 называет этот повод
отдельно именно потому, что он редкий и значимый — подавление спрятало бы инцидент), порога для
`risk.limits_changed`, `token.revoked` и `risk.kill_switch_changed` (производителей у этих
оснований нет до вех M2/M3, и выдумывать правило для несуществующего события значило бы решить
чужую задачу молча — `ADR-028` п. 3), метрик и алертов (их в репозитории нет, `ADR-026` п. 3 о
той же опасности), и самой доставки: канала нет (`tgbot` не поднят и упирается в `T-714`,
почтового транспорта в репозитории нет), поэтому решение — обещание на будущее, а не факт
отправки.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

from packages.common.clock import ensure_aware
from packages.identity.audit import AuditRecordError, canonical_ip, validate_details
from packages.storage.models import AUDIT_NOTIFY_GROUNDS, AUDIT_NOTIFY_OUTCOMES

#: Основания, у которых порог определён в этом срезе. Имена — из домена базы
#: (`ck_web_audit_outbox_ground`), который шире множества производителей намеренно: остальные три
#: имени §8.7 ждут вех M2/M3 (`ADR-028` п. 3).
GROUND_LOGIN: Final = "session.login"
GROUND_BACKUP_CODE_SPENT: Final = "backup_code.spent"

#: Порог шума для входа с нового сочетания адрес/устройство (`ADR-028` п. 6). Смысл — §10.1
#: «при массовых событиях — агрегация»: мобильный провайдер меняет адрес часто, и без порога одно
#: и то же устройство давало бы уведомление на каждую смену выхода. Лимиты §8.3 от этого не
#: защищают: входы успешны, и счётчик неудач молчит.
#:
#: Число совпадает с окном перебора §8.2 (`RATE_BAN_WINDOW_SECONDS`) сознательно: «окно, в котором
#: мы уже предупреждали» и «окно, за которое считается перебор» обязаны читаться одним числом, а не
#: двумя. Это договорное число, а не зависимость от механизма лимитов: импорт
#: `apps/web/security/rate_limit.py` сюда запрещён тем же, чем запрещён импорт `apps/web` в
#: `apps/jobs` (`tests/contract/test_repo_layout.py`).
AUDIT_NOTIFY_LOGIN_COOLDOWN_S: Final = 300

#: Шаг входа, с которого §8.7 считает вход состоявшимся для учётной записи со вторым фактором.
#: Значение — из закрытого домена `SESSION_AUTH_STEPS` (`packages/storage/models.py`, ревизия
#: `0004`): парольный шаг даёт строку `session.login`, но поводом уведомления не является, потому
#: что второй фактор ещё не пройден (`ADR-015` п. 3). Контрактная проверка сверяет это значение с
#: доменом шагов: опечатка здесь означала бы, что уведомлений о входах нет вовсе, а пустая
#: таблица выглядела бы «правильной».
AUTH_STEP_FULL: Final = "full"

# ─── коды причин решения (словарь закрыт; формат держит база) ─────────────────────────────────

#: Сочетание адрес+устройство встречается впервые: это и есть «новый IP/устройство» §8.7.
REASON_NEW_PAIR: Final = "new_pair"

#: Сочетание новое, но по этому основанию уже уведомляли в окне кулдауна: второе сообщение за
#: тот же период не добавило бы администратору ничего, кроме шума (§10.1).
REASON_LOGIN_COOLDOWN: Final = "login_cooldown"

#: Сочетание уже уведомлялось раньше окна кулдауна — нового сообщения не требуется. Строка
#: нужна, чтобы «мы промолчали осознанно» читалось из таблицы, а не выводилось из её пустоты.
REASON_KNOWN_PAIR: Final = "known_pair"

#: Расход резервного кода: порога нет, каждое событие — кандидат (§8.7).
REASON_BACKUP_CODE_SPENT: Final = "backup_code_spent"

#: Закрытый словарь причин. Формат каждой — `^[a-z][a-z0-9_]{0,39}$`
#: (`ck_web_audit_outbox_reason_code`); словарь проверяет контракт
#: `tests/contract/test_audit_notify_contract.py`, потому что база формат не перечисляет и
#: «причина появилась по ходу» здесь осталась бы необнаруженной.
AUDIT_NOTIFY_REASONS: Final[frozenset[str]] = frozenset(
    {
        REASON_NEW_PAIR,
        REASON_LOGIN_COOLDOWN,
        REASON_KNOWN_PAIR,
        REASON_BACKUP_CODE_SPENT,
    }
)

# ─── ключ деидентификации повода (§8.7, `ADR-028` п. 5) ───────────────────────────────────────

#: Длина хэша в ключе сочетания. Ключ обязан быть коротким (формат колонки — до 128 знаков,
#: `ck_web_audit_outbox_dedup_key_format`) и обязан нести адрес, но не обязана нести его целиком:
#: журнал, дамп и страница раздела администрирования не должны становиться вторым носителем
#: адреса как значения (`ADR-025` п. 2, публичный репозиторий по `ADR-019`). 32 шестнадцатеричных
#: знаков — это 128 бит на материал «адрес | устройство» при том числе событий, которое даёт
#: площадка: коллизия здесь означала бы «новое сочетание молча промолчало», а не подделку.
KEY_HASH_CHARS: Final = 32

#: Длина отпечатка половинки сочетания в `details`. Отпечаток нужен для разбора («новым стало
#: адрес или устройство»), а не для криптографической стойкости: 12 шестнадцатеричных знаков
#: (48 бит) на множество значений, которое площадка перебирает за месяцы, — это способ отличить
#: одно значение от другого в тексте строки, а не опора безопасности (`ADR-028` п. 5).
PAIR_FP_CHARS: Final = 12

#: Устройство — значение `User-Agent`, приведённое к сопоставимому виду. Ограничение длины
#: совпадает с `USER_AGENT_MAX_LEN` (`apps/web/store.py`): маршрут режет значение перед записью
#: в сеанс, и ключ обязан считаться по тому же материалу, что лежит в записи сеанса, иначе одно
#: и то же соединение дало бы два ключа.
DEVICE_MAX_CHARS: Final = 256

#: Признак «адрес запроса не разобран» (`session_ip` отвечает `None`, когда Caddy не проставил
#: `X-Forwarded-For`). Отдельный маркер нужен, чтобы вход без адреса не склеивался с входом с
#: адресом `""` и чтобы такие события не складывались в один ключ молча.
NO_ADDRESS_MARKER: Final = "noaddr"

#: Материал ключа для значения адреса, которое политика журнала не распознала. См.
#: `normalize_address_material`: бросать здесь нельзя (вход упал бы в `500`), а печатать
#: нераспознанное значение в ключе — значит сделать из журнала второе носитель произвольного
#: значения из заголовка.
OPAQUE_ADDRESS_PREFIX: Final = "opaque:"


def normalize_device(user_agent: str | None) -> str:
    """Устройство как материал ключа: сжатые пробелы, ограниченный размер, без `None`."""
    if user_agent is None:
        return ""
    return " ".join(user_agent.split())[:DEVICE_MAX_CHARS]


def normalize_address_material(address: str | None) -> str:
    """Адрес как материал ключа: та же нормализация, что у колонки `audit_log.ip`.

    `canonical_ip` — единственная нормализация адреса в журнале (`ADR-025` п. 3, материал хэша
    строится по ней же), и `ADR-009` требует, чтобы «кого показываем», «кого блокируем» и «кого
    уведомляем» считались одинаково. Другая форма (регистр, ведущие нули, IPv4-mapped) дала бы
    два ключа на одно соединение, и порог «этот адрес уже уведомляли» перестал бы работать ровно
    там, где он нужен, — под правым элементом `X-Forwarded-For` от Caddy. Та же функция разбирает
    форму `unknown:203.0.113.7:5678`, которую оставляют прокси-заголовки.

    Значение, которое политика не распознала (`AuditRecordError`), идёт в ключ как
    `opaque:<хэш>`: здесь бросать тоже нельзя — вход уже состоялся и записан в журнал, а
    исключение из пути уведомления превратило бы успешный вход в `500` из-за мусора в заголовке.
    Хэш, а не нераспознанная строка, — по той же причине, что и весь ключ: журнал не обязан
    становиться вторым носителем произвольных значений, а повтор одного и того же значения обязан
    узнаваться.
    """
    if address is None:
        return NO_ADDRESS_MARKER
    try:
        return canonical_ip(address)
    except AuditRecordError:
        return f"{OPAQUE_ADDRESS_PREFIX}{hashlib.sha256(address.encode('utf-8')).hexdigest()[:16]}"


@dataclass(frozen=True)
class LoginPair:
    """Сочетание «адрес + устройство» этого входа: ключ и оба отпечатка по отдельности.

    Ключ держит пару целиком (§8.7 говорит о сочетании, а не об адресе как таковом), а
    отпечатки по половинкам нужны затем, чтобы **различие читалось из `details`** (§8.7 второй
    абзац, `ADR-025` п. 9, границы среза по `docs/HANDOFF.md §2` п. 3): по строкам таблицы видно,
    что именно стало новым — адрес или устройство. Значения в детали не пишутся: отпечаток —
    усечённый хэш канонического материала, а не адрес и не `User-Agent` (`ADR-025` п. 2,
    публичный репозиторий по `ADR-019`).
    """

    dedup_key: str
    address_fp: str
    device_fp: str


def login_pair(*, user_id: UUID, address: str | None, user_agent: str | None) -> LoginPair:
    """Ключ сочетания «этот адрес и это устройство уже уведомляли» и отпечатки половинок (§8.7).

    Материал ключа — **пара** (адрес, устройство), а не каждое значение отдельно: правило
    «новый адрес ИЛИ новое устройство» породило бы на один вход два ключа и две строки, и разбор
    не отличил бы их от удвоения события (`ADR-028` п. 6, «одна точка на событие»).

    Формат ключа держит `ck_web_audit_outbox_dedup_key_format`: префикс — имя основания, дальше
    идентификатор учётной записи и хэш пары. Хэш, а не адрес целиком — по причине из
    `KEY_HASH_CHARS`. Отпечатки половинок считаются по тому же каноническому материалу, что и
    ключ: два разных значения не должны давать одинаковый отпечаток, а одно и то же соединение
    не должно давать двух разных (`ADR-009`).
    """
    address_material = normalize_address_material(address)
    device_material = normalize_device(user_agent)
    material = f"{address_material}|{device_material}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:KEY_HASH_CHARS]
    return LoginPair(
        dedup_key=f"{GROUND_LOGIN}:{user_id}:{digest}",
        address_fp=hashlib.sha256(address_material.encode("utf-8")).hexdigest()[:PAIR_FP_CHARS],
        device_fp=hashlib.sha256(device_material.encode("utf-8")).hexdigest()[:PAIR_FP_CHARS],
    )


def login_dedup_key(*, user_id: UUID, address: str | None, user_agent: str | None) -> str:
    """Только ключ сочетания: тот же материал, что у `login_pair`.

    Отдельная функция нужна читающему состоянию (`read_login_notice_state` ищёт по ключу), чтобы
    ему не требовалось знать про отпечатки.
    """
    return login_pair(user_id=user_id, address=address, user_agent=user_agent).dedup_key


def backup_code_dedup_key(backup_code_id: UUID) -> str:
    """Ключ «этот резервный код уже был основанием уведомления» (§8.7).

    Идентификатор строки `backup_codes`, а не значение кода: значение — секрет входа, и ни в
    журнал, ни в ключ оно попасть не может (`ADR-016` п. 4, `_DETAIL_KEY_DENYLIST`).
    """
    return f"{GROUND_BACKUP_CODE_SPENT}:{backup_code_id}"


class NotifyDecisionError(ValueError):
    """Решение порога противоречит домену таблицы (имя вне основания, `notify` без ключа)."""


# ─── состояние, которое читает база перед решением (§8.7, `ADR-026` п. 4) ─────────────────────


@dataclass(frozen=True)
class LoginNoticeState:
    """Что уже известно о сочетаниях этой учётной записи: пара встречалась? когда уведомляли?

    Оба значения читаются **до** решения одним обращением (`ADR-026` п. 4: сначала чтение, потом
    запись) и не выводятся из «последней строки таблицы»: последняя строка — это любое основание,
    а не это.
    """

    known_pair: bool
    last_notify_at: datetime | None


# ─── решение ──────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NotifyDecision:
    """Строка будущего решения: вердикт, причина, ключ деидентификации и ссылки.

    Значения проверяются здесь же, где формулируются: домен основания и вердикта, словарь причин,
    обязательность ключа у `notify` и его формат (`ck_web_audit_outbox_dedup_key_format`),
    политика значений `details` — та же, что у журнала (`ADR-025` п. 2: идентификаторы, коды и
    целые счётчики, но не значения учётных данных и не адрес как значение). Офлайновая половинка
    отклоняет те же значения, что и база, — иначе «отказ layered» обнаруживался бы только на
    живой площадке.
    """

    ground: str
    outcome: str
    reason: str
    dedup_key: str | None
    user_id: UUID | None
    details: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.ground not in AUDIT_NOTIFY_GROUNDS:
            msg = f"основание {self.ground!r} нет в домене §8.7: {sorted(AUDIT_NOTIFY_GROUNDS)}"
            raise NotifyDecisionError(msg)
        if self.outcome not in AUDIT_NOTIFY_OUTCOMES:
            msg = f"вердикт {self.outcome!r} нет в домене решений: {list(AUDIT_NOTIFY_OUTCOMES)}"
            raise NotifyDecisionError(msg)
        if self.reason not in AUDIT_NOTIFY_REASONS:
            msg = f"причина {self.reason!r} нет в словаре `AUDIT_NOTIFY_REASONS`"
            raise NotifyDecisionError(msg)
        if self.outcome == "notify" and self.dedup_key is None:
            # Ровно то же условие, что `ck_web_audit_outbox_notify_has_dedup_key`: строка
            # «уведомить» без ключа открыла бы повторную рассылку одного и того же повода.
            msg = f"решение notify по основанию {self.ground} обязано нести dedup_key"
            raise NotifyDecisionError(msg)
        if self.dedup_key is not None and not _dedup_key_matches(self.dedup_key):
            msg = f"ключ {self.dedup_key!r} не проходит формат колонки dedup_key"
            raise NotifyDecisionError(msg)
        if self.details is not None:
            validate_details(self.details)


#: Границы и алфавит ключа — те же, что у `ck_web_audit_outbox_dedup_key_format`
#: (`^[a-z0-9._:-]{1,128}$`).
_DEDUP_KEY_MAX_CHARS: Final = 128
_DEDUP_KEY_ALPHABET: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._:-")


def _dedup_key_matches(key: str) -> bool:
    """Тот же класс отклонения, что `ck_web_audit_outbox_dedup_key_format`.

    Проверка повторяет регулярку колонки перечислением алфавита, а не регуляркой: смысл один —
    ключ обязан читаться человеком (`основание:идентификатор:хэш`) и не выходить за границы
    колонки. Кириллица, пробел и заглавная буква в ключе означают, что кто-то подставил в него
    значение (логин, адрес, User-Agent целиком), и отклонить такой ключ нужно до `INSERT`.
    """
    if not 1 <= len(key) <= _DEDUP_KEY_MAX_CHARS:
        return False
    return all(ch in _DEDUP_KEY_ALPHABET for ch in key)


def decide_login_notice(
    state: LoginNoticeState,
    *,
    pair: LoginPair,
    user_id: UUID,
    now: datetime,
    auth_step: str,
    cooldown_s: int = AUDIT_NOTIFY_LOGIN_COOLDOWN_S,
) -> NotifyDecision:
    """Решение по входу (§8.7 «вход нового пользователя (новый IP/устройство)»).

    Порядок правил значим:

    1. по этому основанию эту учётную запись уже уведомляли в окне кулдауна → `muted` /
       `login_cooldown`. Правило стоит первым сознательно: у мобильного клиента адрес меняется
       на каждую выдачу провайдером, и если бы сначала шло правило «сочетание новое», порог шумел
       бы ровно там, для чего написан (§10.1 требует агрегации при массовых событиях);
    2. сочетание уже уведомлялось раньше, а окно закрыто → `muted` / `known_pair`: требование
       §8.7 про новое сочетание не выполнено, нового сообщения не требуется;
    3. иначе сочетание встречается впервые и окно закрыто → `notify` / `new_pair`; ключ занят за
       этой строкой (`ix_web_audit_outbox_dedup_key`).

    `muted` пишется строкой, а не отсутствием строки намеренно (`ADR-028` п. 4): иначе «порог
    промолчал» неотличимо от «события не было».

    `auth_step` входит в `details` затем, чтобы разбор видел: уведомление относится к полному входу
    (§8.7), а не к принятому паролю на шаге `'password'` — вторую строку `session.login` даёт
    именно шаг `full`, и именно она является поводом (`ADR-025` п. 6, «одна точка на событие).
    Отпечатки половинок сочетания входят в `details` затем, чтобы из строки читалось, что стало
    новым — адрес или устройство (§8.7 второй абзац, `ADR-025` п. 9).
    """
    details: dict[str, Any] = {
        "auth_step": auth_step,
        "address_fp": pair.address_fp,
        "device_fp": pair.device_fp,
    }

    last = state.last_notify_at
    if last is not None and ensure_aware(now) - ensure_aware(last) < timedelta(seconds=cooldown_s):
        details["cooldown_s"] = cooldown_s
        return NotifyDecision(
            ground=GROUND_LOGIN,
            outcome="muted",
            reason=REASON_LOGIN_COOLDOWN,
            dedup_key=None,
            user_id=user_id,
            details=details,
        )

    if state.known_pair:
        return NotifyDecision(
            ground=GROUND_LOGIN,
            outcome="muted",
            reason=REASON_KNOWN_PAIR,
            dedup_key=None,
            user_id=user_id,
            details=details,
        )

    return NotifyDecision(
        ground=GROUND_LOGIN,
        outcome="notify",
        reason=REASON_NEW_PAIR,
        dedup_key=pair.dedup_key,
        user_id=user_id,
        details=details,
    )


def decide_backup_code_notice(*, user_id: UUID, backup_code_id: UUID) -> NotifyDecision:
    """Решение по расходу резервного кода (§8.7 «расход резервного кода»).

    Порога нет сознательно: §8.7 называет этот повод отдельно потому, что он редкий и значимый, а
    кулдаун молча спрятал бы инцидент (`ADR-028` п. 6). Идемпотентность при этом держит ключ по
    идентификатору строки кода: повторная попытка зафиксировать тот же расход (например, при
    повторе того же запроса) не создаст второго уведомления — её отклонит частичный уникальный
    индекс `ix_web_audit_outbox_dedup_key`, а не «проверка перед вставкой».
    """
    return NotifyDecision(
        ground=GROUND_BACKUP_CODE_SPENT,
        outcome="notify",
        reason=REASON_BACKUP_CODE_SPENT,
        dedup_key=backup_code_dedup_key(backup_code_id),
        user_id=user_id,
        details={"backup_code_id": str(backup_code_id)},
    )


def grounds_without_producer() -> dict[str, str]:
    """Основания §8.7, у которых нет производителя, и что именно их держит.

    Возвращается отображение, а не список, потому что смысл записи — «почему имени в коде нет»:
    `ADR-028` п. 3 требует, чтобы остаток был зафиксирован явно, а не закрыт молчанием. Контракт
    `tests/contract/test_audit_notify_contract.py` сверяет это отображение с доменом базы: если
    производитель появится, запись обязана исчезнуть, а если основание исчезнет из домена —
    контракт покраснеет как раз потому, что требование §8.7 сузилось бы до написанного.
    """
    return {
        "token.revoked": "ожидает `T-108` (веха M2: подключение, ротация и отзыв токена)",
        "risk.limits_changed": "ожидает риск-контур (веха M3): пороги риска задаёт `risk-gate`",
        "risk.kill_switch_changed": "ожидает emergency-переключатель (веха M3, `T-110`)",
    }
