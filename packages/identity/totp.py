"""Коды 2FA по RFC 6238 (TZ §8.2, `REQ-identity-*`, задача `T-103` — срез `R4a`: домен без
хранения секрета и без маршрутов).

Что закреплено этим модулем:

* параметры кода — ровно §8.2: RFC 6238, SHA-1, 6 цифр, шаг 30 с; допуск ±1 шаг, **максимум ±2**.
  Верхняя граница взята из схемы (`TOTP_WINDOW_MAX` в `packages/storage/models.py` — там же
  CHECK-ограничение `verify_window`), чтобы код и база не могли разойтись: widening окна в коде
  иначе просто перестал бы быть заметен;
* секрет — 160 бит (20 байт), base32 без дополнения: RFC 6238 §5.1 — длина ключа SHOULD быть
  равна длине выхода HMAC (для SHA-1 это 160 бит), RFC 4226 §4 (R6) — не менее 128 бит при
  рекомендации 160. На входе (ручной ввод с экрана аутентикатора) принимаются 128–512 бит:
  ниже 128 — ключ, который RFC запрещает принимать, выше 512 — секрет, который часть
  приложений сохраняет укороченным, и пользователь получает «код не подходит» без объяснений;
* реализация своя, `pyotp` не подключена: §8.2 предпочитает собственный код «для аудита» и требует
  оформить выбор ADR — это `docs/adr/ADR-013-totp-own-implementation-and-replay-guard.md`. Пока
  ADR не принят, зависимость не появляется: новый пакет меняет образ и требует пересъёма digest
  (`runbook/stand-deploy §2`);
* сравнение кода — `hmac.compare_digest` по **всем** кандидатам окна, без раннего выхода: иначе
  длительность ответа начинает зависеть от того, на каком шаге окна совпало;
* защита от повторного использования окна (§8.2 «коды принимаются один раз») — правило монотонности
  счётчика из RFC 6238 §5.2: предъявленный код принимается, только если его номер шага **больше**
  последнего принятого для этой привязки. Функция получает `last_used_counter` параметром: где он
  хранится — вопрос к схеме (см. ADR), сам домен состояния не имеет;
* подтверждение привязки — **два последовательных** кода (§8.2): номера их шагов обязаны отличаться
  ровно на 1. Иначе «ввести один код дважды» проходило бы, а это ровно то, что проверяет
  «пользователь действительно держит генератор на руках и время идёт»;
* лента неудач (`totp_failures`) — источник решения о блокировке: строку пишет вызывающий слой,
  порог «5 неудачных кодов → блокировка входа на 15 минут» считается по ленте (см. ниже про окно).

Чего здесь сознательно нет (и почему это не недоделка, а граница среза):

* шифрования секрета (`totp_enrollments.secret_enc`, AES-256-GCM + KEK вне БД, §8.4) — шифровального
  слоя в репозитории ещё нет ни для чего; он отдельный срез (`R4b`), потому что затрагивает
  `common` (ключи, `secrets_dir`, режимы файлов по `ADR-005`), а не только `identity`. До него
  привязку в базу нельзя класть **вообще**: колонка `secret_enc` объявлена как `bytea`, и открытое
  значение в ней — прямое нарушение §8.4, а не «временное упрощение»;
* QR-картинки: §8.2 требует QR **и** ручной ввод секрета. Здесь строится URI `otpauth://` — то, что
  кладётся в QR. Превратить URI в картинку без зависимости нельзя (собственный кодировщик QR — это
  сотни строк алгоритма, который никто не аудитировал), а новая зависимость — решение заказчика
  (ADR-013 «Что нужно от заказчика»); ручной секрет уже доступен, поэтому вход с `T-103` не ждёт
  картинку;
* записи «последнего принятого шага»: колонка `totp_enrollments.last_used_step` в схеме уже
  есть (ревизия `0004`, ADR-013 п. 4), но писать её некому до `R4c`. Домен состояния не имеет
  и получает `last_used_counter` параметром, поэтому §8.2 «коды принимаются один раз» действует
  пока только внутри одного запроса; компенсирующий контроль — счётчики `ADR-007`/`R3d`
  (`totp_session` 10/мин, `totp_ip` 5/мин, блокировка после 5 неудач);
* паузы приёма кодов при расхождении часов >2 с (§8.2, инцидент `R32`) — в репозитории нет
  источника актуального смещения часов: смещение измеряет `scripts/prod_bootstrap_check.py` по
  снимку `chronyc tracking` (приёмка `T-011`), но это разовая проверка площадки, а не значение,
  которое знает процесс `web`. Прикладывать константу «2 секунды» без источника — значит сделать
  вид, что контроль есть;
* временного бана адреса по правилу «3 попытки с одного IP за 5 минут» — §8.2 относит его к
  периметру (`nginx/fail2ban`, у выбранного Caddy встроенного счётчика нет, `ADR-003`), а
  прикладная часть правила уже стоит: область `totp_ip` 5 запросов/мин на адрес и общий бан адреса
  введены срезом `R3d`. Лента `totp_failures` с колонкой `ip` — как раз то, по чему периметр и
  разбор инцидентов считают это правило;
* резервных кодов (§8.2) — `T-104`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal
from urllib.parse import quote
from uuid import UUID

from packages.common.clock import ensure_aware
from packages.identity.users import LOCK_DURATION
from packages.storage.models import TOTP_WINDOW_DEFAULT, TOTP_WINDOW_MAX, TotpFailure, User

# ─── параметры кода (§8.2: RFC 6238, SHA-1, 6 цифр, шаг 30 с, допуск ±1, максимум ±2) ─────────

#: §8.2 фиксирует алгоритм: SHA-1 и 6 цифр — это RFC 6238 §4/§5 в конфигурации по умолчанию, которую
#: понимают «Google Authenticator и совместимые» (§8.2). Отличное от RFC число цифр аутентикатор не
#: покажет, поэтому константа не «настройка», а часть протокола.
TOTP_DIGITS: Final = 6
TOTP_PERIOD_SECONDS: Final = 30
#: 160 бит — длина, которую RFC 6238 §5.1 требует для HMAC-SHA-1 (ключ SHOULD быть равен
#: длине выхода хэша) и которую RFC 4226 §4 (R6) рекомендует; из неё исходят совместимые
#: аутентикаторы. Источник случайности — `secrets` (CSPRNG), как требует RFC 6238 §5.1.
TOTP_SECRET_BYTES: Final = 20
#: Границы принимаемого вручную секрета: 128–512 бит. Нижняя — дословный запрет RFC 4226
#: §4 (R6): «the length of the shared secret MUST be at least 128 bits». Это не перестраховка:
#: код — шесть цифр, то есть миллион значений, и ключ короче 128 бит подбирается
#: быстрее, чем владелец успевает заметить привязку. Верхняя — прикладной предел: секрет
#: длиннее 512 бит часть аутентикаторов сохраняет укороченным, и «правильный» код перестаёт
#: подходить навсегда, причём виноватым выглядит пользователь.
TOTP_SECRET_BYTES_MIN: Final = 16
TOTP_SECRET_BYTES_MAX: Final = 64

#: Окно допуска. Нижняя и верхняя границы приходят из схемы: `verify_window` ограничен
#: CHECK-ограничением `totp_enrollments_verify_window_check`, поэтому расширять окно в коде — значит
#: разъезжаться с базой незаметно.
TOTP_WINDOW_DEFAULT_STEPS: Final = TOTP_WINDOW_DEFAULT
TOTP_WINDOW_MAX_STEPS: Final = TOTP_WINDOW_MAX

#: §8.2: «5 неудачных кодов подряд → блокировка входа пользователя на 15 минут». Срок тот же, что у
#: перебора пароля (`users.LOCK_DURATION`), и это не экономия: обе формулировки §8.1/§8.2 называют
#: один и тот же срок и то же состояние — «вход закрыт».
TOTP_MAX_FAILED_CODES: Final = 5
#: Окно, за которое считаются неудачи. «Подряд» по ленте не восстановить: записи в `totp_failures`
#: при успехе не удаляются (так решил слой `storage`: иначе перебор «до блокировки» обнулялся бы
#: успехом), а отметки об успешном коде в схеме нет. Окно = срок блокировки: деталь разобрана в
#: ADR-013 п. 4.
#: Совпадение срока не случайность: к моменту, когда блокировка сама открывается, все попавшие
#: в неё неудачи перестают попадать в окно. Иначе пятая попытка сразу после разблокировки
#: оказывалась бы шестой и закрывала вход повторно без единой новой неудачи.
TOTP_FAILURE_HORIZON: Final = LOCK_DURATION

#: Источники попытки кода. Схема оставила множество открытым («его определит T-103/T-110 вместе с
#: маршрутами») — здесь оно закрывается: код вводят либо в консоли, либо в Telegram-боте.
TOTP_SOURCE_WEB: Final = "web"
TOTP_SOURCE_TELEGRAM: Final = "telegram"
TOTP_SOURCES: Final[tuple[str, ...]] = (TOTP_SOURCE_WEB, TOTP_SOURCE_TELEGRAM)

#: Метка алгоритма в URI `otpauth://`: §8.2 фиксирует SHA-1, и аутентикатор обязан получить именно
#: её, иначе он сгенерирует код по своему алгоритму по умолчанию и привязка «не взлетит».
TOTP_ALGORITHM: Final = "SHA1"

type TotpCheckStatus = Literal[
    "accepted",  # код принят
    "mismatch",  # ни один кандидат окна не совпал
    "malformed",  # предъявлено значение, не похожее на код
    "replay",  # совпал шаг не позже уже принятого (§8.2 «коды принимаются один раз»)
    "not_consecutive",  # пара кодов подтверждение не проходит (шаги не соседние)
]


class TotpSecretError(ValueError):
    """Секрет привязки нельзя принять: не base32, слишком короткий или слишком длинный."""


class TotpSourceError(ValueError):
    """Источник попытки кода вне закрытого перечня `TOTP_SOURCES` (§4.1 оставил перечень открытым)."""


@dataclass(frozen=True)
class TotpCheck:
    """Итог проверки кода. Ни секрет, ни предъявленное значение сюда не попадают: результат уходит
    в лог и в обработчик, а §8.4 требует, чтобы материал доступа в логах не печатался. `counter` —
    номер шага (не код): он нужен вызывающему, чтобы сохранить его как «последний принятый»."""

    status: TotpCheckStatus
    counter: int | None = None
    step_offset: int | None = None


# ─── секрет привязки ──────────────────────────────────────────────────────────────────────────


def new_totp_secret() -> str:
    """Новый секрет привязки — base32 без дополнения (§8.2: его показывают для QR и ручного ввода).

    Источник — `secrets` (CSPRNG), а не `random`: секрет привязки — единственное, что отличает
    предъявление кода от его угадывания, и восстановим он только из CSPRNG. Дополнение `=` снимается намеренно:
    аутентикаторы и библиотеки ключа URL-безопасного base32 с дополнением принимают не все, а
    длина 32 символа без дополнения стандартна (RFC 4648 §6, профиль без заполнения).
    """
    return base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def normalize_totp_secret(text: str) -> str:
    """Привести предъявленный секрет к канону: верхний регистр, без пробелов и дефисов.

    Пользователь копирует секрет с экрана аутентикатора, где он напечатан блоками по 4 символа,
    и вводит с телефона: пробелы, дефисы и нижний регистр — норма, а не ошибка. Отказывать за них
    §8.2 не просит, а «тихо починить» нельзя только то, что меняет смысл: символы вне алфавита
    base32 остаются ошибкой.
    """
    cleaned = "".join(ch for ch in text.upper() if ch.isalnum())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    offenders = {ch for ch in cleaned if ch not in alphabet}
    #: Перечисляются только символы, которых в алфавите base32 нет: сам секрет из таких символов
    #: не состоит, поэтому в лог (куда текст исключения уносит обработчик) материал привязки не
    #: попадает. Список ограничивается длиной — сообщение печатается в ответе пользователя.
    bad = "".join(sorted(offenders))[:8]
    if bad:
        raise TotpSecretError(
            f"секрет содержит символы вне base32 (алфавит A–Z и 2–7): {''.join(bad)}"
        )
    return cleaned


def decode_totp_secret(text: str) -> bytes:
    """Декодировать секрет (в т.ч. введённый вручную) в ключ для HMAC и проверить его длину.

    Проверка длины — не косметика: короткий ключ перебирается, длинный аутентикатор может обрезать,
    и в обоих случаях привязка выглядит работающей, пока не станет непригодной.
    """
    canonical = normalize_totp_secret(text)
    if not canonical:
        raise TotpSecretError("секрет пуст")
    padding = "=" * (-len(canonical) % 8)
    try:
        key = base64.b32decode(canonical + padding, casefold=False)
    except (ValueError, TypeError) as exc:
        raise TotpSecretError(f"секрет не является base32: {exc}") from exc
    if not TOTP_SECRET_BYTES_MIN <= len(key) <= TOTP_SECRET_BYTES_MAX:
        raise TotpSecretError(
            f"длина секрета {len(key)} байт вне допустимого "
            f"[{TOTP_SECRET_BYTES_MIN}; {TOTP_SECRET_BYTES_MAX}] (§8.2, RFC 4226 §4)"
        )
    return key


def totp_provisioning_uri(
    secret: str,
    *,
    account_name: str,
    issuer: str,
) -> str:
    """Собрать URI `otpauth://` (ключ-профиль Google Authenticator) для QR-кода и ручного ввода.

    Метка и параметр `issuer` обязательны: без метки аутентикатор показывает только логин, и
    пользователю неотличимо, к какой учётной записи секрет привязан, а при двух учётных записях с
    одним логином — и того хуже. Символ `:` в метке экранируется, иначе аутентикатор разрежет метку
    не по тому разделителю.

    Параметры `algorithm`, `digits` и `period` пишутся явно, хотя у RFC есть значения по умолчанию:
    аутентикаторы трактуют отсутствие параметра по-разному, а «не тот алгоритм» проявляется как
    «код никогда не подходит» — самый дешёвый способ получить необъяснимый отказ.
    """
    label = f"{quote(issuer, safe='')}:{quote(account_name, safe='')}"
    query = "&".join(
        (
            f"secret={quote(secret.upper(), safe='')}",
            f"issuer={quote(issuer, safe='')}",
            f"algorithm={TOTP_ALGORITHM}",
            f"digits={TOTP_DIGITS}",
            f"period={TOTP_PERIOD_SECONDS}",
        )
    )
    return f"otpauth://totp/{label}?{query}"


# ─── вычисление и проверка кода ───────────────────────────────────────────────────────────────


def _key(secret: bytes | str) -> bytes:
    """Ключ HMAC из секрета: готовый `bytes` (из хранилища) или текст (ввод оператора/URL)."""
    return decode_totp_secret(secret) if isinstance(secret, str) else secret


def _step_of(moment: datetime) -> int:
    """Номер шага по времени: целое число 30-секундных интервалов от эпохи Unix (RFC 6238 §4)."""
    return int(moment.timestamp()) // TOTP_PERIOD_SECONDS


def totp_step(moment: datetime | None = None) -> int:
    """Номер текущего шага: RFC 6238 §4.2 — `T = (Current Unix time - T0) / X`, где `T0` = 0,
    `X` = 30 и деление с округлением вниз (тот же пример RFC: `T` = 1 на 59-й секунде).

    RFC 6238 §4.2 отдельно требует, чтобы за 2038 годом `T` не обрезался 32 битами: счётчик
    здесь — целое Python, а в HMAC упаковывается восемью байтами (`>Q`), поэтому таблица
    эталонов RFC (2603 год) проходит тем же путём, что и обычные значения."""
    return _step_of(ensure_aware(moment))


def _code_at_counter(key: bytes, counter: int) -> str:
    """HOTP-код по счётчику (RFC 4226 §5.3, динамическая усечка) — внутренняя часть TOTP.

    Отдельной публичной HOTP-функции здесь нет намеренно: счётчик в TOTP — не «что угодно
    подставить», а номер шага времени, и соблазн вызвать HOTP с произвольным счётчиком — это дыра.
    """
    message = struct.pack(">Q", counter & 0xFFFFFFFFFFFFFFFF)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = (
        (digest[offset] & 0x7F) << 24
        | digest[offset + 1] << 16
        | digest[offset + 2] << 8
        | digest[offset + 3]
    )
    return str(truncated % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_code(secret: bytes | str, moment: datetime | None = None) -> str:
    """Код для указанного момента — сторона генерации (§8.2: привязка требует показать секрет и
    коды, генератор живёт у пользователя, но проверить «что должен показать аутентикатор» обязаны мы).

    Вызов без `moment` — реальное «сейчас»: для привязки и подсказок это допустимо, а вот проверки
    обязаны передавать время явно (или через тестовые часы), иначе грань окна становится
    непроверяемой (то же правило, что в `ADR-009` п. 3 для счётчиков).
    """
    return _code_at_counter(_key(secret), totp_step(moment))


def _malformed(code: str) -> bool:
    """Предъявленное значение нельзя рассматривать как код: не 6 ASCII-цифр.

    `str.isdigit()` здесь не годится: он истинен для «١٢٣٤٥٦» (арбано-индийские цифры) и для
    надстрочных, а такое значение не совпадёт никогда — отказ обязан быть «код не похож на код», а
    не «код неверный» (у этих двух разные объяснения и разные счётчики).
    """
    return len(code) != TOTP_DIGITS or not code.isascii() or not code.isdecimal()


def verify_totp_code(
    secret: bytes | str,
    code: str,
    *,
    last_used_counter: int | None = None,
    window: int = TOTP_WINDOW_DEFAULT_STEPS,
    now: datetime | None = None,
) -> TotpCheck:
    """Проверить код 2FA (§8.2) и вернуть итог с номером принятого шага.

    Что держится:

    * окно ±1 по умолчанию и **не шире** `TOTP_WINDOW_MAX` (±2): значение `window=5` не превращается
      в «пять шагов допуска», а сжимается до границы схемы. Окно шире — это не «добрее», а 11
      принимаемых значений вместо 3 на каждые 30 секунд, то есть грубая поддержка перебора;
    * сравнение по всем кандидатам окна без раннего выхода (`hmac.compare_digest` и накопление, а не
      `return` внутри цикла): длительность ответа не должна говорить атакующему, на каком шаге
      совпало;
    * §8.2 «коды принимаются один раз»: шаг обязан быть **новее** ранее принятого. Совпадение с
      уже использованным шагом и более старый шаг отвечают `replay` — с тем же отказом, что и
      неверный код, но с различимой причиной в логе;
    * сравнение идёт только после проверки синтаксиса предъявленного значения; пустая строка или
      поле «6 букв» не тратят_candidates и не выглядят как неверный код.

    Часов без явного значения здесь нет: `now=None` означает «реальное сейчас» только для совместимых
    вызовов вне проверок; интеграционные и юнит-проверки передают время тестом.
    """
    moment = ensure_aware(now)
    if _malformed(code):
        return TotpCheck(status="malformed")

    key = _key(secret)
    current_step = _step_of(moment)
    span = min(max(int(window), 0), TOTP_WINDOW_MAX_STEPS)

    matched_offset: int | None = None
    matched = False
    for offset in range(-span, span + 1):
        candidate = _code_at_counter(key, current_step + offset)
        hit = hmac.compare_digest(candidate, code)
        # Накопление вместо выхода: все кандидаты сравниваются всегда, иначе сравнение становится
        # «до первого совпадения» и начинает зависеть от порядка перебора.
        if hit and not matched:
            matched = True
            matched_offset = offset

    if not matched:
        return TotpCheck(status="mismatch")

    accepted_step = current_step + (matched_offset or 0)
    if last_used_counter is not None and accepted_step <= last_used_counter:
        return TotpCheck(status="replay", counter=accepted_step, step_offset=matched_offset)
    return TotpCheck(status="accepted", counter=accepted_step, step_offset=matched_offset)


def verify_totp_pair(
    secret: bytes | str,
    first_code: str,
    second_code: str,
    *,
    last_used_counter: int | None = None,
    window: int = TOTP_WINDOW_DEFAULT_STEPS,
    now: datetime | None = None,
) -> TotpCheck:
    """Подтверждение привязки двумя **последовательными** кодами (§8.2).

    Оба кода проверяются в том же окне, а затем их номера шагов обязаны быть соседними: второй код
    ровно на один шаг новее первого. Это и есть ответ на вопрос «пользователь действительно держит
    генератор и может показать следующий код»: один и тот же код, введённый дважды (один шаг), или
    коды через шаг (пропущенный шаг — пользователь подсмотрел одно значение) не проходят.

    Результат несёт номер шага второго кода — его вызывающий сохраняет как «последний принятый»,
    иначе привязка, подтверждённая кодом шага `c`, откроет вход кодом того же шага `c`.
    `last_used_counter` — тот же шаг, что хранится для входа: подтверждение привязки не должно
    принимать код, который уже был израсходован входом в систему. Без этого шага кодом, один раз
    показанным на входе, можно было бы подтвердить новую привязку.
    """
    first = verify_totp_code(
        secret, first_code, last_used_counter=last_used_counter, window=window, now=now
    )
    if first.status != "accepted" or first.counter is None:
        return TotpCheck(status=first.status, counter=first.counter, step_offset=first.step_offset)
    confirmed_step = first.counter
    second = verify_totp_code(
        secret,
        second_code,
        last_used_counter=confirmed_step,
        window=window,
        now=now,
    )
    if second.status != "accepted" or second.counter is None:
        return TotpCheck(
            status=second.status, counter=second.counter, step_offset=second.step_offset
        )
    if second.counter != confirmed_step + 1:
        return TotpCheck(status="not_consecutive", counter=second.counter)
    return TotpCheck(status="accepted", counter=second.counter, step_offset=second.step_offset)


# ─── лента неудач и блокировка входа (§8.2) ───────────────────────────────────────────────────


def new_totp_failure(
    user_id: UUID,
    *,
    ip: str | None,
    source: str = TOTP_SOURCE_WEB,
    at: datetime | None = None,
) -> TotpFailure:
    """Строка ленты `totp_failures` для неудачной попытки кода.

    Вставляется вызывающим слоем в ту же транзакцию, что и ответ: §8.2 требует, чтобы попытки
    «фиксировались в `totp_failures`», а лента — единственный источник и для порога «5 кодов», и для
    разбора «3 попытки с адреса за 5 минут» (периметр и `T-109`). `ip` пишется как значение колонки
    `INET` — текст адреса, канон по `ADR-009`.
    """
    if source not in TOTP_SOURCES:
        raise TotpSourceError(f"источник попытки {source!r} вне перечня {TOTP_SOURCES}")
    return TotpFailure(user_id=user_id, at=ensure_aware(at), ip=ip, source=source)


def count_recent_totp_failures(
    failures: Iterable[TotpFailure],
    *,
    now: datetime | None = None,
    horizon: timedelta = TOTP_FAILURE_HORIZON,
) -> int:
    """Сколько неудач в ленте попали в окно `horizon` до `now`.

    Лента читается вызывающим слоем запросом по `(user_id, at)` — индекс
    `ix_totp_failures_user_id_at` для этого и поставлен в `0002`. Здесь только арифметика окна,
    чтобы порог можно было проверить офлайном на фиксированном времени.
    """
    moment = ensure_aware(now)
    edge = moment - horizon
    total = 0
    for row in failures:
        if edge < row.at <= moment:
            total += 1
    return total


def register_totp_code_failure(
    user: User,
    failures: Iterable[TotpFailure],
    *,
    ip: str | None,
    source: str = TOTP_SOURCE_WEB,
    now: datetime | None = None,
) -> tuple[TotpFailure, datetime | None]:
    """Зафиксировать неудачу кода и, если достигнут порог §8.2, закрыть вход на срок блокировки.

    Возвращает пару «строка ленты (вставить в транзакцию), момент блокировки или `None`». Строка
    считается **включая** эту попытку: иначе пятая неудача оставалась бы неучтённой до следующего
    запроса, и «5 подряд» превращалось бы в «5, а блокировка с шестой».

    Блокировка ставится в те же поля `users`, что и перебор пароля (`locked_until`,
    `ADR-006`-подобной отдельной колонки нет и не заводится): §8.2 называет то же состояние —
    «блокировка входа пользователя», и раздельные состояния дали бы два ответа на вопрос «почему
    вход закрыт». Отдельно держится, что `failed_attempts` (счётчик **парольных** неудач) эта функция
    не трогает: пороги §8.1 (5 неверных паролей) и §8.2 (5 неверных кодов) считаются раздельно,
    иначе «неверный код» начал бы влиять на блокировку от перебора пароля.
    """
    moment = ensure_aware(now)
    row = new_totp_failure(user.id, ip=ip, source=source, at=moment)
    counted = count_recent_totp_failures(failures, now=moment) + 1
    if counted < TOTP_MAX_FAILED_CODES:
        return row, None
    until = moment + LOCK_DURATION
    user.locked_until = until
    return row, until
