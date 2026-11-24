"""Порог уведомлений §8.7: ключи, вердикты и причины — оффлайн-половинка (`T-116`, `ADR-028`).

Что проверяется здесь, где нет ни базы, ни HTTP: ключ деидентификации (детерминированность,
нормализация материала, длина и алфавит формата колонки), отпечатки половинок сочетания («новым
стало адрес или устройство» читается из `details`), правила порога входа (окно кулдауна, затем
известное сочетание, затем первое сочетание), отсутствие порога на расход резервного кода,
закрытость доменов основания/вердикта/причины и политика значений `details`.

Чего память доказать не может и переносить сюда нельзя: частичный уникальный индекс
`ix_web_audit_outbox_dedup_key` (в памяти «повтор» — предикат, а не отказ `23505`), `ON CONFLICT
DO NOTHING RETURNING id`, отказ внешнего ключа `audit_id → audit_log.id` с `23503`, `CHECK`
доменов и append-only права роли приложения. Это держит живой файл
`tests/integration/test_audit_notify_db.py` (шаг job'а `миграции`), а путь «маршрут → решение →
строка» — `tests/integration/test_audit_notify_web.py`.

**Зачем ключи pinned векторами.** Если материал ключа меняется (другая нормализация адреса,
другой разделитель, другая длина хэша), уже записанные на площадке строки перестают узнавать
«это сочетание уже уведомляли»: площадка начинает считать новым то, о чём уже предупреждала, и
делает это молча — таблица-то заполнена. Поэтому ожидаемые строки записаны значениями, а не
вычислены теми же функциями: правка материала красится здесь, и она обязана сопровождаться
записью в `ADR-028` (п. 5 и «риски»).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

import pytest

from packages.identity.audit import AuditRecordError
from packages.identity.notify import (
    AUDIT_NOTIFY_LOGIN_COOLDOWN_S,
    AUDIT_NOTIFY_REASONS,
    AUTH_STEP_FULL,
    DEVICE_MAX_CHARS,
    GROUND_BACKUP_CODE_SPENT,
    GROUND_LOGIN,
    KEY_HASH_CHARS,
    NO_ADDRESS_MARKER,
    OPAQUE_ADDRESS_PREFIX,
    PAIR_FP_CHARS,
    REASON_BACKUP_CODE_SPENT,
    REASON_KNOWN_PAIR,
    REASON_LOGIN_COOLDOWN,
    REASON_NEW_PAIR,
    LoginNoticeState,
    LoginPair,
    NotifyDecision,
    NotifyDecisionError,
    backup_code_dedup_key,
    decide_backup_code_notice,
    decide_login_notice,
    grounds_without_producer,
    login_dedup_key,
    login_pair,
    normalize_address_material,
    normalize_device,
)
from packages.storage.models import (
    AUDIT_NOTIFY_GROUNDS,
    AUDIT_NOTIFY_OUTCOMES,
    SESSION_AUTH_STEPS,
)

#: Фиксированная учётная запись векторов. Значение постоянное намеренно: ключ обязан читаться
#: человеком (`основание:учётная_запись:хэш`), а «плавающий» идентификатор сделал бы вектор
#: невоспроизводимым при разборе красного CI.
_ACCOUNT: Final = UUID("00000000-0000-0000-0000-000000000001")
_OTHER_ACCOUNT: Final = UUID("00000000-0000-0000-0000-000000000009")
_CODE_ID: Final = UUID("00000000-0000-0000-0000-000000000002")

#: Зафиксированные ключи (`ADR-028` п. 5): материал — канонический адрес и нормализованное
#: устройство. Менять эти значения можно только вместе с записью в ADR и с пониманием, что
#: старые строки `notify` на площадке перестанут узнавать свои сочетания.
_KEY_IPV4: Final = (
    "session.login:00000000-0000-0000-0000-000000000001:22ef528dcbd64270bdfc637625bfe0ba"
)
_KEY_IPV6: Final = (
    "session.login:00000000-0000-0000-0000-000000000001:65fd0e4be453571b4777b78c779ea604"
)
_KEY_NO_ADDRESS: Final = (
    "session.login:00000000-0000-0000-0000-000000000001:0b514c31ba37b96d6442c2fbdb40408d"
)

#: Адрес и устройство векторов. Разносятся константами, чтобы вызовы решений читались как
#: «вход с адреса X под устройством Y», а не как набор строковых литералов.
_ADDRESS_A: Final = "198.51.100.7"
_ADDRESS_B: Final = "198.51.100.8"
_DEVICE_A: Final = "Mozilla/5.0 (X11; Linux x86_64)"
_DEVICE_B: Final = "Mozilla/5.0 (Windows NT 10.0)"

_NOW: Final = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def _pair(
    address: str | None = _ADDRESS_A,
    user_agent: str | None = _DEVICE_A,
    user_id: UUID = _ACCOUNT,
) -> LoginPair:
    return login_pair(user_id=user_id, address=address, user_agent=user_agent)


# ─── ключ деидентификации сочетания (§8.7, `ADR-028` п. 5) ────────────────────────────────────


def test_ключ_сочетания_детерминирован_и_зафиксирован_значениями() -> None:
    """Векторы записаны значениями: материал ключа — канонический адрес и нормализованное устройство.

    Проверка обязана быть на значениях, а не «та же функция против себя»: иначе любая правка
    материала прошла бы зелёной, а уже записанные строки перестали бы узнавать свои сочетания.
    """
    assert login_dedup_key(user_id=_ACCOUNT, address=_ADDRESS_A, user_agent=_DEVICE_A) == _KEY_IPV4
    assert (
        login_dedup_key(user_id=_ACCOUNT, address="2001:DB8::0042", user_agent="curl/8.5.0   ")
        == _KEY_IPV6
    )
    assert login_dedup_key(user_id=_ACCOUNT, address=None, user_agent=None) == _KEY_NO_ADDRESS
    # Повторный вызов даёт тот же ключ: «этот адрес уже уведомляли» обязано читаться из таблицы,
    # а не из угадывания, как именно в этот раз нормализовали заголовок.
    assert login_dedup_key(user_id=_ACCOUNT, address=_ADDRESS_A, user_agent=_DEVICE_A) == _KEY_IPV4
    assert _pair().dedup_key == _KEY_IPV4, "ключ из пары и ключ из функции разошлись"


def test_форма_ключа_проходит_ограничение_колонки_и_не_несёт_значений() -> None:
    """`ck_web_audit_outbox_dedup_key_format` (`^[a-z0-9._:-]{1,128}$`) и длина хэша.

    Значение адреса и значение `User-Agent` в ключе не печатаются: журнал, дамп и страница
    раздела администрирования не должны становиться вторым носителем этих значений (`ADR-025`
    п. 2, публичный репозиторий по `ADR-019`). При этом ключ обязан оставаться читаемым:
    префикс — имя основания, затем идентификатор учётной записи.
    """
    for key in (_KEY_IPV4, _KEY_IPV6, _KEY_NO_ADDRESS):
        prefix, account, digest = key.split(":", 2)
        assert prefix == GROUND_LOGIN, f"префикс ключа {key!r} разошёлся с именем основания"
        assert account == str(_ACCOUNT), f"идентификатор учётной записи в ключе {key!r} не тот"
        assert len(digest) == KEY_HASH_CHARS, f"хэш в ключе {key!r} другой длины"
        assert len(key) <= 128, f"ключ {key!r} длиннее колонки"
        assert all(
            ch.islower() or ch.isdigit() or ch in "._:-" for ch in key
        ), f"ключ {key!r} содержит символ вне алфавита колонки"
    assert _ADDRESS_A not in _KEY_IPV4, "адрес попал в ключ целиком"
    assert "2001:DB8" not in _KEY_IPV6.replace(
        "2001:db8", ""
    ), "адрес попал в ключ в исходной (неканонической) форме"
    assert "Mozilla" not in _KEY_IPV4, "значение User-Agent попало в ключ целиком"
    assert "curl" not in _KEY_IPV6, "значение User-Agent попало в ключ целиком"


def test_нормализация_материала_совпадает_с_журналом_и_записью_сеанса() -> None:
    """Ключ обязан считаться по тем же значениям, что лежат в `audit_log.ip` и `sessions.user_agent`.

    Разные формы одного соединения дали бы два ключа, и порог «этот адрес уже уведомляли»
    перестал бы работать ровно там, где он нужен, — под правым элементом `X-Forwarded-For` от
    Caddy (`ADR-009`). Маршрут получает адрес из `session_ip` (`apps/web/security/sessions.py`),
    который сам приводит значение к каноническому тексту, а журнал приводит его `canonical_ip`:
    оба пути обязаны сходиться на IPv4-mapped и на написании IPv6, иначе одна площадка считала бы
    адрес по-разному в колонке `audit_log.ip`, в ключе счётчика лимитов и в ключе порога.
    """
    assert (
        login_dedup_key(user_id=_ACCOUNT, address="::ffff:198.51.100.7", user_agent=_DEVICE_A)
        == _KEY_IPV4
    ), "IPv4-mapped дал другой ключ: одна площадка считает адрес по-разному в двух местах"
    assert login_dedup_key(
        user_id=_ACCOUNT, address="2001:0DB8:0000:0000:0000:0000:0000:0042", user_agent=_DEVICE_A
    ) == login_dedup_key(
        user_id=_ACCOUNT, address="2001:db8::42", user_agent=_DEVICE_A
    ), "разное написание одного IPv6 дало бы два ключа и два уведомления"
    assert (
        normalize_address_material(None) == NO_ADDRESS_MARKER
    ), "вход без адреса обязан отличаться от входа с пустым адресом"
    assert normalize_device("  Mozilla   5.0 ") == "Mozilla 5.0"
    assert normalize_device(None) == ""
    # Ограничение длины — то же, что у `clamp_user_agent` (`USER_AGENT_MAX_LEN`): маршрут режет
    # значение до записи в сеанс, и ключ обязан считаться по порезанному материалу.
    long_agent = "a" * (DEVICE_MAX_CHARS + 400)
    assert len(normalize_device(long_agent)) == DEVICE_MAX_CHARS
    assert login_dedup_key(user_id=_ACCOUNT, address="203.0.113.9", user_agent=long_agent) == (
        login_dedup_key(user_id=_ACCOUNT, address="203.0.113.9", user_agent="a" * DEVICE_MAX_CHARS)
    ), "ключ посчитан по неполному значению: одно соединение дало бы два ключа"


def test_нераспознанный_адрес_идёт_в_ключ_отпечатком_и_не_бросает() -> None:
    """Значение адреса, которое политика журнала не приняла, не роняет вход и не печатается.

    `canonical_ip` бросает `AuditRecordError` на значение, которое адресом не является, и для
    журнала это правильно: строка с выдуманным адресом не должна появляться в протоколе. В пути
    уведомления бросать нельзя: вход уже состоялся и записан, а исключение из уведомления
    превратило бы успешный вход в `500`. Печатать нераспознанное значение — значит сделать из
    ключа второй носитель произвольной строки. Поэтому форма — `opaque:<хэш>`: повтор одного и
    того же значения узнаётся, разного — различается.
    """
    garbage = "198.51.100.07"  # ведущий ноль: политика `canonical_ip` такой адрес отклоняет
    material = normalize_address_material(garbage)
    assert material.startswith(
        OPAQUE_ADDRESS_PREFIX
    ), f"ожидалась форма {OPAQUE_ADDRESS_PREFIX!r}, получено {material!r}"
    assert garbage not in material, "нераспознанное значение попало в материал ключа целиком"
    assert material == normalize_address_material(
        garbage
    ), "отпечаток нераспознанного значения неустойчив"
    assert material != normalize_address_material("198.51.100.08")
    # Форма `unknown:203.0.113.7:5678`, которую оставляют чужие прокси, адресом не является и
    # попадает сюда же: `canonical_ip` её не принимает, и вытаскивать из неё адрес ключ не должен
    # — маршрут обязан отдавать канонический текст из `session_ip`.
    assert normalize_address_material("unknown:203.0.113.7:5678") != normalize_address_material(
        "203.0.113.7"
    ), "нераспознанная форма притворилась разобранной"
    assert all(
        ch.islower() or ch.isdigit() or ch in "._:-" for ch in material
    ), "материал вышел за алфавит формата ключа"
    # Главное: вызов не бросает, а ключ строится — вход с мусорным адресом остаётся входом.
    assert login_dedup_key(user_id=_ACCOUNT, address=garbage, user_agent=_DEVICE_A).startswith(
        f"{GROUND_LOGIN}:{_ACCOUNT}:"
    )


def test_разные_учётные_записи_и_разные_сочетания_дают_разные_ключи() -> None:
    """Сочетание различает и адрес, и устройство, и учётную запись.

    Ключ без учётной записи сделал бы «уже уведомляли» общим для всех: вход сотрудника `A` с
    адреса X закрыл бы уведомление о входе сотрудника `B` с того же адреса (§8.7 говорит о входе
    пользователя, а не об адресе как таковом).
    """
    keys = {
        login_dedup_key(user_id=_ACCOUNT, address=_ADDRESS_A, user_agent=_DEVICE_A),
        login_dedup_key(user_id=_OTHER_ACCOUNT, address=_ADDRESS_A, user_agent=_DEVICE_A),
        login_dedup_key(user_id=_ACCOUNT, address=_ADDRESS_B, user_agent=_DEVICE_A),
        login_dedup_key(user_id=_ACCOUNT, address=_ADDRESS_A, user_agent=_DEVICE_B),
    }
    assert len(keys) == 4, "разные сочетания или разные учётные записи склеились в один ключ"


def test_отпечатки_половинок_позволяют_отличить_новый_адрес_от_нового_устройства() -> None:
    """§8.7: «вход нового пользователя (новый IP/устройство)» — различие читается из `details`.

    Граница среза по `docs/HANDOFF.md §2` п. 3 и `ADR-025` п. 9 требует, чтобы различие
    «новый адрес» / «новое устройство» читалось из деталей строки. Ключ держит пару целиком
    (иначе одно событие дало бы два ключа), поэтому различие несут отпечатки половинок: у пары,
    отличающейся адресом, `address_fp` разный при одинаковом `device_fp`, и наоборот.

    Отпечатки — усечённые хэши канонического материала, а не значения: страница раздела
    администрирования и дамп журнала не должны становиться вторым носителем адреса и `User-Agent`.
    """
    same_device_other_address = _pair(address=_ADDRESS_B)
    same_address_other_device = _pair(user_agent=_DEVICE_B)
    assert (
        _pair().address_fp != same_device_other_address.address_fp
    ), "новый адрес не отличим: отпечаток адреса совпал"
    assert (
        _pair().device_fp == same_device_other_address.device_fp
    ), "устройство то же, а отпечаток изменился: разбор показал бы новое устройство там, где его нет"
    assert _pair().device_fp != same_address_other_device.device_fp
    assert _pair().address_fp == same_address_other_device.address_fp
    for fingerprint in (_pair().address_fp, _pair().device_fp):
        assert len(fingerprint) == PAIR_FP_CHARS, f"отпечаток {fingerprint!r} другой длины"
        assert all(ch in "0123456789abcdef" for ch in fingerprint)
    assert _ADDRESS_A not in _pair().address_fp, "адрес попал в отпечаток целиком"
    assert _DEVICE_A not in _pair().device_fp, "значение устройства попало в отпечаток целиком"
    # Нормализация общая: leading-zero-форма не должна существовать, а IPv4-mapped даёт тот же
    # отпечаток, что и канонический адрес.
    assert (
        _pair().address_fp
        == login_pair(
            user_id=_ACCOUNT, address="::ffff:198.51.100.7", user_agent=_DEVICE_A
        ).address_fp
    )


# ─── ключ повода «расход резервного кода» ─────────────────────────────────────────────────────


def test_ключ_расхода_кода_держит_идентификатор_строки_а_не_значение() -> None:
    """`backup_code.spent:{id}` — идентификатор строки `backup_codes`.

    Значение резервного кода и его хэш в ключ попасть не могут: это проверочное значение входа
    (`ADR-016` п. 3–4, `_DETAIL_KEY_DENYLIST` журнала).
    """
    key = backup_code_dedup_key(_CODE_ID)
    assert key == f"{GROUND_BACKUP_CODE_SPENT}:{_CODE_ID}"
    assert key != backup_code_dedup_key(UUID("00000000-0000-0000-0000-000000000003"))


# ─── порог входа (§8.7 «вход нового пользователя (новый IP/устройство)») ──────────────────────


def test_первое_сочетание_даёт_уведомление_с_ключом() -> None:
    """Первое сочетание — это и есть требование §8.7; строка обязана нести ключ.

    Ключ у `notify` — не украшение: без него база отклоняет строку
    (`ck_web_audit_outbox_notify_has_dedup_key`), и стражу повтора нечего было бы проверять.
    """
    pair = _pair()
    decision = decide_login_notice(
        LoginNoticeState(known_pair=False, last_notify_at=None),
        pair=pair,
        user_id=_ACCOUNT,
        now=_NOW,
        auth_step=AUTH_STEP_FULL,
    )
    assert decision.ground == GROUND_LOGIN
    assert decision.outcome == "notify"
    assert decision.reason == REASON_NEW_PAIR
    assert decision.dedup_key == pair.dedup_key
    assert decision.details == {
        "auth_step": AUTH_STEP_FULL,
        "address_fp": pair.address_fp,
        "device_fp": pair.device_fp,
    }, (
        "в деталях обязаны быть шаг и оба отпечатка: шаг отличает полный вход от принятого "
        "пароля, отпечатки показывают, что стало новым — адрес или устройство (§8.7)"
    )


def test_известное_сочетание_вне_окна_молчит_и_пишет_причину() -> None:
    """`muted` строкой, а не отсутствием строки: «порог промолчал» обязано читаться (`ADR-028` п. 4)."""
    decision = decide_login_notice(
        LoginNoticeState(known_pair=True, last_notify_at=_NOW - timedelta(days=1)),
        pair=_pair(),
        user_id=_ACCOUNT,
        now=_NOW,
        auth_step=AUTH_STEP_FULL,
    )
    assert (decision.outcome, decision.reason) == ("muted", REASON_KNOWN_PAIR)
    assert decision.dedup_key is None, (
        "у строки `muted` ключа нет намеренно: иначе на одно основание было бы одно молчание "
        "за всё время"
    )


@pytest.mark.parametrize(
    ("elapsed", "ожидание"),
    [
        (timedelta(seconds=1), REASON_LOGIN_COOLDOWN),
        (timedelta(seconds=AUDIT_NOTIFY_LOGIN_COOLDOWN_S - 1), REASON_LOGIN_COOLDOWN),
        (timedelta(seconds=AUDIT_NOTIFY_LOGIN_COOLDOWN_S), REASON_KNOWN_PAIR),
        (timedelta(days=2), REASON_KNOWN_PAIR),
    ],
)
def test_окно_кулдауна_граница_строго_меньше(elapsed: timedelta, ожидание: str) -> None:
    """Граница порога — `elapsed < AUDIT_NOTIFY_LOGIN_COOLDOWN_S`, а не `<=`.

    Граница принципиальна для разбора: «окно ещё живёт» и «окно закрылось» дают разные коды
    причины, и вторая половина пары обязана быть достижимой — иначе молчание навсегда
    прикрепилось бы к основанию.
    """
    decision = decide_login_notice(
        LoginNoticeState(known_pair=True, last_notify_at=_NOW - elapsed),
        pair=_pair(),
        user_id=_ACCOUNT,
        now=_NOW,
        auth_step=AUTH_STEP_FULL,
    )
    assert decision.outcome == "muted"
    assert decision.reason == ожидание, f"через {elapsed} ожидалась причина {ожидание}"
    if ожидание == REASON_LOGIN_COOLDOWN:
        assert decision.details == {
            "auth_step": AUTH_STEP_FULL,
            "address_fp": _pair().address_fp,
            "device_fp": _pair().device_fp,
            "cooldown_s": AUDIT_NOTIFY_LOGIN_COOLDOWN_S,
        }, "разбор обязан видеть, каким числом молчание объяснено"


def test_новое_сочетание_в_окне_кулдауна_тоже_молчит() -> None:
    """Порог шума (§10.1 «при массовых событиях — агрегация») стоит до правила о новом сочетании.

    У мобильного клиента адрес меняется на каждую выдачу провайдера, и каждое такое значение —
    «новое сочетание». Если бы правило о новом сочетании проверялось первым, порог шумел бы ровно
    там, для чего написан, а §8.3 от этого не защищает: входы успешны, счётчик неудач молчит.
    """
    decision = decide_login_notice(
        LoginNoticeState(known_pair=False, last_notify_at=_NOW - timedelta(minutes=2)),
        pair=_pair(address=_ADDRESS_B),
        user_id=_ACCOUNT,
        now=_NOW,
        auth_step=AUTH_STEP_FULL,
    )
    assert (decision.outcome, decision.reason) == ("muted", REASON_LOGIN_COOLDOWN)
    assert decision.dedup_key is None, (
        "молчание не занимает ключ: иначе следующее новое сочетание было бы объявлено "
        "уже уведомлённым и молчало бы навсегда"
    )


def test_последний_прогон_не_известен_но_ключ_занят_молчит_known_pair() -> None:
    """`known_pair=True` при `last_notify_at is None` — состояние повреждённой таблицы.

    Так бывает, если строка с этим ключом есть, но её `at` не прочитался как строка `notify`
    этого основания. Решение — промолчать без кулдауна: «уже уведомляли» важнее, чем «когда
    именно», и выдумывать срок нельзя.
    """
    decision = decide_login_notice(
        LoginNoticeState(known_pair=True, last_notify_at=None),
        pair=_pair(),
        user_id=_ACCOUNT,
        now=_NOW,
        auth_step=AUTH_STEP_FULL,
    )
    assert (decision.outcome, decision.reason) == ("muted", REASON_KNOWN_PAIR)


def test_расход_резервного_кода_всегда_даёт_кандидата() -> None:
    """Порога на этот повод нет сознательно (§8.7 называет его отдельно).

    Кулдаун на расход кода молча спрятал бы инцидент: код тратят, когда обычный второй фактор
    недоступен, и это ровно тот момент, когда администратор обязан узнать о входе.
    """
    decision = decide_backup_code_notice(user_id=_ACCOUNT, backup_code_id=_CODE_ID)
    assert decision.ground == GROUND_BACKUP_CODE_SPENT
    assert decision.outcome == "notify"
    assert decision.reason == REASON_BACKUP_CODE_SPENT
    assert decision.dedup_key == backup_code_dedup_key(_CODE_ID)
    assert decision.details == {
        "backup_code_id": str(_CODE_ID)
    }, "в деталях — идентификатор строки кода, ни значения, ни его хэша"


# ─── закрытые домены и политика значений (`ADR-028` п. 3–4, `ADR-025` п. 2) ───────────────────


def test_решение_вне_домена_основания_отклоняется() -> None:
    """Имя вне `ck_web_audit_outbox_ground` отклоняется до `INSERT`.

    Класс отказа обязан быть тот же, что у базы: иначе «основание §8.7 появилось по ходу»
    обнаруживалось бы только на живой площадке.
    """
    with pytest.raises(NotifyDecisionError, match="нет в домене"):
        NotifyDecision(
            ground="account.role_changed",
            outcome="notify",
            reason=REASON_NEW_PAIR,
            dedup_key="session.login:x:y",
            user_id=_ACCOUNT,
        )


def test_решение_вне_домена_вердикта_и_причины_отклоняется() -> None:
    """Третьего вердикта («отправлено», «доставлено») здесь быть не может (`ADR-028` п. 4).

    Причина вне словаря — та же ловушка: формат колонки её пропускает, а перечень причин
    перестаёт читаться.
    """
    for outcome in ("sent", "delivered", "queued"):
        with pytest.raises(NotifyDecisionError, match="нет в домене решений"):
            NotifyDecision(
                ground=GROUND_LOGIN,
                outcome=outcome,
                reason=REASON_NEW_PAIR,
                dedup_key="session.login:x:y",
                user_id=_ACCOUNT,
            )
    for reason in ("send_failed", "already_sent", "new_cause"):
        with pytest.raises(NotifyDecisionError, match="нет в словаре"):
            NotifyDecision(
                ground=GROUND_LOGIN,
                outcome="muted",
                reason=reason,
                dedup_key=None,
                user_id=_ACCOUNT,
            )


def test_уведомить_без_ключа_и_ключ_вне_формата_отклоняются() -> None:
    """Ровно те же классы отказа, что `ck_web_audit_outbox_notify_has_dedup_key` и `…_format`.

    Ключ с заглавной буквой, пробелом или кириллицей означает, что в него подставили значение
    (логин, адрес, `User-Agent` целиком) — отклонить нужно до запроса.
    """
    with pytest.raises(NotifyDecisionError, match="обязано нести dedup_key"):
        NotifyDecision(
            ground=GROUND_LOGIN,
            outcome="notify",
            reason=REASON_NEW_PAIR,
            dedup_key=None,
            user_id=_ACCOUNT,
        )
    for bad in ("Session.login:x:y", "session.login:x y", "session.login:иванов:1", "", "x" * 129):
        with pytest.raises(NotifyDecisionError, match="формат колонки"):
            NotifyDecision(
                ground=GROUND_LOGIN,
                outcome="muted",
                reason=REASON_KNOWN_PAIR,
                dedup_key=bad,
                user_id=_ACCOUNT,
            )


def test_значения_details_подчиняются_политике_журнала() -> None:
    """Политика `details` одна на журнал и на решения: значения учётных данных не пишутся.

    Второго списка запрещённых ключей здесь нет намеренно — проверку держит
    `_DETAIL_KEY_DENYLIST` (`ADR-025` п. 2), и расхождения двух списков быть не может.
    """
    with pytest.raises(AuditRecordError, match="похож на значение секрета"):
        NotifyDecision(
            ground=GROUND_BACKUP_CODE_SPENT,
            outcome="notify",
            reason=REASON_BACKUP_CODE_SPENT,
            dedup_key=backup_code_dedup_key(_CODE_ID),
            user_id=_ACCOUNT,
            details={"backup_code": "ABCDE-FGHJK"},
        )
    with pytest.raises(AuditRecordError, match="нестабильным"):
        NotifyDecision(
            ground=GROUND_LOGIN,
            outcome="muted",
            reason=REASON_LOGIN_COOLDOWN,
            dedup_key=None,
            user_id=_ACCOUNT,
            details={"cooldown_s": 300.5},
        )
    # Целые счётчики и коды — проходят: разбор обязан видеть окно порога числом.
    assert (
        NotifyDecision(
            ground=GROUND_LOGIN,
            outcome="muted",
            reason=REASON_LOGIN_COOLDOWN,
            dedup_key=None,
            user_id=_ACCOUNT,
            details={"auth_step": AUTH_STEP_FULL, "cooldown_s": AUDIT_NOTIFY_LOGIN_COOLDOWN_S},
        ).reason
        == REASON_LOGIN_COOLDOWN
    )


def test_домены_базы_словарь_причин_и_шаг_входа_совпадают() -> None:
    """Один источник имён: домен `ck_web_audit_outbox_ground`/`…_outcome`, словарь причин, шаг.

    `AUTH_STEP_FULL` обязан входить в `SESSION_AUTH_STEPS`: опечатка в этом значении означала бы,
    что уведомлений о входах нет вовсе, а пустая таблица выглядела бы «правильной».
    """
    assert GROUND_LOGIN in AUDIT_NOTIFY_GROUNDS
    assert GROUND_BACKUP_CODE_SPENT in AUDIT_NOTIFY_GROUNDS
    assert set(AUDIT_NOTIFY_OUTCOMES) == {"notify", "muted"}
    assert {
        REASON_NEW_PAIR,
        REASON_LOGIN_COOLDOWN,
        REASON_KNOWN_PAIR,
        REASON_BACKUP_CODE_SPENT,
    } == set(
        AUDIT_NOTIFY_REASONS
    ), "словарь причин разошёлся с перечнем: база формат пропускает, а контракт не заметил бы"
    assert AUTH_STEP_FULL in SESSION_AUTH_STEPS


def test_основания_без_производителя_зафиксированы_явно() -> None:
    """Три имени §8.7 стоят в домене без производителя — это записанный остаток, а не дыра.

    Убрать их «как неиспользуемые» — значит сузить требование §8.7 до написанного; добавить
    производителя «для галочки» — значит написать событие, которого не было. Поэтому причина
    каждого отсутствия называется здесь же, где и список (`ADR-025` п. 9, `docs/HANDOFF.md §2`
    п. 3 этой задачи).
    """
    pending = grounds_without_producer()
    produced = {GROUND_LOGIN, GROUND_BACKUP_CODE_SPENT}
    assert (
        set(pending) == set(AUDIT_NOTIFY_GROUNDS) - produced
    ), f"перечень оснований без производителя разошёлся с доменом базы: {sorted(pending)}"
    for ground, причина in pending.items():
        assert причина, f"основание {ground} записано без причины отсутствия"
        assert (
            "`" in причина or "M2" in причина or "M3" in причина
        ), f"причина отсутствия производителя у {ground} не указывает ни задачу, ни веху"


def test_порог_шума_держится_константой_а_не_настройкой() -> None:
    """Значение порога — константа кода, а не переменная окружения или поля настроек.

    Порог, который можно поменять конфигурацией деплоя, перестаёт быть частью контракта: та же
    сборка вела бы себя по-разному на площадке и на стенде, а `ADR-028` п. 6 описывает правило,
    а не настройку.
    """
    assert AUDIT_NOTIFY_LOGIN_COOLDOWN_S == 300, (
        "число совпадает с окном перебора §8.2 сознательно (`ADR-028` п. 6): менять его нужно "
        "вместе с ADR, а не точкой конфигурации"
    )
