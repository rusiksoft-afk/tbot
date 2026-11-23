"""Журнал аудита: канонический вид записи, цепочка хэшей, реестр событий (TZ §4.1, §8.7, `T-109`, `ADR-025`).

Живая половинка — `tests/integration/test_audit_chain_db.py` (CI job `миграции`): там цепочка
строится и разбирается по настоящему `audit_log`, где `id` выдаёт база, `details` проходит через
`jsonb`, а адрес читается объектом `ipaddress`. Здесь — то, что видно без сервера:

* **векторы хэша.** Фиксированные SHA-256 на фиксированные записи (полную и «голую» первую):
  молчаливая смена рецептуры — формата времени, порядка частей, разделителей — означала бы, что
  уже записанная на площадке цепочка перестала бы сходиться. Дешевлей узнать это здесь, чем при
  разборе инцидента;
* **каноничность.** одна запись, записанная по-разному (порядок ключей `details`, форма адреса,
  часовой пояс момента), обязана давать один хэш, и разный — если изменилось существенное:
  `hash_prev` входит в материал, иначе «вставили строку в середину» не двигает ничего;
* **политика записи `details`:** нецелые числа и ключи, похожие на значения секретов,
  отклоняются. Первое ломает совпадение «отхэшировали ↔ прочитали» (`jsonb` хранит число как
  `numeric`), второе запрещено `ADR-004` в публичном репозитории (`ADR-019`);
* **разрывы находят, а не пропускают:** подделка содержимого, вырез строки, развилка, обрезанное
  начало и выборка не по `id` — разные коды (`AC-identity-04`: «`audit-verify` на изменённой
  вручную копии дампа → найден разрыв»);
* **реестр событий сверяется с текстом §8.7**, а не с памятью среза: каждая строка перечня ТЗ
  обязана быть покрыта хотя бы одним идентификатором, а каждое имя вне перечня — стоять в
  явном списке оснований.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, cast
from uuid import UUID

import pytest

from packages.common.clock import MSK_TZ
from packages.identity.audit import (
    AUDIT_ACTIONS,
    AuditRecord,
    AuditRecordError,
    StoredRecord,
    build_audit_entry,
    canonical_at,
    canonical_ip,
    chain_from_drafts,
    make_record,
    read_stored_record,
    record_of_entry,
    verify_chain,
)
from packages.storage.models import AuditLogEntry

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"

#: Момент и идентификаторы векторов постоянны: значение хэша обязано быть тем же на любой машине
#: и в любом часовом поясе раннера.
VECTOR_AT: Final = datetime(2026, 11, 23, 9, 20, 5, 123456, tzinfo=UTC)
GENESIS_AT: Final = datetime(2026, 11, 23, 4, 49, 0, tzinfo=UTC)
VECTOR_ACTOR: Final = UUID("01a2075d-bdb5-7c8b-94f8-a7c7c85a2bde")
VECTOR_REQUEST: Final = UUID("01a20774-0bd8-7000-8000-000000000001")
VECTOR_PREV: Final = "3f7a1c0e5b9d4c8a6e2f10b7d9c8a5b4e3d2c1f0a9b8c7d6e5f4a3b2c1d0e9f8"

#: Хэш полной записи по рецептуре `SHA-256("tbot-audit-v1" || "\n" || канонический JSON ||
#: "\n" || hash_prev)` и хэш «голой» первой записи цепочки (`hash_prev` пуст, второй частью
#: идёт пустая строка). Держатся здесь ровно ради одного: чтобы смена рецептуры не прошла
#: незаметно, включая случай «начало цепочки хэшируется иначе, чем продолжение».
VECTOR_HASH: Final = "d374f8c2def6b56241e731e07b3c6c663f817df2bf1d7348f60a3524bc40c786"
GENESIS_HASH: Final = "590ed0c0974bb9f51a181dc160991a839226803d17851a056235080c71f739d5"


def _vector_record(*, hash_prev: str | None = VECTOR_PREV) -> AuditRecord:
    return make_record(
        action="backup_code.spent",
        at=VECTOR_AT,
        actor=VECTOR_ACTOR,
        entity="backup_code",
        entity_id="01a20774-0bd8-7000-8000-0000000000aa",
        details={"codes_left": 9, "reason": "recovery", "note": None, "codes_в_пачке": 10},
        ip="2001:0DB8:0000:0000:0000:0000:0000:0007",
        request_id=VECTOR_REQUEST,
        hash_prev=hash_prev,
    )


def _tz_section() -> str:
    text = TZ_SECURITY.read_text(encoding="utf-8")
    match = re.search(r"## 8\.7 .*\n(.*?)(?=\n## )", text, re.S)
    assert match is not None, "в ТЗ нет секции 8.7 — сверка реестра событий потеряла основание"
    # Перечисления ТЗ напечатаны с переносом строки посреди фразы — в том числе сразу после
    # слэша («подключение/ротация/⏎отзыв токена»), где пробел не ставился. Сравнение идёт по
    # тексту без пробелов: иначе фраза «не найдена» из-за вёрстки, а не из-за смысла.
    return re.sub(r"\s+", "", match.group(0))


# ─── векторы и каноничность ─────────────────────────────────────────────────────────────────


def test_векторы_записей_и_их_хэши_фиксированы() -> None:
    """Рецептура хэша не должна меняться незаметно (`REQ-identity-04`)."""
    record = _vector_record()
    assert canonical_at(record.at) == "2026-11-23T09:20:05.123456+00:00"
    assert record.ip == "2001:db8::7"
    assert record.canonical_json() == (
        '{"action":"backup_code.spent",'
        f'"actor":"{VECTOR_ACTOR}",'
        '"at":"2026-11-23T09:20:05.123456+00:00",'
        '"details":{"codes_left":9,"codes_в_пачке":10,"note":null,"reason":"recovery"},'
        '"entity":"backup_code","entity_id":"01a20774-0bd8-7000-8000-0000000000aa",'
        f'"ip":"2001:db8::7","request_id":"{VECTOR_REQUEST}"}}'
    )
    assert record.content_hash() == VECTOR_HASH

    genesis = make_record(action="session.login", at=GENESIS_AT)
    assert genesis.canonical_json() == (
        '{"action":"session.login","actor":null,"at":"2026-11-23T04:49:00.000000+00:00",'
        '"details":null,"entity":null,"entity_id":null,"ip":null,"request_id":null}'
    )
    assert genesis.content_hash() == GENESIS_HASH
    # Формат значения совпадает с CHECK'ом базы `ck_audit_log_hash_sha256` (ревизия `0002`).
    assert re.fullmatch(r"[0-9a-f]{64}", record.content_hash())


def test_порядок_ключей_хэш_не_меняет() -> None:
    """`jsonb` порядок ключей не сохраняет — канонический вывод обязан его не различать.

    Иначе пересчёт ломался бы на строках, где ключи вернулись в другом порядке, и «разрыв
    цепочки» стал бы обычным шумом.
    """
    first = make_record(action="session.login", details={"b": 1, "a": {"y": 2, "x": [1, 2]}})
    second = make_record(action="session.login", details={"a": {"x": [1, 2], "y": 2}, "b": 1})
    assert first.canonical_json() == second.canonical_json()
    assert first.content_hash() == second.content_hash()


def test_форма_адреса_хэш_не_меняет_а_разный_адрес_меняет() -> None:
    """Адрес приводится к каноническому тексту колонки `INET` (psycopg3 читает её объектом).

    Ведущие нули, прописные буквы и IPv4-mapped форма — один и тот же адрес: база хранит его в
    своей форме, и хэш обязан сходиться с чтением. Нормализация идемпотентна: канонический текст
    второго прохода даёт себя же.
    """
    assert canonical_ip("2001:0DB8:0000::0007") == "2001:db8::7"
    assert canonical_ip("2001:db8::7") == "2001:db8::7"
    assert canonical_ip("::ffff:127.0.0.1") == "127.0.0.1"
    assert canonical_ip(canonical_ip("::ffff:127.0.0.1")) == "127.0.0.1"
    assert canonical_ip(ipaddress.IPv6Address("2001:db8::7")) == "2001:db8::7"
    assert canonical_ip(ipaddress.IPv4Address("127.0.0.1")) == "127.0.0.1"

    hashes = {
        make_record(action="auth.rate_limited", ip=form).content_hash()
        for form in ("2001:0DB8::7", "2001:db8::7")
    }
    assert len(hashes) == 1, "разная текстовая форма одного адреса дала разные хэши"
    assert make_record(action="auth.rate_limited", ip="2001:db8::8").content_hash() not in hashes

    for bad in ("не-адрес", "2001:db8::7/64", "localhost"):
        with pytest.raises(AuditRecordError):
            canonical_ip(bad)


def test_момент_в_любом_поясе_и_нулевые_доли_дают_одну_строку() -> None:
    """Время записи — UTC с микросекундами всегда (§2.7, §4 «общие правила»).

    Момент в Москве и тот же момент в UTC — одна запись. Момент без долей обязан печататься с
    `.000000`: PostgreSQL возвращает микросекунды колонки `timestamptz`, и «строка без долей» не
    совпала бы с прочитанной.
    """
    msk = datetime(2026, 11, 23, 12, 20, 5, 123456, tzinfo=MSK_TZ)
    utc = datetime(2026, 11, 23, 9, 20, 5, 123456, tzinfo=UTC)
    assert canonical_at(msk) == canonical_at(utc) == "2026-11-23T09:20:05.123456+00:00"
    assert canonical_at(utc.replace(microsecond=0)).endswith(".000000+00:00")
    assert (
        make_record(action="session.login", at=msk).content_hash()
        == make_record(action="session.login", at=utc).content_hash()
    )
    naive = utc.replace(tzinfo=None)
    # Наивный момент отсекает `packages/common/clock.to_utc` (§2.7): хэш по неопределённому
    # времени получился бы разным на двух машинах.
    with pytest.raises(ValueError, match="tzinfo"):
        canonical_at(naive)


# ─── политика записи `details` ──────────────────────────────────────────────────────────────


def test_нецелые_числа_в_details_отклоняются() -> None:
    """`jsonb` хранит число как `numeric`: `1e2` вернётся текстом `100.0`.

    Нецелое значение сделало бы невозможным совпадение «отхэшировали при записи ↔ пересчитали при
    чтении», поэтому журнал принимает целые, строки, флаги и `None`.
    """
    for value in (1.5, Decimal("1.5"), {"вклад": 1e2}, [1.5]):
        with pytest.raises(AuditRecordError):
            make_record(action="risk.limits_changed", details={"значение": value})
    # Целое и строка — ровно та форма, которая вернётся из базы.
    assert make_record(action="risk.limits_changed", details={"порог": 100}).details == {
        "порог": 100
    }


def test_ключи_похожие_на_значения_секретов_отклоняются() -> None:
    """Значения секретов в журнал не пишут (`ADR-004`), и репозиторий публичный (`ADR-019`).

    Страховка на уровне ключа: `token`, `tokenHash`, `code-hash`, `session cookie` и вложенные
    варианты отклоняются, а безобидный `reason_code` (совпадение не целым ключом) проходит.
    """
    for key in ("password", "TOKEN", "token_hash", "code-hash", "session cookie"):
        with pytest.raises(AuditRecordError):
            make_record(action="auth.csrf_rejected", details={key: "значение"})
    with pytest.raises(AuditRecordError):
        make_record(action="session.login_failed", details={"вложенно": {"otp": 1}})
    make_record(
        action="auth.csrf_rejected", details={"reason_code": "origin_mismatch", "длина": 43}
    )


def test_значения_вне_json_отклоняются() -> None:
    """UUID и байты в `details` не пишут: в колонке `jsonb` им нет канонической формы.

    Идентификаторы подаются в `entity_id`, где `UUID` приводится к каноническому тексту
    (колонка §4.1 — `TEXT`).
    """
    for value in (VECTOR_ACTOR, b"abc", object()):
        with pytest.raises(AuditRecordError):
            make_record(action="session.revoke", details={"значение": value})
    assert make_record(action="session.revoke", entity_id=VECTOR_ACTOR).entity_id == str(
        VECTOR_ACTOR
    )
    assert make_record(action="session.revoke", entity=12).entity == "12"


# ─── реестр событий (TZ §8.7) ───────────────────────────────────────────────────────────────

#: Строки перечня §8.7 «`audit_log` обязателен для: …» → идентификаторы журнала. Ключи обязаны
#: оставаться подстроками текста ТЗ: изменит заказчик перечень — упадёт тест и потребует править
#: реестр, а не жить со старым набором.
TZ_87_EVENTS: Final[dict[str, tuple[str, ...]]] = {
    "вход/выход/неудачные попытки": ("session.login", "session.logout", "session.login_failed"),
    "привязка/отзыв 2FA": ("totp.enrolled", "totp.confirmed", "totp.revoked"),
    "расход резервного кода": ("backup_code.spent",),
    "создание/изменение/удаление пользователя и роли": (
        "account.created",
        "account.state_changed",
        "account.role_changed",
    ),
    "подключение/ротация/отзыв токена": ("token.connected", "token.rotated", "token.revoked"),
    "изменение лимитов риска": ("risk.limits_changed",),
    "старт/пауза/стоп стратегии": ("strategy.started", "strategy.paused", "strategy.stopped"),
    "изменения kill-switch": ("risk.kill_switch_changed",),
    "изменения IP-allowlist": ("allowlist.changed",),
    "экспорт отчётов": ("report.exported",),
    "ручное редактирование в БД (через сервис)": ("db.manual_edit",),
    "деплой": ("deploy.applied",),
}

#: Имена вне перечня §8.7 — каждое с основанием. Расширение допускается, но только перечисленное:
#: иначе за два среза реестр обрастает именами «по месту», и сверка с ТЗ теряет смысл.
EXTRA_EVENTS: Final[dict[str, str]] = {
    # Квалифицированный отзыв сеанса (§8.3, `ADR-010`): именно его не удалось восстановить
    # серверным следом при приёмке 2026-11-23 (отзыв строки в 08:19:08 UTC) —
    # `docs/HANDOFF.md §1.60` п. 7 и протокол `prod-accept-t106-auth-half.md §7.2.2`.
    "session.revoke": "TZ §8.3 квалифицированный отзыв; замер приёмки §7.2.2",
    "session.revoke_all": "TZ §8.3 отзыв всех сеансов (`ADR-010`)",
    # Смена пароля: §8.1 и §8.8 требуют отзыва сеансов; §8.7 покрывает это как «изменение
    # пользователя», но отзыв должен читаться следствием смены, а не самостоятельным действием.
    "account.password_changed": "TZ §8.1 смена пароля, §8.8 «смена пароля отзывает сессии»",
    # Церемония приглашений (`ADR-020`, `ADR-021`): «все попытки использования ссылки» (§1.2).
    "invitation.issued": "`ADR-020` выпуск ссылки (TZ §1.2)",
    "invitation.accepted": "`ADR-021` приём ссылки (TZ §1.2)",
    "invitation.accept_failed": "`ADR-021` п. 11: различимые коды отказа приёма",
    "invitation.revoked": "`ADR-020` отзыв выпуска",
    "account.approved": "`ADR-021` одобрение учётной записи (TZ §1.2)",
    # 2FA и резервные коды: §8.2, `ADR-013`, `ADR-016` требуют различать отказ кода, выпуск
    # пачки и её обесценивание.
    "totp.verify_failed": "TZ §8.2 неудачный код 2FA (след `totp_failures` + журнал)",
    "backup_codes.issued": "`ADR-016` выпуск пачки кодов",
    "backup_codes.invalidated": "`ADR-016` обесценивание неиспользованных кодов",
    # Отказ частоты и отказа допуска: `ADR-007` требует записывать `429`, `ADR-009` п. 4 перенёс
    # это в `T-109` (замер приёмки §3.4: отказа `429` в журнале нет вовсе); CSRF и допуск — те же
    # замеры со стороны периметра (structlog-события `csrf_rejected`, `access_denied`).
    "auth.rate_limited": "`ADR-007`, `ADR-009` п. 4: отказ `429` обязан попадать в журнал",
    "auth.address_banned": "TZ §8.2 бан адреса (`ADR-009`)",
    "auth.access_denied": "TZ §8.8 «доступ `operator` к чужим данным», `ADR-017`",
    "auth.csrf_rejected": "TZ §8.3 «CSRF обязателен для всех POST», `ADR-008`",
    # Ежедневная `integrity-check` (§8.7): сверка цепочки — задача, а не действие пользователя,
    # поэтому имени в первом предложении §8.7 нет. Без строки-носителя находка разбора остаётся
    # только в stderr крона: ни уведомления (§8.7), ни повторной сверки по дампу (§4.1
    # `REQ-identity-04`).
    "integrity.audit_chain": "TZ §8.7 `integrity-check`, §4.1 `REQ-identity-04`",
}


def test_реестр_покрывает_каждую_строку_8_7() -> None:
    section = _tz_section()
    for phrase, names in TZ_87_EVENTS.items():
        needle = phrase.replace(" ", "")
        assert (
            needle in section
        ), f"строка §8.7 {phrase!r} исчезла из текста ТЗ — сверку реестра событий надо править"
        assert names, f"{phrase!r}: нет ни одного идентификатора журнала"
        missing = [name for name in names if name not in AUDIT_ACTIONS]
        assert not missing, f"§8.7 {phrase!r} не покрыт реестром: {missing}"


def test_реестр_замкнут_у_каждого_имени_есть_основание() -> None:
    """Новое имя журнала обязано появиться либо из §8.7, либо из перечня оснований."""
    from_tz = {name for names in TZ_87_EVENTS.values() for name in names}
    overlap = from_tz & set(EXTRA_EVENTS)
    assert not overlap, f"имя попало в оба перечня одновременно: {sorted(overlap)}"
    unexplained = set(AUDIT_ACTIONS) - from_tz - set(EXTRA_EVENTS)
    unused = set(EXTRA_EVENTS) - set(AUDIT_ACTIONS)
    assert not unexplained, f"в реестре появились имена без основания: {sorted(unexplained)}"
    assert not unused, f"основания остались у имён, которых в реестре нет: {sorted(unused)}"
    assert all(reason.strip() for reason in EXTRA_EVENTS.values())


def test_имена_событий_с_доменом_и_всего_имен_столько_сколько_оснований() -> None:
    """Имя события — `домен.действие`: строка журнала без домена не отвечает на вопрос «чего»."""
    for name in AUDIT_ACTIONS:
        assert re.fullmatch(r"[a-z][a-z_]*(\.[a-z_][a-z_]*)+", name), f"имя {name} вне формата"
    justified = {name for names in TZ_87_EVENTS.values() for name in names} | set(EXTRA_EVENTS)
    assert frozenset(justified) == AUDIT_ACTIONS, (
        "реестр событий и перечни оснований разошлись: основания есть у "
        f"{sorted(justified - set(AUDIT_ACTIONS))}, в реестре лишние "
        f"{sorted(set(AUDIT_ACTIONS) - justified)}"
    )


def test_неизвестное_событие_отклоняется_известное_принимается() -> None:
    with pytest.raises(AuditRecordError):
        make_record(action="session.loginn")
    with pytest.raises(AuditRecordError):
        make_record(action="")
    with pytest.raises(AuditRecordError):
        make_record(action="session")
    # Каждое имя из реестра обязано строиться: проверка против опечаток в самих перечнях.
    for name in AUDIT_ACTIONS:
        make_record(action=name)


# ─── цепочка: построение и находки ──────────────────────────────────────────────────────────


def _draft(index: int) -> AuditRecord:
    return make_record(
        action="session.login",
        at=VECTOR_AT.replace(microsecond=index),
        entity="session",
        entity_id=f"session-{index}",
        details={"номер": index},
    )


def _built_chain(count: int = 4) -> list[StoredRecord]:
    return chain_from_drafts(_draft(index) for index in range(1, count + 1))


def test_цепочка_строится_и_проверяется_без_находок() -> None:
    built = _built_chain()
    assert built[0].record.hash_prev is None, "у первой записи предыдущего хэша нет"
    assert [row.record.hash_prev for row in built[1:]] == [row.stored_hash for row in built[:-1]]
    report = verify_chain(built)
    assert report.intact, report.summary()
    assert (report.rows, report.first_row_id, report.last_row_id) == (4, 1, 4)
    assert "цепочка цела" in report.summary()


def test_подделка_содержимого_обнаруживается() -> None:
    """`AC-identity-04`: изменённую вручную строку обязано найти, а не пропустить.

    Здесь ровно то, что делает правка правами владельца схемы: значение колонки поменяли, колонку
    `hash` не тронули. Пересчёт расходится, и находка указывает конкретную строку.
    """
    built = _built_chain(3)
    target = built[1]
    forged = StoredRecord(
        row_id=target.row_id,
        record=AuditRecord(
            at=target.record.at,
            action="session.login",
            entity="session",
            entity_id="подделка",
            details={"номер": 999},
            hash_prev=target.record.hash_prev,
        ),
        stored_hash=target.stored_hash,
    )
    report = verify_chain([built[0], forged, built[2]])
    kinds = {issue.kind for issue in report.issues}
    assert kinds == {"content_mismatch"}, report.summary()
    issue = report.issues[0]
    assert (issue.row_id, issue.previous_id) == (2, 1)
    assert not report.intact
    assert "цепочка нарушена" in report.summary()
    assert "строка 2 (после 1)" in report.summary()


def test_вырез_строки_обнаруживается() -> None:
    """Строку удалили правами владельца — связь следующей строки рвётся (`broken_link`)."""
    built = _built_chain(4)
    report = verify_chain([built[0], built[2], built[3]])
    kinds = {issue.kind for issue in report.issues}
    assert kinds == {"broken_link"}, report.summary()
    assert (report.issues[0].row_id, report.issues[0].previous_id) == (3, 1)


def test_развилка_обнаруживается_отдельным_кодом() -> None:
    """Две строки на одного предка.

    На живой базе развилку закрывает частичный уникальный индекс `ix_audit_log_hash_prev_linked`
    (ревизия `0007`), но разбор запускают и на дампе, где индекса может не быть: находка обязана
    быть отдельным кодом, а не «ещё одним разрывом».
    """
    built = _built_chain(3)
    first, second, third = built
    branch = AuditRecord(
        at=third.record.at,
        action="session.login",
        entity="session",
        entity_id="ветка-2",
        hash_prev=first.stored_hash,
    )
    forked = StoredRecord(row_id=third.row_id, record=branch, stored_hash=branch.content_hash())
    report = verify_chain([first, second, forked])
    kinds = {issue.kind for issue in report.issues}
    assert kinds == {"broken_link", "duplicate_parent"}, report.summary()
    duplicate = next(issue for issue in report.issues if issue.kind == "duplicate_parent")
    # «Предок уже занят»: первой на этот хэш претендовала строка 2, развилка открыта строкой 3.
    assert (duplicate.row_id, duplicate.previous_id) == (3, 2)


def test_обрезанное_начало_обнаруживается_и_снимается_явным_режимом() -> None:
    """Выборка «за период» начинается не с первой строки журнала — это не поломка цепочки.

    `expect_genesis=True` (по умолчанию) требует от первой строки быть началом: иначе «впереди
    что-то было» осталось бы незамеченным при полной сверке. Для выборки по периоду (`make
    audit-verify --from …`) режим снимается явным параметром, чтобы ложная находка не выдавалась
    за разрыв.
    """
    built = _built_chain(3)
    tail = built[1:]
    assert verify_chain(built).intact
    partial = verify_chain(tail)
    assert {issue.kind for issue in partial.issues} == {"missing_prefix"}, partial.summary()
    assert verify_chain(tail, expect_genesis=False).intact


def test_связь_цепочки_входит_в_материал_хэша() -> None:
    """`hash_prev` — часть материала: сдвиг в цепочке меняет хэш последующих записей.

    Если бы связь в хэш не входила, «вставили строку в середину» оставалось бы невидимым для
    пересчёта содержимого.
    """
    base = _vector_record()
    shifted = make_record(
        action=base.action,
        at=base.at,
        actor=base.actor,
        entity=base.entity,
        entity_id=base.entity_id,
        details=base.details,
        ip=base.ip,
        request_id=base.request_id,
        hash_prev="0" * 64,
    )
    assert base.content_hash() != shifted.content_hash()
    assert base.content_hash() != _vector_record(hash_prev=None).content_hash()


def test_кривая_выборка_или_кривой_хэш_отклоняются_сразу() -> None:
    """Выборка обязана идти по `id`, а колонка `hash` — быть хэшем, а не чем попало.

    Хронологию журнала задаёт `id` (его выдаёт база, §4.1), поэтому перепутанный порядок чтения
    — ошибка инструмента, а не находка в данных: молча сравнить связи в перепутанном порядке
    означало бы нарисовать разрывы там, где их нет.
    """
    built = _built_chain(3)
    with pytest.raises(AuditRecordError):
        verify_chain([built[0], built[2], built[1]])
    with pytest.raises(AuditRecordError):
        make_record(action="session.login", hash_prev="zz")
    with pytest.raises(AuditRecordError):
        read_stored_record(
            row_id=1,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="не-хэш",
        )


def test_пустая_выборка_читается_как_пустая_а_не_как_целая() -> None:
    """Пустой журнал — отдельный случай.

    На площадке `audit_log` пуст (0 строк, замер приёмки 2026-11-23), и «цепочка цела» по пустой
    выборке было бы неправдой: инструмент обязан сказать, что строк не прочитано.
    """
    report = verify_chain([])
    assert report.intact
    assert report.rows == 0
    assert report.first_row_id is None
    assert report.last_row_id is None
    assert "цепочка пуста" in report.summary()


# ─── строка журнала и её прочтение ──────────────────────────────────────────────────────────


def test_построенная_строка_несёт_посчитанный_хэш_и_не_несёт_id() -> None:
    record = _vector_record()
    entry = build_audit_entry(record)
    assert isinstance(entry, AuditLogEntry)
    # `id` — identity-колонка: значение выдаёт база. В модели она объявлена как `Mapped[int]`
    # (после flush оно есть всегда), поэтому «приложение id не присваивает» проверяем отсутствием
    # значения в `__dict__` объекта, а не сравнением `entry.id is None`.
    assert "id" not in entry.__dict__, (
        "identity-колонку заполняет база (TZ §4.1): присвоенный приложению id ломает и хэш, "
        "и хронологию читки цепочки"
    )
    assert entry.hash == VECTOR_HASH
    assert entry.hash_prev == VECTOR_PREV
    assert entry.ip == "2001:db8::7", "колонка INET обязана принять канонический текст"
    assert entry.at == VECTOR_AT
    assert entry.actor == VECTOR_ACTOR
    # Копия `details` обязательна: правка словаря вызывающим слоем не должна менять строку, хэш
    # которой уже посчитан.
    mutable = {"число": 1}
    draft = make_record(action="risk.limits_changed", details=mutable)
    built = build_audit_entry(draft)
    mutable["число"] = 2
    assert built.details == {"число": 1}
    assert built.hash == draft.content_hash()


def test_прочитанное_из_jsonb_значение_не_получает_политику_записи() -> None:
    """Чужую строку (прямой `INSERT`, восстановление из дампа) разбор обязан показать, а не
    оборвать отказом: политика записи работает на записи, на чтении — пересчёт и сравнение."""
    foreign = read_stored_record(
        row_id=7,
        at=VECTOR_AT,
        action="session.login",
        actor=str(VECTOR_ACTOR),
        entity=None,
        entity_id=None,
        details={"token": "выдано_до_правила", "число": 1.5},
        ip="::ffff:127.0.0.1",
        request_id=VECTOR_REQUEST,
        hash_prev=None,
        stored_hash="0" * 64,
    )
    assert foreign.row_id == 7
    assert foreign.record.actor == VECTOR_ACTOR
    assert foreign.record.ip == "127.0.0.1"
    assert foreign.record.details is not None
    report = verify_chain([foreign])
    assert {issue.kind for issue in report.issues} == {"content_mismatch"}
    assert report.issues[0].row_id == 7


def test_кривые_прочитанные_значения_отклоняются_с_упоминанием_колонки() -> None:
    """`actor` обязан быть UUID, `details` — объектом `jsonb`: иначе разбора не будет.

    Сообщения указывают колонку и строку: на площадке разбор запускают по журналу целиком, и
    «сломанная строка 412» читается иначе, чем «что-то не так».
    """
    with pytest.raises(AuditRecordError, match="actor"):
        read_stored_record(
            row_id=412,
            at=VECTOR_AT,
            action="session.login",
            actor="не uuid",
            entity=None,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    with pytest.raises(AuditRecordError, match="412"):
        read_stored_record(
            row_id=412,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details=[1, 2],
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )


def test_чужие_типы_колонок_отклоняются_с_именем_колонки() -> None:
    """Читатель дампа может принести что угодно: отказ обязан именовать колонку, а не «сломалось».

    Это та поверхность, где разбор встречается со значениями, которые приложение не записывало:
    строка из восстановленного дампа, `INSERT` из ручного восстановления (`ADR-017`), чужой тип из
    `psql`. Молча подставить пустое значение хуже отказа: пересчёт сошёлся бы по подставному
    содержимому, и подделка осталась бы невидимой.
    """
    with pytest.raises(AuditRecordError, match="id обязан быть целым"):
        read_stored_record(
            row_id="9",
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    with pytest.raises(AuditRecordError, match="колонка hash строки 9"):
        read_stored_record(
            row_id=9,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="zz" * 32,
        )
    with pytest.raises(AuditRecordError, match="actor: ожидался UUID"):
        read_stored_record(
            row_id=9,
            at=VECTOR_AT,
            action="session.login",
            actor=[str(VECTOR_ACTOR)],
            entity=None,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    with pytest.raises(AuditRecordError, match="details строки 9"):
        read_stored_record(
            row_id=9,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details="не объект",
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    with pytest.raises(AuditRecordError, match="адрес журнала обязан быть"):
        read_stored_record(
            row_id=9,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=None,
            entity_id=None,
            details=None,
            ip=1,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    with pytest.raises(AuditRecordError, match="обязано быть строкой, UUID или целым"):
        read_stored_record(
            row_id=9,
            at=VECTOR_AT,
            action="session.login",
            actor=None,
            entity=1.5,
            entity_id=None,
            details=None,
            ip=None,
            request_id=None,
            hash_prev=None,
            stored_hash="0" * 64,
        )
    # Текст, похожий на адрес, но не адрес: форма колонки `INET` неотличима от текста на глаз.
    with pytest.raises(AuditRecordError, match="не является IP-адресом"):
        canonical_ip("2001:db8::gg")
    # Ключи `jsonb` — строки по определению, но прочитанное из чужой копии значение может быть и
    # не словарём `str`: политика записи отклоняет такой ключ, а не приводит его к тексту.
    with pytest.raises(AuditRecordError, match="ключ details обязан быть строкой"):
        make_record(
            action="session.login",
            at=VECTOR_AT,
            details=cast("Mapping[str, Any]", {1: "значение"}),
        )


def test_строку_орм_читают_теми_же_колонками_что_и_кортеж_psycopg() -> None:
    """`record_of_entry` — та же нормализация, что у `read_stored_record`.

    Разбор запускается и по ORM-объектам (инструмент внутри приложения), и по кортежам `psycopg`
    (разбор дампа). Если бы для ORM-объекта существовал отдельный путь, площадка видела бы два
    разных ответа на один и тот же журнал.
    """
    entry = build_audit_entry(_vector_record())
    # identity-колонку заполняет база; здесь она выставляет значение вручную, имитируя
    # прочитанную строку (`ADR-025` п. 5).
    entry.id = 9
    stored = record_of_entry(entry)
    assert stored.row_id == 9
    assert stored.stored_hash == VECTOR_HASH
    assert stored.record.entity == "backup_code"
    assert stored.record.content_hash() == VECTOR_HASH
