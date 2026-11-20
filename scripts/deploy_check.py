#!/usr/bin/env python3
"""Предстартовая проверка площадки: `make deploy-check` (TZ §4, чек-лист `docs/research/03 §3.10`).

Назначение — не давая «боевому» контуру запуститься поверх неподготовленной площадки, честно
показать, что именно не готово. Отличия от обычного теста:

* проверки идут против реальной системы (время, диск, память, TLS до брокера, SOCKS-туннель);
* каждая проверка имеет уровень: `fatal` блокирует запуск, `warn` требует явного решения
  заказчика, но не блокирует подготовку;
* вывод не содержит секретов: проверяются наличие и права файлов, а не их содержимое.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess  # nosec B404 — ниже только вызовы с фиксированным списком аргументов
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import ca_policy
from _bootstrap import ensure_repo_root_on_path
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from packages.common.config import ConfigError, Contour, Settings, load_settings
from packages.common.db import psycopg_dsn

ROOT = ensure_repo_root_on_path()

# Нижние границы площадки. Значения соответствуют измеренной конфигурации (2 vCPU / 3.8 GiB /
# 72 ГБ) и решениям OQ-11: расширение ВМ не утверждено, поэтому потолок — не целевые 4 vCPU/8 GiB,
# а фактические возможности; всё, что ниже, работать не будет.
FLOOR_CPU = 2
FLOOR_RAM_GIB = 3.5
FLOOR_DISK_FREE_GIB = 20.0

BROKER_TLS_TARGETS: tuple[tuple[str, int], ...] = (
    ("invest-public-api.tbank.ru", 443),
    ("sandbox-invest-public-api.tbank.ru", 443),
)

# Корень НУЦ («Российский доверенный корневой»): артефакт, отпечаток и границы срока закреплены
# в scripts/ca_policy.py — одном месте для `deploy-check`, приёмочной пробы и CI. Здесь они
# берутся оттуда же: вывод проверки площадки и вывод CI не имеют права разойтись.
CA_FILE = ca_policy.CA_FILE
EXPECTED_CA_FINGERPRINT = ca_policy.EXPECTED_CA_FINGERPRINT
MIN_ROOT_DAYS_LEFT = ca_policy.MIN_ROOT_DAYS_LEFT
MIN_LEAF_DAYS_LEFT = ca_policy.MIN_LEAF_DAYS_LEFT

FATAL = "fatal"
WARN = "warn"


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    severity: str = FATAL


def _human_gib(value_bytes: float) -> str:
    return f"{value_bytes / 1024 / 1024 / 1024:.2f} GiB"


def check_python() -> CheckResult:
    version = sys.version_info
    ok = version >= (3, 12)
    return CheckResult("python", ok, f"{platform.python_version()} (нужно ≥3.12)")


def check_config() -> tuple[CheckResult, Settings | None]:
    try:
        settings = load_settings()
    except ConfigError as exc:
        return CheckResult(
            "config", False, "конфигурация отклонена: " + "; ".join(exc.reasons)
        ), None
    return (
        CheckResult(
            "config",
            True,
            f"контур={settings.contour.value}, экземпляр={settings.instance_name}, "
            f"log_json={settings.log_json}, secrets_dir={settings.secrets_dir}",
        ),
        settings,
    )


def check_contour(settings: Settings | None) -> CheckResult:
    if settings is None:
        return CheckResult("contour", False, "конфигурация не загружена")
    if settings.contour is not Contour.PRODUCTION:
        return CheckResult(
            "contour",
            True,
            f"контур {settings.contour.value}: подготовка площадки не блокируется",
            WARN,
        )
    if not settings.confirm_production:
        return CheckResult(
            "contour", False, "боевой контур без подтверждения TBOT_CONFIRM_PRODUCTION=true"
        )
    return CheckResult("contour", True, "боевой контур подтверждён явно")


def _severity(settings: Settings | None, *, production_fatal: bool = True) -> str:
    """Уровень замечания зависит от контура.

    Для песочцы и бумажного контура недоступность внешнего канала или базы — это замечание к
    подготовке конкретной машины (например, CI-раннера без туннеля). Для боевого контура то же
    самое значение блокирует запуск: на площадке это должно быть проверено заранее.
    """
    if not production_fatal:
        return WARN
    if settings is not None and settings.contour is Contour.PRODUCTION:
        return FATAL
    return WARN


def check_time_sync() -> CheckResult:
    """Синхронизация времени: расхождение ломает границы сессий и метки биржевых данных."""
    timedatectl = shutil.which("timedatectl")
    if timedatectl is None:
        return CheckResult(
            "time_sync",
            True,
            "timedatectl недоступен (не Linux) — проверка на площадке обязательна",
            WARN,
        )
    completed = subprocess.run(  # nosec B603 — абсолютный путь из shutil.which, аргументы фиксированы
        [timedatectl, "show", "-p", "NTPSynchronized", "--value"],
        capture_output=True,
        text=True,
        check=False,
    )
    value = completed.stdout.strip().lower()
    if value == "yes":
        return CheckResult("time_sync", True, "NTP синхронизирован")
    return CheckResult(
        "time_sync",
        False,
        f"время не синхронизировано (NTPSynchronized={value or 'нет данных'})",
        WARN,
    )


def check_resources() -> CheckResult:
    cpu = os.cpu_count() or 0
    mem_total_bytes = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_bytes = int(line.split()[1]) * 1024
                break
    disk = shutil.disk_usage("/")
    ram_gib = mem_total_bytes / 1024**3 if mem_total_bytes else 0.0
    disk_free_gib = disk.free / 1024**3

    if not mem_total_bytes:
        return CheckResult(
            "resources", True, f"CPU={cpu}; объём памяти недоступен (не Linux)", WARN
        )
    problems = []
    if cpu < FLOOR_CPU:
        problems.append(f"CPU={cpu} < {FLOOR_CPU}")
    if ram_gib < FLOOR_RAM_GIB:
        problems.append(f"RAM={_human_gib(mem_total_bytes)} < {FLOOR_RAM_GIB} GiB")
    if disk_free_gib < FLOOR_DISK_FREE_GIB:
        problems.append(f"диск={_human_gib(disk.free)} < {FLOOR_DISK_FREE_GIB} GiB")
    detail = f"CPU={cpu}, RAM={_human_gib(mem_total_bytes)}, диск свободен={_human_gib(disk.free)}"
    if problems:
        return CheckResult("resources", False, detail + "; не хватает: " + ", ".join(problems))
    return CheckResult("resources", True, detail)


def cert_not_after(certificate: Mapping[str, object]) -> datetime | None:
    """Срок действия сертификата из `getpeercert()` (формат SSL — «Aug 24 11:38:26 2027 GMT»)."""
    raw = str(certificate.get("notAfter") or "")
    if not raw:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), UTC)
    except ValueError:
        return None


def _verify_chain(host: str, port: int) -> tuple[bool, str, datetime | None]:
    """TLS-соединение со стандартным набором доверия: без `-k`, без отключения проверок.

    Третье значение — срок действия сертификата: «цепочка доверена, но сертификат почти истёк»
    готовностью не считается, поэтому дата нужна вызывающему коду, а не только для текста.
    """
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=10) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            certificate = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return False, f"цепочка не доверена ({exc.verify_code}): {exc.verify_message}", None
    except (ssl.SSLError, OSError) as exc:
        return False, f"соединение не установлено: {type(exc).__name__}: {exc}", None
    if not certificate:
        return False, "сертификат не получен", None
    return True, "цепочка доверена", cert_not_after(certificate)


def check_ca_bundle() -> CheckResult:
    """REQ-broker-gateway-02: в репозитории лежит нужный корень НУЦ, а не похожий на него.

    Проверка локальная и сетью не пользуется: она отвечает за то, что в образ
    (`deploy/Dockerfile` копирует `deploy/ca/` в `/usr/local/share/ca-certificates/tbot/`) и на
    хост попадает ровно тот корень, чей отпечаток закреплён выше. Сравнение с закреплённым
    значением обязательное: подмена корня — признак перехвата или смены удостоверяющего
    центра, и то и другое требует остановки контура (docs/runbook/nucc-ca.md §5).
    """
    if not CA_FILE.is_file():
        return CheckResult(
            "ca_bundle",
            False,
            f"{CA_FILE} отсутствует — порядок получения корня: docs/runbook/nucc-ca.md",
        )
    try:
        certificate = x509.load_pem_x509_certificate(CA_FILE.read_bytes())
    except ValueError as exc:
        return CheckResult(
            "ca_bundle", False, f"{CA_FILE} не разбирается как PEM-сертификат: {exc}"
        )
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    if fingerprint != EXPECTED_CA_FINGERPRINT:
        return CheckResult(
            "ca_bundle",
            False,
            f"отпечаток {CA_FILE} = {fingerprint}, закреплён {EXPECTED_CA_FINGERPRINT} —"
            " возможная подмена корня или устаревший файл, запуск блокируется",
        )
    if certificate.subject != certificate.issuer:
        return CheckResult(
            "ca_bundle",
            False,
            f"{CA_FILE} не самоподписан (issuer ≠ subject) — это не корневой сертификат",
        )
    now = datetime.now(UTC)
    days_left = (certificate.not_valid_after_utc - now).days
    subject = certificate.subject.rfc4514_string()
    detail = (
        f"{subject}: срок {certificate.not_valid_before_utc:%Y-%m-%d}…"
        f"{certificate.not_valid_after_utc:%Y-%m-%d} (осталось {days_left} дн.),"
        f" отпечаток совпадает с закреплённым"
    )
    if certificate.not_valid_after_utc <= now:
        return CheckResult("ca_bundle", False, f"срок действия корня истёк: {detail}")
    if days_left < MIN_ROOT_DAYS_LEFT:
        return CheckResult(
            "ca_bundle",
            False,
            f"до конца срока корня {days_left} дн. (нужно ≥{MIN_ROOT_DAYS_LEFT}) — замена заранее, "
            "см. docs/runbook/nucc-ca.md §5: " + detail,
        )
    return CheckResult("ca_bundle", True, detail)


def broker_endpoints(settings: Settings | None) -> tuple[tuple[str, int, bool], ...]:
    """Адреса брокера в порядке значимости: первичный — тот, что соответствует контуру.

    Отказ по первичному адресу блокирует запуск, по вторичному — только замечание: вторичным
    оказывается `sandbox_host` при боевом контуре и `production_host` при песочце. Без
    конфигурации (например, на CI-раннере) равнозначно первичными считаются оба адреса из
    `BROKER_TLS_TARGETS`, но уровень всё равно не блокирующий — на раннере нет контура.
    """
    if settings is None:
        return tuple((host, port, True) for host, port in BROKER_TLS_TARGETS)
    production = settings.contour is Contour.PRODUCTION
    primary = settings.broker.production_host if production else settings.broker.sandbox_host
    secondary = settings.broker.sandbox_host if production else settings.broker.production_host
    return ((primary, 443, True), (secondary, 443, False))


def check_broker_tls(settings: Settings | None = None) -> CheckResult:
    """REQ-broker-gateway-02: TLS брокера обязан проходить со стандартным набором доверия.

    Промежуточный сертификат выдаёт НУЦ, корень которого отсутствует в Ubuntu по умолчанию
    (замер — `docs/research/03 §3.3`). Пока корень не установлен в хосте или образе, проверка
    обязана быть красной: отключать проверку нельзя.

    Срок действия сертификата брокера контролируется здесь же: «доверено, но истечёт через
    три дня» — не готовность (TZ §3.1 требует проверки даты в `make deploy-check`).
    """
    details: list[str] = []
    primary_failed = False
    secondary_failed = False
    expiring: list[str] = []
    for host, port, primary in broker_endpoints(settings):
        ok, detail, not_after = _verify_chain(host, port)
        if not_after is not None:
            days_left = (not_after - datetime.now(UTC)).days
            detail += f", сертификат до {not_after:%Y-%m-%d} (осталось {days_left} дн.)"
            if days_left < MIN_LEAF_DAYS_LEFT:
                expiring.append(f"{host}: до {not_after:%Y-%m-%d} осталось {days_left} дн.")
                ok = False
        details.append(f"{host}: {detail}")
        if ok:
            continue
        if primary:
            primary_failed = True
        else:
            secondary_failed = True
    if not primary_failed and not secondary_failed:
        return CheckResult("broker_tls", True, "; ".join(details))
    if expiring:
        hint = (
            f"сертификат брокера почти истёк ({'; '.join(expiring)}) — нужна его перевыдача; "
            "проверку не отключаем"
        )
    else:
        hint = "установите корень НУЦ (docs/runbook/nucc-ca.md, задачи T-006 и T-709)"
    severity = _severity(settings) if primary_failed else WARN
    return CheckResult("broker_tls", False, "; ".join(details) + ". " + hint, severity)


def check_telegram_path(settings: Settings | None) -> CheckResult:
    """Канал управления: локальный SOCKS туннель должен отвечать (docs/runbook/telegram-egress-proxy.md)."""
    if settings is None:
        return CheckResult("telegram_path", False, "конфигурация не загружена")
    severity = _severity(settings)
    section = settings.telegram
    try:
        with socket.create_connection((section.socks_host, section.socks_port), timeout=5):
            pass
    except OSError as exc:
        return CheckResult(
            "telegram_path",
            False,
            f"SOCKS {section.socks_host}:{section.socks_port} не отвечает: "
            f"{type(exc).__name__} (с этой площадки Bot API напрямую недоступен)",
            severity,
        )
    if settings.tg_bot_token is None:
        return CheckResult(
            "telegram_path",
            False,
            f"туннель отвечает, но токен бота не настроен ({settings.secrets_dir}/tg_bot_token)",
            severity,
        )
    return CheckResult(
        "telegram_path",
        True,
        f"SOCKS {section.socks_host}:{section.socks_port} отвечает, токен загружен",
    )


# Имена файлов секретов различаются в двух местах, и путать их — значит получить красный
# `secret_files` на полностью готовой площадке (замер 2026-11-20, `stand-deploy §8`): внутри
# контейнера приложение читает имена **конфигурации** (`/run/secrets/{db_url,tg_bot_token,
# tg_socks_password}`, `packages.common.config.SECRET_FIELDS`), а на хосте площадки файлы названы
# по `deploy/compose.prod.yaml` — `db_url`, `db_password`, `telegram_token`,
# `telegram_socks_pass` и `ghcr_token` (последний нужен хосту для `docker login ghcr.io` и в
# контейнеры не монтируется). Ниже — слоты: логический секрет, его имена (хостовое первым, имя
# конфигурации вторым) и обязан ли он существовать. Какое из имён принимает конкретный контур —
# решает `slot_names`, а не порядок в кортеже.
@dataclass(frozen=True)
class _SecretSlot:
    key: str
    names: tuple[str, ...]
    required_everywhere: bool
    required_in_production_only: bool = False


SECRET_SLOTS: tuple[_SecretSlot, ...] = (
    _SecretSlot("db_password", ("db_password",), True),
    _SecretSlot("db_url", ("db_url",), True),
    _SecretSlot("telegram_token", ("telegram_token", "tg_bot_token"), False, True),
    _SecretSlot("telegram_socks_pass", ("telegram_socks_pass", "tg_socks_password"), True),
    _SecretSlot("ghcr_token", ("ghcr_token",), False, True),
)

# Форма значений (контракт и признаки подмены — docs/runbook/secrets-on-host.md §4.1). Схема DSN
# допускает и `postgresql://`, и `postgresql+psycopg://`: нормализация диалекта — забота
# packages/common/db.py, а жёсткость здесь давала бы ложные отказы dev-стенда.
_SECRET_SHAPES: dict[str, re.Pattern[str]] = {
    "db_url": re.compile(
        r"postgres(ql|ql\+psycopg)://[A-Za-z][A-Za-z0-9_]*:[^@\s]+@[A-Za-z0-9._-]+:[0-9]{2,5}"
        r"/[A-Za-z][A-Za-z0-9_]*"
    ),
    "ghcr_token": re.compile(
        r"github_pat_[A-Za-z0-9_]{22,}|gh[pousr]_[A-Za-z0-9]{36,}|[0-9a-f]{40}"
    ),
    "telegram_token": re.compile(r"[0-9]{6,12}:[A-Za-z0-9_-]{35}"),
    "db_password": re.compile(r"[A-Za-z0-9._~-]{16,64}"),
    "telegram_socks_pass": re.compile(r"[^\s]{8,128}"),
}

_SECRET_SHAPE_HINTS: dict[str, str] = {
    "db_url": "postgresql+psycopg://<user>:<пароль>@<хост>:<порт>/<база>",
    "ghcr_token": "personal access token GitHub (github_pat_…, gh…_… или классический hex-40)",
    "telegram_token": "<id бота>:<35 символов из @BotFather>",
    "db_password": "16–64 символа без пробелов и спецсимволов (URL-безопасно: он же внутри db_url)",
    "telegram_socks_pass": "8–128 символов без пробелов (пароль SOCKS-входа туннеля)",
}


def secret_ownership_ok(stat_result: os.stat_result) -> bool:
    """Файл секрета должен принадлежать root:root (TZ §8.3); вызывается только для боевого контура."""
    return stat_result.st_uid == 0 and stat_result.st_gid == 0


def slot_required(slot: _SecretSlot, settings: Settings) -> bool:
    if slot.required_everywhere:
        return True
    return slot.required_in_production_only and settings.contour is Contour.PRODUCTION


def slot_names(slot: _SecretSlot, settings: Settings) -> tuple[str, ...]:
    """Имена файла, которые читает именно этот контур.

    Боевой контур — это каталог площадки, а состав, который его запускает,
    (`deploy/compose.prod.yaml`) монтирует `/etc/tbot/secrets/telegram_token` и
    `…/telegram_socks_pass`. Имена `tg_bot_token` и `tg_socks_password` существуют только
    **внутри** контейнера (`packages.common.config.SECRET_FIELDS`), и файл с таким именем в
    каталоге площадки состав не прочитает. Принимать его за наличие слота — значит соврать
    дважды: и про готовность, и про то, какой файл надо создать (замер 2026-11-20,
    `docs/runbook/stand-deploy.md §8`).

    Вне боя каталог секретов — `deploy/secrets/` dev-стенда, где штатные имена как раз из
    конфигурации, поэтому там принимаются оба варианта.
    """
    return slot.names[:1] if settings.contour is Contour.PRODUCTION else slot.names


def slot_foreign_names(slot: _SecretSlot, settings: Settings) -> tuple[str, ...]:
    """Имена из другой пары, которые этот контур не читает, но которые могут лежать рядом.

    Лишний файл с именем конфигурации в каталоге площадки — признак подмены пары имён: кто-то
    уже пытался починить красный `secret_files` созданием лишнего секрета. Наружу это выводится
    отдельной строкой, чтобы «файла нет» и «есть не тот файл» не путались.
    """
    admissible = set(slot_names(slot, settings))
    return tuple(name for name in slot.names if name not in admissible)


def check_secret_files(settings: Settings | None) -> CheckResult:
    """Наличие, права и владелец файлов секретов; содержимое не выводится (REQ-sec-04)."""
    if settings is None:
        return CheckResult("secret_files", False, "конфигурация не загружена")
    if os.name != "posix":
        return CheckResult("secret_files", True, "проверка прав доступна только на POSIX", WARN)
    problems: list[str] = []
    present: list[str] = []
    for slot in SECRET_SLOTS:
        names = slot_names(slot, settings)
        found = False
        for name in names:
            path = settings.secrets_dir / name
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            except PermissionError:
                problems.append(f"{name}: нет доступа к файлу (нужен root)")
                found = True
                break
            found = True
            if stat.st_mode & 0o170000 == 0o040000:
                problems.append(f"{name}: каталог вместо файла")
                break
            if stat.st_size == 0:
                problems.append(f"{name}: пустой файл")
                break
            mode = stat.st_mode & 0o777
            if mode & 0o077:
                problems.append(f"{name}: права {oct(mode)}, нужно 600")
            if settings.contour is Contour.PRODUCTION and not secret_ownership_ok(stat):
                problems.append(f"{name}: владелец {stat.st_uid}:{stat.st_gid}, нужен root:root")
            present.append(f"{name} ({stat.st_size} байт)")
            break
        if not found and slot_required(slot, settings):
            problems.append(f"{slot.key}: файла нет (имя этого контура: {', '.join(names)})")
        for foreign in slot_foreign_names(slot, settings):
            if (settings.secrets_dir / foreign).is_file():
                problems.append(
                    f"{foreign}: файл с именем контейнера, а не хоста — этот контур читает "
                    f"{', '.join(names)} (deploy/compose.prod.yaml)"
                )
    if problems:
        return CheckResult("secret_files", False, "; ".join(problems), _severity(settings))
    return CheckResult(
        "secret_files", True, "права 600 и root:root у файлов: " + ", ".join(present)
    )


def check_secret_shapes(settings: Settings | None) -> CheckResult:
    """Форма значений секретов — отдельно от наличия, прав и владельца.

    Presence-проверка этого не ловит: замер 2026-11-20 на площадке дал зелёный `--check` по
    режимам при значениях не по назначению (`db_url` из 11 цифр без схемы, токен не-PAT из 11
    символов, пароль с пробелами). Проверка читает файл, но в вывод кладёт только имя, длину и
    подсказку формата: значение не печатается ни целиком, ни по частям (разбор полей значения =
    утечка в журнал сессии).
    """
    if settings is None:
        return CheckResult("secret_shapes", False, "конфигурация не загружена")
    if settings.contour is Contour.SANDBOX:
        # В песочце значения фиктивные (`deploy/README.md §2`: `dev-not-a-real-token`), и форма
        # здесь не показательна. Для торгового и боевого контуров значения настоящие, и именно
        # там не-форма означает «деплой встанет на месте» — см. замер 2026-11-20.
        return CheckResult(
            "secret_shapes",
            True,
            "форма значений проверяется в торговом и боевом контурах (песочца — фиктивные)",
            WARN,
        )
    problems: list[str] = []
    ok_items: list[str] = []
    for slot in SECRET_SLOTS:
        shape = _SECRET_SHAPES.get(slot.key)
        if shape is None:
            continue
        for name in slot_names(slot, settings):
            path = settings.secrets_dir / name
            try:
                raw = path.read_bytes()
            except (FileNotFoundError, PermissionError):
                continue
            text = raw.decode("utf-8", "replace").strip()
            if shape.fullmatch(text):
                ok_items.append(f"{name} ({len(raw)} байт)")
            else:
                problems.append(
                    f"{name}: значение не по форме ({len(raw)} байт) — ожидалось: "
                    f"{_SECRET_SHAPE_HINTS[slot.key]}"
                )
            break
    if problems:
        return CheckResult("secret_shapes", False, "; ".join(problems), _severity(settings))
    return CheckResult(
        "secret_shapes", True, "форма значений соответствует: " + ", ".join(ok_items)
    )


def check_db(settings: Settings | None) -> CheckResult:
    if settings is None:
        return CheckResult("database", False, "конфигурация не загружена")
    severity = _severity(settings)
    if settings.db_url is None:
        return CheckResult(
            "database", False, f"нет {settings.secrets_dir}/db_url или TBOT_DB_URL", severity
        )
    try:
        import psycopg
    except ImportError:
        return CheckResult(
            "database",
            True,
            "драйвер psycopg не установлен (dev-машина) — проверка на площадке",
            WARN,
        )
    try:
        with (
            psycopg.connect(
                psycopg_dsn(settings.db_url.get_secret_value()), connect_timeout=5
            ) as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("SELECT version()")
            row = cursor.fetchone()
    except psycopg.Error as exc:
        return CheckResult("database", False, f"база недоступна: {type(exc).__name__}")
    version = str(row[0]) if row else "нет данных"
    return CheckResult("database", True, version.split(",")[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="проверка готовности площадки к запуску")
    parser.add_argument("--json", action="store_true", help="машинный вывод для CI")
    parser.add_argument("--skip-broker-tls", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)

    config_result, settings = check_config()
    results: list[CheckResult] = [
        check_python(),
        config_result,
        check_contour(settings),
        check_ca_bundle(),
        check_time_sync(),
        check_resources(),
        check_secret_files(settings),
        check_secret_shapes(settings),
        check_db(settings),
        check_telegram_path(settings),
    ]
    if not arguments.skip_broker_tls:
        results.append(check_broker_tls(settings))

    blocking = [item for item in results if not item.ok and item.severity == FATAL]

    if arguments.json:
        payload = [
            {"name": item.name, "ok": item.ok, "severity": item.severity, "detail": item.detail}
            for item in results
        ]
        print(json.dumps({"passed": not blocking, "checks": payload}, ensure_ascii=False, indent=2))
    else:
        print("проверка готовности площадки (TZ §4, чек-лист docs/research/03 §3.10):")
        for item in results:
            mark = "OK  " if item.ok else ("FAIL" if item.severity == FATAL else "WARN")
            print(f"  [{mark}] {item.name:<14} {item.detail}")
        if blocking:
            print(f"\nитог: не пройдено {len(blocking)} блокирующих проверок — запуск блокируется")
        else:
            print("\nитог: блокирующих замечаний нет")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
