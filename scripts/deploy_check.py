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
import shutil
import socket
import ssl
import subprocess  # nosec B404 — ниже только вызовы с фиксированным списком аргументов
import sys
from dataclasses import dataclass
from pathlib import Path

from _bootstrap import ensure_repo_root_on_path

from packages.common.config import ConfigError, Contour, Settings, load_settings

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

# Отпечаток корневого сертификата НУЦ. Заполняется вместе с T-709: до заполнения проверка
# выполняется «как есть» и обязана честно сообщать, что корень не подтверждён.
EXPECTED_CA_FINGERPRINT: str | None = None

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


def _verify_chain(host: str, port: int) -> tuple[bool, str]:
    """TLS-соединение со стандартным набором доверия: без `-k`, без отключения проверок."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=10) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            certificate = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return False, f"цепочка не доверена ({exc.verify_code}): {exc.verify_message}"
    except (ssl.SSLError, OSError) as exc:
        return False, f"соединение не установлено: {type(exc).__name__}: {exc}"
    if not certificate:
        return False, "сертификат не получен"
    return True, "цепочка доверена"


def check_broker_tls() -> CheckResult:
    """REQ-broker-gateway-02: TLS брокера обязан проходить со стандартным набором доверия.

    Промежуточный сертификат выдаёт НУЦ, корень которого отсутствует в Ubuntu по умолчанию
    (замер — `docs/research/03 §3.3`). Пока корень не установлен, проверка обязана быть
    красной: отключать проверку нельзя.
    """
    results: list[str] = []
    verified = 0
    for host, port in BROKER_TLS_TARGETS:
        ok, detail = _verify_chain(host, port)
        results.append(f"{host}: {detail}")
        verified += 1 if ok else 0
    if verified == len(BROKER_TLS_TARGETS):
        return CheckResult("broker_tls", True, "; ".join(results))
    hint = "установите корень НУЦ (deploy/ca/README.md, задача T-709)"
    if EXPECTED_CA_FINGERPRINT is None:
        hint += "; отпечаток корня ещё не зафиксирован в deploy_check.py"
    return CheckResult("broker_tls", False, "; ".join(results) + ". " + hint)


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


def check_secret_files(settings: Settings | None) -> CheckResult:
    """Права на файлы секретов: содержимое не читается и не выводится (REQ-sec-04)."""
    if settings is None:
        return CheckResult("secret_files", False, "конфигурация не загружена")
    if os.name != "posix":
        return CheckResult("secret_files", True, "проверка прав доступна только на POSIX", WARN)
    expected = (
        "db_url",
        "tg_bot_token",
        "tg_socks_password",
    )
    problems: list[str] = []
    present: list[str] = []
    for name in expected:
        path = settings.secrets_dir / name
        if not path.is_file():
            problems.append(f"{name}: файла нет")
            continue
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            problems.append(f"{name}: права {oct(mode)}, нужно 600")
        present.append(name)
    if problems:
        return CheckResult("secret_files", False, "; ".join(problems), _severity(settings))
    return CheckResult("secret_files", True, "права 600 у файлов: " + ", ".join(present))


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
            psycopg.connect(settings.db_url.get_secret_value(), connect_timeout=5) as connection,
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
        check_time_sync(),
        check_resources(),
        check_secret_files(settings),
        check_db(settings),
        check_telegram_path(settings),
    ]
    if not arguments.skip_broker_tls:
        results.append(check_broker_tls())

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
