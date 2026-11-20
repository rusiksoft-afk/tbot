#!/usr/bin/env python3
"""Проверка базовой подготовки рабочей ВМ: своп, время, доверие НУЦ, доступность контуров (T-011).

Задача модуля — ответить на вопрос «можно ли поднимать здесь приложение» до того, как на машине
появятся Docker и образы tbot. В отличие от `scripts/deploy_check.py` он не требует зависимостей
приложения: достаточно `python3` из дистрибутива, поэтому его можно запустить на чистой Ubuntu
24.04 сразу после базовой настройки.

Два правила, которые держат этот файл:

* `subprocess` не используется вовсе. Состояние системы читается из `/proc`, `/etc` и
  `shutil.disk_usage` — так проверка остаётся запускаемой без привилегий и не требует новых
  подавлений bandit (базовый уровень подавлений в проекте не повышается без решения заказчика).
* смещение часов здесь измеряется по снимку вывода `chronyc tracking` (флаг
  `--chrony-tracking`). Без снимка проверка остаётся замечанием: требовать «часы в порядке» по
  косвенным признакам нельзя, а прикладной контроль (алерт `R32/CLOCK_SKEW` и `deploy-check`)
  выполняется на уровне приложения, где есть свои механизмы.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

import ca_policy
import tls_trust_probe

FATAL = "fatal"
WARN = "warn"

# Границы взяты из ТЗ и из замера конкретной площадки (TZ §14.9, решение OQ-11 «без расширения»):
# 2 vCPU / 3.8 GiB RAM / 72 GiB SSD. Значения ниже — машина не годится, и поднимать на ней
# торговый контур нельзя.
MIN_SWAP_GIB = 4.0
# `mkswap` резервирует несколько КиБ в начале файла под заголовок свопа, поэтому файл на 4 ГиБ
# в `/proc/swaps` выглядит как 4194300 КиБ вместо 4194304. Допуск в 64 КиБ не скрывает реальный
# недостаток (своп 3.9 ГиБ по-прежнему не проходит), но не превращает заголовок в ошибку.
SWAP_HEADER_TOLERANCE_KIB = 64
EXPECTED_SWAPPINESS = 10
FLOOR_CPU = 2
FLOOR_RAM_GIB = 3.5
FLOOR_DISK_GIB = 40.0
FLOOR_DISK_FREE_GIB = 20.0
DISK_WARN_PERCENT = 75.0
DISK_FAIL_PERCENT = 85.0
CLOCK_OFFSET_LIMIT_SECONDS = 2.0

PROC_ROOT = Path("/proc")
SYSTEMD_WANTS_DIR = Path("/etc/systemd/system/multi-user.target.wants")
FSTAB_FILE = Path("/etc/fstab")
SWAPPINESS_FILE = Path("/proc/sys/vm/swappiness")
SWAPS_FILE = Path("/proc/swaps")

BROKER_TLS_TARGETS: tuple[tuple[str, int], ...] = (
    ("invest-public-api.tbank.ru", 443),
    ("sandbox-invest-public-api.tbank.ru", 443),
)

_OFFSET_RE = re.compile(
    r"System time\s*:\s*(?P<value>\d+(?:\.\d+)?)\s*seconds\s+(?P<direction>slow|fast)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CheckResult:
    """Одна проверка. `severity=fatal` блокирует вывод «готово», `warn` — требует решения заказчика."""

    name: str
    ok: bool
    detail: str
    severity: str = FATAL


def _gib(value_bytes: float) -> str:
    return f"{value_bytes / 1024**3:.2f} GiB"


def parse_swap_total_kib(swaps_text: str) -> int:
    """Суммарный размер включённого свопа в КиБ из вывода `/proc/swaps`.

    Первая строка — заголовок (`Filename Type Size Used Priority`); пустые строки игнорируются,
    чтобы вывод с завершающим переводом строки не считался битым.
    """
    total = 0
    for line in swaps_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3:
            continue
        total += int(fields[2])
    return total


def parse_swappiness(swappiness_text: str) -> int | None:
    """Значение `vm.swappiness` из `/proc/sys/vm/swappiness`; `None`, если содержимое не число."""
    try:
        return int(swappiness_text.strip())
    except ValueError:
        return None


def fstab_has_swap(fstab_text: str) -> bool:
    """Есть ли в `/etc/fstab` запись о свопе (третье поле — тип, `swap`).

    Строки комментариев и пустые строки не считаются: проверка отвечает на вопрос «поднимется ли
    своп после перезагрузки», а не «упоминается ли swap в файле вообще». Формат строки fstab —
    `<устройство> <точка монтирования> <тип> <опции> <dump> <pass>`: тип в третьем поле, поэтому
    запись `/swapfile none swap sw,pri=1 0 0` ищется по полям[2], а не по опциям.
    """
    for line in fstab_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 4 and fields[2] == "swap":
            return True
    return False


def parse_chrony_offset_seconds(tracking_text: str) -> float | None:
    """Модуль смещения часов по выводу `chronyc tracking` (`System time : …`).

    `chronyc tracking` печатает знак отдельно от величины («slow of NTP time» / «fast of NTP
    time»), поэтому здесь важен только модуль: граница ТЗ — расхождение больше 2 секунд.
    """
    match = _OFFSET_RE.search(tracking_text)
    if match is None:
        return None
    return abs(float(match.group("value")))


def find_process(name: str, proc_root: Path = PROC_ROOT) -> int | None:
    """Первый PID процесса с именем `name` по `/proc/<pid>/comm` (без `subprocess`)."""
    if not proc_root.is_dir():
        return None
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        comm = entry / "comm"
        try:
            if comm.read_text(encoding="utf-8", errors="replace").strip() == name:
                return int(entry.name)
        except OSError:
            # Процесс мог завершиться между перечислением и чтением — это не ошибка проверки.
            continue
    return None


def systemd_unit_enabled(unit: str, wants_dir: Path = SYSTEMD_WANTS_DIR) -> bool:
    """Включён ли юнит в автозагрузку: `systemctl enable` создаёт ссылку в `multi-user.target.wants`."""
    return (wants_dir / unit).exists()


def verdict_swap(total_kib: int, min_gib: float = MIN_SWAP_GIB) -> tuple[bool, str]:
    if total_kib <= 0:
        return False, "свопа нет (`/proc/swaps` пуст) — OOM-killer снимет worker бэктеста"
    needed_kib = min_gib * 1024 * 1024
    gib = total_kib / 1024 / 1024
    if total_kib + SWAP_HEADER_TOLERANCE_KIB < needed_kib:
        return False, f"{gib:.2f} GiB ({total_kib} КиБ), нужно ≥{min_gib:g} GiB"
    return True, f"{gib:.2f} GiB ({total_kib} КиБ) включено (нужно ≥{min_gib:g} GiB)"


def verdict_swappiness(value: int | None, expected: int = EXPECTED_SWAPPINESS) -> tuple[bool, str]:
    if value is None:
        return False, "значение недоступно: файла нет или содержимое не число"
    if value > expected:
        return False, f"vm.swappiness={value}, нужно {expected} (иначе ядро вытесняет кэш БД)"
    return True, f"vm.swappiness={value}"


def verdict_resources(
    cpu: int, ram_gib: float, disk_gib: float, disk_free_gib: float, disk_used_percent: float
) -> tuple[bool, str, str]:
    """Нижняя граница конфигурации и заполненность диска (пороги алертов — TZ §12.4).

    Заполненность учитывается независимо от границ размера: на машине достаточного размера,
    у которой кончилось место, вердикт обязан быть «нужна чистка», а не «железа мало».
    """
    problems: list[str] = []
    if cpu < FLOOR_CPU:
        problems.append(f"CPU={cpu} < {FLOOR_CPU}")
    if ram_gib + 1e-9 < FLOOR_RAM_GIB:
        problems.append(f"RAM={ram_gib:.2f} GiB < {FLOOR_RAM_GIB:g}")
    if disk_gib + 1e-9 < FLOOR_DISK_GIB:
        problems.append(f"диск={disk_gib:.2f} GiB < {FLOOR_DISK_GIB:g}")
    if disk_free_gib + 1e-9 < FLOOR_DISK_FREE_GIB:
        problems.append(f"свободно {disk_free_gib:.2f} GiB < {FLOOR_DISK_FREE_GIB:g}")
    if disk_used_percent > DISK_FAIL_PERCENT:
        problems.append(
            f"занято {disk_used_percent:.1f}% > {DISK_FAIL_PERCENT:g}% — "
            "нужен cleanup партиций, логов и старых дампов до запуска"
        )
    detail = (
        f"CPU={cpu}, RAM={ram_gib:.2f} GiB, диск={disk_gib:.2f} GiB "
        f"(свободно {disk_free_gib:.2f} GiB, занято {disk_used_percent:.1f}%)"
    )
    if problems:
        return False, f"{detail}: " + "; ".join(problems), FATAL
    if disk_used_percent > DISK_WARN_PERCENT:
        return True, f"{detail}: занято >{DISK_WARN_PERCENT:g}% — пора чистить партиции", WARN
    return True, detail, FATAL


def check_python() -> CheckResult:
    version = sys.version_info
    return CheckResult("python", version >= (3, 12), f"{sys.version.split()[0]} (нужно ≥3.12)")


def check_swap(swaps_file: Path = SWAPS_FILE) -> CheckResult:
    if not swaps_file.is_file():
        return CheckResult(
            "swap",
            True,
            "сводка свопа недоступна (не Linux) — проверка на площадке обязательна",
            WARN,
        )
    total_kib = parse_swap_total_kib(swaps_file.read_text(encoding="utf-8"))
    ok, detail = verdict_swap(total_kib)
    return CheckResult("swap", ok, detail)


def check_swap_in_fstab(fstab_file: Path = FSTAB_FILE) -> CheckResult:
    if not fstab_file.is_file():
        return CheckResult(
            "swap_fstab",
            True,
            "/etc/fstab недоступен (не Linux) — проверка на площадке обязательна",
            WARN,
        )
    if fstab_has_swap(fstab_file.read_text(encoding="utf-8")):
        return CheckResult("swap_fstab", True, "запись о свопе есть — переживает перезагрузку")
    return CheckResult(
        "swap_fstab", False, "в /etc/fstab записи о свопе нет: после перезагрузки своп исчезнет"
    )


def check_swappiness(swappiness_file: Path = SWAPPINESS_FILE) -> CheckResult:
    value: int | None = None
    if swappiness_file.is_file():
        value = parse_swappiness(swappiness_file.read_text(encoding="utf-8"))
    ok, detail = verdict_swappiness(value)
    return CheckResult("swappiness", ok, detail)


def check_chrony(
    proc_root: Path = PROC_ROOT, wants_dir: Path = SYSTEMD_WANTS_DIR
) -> tuple[CheckResult, CheckResult]:
    """`chronyd` должен работать и быть включённым: TOTP и метки сделок зависят от часов (TZ §8.2)."""
    pid = find_process("chronyd", proc_root)
    running = CheckResult(
        "chronyd",
        pid is not None,
        f"процесс chronyd запущен (pid {pid})"
        if pid is not None
        else "процесс chronyd не найден — часы не синхронизируются",
    )
    enabled = systemd_unit_enabled("chrony.service", wants_dir)
    unit = CheckResult(
        "chrony_enabled",
        enabled,
        "юнит chrony.service включён в автозагрузку"
        if enabled
        else "chrony.service не включён в автозагрузку: после перезагрузки часы разъедутся",
    )
    return running, unit


def check_clock_offset(tracking_file: Path | None) -> CheckResult:
    if tracking_file is None:
        return CheckResult(
            "clock_offset",
            True,
            "смещение не измерено: замерить и передать снимком — "
            "`chronyc tracking | sudo tee /tmp/chrony-tracking.txt`, затем "
            "`--chrony-tracking /tmp/chrony-tracking.txt`",
            WARN,
        )
    if not tracking_file.is_file():
        return CheckResult(
            "clock_offset", False, f"снимок `{tracking_file}` не найден — смещение не измерено"
        )
    offset = parse_chrony_offset_seconds(tracking_file.read_text(encoding="utf-8"))
    if offset is None:
        return CheckResult(
            "clock_offset",
            False,
            f"в снимке `{tracking_file}` нет строки `System time …` — вывод chronyc не разобран",
        )
    if offset > CLOCK_OFFSET_LIMIT_SECONDS:
        return CheckResult(
            "clock_offset",
            False,
            f"смещение {offset:.3f} с > {CLOCK_OFFSET_LIMIT_SECONDS:g} с — запрет TOTP (R32)",
        )
    return CheckResult(
        "clock_offset", True, f"смещение {offset:.6f} с (граница {CLOCK_OFFSET_LIMIT_SECONDS:g} с)"
    )


def check_ca_bundle(bundle: Path = Path(ca_policy.CA_SYSTEM_BUNDLE)) -> CheckResult:
    """Корень НУЦ в системном наборе доверия хоста — условие T-709 на площадке."""
    if not bundle.is_file():
        return CheckResult("ca_bundle", False, f"связка доверия `{bundle}` не найдена (не Linux?)")
    found = ca_policy.contains_fingerprint(bundle, ca_policy.EXPECTED_CA_FINGERPRINT)
    if not found:
        return CheckResult(
            "ca_bundle",
            False,
            f"корня с отпечатком {ca_policy.EXPECTED_CA_FINGERPRINT[:16]}… в `{bundle}` нет: "
            f"нужен файл `{ca_policy.CA_IMAGE_FILE}` (верхний уровень, расширение `.crt`) "
            "и `update-ca-certificates`",
        )
    return CheckResult(
        "ca_bundle",
        True,
        f"корень НУЦ входит в `{bundle}` (отпечаток {ca_policy.EXPECTED_CA_FINGERPRINT[:16]}…)",
    )


def check_broker_tls(
    targets: Iterable[tuple[str, int]] = BROKER_TLS_TARGETS, timeout: float = 10.0
) -> CheckResult:
    """Штатная проверка цепочки обоих контуров: без корня НУЦ здесь обязано быть «не доверено»."""
    parts: list[str] = []
    failed = False
    unreachable = False
    for host, port in targets:
        outcome = tls_trust_probe.probe(host, port, timeout=timeout)
        parts.append(f"{host}: {outcome.verdict} ({outcome.detail})")
        if outcome.verdict == tls_trust_probe.UNREACHABLE:
            unreachable = True
        elif outcome.verdict != tls_trust_probe.VERIFIED:
            failed = True
    detail = "; ".join(parts)
    if failed:
        return CheckResult("broker_tls", False, f"цепочка не доверена: {detail}")
    if unreachable:
        return CheckResult(
            "broker_tls",
            True,
            f"часть точек недоступна (проверить egress и DNS): {detail}",
            WARN,
        )
    return CheckResult("broker_tls", True, detail)


def check_resources() -> CheckResult:
    cpu = os.cpu_count() or 0
    mem_total_bytes = 0
    meminfo = PROC_ROOT / "meminfo"
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_bytes = int(line.split()[1]) * 1024
                break
    if not mem_total_bytes:
        return CheckResult(
            "resources", True, f"CPU={cpu}; объём памяти недоступен (не Linux)", WARN
        )
    usage = shutil.disk_usage("/")
    ok, detail, severity = verdict_resources(
        cpu=cpu,
        ram_gib=mem_total_bytes / 1024**3,
        disk_gib=usage.total / 1024**3,
        disk_free_gib=usage.free / 1024**3,
        disk_used_percent=usage.used / usage.total * 100.0,
    )
    return CheckResult("resources", ok, detail, severity)


def collect_checks(tracking_file: Path | None, live: bool) -> list[CheckResult]:
    results = [
        check_python(),
        check_swap(),
        check_swap_in_fstab(),
        check_swappiness(),
    ]
    chronyd, chrony_unit = check_chrony()
    results.extend([chronyd, chrony_unit])
    results.append(check_clock_offset(tracking_file))
    results.append(check_ca_bundle())
    if live:
        results.append(check_broker_tls())
    else:
        results.append(
            CheckResult(
                "broker_tls",
                True,
                "проверка пропущена (--skip-broker): живые точки недоступны",
                WARN,
            )
        )
    results.append(check_resources())
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Проверка базовой подготовки рабочей ВМ (T-011): своп, время, доверие НУЦ, контуры"
    )
    parser.add_argument(
        "--chrony-tracking",
        type=Path,
        default=None,
        help="снимок вывода `chronyc tracking` для замера смещения часов",
    )
    parser.add_argument(
        "--skip-broker",
        action="store_true",
        help="не обращаться к точкам брокера (офлайн-прогон, замечание в выводе)",
    )
    parser.add_argument("--json", action="store_true", help="машинный вывод для протокола")
    args = parser.parse_args(argv)

    results = collect_checks(args.chrony_tracking, live=not args.skip_broker)
    blocking = [item for item in results if not item.ok and item.severity == FATAL]
    if args.json:
        print(
            json.dumps(
                {"ok": not blocking, "checks": [asdict(item) for item in results]},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for item in results:
            mark = "OK" if item.ok else ("WARN" if item.severity == WARN else "FAIL")
            print(f"{mark:4} {item.name}: {item.detail}")
        if blocking:
            print(f"НЕ ГОТОВО: блокирующих проверок — {len(blocking)}")
        else:
            print("ГОТОВО: блокирующих замечаний нет")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
