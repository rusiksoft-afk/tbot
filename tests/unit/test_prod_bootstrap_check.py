"""Проверка базовой подготовки рабочей ВМ (`scripts/prod_bootstrap_check.py`, T-011).

Модуль запускается на площадке, где есть `/proc` и системная связка доверия, а тесты — на dev-машине.
Поэтому проверяется то, что не требует Linux: разбор состояния (`/proc/swaps`, `vm.swappiness`,
`/etc/fstab`, вывод `chronyc tracking`), поиск процесса по фиктивному `/proc`, пороги ресурсов и
то, что вывод никогда не становится «зелёным» по косвенным признакам.

Отдельно закреплено, что модуль не использует `subprocess`: это держит число подавлений bandit на
базовом уровне (новые `nosec` в проекте не появляются без решения заказчика).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.paths import CA_FILE, SCRIPTS, load_script

bootstrap = load_script("prod_bootstrap_check")
ca_policy = load_script("ca_policy")

SWAPS_SAMPLE = (
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    "/swapfile                              file\t4194300\t0\t\t1\n"
    "/dev/sdb1                              partition\t1048572\t0\t\t-2\n"
)


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_сводка_свопа_суммирует_все_устройства() -> None:
    assert bootstrap.parse_swap_total_kib(SWAPS_SAMPLE) == 4194300 + 1048572


def test_сводка_свопа_без_устройств_это_ноль_а_не_ошибка_разбора() -> None:
    header_only = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    assert bootstrap.parse_swap_total_kib(header_only) == 0
    ok, detail = bootstrap.verdict_swap(0)
    assert not ok
    assert "свопа нет" in detail


def test_своп_меньше_четырёх_гиб_не_проходит() -> None:
    ok, detail = bootstrap.verdict_swap(2 * 1024 * 1024)
    assert not ok
    assert "2.00 GiB" in detail


def test_своп_ровно_четыре_гиб_проходит() -> None:
    ok, _ = bootstrap.verdict_swap(int(4 * 1024 * 1024))
    assert ok


def test_своп_файла_на_четыре_гиб_после_заголовка_mkswap_проходит() -> None:
    """Замер с рабочей ВМ: файл в 4 ГиБ в `/proc/swaps` выглядит как 4194300 КиБ.

    `mkswap` резервирует начало файла под заголовок, поэтому без допуска проверка считала бы
    правильно настроенную машину «готовой с ошибкой» (первый прогон на площадке так и упал).
    """
    prod_line = (
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" "/swapfile file 4194300\t0\t1\n"
    )
    total_kib = bootstrap.parse_swap_total_kib(prod_line)
    assert total_kib == 4194300
    ok, detail = bootstrap.verdict_swap(total_kib)
    assert ok
    assert "4194300 КиБ" in detail


def test_нехватка_свопа_не_прячется_допуском_заголовка() -> None:
    ok, detail = bootstrap.verdict_swap(int(3.9 * 1024 * 1024))
    assert not ok
    assert "3.90 GiB" in detail


def test_дефолтное_значение_swappiness_считается_ошибкой() -> None:
    ok, detail = bootstrap.verdict_swappiness(60)
    assert not ok
    assert "vm.swappiness=60" in detail
    assert "кэш БД" in detail


def test_битое_значение_swappiness_не_приравнивается_нулю() -> None:
    assert bootstrap.parse_swappiness("не-число\n") is None
    ok, detail = bootstrap.verdict_swappiness(None)
    assert not ok
    assert "недоступно" in detail


def test_fstab_не_принимает_комментарий_за_запись_о_свопе(tmp_path: Path) -> None:
    commented = "# /swapfile none swap sw,pri=1 0 0\n"
    assert not bootstrap.fstab_has_swap(commented)
    assert not bootstrap.check_swap_in_fstab(_write(tmp_path, "fstab", commented)).ok


def test_fstab_видит_запись_о_свопе_и_отсутствующую_запись() -> None:
    applied = "/swapfile none swap sw,pri=1 0 0\n"
    assert bootstrap.fstab_has_swap(applied)
    assert not bootstrap.fstab_has_swap("/dev/sda1 / ext4 defaults 0 1\n")


def test_смещение_часов_разбирается_в_обе_стороны() -> None:
    slow = "System time     : 0.000000088 seconds slow of NTP time\n"
    fast = "System time     : 1.500000 seconds fast of NTP time\n"
    assert bootstrap.parse_chrony_offset_seconds(slow) == pytest.approx(0.000000088)
    assert bootstrap.parse_chrony_offset_seconds(fast) == pytest.approx(1.5)


def test_смещение_больше_двух_секунд_блокирует_запуск(tmp_path: Path) -> None:
    snapshot = _write(tmp_path, "tracking.txt", "System time     : 3.20 seconds slow of NTP time\n")
    result = bootstrap.check_clock_offset(snapshot)
    assert not result.ok
    assert result.severity == bootstrap.FATAL
    assert "R32" in result.detail


def test_смещение_без_снимка_остаётся_замечанием_а_не_зелёным() -> None:
    result = bootstrap.check_clock_offset(None)
    assert result.ok
    assert result.severity == bootstrap.WARN
    assert "chronyc tracking" in result.detail


def test_снимок_без_ожидаемой_строки_не_означает_нулевое_смещение(tmp_path: Path) -> None:
    snapshot = _write(
        tmp_path, "tracking.txt", "Reference ID    : A29FC87B (time.cloudflare.com)\n"
    )
    result = bootstrap.check_clock_offset(snapshot)
    assert not result.ok
    assert "не разобран" in result.detail


def test_проверка_свопа_по_файлу_с_двумя_устройствами(tmp_path: Path) -> None:
    result = bootstrap.check_swap(_write(tmp_path, "swaps", SWAPS_SAMPLE))
    assert result.ok
    assert "5.00 GiB" in result.detail
    assert "включено" in result.detail


def test_проверка_свопа_без_файла_это_замечание_а_не_отказ(tmp_path: Path) -> None:
    result = bootstrap.check_swap(tmp_path / "нет-такого-файла")
    assert result.ok
    assert result.severity == bootstrap.WARN
    assert "на площадке обязательна" in result.detail


def test_проверка_swappiness_читает_значение_из_файла(tmp_path: Path) -> None:
    assert bootstrap.check_swappiness(_write(tmp_path, "swappiness", "10\n")).ok
    broken = bootstrap.check_swappiness(_write(tmp_path, "swappiness.bad", "auto\n"))
    assert not broken.ok
    assert "недоступно" in broken.detail


def test_процесс_ищется_по_comm_без_subprocess(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    for pid, comm in {"1": "systemd", "4242": "chronyd", "77": "cron"}.items():
        directory = proc / pid
        directory.mkdir(parents=True)
        (directory / "comm").write_text(f"{comm}\n", encoding="utf-8")
    assert bootstrap.find_process("chronyd", proc) == 4242
    assert bootstrap.find_process("ntpd", proc) is None
    # каталог, похожий на pid, но без comm (процесс завершился) — не ошибка проверки
    (proc / "99").mkdir()
    assert bootstrap.find_process("chronyd", proc) == 4242


def test_юнит_считается_включённым_только_при_наличии_ссылки(tmp_path: Path) -> None:
    wants = tmp_path / "multi-user.target.wants"
    assert not bootstrap.systemd_unit_enabled("chrony.service", wants)
    wants.mkdir()
    (wants / "chrony.service").write_text("", encoding="utf-8")
    assert bootstrap.systemd_unit_enabled("chrony.service", wants)


def test_проверка_chrony_даёт_два_раздельных_вывода(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    (proc / "10").mkdir(parents=True)
    (proc / "10" / "comm").write_text("chronyd\n", encoding="utf-8")
    running, enabled = bootstrap.check_chrony(proc, tmp_path / "wants")
    assert running.ok
    assert "pid 10" in running.detail
    assert not enabled.ok
    assert "после перезагрузки" in enabled.detail


def test_ресурсы_ловят_пороги_заполненности_диска() -> None:
    ok, _, severity = bootstrap.verdict_resources(
        cpu=2, ram_gib=3.81, disk_gib=71.13, disk_free_gib=65.0, disk_used_percent=70.0
    )
    assert ok
    assert severity == bootstrap.FATAL
    ok, detail, severity = bootstrap.verdict_resources(
        cpu=2, ram_gib=3.81, disk_gib=71.13, disk_free_gib=65.0, disk_used_percent=80.0
    )
    assert ok
    assert severity == bootstrap.WARN
    assert "пора чистить" in detail
    ok, detail, severity = bootstrap.verdict_resources(
        cpu=2, ram_gib=3.81, disk_gib=71.13, disk_free_gib=10.0, disk_used_percent=90.0
    )
    assert not ok
    assert severity == bootstrap.FATAL
    assert "cleanup" in detail


def test_ресурсы_ловят_память_ниже_границы_площадки() -> None:
    ok, detail, severity = bootstrap.verdict_resources(
        cpu=2, ram_gib=2.9, disk_gib=19.0, disk_free_gib=13.0, disk_used_percent=30.0
    )
    assert not ok
    assert severity == bootstrap.FATAL
    assert "RAM=2.90 GiB" in detail
    assert "диск=19.00 GiB" in detail


def test_связка_доверия_содержит_именно_закреплённый_корень(tmp_path: Path) -> None:
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(CA_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    result = bootstrap.check_ca_bundle(bundle)
    assert result.ok
    assert ca_policy.EXPECTED_CA_FINGERPRINT[:16] in result.detail


def test_отсутствие_корня_в_связке_объясняет_как_его_поставить(tmp_path: Path) -> None:
    bundle = _write(tmp_path, "ca-certificates.crt", "-----BEGIN CERTIFICATE-----\nAAAA\n")
    result = bootstrap.check_ca_bundle(bundle)
    assert not result.ok
    assert ca_policy.CA_IMAGE_FILE in result.detail
    assert "update-ca-certificates" in result.detail


def test_офлайн_прогон_не_считает_точки_брокера_упавшими() -> None:
    results = bootstrap.collect_checks(None, live=False)
    broker = [item for item in results if item.name == "broker_tls"]
    assert len(broker) == 1
    assert broker[0].ok
    assert broker[0].severity == bootstrap.WARN
    assert "--skip-broker" in broker[0].detail


def test_на_машине_без_системной_связки_доверия_итог_красный(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Красный вывод там, где нет Linux-связки, — это поведение, а не промах проверки."""
    code = bootstrap.main(["--json", "--skip-broker"])
    output = capsys.readouterr().out
    assert code == 1
    assert '"ok": false' in output
    assert "ca_bundle" in output


def test_модуль_не_использует_subprocess_и_не_требует_подавлений() -> None:
    """Без `subprocess` проверка не нуждается в `nosec` — базовый уровень подавлений не растёт."""
    text = (SCRIPTS / "prod_bootstrap_check.py").read_text(encoding="utf-8")
    assert "import subprocess" not in text
    assert "subprocess." not in text
    for marker in ("noqa", "nosec", "type: ignore", "pragma: no cover"):
        assert marker not in text
