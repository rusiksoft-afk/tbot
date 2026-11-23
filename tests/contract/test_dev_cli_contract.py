"""Контракт TZ §4: обязательные команды существуют и не имитируют успех."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Обязательный перечень команд из TZ §4. Изменение перечня — только вместе с правкой ТЗ.
TZ_VERBS: tuple[str, ...] = (
    "dev",
    "lint",
    "test",
    "test-live",
    "e2e",
    "migrate",
    "revision",
    "seed-dev",
    "history-load",
    "backtest",
    "deploy-check",
    "backup",
    "restore-verify",
    "deploy",
)


def _load_dev_cli() -> ModuleType:
    spec = importlib.util.spec_from_file_location("tbot_dev_cli", ROOT / "scripts" / "dev.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_все_обязательные_команды_объявлены() -> None:
    module = _load_dev_cli()
    commands: dict[str, tuple[object, str]] = module.COMMANDS
    missing = [verb for verb in TZ_VERBS if verb not in commands]
    assert not missing, f"в dev-CLI нет обязательных команд: {missing}"
    for verb, (_handler, description) in commands.items():
        assert description, f"команда {verb} не описана в справке"


def test_цели_makefile_соответствуют_обязательным_командам() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for verb in TZ_VERBS:
        assert f"{verb}:" in makefile, f"в Makefile нет цели {verb}"
    wrapper = (ROOT / "make.ps1").read_text(encoding="utf-8")
    for verb in TZ_VERBS:
        assert f"'{verb}'" in wrapper, f"в make.ps1 нет команды {verb}"


def test_audit_verify_существует_и_не_является_заглушкой() -> None:
    """`make audit-verify` обязана существовать и исполняться (`AC-identity-04`, `T-109`).

    В `TZ_VERBS` её нет намеренно: перечень выше — это команды ТЗ §4, и правится он только вместе
    с ТЗ. Команда приходит из приёмки `AC-identity-04` («изменённую вручную копию дампа найти по
    цепочке хэшей») и из `tasks/todo.md` (`T-109`, файлы: `packages/identity/audit.py`,
    `scripts/audit_verify.py`). Разрыв «приёмка требует команду, а обёртки её не знают» — ровно
    тот вид недоделки, который иначе всплывает только на площадке: проверка держит и CLI, и
    обе обёртки, и сам скрипт.

    Заглушкой она быть не может: `GATED` — это перечень команд, которые обязаны возвращать `2`
    до своей вехи, а разбор журнала нужен уже сейчас (на площадке `audit_log` пишется с `R2b`, и
    `integrity-check` §8.7 обязан опираться на тот же разбор, что и ручной прогон).
    """
    module = _load_dev_cli()
    assert "audit-verify" in module.COMMANDS, "в dev-CLI нет команды audit-verify"
    assert "audit-verify" not in module.GATED, "разбор журнала не может быть gated-заглушкой"

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "audit-verify:" in makefile, "в Makefile нет цели audit-verify"
    lines = makefile.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith(".PHONY:"))
    declared = " ".join(lines[start : start + 2])
    assert "audit-verify:" in makefile, "в Makefile нет цели audit-verify"
    assert "audit-verify" in declared, "цель audit-verify не объявлена в .PHONY"
    wrapper = (ROOT / "make.ps1").read_text(encoding="utf-8")
    assert "'audit-verify'" in wrapper, "в make.ps1 нет команды audit-verify"

    script = ROOT / "scripts" / "audit_verify.py"
    assert script.is_file(), "скрипт разбора журнала обязателен (AC-identity-04, T-109)"
    completed = subprocess.run(
        [sys.executable, str(script), "--help"], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    # Коды возврата — часть контракта (`ADR-025` п. 7): разбор обязан объяснять их сам,
    # иначе «1 = находки» и «1 = проверка упала» невозможно различить в cron.
    assert "0 — находок нет" in completed.stdout, completed.stdout
    assert "1 — цепочка нарушена" in completed.stdout, completed.stdout


@pytest.mark.parametrize(
    "verb", ["seed-dev", "history-load", "backtest", "e2e", "backup", "restore-verify"]
)
def test_не_реализованные_по_вехе_команды_возвращают_ошибку(
    verb: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Команда существует, но обязана падать, а не «проходить» с пустым результатом."""
    module = _load_dev_cli()
    handler, _description = module.COMMANDS[verb]
    code = handler(())
    assert code == 2, f"команда {verb} не должна возвращать успех до своей вехи"
    captured = capsys.readouterr()
    assert "задача" in captured.err or "T-" in captured.err


def test_справка_перечисляет_все_команды(capsys: pytest.CaptureFixture[str]) -> None:
    module = _load_dev_cli()
    assert module.main(["--list"]) == 0
    printed = capsys.readouterr().out
    for verb in TZ_VERBS:
        assert verb in printed


def test_неизвестная_команда_это_ошибка_а_не_успех() -> None:
    module = _load_dev_cli()
    assert module.main(["such-command"]) != 0


def test_скрипт_запускается_как_программа() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dev.py"), "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert "deploy-check" in completed.stdout


def test_проверка_конфигурации_площадки_исполнима() -> None:
    """`deploy-check` обязан существовать как скрипт и возвращать осмысленный код."""
    script = ROOT / "scripts" / "deploy_check.py"
    assert script.is_file(), "скрипт проверки площадки обязателен (TZ §4)"
    completed = subprocess.run(
        [sys.executable, str(script), "--help"], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
