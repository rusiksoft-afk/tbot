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
