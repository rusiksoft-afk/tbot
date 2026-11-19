"""Контракт TZ §5: структура репозитория и направление импортов (только «вниз» по Capability Map)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_TOP_LEVEL: tuple[str, ...] = (
    "CAPABILITY_MAP.md",
    "README.md",
    "docs/TZ.md",
    "docs/PROMPT.md",
    "docs/tz",
    "docs/runbook",
    "docs/research",
    "docs/acceptance",
    "tasks/plan.md",
    "tasks/todo.md",
    "apps",
    "packages",
    "configs",
    "deploy",
    "tests",
    "scripts",
    ".github/workflows",
    "pyproject.toml",
    "Makefile",
    ".gitignore",
    ".editorconfig",
)

APP_PACKAGES: tuple[str, ...] = ("web", "engine", "tgbot", "jobs")


@pytest.mark.parametrize("entry", REQUIRED_TOP_LEVEL)
def test_обязательные_элементы_структуры_на_месте(entry: str) -> None:
    assert (ROOT / entry).exists(), f"в структуре нет обязательного элемента: {entry}"


@pytest.mark.parametrize("app", APP_PACKAGES)
def test_каждый_процесс_объявлен_как_пакет_с_точкой_входа(app: str) -> None:
    package = ROOT / "apps" / app
    assert (package / "__init__.py").is_file(), f"нет пакета приложения: {app}"
    assert (package / "main.py").is_file(), f"нет точки входа процесса: {app}"


def test_секции_техзадания_присутствуют() -> None:
    sections = sorted(path.name for path in (ROOT / "docs" / "tz").glob("[0-9][0-9]-*.md"))
    assert len(sections) == 15, f"ожидалось 15 секций ТЗ, найдено {len(sections)}: {sections}"


def test_каждый_пакет_общего_слоя_оформлен_правильно() -> None:
    for package in (ROOT / "packages").iterdir():
        if not package.is_dir() or package.name in {"__pycache__"}:
            continue
        assert (package / "__init__.py").is_file(), f"в {package.name} нет __init__.py"


def test_общий_слой_не_импортирует_прикладной() -> None:
    """`packages/*` не вправе импортировать `apps/*` — это ломает переиспользование в бэктесте."""
    offenders: list[str] = []
    for path in (ROOT / "packages").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name == "apps" or name.startswith("apps."):
                    offenders.append(f"{path.relative_to(ROOT)}: {name}")
    assert not offenders, "нарушено направление импортов: " + "; ".join(offenders)


def test_прикладные_процессы_не_импортируют_друг_друга() -> None:
    """Процессы общаются через базу и очереди состояний, а не друг через друга (docs/tz/02 §2.1)."""
    offenders: list[str] = []
    for app in APP_PACKAGES:
        for path in (ROOT / "apps" / app).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    for other in APP_PACKAGES:
                        if other != app and (
                            name == f"apps.{other}" or name.startswith(f"apps.{other}.")
                        ):
                            offenders.append(f"{path.relative_to(ROOT)}: {name}")
    assert not offenders, "межпроцессные импорты приложения: " + "; ".join(offenders)


def test_тесты_разложены_по_уровням() -> None:
    for level in ("unit", "integration", "contract"):
        assert (ROOT / "tests" / level).is_dir(), f"нет каталога тестов уровня {level}"
