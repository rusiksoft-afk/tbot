#!/usr/bin/env python3
"""Подсчёт подавлений проверок в дереве: `make suppressions` и шаг CI `suppress-growth`.

Единый источник правды для числа `SUPPRESSION_BASELINE` в workflow: раньше регулярное
выражение было продублировано в CI и в контрактном тесте, и они могли разойтись (подавления
`nosec` от bandit вообще не попадали в счётчик, хотя охранять надо и их).

Считаются четыре вида: `noqa`, `nosec`, `type: ignore`, `pragma: no cover`. Порог не повышается
молча — рост обязан сопровождаться решением заказчика и записью в
`docs/acceptance/m0-quality.md §2`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIR_PARTS: frozenset[str] = frozenset(
    {".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "tbot.egg-info"}
)
SUPPRESSION_RE = re.compile(r"#\s*(noqa|nosec|type:\s*ignore|pragma:\s*no cover)")


def find_suppressions(root: Path = ROOT) -> list[tuple[str, int, str]]:
    """Вернуть список (файл, строка, текст строки) для всех подавлений в дереве."""
    found: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*.py")):
        if EXCLUDED_DIR_PARTS & set(path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if SUPPRESSION_RE.search(line):
                found.append((str(path.relative_to(root)), line_no, line.strip()))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="посчитать подавления проверок в дереве")
    parser.add_argument(
        "--list", action="store_true", help="показать не только число, но и адреса строк"
    )
    arguments = parser.parse_args(argv)

    found = find_suppressions()
    for name, line_no, line in found:
        if arguments.list:
            print(f"{name}:{line_no}: {line}")
    print(len(found))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
