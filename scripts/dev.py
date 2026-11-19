#!/usr/bin/env python3
"""Реализация обязательных команд разработки (TZ §4).

`Makefile` и `make.ps1` — тонкие обёртки над этим файлом, чтобы набор команд был одним и тем
же на dev-машине Windows, на Linux и в CI.

Принцип: команда, которая ещё не реализована по вехе, существует и исполняется, но завершается
кодом 2 с явным указанием задачи и вехи, которые её закроют. Успешного «пустого» результата ни
одна из команд имитировать не может (см. `GATED`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_PYTHON = (3, 12)

# Команды, закрытие которых привязано к задаче и вехе: (задача, веха, что нужно сделать).
GATED: dict[str, tuple[str, str, str]] = {
    "seed-dev": ("T-121", "M1", "фикстуры появятся вместе с web-консолью и first-run-сценарием"),
    "history-load": ("T-201", "M2", "загрузчик истории с бюджетом запросов"),
    "backtest": ("T-401", "M4", "движок бэктеста и формат конфигов бэктестов"),
    "e2e": ("T-501", "M5", "сценарии Playwright против развёрнутого dev-стенда"),
    "backup": ("T-601", "M6", "контур резервного копирования и хранение вне площадки"),
    "restore-verify": ("T-602", "M6", "проверка восстановления дампа и сверка контрольных сумм"),
}

Handler = Callable[[Sequence[str]], int]


def run(argv: Sequence[str], *, env: dict[str, str] | None = None) -> int:
    """Запустить команду в корне репозитория; вернуть её код (127 — если инструмента нет)."""
    printable = " ".join(argv)
    print(f"$ {printable}", flush=True)
    try:
        completed = subprocess.run(
            list(argv), cwd=ROOT, env={**os.environ, **(env or {})}, check=False
        )
    except FileNotFoundError:
        print(f"не найдена программа: {argv[0]}", file=sys.stderr)
        return 127
    return int(completed.returncode)


def _python_tool(name: str, args: Sequence[str]) -> list[str]:
    """Инструмент запускается модулем данного интерпретатора: путь к venv не нужен."""
    return [sys.executable, "-m", name, *args]


def cmd_lint(_args: Sequence[str]) -> int:
    steps = [
        _python_tool("ruff", ["format", "--check", "."]),
        _python_tool("ruff", ["check", "."]),
        _python_tool("mypy", ["."]),
    ]
    for step in steps:
        code = run(step)
        if code != 0:
            return code
    return 0


def cmd_fmt(_args: Sequence[str]) -> int:
    for step in (
        _python_tool("ruff", ["format", "."]),
        _python_tool("ruff", ["check", "--fix", "."]),
    ):
        code = run(step)
        if code != 0:
            return code
    return 0


def cmd_typecheck(_args: Sequence[str]) -> int:
    return run(_python_tool("mypy", ["."]))


def cmd_test(_args: Sequence[str]) -> int:
    return run(
        _python_tool(
            "pytest",
            ["-m", "not live_api and not e2e", "--cov", "--cov-report=term-missing"],
        )
    )


def cmd_test_live(args: Sequence[str]) -> int:
    if not os.environ.get("TBOT_SANDBOX_TOKEN"):
        print(
            "TBOT_SANDBOX_TOKEN не задан. Команда обращается к песочнице брокера; боевой "
            "токен ею использоваться не может (TZ §6.4).",
            file=sys.stderr,
        )
        return 2
    return run(_python_tool("pytest", ["-m", "live_api", *args]))


def _compose_base() -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(ROOT / "deploy" / "compose.yaml"),
        "-f",
        str(ROOT / "deploy" / "compose.override.yaml"),
    ]


def cmd_dev(args: Sequence[str]) -> int:
    if shutil.which("docker") is None:
        print(
            "docker не найден на этой машине. Проверка compose-стенда выполняется в CI "
            "(job smoke) или на test-стенде 192.168.1.40 (T-010).",
            file=sys.stderr,
        )
        return 2
    return run([*_compose_base(), "up", "--build", "--wait", "--wait-timeout", "120", *args])


def cmd_migrate(_args: Sequence[str]) -> int:
    return run(_python_tool("alembic", ["upgrade", "head"]))


def cmd_revision(args: Sequence[str]) -> int:
    return run(_python_tool("alembic", ["revision", "--autogenerate", *args]))


def cmd_deploy_check(_args: Sequence[str]) -> int:
    return run([sys.executable, str(ROOT / "scripts" / "deploy_check.py")])


def cmd_deploy(_args: Sequence[str]) -> int:
    print(
        "Боевой деплой выполняется вручную по docs/runbook/deploy.md (TZ §12.7): образы только "
        "по digest, миграции до переключения, обязательная точка отката. Автоматический запуск "
        "из этой команды не предусмотрен.",
        file=sys.stderr,
    )
    return 2


def cmd_ci_local(_args: Sequence[str]) -> int:
    for handler in (cmd_lint, cmd_test, cmd_deploy_check):
        code = handler(())
        if code != 0:
            return code
    return 0


def cmd_clean(_args: Sequence[str]) -> int:
    targets = [
        ROOT / ".pytest_cache",
        ROOT / ".mypy_cache",
        ROOT / ".ruff_cache",
        ROOT / "htmlcov",
        ROOT / "coverage.xml",
        ROOT / ".coverage",
    ]
    removed = 0
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            removed += 1
        elif target.is_file():
            target.unlink(missing_ok=True)
            removed += 1
    for cache in ROOT.rglob("__pycache__"):
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
            removed += 1
    print(f"удалено объектов: {removed}")
    return 0


def _gated(verb: str) -> Handler:
    def handler(_args: Sequence[str]) -> int:
        task, milestone, why = GATED[verb]
        print(
            f"команда `{verb}` ещё не реализована: закроет задача {task} (веха {milestone}) — {why}.",
            file=sys.stderr,
        )
        return 2

    return handler


COMMANDS: dict[str, tuple[Handler, str]] = {
    "dev": (cmd_dev, "compose up dev-стенда (sandbox/paper)"),
    "lint": (cmd_lint, "ruff format --check, ruff check, mypy"),
    "fmt": (cmd_fmt, "отформатировать код"),
    "typecheck": (cmd_typecheck, "только mypy"),
    "test": (cmd_test, 'pytest -m "not live_api and not e2e" с покрытием'),
    "test-live": (cmd_test_live, "pytest -m live_api (только песочница)"),
    "e2e": (_gated("e2e"), "Playwright против dev-стенда"),
    "migrate": (cmd_migrate, "alembic upgrade head"),
    "revision": (cmd_revision, "alembic revision --autogenerate"),
    "seed-dev": (_gated("seed-dev"), "фикстуры dev-стенда"),
    "history-load": (_gated("history-load"), "загрузчик истории с бюджетом"),
    "backtest": (_gated("backtest"), "прогон бэктеста по конфигу"),
    "deploy-check": (cmd_deploy_check, "проверка площадки перед боевым контуром"),
    "backup": (_gated("backup"), "pg_dump + чек-сумма"),
    "restore-verify": (_gated("restore-verify"), "восстановление дампа и сверка"),
    "deploy": (cmd_deploy, "ручной боевой деплой (не автоматизируется здесь)"),
    "ci-local": (cmd_ci_local, "lint + test + deploy-check"),
    "clean": (cmd_clean, "удалить кэши и артефакты"),
}


def _list_commands() -> int:
    print("обязательные команды (TZ §4):")
    for verb, (_handler, description) in COMMANDS.items():
        gate = ""
        if verb in GATED:
            task, milestone, _why = GATED[verb]
            gate = f"  [ожидает: {task}, {milestone}]"
        print(f"  {verb:<15} {description}{gate}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info < MIN_PYTHON:
        print(
            f"нужен Python {'.'.join(map(str, MIN_PYTHON))}+, найден "
            f"{'.'.join(map(str, sys.version_info[:3]))}",
            file=sys.stderr,
        )
        return 2
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "--list"}:
        return _list_commands()
    verb, *rest = args
    entry = COMMANDS.get(verb)
    if entry is None:
        print(f"неизвестная команда: {verb}", file=sys.stderr)
        _list_commands()
        return 2
    handler, _description = entry
    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main())
