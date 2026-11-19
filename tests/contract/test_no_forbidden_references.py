"""Контракт TZ §7 и docs/tz/15: в репозитории нет запрещённых ссылок, чужих импортов и секретов.

Файл намеренно собирает запрещённые подстроки из частей: иначе сам себя и помечал бы как
нарушение при обходе дерева.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".sql",
    ".j2",
    ".html",
    ".css",
    ".sh",
    ".cfg",
    ".ini",
}
SPECIAL_NAMES = {"Makefile", "make.ps1"}

# Ссылки на сторонний облачный сервис-аналог запрещены (TZ §7, docs/tz/15 §15.1).
BANNED_SUBSTRINGS: tuple[str, ...] = (
    ("cloud" + "bot").lower(),
    ("cloud" + "bots"),
    "clou" + "dbot.uk",
)

# Старые/чужие пути импорта SDK брокера запрещены (docs/tz/03 §3.1).
BANNED_IMPORT_PREFIXES: tuple[str, ...] = (
    "tinkoff" + ".invest",
    "t_tech.invest" + ".services",
    "tinkoff" + "-invest-api-python-sdk",
)

# Учётные данные в URI: реальный секрет выглядит как набор допустимых символов base64/url.
# Регулярность исходного кода (например, шаблон `…://[^/\s]*@` в `config.py`) под это правило
# не попадает, поэтому само правило не помечает файл, в котором оно объявлено.
CREDENTIALED_URI_RE = re.compile(
    r"(?:ss|vless|trojan|vmess|socks5|socks5h|redis|postgres(?:ql)?|amqp|https?)://"
    r"(?P<cred>[A-Za-z0-9+/_=-]{6,}(?::[^/\s@\"]{3,})?)@"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|RSA PRIVATE KEY)-----")
TOKENISH_RE = re.compile(r"\b\d{9,11}:[A-Za-z0-9_-]{34,}")


def _text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(ROOT).parts)
        if {".git", ".venv", "__pycache__", "node_modules", ".mypy_cache", ".ruff_cache"} & parts:
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in SPECIAL_NAMES:
            files.append(path)
    return files


@pytest.mark.parametrize("banned", BANNED_SUBSTRINGS)
def test_запрещённые_упоминания_стороннего_сервиса_отсутствуют(banned: str) -> None:
    hits: list[str] = []
    for path in _text_files():
        content = path.read_text(encoding="utf-8", errors="ignore").lower()
        if banned in content:
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, f"найден запрещённый термин {banned!r} в файлах: {hits}"


def test_запрещённые_импорты_sdk_отсутствуют() -> None:
    hits: list[str] = []
    for path in ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            # Файл с синтаксической ошибкой всё равно не пройдёт `ruff check` и `mypy` в том же
            # job'е, поэтому ветка здесь — страховка от падения самого сканирования.
            continue
        for node in ast.walk(tree):
            module = (
                node.module
                if isinstance(node, ast.ImportFrom)
                else next((alias.name for alias in node.names), "")
                if isinstance(node, ast.Import)
                else ""
            )
            if module and any(module.startswith(banned) for banned in BANNED_IMPORT_PREFIXES):
                hits.append(f"{path.relative_to(ROOT)}: {module}")
    assert not hits, f"запрещённые импорты SDK: {hits}"


def test_разрешённый_путь_импорта_sdk_используется_корректно() -> None:
    """Если SDK уже подключён, импорт обязан идти из канонического пути `t_tech.invest.grpc`."""
    for path in ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if "t_tech" not in source:
            continue
        assert (
            "t_tech.invest.grpc" in source
        ), f"{path.relative_to(ROOT)}: неканонический импорт SDK"


def test_в_файлах_нет_учебных_ключей_и_приватных_ключей() -> None:
    offenders: list[str] = []
    for path in _text_files():
        relative = path.relative_to(ROOT)
        # Синтетические «канареечные» значения живёт только в тестах: они и нужны, чтобы
        # проверять маскирование. Для остальных файлов проверка строгая.
        canaries_allowed = relative.parts[0] == "tests" and relative.name.startswith("test_")
        content = path.read_text(encoding="utf-8", errors="ignore")
        if not canaries_allowed and PRIVATE_KEY_RE.search(content):
            # Метка приватного ключа допускается только в тестовых канарейках: она нужна,
            # чтобы проверять маскирование в логах (см. test_logging_masking).
            offenders.append(f"{relative}: метка приватного ключа")
        if not canaries_allowed:
            for match in CREDENTIALED_URI_RE.finditer(content):
                credential = match.group("cred")
                if "<" in credential or "*" in credential or "МАСКА" in credential.upper():
                    continue  # явный плейсхолдер из документации
                offenders.append(f"{relative}: URI с учётными данными")
            if TOKENISH_RE.search(content):
                offenders.append(f"{relative}: набор, похожий на токен Bot API")
    assert not offenders, "секретоподобные значения в дереве: " + "; ".join(offenders)


def test_файлы_секретов_не_в_дереве() -> None:
    forbidden_names = {".env"}
    for path in ROOT.rglob("*"):
        if path.is_file() and path.name in forbidden_names:
            pytest.fail(f"в дереве репозитория лежит файл секретов: {path.relative_to(ROOT)}")
