"""Пути к файлам инфраструктуры и загрузка скриптовых модулей — общее для тестов разных уровней."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
COMPOSE_BASE = DEPLOY / "compose.yaml"
COMPOSE_OVERRIDE = DEPLOY / "compose.override.yaml"
POSTGRES_CONF = DEPLOY / "postgres" / "tbot.conf"
DOCKERFILE = DEPLOY / "Dockerfile"
CONFIG_EXAMPLE = ROOT / "configs" / "tbot.example.yaml"
CA_FILE = DEPLOY / "ca" / "ru-trusted-root-ca.pem"
SCRIPTS = ROOT / "scripts"


def load_script(name: str) -> ModuleType:
    """Загрузить модуль из `scripts/` так, как его запускает shell: файлом по пути.

    Скрипты не входят в пакет приложения и не установлены в окружение, поэтому обычный
    `import` их не найдёт. Каталог `scripts/` попадает в `sys.path`: скрипты импортируют соседей
    (`_bootstrap`, `ca_policy`) по имени. Модуль регистрируется в `sys.modules` до выполнения:
    на нём работают `@dataclass` и прочие конструкции, которые ищут свой модуль по имени.
    """
    directory = str(SCRIPTS)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"tbot_scripts.{name}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
