"""Пути к файлам инфраструктуры и загрузка скриптовых модулей — общее для тестов разных уровней."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
COMPOSE_BASE = DEPLOY / "compose.yaml"
COMPOSE_OVERRIDE = DEPLOY / "compose.override.yaml"
COMPOSE_PROD = DEPLOY / "compose.prod.yaml"
PROD_ENV = DEPLOY / "tbot.prod.env"
CADDYFILE = DEPLOY / "caddy" / "Caddyfile"
POSTGRES_CONF = DEPLOY / "postgres" / "tbot.conf"
DOCKERFILE = DEPLOY / "Dockerfile"
CONFIG_EXAMPLE = ROOT / "configs" / "tbot.example.yaml"
CA_FILE = DEPLOY / "ca" / "ru-trusted-root-ca.pem"
VPS = DEPLOY / "vps"
README = DEPLOY / "README.md"
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


class _ComposeLoader(yaml.SafeLoader):
    """`SafeLoader`, знающий теги слияния compose: без них боевой файл не разобрать вовсе."""


def _compose_tag(loader: yaml.SafeLoader, node: yaml.nodes.Node) -> object:
    """Разобрать содержимое тега `!override` как обычное значение его формы."""
    if isinstance(node, yaml.nodes.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.nodes.MappingNode):
        return loader.construct_mapping(node)
    # Остальные формы в compose-файлах этого вида — скаляры (`!override null`, `!reset []` и т.п.).
    return loader.construct_scalar(cast(yaml.nodes.ScalarNode, node))


def _reset_tag(_loader: yaml.SafeLoader, _node: yaml.nodes.Node) -> None:
    """`!reset` (compose ≥2.24): содержимое тега compose игнорирует, значение сбрасывается.

    Возвращаемое значение — `None` (единственное тело — докстринг): именно так compose и
    трактует сброшенный атрибут.
    """


_ComposeLoader.add_constructor("!reset", _reset_tag)
_ComposeLoader.add_constructor("!override", _compose_tag)


def load_compose_yaml(path: Path) -> dict[str, Any]:
    """Разобрать compose-файл загрузчиком, который знает теги compose.

    Это подкласс `yaml.SafeLoader`, поэтому произвольные объекты он не создаёт: набор
    принимаемых тегов замкнут двумя конструкторами выше. `yaml.safe_load` вместо него не
    подходит — он падает на неизвестном теге `!reset` (его понимает только compose).
    """
    parser = _ComposeLoader(path.read_text(encoding="utf-8"))
    data = parser.get_single_data()
    assert isinstance(data, dict), f"{path.name}: ожидаем отображение верхнего уровня"
    return cast(dict[str, Any], data)
