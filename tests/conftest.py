"""Общая изоляция окружения для тестов: конфигурация не должна читать реальные секреты."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.common.config import Settings

# Переменные, которые не должны просачиваться в тесты из dev-оболочки.
_TBOT_ENV_PREFIX = "TBOT_"


@pytest.fixture(autouse=True)
def clean_tbot_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Убрать все TBOT_* переменные, кроме явно заданных самим тестом."""
    for name in list(os.environ):
        if name.startswith(_TBOT_ENV_PREFIX):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    """Каталог секретов в временной директории (пустой; тесты кладут файлы сами)."""
    directory = tmp_path / "secrets"
    directory.mkdir()
    return directory


@pytest.fixture
def settings(secrets_dir: Path) -> Settings:
    """Конфигурация по умолчанию для контура песочницы."""
    return Settings(secrets_dir=secrets_dir, instance_name="test")
