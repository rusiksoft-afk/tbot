"""Пути к файлам инфраструктуры, общие для тестов разных уровней."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
COMPOSE_BASE = DEPLOY / "compose.yaml"
COMPOSE_OVERRIDE = DEPLOY / "compose.override.yaml"
POSTGRES_CONF = DEPLOY / "postgres" / "tbot.conf"
DOCKERFILE = DEPLOY / "Dockerfile"
CONFIG_EXAMPLE = ROOT / "configs" / "tbot.example.yaml"
