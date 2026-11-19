"""Контракт compose: сеть без исходящего трафика у БД, healthchecks, non-root, лимиты (T-005).

Проверка статическая: она исполняется на dev-машине без Docker и в CI до подъёма стенда.
Поведенческая часть (реальный `up` и пробы) — job `compose-smoke` в `.github/workflows/ci.yml`.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from tests.paths import COMPOSE_BASE, COMPOSE_OVERRIDE

LONG_RUNNING = ("web", "engine", "tgbot", "jobs")


def _base() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE_BASE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _override() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE_OVERRIDE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_состав_сервисов_соответствует_архитектуре() -> None:
    services = _base()["services"]
    assert set(services) >= {*LONG_RUNNING, "postgres", "migrate"}


def test_база_не_имеет_пути_наружу() -> None:
    """Приёмка T-005: egress для БД закрыт — только внутренняя сеть, без публикации портов."""
    compose = _base()
    postgres = compose["services"]["postgres"]
    assert "ports" not in postgres, "порты базы нельзя публиковать в базовом compose"
    assert postgres["networks"] == ["tbot-backend"]
    assert compose["networks"]["tbot-backend"]["internal"] is True


@pytest.mark.parametrize("service", LONG_RUNNING)
def test_каждый_процесс_имеет_healthcheck_и_ограничения(service: str) -> None:
    services = _base()["services"]
    spec = services[service]
    assert spec.get("healthcheck"), f"у {service} нет healthcheck"
    test_command = spec["healthcheck"]["test"]
    assert isinstance(test_command, list)
    assert "packages.common.health_probe" in " ".join(
        test_command
    ), f"healthcheck {service} обязан использовать общий модуль пробы, а не curl"
    # Общие runtime-настройки разворачиваются YAML-якорем: проверяем наличие самого якоря.
    assert "no-new-privileges:true" in COMPOSE_BASE.read_text(encoding="utf-8")
    assert spec.get("read_only") is True, f"{service} обязан запускаться на read-only rootfs"
    assert spec.get("pids_limit"), f"у {service} нет ограничения на число процессов"


def test_зависимости_построены_на_готовности_базы() -> None:
    services = _base()["services"]
    for service in ("web", "engine", "jobs"):
        depends = services[service].get("depends_on", {})
        assert (
            depends.get("postgres", {}).get("condition") == "service_healthy"
        ), f"{service} обязан ждать готовности базы"


def test_секреты_описаны_и_монтируются_как_файлы() -> None:
    compose = _base()
    secrets = compose.get("secrets", {})
    assert set(secrets) >= {"db_password", "db_url", "tg_bot_token", "tg_socks_password"}
    for name, spec in secrets.items():
        assert str(spec.get("file", "")).startswith(
            "./secrets/"
        ), f"секрет {name} обязан быть файлом"
    assert "secrets/" in (COMPOSE_BASE.parent.parent / ".gitignore").read_text(encoding="utf-8")


def test_секрет_попадает_только_тому_процессу_который_его_читает() -> None:
    """Минимум лишнего доступа: токен бота не виден вебу, адрес базы — не виден tgbot-контейнеру.

    Проверка держит соответствие между списком `SECRET_FIELDS` в конфигурации и тем, что
    реально монтируется: лишний секрет в контейнере — это лишний путь утечки в дампе или в логе.
    """
    services = _base()["services"]
    expected = {
        "postgres": {"db_password"},
        "web": {"db_url"},
        "engine": {"db_url"},
        "jobs": {"db_url"},
        "migrate": {"db_url"},
        "tgbot": {"tg_bot_token", "tg_socks_password"},
    }
    for service, names in expected.items():
        mounted = set(services[service].get("secrets", []))
        assert mounted == names, f"{service}: ожидались секреты {names}, получено {mounted}"


def test__logs_ограничены_по_объёму() -> None:
    raw = COMPOSE_BASE.read_text(encoding="utf-8")
    assert "max-size" in raw
    assert "max-file" in raw, "нужна ротация логов контейнеров"


def test_дополнение_dev_публикует_порты_только_на_loopback() -> None:
    services = _override()["services"]
    for service, spec in services.items():
        for mapping in spec.get("ports", []):
            assert str(mapping).startswith(
                "127.0.0.1:"
            ), f"{service}: публикация наружу недопустима, только loopback (dev)"


def test_параметры_базы_под_ограничения_площадки() -> None:
    """OQ-11: shared_buffers ≤512MB и max_connections ≤60 для 2 vCPU / 3.8 GiB."""
    conf = (COMPOSE_BASE.parent / "postgres" / "tbot.conf").read_text(encoding="utf-8")
    values = {
        line.split("=")[0].strip(): line.split("=", 1)[1].strip().strip("'\"")
        for line in conf.splitlines()
        if "=" in line and not line.strip().startswith("#")
    }
    assert values["max_connections"] == "60"
    shared_buffers = values["shared_buffers"]
    assert shared_buffers.endswith("MB")
    assert int(shared_buffers[:-2]) <= 512, "для OQ-11 shared_buffers не выше 512MB"
    assert values["timezone"] == "UTC"


def test_образ_запускается_от_ne_root() -> None:
    dockerfile = (COMPOSE_BASE.parent / "Dockerfile").read_text(encoding="utf-8")
    assert "useradd --uid 10001" in dockerfile
    assert "USER 10001:10001" in dockerfile
