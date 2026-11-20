"""Контракт compose: сеть без исходящего трафика у БД, healthchecks, non-root, лимиты (T-005).

Проверка статическая: она исполняется на dev-машине без Docker и в CI до подъёма стенда.
Поведенческая часть (реальный `up` и пробы) — job `compose-smoke` в `.github/workflows/ci.yml`.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from tests.paths import COMPOSE_BASE, COMPOSE_OVERRIDE, DOCKERFILE, ROOT, load_script

LONG_RUNNING = ("web", "engine", "tgbot", "jobs")

# Минимальный набор capability, который нужен entrypoint официального образа postgres:
# вход в каталог данных после `chmod 00700` (DAC_OVERRIDE), chmod этих каталогов (FOWNER),
# chown каталога данных и unix-сокета (CHOWN) и переключение на пользователя postgres через
# gosu — setgroups/setgid/setuid (SETGID, SETUID).
DB_CAPS_ALLOWED: frozenset[str] = frozenset({"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"})


def _postgres_conf_values() -> dict[str, str]:
    conf = (COMPOSE_BASE.parent / "postgres" / "tbot.conf").read_text(encoding="utf-8")
    return {
        line.split("=")[0].strip(): line.split("=", 1)[1].strip().strip("'\"")
        for line in conf.splitlines()
        if "=" in line and not line.strip().startswith("#")
    }


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


def test_контекст_сборки_и_dockerfile_существуют() -> None:
    """Контекст в compose разрешается относительно каталога compose-файла, а не репозитория.

    Ошибка вида `context: .` внутри deploy/compose.yaml даёт `deploy/deploy/Dockerfile` и
    падает на сборке в CI; здесь это проверяется без Docker — по факту существования путей.
    """
    services = _base()["services"]
    project_dir = COMPOSE_BASE.parent
    built = [
        name for name, spec in services.items() if isinstance(spec, dict) and spec.get("build")
    ]
    assert built, "в compose не осталось ни одной сборки — стенд нечем поднять"
    for name in built:
        build = services[name]["build"]
        context = (project_dir / str(build["context"])).resolve()
        dockerfile = context / str(build["dockerfile"])
        assert context.is_dir(), f"{name}: контекст не существует: {context}"
        assert dockerfile.is_file(), f"{name}: dockerfile не найден: {dockerfile}"
        assert build["context"] == "..", (
            f"{name}: контекст обязан быть `..` (корень репозитория), иначе докерфайл ищется "
            "внутри deploy/"
        )


def test_хостовые_пут_и_монтирований_существуют() -> None:
    """Относительные пути в `volumes` разрешаются относительно каталога compose-файла.

    `./deploy/postgres/tbot.conf` внутри `deploy/compose.yaml` — это `deploy/deploy/...`, а
    несуществующий хостовый путь в короткой форме Docker молча заменяет на пустой каталог.
    Для базы это выглядело бы как `config_file=…`, которым оказался каталог, и падение с
    `input in flex scanner failed at file "/etc/postgresql/tbot.conf" line 1` — в сообщении
    нет ни слова про пропущенный монтаж, поэтому проверка здесь.
    """
    project_dir = COMPOSE_BASE.parent
    broken: list[str] = []
    for name, spec in _base()["services"].items():
        for mount in spec.get("volumes", []):
            source = str(mount).split(":", 1)[0]
            if not source.startswith(("./", "../")):
                continue  # именованный том (`pgdata`) или абсолютный путь — проверять нечего
            if not (project_dir / source).exists():
                broken.append(f"{name}: {source} -> {project_dir / source}")
    assert not broken, f"монтируемых файлов/каталогов нет на месте: {broken}"


def test_докерфайл_объявляет_синтаксис_buildkit_корректно() -> None:
    """Директива `# syntax=` обязана быть первой строкой и в форме образа, а не контекста.

    Форма `docker/dockerfile=1.7` парсится как имя контекста и даёт
    `invalid reference format` — сборка падает до первого шага.
    """
    first_line = DOCKERFILE.read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith("# syntax=docker/dockerfile:"), f"первая строка: {first_line!r}"


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
    values = _postgres_conf_values()
    assert values["max_connections"] == "60"
    shared_buffers = values["shared_buffers"]
    assert shared_buffers.endswith("MB")
    assert int(shared_buffers[:-2]) <= 512, "для OQ-11 shared_buffers не выше 512MB"
    assert values["timezone"] == "UTC"


def test_база_слушает_не_только_loopback_внутри_контейнера() -> None:
    """Приложение ходит в базу по TCP через сеть `tbot-backend`.

    `listen_addresses = 'localhost'` — это только loopback самого контейнера, и тогда
    web/engine/jobs получают «connection refused», а job `compose-smoke` падает на
    неготовом `/readyz` — по причине, которую по журналу базы не найти.
    """
    assert _postgres_conf_values()["listen_addresses"] == "*", (
        "внутри контейнера база обязана слушать все интерфейсы: наружу её порт не смотрит, "
        "потому что база подключена только к internal-сети, а публикация портов есть "
        "только в dev-дополнении и только на 127.0.0.1"
    )


def test_база_получает_только_те_capability_которые_нужны_entrypoint() -> None:
    """Исключение из `cap_drop: ALL` разрешено только базе и только в этом наборе.

    Без CHOWN/FOWNER entrypoint не может подготовить каталоги, без DAC_OVERRIDE он не может
    войти в каталог данных, который сам же перевёл в режим 0700 (владелец-то postgres), а без
    SETGID/SETUID он падает на `failed switching to \"postgres\"` (gosu делает
    setgroups/setgid/setuid). Всё остальное обязано оставаться сброшенным; `no-new-privileges`
    и read-only rootfs сохраняются и у базы — исключение не должно превратиться в «обычный»
    контейнер.
    """
    postgres = _base()["services"]["postgres"]
    assert postgres.get("cap_drop") == ["ALL"], "у базы список capability сбрасывается целиком"
    granted = set(postgres.get("cap_add", []))
    assert (
        granted == DB_CAPS_ALLOWED
    ), f"у базы capability {sorted(granted)}, а обосновано только {sorted(DB_CAPS_ALLOWED)}"
    assert "no-new-privileges:true" in postgres.get("security_opt", [])
    assert postgres.get("read_only") is True, "read-only rootfs у базы сохраняется"
    tmpfs_paths = [str(item).split(":", 1)[0] for item in postgres.get("tmpfs", [])]
    assert "/var/run/postgresql" in tmpfs_paths, (
        "каталог unix-сокета базы обязан быть на записи: на read-only rootfs postgres не "
        "может создать в нём сокет"
    )


@pytest.mark.parametrize("service", [*LONG_RUNNING, "migrate"])
def test_прикладные_процессы_не_получают_capability(service: str) -> None:
    """Точечное исключение — только у postgres; прикладные процессы запускаются под uid 10001."""
    spec = _base()["services"][service]
    assert spec.get("cap_drop") == ["ALL"]
    assert "cap_add" not in spec, f"{service}: возвращать capability прикладному процессу нельзя"


def test_процесс_jobs_проверяется_liveness_а_не_readiness() -> None:
    """На M0 у `jobs` нет ни одного исполнителя задач, и `/readyz` честно отвечает 503.

    Если оставить healthcheck на `/readyz`, `up --wait` никогда не станет зелёным, а
    приёмка T-005 («/readyz» 200 у web и engine) этого и не требует. Проверка готовности
    задач вернётся вместе с исполнителями (M2, docs/tz/12 §12.3) — см.
    `tests/unit/test_jobs_registry.py::test_исполнители_задач_появятся_не_раньше_своей_логики`.
    """
    test_command = _base()["services"]["jobs"]["healthcheck"]["test"]
    joined = " ".join(str(item) for item in test_command)
    assert "--liveness" in joined, "healthcheck jobs обязан использовать флаг --liveness"
    assert "/healthz" in joined, "healthcheck jobs обязан опрашивать /healthz (liveness)"


def test_образ_запускается_от_ne_root() -> None:
    dockerfile = (COMPOSE_BASE.parent / "Dockerfile").read_text(encoding="utf-8")
    assert "useradd --uid 10001" in dockerfile
    assert "USER 10001:10001" in dockerfile


def test_образ_кладёт_корень_нц_до_пересборки_связки_доверия() -> None:
    """Порядок шагов в Dockerfile — единственное, что гарантирует доверие к брокеру в образе.

    `update-ca-certificates` пересобирает `/etc/ssl/certs/ca-certificates.crt` из того, что уже
    лежит в `/usr/local/share/ca-certificates`. Если копирование корня идёт после этого шага,
    сборка выглядит успешной, а доверия в образе нет: приложение спотыкается уже в бою, где
    сеть к брокеру есть, а корня нет. Поведенчески это проверяет шаг compose-smoke «корень НУЦ
    установлен в системный набор доверия образа», а порядок закрепляется здесь.
    """
    ca_policy = load_script("ca_policy")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    copy_marker = f"COPY deploy/ca/ {ca_policy.CA_IMAGE_DIR}/"
    assert copy_marker in dockerfile, (
        f"в Dockerfile нет копирования корня в {ca_policy.CA_IMAGE_DIR} — каталог якорей "
        "разошёлся с scripts/ca_policy.py"
    )
    copy_at = dockerfile.index(copy_marker)
    update_at = dockerfile.index("update-ca-certificates")
    assert copy_at < update_at, (
        "`update-ca-certificates` исполняется раньше, чем скопирован корень: связка доверия "
        "образа останется без него"
    )


def test_публичный_корень_нц_не_прячется_в_gitignore() -> None:
    """`*.pem` в `.gitignore` защищает от приватных ключей, но публичный корень — артефакт сборки.

    Если `deploy/ca/ru-trusted-root-ca.pem` не попадает в коммит, в свежем чекауте в образ
    копируется только README: сборка и `up --wait` остаются зелёными, а доверия к брокеру в
    образе нет — приложение спотыкается уже в бою. Поэтому для этого каталога нужна явная
    отмена игнорирования, и она здесь закреплена.
    """
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "!deploy/ca/*.pem" in ignore, (
        "в .gitignore нет `!deploy/ca/*.pem`: публичный корень НУЦ не попадёт в коммит, "
        "и в образе не будет доверия к брокеру"
    )
