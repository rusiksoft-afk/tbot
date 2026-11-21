"""Контракт боевого состава: `deploy/compose.prod.yaml`, `deploy/tbot.prod.env`, `deploy/caddy/Caddyfile`.

Dev-стенд покрыт `test_compose_contract.py` и job'ом `compose-smoke`, а боевой состав не
исполняется нигде: ни локально (на dev-машине нет Docker), ни в CI до появления job'а
`prod-config`. Класс возможных ошибок здесь тот же, что и «восемь причин» падения
`compose-smoke` (HANDOFF §1.2, §1.4): файл разбирается, но проверяет не то. Что держится этим
контрактом:

*   образы берутся из реестра **по digest**, а локальной сборки в боевом разборе нет вовсе
    (`build` объявлен только в dev-дополнении: `!reset null` в overlay её не отключает —
    проверено первым прогоном job'а `prod-config`);
*   наружу публикуется **только** 80/443 Caddy: опубликованный Docker-портом порт доступен
    снаружи независимо от `ufw` (правила уходят в `FORWARD`/`nat`), поэтому «какой порт
    наружу» решает этот файл, а не файрвол (`docs/acceptance/prod-firewall.md §5`);
*   секреты читаются файлами из каталога площадки (TZ §14.3), а не из `deploy/secrets/`;
*   лимиты памяти/CPU не выше потолков TZ §14.6 и вписываются в фактическую площадку (OQ-11);
*   Caddyfile держит заголовки и версии TLS из TZ §8.3, не отключает ACME и проксирует на тот
    порт, который процесс `web` действительно слушает.

Поведенческая половина — job `prod-config` в `.github/workflows/ci.yml`: только `docker compose
config` знает настоящие правила слияния overlay, а `caddy validate` внутри образа с
закреплённым digest — единственный способ проверить Caddyfile, не поднимая площадку.

Подавления проверок здесь не проверяются отдельным тестом: уровень 14 держит общий счётчик
`scripts/count_suppressions.py`, на нём стоит `test_ci_workflows` и job `quality` в CI; локальный
поиск по строкам внутри этого файла неизбежно находил бы собственный шаблон поиска.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from packages.common.config import Settings
from tests.paths import (
    CADDYFILE,
    COMPOSE_BASE,
    COMPOSE_OVERRIDE,
    COMPOSE_PROD,
    DEPLOY,
    PROD_ENV,
    README,
    VPS,
    load_compose_yaml,
)

APP_SERVICES: tuple[str, ...] = ("web", "engine", "tgbot", "jobs")
ONE_SHOT = "migrate"
PROXY = "caddy"
PROD_SERVICES: tuple[str, ...] = (*APP_SERVICES, "postgres", ONE_SHOT, PROXY)

# Потолки TZ §14.6. Фактическая площадка (OQ-11: 2 vCPU / 3.8 ГиБ) меньше целевой
# конфигурации ТЗ, поэтому в боевом составе значения обязаны быть НЕ ВЫШЕ этих: понижать
# можно и нужно, повышать — нет.
TZ_MEM_MIB: dict[str, int] = {
    PROXY: 128,
    "web": 512,
    "engine": 1536,
    "tgbot": 256,
    "jobs": 3072,
    "postgres": 3072,
}
TZ_CPUS: dict[str, float] = {
    PROXY: 0.25,
    "web": 1.0,
    "engine": 2.0,
    "tgbot": 0.25,
    "jobs": 3.0,
    "postgres": 2.0,
}

# 3.8 ГиБ ≈ 3892 МиБ. Потолок 3072 МиБ оставляет ≈0.8 ГиБ на ядро, dockerd, xray-туннель
# (MemoryMax=96M у службы), fail2ban и page cache. Число сознательно «тугое»: рост суммы
# требует явного решения, а не молчаливой правки одной строки.
HOST_MEM_CEILING_MIB = 3072
HOST_VCPU = 2.0
CPU_OVERSUBSCRIPTION = 2.0

ALLOWED_PUBLIC_PORTS = {"80:80", "443:443", "443:443/udp"}
# Внутренние порты не должны появляться в боевом файле даже как подстрока «порт:».
NEVER_PUBLISHED = ("5432", "8080", "9101", "9102", "9103", "10800")

# Белый список полей, которые overlay вправе задавать для уже существующего сервиса. Смысл:
# overlay описывает *что запускать* (образ, лимиты, сети, restart), а не *как песочница* —
# режим контейнера задаёт базовый файл, и вернуть через overlay `privileged`, `cap_add` или
# хостовый том нельзя.
ALLOWED_OVERLAY_KEYS: dict[str, set[str]] = {
    "postgres": {"image", "restart", "mem_limit", "cpus"},
    "web": {"image", "restart", "mem_limit", "cpus", "networks", "environment"},
    "engine": {
        "image",
        "restart",
        "mem_limit",
        "cpus",
        "stop_grace_period",
        "environment",
    },
    "tgbot": {"image", "restart", "mem_limit", "cpus", "environment"},
    "jobs": {"image", "restart", "mem_limit", "cpus", "environment"},
    ONE_SHOT: {"image", "mem_limit"},
}
ALLOWED_OVERLAY_ENV_KEYS = {"TBOT_CONTOUR", "TBOT_CONFIRM_PRODUCTION"}

# Имена файлов на площадке (те, что кладёт заказчик и описывают runbook'и) отличаются от имён
# compose-секретов: в контейнер compose монтирует их под именем секрета, а приложение читает
# `/run/secrets/<имя_поля_конфигурации>`.
PROD_SECRET_FILES: dict[str, str] = {
    "db_password": "db_password",
    "db_url": "db_url",
    "tg_bot_token": "telegram_token",
    "tg_socks_password": "telegram_socks_pass",
}
SECRETS_ROOT = "/etc/tbot/secrets"

# Файл ключей TOTP — единственное исключение из «все секреты из каталога площадки»: путь называет
# сам TZ §8.4 (`/etc/tbot/keys/kek.json`), а `ADR-014` п. 5 и решение заказчика от 2026-11-21
# (ask `05f7f262-0c56-41e6-9959-12aac2a45edb`) задали для него права `640 root:gid 10001`.
# Исключение держится контрактом явно: перенос файла ключей в `SECRETS_ROOT` выглядел бы как
# «наведение порядка», но на деле отдаёт права файлу, о котором `secrets-setup.sh` не знает
# (тот умеет только строку секрета), и отменяет путь, названный TZ.
KEK_SECRET = "kek_file"
KEYS_ROOT = "/etc/tbot/keys"
KEK_PATH = f"{KEYS_ROOT}/kek.json"

CADDY_CAPS: frozenset[str] = frozenset({"NET_BIND_SERVICE"})
CADDY_MEM_LIMIT = "128m"
CADDY_CPUS = 0.25

# Пределы охранных настроек прокси. Строка «ограничение есть» сама по себе ничего не значит:
# `max_size 500MB` или `read_header 600s` формально ограничивают, но защиту не обеспечивают,
# поэтому проверяется и величина.
MAX_BODY_BYTES = 20 * 1024 * 1024
MAX_READ_HEADER_SECONDS = 15.0

# CSP обязана покрывать набор TZ §8.3 дословно. `img-src 'self'` без `data:` выбран намеренно:
# QR-код TOTP (TZ §8.2, T-103) обязан отдаваться эндпоинтом панели, а не data: URI.
REQUIRED_CSP: dict[str, str] = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
}

VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")


def _load(path: Path) -> dict[str, Any]:
    """Разобрать compose-файл загрузчиком, который знает теги compose (`tests.paths`).

    Общий он потому, что тот же разбор нужен офлайн-тестам `scripts/prod_compose_check.py`
    (`tests/unit/test_prod_compose_check.py`): два одинаковых загрузчика обязательно разъедутся.
    """
    return load_compose_yaml(path)


def _prod() -> dict[str, Any]:
    return _load(COMPOSE_PROD)


def _base() -> dict[str, Any]:
    return _load(COMPOSE_BASE)


def _prod_services() -> dict[str, Any]:
    services: dict[str, Any] = _prod()["services"]
    return services


def _env_pairs() -> dict[str, str]:
    pairs: dict[str, str] = {}
    for raw in PROD_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        pairs[key] = value
    return pairs


def _interpolated(text: str) -> tuple[set[str], set[str]]:
    """Имена переменных compose: обязательные `${VAR}` и те, у которых есть значение по
    умолчанию (`${VAR:-значение}` — по определению могут отсутствовать в env-файле)."""
    required: set[str] = set()
    defaulted: set[str] = set()
    for match in VAR_PATTERN.finditer(text):
        (defaulted if ":-" in match.group(0) else required).add(match.group(1))
    return required, defaulted


def _resolved(value: str, env: dict[str, str]) -> str:
    """Подставить значения из `deploy/tbot.prod.env` так, как это сделает compose."""
    return VAR_PATTERN.sub(lambda match: env.get(match.group(1), f"<{match.group(1)}>"), value)


def _mib(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)([mg]?)", value.strip())
    assert match, f"непонятное значение ограничения памяти: {value!r}"
    amount, unit = int(match.group(1)), match.group(2)
    return amount * {"": 1, "m": 1, "g": 1024}[unit]


def _network_names(spec: dict[str, Any]) -> list[str]:
    """Имена сетей сервиса: compose допускает и список, и отображение."""
    listed = spec.get("networks", [])
    if isinstance(listed, dict):
        return list(listed)
    return [entry for entry in listed if isinstance(entry, str)]


def _merged_networks(service: str) -> list[str]:
    """Сети сервиса после слияния файлов: compose объединяет списки по имени, а не заменяет."""
    merged: list[str] = []
    for source in (_base(), _prod()):
        spec = source["services"].get(service)
        if not isinstance(spec, dict):
            continue
        for name in _network_names(spec):
            if name not in merged:
                merged.append(name)
    return merged


def _network_specs() -> dict[str, dict[str, Any]]:
    """Top-level `networks` обоих файлов одним отображением: значения overlay важнее базовых."""
    merged: dict[str, dict[str, Any]] = {}
    for source in (_base(), _prod()):
        for name, spec in source.get("networks", {}).items():
            merged[name] = spec if isinstance(spec, dict) else {}
    return merged


def _egress_services() -> set[str]:
    """Сервисы, у которых есть сеть без `internal: true`, то есть путь наружу."""
    external = {name for name, spec in _network_specs().items() if spec.get("internal") is not True}
    all_services = set(_base()["services"]) | set(_prod()["services"])
    return {service for service in all_services if external & set(_merged_networks(service))}


def _caddy_scopes() -> list[tuple[int, tuple[str, ...], str]]:
    """Для каждой строки Caddyfile: (номер, цепочка открытых блоков, код без комментария).

    Разбор намеренно простой: блок открывается строкой, оканчивающейся `{`, и закрывается
    строкой, состоящей из `}`. Плейсхолдеры вида `{scheme}` строку не закрывают — они не
    являются одиночной `}`. Структурная целостность такого разбора проверяется отдельным
    тестом, иначе проверки ниже видели бы «правильную» структуру не в том месте.
    """
    stack: list[str] = []
    rows: list[tuple[int, tuple[str, ...], str]] = []
    for number, raw in enumerate(CADDYFILE.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        rows.append((number, tuple(stack), line))
        if not line:
            continue
        if line == "}":
            if stack:
                stack.pop()
        elif line.endswith("{"):
            head = line[:-1].strip().split()
            stack.append(head[0] if head else "")
    return rows


def _caddy_fields(scope: str) -> dict[str, str]:
    """Строки вида `Поле значение`, лежащие непосредственно в блоке `<scope>`."""
    collected: dict[str, str] = {}
    for _, scopes, line in _caddy_scopes():
        if not line or scopes[-1:] != (scope,):
            continue
        field, _, value = line.partition(" ")
        collected[field] = value.strip().strip('"')
    return collected


def _size_bytes(value: str) -> int:
    """Размер в форме, которую понимает go-humanize: `10MB`, `10485760`, `512KB`."""
    match = re.fullmatch(r"([0-9]+)\s*([KMGT]?B)?", value.strip(), re.IGNORECASE)
    assert match, f"непонятное значение размера: {value!r}"
    factors = {"": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}
    return int(match.group(1)) * factors.get((match.group(2) or "").upper(), 1)


def _duration_seconds(value: str) -> float:
    """Тайм-аут в секундах: `10s`, `250ms`, `2m` (формы go-duration, которые принимает Caddy)."""
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", value.strip())
    assert match, f"непонятное значение тайм-аута: {value!r}"
    return float(match.group(1)) * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]


def _caddy_directive_lines(directive: str) -> list[tuple[int, tuple[str, ...], str]]:
    """Строки, в которых `directive` стоит первым словом (со своей цепочкой блоков)."""
    return [
        (number, scopes, line)
        for number, scopes, line in _caddy_scopes()
        if line.split() and line.split()[0] == directive
    ]


def _split_csp(value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for chunk in value.split(";"):
        stripped = chunk.strip()
        if not stripped:
            continue
        name, _, sources = stripped.partition(" ")
        directives[name] = sources.strip()
    return directives


def test_боевой_разбор_вообще_не_содержит_локальной_сборки() -> None:
    """Ни `build`, ни «отключённый» `build`: в паре compose.yaml + compose.prod.yaml его нет.

    Первый прогон job'а `prod-config` (2026-11-20) опроверг допущение, что `build: !reset null`
    в overlay отключает сборку: после слияния в `config --format json` у web/engine/tgbot/jobs/
    migrate остались `context` (каталог проекта) и `dockerfile` из базового файла — тег не
    сбросил отображение. Пока `build` в модели есть, `up -d` с отсутствующим локально образом
    соберёт его прямо на площадке: на 2 vCPU это остановит остальное, а связь «запустили ровно
    то, что собрали в CI» (TZ §14.6, `docs/runbook/ghcr-pull.md §1`) потеряется молча — compose
    не считает это ошибкой. Поэтому `build` переехал в dev-дополнение: полагаться на семантику
    тегов слияния больше не нужно, а `no_local_build` в `scripts/prod_compose_check.py` смотрит
    на разобранную модель.
    """
    for name, spec in _base()["services"].items():
        assert "build" not in spec, (
            f"{name}: сборка объявлена в базовом файле — боевой разбор унаследует её, даже "
            "если overlay попытается её сбросить"
        )
    for name, spec in _prod_services().items():
        assert "build" not in spec, f"{name}: сборка объявлена в боевом overlay"
    override = _load(COMPOSE_OVERRIDE)["services"]
    built = {
        name for name, spec in override.items() if isinstance(spec, dict) and spec.get("build")
    }
    assert built == {*APP_SERVICES, ONE_SHOT}, (
        f"сборки объявлены не там, где ожидается: {sorted(built)} — dev-стенд нечем собрать, "
        "или сборка утекла в боевой разбор"
    )


def test_образы_боевого_состава_зафиксированы_по_digest() -> None:
    """Каждый образ — `имя@sha256:<64 hex>`; тег (`main`, `16.4`) — перемещаемая метка (TZ §14.6)."""
    env = _env_pairs()
    services = _prod_services()
    for name in PROD_SERVICES:
        image = _resolved(str(services[name]["image"]), env)
        assert re.fullmatch(r"[a-z0-9.:/_@-]+@sha256:[0-9a-f]{64}", image), (
            f"{name}: образ {image!r} не зафиксирован digest'ом — переменная не определена "
            "в deploy/tbot.prod.env или образ задан тегом"
        )
    # Миграция использует образ web: тот же набор слоёв, другая команда.
    assert services[ONE_SHOT]["image"] == services["web"]["image"]


def test_переменные_из_env_файла_и_overlay_не_разъезжаются() -> None:
    """Каждая `${VAR}` из overlay описана в `tbot.prod.env`, и каждый ключ файла используется.

    Неиспользуемый ключ — это тишина: `TBOT_POSTGRES_DIGEST` уже лежал в env-файле, тогда как
    overlay не перекрывал базовое `image: postgres:16.4`, и база в бою тянулась бы по тегу.
    """
    used, defaulted = _interpolated(COMPOSE_PROD.read_text(encoding="utf-8"))
    declared = set(_env_pairs())
    assert used <= declared, f"в deploy/tbot.prod.env нет переменных: {sorted(used - declared)}"
    assert (
        declared <= used | defaulted
    ), f"в deploy/tbot.prod.env есть неиспользуемые ключи: {sorted(declared - used - defaulted)}"
    # Переменные со значением по умолчанию не обязаны быть в env-файле, но не должны и
    # «прятаться» в git с боевым значением — это проверяет отдельный тест про контур.
    assert defaulted, "значения по умолчанию в overlay должны быть описаны явно"


def test_digest_в_env_файле_имеют_форму_и_не_похожи_на_секреты() -> None:
    for key, value in _env_pairs().items():
        assert re.fullmatch(r"[A-Z0-9_]+", key), f"ключ {key!r} не выглядит константой состава"
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", value), f"{key}: значение {value!r} не digest"
    # «Быстрый откат» возможен, только если набор digest лежит в истории git (ADR-002): файл не
    # должен содержать ничего, похожего на учётные данные (TZ §14.3, job `secret-scan`).
    suspicious = re.compile(r"(token|password|secret|apikey)", re.IGNORECASE)
    offenders = [key for key in _env_pairs() if suspicious.search(key)]
    assert not offenders, f"в deploy/tbot.prod.env появились ключи, похожие на секреты: {offenders}"


def test_наружу_публикуется_только_80_и_443_caddy() -> None:
    services = _prod_services()
    assert {str(item) for item in services[PROXY].get("ports", [])} == ALLOWED_PUBLIC_PORTS
    for name, spec in services.items():
        if name == PROXY:
            continue
        assert "ports" not in spec, f"{name}: публикация порта в боевом составе запрещена"
    for name, spec in _base()["services"].items():
        assert "ports" not in spec, f"{name}: порты публикуются только в dev-дополнении"


def test_внутренние_порты_не_появляются_в_боевом_составе() -> None:
    raw = COMPOSE_PROD.read_text(encoding="utf-8")
    for port in NEVER_PUBLISHED:
        assert (
            f"{port}:" not in raw
        ), f"в боевом составе появляется публикация внутреннего порта {port}"


def test_боевой_overlay_не_расширяет_разрешённые_поля_сервисов() -> None:
    for name, spec in _prod_services().items():
        if name == PROXY:
            continue  # новый сервис: его требования проверяются отдельными тестами
        extra = set(spec) - ALLOWED_OVERLAY_KEYS[name]
        assert not extra, f"{name}: в overlay появились незащищённые поля: {sorted(extra)}"
        env_keys = set(spec.get("environment") or {})
        assert env_keys <= ALLOWED_OVERLAY_ENV_KEYS, (
            f"{name}: через overlay задаются переменные "
            f"{sorted(env_keys - ALLOWED_OVERLAY_ENV_KEYS)}"
        )


def test_боевой_контур_включается_явным_решением_а_не_значением_из_git() -> None:
    """Состав поднимается в контуре `sandbox`, если оператор не переопределил его при деплое.

    `Settings.contour` по умолчанию `sandbox`, а `production` без
    `TBOT_CONFIRM_PRODUCTION=true` не стартует вообще (TZ §2.4). Значения передаются при
    деплое, а не прописаны в репозитории: иначе «подтверждение боя» стало бы строкой в истории
    git, а охрана из конфигурации перестала бы что-либо означать.
    """
    env = _env_pairs()
    assert "TBOT_CONTOUR" not in env, "контур нельзя фиксировать в git — это решение оператора"
    assert "TBOT_CONFIRM_PRODUCTION" not in env, "то же касается явного подтверждения боя"
    for name in APP_SERVICES:
        environment = _prod_services()[name].get("environment") or {}
        assert environment["TBOT_CONTOUR"] == "${TBOT_CONTOUR:-sandbox}"
        assert environment["TBOT_CONFIRM_PRODUCTION"] == "${TBOT_CONFIRM_PRODUCTION:-false}"


def test_секреты_боевого_состава_читаются_из_каталога_площадки() -> None:
    """Имена секретов те же, что в базовом файле, а пути — только файловые и только из TZ §14.3.

    Проверка держит два свойства сразу: overlay не меняет состав секретов (иначе приложение
    перестал бы видеть нужный файл) и не переводит их в переменные окружения — красное правило
    TZ §8.4 требует, чтобы значение не попадало в `ps aux` и в argv.

    Файл ключей (`kek_file`) — разрешённое исключение по каталогу, но не по форме: он тоже
    читается файлом, тоже задаётся абсолютным путём и тоже не может собираться из переменной
    окружения. Поэтому исключение перечислено именем, а не «своим префиксом»: закрытый перечень
    не дадёт появиться третьему варианту молча.
    """
    base_secrets: dict[str, Any] = _base().get("secrets", {})
    prod_secrets: dict[str, Any] = _prod().get("secrets", {})
    assert set(prod_secrets) == set(base_secrets), "состав секретов в overlay разошёлся с базовым"
    ожидаемые = set(PROD_SECRET_FILES) | {KEK_SECRET}
    assert (
        set(prod_secrets) == ожидаемые
    ), f"ожидались секреты {sorted(ожидаемые)}, найдено {sorted(prod_secrets)}"
    for name, spec in prod_secrets.items():
        source = str(spec.get("file", ""))
        if name == KEK_SECRET:
            assert (
                source == KEK_PATH
            ), f"секрет {name}: путь {source!r} не совпадает с TZ §8.4 ({KEK_PATH})"
            assert not source.startswith(
                f"{SECRETS_ROOT}/"
            ), f"файл ключей нельзя переносить в каталог секретов: права на нём ставит не {SECRETS_ROOT}"
        else:
            assert (
                source == f"{SECRETS_ROOT}/{PROD_SECRET_FILES[name]}"
            ), f"секрет {name}: путь {source!r} не совпадает с каталогом площадки и runbook'ом"
        assert "${" not in source, f"секрет {name}: путь собран из переменной окружения"
    for name, spec in base_secrets.items():
        assert str(spec.get("file", "")).startswith(
            "./secrets/"
        ), f"{name}: базовый файл обязан оставаться на dev-каталоге — боевые пути только в overlay"


def test_путь_файла_ключей_в_составе_совпадает_с_путём_приложения() -> None:
    """`Settings.kek_file` и `secrets.kek_file.file` в боевом составе — один и тот же путь.

    Расхождение выглядит как «процесс не может открыть файл ключей» уже на площадке: хозяйский
    инструмент (`deploy/vps/keys_setup.py`) пишет по умолчанию в путь из TZ §8.4, приложение
    читает путь из своей настройки, а compose монтирует свой. Если значения разъедутся, зелёный
    `--check` хозяйской диагностики будет соседствовать с красным запуском контейнера.
    """
    kek_spec = _prod()["secrets"][KEK_SECRET]
    путь_compose = str(kek_spec["file"])
    # `as_posix()` обязателен: на dev-машине Windows это тот же путь, но с обратными слэшами,
    # и сравнение строк давало бы ложный отказ ровно на той платформе, где тест запускается.
    путь_приложения = Path(Settings.model_fields["kek_file"].default).as_posix()
    assert путь_compose == KEK_PATH == путь_приложения, (
        f"путь файла ключей разошёлся: compose {путь_compose!r}, приложение {путь_приложения!r}, "
        f"ожидалось {KEK_PATH!r}"
    )


def test_токен_реестра_образов_не_становится_секретом_compose() -> None:
    """/etc/tbot/secrets/ghcr_token нужен `docker login` на хосте, а не контейнеру (runbook §3).

    Смонтировать токен реестра в контейнер — значит отдать его процессу, который к реестру не
    обращается: pull в бою делает хост, а не сервис.
    """
    assert "ghcr_token" not in COMPOSE_PROD.read_text(
        encoding="utf-8"
    ), "токен GHCR не должен попадать в compose-секреты"


def test_лимиты_не_выше_чем_в_ТЗ_и_вписываются_в_площадку() -> None:
    """OQ-11 («без расширения»): сумма потолков памяти обязана оставлять память ядру."""
    services = _prod_services()
    total_mem = 0
    total_cpu = 0.0
    for name in (*APP_SERVICES, "postgres", PROXY):
        spec = services[name]
        mem_value = str(spec.get("mem_limit", ""))
        assert mem_value, f"у {name} нет mem_limit: без потолка OOM-killer выберет самое крупное"
        mem = _mib(mem_value)
        assert (
            mem <= TZ_MEM_MIB[name]
        ), f"{name}: mem_limit {mem_value} выше потолка TZ §14.6 ({TZ_MEM_MIB[name]} МиБ)"
        cpus = float(spec.get("cpus", 0))
        assert 0 < cpus <= TZ_CPUS[name], f"{name}: cpus {cpus} вне диапазона TZ §14.6"
        total_mem += mem
        total_cpu += cpus
    assert total_mem <= HOST_MEM_CEILING_MIB, (
        f"сумма потолков памяти {total_mem} МиБ превышает бюджет площадки "
        f"({HOST_MEM_CEILING_MIB} МиБ при ~3892 МиБ на хосте)"
    )
    assert total_cpu <= HOST_VCPU * CPU_OVERSUBSCRIPTION, (
        f"сумма потолков CPU {total_cpu} больше {HOST_VCPU * CPU_OVERSUBSCRIPTION} vCPU: "
        "на 2 vCPU это уже не ограничение, а очередь"
    )
    assert _mib(str(services[ONE_SHOT]["mem_limit"])), "у разового migrate тоже есть потолок"


def test_caddy_получает_ровно_net_bind_service() -> None:
    """Единственное исключение по capability в боевом составе — привилегированный диапазон.

    Официальный образ Caddy работает от root, поэтому без `NET_BIND_SERVICE` ему недоступны
    80/443; всё остальное обязано остаться сброшенным, иначе исключение превратится в
    «обычный» привилегированный контейнер. Отклонение от абзаца TZ §8.5 «не-root в контейнерах»
    обосновано комментарием в `deploy/compose.prod.yaml`.
    """
    spec = _prod_services()[PROXY]
    assert spec.get("cap_drop") == ["ALL"]
    granted = set(spec.get("cap_add", []))
    assert granted == CADDY_CAPS, f"у прокси capability {sorted(granted)}"
    assert "no-new-privileges:true" in spec.get("security_opt", [])
    assert spec.get("read_only") is True, "read-only rootfs прокси сохраняется"
    assert spec.get("pids_limit"), "у прокси нет ограничения на число процессов"
    assert spec.get("restart") == "always", "TZ §14.6: caddy — restart always"
    # restart для всего остального: база и прикладные процессы получают его из общего якоря.
    # `unless-stopped` (значение базового файла) в бою недостаточно: после рестарта Docker
    # панель и ядро обязаны подняться сами, без участия человека (TZ §12.1).
    assert (
        _prod()["x-prod-app"].get("restart") == "always"
    ), "общий якорь прикладных процессов потерял `restart: always`"
    assert _prod_services()["postgres"].get("restart") == "always", "база обязана перезапускаться"
    assert str(spec.get("mem_limit")) == CADDY_MEM_LIMIT
    assert float(spec.get("cpus", 0)) == CADDY_CPUS, "TZ §14.6: caddy — CPU 0.25"
    logging_spec = spec.get("logging", {})
    options = logging_spec.get("options", {})
    assert str(logging_spec.get("driver")) == "json-file"
    assert str(options.get("max-size")) == "50m", "размер файла лога прокси — TZ §14.6"
    assert (
        int(options.get("max-file", 0)) == 10
    ), "ротация логов контейнера — TZ §14.6: иначе json-логи занимают диск раньше данных"


def test_caddy_не_теряет_сертификат_между_пересозданиями_контейнера() -> None:
    """Без именованных томов каждый деплой выпускал бы новый сертификат.

    Лимит Let's Encrypt — 5 выпусков в неделю на домен: превышение означает не предупреждение,
    а отказ выпускать сертификат, то есть панель лежит на TLS-ошибке. TZ §14.6 прямо требует
    `volumes: certs`.
    """
    spec = _prod_services()[PROXY]
    mounts = {str(item) for item in spec.get("volumes", [])}
    assert {
        "caddy_data:/data",
        "caddy_config:/config",
    } <= mounts, f"томы ACME не смонтированы: {sorted(mounts)}"
    assert {"caddy_data", "caddy_config"} <= set(
        _prod().get("volumes", {})
    ), "томы не объявлены на верхнем уровне compose"
    tmpfs_paths = [str(item).split(":", 1)[0] for item in spec.get("tmpfs", [])]
    assert "/data" not in tmpfs_paths, "каталог ACME нельзя выносить на tmpfs: он ephemeral"


def test_хостовый_Caddyfile_монтируется_по_тому_же_путём_что_проверяют_command_и_healthcheck() -> (
    None
):
    """Тот же класс дефекта, что «восьмая причина» compose-smoke (HANDOFF §1.2, §1.4).

    Относительный путь монтирования разрешается относительно каталога compose-файла, а
    несуществующий хостовый путь в короткой форме Docker молча заменяется пустым каталогом:
    контейнер падал бы на разборе конфигурации, а не на пропущенном монтировании. Проверяются
    три вещи: файл существует, смонтирован read-only в ту же цель, что называют `command` и
    healthcheck, и все три пути совпадают.
    """
    spec = _prod_services()[PROXY]
    bind_mounts = [str(item) for item in spec.get("volumes", []) if str(item).startswith("./")]
    assert bind_mounts, "Caddyfile не смонтирован из репозитория"
    source, _, rest = bind_mounts[0].partition(":")
    target, _, mode = rest.rpartition(":")
    assert (DEPLOY / source).is_file(), f"монтируемого файла нет: {DEPLOY / source}"
    assert mode == "ro", f"Caddyfile смонтирован не read-only: {bind_mounts[0]!r}"
    command_paths = [str(part) for part in spec["command"] if str(part).endswith("/Caddyfile")]
    assert command_paths == [
        target
    ], f"command указывает на {command_paths}, а смонтировано в {target!r}"
    health_paths = [
        str(item) for item in spec["healthcheck"]["test"] if str(item).endswith("/Caddyfile")
    ]
    assert health_paths == [target], (
        f"healthcheck валидирует {health_paths}, а контейнер работает с {target!r}: "
        "проверка готовности касается не той конфигурации"
    )


def test_egress_получают_только_разрешённые_сервисы() -> None:
    """Список «у кого есть путь наружу» закрыт: случайная добавка валит тест.

    Caddy появляется в нём потому, что ACME обязан ходить в каталог Let's Encrypt (входящего
    HTTP-01 вызова недостаточно), а `web` — потому, что прокси обязан достучаться до него как до
    upstream. Отдельно зафиксировано отклонение от TZ §8.5: у `jobs` пути наружу сейчас нет
    (базовый compose подключает его только к `tbot-backend`), хотя §8.5 упоминает исходящие
    соединения этого процесса — расхождение закрывается вместе с бэктест-воркером на проде
    (T-031/T-711), и тогда список обновляют осознанно.
    """
    assert _egress_services() == {"web", "engine", "tgbot", PROXY}
    specs = _network_specs()
    assert (
        specs.get("tbot-public", {}).get("internal") is not True
    ), "сеть прокси обязана давать исходящие: без них ACME не выпускает сертификат"
    for name in ("tbot-backend", "tbot-edge"):
        assert specs[name].get("internal") is True, f"базовая сеть {name} обязана быть internal"
    assert (
        "tbot-public" not in _base()["networks"]
    ), "сеть с egress обязана появляться только в боевом overlay: в dev-стенде её нет"
    for service in ("postgres", ONE_SHOT, "jobs"):
        assert _merged_networks(service) == [
            "tbot-backend"
        ], f"{service}: состав сетей разошёлся, изоляция потеряна"


def test_engine_ждут_столько_сколько_требует_ТЗ() -> None:
    """TZ §14.6: `stop_grace_period 60s` для engine — отписка от потока и запись состояния."""
    assert str(_prod_services()["engine"].get("stop_grace_period")) == "60s"


def test_Caddyfile_держит_заголовки_из_ТЗ_8_3() -> None:
    fields = _caddy_fields("header")
    assert fields["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains"
    assert fields["X-Content-Type-Options"] == "nosniff"
    assert fields["X-Frame-Options"] == "DENY"
    assert (
        fields["Referrer-Policy"] == "same-origin"
    ), "TZ §8.3 называет это значение: другое требует правки контракта, а не файла"
    assert "Permissions-Policy" in fields, "TZ §8.3: Permissions-Policy минимум"
    assert fields.get("-Server") == "", "служебный заголовок сервера не снимается"
    assert fields["Cache-Control"] == "no-store", "панель приватная: кэш на прокси недопустим"


def test_CSP_покрывает_ТЗ_и_не_содержит_внешних_источников() -> None:
    """Ни `unsafe-*`, ни чужих хостов: TZ §8.3 запрещает внешние CDN, шрифты и JS — свои."""
    value = _caddy_fields("header")["Content-Security-Policy"]
    directives = _split_csp(value)
    for name, sources in REQUIRED_CSP.items():
        assert (
            directives.get(name) == sources
        ), f"CSP: {name} = {directives.get(name)!r}, ждалось {sources!r}"
    for weakening in ("unsafe-inline", "unsafe-eval"):
        assert weakening not in value, f"CSP ослаблена: в политике есть {weakening}"
    for name, sources in directives.items():
        for source in sources.split():
            assert not re.search(
                r"[a-z0-9-]+\.[a-z]{2,}", source
            ), f"CSP: в {name} появился внешний источник {source!r}"
    assert directives.get("img-src") == "'self'", (
        "img-src обязан быть 'self': data: URI — отклонение от CSP из TZ §8.3, "
        "а QR-код TOTP обязан отдаваться эндпоинтом панели (TZ §8.2)"
    )


def test_Caddyfile_фиксирует_TLS_и_не_отключает_выпуск_сертификата() -> None:
    """ACME обязан остаться включённым: сертификат выпускает Caddy (TZ §8.3, §14.6).

    `protocols` — поддиректива блока `tls` (версии TLS), а ещё — блока `servers` (версии HTTP).
    Отдельной строкой сайта она не разбирается, и обнаруживать это пришлось бы при запуске на
    площадке. Проверка структурная: каждой строке `protocols …` обязан предшествовать один из
    двух блоков, а внутри `tls` обязан быть диапазон 1.2/1.3.
    """
    lines = _caddy_directive_lines("protocols")
    assert lines, "версии TLS не зафиксированы: дефолты Caddy меняются между минорными релизами"
    for number, chain, line in lines:
        assert chain[-1:] in (
            ("tls",),
            ("servers",),
        ), f"строка {number}: `protocols` вне блоков `tls` и `servers`: {line!r}"
    в_блоке_tls = [line for _, chain, line in lines if chain[-1:] == ("tls",)]
    assert в_блоке_tls, "блок `tls` с версиями TLS исчез из Caddyfile"
    assert any(
        "tls1.2" in line and "tls1.3" in line for line in в_блоке_tls
    ), "TZ §2: диапазон TLS 1.2/1.3 обязан быть зафиксирован явно"
    raw = CADDYFILE.read_text(encoding="utf-8")
    for forbidden in ("auto_https off", "tls internal", "acme_ca ", "dns_challenge"):
        assert forbidden not in raw, f"Caddyfile содержит {forbidden!r}: это ослабляет ACME-выпуск"
    assert not re.search(r"^\s*email\s+\S+", raw, re.MULTILINE), (
        "внутри блока сайта директивы `email` нет: почта задаётся глобальной опцией `email` "
        "или строкой `tls <ящик>` — иначе раскомментированная подсказка уронит запуск"
    )


def test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443() -> None:
    """Caddyfile и правила `ufw` обязаны двигаться одним шагом: `h3` ↔ `allow 443/udp`.

    Причина — замер, а не догадка. Локально на v2.11.9: без явного `protocols` Caddy сам навешивает
    `Alt-Svc: h3=":443"`, и первый визит браузера уходит в QUIC; если udp/443 не проходит, часть
    клиентов получает тайм-аут вместо рабочего HTTP/2. Обратный риск не меньше: открыть `443/udp` и
    забыть включить `h3` — значит держать порт открытым без пользы.

    Поэтому правило проверяется как пара. Проход UDP/443 через облачную группу безопасности и `ufw`
    подтверждён замером на площадке 2026-11-20: 20 датаграмм с dev-машины подняли счётчик цепочки
    `ufw-user-input` (правило `udp dpt:443`) ровно до 20 пакетов / 900 байт —
    `docs/acceptance/tls-edge.md §3.6`. Снять udp-правило можно только вместе с `h3`.
    """
    строки = [
        line for _, chain, line in _caddy_directive_lines("protocols") if chain[-1:] == ("servers",)
    ]
    assert (
        len(строки) == 1
    ), f"версии HTTP обязаны быть заданы один раз в глобальном `servers`: {строки}"
    assert строки[0].split() == [
        "protocols",
        "h1",
        "h2",
        "h3",
    ], f"в `servers` ожидался набор `protocols h1 h2 h3`, получено {строки[0]!r}"

    правила = (VPS / "ufw.rules").read_text(encoding="utf-8")
    assert "allow 443/udp" in правила, (
        "в `deploy/vps/ufw.rules` нет `allow 443/udp`, но Caddyfile уже объявляет h3: браузер "
        "получит Alt-Svc на транспорт, который файрвол не пропускает"
    )
    assert "allow 443/tcp" in правила, "443/tcp обязан остаться: это HTTPS-панель"

    публикация = {str(item) for item in _prod_services()[PROXY].get("ports", [])}
    assert "443:443/udp" in публикация, (
        "одного `443:443` мало: Docker публикует только tcp, и периметр отдаёт "
        '`Alt-Svc: h3=":443"`, не слушая UDP/443 (замер на площадке 2026-11-20: ICMP port '
        "unreachable на UDP/443 при открытом ufw-правиле)"
    )


def test_журнал_прокси_не_выписывает_токены_из_query_и_api_ключ() -> None:
    """TZ §8.4 «красное правило»: в логе нет ни сессий, ни токенов, ни одноразовых ссылок.

    Замер на v2.11.9 (probe на копии Caddyfile): Caddy сам прячет Cookie, Set-Cookie,
    Authorization и Proxy-Authorization (пишет REDACTED), но `?token=…` в `uri` и заголовок
    `X-Api-Key` выписывает открытым текстом. Одноразовая ссылка на отчёт (TZ §8.3, TTL 5 минут)
    в журнале — это доступ к чужим данным, записанный в файл на диске. Поэтому фильтр журнала
    обязателен, а опция, которая возвращает чувствительные заголовки в лог, запрещена.
    """
    rows = [(chain, line) for _, chain, line in _caddy_scopes() if line]
    assert any(
        chain[-1:] == ("log",) and line.startswith("format filter") for chain, line in rows
    ), "у журнала доступа нет фильтра полей: секреты из query попадут в файл"
    в_filter = [line for chain, line in rows if chain[-2:] == ("log", "format")]
    assert any(
        line.startswith("wrap json") for line in в_filter
    ), "фильтр журнала обязан явно оборачивать json-энкодер: иначе формат зависит от терминала"
    assert any(
        line.startswith("request>headers>X-Api-Key replace") for line in в_filter
    ), "X-Api-Key не входит в список «чувствительных» заголовков Caddy и обязан заменяться"
    query = [line for chain, line in rows if chain[-3:] == ("log", "format", "request>uri")]
    for ключ in ("token", "key", "sig"):
        assert any(
            f"replace {ключ} REDACTED" in line for line in query
        ), f"query-ключ {ключ!r} не скрыт: ссылка вида ?{ключ}=… попадёт в журнал открытым текстом"
    код = "\n".join(line for _, _, line in _caddy_scopes() if line)
    assert "log_credentials" not in код, (
        "`log_credentials` возвращает в журнал Cookie/Set-Cookie/Authorization — это красное "
        "правило TZ §8.4"
    )
    assert any(
        chain[-1:] == ("log",) and line.startswith("output stderr") for chain, line in rows
    ), "журнал обязан идти в stderr контейнера (его собирает json-file из compose)"


def test_Caddyfile_проксирует_на_порт_который_слушает_web() -> None:
    """upstream обязан совпадать с сервисом compose и с дефолтом `Settings.web_port`."""
    raw = CADDYFILE.read_text(encoding="utf-8")
    target = re.search(r"reverse_proxy\s+(?:@\S+\s+)?([A-Za-z0-9_.-]+):([0-9]+)", raw)
    assert target, "в Caddyfile нет reverse_proxy с явным адресом и портом"
    service, port = target.group(1), int(target.group(2))
    assert service in _prod_services(), f"upstream {service!r} не является сервисом состава"
    default_port = int(Settings.model_fields["web_port"].default)
    assert port == default_port, f"прокси ходит на {port}, процесс web слушает {default_port}"
    compose_port = str(_base()["services"][service].get("environment", {}).get("TBOT_WEB_PORT", ""))
    assert compose_port in (
        "",
        str(port),
    ), f"compose задаёт TBOT_WEB_PORT={compose_port}, а прокси ходит на {port}"


def test_Caddyfile_ограничивает_тело_запроса_методы_и_не_отдаёт_метрики() -> None:
    """Форма `request_body { max_size … }` актуальна с v2.10: позиционный аргумент не используется."""
    raw = CADDYFILE.read_text(encoding="utf-8")
    in_body_block = [line for _, chain, line in _caddy_scopes() if chain[-1:] == ("request_body",)]
    assert any(
        line.startswith("max_size") for line in in_body_block
    ), f"в блоке request_body нет max_size: {in_body_block}"
    assert re.search(
        r"^\s*@forbidden\s+method\b.*\bTRACE\b", raw, re.MULTILINE
    ), "TRACE не заблокирован (TZ §8.3: разведочные методы не должны проходить к приложению)"
    assert re.search(r"^\s*respond 405\s*$", raw, re.MULTILINE), "для запрещённых методов нет 405"
    assert re.search(
        r"handle\s+/metrics\s*\{", raw
    ), "/metrics обязан отсекаться на прокси: он отдаёт версию сборки и счётчики (TZ §12.2)"
    assert re.search(r"^\s*max_header_size\s+\S+", raw, re.MULTILINE), "нет предела заголовков"
    body_values = [
        line.split(None, 1)[1].strip()
        for line in in_body_block
        if line.startswith("max_size") and len(line.split(None, 1)) == 2
    ]
    assert body_values, "в блоке request_body нет max_size"
    largest = max(_size_bytes(value) for value in body_values)
    assert largest <= MAX_BODY_BYTES, (
        f"предел тела запроса {largest} Б больше {MAX_BODY_BYTES} Б: форма импорта обязана "
        "быть небольшой, а лимит в 500 МБ формально «ограничивает», но защиту не даёт"
    )
    assert re.search(r"^\s*max_header_size\s+\S+", raw, re.MULTILINE), "нет предела заголовков"
    header_timeouts = [
        line.split(None, 1)[1].strip()
        for _, chain, line in _caddy_scopes()
        if chain[-1:] == ("timeouts",) and line.startswith("read_header")
    ]
    assert (
        header_timeouts
    ), "нет тайм-аута чтения заголовков: медленные «шляпные» соединения держат воркера"
    for value in header_timeouts:
        seconds = _duration_seconds(value)
        assert (
            0 < seconds <= MAX_READ_HEADER_SECONDS
        ), f"read_header {value}: при {seconds} с лимит перестаёт быть защитой"


def test_в_Caddyfile_один_сайт_это_боевой_домен() -> None:
    """Отдельный `:80`-сайт не нужен: редирект и ACME-вызовы строит сам Caddy."""
    sites = [
        line[:-1].strip()
        for _, chain, line in _caddy_scopes()
        if not chain and line.endswith("{") and line.strip() != "{"
    ]
    assert sites == ["tbot.rusiksoft.ru"], f"в Caddyfile неожиданные сайты: {sites}"


def test_Caddyfile_разобран_без_искажения_структуры() -> None:
    """Проверки выше опираются на разбор по строкам: `{`/`}` внутри комментариев его ломают.

    Дополнительно проверяется, что все блоки закрыты: незакрытый блок сдвигает цепочки блоков
    у всех последующих строк, и тесты видели бы «правильную» структуру не в том месте.
    """
    with_braces_in_comments = [
        number
        for number, raw in enumerate(CADDYFILE.read_text(encoding="utf-8").splitlines(), start=1)
        if "#" in raw and any(char in raw.split("#", 1)[1] for char in "{}")
    ]
    assert (
        not with_braces_in_comments
    ), f"комментарии с фигурными скобками ломают разбор строк: {with_braces_in_comments}"
    openers = sum(
        1 for _, _, line in _caddy_scopes() if line.endswith("{") and not line.endswith("}")
    )
    closers = sum(1 for _, _, line in _caddy_scopes() if line == "}")
    assert openers == closers, f"блоки не сбалансированы: открыто {openers}, закрыто {closers}"


def test_в_README_описан_тот_же_прод_состав_что_и_в_файлах() -> None:
    """`deploy/README.md` — то, что читает оператор, сидя на площадке.

    Расхождение с реальными файлами означает «команда из README не работает»: прод-состав нельзя
    поднять без env-файла дайджестов, а проверка состава живёт в job `prod-config` и скрипте.
    Отдельно держится упоминание фильтра журнала и набора `protocols h1 h2 h3`: обе правки дала
    поведенческая проба Caddy (docs/acceptance/tls-edge.md §3–§4). Список имён файлов секретов и
    путь к runbook деплоя — тоже часть контракта: оператор на площадке обязан видеть те же имена,
    что читает compose, и скрипт, которым эти имена создаются.
    """
    readme = README.read_text(encoding="utf-8")
    for needle in (
        "compose.prod.yaml",
        "--env-file tbot.prod.env",
        "prod_compose_check.py",
        "prod-config",
        "/etc/tbot/secrets",
        "caddy_data",
        "protocols h1 h2 h3",
        "format filter",
        "stop_grace_period",
        "docs/acceptance/tls-edge.md",
        "secrets-setup.sh",
        "POSTGRES_PASSWORD_FILE",
        "docs/runbook/stand-deploy.md",
        "allow 443/udp",
    ):
        assert needle in readme, f"в deploy/README.md нет {needle!r}"
