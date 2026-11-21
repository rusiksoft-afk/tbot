#!/usr/bin/env python3
"""Проверка **разобранного** боевого состава: вывод `docker compose config` (T-712, T-713).

Статический контракт `tests/integration/test_compose_prod_contract.py` видит то, что написано в
`deploy/compose.prod.yaml`. Этот модуль видит то, что осталось после слияния двух compose-файлов:
правила объединения overlay (списки `networks` и `ports` compose объединяет по имени/уникальному
ключу, а не заменяет целиком) знает только сам compose. Отсюда разделение: YAML-контракт хранит
намерения, этот скрипт — фактический состав, который пойдёт на площадку.

Запуск в CI (`job prod-config`) и на площадке:

    docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \\
      --env-file deploy/tbot.prod.env config --format json \\
      | python3 scripts/prod_compose_check.py

Локально на dev-машине Docker нет, поэтому проверка прогоняется по сохранённому снимку разбора:
`python3 scripts/prod_compose_check.py --model prod-config.json`. Ожидание состава и его
отклонения закреплены офлайн-тестами `tests/unit/test_prod_compose_check.py`.

Правила файла: только стандартная библиотека, `subprocess` не вызывается (состояние читается из
переданного JSON), новых подавлений проверок не появляется (базовый уровень — 14).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

FATAL = "fatal"
WARN = "warn"

MIB = 1024**2

# Потолки «не выше значения ТЗ» — числа из TZ §14.6 («Состав и параметры контейнеров (прод)»).
# Держатся здесь, а не в compose-файле, потому что проверяют разобранный состав: compose может
# унаследовать лимит из якоря или из базового файла, и тогда фактический потолок станет больше
# согласованного.
MEM_CEILING_BYTES: dict[str, int] = {
    "caddy": 128 * MIB,
    "web": 512 * MIB,
    "engine": int(1.5 * 1024 * MIB),
    "tgbot": 256 * MIB,
    "jobs": 3 * 1024 * MIB,
    "postgres": 3 * 1024 * MIB,
}
CPU_CEILING: dict[str, float] = {
    "caddy": 0.25,
    "web": 1.0,
    "engine": 2.0,
    "tgbot": 0.25,
    "jobs": 3.0,
    "postgres": 2.0,
}

# Бюджет площадки: 2 vCPU / 3.8 ГиБ (OQ-11 «без расширения», ADR-001). От 3.8 ГиБ отнимаем
# ~0.8 ГиБ на ядро, dockerd, службу xray-туннеля и fail2ban — остаток и есть потолок суммы
# лимитов постоянного состава. Фактические лимиты `deploy/compose.prod.yaml` (2880 МиБ) под него
# попадают; проверка ловит случай, когда каждый лимит по отдельности разрешён ТЗ, а вместе они
# не влезают — на 3.8 ГиБ машине это гарантированный OOM-killer (TZ §14.9).
HOST_MEM_BUDGET_BYTES = 3 * 1024 * MIB
# Сумма потолков CPU: 2 vCPU при коэффициенте перераспределения 2.0. Правило намеренно мягкое
# (замечание): CPU, в отличие от памяти, перераспределяется планировщиком без гибели процесса.
HOST_VCPU = 2.0
CPU_OVERSUBSCRIPTION = 2.0
HOST_CPU_BUDGET = HOST_VCPU * CPU_OVERSUBSCRIPTION

# Единственный слушатель наружу. Опубликованный Docker-портом порт доступен снаружи независимо
# от `ufw` (правила уходят в FORWARD/nat, `INPUT` не участвует), поэтому именно список публикаций
# и описывает периметр — а не файрвол (`docs/acceptance/prod-firewall.md §5`).
PUBLIC_SERVICE = "caddy"
# Публикации вместе с протоколом. `443/udp` — не украшение: Caddyfile объявляет h1/h2/h3 и отдаёт
# `Alt-Svc: h3=":443"`, файрвол пропускает 443/udp (TZ §8.5, ADR-003), но Docker публикует UDP
# только отдельной строкой с `/udp`. Замер 2026-11-20 на площадке: при публикациях `80:80` и
# `443:443` UDP/443 не слушается вообще, то есть периметр обещает транспорт, которого нет
# (браузер после первого визита уходит в QUIC и получает тайм-аут).
ALLOWED_PUBLICATIONS = {"80:80/tcp", "443:443/tcp", "443:443/udp"}

# Сервисы, которым путь наружу запрещён архитектурно (TZ §8.5: у БД исходящих нет, секреты
# наружу не уходят). Caddy и web обязаны egress иметь: прокси выпускает сертификат ACME, а
# прокси ходит к web как к upstream по имени сервиса.
MUST_HAVE_NO_EGRESS = ("postgres", "migrate", "jobs")
ALLOWED_EXTERNAL_NETWORKS = {"tbot-egress", "tbot-public"}

# Ожидаемый состав секретов по сервисам. Лишний секрет процессу не нужен, но он лежит у него в
# памяти и может попасть в лог при неаккуратном дампе окружения (TZ §8.4 — «красное» правило:
# токен в логах = компрометация).
# `kek_file` — файл ключей TOTP (`ADR-014`): он нужен только `web`, потому что привязку делает
# панель, а расшифровкой секрета привязки больше никто не занимается. `engine`, `jobs` и
# `migrate` ключевой материал не читают, поэтому KEK у них — такая же находка, как токен бота у
# базы: лишний процесс с ключом = лишний путь утечки.
SECRETS_BY_SERVICE: dict[str, set[str]] = {
    "postgres": {"db_password"},
    "migrate": {"db_url"},
    "web": {"db_url", "kek_file"},
    "engine": {"db_url"},
    "jobs": {"db_url"},
    "tgbot": {"tg_bot_token", "tg_socks_password"},
    PUBLIC_SERVICE: set(),
}

# Политика путей файловых секретов: имя секрета → путь на хосте. Это закрытый перечень, а не
# правило «всё из `SECRETS_ROOT`»: файл ключей KEK по TZ §8.4 живёт отдельно, и попытка
# «унифицировать» его, сдвинув в каталог секретов, на самом деле меняет ему права (политику
# каталога держит `secrets-setup.sh`, который умеет писать только строку секрета, а не JSON с
# версиями ключей) и молча отклоняется от §8.4. Точное совпадение пути держит и обратный
# случай: перенос `db_url` в каталог ключей тоже отказ.
SECRETS_ROOT = "/etc/tbot/secrets"
KEYS_FILE = "kek_file"
KEYS_ROOT = "/etc/tbot/keys"
KEK_PATH = f"{KEYS_ROOT}/kek.json"
ALLOWED_SECRET_PATHS: dict[str, str] = {
    "db_password": f"{SECRETS_ROOT}/db_password",
    "db_url": f"{SECRETS_ROOT}/db_url",
    "tg_bot_token": f"{SECRETS_ROOT}/telegram_token",
    "tg_socks_password": f"{SECRETS_ROOT}/telegram_socks_pass",
    KEYS_FILE: KEK_PATH,
}
# Постоянные процессы обязаны перезапускаться сами (TZ §14.6 «restart always»); `migrate` —
# одноразовый запуск командой, ему это не касается.
ALWAYS_ON_SERVICES = ("postgres", "web", "engine", "tgbot", "jobs", PUBLIC_SERVICE)
DIGEST_RE = re.compile(r"[a-z0-9.:/_@-]+@sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class CheckResult:
    """Одна проверка разобранного состава; `severity=fatal` блокирует вывод «готово»."""

    name: str
    ok: bool
    detail: str
    severity: str = FATAL


def load_model(path: Path | None) -> dict[str, Any]:
    """Прочитать вывод `docker compose config --format json` из файла (по умолчанию — из stdin)."""
    text = path.read_text(encoding="utf-8") if path else sys.stdin.read()
    model = json.loads(text)
    if not isinstance(model, dict):
        raise TypeError("ожидалось отображение верхнего уровня вывода compose config")
    return model


def _services(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = model.get("services") or {}
    return {str(name): spec for name, spec in raw.items() if isinstance(spec, dict)}


def _network_names(spec: dict[str, Any]) -> set[str]:
    """Сети сервиса из разобранного состава: compose отдаёт их отображением или списком."""
    listed = spec.get("networks")
    if isinstance(listed, dict):
        return {str(name) for name in listed}
    if isinstance(listed, list):
        names: set[str] = set()
        for item in listed:
            names.add(str(item) if isinstance(item, str) else str(next(iter(item))))
        return names
    return set()


def _external_networks(model: dict[str, Any]) -> set[str]:
    """Сети, которые дают исходящий трафик: `internal` в разобранном составе не выставлен."""
    external: set[str] = set()
    for name, spec in (model.get("networks") or {}).items():
        if isinstance(spec, dict) and not spec.get("internal"):
            external.add(str(name))
    return external


def _secret_names(spec: dict[str, Any]) -> set[str]:
    """Имена секретов сервиса: compose отдаёт их строками или объектами с полем `source`."""
    names: set[str] = set()
    for item in spec.get("secrets") or []:
        if isinstance(item, str):
            names.add(item)
        elif isinstance(item, dict):
            names.add(str(item.get("source") or item.get("target") or ""))
    return {name for name in names if name}


def _publications(spec: dict[str, Any]) -> set[str]:
    """Публикации портов вида «хостовый:контейнерный/протокол» (строка или объект).

    Протокол сохраняется намеренно: `443:443` и `443:443/udp` — это разные слушатели, и
    свести их к одной строке значит перестать замечать отсутствующий HTTP/3.
    """
    result: set[str] = set()
    for item in spec.get("ports") or []:
        if isinstance(item, str):
            pair, _, protocol = item.partition("/")
            result.add(f"{pair}/{protocol or 'tcp'}")
        elif isinstance(item, dict):
            protocol = str(item.get("protocol") or "tcp")
            result.add(f"{item.get('published')}:{item.get('target')}/{protocol}")
    return result


def limit_bytes(value: object) -> int | None:
    """Размер лимита в байтах: compose отдаёт `mem_limit` числом (байты) или строкой (`768m`)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    match = re.fullmatch(r"([0-9]+)([bkmg]?)", str(value).strip(), re.IGNORECASE)
    if not match:
        return None
    factors = {"": 1, "k": 1024, "m": MIB, "g": 1024**3}
    return int(match.group(1)) * factors[match.group(2).lower()]


def _cpus(value: object) -> float | None:
    """Потолок CPU: compose отдаёт число, строку может (`"0.5"`); всё остальное — «лимита нет»."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, int | float | str):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def check_ports(model: dict[str, Any]) -> list[CheckResult]:
    """Наружу смотрит только прокси, и ровно 80/tcp, 443/tcp и 443/udp (T-713, TZ §8.3, §8.5)."""
    services = _services(model)
    actual = _publications(services.get(PUBLIC_SERVICE, {}))
    results = [
        CheckResult(
            "ports_proxy_publication",
            actual == ALLOWED_PUBLICATIONS,
            f"публикации {PUBLIC_SERVICE}: {sorted(actual)}, ожидалось "
            f"{sorted(ALLOWED_PUBLICATIONS)}",
        )
    ]
    leaked = {
        name: sorted(_publications(spec))
        for name, spec in services.items()
        if name != PUBLIC_SERVICE and _publications(spec)
    }
    results.append(
        CheckResult(
            "ports_only_proxy",
            not leaked,
            f"публикации появились у сервисов {leaked}"
            if leaked
            else "кроме прокси наружу не смотрит никто",
        )
    )
    return results


def check_images(model: dict[str, Any]) -> CheckResult:
    """Каждый образ зафиксирован digest'ом (`docs/runbook/ghcr-pull.md §1–2`)."""
    bad: dict[str, str] = {}
    for name, spec in _services(model).items():
        image = str(spec.get("image") or "")
        if not DIGEST_RE.fullmatch(image):
            bad[name] = image or "<пусто>"
    return CheckResult(
        "images_by_digest",
        not bad,
        f"образы без digest: {bad}" if bad else "все образы заданы @sha256:…",
    )


def check_no_build(model: dict[str, Any]) -> CheckResult:
    """В разобранном составе не должно быть ни одного `build` — ни в какой форме.

    Первый прогон job'а `prod-config` (2026-11-20) опроверг допущение, что `build: !reset null`
    в overlay отключает сборку: после слияния compose оставляет `context` (каталог проекта) и
    `dockerfile` из базового файла. Пока `build` в модели есть, `up -d` с отсутствующим локально
    образом соберёт его на площадке (compose не считает это ошибкой), и связь «запустили ровно
    то, что собрали в CI» (TZ §14.6, `docs/runbook/ghcr-pull.md §1`) теряется.
    Поэтому проверяется именно наличие ключа: `build: null` — тоже сигнал, что кто-то
    пытается «отключить» сборку вместо того, чтобы убрать её из боевого разбора.
    """
    built = sorted(name for name, spec in _services(model).items() if "build" in spec)
    return CheckResult(
        "no_local_build",
        not built,
        f"в разобранном составе осталась сборка: {built}"
        if built
        else "сборок нет ни в одной форме: все образы тянутся из реестра",
    )


def check_egress(model: dict[str, Any]) -> list[CheckResult]:
    """Сети с исходящим трафиком: кому нельзя (база, migrate, jobs) и кому обязательно нужно (прокси)."""
    external = _external_networks(model)
    services = _services(model)
    proxy_networks = _network_names(services.get(PUBLIC_SERVICE, {}))
    offenders = {
        name: sorted(_network_names(spec) & external)
        for name, spec in services.items()
        if name in MUST_HAVE_NO_EGRESS and _network_names(spec) & external
    }
    unexpected = external - ALLOWED_EXTERNAL_NETWORKS
    return [
        CheckResult(
            "egress_denied",
            not offenders,
            f"доступ наружу появился у {offenders}"
            if offenders
            else f"без исходящих: {sorted(MUST_HAVE_NO_EGRESS)} "
            f"(сети с egress: {sorted(external)})",
        ),
        CheckResult(
            "proxy_has_egress",
            bool(proxy_networks & external),
            f"у прокси нет сети с исходящим трафиком (сети: {sorted(proxy_networks)}): "
            "ACME не выпустит сертификат"
            if not proxy_networks & external
            else f"прокси в сетях с egress: {sorted(proxy_networks & external)}",
        ),
        CheckResult(
            "external_networks_expected",
            not unexpected,
            f"неожиданные сети с исходящим трафиком: {sorted(unexpected)}"
            if unexpected
            else f"сети с egress: {sorted(external)}",
        ),
    ]


def check_secrets(model: dict[str, Any]) -> CheckResult:
    """Состав секретов по сервисам совпадает с ожидаемым: лишним секретом процесс не пользуется."""
    services = _services(model)
    drift: dict[str, list[str]] = {}
    for name, expected in SECRETS_BY_SERVICE.items():
        spec = services.get(name)
        if spec is None:
            continue
        actual = _secret_names(spec)
        if actual != expected:
            drift[name] = sorted(actual ^ expected)
    return CheckResult(
        "secrets_per_service",
        not drift,
        f"состав секретов разошёлся: {drift}"
        if drift
        else "секреты смонтированы ровно туда, где их читают",
    )


def _secret_file_paths(model: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Пути файловых секретов из разобранного состава и имена, у которых пути нет.

    Компоновщик отдаёт для файлового секрета поле `file` (в YAML-разборе это видно прямо: рядом
    с `name` лежит `file: /etc/tbot/secrets/db_password`). Если поля нет, значит секрет пришёл
    не из файла — `external`, инлайн-`content` или переменная окружения: проверить путь
    невозможно, и притворяться, что проверка прошла, нельзя.
    """
    paths: dict[str, str] = {}
    no_path: list[str] = []
    for name, spec in (model.get("secrets") or {}).items():
        key = str(name)
        value = spec.get("file") if isinstance(spec, dict) else None
        if isinstance(value, str) and value:
            paths[key] = value
        else:
            no_path.append(key)
    return paths, no_path


def check_secret_paths(model: dict[str, Any]) -> CheckResult:
    """Пути файловых секретов совпадают с политикой: каталог секреты + отдельный файл ключей.

    Проверка держит три свойства разом: секрет не переведён в переменные окружения или в
    инлайн-`content` (TZ §8.4: значение не должно попадать в `ps aux` и в argv), файл ключей
    не переехал в каталог секретов (§8.4 называет отдельный путь, а `ADR-005` — отдельные права
    `640 root:gid 10001`), и боевой разбор не показывает dev-каталог `deploy/secrets`.
    """
    paths, no_path = _secret_file_paths(model)
    problems: list[str] = []
    for name in sorted(no_path):
        problems.append(
            f"{name}: в разобранном составе нет поля `file` — секреты читаются файлами "
            f"(TZ §14.3), а без пути проверка пути невозможна"
        )
    extra = sorted(set(paths) - set(ALLOWED_SECRET_PATHS))
    if extra:
        problems.append(f"секреты вне политики путей: {extra}")
    moved = {
        name: path
        for name, path in paths.items()
        if name in ALLOWED_SECRET_PATHS and path != ALLOWED_SECRET_PATHS[name]
    }
    for name, path in sorted(moved.items()):
        problems.append(f"{name}: путь {path} вместо {ALLOWED_SECRET_PATHS[name]}")
    absent = sorted(set(ALLOWED_SECRET_PATHS) - set(paths))
    if absent:
        problems.append(
            f"в разборе нет секретов {absent}: состав должен совпадать с закрытым перечнем"
        )
    return CheckResult(
        "secret_paths_policy",
        not problems,
        "; ".join(problems)
        if problems
        else f"пути секретов по политике: {len(paths)} файловых путей, "
        f"файл ключей отдельно ({KEK_PATH}, вне {SECRETS_ROOT})",
    )


def check_limits(model: dict[str, Any]) -> list[CheckResult]:
    """Лимиты дожили до разобранного состава, не выше ТЗ §14.6 и влезают в бюджет площадки."""
    services = _services(model)
    mem_problems: list[str] = []
    cpu_problems: list[str] = []
    total_mem = 0
    total_cpu = 0.0
    for name in MEM_CEILING_BYTES:
        spec = services.get(name)
        if spec is None:
            mem_problems.append(f"сервиса {name} нет в составе")
            cpu_problems.append(f"сервиса {name} нет в составе")
            continue
        mem = limit_bytes(spec.get("mem_limit"))
        if mem is None:
            mem_problems.append(
                f"{name}: mem_limit отсутствует или неразбираем " f"({spec.get('mem_limit')!r})"
            )
        elif mem > MEM_CEILING_BYTES[name]:
            mem_problems.append(
                f"{name}: mem_limit {mem // MIB} МиБ выше потолка ТЗ §14.6 "
                f"({MEM_CEILING_BYTES[name] // MIB} МиБ)"
            )
        else:
            total_mem += mem
        cpus = _cpus(spec.get("cpus"))
        if cpus is None or cpus <= 0:
            cpu_problems.append(f"{name}: cpus отсутствует или неразбираем ({spec.get('cpus')!r})")
        elif cpus > CPU_CEILING[name]:
            cpu_problems.append(f"{name}: cpus {cpus} выше потолка ТЗ §14.6 ({CPU_CEILING[name]})")
        else:
            total_cpu += cpus

    if total_mem > HOST_MEM_BUDGET_BYTES:
        mem_problems.append(
            f"сумма лимитов постоянного состава {total_mem // MIB} МиБ превышает бюджет площадки "
            f"{HOST_MEM_BUDGET_BYTES // MIB} МиБ (OQ-11: 3.8 ГиБ) — OOM-killer неизбежен"
        )
    results = [
        CheckResult(
            "resource_limits",
            not mem_problems,
            "; ".join(mem_problems)
            if mem_problems
            else f"лимиты в бюджете: сумма памяти {total_mem // MIB} МиБ "
            f"при потолке {HOST_MEM_BUDGET_BYTES // MIB} МиБ",
        )
    ]
    if total_cpu > HOST_CPU_BUDGET:
        cpu_problems.append(
            f"сумма лимитов CPU {total_cpu} превышает {HOST_CPU_BUDGET} vCPU "
            f"({HOST_VCPU} ядра × {CPU_OVERSUBSCRIPTION})"
        )
    results.append(
        CheckResult(
            "cpu_limits",
            not cpu_problems,
            "; ".join(cpu_problems)
            if cpu_problems
            else f"лимиты CPU в бюджете: сумма {total_cpu} при потолке {HOST_CPU_BUDGET}",
            WARN,
        )
    )
    return results


def check_restart_and_grace(model: dict[str, Any]) -> list[CheckResult]:
    """`restart: always` у постоянных процессов (TZ §14.6) и 60 секунд на остановку engine."""
    services = _services(model)
    not_always = sorted(
        name
        for name in ALWAYS_ON_SERVICES
        if name in services and str(services[name].get("restart")) != "always"
    )
    results = [
        CheckResult(
            "restart_always",
            not not_always,
            f"restart отличается от always у {not_always}"
            if not_always
            else "постоянные процессы перезапускаются сами",
        )
    ]
    grace = str((services.get("engine") or {}).get("stop_grace_period") or "")
    results.append(
        CheckResult(
            "engine_stop_grace",
            grace in {"60s", "1m", "1m0s"},
            f"stop_grace_period engine = {grace or '<нет>'}; ТЗ §14.6 требует 60s, иначе ядро "
            "не успевает записать состояние при остановке (TZ §7.6)",
            WARN,
        )
    )
    return results


def check_read_only(model: dict[str, Any]) -> CheckResult:
    """Read-only корневая ФС сохранена у всех процессов (TZ §8.5, §14.6)."""
    writable = sorted(name for name, spec in _services(model).items() if not spec.get("read_only"))
    return CheckResult(
        "read_only_rootfs",
        not writable,
        f"rootfs открыт на запись у {writable}" if writable else "read-only у всех процессов",
    )


def collect_checks(model: dict[str, Any]) -> list[CheckResult]:
    """Полный набор проверок разобранного состава: часть проверок возвращает по несколько итогов."""
    results: list[CheckResult] = []
    for group_check in (check_ports, check_egress, check_limits, check_restart_and_grace):
        results.extend(group_check(model))
    for single_check in (
        check_images,
        check_no_build,
        check_secrets,
        check_secret_paths,
        check_read_only,
    ):
        results.append(single_check(model))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Проверка разобранного боевого состава (TZ §14.6): порты, образы, сети, лимиты",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=None,
        help="файл с выводом `docker compose config --format json` (по умолчанию — stdin)",
    )
    parser.add_argument("--json", action="store_true", help="машинный вывод для протокола")
    args = parser.parse_args(argv)

    try:
        model = load_model(args.model)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"снимок разбора состава не прочитан: {exc}", file=sys.stderr)
        return 2

    results = collect_checks(model)
    blocking = [item for item in results if not item.ok and item.severity == FATAL]
    if args.json:
        print(
            json.dumps(
                {"ok": not blocking, "checks": [asdict(item) for item in results]},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for item in results:
            mark = "OK" if item.ok else ("WARN" if item.severity == WARN else "FAIL")
            print(f"{mark:4} {item.name}: {item.detail}")
        if blocking:
            print(f"НЕ ГОТОВО: блокирующих проверок — {len(blocking)}")
        else:
            print("ГОТОВО: боевой состав разобран без замечаний")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
