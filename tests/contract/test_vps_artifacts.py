"""Контракт на файлы конфигурации **хоста** (deploy/vps/).

Смысл тот же, что у контракта на compose: смысл держится не словами в docs, а значениями,
которые реально лежат в репозитории. Площадка настраивается один раз руками, и единственное,
что мешает ей через полгода разъехаться с ТЗ, — проверка, что в эталонных файлах остались
порты, политики и лимиты из ТЗ §8.3, §14.5, §14.6.
"""

from __future__ import annotations

import json
from typing import Any, cast

from tests.paths import ROOT, VPS

RULES = VPS / "ufw.rules"
FIREWALL = VPS / "firewall.sh"
SAFE_APPLY = VPS / "ufw_apply_safe.sh"
JAIL = VPS / "fail2ban-jail.local"
DAEMON = VPS / "docker-daemon.json"
VPS_README = VPS / "README.md"

# Что требует ТЗ §8.3 («вход наружу: только 443 и 22»): 80 добавлен как редирект и ACME.
ALLOWED_INBOUND = {"22/tcp", "80/tcp", "443/tcp"}
# Порты внутренних сервисов: наружу они не смотрят никогда (ни в dev, ни в боевом составе).
MUST_NOT_BE_PUBLIC = ("5432", "8080", "9101", "9102", "9103", "10800")
# Разрешённые исключения в ignoreip fail2ban: только loopback и приватные сети.
PRIVATE_IGNORE = {"127.0.0.1/8", "::1", "10.0.0.0/8", "192.168.0.0/16"}


def _rules_lines() -> list[str]:
    text = RULES.read_text(encoding="utf-8")
    return [line.split("#", 1)[0].strip() for line in text.splitlines()]


def _policies() -> dict[str, str]:
    found: dict[str, str] = {}
    for line in _rules_lines():
        if line.startswith("policy "):
            _, direction, policy = line.split()
            found[direction] = policy
    return found


def _allow_specs() -> set[str]:
    specs: set[str] = set()
    for line in _rules_lines():
        if line.startswith("allow "):
            spec = line[len("allow ") :].split(" comment", 1)[0].strip()
            specs.add(spec)
    return specs


def _jail_options() -> dict[str, str]:
    """Значения из секции [DEFAULT] плюс флаг включённости jail sshd."""
    options: dict[str, str] = {}
    section = ""
    for raw in JAIL.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "DEFAULT" and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            options[key] = value
        if section == "sshd" and line.startswith("enabled"):
            options["sshd_enabled"] = line.split("=", 1)[1].strip()
    return options


def _daemon() -> dict[str, Any]:
    data = json.loads(DAEMON.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("daemon.json должен содержать объект")
    return cast(dict[str, Any], data)


def test_артефакты_хоста_существуют() -> None:
    for path in (RULES, FIREWALL, SAFE_APPLY, JAIL, DAEMON, VPS_README):
        assert path.is_file(), f"нет эталонного файла хоста: {path}"


def test_разрешены_только_22_80_443() -> None:
    assert _allow_specs() == ALLOWED_INBOUND


def test_внутренние_порты_не_публикуются_наружу() -> None:
    text = RULES.read_text(encoding="utf-8")
    for port in MUST_NOT_BE_PUBLIC:
        assert f"allow {port}" not in text, f"правило открывает внутренний порт {port}"


def test_политики_уф_соответствуют_тз() -> None:
    """§8.3/§14.5: входящий — deny, исходящий — allow; пересылка — allow из-за Docker."""
    assert _policies() == {"incoming": "deny", "outgoing": "allow", "routed": "allow"}


def test_файрвол_включается_только_после_правил() -> None:
    """Порядок в скрипте — часть безопасности: `deny incoming` до правила 22/tcp отрезает SSH."""
    script = FIREWALL.read_text(encoding="utf-8")
    enable = script.index("ufw --force enable")
    first_allow = script.index('commands+=("ufw allow')
    assert first_allow < enable, "правила должны добавляться до `ufw enable`"
    assert "--revert" in script, "нет режима отката"
    assert "ufw disable" in script, "откат не выключает файрвол"


def test_политику_пересылки_читает_etc_default_ufw() -> None:
    """Docker требует ACCEPT в FORWARD; ufw берёт это из /etc/default/ufw, а не из правил."""
    script = FIREWALL.read_text(encoding="utf-8")
    assert "/etc/default/ufw" in script
    assert "DEFAULT_FORWARD_POLICY" in script
    # ACCEPT/DROP — имена политик пакета фильтра, а не слова ufw: в скрипте есть сопоставление
    # `allow → ACCEPT`, `deny → DROP`, и значение подставляется в кавычках.
    assert 'forward_policy="ACCEPT"' in script
    assert 'forward_policy="DROP"' in script
    assert 'DEFAULT_FORWARD_POLICY=\\"$forward_policy\\"' in script


def test_включение_идёт_со_сторожевым_таймером() -> None:
    """Если правило для 22/tcp окажется кривым, чинить SSH будет нечем — поэтому таймер сам
    выключает ufw, а администратор получает команду снятия."""
    script = SAFE_APPLY.read_text(encoding="utf-8")
    assert "sleep" in script, "сторож не ждёт"
    assert "ufw disable" in script, "сторож не выключает файрвол"
    assert "WATCHDOG_PID" in script, "в выводе нет команды снятия сторожа"
    assert "firewall.sh" in script
    assert "--apply" in script


def test_jail_соответствует_тз_8_3() -> None:
    """Три неудачи за десять минут → бан на полчаса."""
    options = _jail_options()
    assert options["maxretry"] == "3"
    assert options["findtime"] == "600"
    assert options["bantime"] == "1800"
    assert options["sshd_enabled"] == "true"
    assert options["backend"] == "systemd", "на 24.04 sshd пишет в journald, auth.log отсутствует"


def test_из_исключений_банa_нет_публичных_адресов() -> None:
    """Свой публичный адрес в ignoreip — это «fail2ban никогда не сработает для администратора»,
    то есть обнуление требования §8.3. Исключения — только loopback и приватные сети."""
    raw = _jail_options()["ignoreip"]
    entries = {entry.strip() for entry in raw.split() if entry.strip()}
    assert entries, "строка ignoreip пуста"
    assert (
        entries <= PRIVATE_IGNORE
    ), f"в исключения попали лишние адреса: {entries - PRIVATE_IGNORE}"


def test_ротация_логов_docker_из_тз_14_6() -> None:
    """50 МБ × 10 на контейнер: без этого json-логи занимают диск раньше, чем кончаются данные."""
    options = _daemon()["log-opts"]
    assert _daemon()["log-driver"] == "json-file"
    assert options["max-size"] == "50m"
    assert int(options["max-file"]) == 10


def test_пул_сетей_docker_вне_адресов_площадки() -> None:
    """Докер-подсети не должны совпадать ни с приватной сетью ВМ (10.130.0.0/24), ни с
    docker0-подсетью по умолчанию, иначе маршрутизация ломается тихо."""
    pools = _daemon()["default-address-pools"]
    assert len(pools) == 1
    base = pools[0]["base"]
    assert base.startswith("172."), base
    assert not base.startswith("172.17."), "нельзя занимать подсеть docker0 по умолчанию"
    assert int(pools[0]["size"]) >= 24


def test_файлы_хоста_обязаны_быть_с_lf() -> None:
    """Парсер правил и jail.local читает bash на Linux: CRLF из рабочей копии Windows ломает
    разбор порта молча, поэтому концовка закреплена в .gitattributes."""
    attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    for rule in (
        "*.sh text eol=lf",
        "*.json text eol=lf",
        "deploy/vps/*.rules text eol=lf",
        "deploy/vps/*.local text eol=lf",
    ):
        assert rule in attrs, f"в .gitattributes нет правила: {rule}"


def test_в_daemon_json_нет_секретов() -> None:
    """daemon.json читается доверенно всем, у кого есть доступ к хосту: токены туда не кладут."""
    raw = DAEMON.read_text(encoding="utf-8")
    for forbidden in ("token", "password", "ghcr_login"):
        assert forbidden not in raw.lower(), f"в daemon.json появилось {forbidden}"
