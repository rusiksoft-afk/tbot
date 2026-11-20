"""Контракт на файлы конфигурации **хоста** (deploy/vps/).

Смысл тот же, что у контракта на compose: смысл держится не словами в docs, а значениями,
которые реально лежат в репозитории. Площадка настраивается один раз руками, и единственное,
что мешает ей через полгода разъехаться с ТЗ, — проверка, что в эталонных файлах остались
порты, политики и лимиты из ТЗ §8.3, §14.5, §14.6.
"""

from __future__ import annotations

import json
import re
from typing import Any, cast

from tests.paths import COMPOSE_PROD, ROOT, VPS, load_compose_yaml

RULES = VPS / "ufw.rules"
FIREWALL = VPS / "firewall.sh"
SAFE_APPLY = VPS / "ufw_apply_safe.sh"
JAIL = VPS / "fail2ban-jail.local"
DAEMON = VPS / "docker-daemon.json"
SECRETS_SETUP = VPS / "secrets-setup.sh"
VPS_README = VPS / "README.md"

# Что требует ТЗ §8.5 («вход наружу: 443/tcp, 443/udp, 80/tcp и 22»): 80 — редирект и ACME,
# 443/udp — HTTP/3 (решение заказчика от 2026-11-20, docs/adr/ADR-003). Набор udp-портов связан
# с Caddyfile контрактом `test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443`: `h3` без
# `allow 443/udp` обещает транспорт, который файрвол теряет, а udp без `h3` — открыт зря.
ALLOWED_INBOUND = {"22/tcp", "80/tcp", "443/tcp", "443/udp"}
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
    for path in (RULES, FIREWALL, SAFE_APPLY, JAIL, DAEMON, SECRETS_SETUP, VPS_README):
        assert path.is_file(), f"нет эталонного файла хоста: {path}"


def test_разрешены_только_22_80_443_tcp_и_443_udp() -> None:
    assert _allow_specs() == ALLOWED_INBOUND


def test_HTTP_3_имеет_подписанное_udp_правило() -> None:
    """У правила 443/udp обязано быть назначение: без комментария его снимают «за ненадобностью»,
    и Caddyfile остаётся с `h3`, которого сеть не пропускает."""
    строки = [line for line in _rules_lines() if line.startswith("allow 443/udp")]
    assert len(строки) == 1, f"ожидалось одно правило 443/udp: {строки}"
    assert " comment " in строки[0], f"у правила нет назначения: {строки[0]!r}"


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


# ─── deploy/vps/secrets-setup.sh: ввод секретов заказчиком (TZ §14.3, docs/adr/ADR-003) ───

# Порядок имён в скрипте = порядок ответов на вопросы. Он закреплён, потому что перепутанный
# порядок кладёт токен в файл с паролем: значения не видны ни агенту, ни логам, поэтому
# единственный способ поймать такую ошибку — контракт на имена и длины.
SETUP_NAMES: tuple[str, ...] = ("db_password", "db_url", "ghcr_token", "telegram_token")


def _setup_text() -> str:
    return SECRETS_SETUP.read_text(encoding="utf-8")


def _setup_lines() -> list[str]:
    return _setup_text().splitlines()


def test_скрипт_секретов_не_выводит_и_не_сохраняет_значения() -> None:
    """Ценность скрипта — в том, чего не видно: ни echo значения, ни значения в argv и в истории.

    `read -s` без `-r` съедал бы обратный слэш из пароля, `echo "$val"` выписывал бы секрет в
    терминал (а SSH-сессию пишут в журнал), `printenv` или забытая переменная — та же утечка
    через `ps` и дампы. Поэтому строки, которые упоминают `$val`, перечислены явно.
    """
    строки_со_значением = [line for line in _setup_lines() if "$val" in line]
    assert строки_со_значением, "скрипт не записывает введённое значение — он бессмысленен"
    разрешено = ("printf '%s' \"$val\"", '[[ -z "$val" ]]', "unset val", "IFS= read -r -s")
    for line in строки_со_значением:
        assert any(
            hay in line for hay in разрешено
        ), f"строка обращается к значению вне белого списка: {line.strip()!r}"
    assert "set -euo pipefail" in _setup_text()
    assert "set +o history" in _setup_text(), "история оболочки на время ввода не отключена"
    assert "unset val" in _setup_text(), "значение остаётся в переменных оболочки после записи"
    for forbidden in ("set -x", "printenv", "env >", 'echo "$val"'):
        assert forbidden not in _setup_text(), f"в скрипте появилось {forbidden!r}"


def test_скрипт_пишет_файлы_с_правами_из_тз() -> None:
    """TZ §14.3: файлы 600 с root-владельцем; каталог 700; без перевода строки в конце.

    Лишний `\n` в конце токена или DSN — это «пароль не подходит», который ищут сутки: приложение
    читает файл как есть. Режим 644 читается любой учёткой на хосте, а каталог 755 позволяет
    перечислить, какие секреты на площадке вообще есть.
    """
    текст = _setup_text()
    assert "umask 077" in текст
    assert "install -d -m 700 -o root -g root" in текст
    assert "chmod 600" in текст
    assert "chown root:root" in текст
    assert (
        "printf '%s'" in текст
    ), "значение обязано писаться через printf без завершающего перевода строки"
    assert '"$val"' in текст, "значение обязано быть в кавычках: без них пробелы разбились бы"
    assert "id -u" in текст, "скрипт обязан требовать root: иначе владелец файла — пользователь"


def test_имена_секретов_совпадают_с_боевым_составом() -> None:
    """Набор файлов скрипта и набор файлов, которые читает compose, обязаны сходиться.

    Расхождение выглядит как «контейнер стартанул и упал с секретом не найден» уже на деплое, а
    чинить его придётся на живой площадке. `ghcr_token` — единственное имя вне compose: он нужен
    хосту для `docker login ghcr.io` (docs/runbook/ghcr-pull.md §3) и в контейнеры не монтируется.
    `telegram_socks_pass` создавался раньше, в составе туннеля Telegram (T-714).
    """
    match = re.search(r"SECRET_NAMES=\(([^)]*)\)", _setup_text())
    assert match, "в скрипте нет списка SECRET_NAMES — контракт на имена теряется"
    имена = tuple(match.group(1).split())
    assert имена == SETUP_NAMES, f"порядок или набор имён изменились: {имена}"

    состав = load_compose_yaml(COMPOSE_PROD)["secrets"]
    assert isinstance(состав, dict), "в deploy/compose.prod.yaml нет секции secrets"
    из_состава = {
        str(spec["file"]).rsplit("/", 1)[-1]
        for spec in состав.values()
        if isinstance(spec, dict) and spec.get("file")
    }
    assert из_состава, "боевой состав не читает файловых секретов"
    assert (
        из_состава - {"telegram_socks_pass"} <= set(имена)
    ), f"составу нужен файл, который скрипт не создаёт: {из_состава - set(имена) - {'telegram_socks_pass'}}"
    assert set(имена) - из_состава == {"ghcr_token"}, (
        "у хостового секрета появился лишний сосед или compose перестал читать известный: "
        f"{set(имена) ^ из_состава}"
    )


def test_режим_check_не_трогает_файлы_и_не_печатает_содержимое() -> None:
    """`--check` — единственный способ для агента убедиться в готовности площадки: только имена,
    размеры и права. Если в этом режиме появится перенаправление или содержимое, проверка сама
    станет источником компрометации."""
    текст = _setup_text()
    начало = текст.index("check_mode() {")
    конец = текст.index("\n}", начало)
    тело = текст[начало:конец]
    assert "--check" in текст, "у скрипта нет режима проверки"
    assert "$val" not in тело, "`--check` обращается к значениям"
    assert "printf" not in тело, "`--check` что-то записывает (запись значений — только `printf`)"
    for line in тело.splitlines():
        if ">" in line:
            assert ">&2" in line, f"`--check` перенаправляет вывод не в stderr: {line.strip()!r}"
    assert "stat -c '%s'" in тело, "`--check` не печатает размер: обрезанное значение не видно"
    assert "stat -c '%a'" in тело, "`--check` не проверяет режим файла"
    assert "stat -c '%U:%G'" in тело, "`--check` не проверяет владельца"
