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

from tests.paths import COMPOSE_PROD, DOCKERFILE, ROOT, VPS, load_compose_yaml

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
HOST_ONLY_NAMES: tuple[str, ...] = ("telegram_socks_pass",)


def _setup_text() -> str:
    return SECRETS_SETUP.read_text(encoding="utf-8")


def _setup_lines() -> list[str]:
    return _setup_text().splitlines()


def _setup_code() -> str:
    """Скрипт без полноструочных комментариев.

    Без этого контракт проверяет текст подсказки вместо кода: мутация 2026-11-20 (заменить
    `set +o history 2>/dev/null || true` на `:`) прошла незамеченной именно потому, что та же
    строка упоминается в шапке скрипта. Тот же приём ловит «вызов функции заменён, а упоминание
    в комментарии остался».
    """
    return "\n".join(line for line in _setup_lines() if not line.lstrip().startswith("#"))


def _bash_func(name: str) -> str:
    """Тело bash-функции: от строки `name() {` до `}` в колонке 0."""
    текст = _setup_code()
    начало = текст.index(f"{name}() {{")
    конец = текст.index("\n}", начало)
    return текст[начало:конец]


def test_скрипт_секретов_не_выводит_и_не_сохраняет_значения() -> None:
    """Ценность скрипта — в том, чего не видно: ни echo значения, ни значения в argv и в истории.

    `read -s` без `-r` съедал бы обратный слэш из пароля, `echo "$val"` выписывал бы секрет в
    терминал (а SSH-сессию пишут в журнал), `printenv` или забытая переменная — та же утечка через
    `ps` и дампы. Поэтому перечислены ЯВНО все строки кода, которые обращаются к любому из
    значений: `val` (ввод), `probe` (чтение файла в `--check`), `existing_password` и
    `db_password_value` (пароль, из которого собирается DSN). Последняя пара появилась не из
    фантазии: скрипт собирает `db_url` из `db_password`, и пароль перестал быть одноразовой
    переменной — утечка такого значения компрометирует сразу оба файла пары.
    """
    переменные_значений: dict[str, tuple[str, ...]] = {
        "$val": (
            """printf '%s' "$val\"""",
            '[ -z "$val" ]',
            "IFS= read -r -s val",
            "unset val",
            'shape_ok "$name" "$val"',
            'db_password_value="$val"',
            'val="$existing_password"',
            'val="$TBOT_DB_URL"',
            'val="postgresql+psycopg://',
            '"${#val}"',
            "printf '  %s: записать это значение несмотря на форму? [y/N]: ' \"$name\"",
        ),
        "$probe": ('probe=$(<"$path")', 'shape_ok "$name" "$probe"', 'probe=""'),
        "$existing_password": (
            'if [ -n "$existing_password" ]',
            'val="$existing_password"',
            'db_password_value="$existing_password"',
        ),
        "$db_password_value": ('val="postgresql+psycopg://',),
    }
    строки_со_значением = [
        line
        for line in _setup_code().splitlines()
        if any(var in line for var in переменные_значений)
    ]
    assert строки_со_значением, "скрипт не работает со значениями — он бессмысленен"
    for line in строки_со_значением:
        допустимо = next(
            (разрешено for var, разрешено in переменные_значений.items() if var in line), ()
        )
        assert any(
            hay in line for hay in допустимо
        ), f"строка обращается к значению вне белого списка: {line.strip()!r}"
    код = _setup_code()
    for forbidden in ('echo "$', "tee ", "printenv", "logger", "curl ", "env >", "set -x"):
        assert forbidden not in код, f"в коде скрипта появилось {forbidden!r}"
    assert "set -euo pipefail" in код
    assert "set +o history 2>/dev/null || true" in код, (
        "история оболочки на время ввода не отключена: значение останется в ~/.bash_history "
        "и в журнале SSH-сессии"
    )
    assert "unset val" in код, "значение остаётся в переменных оболочки после записи"
    assert (
        _bash_func("check_mode").count('probe=""') >= 2
    ), "в `--check` значение не стирается на одной из веток: оно переживает функцию"


def test_скрипт_пишет_файлы_с_правами_из_тз() -> None:
    """TZ §14.3: файлы 600 с root-владельцем; каталог 700; без перевода строки в конце.

    Лишний перевод строки в конце токена или DSN — это «пароль не подходит», который ищут сутки:
    приложение читает файл как есть. Режим 644 читается любой учёткой на хосте, а каталог 755
    позволяет перечислить, какие секреты на площадке вообще есть.
    """
    код = _setup_code()
    запись = _bash_func("write_file")
    assert "umask 077" in код
    assert 'install -d -m 700 -o root -g root "$SECRETS_DIR"' in код
    политика = _bash_func("apply_policy")
    assert 'apply_policy "$name" "$path"' in запись, (
        "write_file обязан ставить права по имени файла: 600 root:root у секрета, который compose "
        "монтирует в контейнер, означает недоступный секрет для процесса под uid/gid 10001 "
        "(ADR-005)"
    )
    assert 'chmod 640 "$path"' in политика, "монтируемым секретам не выдаётся режим по группе"
    assert 'chown "0:$CONTAINER_GID" "$path"' in политика, "монтируемым секретам не ставится gid"
    assert 'chmod 600 "$path"' in политика, "файлу хозяйственного инструмента обязан остаться 600"
    assert 'chown root:root "$path"' in политика, "файл хозяйственного инструмента теряет 0:0"
    assert (
        """printf '%s' "$val" >"$path\"""" in запись
    ), "значение обязано писаться через printf без завершающего перевода строки"
    assert """printf '%s\\n'""" not in запись, (
        "в записи значения появился завершающий перевод строки: DSN и токен читаются «как есть», "
        "лишний \\n ломает подключение к базе на первом же migrate"
    )
    assert 'if [ "$(id -u)" -ne 0 ]; then' in код, (
        "скрипт обязан требовать root: иначе владелец файла — пользователь, и compose не сможет "
        "прочитать секрет"
    )


def test_права_монтируемых_секретов_совпадают_с_gid_процесса_в_образе() -> None:
    """ADR-005: режим и владелец файла секрета обязан подходить процессу внутри контейнера.

    Замер на площадке 2026-11-20: `run --rm migrate` упал с `PermissionError: [Errno 13] Permission
    denied: '/run/secrets/db_url'` (migrate_exit=1). Причина не в площадке, а в сочетании требований:
    bind-маунт секрета сохраняет владельца и режим с хоста, процесс в образе работает под
    uid/gid 10001 (`deploy/Dockerfile`: `USER 10001:10001`), а compose 2.40.3 отказывается принимать
    `uid`/`gid`/`mode` у file-секретов (`secrets.db_url additional properties 'uid', 'gid', 'mode'
    not allowed`). Значит единственный рычаг — права на хосте, и они обязаны совпадать с gid
    процесса: 640 и группа с gid 10001. Замеры хоста того же дня: учётной записи с uid или gid
    10001 на хосте нет, поэтому «мир» и локальные пользователи по-прежнему ничего не читают.
    """
    код = _setup_code()
    m = re.search(r"CONTAINER_GID=(\d+)", код)
    assert m, "в скрипте нет CONTAINER_GID: политика прав не выражена явным числом"
    gid = m.group(1)
    образ = re.search(r"(?m)^USER (\d+):(\d+)$", DOCKERFILE.read_text(encoding="utf-8"))
    assert образ, "в deploy/Dockerfile нет числовой USER: gid процесса нечем сверить"
    assert (образ.group(1), образ.group(2)) == (gid, gid), (
        f"gid процесса в образе {образ.group(1)}:{образ.group(2)} не совпадает с CONTAINER_GID={gid}: "
        "монтируемые секреты окажутся нечитаемыми"
    )

    состав = load_compose_yaml(COMPOSE_PROD)["secrets"]
    монтируемые = {
        str(spec["file"]).rsplit("/", 1)[-1]
        for spec in состав.values()
        if isinstance(spec, dict) and spec.get("file")
    }
    m_mount = re.search(r"MOUNTED_NAMES=\(([^)]*)\)", код)
    assert m_mount, "в скрипте нет MOUNTED_NAMES: список «файл монтируется в контейнер» потерян"
    assert set(m_mount.group(1).split()) == монтируемые, (
        f"политика прав разошлась с составом: в контейнеры монтируются {sorted(монтируемые)}, "
        f"а по группе доступ настроен для {sorted(m_mount.group(1).split())}"
    )
    m_host = re.search(r"HOST_READ_ONLY_NAMES=\(([^)]*)\)", код)
    assert m_host, "в скрипте нет HOST_READ_ONLY_NAMES: не описано, какой файл читает только хост"
    assert set(m_host.group(1).split()) == set(SETUP_NAMES) - монтируемые, (
        "файл, который читает только хозяйственный инструмент, обязан быть ровно "
        "«имена скрипта минус монтируемые»: иначе 600 получит читаемый контейнером файл"
    )


def test_remed_приводит_права_не_касаясь_значений() -> None:
    """Переход площадки на ADR-005 возможен только без перезаписи значений.

    Пароль базы при initdb оседает в томе `pgdata`: перегенерация означала бы новый том и потерю
    данных, а внешние токены (ADR-004) при повторном вводе считаются скомпрометированными. Поэтому
    режим и владелец приводятся отдельной операцией, которая читает метаданные и ничего не пишет в
    содержимое файлов.
    """
    текст = _setup_text()
    assert "--remed) REMEDIATE_ONLY=1 ;;" in текст, "у скрипта нет режима приведения прав"
    тело = _bash_func("remediate")
    assert "apply_policy" in тело, "`--remed` не вызывает политику прав"
    assert "stat -c '%a'" in тело, "`--remed` не сверяет текущий режим: он чинит только отклонения"
    assert "stat -c '%u:%g'" in тело, "`--remed` не сверяет текущий gid: он чинит только отклонения"
    for запрещено in ('>"$path"', """printf '%s' "$""", "read -", "$(<"):
        assert (
            запрещено not in тело
        ), f"`--remed` трогает содержимое файла ({запрещено!r}): значения перезаписывать нельзя"


def test_имена_секретов_совпадают_с_боевым_составом() -> None:
    """Набор файлов скрипта и набор файлов, которые читает compose, обязаны сходиться.

    Расхождение выглядит как «контейнер стартанул и упал с секретом не найден» уже на деплое, а
    чинить его придётся на живой площадке. `ghcr_token` — единственное имя вне compose: он нужен
    хосту для `docker login ghcr.io` (docs/runbook/ghcr-pull.md §3) и в контейнеры не монтируется.
    """
    match = re.search(r"SECRET_NAMES=\(([^)]*)\)", _setup_code())
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
        из_состава - set(HOST_ONLY_NAMES) <= set(имена)
    ), f"составу нужен файл, который скрипт не создаёт: {из_состава - set(имена) - set(HOST_ONLY_NAMES)}"
    assert set(имена) - из_состава == {"ghcr_token"}, (
        "у хостового секрета появился лишний сосед или compose перестал читать известный: "
        f"{set(имена) ^ из_состава}"
    )


def test_состав_требует_пять_файлов_и_все_пять_видны_в_диагностике() -> None:
    """Подзадача из замера 2026-11-20: проверка готовности не должна молчать про пятый файл.

    Скрипт записи создаёт четыре файла, а compose читает пять: `telegram_socks_pass` появился
    раньше, вместе с туннелем Telegram (T-714). Пока его не было ни в списке записи, ни в
    диагностике, «всё готово» на площадке означало «состав упадёт при старте». Разделение
    зафиксировано отдельным списком `HOST_ONLY_NAMES`, а диагностика обязана пройти по обоим
    спискам — иначе пятый файл снова станет невидимкой.
    """
    match = re.search(r"HOST_ONLY_NAMES=\(([^)]*)\)", _setup_code())
    assert match, "в скрипте нет отдельного списка файлов, которые состав требует, но не создаёт"
    только_хоста = tuple(match.group(1).split())
    assert только_хоста == HOST_ONLY_NAMES, f"состав изменился: {только_хоста}"

    состав = load_compose_yaml(COMPOSE_PROD)["secrets"]
    из_состава = {
        str(spec["file"]).rsplit("/", 1)[-1]
        for spec in состав.values()
        if isinstance(spec, dict) and spec.get("file")
    }
    assert set(только_хоста) == из_состава - set(SETUP_NAMES), (
        "файлы состава разделены между списками не полностью: "
        f"{из_состава ^ (set(SETUP_NAMES) | set(только_хоста))}"
    )
    диагностика = _bash_func("check_mode")
    assert '"${SECRET_NAMES[@]}" "${HOST_ONLY_NAMES[@]}"' in диагностика, (
        "`--check` перебирает только записываемые файлы: пятый файл состава снова станет "
        "невидимкой, и зелёный вывод соврёт о готовности"
    )
    assert (
        'for name in "${SECRET_NAMES[@]}"; do' not in диагностика
    ), "в диагностике остался цикл только по записываемым файлам: он подменяет полный обход"


def test_значения_проверяются_по_форме_до_записи_файла() -> None:
    """Главный вывод замера 2026-11-20: наличие файла и режим 600 о значении не говорят ничего.

    На площадке `--check` был зелёным, а значения — не по назначению: 11 цифр вместо DSN, 11
    символов вместо PAT, пароль с пробелами, отсутствующий токен бота. Проверка формы обязана
    вызываться в ветке ввода (а не только в диагностике) и до `write_file`: иначе мусор всё равно
    ложится на диск, а оператор видит «записано».
    """
    ввод = _bash_func("ask_value")
    assert 'shape_ok "$name" "$val"' in ввод, "введённое значение не проверяется по форме"
    assert "НЕ ПОДХОДИТ" in ввод, "отказ по форме не виден оператору: он не поймёт, что вводить"
    assert '"${#val}"' in ввод, "длина значения — единственная подсказка оператора об опечатке"
    assert (
        "[y/N]" in ввод
    ), "после трёх неудач скрипт обязан спросить, а не записывать молча и не умирать молча"

    код = _setup_code()
    assert 'ask_value "$name"' in код, "в цикле записи нет вызова ввода значений"
    assert 'write_file "$name"' in код, "в цикле нет вызова записи файла"
    assert код.index('ask_value "$name"') < код.index(
        'write_file "$name"'
    ), "форма проверяется после записи файла: проверка превращается в консультацию"

    шаблоны = _bash_func("shape_ok")
    for name in (*SETUP_NAMES, *HOST_ONLY_NAMES):
        assert re.search(rf"^\s+{name}\)", шаблоны, re.MULTILINE), f"для {name} нет шаблона формы"
    assert "grep -Eq" in шаблоны, (
        "шаблон не прикреплён якорями и не читает значение из stdin: значение попало бы в argv "
        "подпроцесса (видно в `ps`) или совпало бы с его частью"
    )


def test_db_url_собирается_из_пароля_а_не_вручается_оператору() -> None:
    """Пара `db_password` + `db_url` рассинхронилась на площадке: DSN скопировали отдельно.

    Пока `db_url` вводят с клавиатуры, он может быть кем угодно (2026-11-20 в нём лежало 11 цифр).
    Скрипт собирает DSN из параметров состава и пароля, а для внешней базы оставляет явный
    `TBOT_DB_URL` — с проверкой формы, а не «доверяю на слово».
    """
    код = _setup_code()
    assert 'if [ "$name" = "db_url" ]' in код, "у db_url нет отдельного обращения с ним"
    assert (
        'val="postgresql+psycopg://${DB_USER}:${db_password_value}@${DB_HOST}:${DB_PORT}/${DB_NAME}"'
        in код
    ), "db_url не собирается из пароля состава: остаются два независимых источника истины"
    assert 'val="$TBOT_DB_URL"' in код, "для внешней базы нет явного переопределения DSN"
    assert (
        код.count("IFS= read -r -s val") == 1
    ), "значение читается в нескольких местах: порядок ответов контролировать невозможно"
    assert (
        "собранный DSN не по форме" in код
    ), "собственный DSN скрипта не проверяется: пустой пароль дал бы нерабочий файл с тихим видом"


def test_пароль_базы_можно_не_придумывать_и_не_переносить_через_буфер() -> None:
    """Пароль базы нужен только внутри пары файлов: требовать от оператора придумать его — риск.

    Пустой ввод = генерация (`openssl rand -hex`), а если пароль уже лежит на площадке и его не
    вводят заново, DSN собирается из существующего значения: оператору не нужно знать пароль,
    чтобы пересобрать пару файлов. Границы длины общие с шаблоном формы, иначе «генерируем одно,
    а принимаем другое».
    """
    код = _setup_code()
    assert 'val=$(openssl rand -hex "$DB_PASSWORD_BYTES")' in код, (
        "пароль базы не генерируется: оператор выдумывает его, придумывает ограничение по длине "
        "и переносит через буфер обмена — ровно так появился пароль с пробелами на площадке"
    )
    assert 'DB_PASSWORD_BYTES="${TBOT_DB_PASSWORD_BYTES:-24}"' in код
    assert 'if [ -n "$existing_password" ]; then' in код, (
        "при повторном запуске DSN нельзя собрать из уже лежащего пароля: оператору пришлось бы "
        "вводить секрет, которого он не знает"
    )
    ввод = _bash_func("ask_value")
    assert (
        'if [ -n "$existing_password" ] && shape_ok db_password "$existing_password"; then' in ввод
    ), (
        "пустой ввод повторяет лежащий пароль без проверки формы: на площадке 2026-11-20 там "
        "остался бы пароль с пробелами, и оператор, нажав Enter, сохранил бы нерабочую пару"
    )
    assert (
        "генерируется новое" in ввод
    ), "случай «лежащий пароль не по форме» не объяснён оператору: он решит, что Enter безопасен"
    assert (
        'if ! shape_ok "$name" "$(<"$SECRETS_DIR/$name")"; then' in ввод
    ), "пустой ввод оставляет нерабочее значение молча: предупреждение о форме обязательно"
    шаблоны = _bash_func("shape_ok")
    assert "{${DB_PASSWORD_MIN},${DB_PASSWORD_MAX}}" in шаблоны, (
        "шаблон формы пароля не использует общие границы DB_PASSWORD_MIN/DB_PASSWORD_MAX: "
        "сгенерированное значение могут отклонить, а слишком короткое — принять"
    )


def test_перезапись_требует_подтверждения_а_неинтерактивный_прогон_отказывается() -> None:
    """Скрипт запускают на живой площадке: молча перезаписать секрет — значит устроить простой.

    Подтверждение `[y/N]` и отказ без терминала (`--force` обязателен в CI) — защита от «запустили
    не в том каталоге» и от прогона, который пишет значения из неинтерактивного канала. `--only`
    нужен, чтобы перезаливать одно значение, а не пересоздавать весь набор ценой новой пары
    пароль+DSN.
    """
    запись = _bash_func("write_file")
    assert '[ ! -t 1 ] && [ "$FORCE" -eq 0 ]' in запись, (
        "без терминала скрипт обязан отказаться писать: иначе значения читаются из случайного "
        "канала (пайп, cron, CI) и попадают в боевой каталог"
    )
    assert "INTERACTIVE_REQUIRED" in запись
    assert (
        '[ -e "$path" ] && [ "$FORCE" -eq 0 ] && [ -t 0 ]' in запись
    ), "существующий секрет перезаписывается без подтверждения"
    assert "[y/N]" in запись, "подтверждение перезаписи должно быть по умолчанию «нет»"
    assert "--only" in _setup_code(), (
        "нет возможности перезалить одно значение: оператор пересоздаёт весь набор, меняя пароль "
        "базы и DSN там, где этого не просили"
    )


def test_режим_check_не_трогает_файлы_и_не_печатает_содержимое() -> None:
    """`--check` — единственный способ для агента убедиться в готовности площадки: имена, размеры,
    права, владелец и вердикт формы. Сами значения при этом не печатаются и не уходят в подпроцесс.

    Значение в `--check` приходится читать: иначе не вынести вердикт о форме, а ровно этого
    вердикта не хватило 2026-11-20, когда зелёный вывод сопровождал 11 цифр вместо DSN и 11
    символов вместо PAT. Поэтому правила здесь точнее, чем запрет `printf`:
      - `printf` в этом режиме печатает только метаданные — ни одна его строка не упоминает
        переменную значения;
      - значение читается встроенным механизмом оболочки (`$(<файл)`), без `cat`: аргументы
        подпроцессов видно в `ps`, а вывод `cat` легко унести в терминал;
      - переменная значения локальна и обнуляется на обеих ветках;
      - из перенаправлений разрешён только `>&2`;
      - размер, режим и владелец печатаются (иначе обрезанное или открытое на всех значение не
        видно), и обязательно вызывается проверка формы.
    """
    код = _setup_code()
    assert "--check) CHECK_ONLY=1 ;;" in код, (
        "режим диагностики не отделён от записи явным флагом: «посмотреть готовность» и «залить "
        "значения» не должны быть одним и тем же вызовом"
    )
    assert 'if [ "$CHECK_ONLY" -eq 1 ]; then' in код, "флаг CHECK_ONLY ни на что не влияет"
    диагностика = _bash_func("check_mode")
    assert "$val" not in диагностика, "`--check` обращается к переменным ввода"
    assert "cat " not in диагностика, (
        "`--check` читает значение подпроцессом: аргументы `cat` видно в `ps`, а его stdout "
        "легко оставить в терминале"
    )
    assert 'probe=$(<"$path")' in диагностика, "значение читается не встроенным механизмом оболочки"
    assert 'shape_ok "$name" "$probe"' in диагностика, (
        "`--check` не проверяет форму: значение не по назначению снова станет невидимым, как это "
        "было на площадке 2026-11-20"
    )
    assert re.search(
        r"^\s*local\b.*\bprobe\b", диагностика, re.MULTILINE
    ), "переменная значения не локальна: после `--check` оно останется в переменных оболочки"
    for line in диагностика.splitlines():
        if "printf" in line:
            assert (
                "$probe" not in line
            ), f"`--check` печатает прочитанное значение: {line.strip()!r}"
            assert "$val" not in line, f"`--check` печатает введённое значение: {line.strip()!r}"
        if ">" in line:
            assert ">&2" in line, f"`--check` перенаправляет вывод не в stderr: {line.strip()!r}"
    assert (
        "stat -c '%s'" in диагностика
    ), "`--check` не печатает размер: обрезанное значение не видно"
    assert "stat -c '%a'" in диагностика, "`--check` не проверяет режим файла"
    assert "stat -c '%U:%G'" in диагностика, "`--check` не проверяет владельца"
    assert (
        'if [ "$size" -eq 0 ]; then' in диагностика
    ), "пустой файл состава не отличается от рабочего: 0 байт — это тоже «секрет на месте»"
    assert 'if [ "$mode" != "$(expected_mode "$name")" ]' in диагностика, (
        "`--check` не сверяет режим с политикой ADR-005: у монтируемых в контейнер файлов нужен "
        "640, у файла хозяйственного инструмента — 600"
    )
    assert (
        '"$(expected_owner "$name")"' in диагностика
    ), "`--check` не сверяет владельца с политикой ADR-005 (gid контейнера)"
    assert "stat -c '%u:%g'" in диагностика, (
        "`--check` сверяет владельца по имени группы: на хосте у gid контейнера имени может не "
        "быть, и проверка начнёт сравнивать NULL с NULL"
    )
    for запись_файла in ("chmod ", "chown ", "install -d ", "read -", """printf '%s' "$"""):
        assert запись_файла not in диагностика, (
            f"`--check` что-то меняет или читает из терминала ({запись_файла!r}): "
            "режим проверки обязан остаться только чтением метаданных"
        )
