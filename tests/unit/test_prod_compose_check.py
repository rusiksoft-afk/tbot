"""Офлайн-проверка `scripts/prod_compose_check.py` — анализа **разобранного** боевого состава (T-712, T-713).

Живого `docker compose config` на dev-машине нет (Docker не установлен), поэтому тесты работают
на модельных словарях в формате `config --format json`. Снимок собран по фактическим значениям
двух compose-файлов (`deploy/compose.yaml` + `deploy/compose.prod.yaml`): сети, лимиты, секреты и
состав публикаций взяты оттуда, как их увидит compose после слияния overlay.

Смысл проверок — отловить то, чего не видно в YAML-контракте
(`tests/integration/test_compose_prod_contract.py`): как файлы слились. Именно слияние способно
принести лишнюю публикацию порта, сеть с egress у базы, оставшуюся сборку или унаследованный из
якоря лимит памяти.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.paths import COMPOSE_PROD, SCRIPTS, load_compose_yaml, load_script

check = load_script("prod_compose_check")

MIB = 1024**2
WEB_DIGEST_IMAGE = "ghcr.io/rusiksoft-afk/tbot-web@sha256:" + "a" * 64
CADDY_DIGEST_IMAGE = "caddy@sha256:" + "c" * 64
POSTGRES_DIGEST_IMAGE = "postgres@sha256:" + "d" * 64


def _secret(name: str) -> dict[str, Any]:
    """Секрет сервиса в том виде, в каком его отдаёт compose v2 (объект с `source`)."""
    return {"source": name, "target": name, "uid": 0, "gid": 0, "mode": 256}


def _port(target: int, published: str, protocol: str = "tcp") -> dict[str, Any]:
    return {"mode": "ingress", "target": target, "published": published, "protocol": protocol}


def _service(
    name: str,
    image: str,
    networks: dict[str, Any],
    *,
    ports: list[Any] | None = None,
    secrets: list[Any] | None = None,
    mem: int | None = None,
    cpus: float | None = None,
    restart: str = "always",
    read_only: bool = True,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "name": f"tbot-{name}",
        "image": image,
        "networks": networks,
        "restart": restart,
        "read_only": read_only,
    }
    if mem is not None:
        spec["mem_limit"] = mem
    if cpus is not None:
        spec["cpus"] = cpus
    if ports:
        spec["ports"] = ports
    if secrets:
        spec["secrets"] = secrets
    if extra:
        spec.update(extra)
    return spec


def _model() -> dict[str, Any]:
    """Снимок разбора боевого состава: сеть, лимиты и секреты — из фактических compose-файлов.

    Значения памяти/CPU соответствуют `deploy/compose.prod.yaml` (площадка 2 vCPU / 3.8 ГиБ,
    OQ-11), сети — слиянию базового файла и overlay: `tbot-backend`/`tbot-edge` помечены
    `internal`, `tbot-egress` и добавленная overlay'ом `tbot-public` — нет.
    """
    return {
        "name": "tbot",
        "networks": {
            "tbot-backend": {"name": "tbot_tbot-backend", "driver": "bridge", "internal": True},
            "tbot-edge": {"name": "tbot_tbot-edge", "driver": "bridge", "internal": True},
            "tbot-egress": {"name": "tbot_tbot-egress", "driver": "bridge"},
            "tbot-public": {"name": "tbot_tbot-public", "driver": "bridge"},
        },
        "services": {
            "postgres": _service(
                "postgres",
                POSTGRES_DIGEST_IMAGE,
                {"tbot-backend": None},
                secrets=[_secret("db_password")],
                mem=768 * MIB,
                cpus=1.5,
            ),
            # `migrate` — одноразовый запуск: restart у него "no", и в бюджет он не входит.
            "migrate": _service(
                "migrate",
                WEB_DIGEST_IMAGE,
                {"tbot-backend": None},
                secrets=[_secret("db_url")],
                mem=320 * MIB,
                restart="no",
            ),
            "web": _service(
                "web",
                WEB_DIGEST_IMAGE,
                {"tbot-edge": None, "tbot-backend": None, "tbot-public": None},
                secrets=[_secret("db_url")],
                mem=320 * MIB,
                cpus=0.5,
            ),
            "engine": _service(
                "engine",
                WEB_DIGEST_IMAGE,
                {"tbot-backend": None, "tbot-egress": None},
                secrets=[_secret("db_url")],
                mem=896 * MIB,
                cpus=1.0,
                extra={"stop_grace_period": "1m0s"},
            ),
            "tgbot": _service(
                "tgbot",
                WEB_DIGEST_IMAGE,
                {"tbot-backend": None, "tbot-egress": None},
                secrets=[_secret("tg_bot_token"), _secret("tg_socks_password")],
                mem=256 * MIB,
                cpus=0.25,
            ),
            "jobs": _service(
                "jobs",
                WEB_DIGEST_IMAGE,
                {"tbot-backend": None},
                secrets=[_secret("db_url")],
                mem=512 * MIB,
                cpus=0.5,
            ),
            "caddy": _service(
                "caddy",
                CADDY_DIGEST_IMAGE,
                {"tbot-public": None},
                ports=[_port(80, "80"), _port(443, "443"), _port(443, "443", "udp")],
                mem=128 * MIB,
                cpus=0.25,
            ),
        },
        "secrets": {
            "db_password": {"name": "tbot_db_password"},
            "db_url": {"name": "tbot_db_url"},
            "tg_bot_token": {"name": "tbot_tg_bot_token"},
            "tg_socks_password": {"name": "tbot_tg_socks_password"},
        },
    }


def _imap(модель: dict[str, Any]) -> dict[str, Any]:
    return {item.name: item for item in check.collect_checks(модель)}


def test_эталонный_состав_проходит_все_проверки() -> None:
    результаты = check.collect_checks(_model())
    assert результаты, "проверок не должно быть пустым списком"
    упавшие = [f"{item.name}: {item.detail}" for item in результаты if not item.ok]
    assert not упавшие, "эталон обязан сходиться: " + "; ".join(упавшие)


def test_лишняя_публикация_у_web_отклоняется() -> None:
    """Порт, опубликованный Docker'ом, доступен снаружи независимо от ufw — это дыра периметра.

    Память проекта: `[[docker-networking]]`. Проверка обязана сработать и для короткой строковой
    формы публикации, которую тоже отдаёт compose.
    """
    модель = _model()
    модель["services"]["web"]["ports"] = [_port(8080, "8080")]
    проверка = _imap(модель)["ports_only_proxy"]
    assert not проверка.ok
    assert "8080:8080" in проверка.detail
    assert "web" in проверка.detail

    модель = _model()
    модель["services"]["postgres"]["ports"] = ["5432:5432"]
    проверка = _imap(модель)["ports_only_proxy"]
    assert not проверка.ok, "строковая форма публикации должна пониматься так же"
    assert "postgres" in проверка.detail


def test_прокси_обязан_слушать_и_80_и_443() -> None:
    """Без 80 не проходит HTTP-01 и не работает редирект HTTP→HTTPS (TZ §8.3)."""
    модель = _model()
    модель["services"]["caddy"]["ports"] = [_port(443, "443")]
    проверка = _imap(модель)["ports_proxy_publication"]
    assert not проверка.ok
    assert "80" in проверка.detail


def test_неожиданный_порт_у_прокси_отклоняется() -> None:
    модель = _model()
    модель["services"]["caddy"]["ports"] = [_port(80, "80"), _port(443, "443"), _port(8443, "8443")]
    assert not _imap(модель)["ports_proxy_publication"].ok


def test_http_3_без_udp_публикации_отклоняется() -> None:
    """`443:443` без `443:443/udp` — это обещанный и отсутствующий транспорт.

    Замер на площадке 2026-11-20: Caddyfile отдаёт `Alt-Svc: h3=":443"`, `ufw` пропускает
    443/udp, а публикаций UDP у Docker нет — на UDP/443 приходит ICMP port unreachable. Проверка
    обязана падать и на отсутствующем udp, и на udp без tcp (это был бы прокси без HTTPS).
    """
    модель = _model()
    модель["services"]["caddy"]["ports"] = [_port(80, "80"), _port(443, "443")]
    проверка = _imap(модель)["ports_proxy_publication"]
    assert not проверка.ok, "пропуск udp-публикации при объявленном h3 обязан быть красным"
    assert "443/udp" in проверка.detail or "443:443/udp" in проверка.detail

    модель = _model()
    модель["services"]["caddy"]["ports"] = [_port(80, "80"), _port(443, "443", "udp")]
    assert not _imap(модель)["ports_proxy_publication"].ok, "udp без tcp — это не HTTPS-периметр"


def test_протокол_публикации_не_теряется() -> None:
    """Строковая и объектная формы обязаны различать tcp и udp."""
    модель = _model()
    модель["services"]["web"]["ports"] = ["8080:8080", "8080:8080/udp"]
    проверка = _imap(модель)["ports_only_proxy"]
    assert not проверка.ok
    assert "8080:8080/tcp" in проверка.detail
    assert "8080:8080/udp" in проверка.detail, "строковая форма обязана различать протоколы"


def test_образ_без_digest_отклоняется() -> None:
    модель = _model()
    модель["services"]["web"]["image"] = "ghcr.io/rusiksoft-afk/tbot-web:0.2.0"
    проверка = _imap(модель)["images_by_digest"]
    assert not проверка.ok
    assert "web" in проверка.detail


def test_образ_базы_тоже_обязан_быть_по_digest() -> None:
    модель = _model()
    модель["services"]["postgres"]["image"] = "postgres:16.4"
    assert not _imap(модель)["images_by_digest"].ok


def test_оставшаяся_сборка_в_составе_отклоняется() -> None:
    """Так выглядел первый прогон `prod-config`: `!reset null` в overlay не дожил до разбора."""
    модель = _model()
    модель["services"]["engine"]["build"] = {"context": ".", "dockerfile": "deploy/Dockerfile"}
    проверка = _imap(модель)["no_local_build"]
    assert not проверка.ok
    assert "engine" in проверка.detail


def test_ключ_build_даже_со_значением_null_отклоняется() -> None:
    """`build: null` в разобранном составе — не «сборки нет», а попытка её отключить.

    Разница между «ключа нет» и «ключ есть со значением null» — ровно та стена, на которой
    compose v5.1.3 оставил context/dockerfile из базового файла. Проверка не даёт решить,
    что достаточно дописать тег: `build` обязан исчезнуть из боевого разбора целиком.
    """
    модель = _model()
    модель["services"]["web"]["build"] = None
    проверка = _imap(модель)["no_local_build"]
    assert not проверка.ok, "пустой `build` принят как «сборки нет»"
    assert "web" in проверка.detail


def test_в_эталоне_боевого_разбора_ключа_build_нет_ни_у_одного_сервиса() -> None:
    """Иначе предыдущие два теста проверяют отсутствие ключа, которого в модели нет вовсе."""
    for name, spec in _model()["services"].items():
        assert "build" not in spec, f"{name}: в эталоне появился build"


def test_сеть_с_egress_у_базы_отклоняется() -> None:
    """Слияние `networks` идёт по имени сети: статически этого не увидеть."""
    модель = _model()
    модель["services"]["postgres"]["networks"]["tbot-egress"] = None
    проверка = _imap(модель)["egress_denied"]
    assert not проверка.ok
    assert "postgres" in проверка.detail
    assert "tbot-egress" in проверка.detail


def test_прокси_без_egress_отклоняется_из_за_acme() -> None:
    модель = _model()
    модель["services"]["caddy"]["networks"] = {"tbot-edge": None}
    проверка = _imap(модель)["proxy_has_egress"]
    assert not проверка.ok
    assert "ACME" in проверка.detail


def test_tgbot_и_engine_не_считаются_нарушением_egress() -> None:
    """Им исходящий трафик нужен (брокер и Telegram): список запрета не должен их задевать."""
    assert _imap(_model())["egress_denied"].ok


@pytest.mark.parametrize("сервис", ["migrate", "jobs", "postgres"])
def test_каждому_из_запрещённых_сервисов_egress_запрещён(сервис: str) -> None:
    """Список запрета работает целиком: выпадение сервиса из него ловится здесь.

    Иначе `jobs`, добавленный в сеть с исходящим трафиком, прошёл бы незамеченным, а именно
    воркер бэктеста — самый вероятный кандидат «потихоньку разрешить доступ в интернет». Список
    сервисов здесь записан руками, а не взят из константы: иначе проверка «построй модель для
    каждого запрещённого сервиса» тихо сжималась бы вместе с константой.
    """
    assert сервис in check.MUST_HAVE_NO_EGRESS, f"{сервис} выпал из списка запрета"
    модель = _model()
    модель["services"][сервис]["networks"]["tbot-egress"] = None
    проверка = _imap(модель)["egress_denied"]
    assert not проверка.ok, f"{сервис} получил egress, а проверка молчит"
    assert сервис in проверка.detail


def test_списки_запрета_и_разрешения_полны_и_не_пересекаются() -> None:
    """Состав списков — предмет решения, а не следствие кода проверки.

    Постоянные процессы стенда известны: если в состав добавят новый сервис, он не должен
    «получить» разрешение по умолчанию.
    """
    assert sorted(check.MUST_HAVE_NO_EGRESS) == ["jobs", "migrate", "postgres"]
    assert sorted(check.SECRETS_BY_SERVICE) == sorted(_model()["services"])
    assert sorted(check.ALLOWED_EXTERNAL_NETWORKS) == ["tbot-egress", "tbot-public"]
    assert check.HOST_VCPU == 2.0, "число ядер площадки (OQ-11) поменялось — пересчитать лимиты"


def test_новая_сеть_с_исходящим_трафиком_требует_решения() -> None:
    """Появление третьей внешней сети — это изменение политики, оно обязана быть замечено."""
    модель = _model()
    модель["networks"]["tbot-sidecar"] = {"name": "tbot_tbot-sidecar", "driver": "bridge"}
    проверка = _imap(модель)["external_networks_expected"]
    assert not проверка.ok
    assert "tbot-sidecar" in проверка.detail


def test_лишний_секрет_у_процесса_отклоняется() -> None:
    модель = _model()
    модель["services"]["caddy"]["secrets"] = [_secret("db_url")]
    проверка = _imap(модель)["secrets_per_service"]
    assert not проверка.ok
    assert "db_url" in проверка.detail


def test_пропущенный_секрет_у_процесса_отклоняется() -> None:
    """Без SOCKS-пароля tgbot уйдёт в прямой вход в Telegram (TZ §10.7) — это отказ, а не «тихо работает»."""
    модель = _model()
    модель["services"]["tgbot"]["secrets"] = [_secret("tg_bot_token")]
    проверка = _imap(модель)["secrets_per_service"]
    assert not проверка.ok
    assert "tg_socks_password" in проверка.detail


def test_секреты_в_строковой_форме_тоже_понимаются() -> None:
    модель = _model()
    модель["services"]["postgres"]["secrets"] = ["db_password"]
    assert _imap(модель)["secrets_per_service"].ok


def test_лимит_памяти_выше_потолка_тз_отклоняется() -> None:
    модель = _model()
    модель["services"]["caddy"]["mem_limit"] = 512 * MIB
    проверка = _imap(модель)["resource_limits"]
    assert not проверка.ok
    assert "caddy" in проверка.detail
    assert "ТЗ" in проверка.detail


def test_отсутствующий_лимит_памяти_отклоняется() -> None:
    """Без потолка OOM-killer выбирает самое крупное — то есть базу (TZ §14.9)."""
    модель = _model()
    del модель["services"]["engine"]["mem_limit"]
    проверка = _imap(модель)["resource_limits"]
    assert not проверка.ok
    assert "engine" in проверка.detail


def test_каждый_лимит_по_отдельности_разрешён_но_вместе_не_влезает() -> None:
    """Правило про бюджет площадки: значения ТЗ рассчитаны на 8 vCPU/16 ГиБ, у нас 3.8 ГиБ (OQ-11).

    web поднят до потолка ТЗ (512 МиБ), postgres — до 1.5 ГиБ: оба значения не выше TZ §14.6, а
    сумма уже не оставляет памяти ядру и xray-туннелю.
    """
    модель = _model()
    модель["services"]["web"]["mem_limit"] = 512 * MIB
    модель["services"]["postgres"]["mem_limit"] = int(1.5 * 1024 * MIB)
    проверка = _imap(модель)["resource_limits"]
    assert not проверка.ok
    assert "бюджет" in проверка.detail


def test_сумма_фактических_лимитов_уложена_в_бюджет_с_запасом() -> None:
    """Отдельный смысл: запас между суммой лимитов и бюджетом площадки обязан существовать."""
    модель = _model()
    сумма = sum(int(модель["services"][имя]["mem_limit"]) for имя in check.MEM_CEILING_BYTES)
    assert сумма < check.HOST_MEM_BUDGET_BYTES
    проверка = _imap(модель)["resource_limits"]
    assert проверка.ok
    assert str(сумма // MIB) in проверка.detail


def test_лимит_cpu_выше_потолка_тз_отклоняется() -> None:
    модель = _model()
    модель["services"]["engine"]["cpus"] = 2.5
    проверка = _imap(модель)["cpu_limits"]
    assert not проверка.ok
    assert "engine" in проверка.detail


def test_сумма_потолков_cpu_сверх_бюджета_ядер_отклоняется() -> None:
    модель = _model()
    for имя, потолок in check.CPU_CEILING.items():
        модель["services"][имя]["cpus"] = потолок
    проверка = _imap(модель)["cpu_limits"]
    assert not проверка.ok
    assert "vCPU" in проверка.detail


def test_отсутствующий_лимит_cpu_отклоняется() -> None:
    модель = _model()
    del модель["services"]["caddy"]["cpus"]
    проверка = _imap(модель)["cpu_limits"]
    assert not проверка.ok
    assert "caddy" in проверка.detail


def test_размеры_памяти_в_строковой_форме_понимаются() -> None:
    """compose отдаёт `mem_limit` то числом байтов, то строкой с суффиксом — понимать надо оба."""
    for значение, ожидание in (
        ("128m", 128 * MIB),
        ("128M", 128 * MIB),
        ("1g", 1024 * MIB),
        (128 * MIB, 128 * MIB),
        ("128x", None),
        ("", None),
    ):
        assert check.limit_bytes(значение) == ожидание, f"{значение!r} разобрано неверно"


def test_строковый_лимит_в_составе_проходит_проверку() -> None:
    модель = _model()
    модель["services"]["caddy"]["mem_limit"] = "128m"
    assert _imap(модель)["resource_limits"].ok
    модель["services"]["caddy"]["mem_limit"] = "128 мебибайт"
    проверка = _imap(модель)["resource_limits"]
    assert not проверка.ok
    assert "caddy" in проверка.detail


def test_restart_отличный_от_always_отклоняется() -> None:
    модель = _model()
    модель["services"]["caddy"]["restart"] = "unless-stopped"
    проверка = _imap(модель)["restart_always"]
    assert not проверка.ok
    assert "caddy" in проверка.detail


def test_grace_остановки_engine_ниже_шестидесяти_секунд_это_замечание() -> None:
    """Не блокирующий уровень: без 60 секунд ядро не успевает записать состояние (TZ §7.6)."""
    модель = _model()
    модель["services"]["engine"]["stop_grace_period"] = "10s"
    проверка = _imap(модель)["engine_stop_grace"]
    assert not проверка.ok
    assert проверка.severity == check.WARN


def test_grace_в_нормализованном_виде_compose_принимается() -> None:
    """`60s` в файле compose выводит как `1m0s` — проверка обязана принимать обе записи."""
    for запись in ("60s", "1m", "1m0s"):
        модель = _model()
        модель["services"]["engine"]["stop_grace_period"] = запись
        assert _imap(модель)["engine_stop_grace"].ok, запись
    модель = _model()
    del модель["services"]["engine"]["stop_grace_period"]
    assert not _imap(модель)["engine_stop_grace"].ok


def test_открытый_rootfs_отклоняется() -> None:
    модель = _model()
    модель["services"]["caddy"]["read_only"] = False
    проверка = _imap(модель)["read_only_rootfs"]
    assert not проверка.ok
    assert "caddy" in проверка.detail


def test_проверка_не_ломается_если_сервиса_нет_в_составе() -> None:
    """Удаление сервиса из состава — это изменение состава, оно обязано быть замечено, а не схлопнуто."""
    модель = _model()
    del модель["services"]["jobs"]
    результаты = _imap(модель)
    assert not результаты["resource_limits"].ok
    assert "jobs" in результаты["resource_limits"].detail
    assert not результаты["cpu_limits"].ok


def test_main_ноль_на_этлоне_и_единица_на_отклонении(tmp_path: Path) -> None:
    эталон = tmp_path / "prod-config.json"
    эталон.write_text(json.dumps(_model(), ensure_ascii=False), encoding="utf-8")
    assert check.main([f"--model={эталон}"]) == 0

    сломанный = tmp_path / "leak.json"
    модель = _model()
    модель["services"]["web"]["ports"] = [_port(8080, "8080")]
    сломанный.write_text(json.dumps(модель, ensure_ascii=False), encoding="utf-8")
    assert check.main([f"--model={сломанный}"]) == 1


def test_main_два_если_снимок_не_читается(tmp_path: Path) -> None:
    """Отсутствующий или битый снимок — это отдельный код возврата: «проверка не выполнена»."""
    битый = tmp_path / "broken.json"
    битый.write_text("{это не json", encoding="utf-8")
    assert check.main([f"--model={битый}"]) == 2
    assert check.main([f"--model={tmp_path / 'нет-такого-файла.json'}"]) == 2


def test_вывод_json_отражает_итог(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    эталон = tmp_path / "prod-config.json"
    эталон.write_text(json.dumps(_model(), ensure_ascii=False), encoding="utf-8")
    assert check.main([f"--model={эталон}", "--json"]) == 0
    данные = json.loads(capsys.readouterr().out)
    assert данные["ok"] is True
    имена = {item["name"] for item in данные["checks"]}
    assert {"ports_only_proxy", "egress_denied", "images_by_digest"} <= имена


def test_потолки_скрипта_не_ниже_фактических_лимитов_боевого_compose() -> None:
    """Два артефакта хранят одни и те же границы: расходится может только фактический лимит.

    `scripts/prod_compose_check.py` задаёт потолки ТЗ §14.6, `deploy/compose.prod.yaml` выставляет
    лимиты под площадку (они обязаны быть НЕ ВЫШЕ потолков, OQ-11). Если лимит в compose поднимут
    выше потолка, проверка «лимиты в бюджете» превратилась бы в самоподтверждение — здесь это
    ловится напрямую.
    """
    overlay = load_compose_yaml(COMPOSE_PROD)["services"]
    суммы = 0
    for имя, потолок in check.MEM_CEILING_BYTES.items():
        факт = check.limit_bytes(overlay[имя]["mem_limit"])
        assert факт is not None, f"{имя}: mem_limit в compose неразбираем"
        assert факт <= потолок, f"{имя}: лимит compose {факт} выше потолка скрипта {потолок}"
        суммы += факт
        процессор = float(overlay[имя]["cpus"])
        assert процессор <= check.CPU_CEILING[имя], f"{имя}: cpus compose выше потолка скрипта"
    assert (
        суммы <= check.HOST_MEM_BUDGET_BYTES
    ), f"сумма лимитов compose {суммы // MIB} МиБ не влезает в бюджет {check.HOST_MEM_BUDGET_BYTES // MIB} МиБ"


def test_модуль_не_использует_subprocess_и_не_требует_подавлений() -> None:
    """Без `subprocess` скрипту не нужны `nosec` — базовый уровень подавлений (14) не растёт."""
    текст = (SCRIPTS / "prod_compose_check.py").read_text(encoding="utf-8")
    assert "import subprocess" not in текст
    assert "subprocess." not in текст
