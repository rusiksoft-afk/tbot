"""Контрактный тест на файлы CI: их сначала читает GitHub, а не человек.

Ошибка в YAML workflow'ах не видна ни `ruff`, ни `mypy`, ни локальными тестами — она
проявляется только в момент запуска, когда коммит уже в `main`. Поэтому структура и ключевые
константы проверяются здесь: парсинг YAML, обязательные job'ы, и главное — базовый уровень
подавлений проверок должен совпадать с фактическим числом в дереве (в CI за этим следит шаг
`suppress-growth`; здесь мы ловим расхождение до коммита).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.paths import COMPOSE_PROD, load_compose_yaml

ROOT = Path(__file__).resolve().parents[2]
_LIVE_DIR = Path(__file__).resolve().parents[1] / "integration"
CI_FILE = ROOT / ".github" / "workflows" / "ci.yml"
IMAGE_FILE = ROOT / ".github" / "workflows" / "image.yml"
PROD_ENV_FILE = ROOT / "deploy" / "tbot.prod.env"

REQUIRED_JOBS: tuple[str, ...] = (
    "quality",
    "tests",
    "migrations",
    "secret-scan",
    "audit",
    "compose-smoke",
    "prod-config",
    "deploy-check",
    "broker-tls",
)


def _load(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), f"{path.name}: ожидаем отображение верхнего уровня"
    return payload


@pytest.mark.parametrize("path", [CI_FILE, IMAGE_FILE], ids=["ci.yml", "image.yml"])
def test_workflow_разбирается_как_yaml(path: Path) -> None:
    # Именно эта проверка поймала первую версию ci.yml: unquoted `name:` со двоеточием внутри
    # делала workflow непарсируемым, и падение было видно только в GitHub.
    payload = _load(path)
    assert "jobs" in payload, f"{path.name}: нет секции jobs"


def test_обязательные_job_ы_присутствуют_и_описаны() -> None:
    jobs = _load(CI_FILE)["jobs"]
    missing = [name for name in REQUIRED_JOBS if name not in jobs]
    assert not missing, f"в CI нет job'ов: {missing}"
    for name, spec in jobs.items():
        assert "runs-on" in spec, f"job {name}: нет runs-on"
        steps = spec.get("steps")
        assert isinstance(steps, list), f"job {name}: шаги должны быть списком"
        assert steps, f"job {name}: нет шагов"


def test_базовый_уровень_подавлений_совпадает_с_фактом() -> None:
    """Число в workflow и число в дереве не имеют права разъезжаться.

    Рост без объяснения запрещён (см. `docs/acceptance/m0-quality.md §2`), но и занижать
    базовый уровень молча нельзя: тогда шаг `suppress-growth` перестанет что-то охранять.
    Счётчик один — `scripts/count_suppressions.py`; он же используется в CI, поэтому проверка
    не зависит от совпадения двух копий регулярного выражения.
    """
    env = _load(CI_FILE).get("env", {})
    declared = int(str(env["SUPPRESSION_BASELINE"]))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "count_suppressions.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    actual = int(completed.stdout.strip().splitlines()[-1])
    assert declared == actual, (
        f"SUPPRESSION_BASELINE={declared}, а в дереве {actual} — обнови значение вместе "
        "с объяснением в описании PR и в инвентаризации подавлений"
    )


def test_стенд_в_ci_использует_каталог_секретов_compose() -> None:
    """Compose разрешает `./secrets/...` относительно deploy/compose.yaml.

    Если CI положит секреты в корень репозитория, стенд стартует с пустым `/run/secrets`, и
    `web` не пройдёт `/readyz` — то есть job будет падать по причине, не связанной с кодом.
    """
    jobs = _load(CI_FILE)["jobs"]
    steps = jobs["compose-smoke"]["steps"]
    script = "\n".join(str(step.get("run", "")) for step in steps)
    assert "mkdir -p deploy/secrets" in script
    for name in ("db_password", "db_url", "tg_bot_token", "tg_socks_password"):
        assert f"deploy/secrets/{name}" in script, f"секрет {name} не создаётся в нужном каталоге"


def test_порог_покрытия_в_конфиге_не_ниже_обещанного() -> None:
    """Порог покрытия задаётся один раз (pyproject), и он не должен «тихо» падать."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"fail_under\s*=\s*([0-9.]+)", pyproject)
    assert match, "в pyproject.toml нет fail_under для coverage"
    assert float(match.group(1)) >= 80.0, "порог покрытия ниже обещанного в TZ §4"


def test_пробы_внутри_контейнера_базы_не_требуют_инструментов_которых_в_нём_нет() -> None:
    """В образе postgres нет python3 — debian-slim без recommends, пакетов Python там нет.

    Шаг «у контейнера базы нет исходящего трафика» запускает пробу внутри контейнера базы;
    с `python3` он падал бы на `executable file not found`, то есть приёмка egress вообще
    не выполнялась бы. Разрешены только bash (он есть в образе — entrypoint написан на bash)
    и coreutils.
    """
    steps = _load(CI_FILE)["jobs"]["compose-smoke"]["steps"]
    probes = [
        str(step.get("run", "")) for step in steps if "exec -T postgres" in str(step.get("run", ""))
    ]
    assert probes, "проверка egress контейнера базы пропала из job `compose-smoke`"
    for script in probes:
        assert "postgres bash" in script, "проба внутри базы должна запускать bash"
        for missing in ("python3", "curl", "wget", "nc "):
            assert missing not in script, f"в образе postgres нет {missing.strip()}"


def test_приёмка_стенда_требует_readyz_у_web_и_engine() -> None:
    """Приёмка T-005 — «/readyz 200 у web и engine»: пробы должны быть явными.

    Healthcheck engine тоже ходит на `/readyz`, но выводить приёмку из этого косвенно нельзя:
    `up --wait` прошёл бы и при liveness-ручке, если бы шаг приёмки её подменил.
    """
    steps = _load(CI_FILE)["jobs"]["compose-smoke"]["steps"]
    runs = [str(step.get("run", "")) for step in steps if step.get("run")]
    joined = "\n".join(runs)
    probe = "python -m packages.common.health_probe"
    for svc, port in (("web", 8080), ("engine", 9101)):
        assert (
            f"exec -T {svc} {probe} --url http://127.0.0.1:{port}/readyz" in joined
        ), f"в compose-smoke нет строгой readiness-пробы {svc}:{port}/readyz"
    for port in (9101, 9103):
        assert f"{probe} --liveness --url http://127.0.0.1:{port}/healthz" in joined, port


def _runs(job: str) -> str:
    """Все shell-скрипты job'а одним текстом: так удобно искать признаки приёмочной проверки."""
    steps = _load(CI_FILE)["jobs"][job]["steps"]
    return "\n".join(str(step.get("run", "")) for step in steps if step.get("run"))


def test_приёмка_доверия_к_брокеру_покрывает_обе_половины_условия() -> None:
    """AC-broker-gateway-02 (T-006): «без корня — падает, с корнем — работает».

    Отдельного шага «корень установлен» в CI нет, поэтому обе половины закрепляются текстом
    job'ов: отрицательная — пробой без якоря и ассертом в job `deploy-check`, положительная —
    пробой с закреплённым корнём и проверкой системного набора доверия в образе.
    """
    broker_tls = _runs("broker-tls")
    for marker in (
        "--expect unverified",
        "--expect verified",
        "--extra-ca deploy/ca/ru-trusted-root-ca.pem",
        "python scripts/ca_policy.py",
    ):
        assert marker in broker_tls, f"в job `broker-tls` пропало {marker!r}"

    platform_run = _runs("deploy-check")
    assert "не имеет права быть зелёной" in platform_run, (
        "в job `deploy-check` пропал ассерт «без корня НУЦ broker_tls обязан падать» — "
        "именно он не даёт тихо отключить проверку сертификата"
    )

    stand = _runs("compose-smoke")
    assert "ca-certificates.crt" in stand, "проверка системного набора доверия образа пропала из CI"
    assert "ca_policy.py --print-fingerprint" in stand, "отпечаток в compose-smoke должен быть один"


def test_отпечаток_корня_не_дублируется_вне_политики() -> None:
    """Закреплённый якорь живёт в `scripts/ca_policy.py` ровно один раз.

    Копия отпечатка в workflow или Dockerfile — это будущая тихая рассинхронизация: CI начнёт
    проверять старый корень, а приложение ходить по новому, и зелённый прогон будет врать.
    В документации отпечаток разрешён: это инструкция для человека, который ставит корень руками.
    """
    policy = (ROOT / "scripts" / "ca_policy.py").read_text(encoding="utf-8")
    pinned = re.findall(r"\b[0-9a-f]{64}\b", policy)
    assert (
        len(pinned) == 1
    ), f"в ca_policy.py ожидался один закреплённый отпечаток, найдено {pinned}"

    checked: list[Path] = [
        CI_FILE,
        IMAGE_FILE,
        ROOT / "deploy" / "Dockerfile",
        ROOT / "deploy" / "compose.yaml",
        ROOT / "deploy" / "compose.override.yaml",
        ROOT / "scripts" / "deploy_check.py",
        ROOT / "scripts" / "tls_trust_probe.py",
    ]
    for path in checked:
        assert not re.search(r"\b[0-9a-f]{64}\b", path.read_text(encoding="utf-8")), (
            f"{path.relative_to(ROOT)}: отпечаток корня закреплён ещё и здесь — должен быть один "
            "источник (scripts/ca_policy.py)"
        )


def _scripts_of(job: str) -> str:
    """Скрипты всех шагов job'а одним текстом — так удобнее искать договорённости шагов."""
    steps = _load(CI_FILE)["jobs"][job]["steps"]
    return "\n".join(str(step.get("run", "")) for step in steps)


def test_боевой_состав_разбирается_в_ci_а_не_только_руками() -> None:
    """`compose-smoke` поднимает dev-стенд; боевой overlay не исполняется нигде, кроме CI.

    Без шага разбора расхождение в `deploy/compose.prod.yaml` (первая же ошибка — разрыв
    слияния overlay: лишняя публикация порта или сеть с egress у базы) обнаружилось бы только на
    площадке, то есть в момент деплоя.
    """
    script = _scripts_of("prod-config")
    assert (
        "deploy/compose.yaml" in script
    ), "job `prod-config` обязан разбирать состав базовым файлом, как это делает площадка"
    assert (
        "deploy/compose.prod.yaml" in script
    ), "job `prod-config` обязан разбирать состав боевым overlay, как это делает площадка"
    assert "--env-file deploy/tbot.prod.env" in script, (
        "digest берутся из deploy/tbot.prod.env: без `--env-file` compose подставил бы пустые "
        "значения и проверял не тот состав, что пойдёт на площадку"
    )
    assert "config" in script


def test_проверки_разобранного_состава_живут_в_скрипте_а_не_в_workflow() -> None:
    """Логика проверок обязана быть покрываемой офлайн-тестами.

    Вставка `python <<PY …` прямо в workflow не видит ни `mypy`, ни `pytest`, ни покрытие: такой
    шаг постепенно «зарастает» утверждениями, которые никто не исполнял. Поэтому шаг CI только
    вызывает `scripts/prod_compose_check.py`, а его поведение закреплено в
    `tests/unit/test_prod_compose_check.py`.
    """
    script = _scripts_of("prod-config")
    assert (
        "python3 scripts/prod_compose_check.py" in script
    ), "job `prod-config` обязан проверять разбор через скрипт из репозитория"
    assert (
        "<<'PY'" not in script
    ), "проверки разобранного состава переехали обратно в workflow: их нечем покрыть тестами"


def test_разбор_боевого_состава_не_требует_боевых_секретов() -> None:
    """Job не имеет права обращаться к repository secrets: пустышки создаёт сам шаг.

    `compose config` требует, чтобы файлы секретов существовали. Если вместо подставных файлов
    шагу выдать настоящие секреты площадки, они попадут в логи и в кэш раннёра — то есть job
    станет источником компрометации (TZ §8.4).
    """
    script = _scripts_of("prod-config")
    assert (
        "secrets." not in script
    ), "job `prod-config` обратился к секретам репозитория — состав обязан разбираться на пустышках"
    ожидаемые = {
        str(spec["file"])
        for spec in load_compose_yaml(COMPOSE_PROD)["secrets"].values()
        if isinstance(spec, dict) and spec.get("file")
    }
    assert ожидаемые, "в deploy/compose.prod.yaml не осталось файловых секретов"
    for путь in ожидаемые:
        assert путь in script or путь.removeprefix("/etc/tbot/secrets/") in script, (
            f"секрет {путь} не создаётся в job `prod-config` — `compose config` упадёт на "
            "отсутствующем файле, а не на ошибке в составе"
        )


def test_скрипт_ввода_секретов_прогоняется_на_фиктивных_значениях() -> None:
    """Механизм ввода секретов проверяется в CI, значения — нет.

    Настоящие значения в job попасть не могут (TZ §8.4, стоп-лист `AGENTS.md`), но класс ошибок у
    такого скрипта одинаковый и на фиктивных, и на боевых: дописанный перевод строки ломает и DSN,
    и токен; режим 644 читается любой учёткой на хосте; перепутанный порядок ответов кладёт токен в
    чужой файл; значение не по форме (11 цифр вместо DSN, 11 символов вместо PAT, пароль с
    пробелами — замер 2026-11-20 на площадке) проходит как «готово» и рвётся уже на `pull` и
    `migrate`. Поэтому шаг: (а) требует отказа по форме без записи файлов, (б) прогоняет штатный
    ввод с генерацией пароля и сборкой `db_url`, (в) требует совпадения пароля внутри `db_url`,
    (г) проверяет вердикты `--check`, включая отдельную строку про файл туннеля, (д) требует
    падения `--check` на испорченном режиме.
    """
    script = _scripts_of("prod-config")
    assert (
        "script=deploy/vps/secrets-setup.sh" in script
    ), "job `prod-config` не исполняет эталонный скрипт ввода секретов"
    assert (
        script.count('bash "$script"') >= 3
    ), "мало прогонов: нужны отказ по форме, штатная запись и как минимум один `--check`"
    assert "--check" in script, "нет режима проверки готовности"
    assert "--force" in script, (
        "в CI нет терминала: без явного `--force` скрипт обязан отказаться писать файлы — "
        "молчаливая запись из неинтерактивного прогона была бы хуже отказа"
    )
    assert (
        "not a valid password with spaces" in script
    ), "нет фиктивного пароля с пробелами: ровно такой `db_password` лежал на площадке 2026-11-20"
    assert (
        "79135791350" in script
    ), "нет фиктивного значения «11 цифр»: именно так выглядели испорченные db_url и ghcr_token"
    assert 'if [ -e "$tmp/$name" ]' in script, (
        "отказ по форме обязан сопровождаться проверкой, что файлы не созданы: «сообщили о "
        "проблеме и всё равно записали» — тот же дефект"
    )
    assert "PYFIX_OK" in script, (
        "прогон обязан покрывать штатный ввод с пустым db_password: генерация пароля и сборка "
        "db_url из него — тот путь, который не оставляет рассинхона пары файлов"
    )
    assert "chr(58)" in script, (
        "двоеточие в фиктивном токене бота обязано появляться на месте из chr(58): иначе в "
        "файле workflow лежит строка, неотличимая от настоящего токена (её запрещает "
        "test_no_forbidden_references)"
    )
    assert not re.search(r"[0-9]{6,12}:[A-Za-z0-9_-]{35}", script), (
        "в теле job нашлась готовая пара «идентификатор бота:хвост» — фиктивный токен "
        "обязан собираться из частей прямо в прогоне"
    )
    assert (
        "сгенерирован автоматически" in script
    ), "в прогоне не проверяется, что пароль базы действительно сгенерирован, а не запрошен"
    assert "DSN_MATCH" in script, (
        "без проверки, что пароль из db_password встречается внутри db_url, рассинхон пары "
        "файлов остаётся невидимым до падения migrate"
    )
    assert "telegram_socks_pass" in script, (
        "`--check` в CI обязан видеть пятый файл состава: его создаёт T-714, и отсутствие "
        "должно быть отличием, а не тишиной"
    )
    assert "chmod 644" in script, (
        "нет негативной пробы: `--check` обязан отклонять испорченный режим, иначе его "
        "зелёный вывод ничего не значит"
    )
    assert "--remed" in script, (
        "нет прогона `--remed`: переход площадки на политику прав ADR-005 обязан быть проверен, "
        "включая то, что значения файлов при этом не меняются"
    )
    assert '"$before" != "$after"' in script, (
        "`--remed` обязан сверять контрольные суммы файлов: иначе «привести права» легко "
        "превращается в перезапись значений"
    )
    assert 'stat -c %a "$tmp/db_url")" -eq 640' in script, (
        "режим 640 у монтируемого в контейнер секрета — часть контракта ADR-005: 600 даёт "
        "PermissionError в процессе под uid/gid 10001"
    )
    assert "0:10001" in script, "gid процесса из Dockerfile не сверяется в прогоне секретов"
    assert (
        "TBOT_SECRETS_SETUP_DIR" in script
    ), "каталог для прогона задаётся явным именем, чтобы не трогать /etc/tbot/secrets раннёра"
    assert "TBOT_SECRETS_DIR=" not in script, (
        "в других job есть своя переменная TBOT_SECRETS_DIR (каталог секретов приложения): "
        "скрипт ввода не имеет права её перехватывать"
    )
    assert "secrets." not in script, (
        "секреты репозитория GitHub в этот job не попадают: значения фиктивные, боевые секреты "
        "не должны появляться в журнале или кэше"
    )


def test_caddyfile_валидируется_образом_из_env_файла_и_без_доступа_в_сеть() -> None:
    """Тот же бинарник и тот же путь, что на площадке, — и никаких обращений наружу.

    Digest вычитывается из `deploy/tbot.prod.env`, а не переписывается в workflow: копия
    указателя в двух местах обязательно разъедется, и CI начнёт валидировать не тот образ,
    который запускается (тот же смысл у проверки отпечатка корня). `--network none` держит
    шаг подальше от ACME: валидация конфигурации не должна выпускать сертификат.
    """
    script = _scripts_of("prod-config")
    assert (
        '--entrypoint caddy "caddy@$caddy_digest"' in script
    ), "валидировать обязан тот же образ с закреплённым digest, который запускается на площадке"
    assert (
        "^CADDY_DIGEST=" in script
    ), "digest образа Caddy обязан приходить из deploy/tbot.prod.env"
    assert re.search(r"\b[0-9a-f]{64}\b", script) is None, (
        "в job `prod-config` появился закреплённый digest прямо в workflow: единственный "
        "источник указателей — deploy/tbot.prod.env"
    )
    assert "--network none" in script
    assert (
        "--config /etc/caddy/Caddyfile" in script
    ), "валидировать надо тот путь, на котором Caddyfile стоит в контейнере площадки"


def test_каждая_живая_проверка_базы_имеет_свой_шаг_в_ci() -> None:
    """Ни один файл живых проверок базы не должен остаться без шага.

    Причина не в аккуратности: живой файл, который никто не вызывает, выглядит как покрытие.
    Локально на Windows он пропускается (`TBOT_DB_URL` нет), поэтому «проверка есть» без шага в
    job'е `migrations` не значит ничего. Шаг обязан вызывать pytest с `-rs`: группа, которая молча
    пропускается, неотличима от группы, которая прошла.
    """
    runs = [str(step.get("run", "")) for step in _load(CI_FILE)["jobs"]["migrations"]["steps"]]
    live = sorted(path.name for path in _LIVE_DIR.glob("*_db.py"))
    assert live, "каталог с живыми проверками пуст — проверка потеряла смысл"
    unregistered = [name for name in live if not any(name in run for run in runs)]
    assert (
        not unregistered
    ), f"эти живые файлы не исполняются ни одним шагом job'а `migrations`: {unregistered}"
    silent = [name for name in live if not any(name in run and "-rs" in run for run in runs)]
    assert not silent, (
        f"шаг, исполняющий {silent}, не показывает пропуски (нет -rs): молча пропущенная группа "
        "неотличима от прошедшей"
    )
