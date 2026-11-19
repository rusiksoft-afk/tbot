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

ROOT = Path(__file__).resolve().parents[2]
CI_FILE = ROOT / ".github" / "workflows" / "ci.yml"
IMAGE_FILE = ROOT / ".github" / "workflows" / "image.yml"

REQUIRED_JOBS: tuple[str, ...] = (
    "quality",
    "tests",
    "migrations",
    "secret-scan",
    "audit",
    "compose-smoke",
    "deploy-check",
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
