"""Проверки секретов в `scripts/deploy_check.py`: имена файлов, права и **форма** значений.

Два повода для отдельных тестов, оба — из реальных замеров (не из предположений):

1. Зелёный `--check` скрипта ввода секретов на площадке 2026-11-20 не означал готовность: файлы
   были с правильными режимами, но значения оказались не по назначению — `db_url` из 11 цифр без
   схемы, `ghcr_token` из 11 символов (не PAT; обмен в `ghcr.io/token` ответил `401`),
   `db_password` 154 байта с пробелами, `telegram_token` не создан
   (`docs/acceptance/tls-edge.md §2.2`, строка 6). Presence-проверка этого не видит, а последствия
   наступают на деплое: `pull` не авторизуется, `migrate` не подключается.
2. `check_secret_files` искал на хосте имена **конфигурации** (`tg_bot_token`,
   `tg_socks_password`), тогда как хостовые файлы названы по `deploy/compose.prod.yaml`
   (`telegram_token`, `telegram_socks_pass`) → красный вывод при полностью готовой площадке
   (`docs/runbook/stand-deploy.md §8`).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.common.config import Contour, Settings
from tests.paths import SCRIPTS, load_script

deploy_check = load_script("deploy_check")

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="права и владелец файлов — только POSIX")

# Значения-маркеры: они участвуют и в проверке «вывод не содержит значения».
DB_PASSWORD = "Kx7RandomPass-1234"
DB_URL = f"postgresql+psycopg://tbot:{DB_PASSWORD}@postgres:5432/tbot"
TG_TOKEN = "1234567890:AAHabcdefghij_klmnopqrstuvwxy012345"
assert len(TG_TOKEN.split(":", 1)[1]) == 35, "хвост токена ровно 35 символа"
SOCKS_PASS = "sockspass-9182"
GHCR_TOKEN = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2"

# Подпись реального инцидента.
BAD_DB_URL = "79135791350"
BAD_TOKEN = "79135791350"
BAD_PASSWORD = "moy rabochiy parol bazy, " + "x" * 120

HOST_SET = {
    "db_password": DB_PASSWORD,
    "db_url": DB_URL,
    "telegram_token": TG_TOKEN,
    "telegram_socks_pass": SOCKS_PASS,
    "ghcr_token": GHCR_TOKEN,
}

DEV_SET = {
    "db_password": DB_PASSWORD,
    "db_url": DB_URL,
    "tg_bot_token": TG_TOKEN,
    "tg_socks_password": SOCKS_PASS,
}


def _settings(directory: Path, contour: Contour = Contour.SANDBOX) -> Settings:
    return Settings(
        secrets_dir=directory,
        contour=contour,
        instance_name="test",
        confirm_production=contour is Contour.PRODUCTION,
    )


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "secrets"
    directory.mkdir()
    return directory


def _fill(directory: Path, values: dict[str, str]) -> None:
    for name, value in values.items():
        path = directory / name
        path.write_bytes(value.encode("utf-8"))
        if os.name == "posix":
            path.chmod(0o600)


def test_слоты_знают_обе_пары_имён() -> None:
    """Логика выбора имён проверяется без файловой системы — она и на Windows, и на площадке."""
    keys = {slot.key for slot in deploy_check.SECRET_SLOTS}
    assert keys == {"db_password", "db_url", "telegram_token", "telegram_socks_pass", "ghcr_token"}
    by_key = {slot.key: slot for slot in deploy_check.SECRET_SLOTS}
    assert by_key["telegram_token"].names == ("telegram_token", "tg_bot_token")
    assert by_key["telegram_socks_pass"].names == ("telegram_socks_pass", "tg_socks_password")

    prod = _settings(Path("/etc/tbot/secrets"), Contour.PRODUCTION)
    sandbox = _settings(Path("deploy/secrets"), Contour.SANDBOX)
    # Боевой контур требует хостовые имена и ghcr_token; для песочцы они необязательны.
    assert deploy_check.slot_required(by_key["ghcr_token"], prod)
    assert not deploy_check.slot_required(by_key["ghcr_token"], sandbox)
    assert deploy_check.slot_required(by_key["telegram_token"], prod)
    # …а в не-боевом контуре достаточно любого имени слота — оно и есть в DEV_SET.
    assert any(
        (sandbox.secrets_dir / name).name in DEV_SET for name in by_key["telegram_token"].names
    )

    # Выбор имён по контуру — чистая логика без файловой системы. Проверяется здесь, а не в
    # POSIX-ветках, потому что на dev-машине те пропускаются, а дефект выбора имени всплыл
    # только в CI (раннер не root, файлы конфигурации закрыли собой «файла нет»).
    assert deploy_check.slot_names(by_key["telegram_token"], prod) == ("telegram_token",)
    assert deploy_check.slot_names(by_key["telegram_socks_pass"], prod) == ("telegram_socks_pass",)
    assert deploy_check.slot_names(by_key["telegram_token"], sandbox) == (
        "telegram_token",
        "tg_bot_token",
    )
    assert deploy_check.slot_foreign_names(by_key["telegram_token"], prod) == ("tg_bot_token",)
    assert deploy_check.slot_foreign_names(by_key["telegram_socks_pass"], prod) == (
        "tg_socks_password",
    )
    assert deploy_check.slot_foreign_names(by_key["telegram_token"], sandbox) == ()
    # Имена, которые различаются в двух парах, — только telegram_*: у db_* имена совпадают.
    for key in ("db_password", "db_url"):
        assert deploy_check.slot_names(by_key[key], prod) == by_key[key].names
        assert deploy_check.slot_foreign_names(by_key[key], prod) == ()


@POSIX_ONLY
def test_боевой_контур_требует_хостовые_имена_а_не_имена_конфигурации(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Имена лежат в каталоге площадки, а не внутри контейнера (`compose.prod.yaml`).

    Владелец замазан намеренно: тест про имена. Без подмены на Linux-раннере (uid 1001)
    первой претензией к `tg_bot_token` становился владелец, и проверка молчала о том, что
    файлового имени не хватает вовсе — так этот тест и падал в прогоне 44746558946.
    """
    monkeypatch.setattr(deploy_check, "secret_ownership_ok", lambda _stat_result: True)
    _fill(secrets_dir, DEV_SET)
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert not result.ok
    assert "telegram_token: файла нет" in result.detail
    assert "telegram_socks_pass: файла нет" in result.detail
    assert "ghcr_token: файла нет" in result.detail
    assert result.severity == deploy_check.FATAL


@POSIX_ONLY
def test_лишнее_имя_контейнера_в_бою_называется_лишним_а_не_готовностью(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """«Файла нет» и «есть файл с чужим именем» — разные претензии, и подсказка обязана это показывать.

    Иначе вывод зовёт создать `tg_bot_token` в `/etc/tbot/secrets`, чего состав не прочитает
    (`docs/runbook/stand-deploy.md §8`).
    """
    monkeypatch.setattr(deploy_check, "secret_ownership_ok", lambda _stat_result: True)
    _fill(secrets_dir, DEV_SET)
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert not result.ok
    assert "tg_bot_token: файл с именем контейнера" in result.detail
    assert "tg_socks_password: файл с именем контейнера" in result.detail
    assert "telegram_token: файла нет (имя этого контура: telegram_token)" in result.detail
    assert "telegram_token, tg_bot_token" not in result.detail
    assert result.severity == deploy_check.FATAL


@POSIX_ONLY
def test_имена_конфигурации_принимаются_вне_боевого_контура(secrets_dir: Path) -> None:
    _fill(secrets_dir, DEV_SET)
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.SANDBOX))
    assert result.ok, result.detail


@POSIX_ONLY
def test_хостовые_имена_боевого_контура_проходят(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Владелец root:root проверяется отдельно (`test_владелец_файла_секрета_должен_быть_root`):
    в CI тесты идут не от root и создать файлы `root:root` не могут.
    """
    monkeypatch.setattr(deploy_check, "secret_ownership_ok", lambda _stat_result: True)
    _fill(secrets_dir, HOST_SET)
    settings = _settings(secrets_dir, Contour.PRODUCTION)
    files = deploy_check.check_secret_files(settings)
    shapes = deploy_check.check_secret_shapes(settings)
    assert files.ok, files.detail
    assert shapes.ok, shapes.detail


def test_форма_значений_проверяется_без_вывода_значения(secrets_dir: Path) -> None:
    """Именно то, что случилось на площадке: файлы правильные, значения — нет."""
    _fill(
        secrets_dir,
        {"db_password": BAD_PASSWORD, "db_url": BAD_DB_URL, "ghcr_token": BAD_TOKEN},
    )
    result = deploy_check.check_secret_shapes(_settings(secrets_dir, Contour.PRODUCTION))

    assert not result.ok
    assert "не по форме" in result.detail
    for name in ("db_password", "db_url", "ghcr_token"):
        assert name in result.detail
    assert f"{len(BAD_PASSWORD.encode('utf-8'))} байт" in result.detail
    for value in (BAD_PASSWORD, BAD_DB_URL, BAD_TOKEN, DB_PASSWORD, DB_URL, GHCR_TOKEN, TG_TOKEN):
        assert value not in result.detail, f"вывод содержит значение: {name}"
    assert result.severity == deploy_check.FATAL


def test_эталонные_значения_проходят_по_форме(secrets_dir: Path) -> None:
    _fill(secrets_dir, HOST_SET)
    result = deploy_check.check_secret_shapes(_settings(secrets_dir, Contour.PRODUCTION))
    assert result.ok, result.detail


def test_dev_стенд_не_спотыкается_про_форму(secrets_dir: Path) -> None:
    """Dev-значения (`deploy/README.md §2`) обязаны проходить: проверка не должна мешать стенду."""
    _fill(secrets_dir, DEV_SET)
    dev_url = "postgresql://tbot:dev-db-password@postgres:5432/tbot"
    (secrets_dir / "db_url").write_bytes(dev_url.encode("utf-8"))
    (secrets_dir / "db_password").write_bytes(b"dev-db-password")
    result = deploy_check.check_secret_shapes(_settings(secrets_dir, Contour.SANDBOX))
    assert result.ok, result.detail


def test_форма_в_торговом_контуре_это_замечание_а_не_блокировка(secrets_dir: Path) -> None:
    _fill(secrets_dir, {"db_url": BAD_DB_URL, "db_password": DB_PASSWORD})
    result = deploy_check.check_secret_shapes(_settings(secrets_dir, Contour.PAPER))
    assert not result.ok
    assert result.severity == deploy_check.WARN


def test_в_песочце_форма_не_проверяется_и_это_видно_в_выводе(secrets_dir: Path) -> None:
    _fill(secrets_dir, {"db_url": BAD_DB_URL})
    result = deploy_check.check_secret_shapes(_settings(secrets_dir, Contour.SANDBOX))
    assert result.ok
    assert result.severity == deploy_check.WARN
    assert "песочц" in result.detail


@POSIX_ONLY
def test_пустой_файл_это_отдельная_проблема(secrets_dir: Path) -> None:
    _fill(secrets_dir, {"db_url": DB_URL})
    (secrets_dir / "db_password").write_bytes(b"")
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert not result.ok
    assert "db_password: пустой файл" in result.detail


@POSIX_ONLY
def test_права_шише_600_отклоняются(secrets_dir: Path) -> None:
    _fill(secrets_dir, HOST_SET)
    (secrets_dir / "db_url").chmod(0o644)
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert not result.ok
    assert "db_url: права" in result.detail


def test_на_windows_проверка_прав_не_притворяется_зелёной(secrets_dir: Path) -> None:
    if os.name == "posix":
        pytest.skip("проверка прав на POSIX выполняется по-настоящему")
    result = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert result.ok
    assert result.severity == deploy_check.WARN
    assert "POSIX" in result.detail


def test_обе_проверки_включены_в_чеклист_скрипта() -> None:
    """Иначе одна из них тихо выпадет из `make deploy-check` и из CI-джоба."""
    text = (SCRIPTS / "deploy_check.py").read_text(encoding="utf-8")
    assert "check_secret_files(settings)," in text
    assert "check_secret_shapes(settings)," in text


def test_владелец_файла_секрета_должен_быть_root() -> None:
    """Чистая проверка предиката владельца: без файловой системы и без прав root."""
    from types import SimpleNamespace

    assert deploy_check.secret_ownership_ok(SimpleNamespace(st_uid=0, st_gid=0))
    assert not deploy_check.secret_ownership_ok(SimpleNamespace(st_uid=0, st_gid=1000))
    assert not deploy_check.secret_ownership_ok(SimpleNamespace(st_uid=1001, st_gid=0))


@POSIX_ONLY
def test_чужой_владелец_отклоняется_только_в_боевом_контуре(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Тот же набор файлов: в боевом контуре владелец значим, на стенде — нет."""
    monkeypatch.setattr(deploy_check, "secret_ownership_ok", lambda _stat_result: False)
    _fill(secrets_dir, HOST_SET)

    prod = deploy_check.check_secret_files(_settings(secrets_dir, Contour.PRODUCTION))
    assert not prod.ok
    assert "root:root" in prod.detail

    стенд = deploy_check.check_secret_files(_settings(secrets_dir, Contour.SANDBOX))
    assert стенд.ok, стенд.detail
