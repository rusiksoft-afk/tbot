"""REQ-config-01: диапазоны риска; REQ-config-02: запрет секретов в YAML."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from packages.common.config import (
    CORE_MAX_CAPITAL_SHARE,
    CORE_MAX_GRID_LEVELS,
    CORE_MAX_GRID_MULTIPLIER,
    ConfigError,
    Contour,
    Retention,
    RiskLimits,
    Settings,
    TelegramSection,
    load_settings,
    make_settings,
)


def test_значения_по_умолчанию_на_границе_потолков() -> None:
    limits = RiskLimits()
    assert limits.max_capital_share_per_strategy == pytest.approx(CORE_MAX_CAPITAL_SHARE)
    assert limits.max_grid_levels == CORE_MAX_GRID_LEVELS
    assert limits.max_grid_multiplier == pytest.approx(CORE_MAX_GRID_MULTIPLIER)
    assert limits.margin_allowed is False, "маржинальная торговля по умолчанию запрещена (TZ §2)"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_capital_share_per_strategy", 0.06),
        ("max_capital_share_per_strategy", 0.0),
        ("max_daily_loss_share", 0.08),
        ("max_grid_levels", CORE_MAX_GRID_LEVELS + 1),
        ("max_grid_levels", 0),
        ("max_grid_multiplier", CORE_MAX_GRID_MULTIPLIER + 0.1),
        ("max_grid_multiplier", 1.0),
    ],
)
def test_конфиг_не_может_превысить_потолки_ядра(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        RiskLimits.model_validate({field: value})


def test_конфиг_может_уменьшать_потолки() -> None:
    limits = RiskLimits(max_capital_share_per_strategy=0.01, max_grid_levels=2)
    assert limits.max_capital_share_per_strategy == 0.01
    assert limits.max_grid_levels == 2


def test_неизвестное_поле_отбрасывается() -> None:
    with pytest.raises(ValidationError):
        RiskLimits.model_validate({"max_capital_share_per_strategy": 0.01, "disable_risk": True})


def test_боевой_контур_требует_явного_подтверждения(secrets_dir: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        make_settings(contour=Contour.PRODUCTION, secrets_dir=secrets_dir)
    assert any("production" in reason for reason in excinfo.value.reasons)


def test_боевой_контур_с_подтверждением_загружается(secrets_dir: Path) -> None:
    settings = Settings(
        contour=Contour.PRODUCTION, confirm_production=True, secrets_dir=secrets_dir
    )
    assert settings.contour is Contour.PRODUCTION


def test_yml_с_ключом_секретом_отклоняется(tmp_path: Path) -> None:
    config_file = tmp_path / "tbot.yaml"
    config_file.write_text(
        "contour: sandbox\n" "tg_bot_token: '123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_settings(config_file)
    assert any("tg_bot_token" in reason for reason in excinfo.value.reasons)


def test_yml_со_значением_с_учётными_данными_отклоняется(tmp_path: Path) -> None:
    config_file = tmp_path / "tbot.yaml"
    config_file.write_text(
        "contour: sandbox\ntg_proxy: socks5h://tgbot:supersecret@127.0.0.1:10800\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_settings(config_file)
    assert any("учётные данные" in reason for reason in excinfo.value.reasons)


def test_вложенный_ключ_секрет_тоже_находится(tmp_path: Path) -> None:
    config_file = tmp_path / "tbot.yaml"
    config_file.write_text("limits:\n  nested_password: hunter2\n", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_settings(config_file)
    assert any("limits.nested_password" in reason for reason in excinfo.value.reasons)


def test_секреты_читаются_из_файлов_secrets_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "tg_bot_token").write_text(
        "1234567890:AAHCANARYvalue-abcdefghij_klmnop\n", encoding="utf-8"
    )
    (secrets / "tg_socks_password").write_text("local-socks-password\n", encoding="utf-8")
    monkeypatch.setenv("TBOT_SECRETS_DIR", str(secrets))

    loaded = load_settings()
    assert loaded.tg_bot_token is not None
    assert loaded.tg_bot_token.get_secret_value().startswith("1234567890:")
    assert loaded.tg_socks_password is not None
    assert "local-socks-password" in (loaded.tg_proxy_url() or "")


def test_переменные_окружения_перекрывают_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = tmp_path / "tbot.yaml"
    config_file.write_text("instance_name: from-yaml\n", encoding="utf-8")
    monkeypatch.setenv("TBOT_INSTANCE_NAME", "from-env")
    assert load_settings(config_file).instance_name == "from-env"


def test_проверка_tls_нельзя_отключить_ни_для_telegram_ни_для_брокера() -> None:
    with pytest.raises(ValidationError):
        TelegramSection(tls_verify=False)
    with pytest.raises(ValidationError):
        Settings.model_validate({"telegram": {"tls_verify": False}})
    with pytest.raises(ValidationError):
        Settings.model_validate({"broker": {"ssl_tbank_verify": False}})
    with pytest.raises(ValidationError):
        TelegramSection(api_base="http://api.telegram.org")


def test_маскирование_секретных_полей_в_представлении(settings: Settings) -> None:
    with_token = Settings.model_validate(
        {**settings.model_dump(), "tg_bot_token": SecretStr("1234567890:AAHSUPERSECRETvalue123456")}
    )
    assert "AAHSUPERSECRET" not in repr(with_token)
    assert "AAHSUPERSECRET" not in str(with_token.model_dump())


def test_retention_в_допустимых_границах() -> None:
    assert Retention(minute_candles_months=3).minute_candles_months == 3
    with pytest.raises(ValidationError):
        Retention(minute_candles_months=0)
    with pytest.raises(ValidationError):
        Retention(minute_candles_months=25)


def test_неизвестный_ключ_верхнего_уровня_отклоняется(tmp_path: Path) -> None:
    config_file = tmp_path / "tbot.yaml"
    config_file.write_text("contour: sandbox\nunknown_section: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(config_file)


# ─── роль-мигратор (`ADR-018`) ────────────────────────────────────────────────


def test_роль_мигратора_по_умолчанию_не_задана() -> None:
    """Без `TBOT_MIGRATION_DB_USER` поведение прежнее: роль берётся из адреса.

    Так работают job `миграции` в CI и dev-команда `make migrate`, где роль в адресе уже
    владелец схемы. Пустое значение по умолчанию — не «отсутствие роли», а «не подменять».
    """
    assert Settings().migration_db_user is None


def test_роль_мигратора_читается_из_окружения(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`TBOT_MIGRATION_DB_USER` — имя роли, а не секрет: пароль остаётся в `db_url`.

    Значение не должно попадать ни в YAML, ни в файлы секретов: проверяется, что переменная
    с префикса `TBOT_` доходит до поля (иначе compose её объявляет, а код не читает).
    """
    monkeypatch.setenv("TBOT_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("TBOT_MIGRATION_DB_USER", "tbot")
    assert load_settings().migration_db_user == "tbot"


def test_пустое_имя_роли_мигратора_отклоняется() -> None:
    """Пустая строка дала бы адрес без имени пользователя вместо «не подменять».

    Отдельная причина: `${VAR:-tbot}` в compose при пустом `VAR` в env-файле площадки
    подставляет пустую строку, и молча соединяться «без пользователя» нельзя.
    """
    with pytest.raises(ConfigError) as excinfo:
        make_settings(migration_db_user="   ")
    assert any("TBOT_MIGRATION_DB_USER" in reason for reason in excinfo.value.reasons)


def test_роль_мигратора_не_ищется_среди_секретов() -> None:
    """Имя роли не должно попасть в перечень секретных файлов `secrets_dir`.

    Иначе на площадке от неё потребовался бы файл в `/etc/tbot/secrets` — то есть второй
    DSN-подобный секрет, от которого отказался заказчик (`ADR-006`, вариант А).
    """
    from packages.common.config import SECRET_FIELDS

    assert "migration_db_user" not in SECRET_FIELDS
    assert "migration_db_user" in Settings.model_fields
