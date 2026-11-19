"""Загрузка конфигурации (REQ-config-01, REQ-config-02, TZ §14.3).

Правила, которые обеспечивает этот модуль:

1. Потолки риска в конфиге не могут превышать потолки ядра: значения вне диапазонов отбрасываются
   при загрузке, а не проверяются «в рантайме» (см. `RiskLimits`).
2. Секретов в YAML нет: любой ключ, похожий на секрет, в файле конфигурации — ошибка запуска.
   Значения секретов приходят только из переменных окружения или из файлов в `secrets_dir`.
3. Боевой контур требует явного подтверждения (`TBOT_CONFIRM_PRODUCTION=true`), иначе запуск
   считается ошибкой конфигурации.
4. Проверка сертификата брокера и Telegram не может быть отключена конфигурацией.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

# Потолки ядра: конфиг не вправе их превышать (docs/tz/06 §6.3).
CORE_MAX_CAPITAL_SHARE: float = 0.05
CORE_MAX_DAILY_LOSS_SHARE: float = 0.05
CORE_MAX_GRID_LEVELS: int = 6
CORE_MAX_GRID_MULTIPLIER: float = 1.3

# Ключи, которые не должны встречаться в YAML-конфиге (REQ-config-02).
SECRET_KEY_RE = re.compile(
    r"(?i)^(token|.*(token|password|passwd|secret|api_?key|private_?key|totp|backup_code|"
    r"credential|kek|dek).*)$"
)
# Значение вида «схема://логин:пароль@хост» — тоже признак секрета в конфиге.
CREDENTIALED_URI_RE = re.compile(r"(?i)\b(ss|vless|trojan|vmess|socks5|socks5h|https?)://[^/\s]*@")

SECRET_FIELDS: tuple[str, ...] = ("db_url", "tg_bot_token", "tg_socks_password")

# Каталог YAML с текущей конфигурацией. Нужен, чтобы задать порядок источников внутри класса,
# а не «вручную» подмешивать словарь в конструктор (иначе YAML перекрыл бы переменные окружения).
_YAML_PATH: ContextVar[Path | None] = ContextVar("tbot_yaml_path", default=None)


class ConfigError(ValueError):
    """Ошибка конфигурации: содержит читаемый список причин."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__("конфигурация некорректна:\n  - " + "\n  - ".join(reasons))


class Contour(StrEnum):
    """Три контура исполнения (TZ §2.4)."""

    SANDBOX = "sandbox"
    PAPER = "paper"
    PRODUCTION = "production"


class MoneyModel(BaseModel):
    """Общая настройка: запрещены неизвестные поля и изменчивость после загрузки."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RiskLimits(MoneyModel):
    """Потолки риска. Диапазоны зафиксированы ядром, конфиг может только уменьшать."""

    max_capital_share_per_strategy: float = Field(
        default=CORE_MAX_CAPITAL_SHARE, gt=0.0, le=CORE_MAX_CAPITAL_SHARE
    )
    max_daily_loss_share: float = Field(default=0.03, gt=0.0, le=CORE_MAX_DAILY_LOSS_SHARE)
    max_grid_levels: int = Field(default=CORE_MAX_GRID_LEVELS, ge=1, le=CORE_MAX_GRID_LEVELS)
    max_grid_multiplier: float = Field(
        default=CORE_MAX_GRID_MULTIPLIER, gt=1.0, le=CORE_MAX_GRID_MULTIPLIER
    )
    margin_allowed: bool = False

    @model_validator(mode="after")
    def _margin_requires_separate_confirmation(self) -> RiskLimits:
        # Включённый флаг в конфиге — только разрешение ядра; включение на уровне стратегии
        # делается отдельно и с 2FA (docs/tz/06 §6.6). Само по себе оно не увеличивает потолки.
        return self


class Retention(MoneyModel):
    """Сроки хранения данных (TZ §4.4; для площадки 2 vCPU / 3.8 ГБ — OQ-11)."""

    minute_candles_months: int = Field(default=12, ge=1, le=24)
    audit_log_days: int = Field(default=1095, ge=365, le=3650)
    backup_keep_count: int = Field(default=14, ge=1, le=365)


class TelegramSection(MoneyModel):
    """Транспорт канала Telegram. Значение токена здесь отсутствует намеренно."""

    api_base: str = "https://api.telegram.org"
    # Путь к Bot API: `tunnel` — через SOCKS-туннель площадки (единственный рабочий для боевой
    # ВМ, `docs/research/03 §3.4`), `direct` — напрямую (dev-машина, резервный узел).
    # Выбор явный, а не «автоматически»: молча подменять путь нельзя, у путей разные предупреждения.
    transport: Literal["tunnel", "direct"] = "tunnel"
    # Внешний эхо-сервис для замера адреса выхода туннеля (метрика tg_egress_exit, T-714).
    # Используется только для замера; никаких секретов через него не проходит.
    egress_probe_url: str = "https://api.ip.sb/jsonip"
    socks_host: str = "127.0.0.1"
    socks_port: int = Field(default=10800, ge=1, le=65535)
    socks_user: str | None = None
    # Отключение проверки сертификата запрещено (docs/tz/08 §8.10, AC-broker-gateway-02).
    tls_verify: bool = True

    @field_validator("tls_verify")
    @classmethod
    def _tls_verify_cannot_be_disabled(cls, value: bool) -> bool:
        if not value:
            raise ValueError("tls_verify=false запрещено: проверка цепочки Telegram обязательна")
        return value

    @field_validator("egress_probe_url")
    @classmethod
    def _probe_must_be_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("egress_probe_url обязан быть https (иначе замер уходит открыто)")
        return value.rstrip("/")

    @field_validator("api_base")
    @classmethod
    def _api_base_must_be_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("api_base обязан быть https")
        return value.rstrip("/")


class BrokerSection(MoneyModel):
    """Параметры обращения к брокеру. Проверка TLS не отключается."""

    production_host: str = "invest-public-api.tbank.ru"
    sandbox_host: str = "sandbox-invest-public-api.tbank.ru"
    ssl_tbank_verify: bool = True
    request_rate_per_second: int = Field(default=20, ge=1, le=50)

    @field_validator("ssl_tbank_verify")
    @classmethod
    def _verify_cannot_be_disabled(cls, value: bool) -> bool:
        if not value:
            raise ValueError(
                "ssl_tbank_verify=false запрещено: нужен корневой сертификат НУЦ в образе "
                "(docs/runbook/nucc-ca.md)"
            )
        return value


class Settings(BaseSettings):
    """Корневая конфигурация процесса. Значения неизменяемы после загрузки."""

    model_config = SettingsConfigDict(
        env_prefix="TBOT_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
        case_sensitive=False,
    )

    contour: Contour = Contour.SANDBOX
    confirm_production: bool = False
    instance_name: str = "dev"
    secrets_dir: Path = Path("/etc/tbot/secrets")

    limits: RiskLimits = Field(default_factory=RiskLimits)
    retention: Retention = Field(default_factory=Retention)
    telegram: TelegramSection = Field(default_factory=TelegramSection)
    broker: BrokerSection = Field(default_factory=BrokerSection)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    web_host: str = "127.0.0.1"
    web_port: int = Field(default=8080, ge=1, le=65535)
    engine_health_port: int = Field(default=9101, ge=1, le=65535)
    tgbot_health_port: int = Field(default=9102, ge=1, le=65535)
    jobs_health_port: int = Field(default=9103, ge=1, le=65535)

    db_url: SecretStr | None = None
    tg_bot_token: SecretStr | None = None
    tg_socks_password: SecretStr | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003 — состав аргументов задаёт
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003 pydantic-settings, изменить
        # его нельзя; ниже эти источники намеренно не возвращаются (см. docstring).
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Порядок приоритетов: явные аргументы > переменные окружения > YAML.

        `dotenv` и `file_secret` из перечня убраны намеренно: секреты читаются только из
        каталога `secrets_dir` в явном виде (см. `_load_secret_files`), а `.env` в дереве
        репозитория запрещён (REQ-config-02).
        """
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        yaml_path = _YAML_PATH.get()
        if yaml_path is not None:
            sources.append(
                YamlConfigSettingsSource(
                    settings_cls, yaml_file=yaml_path, yaml_file_encoding="utf-8"
                )
            )
        return tuple(sources)

    @model_validator(mode="after")
    def _finalize(self) -> Settings:
        reasons: list[str] = []
        if self.contour is Contour.PRODUCTION and not self.confirm_production:
            reasons.append(
                "контур production требует явного подтверждения: TBOT_CONFIRM_PRODUCTION=true "
                "(TZ §2.4 — запуск только после приёмки sandbox/paper)"
            )
        filled = self._load_secret_files()
        if filled.telegram.socks_user and not filled.telegram.socks_host:
            reasons.append("для SOCKS-пользователя должен быть задан хост")
        if reasons:
            raise ConfigError(reasons)
        return filled

    def _load_secret_files(self) -> Settings:
        """Дописать секреты из файлов `secrets_dir/<имя_поля>`, если они не пришли из ENV.

        Значения проставляются в самом экземпляре (а не копией, возвращаемой из валидатора):
        pydantic вызывает валидатор `mode="after"` с уже созданным объектом и подменой результата
        не заменяет его, а модель заморожена — поэтому используется прямая запись в `__dict__`.
        """
        for field_name in SECRET_FIELDS:
            if getattr(self, field_name, None) is not None:
                continue
            candidate = self.secrets_dir / field_name
            if not candidate.is_file():
                continue
            raw = candidate.read_text(encoding="utf-8").strip()
            if raw:
                self.__dict__[field_name] = SecretStr(raw)
                self.__pydantic_fields_set__.add(field_name)
        return self

    def tg_proxy_url(self) -> str | None:
        """URL SOCKS-транспорта для httpx (`socks5h` — разрешение имени на стороне узла B).

        Возвращаемое значение содержит пароль: в логи и в вывод оно не попадает
        (маскирование — `packages.common.logging`). `None` — если выбран путь `direct`.
        """
        section = self.telegram
        if section.transport == "direct":
            return None
        if self.tg_socks_password is None:
            return f"socks5h://{section.socks_host}:{section.socks_port}"
        user = section.socks_user or "tgbot"
        password = self.tg_socks_password.get_secret_value()
        return f"socks5h://{user}:{password}@{section.socks_host}:{section.socks_port}"


def _collect_secret_key_paths(mapping: object, prefix: str = "") -> list[str]:
    """Найти пути YAML-ключей, похожие на секреты, и значения с учётными данными."""
    found: list[str] = []
    if isinstance(mapping, dict):
        for key, value in mapping.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            name = str(key)
            if SECRET_KEY_RE.match(name):
                found.append(
                    f"{path}: ключ похож на секрет — секреты читаются только из ENV/файлов"
                )
            if isinstance(value, str) and CREDENTIALED_URI_RE.search(value):
                found.append(f"{path}: значение содержит учётные данные (…://***@…)")
            found.extend(_collect_secret_key_paths(value, path))
    elif isinstance(mapping, list):
        for index, item in enumerate(mapping):
            found.extend(_collect_secret_key_paths(item, f"{prefix}[{index}]"))
    return found


def make_settings(**values: object) -> Settings:
    """Создать конфигурацию с переводом ошибок pydantic в читаемый `ConfigError`.

    Единая точка для тестов и скриптов: ошибка конфигурации обязана оставаться одной и той же
    вне зависимости от того, пришла она из YAML, окружения или из аргументов.
    """
    try:
        # Приведение к `dict[str, Any]` нужно только для конструктора модели: он проверяет
        # значения сам (валидаторы `Settings`), а его сгенерированные параметры не совпадают
        # с произвольным набором ключей. На строгость проверки конфигурации это не влияет.
        data: dict[str, Any] = dict(values)
        return Settings(**data)
    except ValidationError as exc:
        reasons = [
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}" for err in exc.errors()
        ]
        raise ConfigError(reasons) from exc


def load_settings(config_file: Path | None = None) -> Settings:
    """Загрузить YAML (если указан) и окружение; проверить запрет секретов в YAML.

    Порядок приоритета: переменные окружения перекрывают YAML, YAML перекрывает значения по
    умолчанию; секреты — только ENV или файлы `secrets_dir`.
    """
    if config_file is not None:
        import yaml  # локальный импорт: нужен только при явном указании файла

        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ConfigError([f"{config_file}: ожидаем YAML-отображение верхнего уровня"])
        bad = _collect_secret_key_paths(loaded)
        if bad:
            raise ConfigError([f"{config_file}: {item}" for item in bad])
    token = _YAML_PATH.set(config_file)
    try:
        return make_settings()
    finally:
        _YAML_PATH.reset(token)
