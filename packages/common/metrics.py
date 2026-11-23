"""Базовые метрики процесса (TZ §12.2, docs/tz/10 §10.7).

Здесь определяются только метрики, нужные инфраструктурной части M0 и обязательные алертам:
отличимость «сервис жив» от «сервис готов», версия сборки, состояние канала Telegram и
фактический адрес выхода, который видит Telegram.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Gauge, Info, generate_latest

# `Info` даёт метрику `tbot_build_info{version,revision,build_time}`.
BUILD_INFO = Info("tbot_build", "Версия, ревизия и время сборки процесса")

PROCESS_ALIVE = Gauge(
    "tbot_process_heartbeat_timestamp_seconds",
    "Метка времени последнего цикла heartbeat процесса",
    labelnames=("app",),
)
DEPENDENCY_UP = Gauge(
    "tbot_dependency_up",
    "Доступность зависимости (1 — доступна): postgres, telegram, broker_api",
    labelnames=("dependency", "contour"),
)
TG_ENDPOINT_UP = Gauge(
    "tg_endpoint_up",
    "Доставляемость Telegram по каждому пути: direct, tunnel",
    labelnames=("path",),
)
TG_LAST_DELIVERY_AGE_S = Gauge(
    "tg_last_delivery_age_s",
    "Возраст последней успешно доставленной сообщения канала управления",
)
# Отдельная метрика для M0: сообщения прикладного уровня ещё не отправляются (веха M3),
# поэтому возраст доставки не выдумывается, а фиксируется успешная проверка транспорта.
TG_PROBE_LAST_SUCCESS_TS = Gauge(
    "tg_probe_last_success_timestamp_seconds",
    "Метка времени последней успешной проверки доступности Bot API (getMe)",
    labelnames=("path",),
)
TG_EGRESS_EXIT = Info("tg_egress_exit", "Адрес выхода, который видит Telegram (замер)")
TG_TUNNEL_UP = Gauge("tg_tunnel_up", "Локальный туннель-клиент отвечает (SOCKS-порт открыт)")

# Свободное место: нужна алерту §12.4 (`tbot_disk_free_bytes < 15%` / `< 8%` → `SYSTEM`) и
# ежедневной `integrity-check` §8.7 («проверка свободных мест», `ADR-025` п. 9, `T-109` `R3.2`).
# Порог §12.4 задан процентами, поэтому рядом заведена ёмкость: Prometheus считает долю из пары
# метрик, а не из одной.
DISK_FREE_BYTES = Gauge(
    "tbot_disk_free_bytes",
    "Свободное место на файловой системе процесса (байты)",
    labelnames=("app",),
)
DISK_TOTAL_BYTES = Gauge(
    "tbot_disk_total_bytes",
    "Полный объём файловой системы процесса (байты)",
    labelnames=("app",),
)


def set_build_info(*, version: str, revision: str, build_time: str) -> None:
    """Заполнить `tbot_build_info`. Значения передаёт сборочный скрипт/образ, не конфиг."""
    BUILD_INFO.info({"version": version, "revision": revision, "build_time": build_time})


def record_egress_exit(ip: str) -> None:
    """Зафиксировать IP выхода из туннеля (проверка детерминированности, T-714)."""
    TG_EGRESS_EXIT.info({"ip": ip})


def render() -> bytes:
    """Тело ответа `/metrics` в текстовом формате Prometheus."""
    return generate_latest(REGISTRY)


def content_type() -> str:
    return str(CONTENT_TYPE_LATEST)
