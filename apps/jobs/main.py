"""Точка входа процесса `jobs` (M0: каркас, health/metrics; сами задачи — по вехам).

Реестр задач заводится списком с указанием вехи и задачи, чтобы планирование было видно из
кода и из `/readyz`, а не «в головах»: задача, которой ещё нет, не может быть «выполнена
успешно» — она отсутствует в исполнителях, и это видно по статусу готовности.
"""

from __future__ import annotations

import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from packages.common import metrics
from packages.common.clock import ms_timestamp
from packages.common.config import ConfigError, Retention, Settings, load_settings
from packages.common.health_server import Check, HealthServer
from packages.common.logging import configure_logging, get_logger

log = get_logger("jobs")

APP_NAME = "jobs"
HEARTBEAT_INTERVAL_S = 15.0
_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}


@dataclass(frozen=True)
class JobSpec:
    """Описание периодической задачи: имя, интервал, исполнитель (может ещё не быть)."""

    name: str
    interval_s: float
    milestone: str
    task: str
    handler: Callable[[], str] | None = None


# Порядок и периодичность соответствуют docs/tz/12 §12.3; исполнители появляются по вехам.
JOB_REGISTRY: tuple[JobSpec, ...] = (
    JobSpec("history_load", 300, "M2", "T-201"),
    JobSpec("instrument_catalog_sync", 21600, "M2", "T-210"),
    JobSpec("digest_report", 86400, "M3", "T-311"),
    JobSpec("data_retention", 86400, "M6", "T-603"),
    JobSpec("backup", 86400, "M6", "T-601"),
)


def readiness_checks(settings: Settings) -> list[Check]:
    """Готовность к запуску задач: конфигурация хранения применена, исполнители — по вехам."""

    def retention_check() -> tuple[bool, str]:
        retention: Retention = settings.retention
        return True, (
            f"минутные свечи {retention.minute_candles_months} мес, "
            f"журнал аудита {retention.audit_log_days} сут, "
            f"бэкапов {retention.backup_keep_count}"
        )

    def executors_check() -> tuple[bool, str]:
        implemented = [job.name for job in JOB_REGISTRY if job.handler is not None]
        pending = [
            f"{job.name}@{job.milestone}({job.task})" for job in JOB_REGISTRY if job.handler is None
        ]
        if not implemented:
            return False, "нет ни одного исполнителя задач: " + ", ".join(pending)
        return True, f"исполнители: {implemented}; ожидают: {pending}"

    return [("retention", retention_check), ("job_executors", executors_check)]


def run() -> int:  # pragma: no cover — процессная обвязка (конфигурация, сигналы, heartbeat)
    """Запуск процесса `jobs`: heartbeat, эндпоинты состояния, реестр задач по вехам.

    Проверяется job'ом `compose-smoke` в CI (реальный `docker compose up --wait` и опрос
    эндпоинтов), а не юнит-тестом с подменой обработчиков сигналов.
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"конфигурация отклонена: {exc}", flush=True)
        return 2

    configure_logging(settings.log_level, json_output=settings.log_json)
    metrics.set_build_info(**_BUILD)

    stop = threading.Event()

    def _on_signal(signum: int, _frame: object) -> None:
        log.info("signal_received", signal=signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    server = HealthServer(
        app_name=APP_NAME,
        checks=readiness_checks(settings),
        host="127.0.0.1",
        port=settings.jobs_health_port,
    )
    server.start()
    started_monotonic = time.monotonic()
    log.info(
        "jobs_started",
        health_port=server.port,
        scheduled=[job.name for job in JOB_REGISTRY],
        note="исполнители задач подключаются по вехам M2–M6",
    )
    try:
        while not stop.is_set():
            metrics.PROCESS_ALIVE.labels(app=APP_NAME).set(ms_timestamp() / 1000.0)
            stop.wait(HEARTBEAT_INTERVAL_S)
    finally:
        server.stop()
        log.info("jobs_stopped", uptime_s=round(time.monotonic() - started_monotonic, 1))
    return 0


if __name__ == "__main__":  # pragma: no cover — точка запуска образа
    raise SystemExit(run())
