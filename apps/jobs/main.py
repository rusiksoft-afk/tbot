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
from dataclasses import dataclass, replace
from functools import partial
from typing import Final

from sqlalchemy.engine import Engine

from apps.jobs.maintenance import (
    PURGE_JOB_NAME,
    RATE_BUCKET_PURGE_INTERVAL_S,
    build_job_engine,
    purge_expired_rate_buckets,
)
from packages.common import metrics
from packages.common.clock import ms_timestamp
from packages.common.config import ConfigError, Retention, Settings, load_settings
from packages.common.health_server import Check, HealthServer
from packages.common.logging import configure_logging, get_logger

log = get_logger("jobs")

APP_NAME = "jobs"
HEARTBEAT_INTERVAL_S = 15.0
_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}

#: Задача чистки окон счётчика (`ADR-007`, TZ §8.3): первая исполненная задача процесса.
#: Её регламент (раз в час, окна старше 24 часов) выбран заказчиком (ask `abb0151c`).
PURGE_TASK: Final = "T-102"


@dataclass(frozen=True)
class JobSpec:
    """Описание периодической задачи: имя, интервал, исполнитель (может ещё не быть)."""

    name: str
    interval_s: float
    milestone: str
    task: str
    handler: Callable[[], str] | None = None


# Порядок и периодичность соответствуют docs/tz/12 §12.3; исполнители появляются по вехам.
# Исключение из перечня §12.3 — `rate_bucket_purge`: её регламент задан `ADR-007` (ask
# `abb0151c`), потому что без чистки «временные» строки счётчика остаются навсегда.
# Объявление здесь декларативное (исполнителя нет): связь «задача ↔ веха ↔ интервал» обязана
# быть видна без адреса базы, а реальные исполнители подключает `build_job_registry`.
JOB_REGISTRY: tuple[JobSpec, ...] = (
    JobSpec(PURGE_JOB_NAME, RATE_BUCKET_PURGE_INTERVAL_S, "M1", PURGE_TASK),
    JobSpec("history_load", 300, "M2", "T-201"),
    JobSpec("instrument_catalog_sync", 21600, "M2", "T-210"),
    JobSpec("digest_report", 86400, "M3", "T-311"),
    JobSpec("data_retention", 86400, "M6", "T-603"),
    JobSpec("backup", 86400, "M6", "T-601"),
)


def _purge_rate_buckets(engine: Engine) -> str:
    """Исполнитель чистки окон счётчика: одна операция раз в регламентированный час."""
    deleted = purge_expired_rate_buckets(engine)
    return f"окон счётчика удалено: {deleted}"


def build_job_registry(engine: Engine | None) -> tuple[JobSpec, ...]:
    """Реестр задач с подключёнными исполнителями.

    Разделение «объявление ↔ исполнитель» нужно не для красоты: `JOB_REGISTRY` видно из кода и из
    `/readyz` без подключения к базе, а исполнитель появляется только тогда, когда для него есть
    всё нужное. Нет движка базы (нет `TBOT_DB_URL`) — исполнителя нет, и готовность честно это
    называет: задача, которую процесс выполнить не может, не должна выглядеть выполненной.

    Исполнители привязываются по имени задачи, потому что порядок реестра — это перечисление
    вех, а не местоположение кода.

    Движок передаётся параметром, а не строится внутри: процесс держит один движок от запуска до
    остановки, а готовность опрачивается неоднократно — заводить пул соединений на каждый опрос
    значило бы копить их. Уже объявленный в реестре исполнитель не затирается: «свой» исполнитель
    остаётся исполнителем, иначе подключение движка молча отменяло бы явную привязку.
    """
    handlers: dict[str, Callable[[], str]] = {}
    if engine is not None:
        handlers[PURGE_JOB_NAME] = partial(_purge_rate_buckets, engine)
    declared: list[JobSpec] = []
    for job in JOB_REGISTRY:
        handler = handlers.get(job.name)
        declared.append(job if handler is None else replace(job, handler=handler))
    return tuple(declared)


def due_jobs(
    registry: tuple[JobSpec, ...], last_run: dict[str, float], *, moment: float
) -> list[JobSpec]:
    """Задачи, у которых есть исполнитель и наступил срок (моменты — `time.monotonic`).

    `monotonic`, а не настенные часы: перевод системного времени (или скачок `chrony`, обязательного по
    §8.2) не должен ни отменять прогон, ни заставлять задачу крутиться постоянно. Первая попытка
    выполняется сразу после запуска процесса: между предыдущим прогоном и рестартом контейнера
    окна могли накопиться, и ждать час после старта незачем.
    """
    due: list[JobSpec] = []
    for job in registry:
        if job.handler is None:
            continue
        previous = last_run.get(job.name)
        if previous is None or moment - previous >= job.interval_s:
            due.append(job)
    return due


def run_job(job: JobSpec, last_run: dict[str, float], *, moment: float) -> None:
    """Выполнить задачу и отметить момент **попытки** (успеха или провала).

    Отметка ставится до вызова исполнителя намеренно: падающая задача не должна превращать
    почасовой регламент в цикл каждые `HEARTBEAT_INTERVAL_S` секунды. Провал не выдаётся за
    выполненное: `/readyz` смотрит на наличие исполнителя, а не на «последний прогон прошёл»,
    поэтому здесь остаётся только журнал процесса.
    """
    last_run[job.name] = moment
    handler = job.handler
    if handler is None:
        return
    try:
        detail = handler()
    except Exception as exc:
        log.exception(
            "job_failed",
            job=job.name,
            error_type=type(exc).__name__,
            detail=str(exc),
        )
        return
    log.info("job_done", job=job.name, detail=detail)


def readiness_checks(settings: Settings, registry: tuple[JobSpec, ...]) -> list[Check]:
    """Готовность к запуску задач: конфигурация хранения применена, исполнители — по вехам.

    Реестр передаётся тем же объектом, которым процесс собирается исполнять задачи: иначе `/readyz`
    отвечал бы по отдельной копии реестра, и расхождение между «что обещаем» и «что делаем»
    осталось бы незамеченным.
    """

    def retention_check() -> tuple[bool, str]:
        retention: Retention = settings.retention
        return True, (
            f"минутные свечи {retention.minute_candles_months} мес, "
            f"журнал аудита {retention.audit_log_days} сут, "
            f"бэкапов {retention.backup_keep_count}"
        )

    def executors_check() -> tuple[bool, str]:
        implemented = [job.name for job in registry if job.handler is not None]
        pending = [
            f"{job.name}@{job.milestone}({job.task})" for job in registry if job.handler is None
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

    # Движок строится один раз на процесс: тот же объект уходит исполнителям реестра и проверке
    # готовности, и он же освобождается при остановке.
    engine = build_job_engine(settings)
    registry = build_job_registry(engine)
    server = HealthServer(
        app_name=APP_NAME,
        checks=readiness_checks(settings, registry),
        host="127.0.0.1",
        port=settings.jobs_health_port,
    )
    server.start()
    started_monotonic = time.monotonic()
    log.info(
        "jobs_started",
        health_port=server.port,
        scheduled=[job.name for job in registry],
        executors=[job.name for job in registry if job.handler is not None],
        note="остальные исполнители подключаются по вехам M2–M6",
    )
    last_run: dict[str, float] = {}
    try:
        while not stop.is_set():
            metrics.PROCESS_ALIVE.labels(app=APP_NAME).set(ms_timestamp() / 1000.0)
            moment = time.monotonic()
            for job in due_jobs(registry, last_run, moment=moment):
                run_job(job, last_run, moment=moment)
            stop.wait(HEARTBEAT_INTERVAL_S)
    finally:
        server.stop()
        if engine is not None:
            engine.dispose()
        log.info("jobs_stopped", uptime_s=round(time.monotonic() - started_monotonic, 1))
    return 0


if __name__ == "__main__":  # pragma: no cover — точка запуска образа
    raise SystemExit(run())
