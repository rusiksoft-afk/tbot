"""Точка входа процесса `engine` (M0: каркас процесса, health/metrics, охрана контуров).

Торговая логика подключается по вехам (M1 — минимальный цикл «песочница», M2 — данные, M3 —
исполнение). На M0 процесс существует реально: он загружает конфигурацию, поднимает эндпоинты
состояния, выставляет heartbeat и метрики, корректно обрабатывает SIGTERM — но торговые вызовы
не совершает, потому что их кода ещё нет.

Охрана на M0:

* контур `production` отказывается запускаться, пока не реализован риск-шлюз и исполнение
  (задачи T-301…T-320): заглушка не должна оказаться способной «что-то отправить брокеру»;
* конфигурация отклоняется до старта, а не подменяется значениями по умолчанию.
"""

from __future__ import annotations

import signal
import threading
import time

from packages.common import metrics
from packages.common.clock import ms_timestamp, utc_now
from packages.common.config import ConfigError, Contour, Settings, load_settings
from packages.common.health_server import Check, CheckResult, HealthServer
from packages.common.logging import configure_logging, get_logger

log = get_logger("engine")

APP_NAME = "engine"
HEARTBEAT_INTERVAL_S = 10.0

_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}


def contour_guard(settings: Settings) -> CheckResult:
    """Готовность контура: боевой запуск запрещён до окончания вехи M3."""
    if settings.contour is Contour.PRODUCTION:
        return False, (
            "боевой контур отключён: риск-шлюз и исполнитель заявок появятся в M3 "
            "(T-301…T-320); запуск в production невозможен"
        )
    return True, f"контур {settings.contour.value} разрешён на текущей вехе"


def readiness_checks(settings: Settings) -> list[Check]:
    """Проверки готовности ядра. Проверки брокера и БД добавляются вместе с их кодом."""
    return [
        ("contour", lambda: contour_guard(settings)),
        (
            "config",
            lambda: (
                True,
                f"потолки риска: {settings.limits.max_capital_share_per_strategy:.2%} на стратегию, "
                f"уровней сетки ≤{settings.limits.max_grid_levels}, "
                f"множитель ≤{settings.limits.max_grid_multiplier}",
            ),
        ),
    ]


def run() -> int:  # pragma: no cover — процессная обвязка (конфигурация, сигналы, heartbeat)
    """Запуск процесса `engine`: каркас с корректной остановкой по сигналу.

    Исключено из юнит-покрытия осознанно и проверяется иначе: job `compose-smoke` в CI поднимает
    реальные контейнеры (`up --wait`) и опрашивает `/healthz` и `/readyz`. Подменять обработчики
    сигналов в юнит-тесте — значит тестировать подмену, а не процесс.
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

    if settings.contour is Contour.PRODUCTION:
        ok, detail = contour_guard(settings)
        log.error("startup_refused", ok=ok, detail=detail)
        return 3

    server = HealthServer(
        app_name=APP_NAME,
        checks=readiness_checks(settings),
        host="127.0.0.1",
        port=settings.engine_health_port,
    )
    server.start()
    started_monotonic = time.monotonic()
    log.info(
        "engine_started",
        contour=settings.contour.value,
        instance=settings.instance_name,
        health_port=server.port,
        note="торговый цикл подключается на M1–M3; сейчас доступен только каркас процесса",
    )
    try:
        while not stop.is_set():
            metrics.PROCESS_ALIVE.labels(app=APP_NAME).set(ms_timestamp() / 1000.0)
            stop.wait(HEARTBEAT_INTERVAL_S)
    finally:
        server.stop()
        log.info(
            "engine_stopped",
            ts=utc_now().isoformat(),
            uptime_s=round(time.monotonic() - started_monotonic, 1),
        )
    return 0


if __name__ == "__main__":  # pragma: no cover — точка запуска образа
    raise SystemExit(run())
