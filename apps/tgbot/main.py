"""Точка входа процесса `tgbot` (M0: транспорт канала и доступность Bot API).

Что закрыто на M0:

* проверка транспорта Telegram через настроенный SOCKS-туннель (`socks5h` — имя разрешается на
  стороне узла B, потому что собственный DNS площадки отдаёт недоступный адрес,
  `docs/research/03 §3.4`);
* проверка цепочки сертификата Bot API: отключить её конфигурацией нельзя
  (`TelegramSection.tls_verify`), при несовпадении — запись в лог и нулевой флаг метрики;
* фиксация фактического адреса выхода (`tg_egress_exit`) — проверка детерминированности из
  `docs/acceptance/tg-egress.md §3`;
* эндпоинты `/healthz`, `/readyz`, `/metrics`.

Чего на M0 сознательно нет: отправки сообщений, кнопок, подтверждения операций кодом TOTP —
это веха M3 (T-301…T-312). Поэтому метрика возраста доставки сообщения не выдумывается:
фиксируется только успешная проверка транспорта (`tg_probe_last_success_timestamp_seconds`).
"""

from __future__ import annotations

import json
import signal
import threading
import time
from dataclasses import dataclass

import httpx

from packages.common import metrics
from packages.common.clock import ms_timestamp
from packages.common.config import ConfigError, Settings, load_settings
from packages.common.health_server import Check, HealthServer
from packages.common.logging import configure_logging, get_logger, mask_text

log = get_logger("tgbot")

APP_NAME = "tgbot"
PROBE_INTERVAL_S = 30.0
PROBE_TIMEOUT_S = 12.0
_BUILD = {"version": "0.0.0", "revision": "unknown", "build_time": "unknown"}


@dataclass(frozen=True)
class ProbeResult:
    """Итог проверки транспорта: связность отдельно, принятие запроса API — отдельно."""

    transport_ok: bool
    api_ok: bool
    detail: str
    latency_ms: int | None
    exit_ip: str | None
    probed_monotonic: float


_NOT_PROBED = ProbeResult(False, False, "проверка ещё не выполнялась", None, None, 0.0)


def _client(settings: Settings) -> httpx.Client:
    """HTTP-клиент с обязательной проверкой TLS и, при настроенном туннеле, через SOCKS."""
    proxy = settings.tg_proxy_url()
    if proxy is None:
        return httpx.Client(timeout=PROBE_TIMEOUT_S, verify=True)
    return httpx.Client(timeout=PROBE_TIMEOUT_S, verify=True, proxy=proxy)


def probe_egress_exit(client: httpx.Client, url: str) -> str | None:
    """Замер адреса выхода, который видит внешний сервис (для `tg_egress_exit`)."""
    try:
        response = client.get(url)
        if response.status_code != 200:
            return None
        payload = json.loads(response.text)
    except (httpx.HTTPError, ValueError):
        return None
    value = payload.get("ip") if isinstance(payload, dict) else None
    return str(value) if isinstance(value, str) else None


def probe_transport(settings: Settings) -> ProbeResult:
    """Один цикл проверки Bot API: getMe через настроенный транспорт.

    Значение токена в лог не попадает: в исключениях httpx может встречаться URL с ним,
    поэтому в детали идёт только имя класса исключения, пропущенное через `mask_text`.
    """
    token = settings.tg_bot_token.get_secret_value() if settings.tg_bot_token else None
    if token is None:
        return ProbeResult(
            False,
            False,
            "токен не настроен (TBOT_TG_BOT_TOKEN или файл секрета)",
            None,
            None,
            time.monotonic(),
        )

    started = time.monotonic()
    try:
        with _client(settings) as client:
            url = f"{settings.telegram.api_base}/bot{token}/getMe"
            response = client.get(url)
            latency_ms = int((time.monotonic() - started) * 1000)
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            api_ok = bool(payload.get("ok"))
            detail = f"status={response.status_code} ok={api_ok}"
            if api_ok and isinstance(payload.get("result"), dict):
                detail += f" username=@{payload['result'].get('username')}"
            exit_ip = probe_egress_exit(client, settings.telegram.egress_probe_url)
            return ProbeResult(True, api_ok, detail, latency_ms, exit_ip, started)
    except httpx.HTTPError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        return ProbeResult(
            False, False, mask_text(f"{type(exc).__name__}"), latency_ms, None, started
        )


class ProbeState:
    """Последний результат проверки, читаемый `/readyz` без обращения к сети."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last = _NOT_PROBED

    def update(self, result: ProbeResult) -> None:
        with self._lock:
            self._last = result

    @property
    def last(self) -> ProbeResult:
        with self._lock:
            return self._last


def readiness_checks(settings: Settings, state: ProbeState) -> list[Check]:
    def transport_check() -> tuple[bool, str]:
        result = state.last
        if result.probed_monotonic == 0.0:
            return False, result.detail
        return result.transport_ok, f"{result.detail} latency_ms={result.latency_ms}"

    def token_check() -> tuple[bool, str]:
        if settings.tg_bot_token is None:
            return False, "токен бота не настроен: канал управления недоступен"
        result = state.last
        return result.api_ok, f"принятие запроса Bot API: {result.detail}"

    def proxy_check() -> tuple[bool, str]:
        section = settings.telegram
        if section.transport == "direct":
            return True, (
                "путь выбран явный: прямой доступ к Bot API (TBOT_TELEGRAM__TRANSPORT=direct); "
                "с боевой площадки он недоступен — docs/research/03 §3.4"
            )
        if settings.tg_proxy_url() is None:  # защитная ветка: туннель заявлен, но адрес не собран
            return False, (
                "SOCKS-туннель не настроен: с этой площадки Bot API недоступен напрямую "
                "(docs/research/03 §3.4); канал управления останется нерабочим"
            )
        return True, "транспортный путь настроен: туннель через узел B"

    return [
        ("telegram_transport", transport_check),
        ("telegram_token", token_check),
        ("telegram_path", proxy_check),
    ]


def run() -> int:  # pragma: no cover — процессная обвязка (конфигурация, сигналы, цикл пробы)
    """Запуск процесса `tgbot`: цикл проверки транспорта и эндпоинты состояния.

    Сама логика пробы (`probe_transport`, `probe_egress_exit`, проверки готовности) покрыта
    юнит-тестами с подставным HTTP-клиентом; здесь остаётся только обвязка, которую проверяет
    job `compose-smoke` в CI.
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

    state = ProbeState()
    server = HealthServer(
        app_name=APP_NAME,
        checks=readiness_checks(settings, state),
        host="127.0.0.1",
        port=settings.tgbot_health_port,
    )
    server.start()
    # Путь берётся из конфигурации, а не «угадывается» из наличия пароля: у путей разные
    # предупреждения и разные метки в метриках (`path="direct|tunnel"`).
    path_label = settings.telegram.transport
    log.info(
        "tgbot_started",
        contour=settings.contour.value,
        health_port=server.port,
        path=path_label,
        note="отправка сообщений и кнопок — веха M3 (T-301…T-312)",
    )

    started_monotonic = time.monotonic()
    try:
        while not stop.is_set():
            result = probe_transport(settings)
            state.update(result)
            metrics.TG_ENDPOINT_UP.labels(path=path_label).set(1.0 if result.transport_ok else 0.0)
            metrics.TG_TUNNEL_UP.set(1.0 if path_label == "tunnel" and result.transport_ok else 0.0)
            if result.api_ok:
                metrics.TG_PROBE_LAST_SUCCESS_TS.labels(path=path_label).set(
                    ms_timestamp() / 1000.0
                )
            if result.exit_ip:
                metrics.record_egress_exit(result.exit_ip)
            metrics.PROCESS_ALIVE.labels(app=APP_NAME).set(ms_timestamp() / 1000.0)
            if result.transport_ok:
                log.info(
                    "tg_transport_probe",
                    path=path_label,
                    api_ok=result.api_ok,
                    detail=result.detail,
                    latency_ms=result.latency_ms,
                    exit_ip=result.exit_ip,
                )
            else:
                log.warning(
                    "tg_transport_probe_failed",
                    path=path_label,
                    detail=result.detail,
                    latency_ms=result.latency_ms,
                )
            stop.wait(PROBE_INTERVAL_S)
    finally:
        server.stop()
        log.info(
            "tgbot_stopped",
            uptime_s=round(time.monotonic() - started_monotonic, 1),
        )
    return 0


if __name__ == "__main__":  # pragma: no cover — точка запуска образа
    raise SystemExit(run())
