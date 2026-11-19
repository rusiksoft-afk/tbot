"""M0: транспорт канала Telegram проверяется без сети (подставной HTTP-клиент).

Смысл проверок в том, чтобы процесс честно различал три разных состояния: «нет токена»,
«нет связности с Bot API» и «связность есть, но API запрос не принял». Смешивать их нельзя —
по ним разные предупреждения и разные метрики (docs/tz/10 §10.4).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import httpx
import pytest

import apps.tgbot.main as tgbot_main
from apps.tgbot.main import ProbeResult, ProbeState, probe_egress_exit, probe_transport
from packages.common.config import Settings, TelegramSection
from packages.common.logging import mask_text


class _Response:
    """Ответ как у httpx: код, текст и `json()`, которая бросает ValueError на не-JSON тексте."""

    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.text = (
            json.dumps(payload, ensure_ascii=False)
            if isinstance(payload, dict | list)
            else str(payload)
        )

    def json(self) -> object:
        return json.loads(self.text)


class _FakeClient:
    """Ответы по признаку URL: запрос `getMe` — про транспорт и API, эхо-запрос — про адрес выхода."""

    def __init__(self, responses: dict[str, _Response], *, error: Exception | None = None) -> None:
        self._responses = responses
        self._error = error
        self.requested: list[str] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, url: str) -> _Response:
        self.requested.append(url)
        if self._error is not None:
            raise self._error
        for marker, response in self._responses.items():
            if marker in url:
                return response
        return _Response(404, {"error": "нет подходящего ответа"})


def _settings(secrets_dir: Path) -> Settings:
    return Settings(secrets_dir=secrets_dir)


def test_без_токена_нет_ни_связности_ни_принятия(secrets_dir: Path) -> None:
    result = probe_transport(_settings(secrets_dir))
    assert result.transport_ok is False
    assert result.api_ok is False
    assert "токен" in result.detail


def test_успешный_getMe_даёт_связность_и_принятие(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TBOT_TG_BOT_TOKEN", "1234567890:AAHkAnArYvAlUe-abcdefghij_klmnopqrstu")
    settings = Settings(secrets_dir=secrets_dir)
    client = _FakeClient(
        {
            "getMe": _Response(200, {"ok": True, "result": {"username": "TtermBot_bot"}}),
            "jsonip": _Response(200, {"ip": "203.0.113.9"}),
        }
    )
    monkeypatch.setattr(tgbot_main, "_client", lambda _settings: client)

    result = probe_transport(settings)
    assert result.transport_ok is True
    assert result.api_ok is True
    assert result.exit_ip == "203.0.113.9"
    assert result.latency_ms is not None
    assert result.latency_ms >= 0
    assert "status=200" in result.detail
    assert "@TtermBot_bot" in result.detail
    # Адрес бота в URL запроса — секретоопасное место: эхо-замер выхода обязан идти без токена.
    probe_urls = [url for url in client.requested if "jsonip" in url]
    assert probe_urls, "замер адреса выхода не выполнен"
    assert all("bot" not in url for url in probe_urls)


def test_связность_есть_но_api_запрос_не_принят(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TBOT_TG_BOT_TOKEN", "1234567890:AAHkAnArYvAlUe-abcdefghij_klmnopqrstu")
    settings = Settings(secrets_dir=secrets_dir)
    client = _FakeClient({"getMe": _Response(401, {"ok": False, "description": "unauthorized"})})
    monkeypatch.setattr(tgbot_main, "_client", lambda _settings: client)

    result = probe_transport(settings)
    assert result.transport_ok is True, "канал жив, но токен не принят — это разные состояния"
    assert result.api_ok is False
    assert "status=401" in result.detail


def test_сетевая_ошибка_не_раскрывает_подробностей(
    secrets_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TBOT_TG_BOT_TOKEN", "1234567890:AAHkAnArYvAlUe-abcdefghij_klmnopqrstu")
    settings = Settings(secrets_dir=secrets_dir)
    client = _FakeClient({}, error=httpx.ConnectError("connection refused 149.154.166.110:443"))
    monkeypatch.setattr(tgbot_main, "_client", lambda _settings: client)

    result = probe_transport(settings)
    assert result.transport_ok is False
    assert result.detail == "ConnectError", "в деталь идёт только имя класса исключения"
    assert "149.154" not in result.detail


def test_замер_адреса_выхода_устойчив_к_чужим_ответам() -> None:
    ok = _FakeClient({"echo": _Response(200, {"ip": "198.51.100.7"})})
    assert probe_egress_exit(cast(httpx.Client, ok), "https://example.test/echo") == "198.51.100.7"

    not_found = _FakeClient({"echo": _Response(500, {"ip": "198.51.100.7"})})
    assert probe_egress_exit(cast(httpx.Client, not_found), "https://example.test/echo") is None

    broken = _FakeClient({"echo": _Response(200, "не JSON")})
    assert probe_egress_exit(cast(httpx.Client, broken), "https://example.test/echo") is None

    list_payload = _FakeClient({"echo": _Response(200, [{"ip": "1"}])})
    assert probe_egress_exit(cast(httpx.Client, list_payload), "https://example.test/echo") is None


def test_состояние_до_первой_проверки_не_притворяется_готовым() -> None:
    state = ProbeState()
    result = state.last
    assert result == ProbeResult(False, False, "проверка ещё не выполнялась", None, None, 0.0)
    assert result.probed_monotonic == 0.0


def test_проверки_готовности_читают_последнее_состояние(secrets_dir: Path) -> None:
    state = ProbeState()
    settings = Settings(secrets_dir=secrets_dir)
    handlers = dict(tgbot_main.readiness_checks(settings, state))
    assert set(handlers) == {"telegram_transport", "telegram_token", "telegram_path"}

    transport_ok, transport_detail = handlers["telegram_transport"]()
    assert transport_ok is False
    assert "ещё не выполнялась" in transport_detail

    token_ok, token_detail = handlers["telegram_token"]()
    assert token_ok is False
    assert "токен" in token_detail

    # По умолчанию выбран туннель — и он должен быть заявлен явно, а не «угадан».
    path_ok, path_detail = handlers["telegram_path"]()
    assert path_ok is True
    assert "туннель" in path_detail


def test_прямой_путь_заявляется_отдельно(secrets_dir: Path) -> None:
    """Прямой путь возможен (dev-машина, резервный узел), но отличается предупреждением."""
    settings = Settings(secrets_dir=secrets_dir, telegram=TelegramSection(transport="direct"))
    handlers = dict(tgbot_main.readiness_checks(settings, ProbeState()))
    ok, detail = handlers["telegram_path"]()
    assert ok is True
    assert "прямой" in detail
    assert settings.tg_proxy_url() is None


def test_туннель_настраивается_через_секрет_пароля(secrets_dir: Path) -> None:
    (secrets_dir / "tg_socks_password").write_text("localParol1234567890", encoding="utf-8")
    settings = Settings(secrets_dir=secrets_dir)
    proxy = settings.tg_proxy_url()
    assert proxy is not None
    assert proxy.startswith("socks5h://tgbot:localParol1234567890@127.0.0.1:10800")
    masked = mask_text(f"подключение к {proxy}")
    assert "localParol1234567890" not in masked
