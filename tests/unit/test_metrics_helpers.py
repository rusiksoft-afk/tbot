"""TZ §12.2: базовый набор метрик и `tbot_build_info`."""

from __future__ import annotations

from packages.common import metrics


def test_метаданные_сборки_появляются_в_выгрузке() -> None:
    metrics.set_build_info(version="0.0.0", revision="abcdef1", build_time="2026-11-19T12:00:00Z")
    body = metrics.render().decode("utf-8")
    assert "tbot_build_info{" in body
    assert 'revision="abcdef1"' in body
    assert 'version="0.0.0"' in body


def test_состояние_канала_telegram_разделяется_по_путям() -> None:
    metrics.TG_ENDPOINT_UP.labels(path="direct").set(0)
    metrics.TG_ENDPOINT_UP.labels(path="tunnel").set(1)
    body = metrics.render().decode("utf-8")
    assert 'tg_endpoint_up{path="direct"} 0' in body
    assert 'tg_endpoint_up{path="tunnel"} 1' in body


def test_замер_адреса_выхода_попадает_в_выгрузку() -> None:
    metrics.record_egress_exit("104.28.225.223")
    body = metrics.render().decode("utf-8")
    assert "tg_egress_exit_info" in body
    assert 'ip="104.28.225.223"' in body


def test_тип_контента_текстовый_формат_prometheus() -> None:
    assert "text/plain" in metrics.content_type()


def test_метрика_возраста_доставки_не_подменяется_проверкой_транспорта() -> None:
    """Разделение смыслов M0: доставка сообщений появится в M3, а не «заранее».

    Метрика возраста доставки объявлена (на неё ориентируются алерты), но значения до M3 не
    имеет: Gauge в prometheus_client стартует с нуля, поэтому проверка не «сэмпла нет», а
    «значение осталось нулевым, хотя успешная проверка транспорта уже была». Успех проверки
    пишется в отдельную метрику, чтобы «проверка прошла» и «сообщение доставлено» не смешивались.
    """
    metrics.TG_PROBE_LAST_SUCCESS_TS.labels(path="tunnel").set(1_750_000_000.0)
    body = metrics.render().decode("utf-8")
    assert "# TYPE tg_last_delivery_age_s gauge" in body
    samples = [line for line in body.splitlines() if line.startswith("tg_last_delivery_age_s")]
    assert samples == ["tg_last_delivery_age_s 0.0"], "значение доставки до M3 выставить нельзя"
    assert 'tg_probe_last_success_timestamp_seconds{path="tunnel"}' in body
