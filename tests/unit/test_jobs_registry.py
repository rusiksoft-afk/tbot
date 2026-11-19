"""M0: реестр периодических задач виден из кода и из `/readyz` (docs/tz/12 §12.3).

Задача, исполнителя которой ещё нет, не может числиться «выполненной успешно»: она отсутствует
в исполнителях, и готовность процесса это показывает.
"""

from __future__ import annotations

import pytest

import apps.jobs.main as jobs_main
from apps.jobs.main import APP_NAME, JOB_REGISTRY, JobSpec, readiness_checks
from packages.common.config import Settings

# Интервалы соответствуют docs/tz/12 §12.3; нижняя граница — чтобы задача не превратилась
# в «крутиться постоянно» на площадке с 2 vCPU.
MIN_INTERVAL_S = 60.0
MAX_INTERVAL_S = 7 * 24 * 3600.0


def test_имена_задач_уникальны() -> None:
    names = [job.name for job in JOB_REGISTRY]
    assert len(names) == len(set(names)), "две задачи с одним именем невозможно различить в логах"


def test_каждая_задача_привязана_к_вехе_и_задаче_плана() -> None:
    for job in JOB_REGISTRY:
        assert job.milestone in {"M1", "M2", "M3", "M4", "M5", "M6", "M7"}, job
        assert job.task.startswith("T-"), f"{job.name}: ссылка на задачу плана обязательна"
        assert MIN_INTERVAL_S <= job.interval_s <= MAX_INTERVAL_S, job.name


def test_исполнители_задач_появятся_не_раньше_своей_логики() -> None:
    """На M0 ни один исполнитель не «изобретён»: иначе `/readyz` врал бы о готовности."""
    assert all(job.handler is None for job in JOB_REGISTRY)


def test_готовность_сообщает_что_исполнителей_ещё_нет(settings: Settings) -> None:
    handlers = dict(readiness_checks(settings))
    assert set(handlers) == {"retention", "job_executors"}
    ok, detail = handlers["job_executors"]()
    assert ok is False
    for job in JOB_REGISTRY:
        assert f"{job.name}@{job.milestone}" in detail


def test_политика_хранения_применена_из_конфигурации(settings: Settings) -> None:
    handlers = dict(readiness_checks(settings))
    ok, detail = handlers["retention"]()
    assert ok is True
    assert f"минутные свечи {settings.retention.minute_candles_months} мес" in detail
    assert f"бэкапов {settings.retention.backup_keep_count}" in detail


def test_задача_с_исполнителем_считается_реализованной(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Проверка `job_executors` меняет ответ, когда появляется хотя бы один исполнитель."""

    def handler() -> str:
        return "свечи загружены"

    implemented = JobSpec("history_load", 300, "M2", "T-201", handler=handler)
    updated = (implemented, *(job for job in JOB_REGISTRY if job.name != implemented.name))
    monkeypatch.setattr(jobs_main, "JOB_REGISTRY", updated)

    handlers = dict(readiness_checks(settings))
    ok, detail = handlers["job_executors"]()
    assert ok is True
    assert "history_load" in detail
    assert f"{updated[1].name}@{updated[1].milestone}" in detail


def test_имя_процесса_совпадает_с_именем_в_compose() -> None:
    assert APP_NAME == "jobs"
