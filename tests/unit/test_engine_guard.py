"""M0: охрана контуров ядра — боевой запуск запрещён до окончания вехи M3 (docs/tz/14, T-004).

Заглушка не должна оказаться способной «что-то отправить брокеру»: проверка выполняется до
подъёма эндпоинтов состояния, и её результат виден в `/readyz`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apps.engine.main import APP_NAME, contour_guard, readiness_checks
from packages.common.config import Contour, Settings


@pytest.fixture(params=[Contour.SANDBOX, Contour.PAPER, Contour.PRODUCTION])
def settings_for_contour(secrets_dir: Path, request: pytest.FixtureRequest) -> Settings:
    # Явное подтверждение боевого контура здесь нужно, чтобы конфигурация вообще дала себя
    # создать: охрана на уровне конфигурации проверяется отдельно (test_config_ranges), а здесь
    # проверяется отказ самого процесса `engine`.
    return Settings(secrets_dir=secrets_dir, contour=request.param, confirm_production=True)


def test_боевой_контур_отклоняется_на_текущей_вехе(secrets_dir: Path) -> None:
    settings = Settings(
        secrets_dir=secrets_dir, contour=Contour.PRODUCTION, confirm_production=True
    )
    ok, detail = contour_guard(settings)
    assert ok is False
    assert "production" in detail or "боевой" in detail
    # Причина отказа обязана быть проверяемой ссылкой на веху, а не «нельзя».
    assert "M3" in detail


def test_песочница_и_бумажный_контур_разрешены(secrets_dir: Path) -> None:
    for contour in (Contour.SANDBOX, Contour.PAPER):
        ok, detail = contour_guard(Settings(secrets_dir=secrets_dir, contour=contour))
        assert ok is True
        assert contour.value in detail


def test_проверки_готовности_перечисляют_имена(settings: Settings) -> None:
    checks = readiness_checks(settings)
    names = [name for name, _ in checks]
    assert names == ["contour", "config"]
    for _name, handler in checks:
        ok, detail = handler()
        assert isinstance(ok, bool)
        assert detail, f"проверка {_name} обязана давать объяснение"


def test_потолки_риска_видны_в_готовности(settings: Settings) -> None:
    """Потолки ядра показываются в `/readyz`: конфигурация не может «тихо» их поднять."""
    handlers = dict(readiness_checks(settings))
    ok, detail = handlers["config"]()
    assert ok is True
    assert f"{settings.limits.max_capital_share_per_strategy:.2%}" in detail
    assert f"уровней сетки ≤{settings.limits.max_grid_levels}" in detail
    assert f"множитель ≤{settings.limits.max_grid_multiplier}" in detail


def test_проверка_контура_зависит_от_настройки(settings_for_contour: Settings) -> None:
    checks = dict(readiness_checks(settings_for_contour))
    ok, _detail = checks["contour"]()
    expected_ok = settings_for_contour.contour is not Contour.PRODUCTION
    assert ok is expected_ok


def test_имя_процесса_совпадает_с_именем_в_compose() -> None:
    """Имя процесса используется в метке `app` — оно должно совпадать с сервисом compose."""
    assert APP_NAME == "engine"
