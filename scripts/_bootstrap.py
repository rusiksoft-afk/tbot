"""Доступ к пакетам репозитория для скриптов, запущенных «файлом по пути».

Скрипты площадки (`deploy_check.py`) вызываются напрямую — `python scripts/deploy_check.py` —
и тогда каталог репозитория ещё не виден в `sys.path`. Сторонних зависимостей здесь нет:
важно, что импорт этого модуля ничего не проверяет и не печатает, а только настраивает путь.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def ensure_repo_root_on_path() -> Path:
    """Добавить корень репозитория в `sys.path`, если его там нет.

    Возвращает корень — чтобы вызывающий код мог строить пути относительно него, а не
    «вслепую» полагаться на текущий каталог.
    """
    path = str(REPO_ROOT)
    if path not in sys.path:
        sys.path.insert(0, path)
    return REPO_ROOT
