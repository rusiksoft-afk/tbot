"""Фоновые операции процесса `jobs`: чистка окон прикладного счётчика частоты (`ADR-007`, TZ §8.3).

Регламент выбран заказчиком (ask `abb0151c`): прогон **раз в час**, удаляются окна **старше 24
часов**. Ленивая чистка внутри слоя входа отвергнута тем же решением: она переносила бы фоновую
работу на путь аутентификации, то есть ровно туда, где перебор и так создаёт нагрузку.

Почему чистка обязательна, а не «желательна»: `rate_buckets` растёт всё время работы площадки
(каждый лимитируемый запрос и каждая неудача входа — это строка окна), и без удаления старых окон
«временные» строки остаются навсегда. Индекс `ix_rate_buckets_window_start` заведён в схеме именно
под этот запрос.

Порог хранения (24 часа) заметно больше и самого широкого окна счётчика (300 с), и срока бана
(15 минут), поэтому чистка не может «съесть» ещё действующий бан: окно, которое всё ещё запрещаешь,
всегда моложе границы. Это проверяет контрактный тест, а не комментарий.

Значения держатся константами кода, а не настройкой: то же правило, что у сроков сессий и
блокировок (`test_sessions_contract.py`). Сдвинуть их — решение заказчика, а не правка YAML.

Фабрика сессий здесь своя, а не взятая из `apps/web/store.py`: межпроцессные импорты процессов
запрещены контрактом `test_repo_layout.py` («процессы общаются через базу, а не друг через друга»,
TZ §02 §2.1), а общий слой (`packages/*`) права импортировать `apps/*` не имеет. Различия в
настройке пула осознанные: задачам не нужен пул на 15 соединений — одна короткая операция в час.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final

from sqlalchemy import create_engine, delete
from sqlalchemy.engine import Engine

from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.common.db import sqlalchemy_url
from packages.storage.models import RateBucket

#: Имя задачи: оно же — в `/readyz` и в логах, менять его можно только вместе с проверками.
PURGE_JOB_NAME: Final = "rate_bucket_purge"

#: Интервал прогона чистки: раз в час (ask `abb0151c`).
RATE_BUCKET_PURGE_INTERVAL_S: Final = 3600.0

#: Возраст окна, после которого оно не нужно никому (ask `abb0151c`: 24 часа). Граница
#: строго «старше»: окно ровно суточной давности ещё удаляется, а чуть более свежее остаётся.
RATE_BUCKET_RETENTION: Final = timedelta(hours=24)


def build_job_engine(settings: Settings) -> Engine | None:
    """Движок для задач; `None`, если адрес базы не настроен.

    `None` — честное состояние, а не отложенная ошибка: без адреса базы у задачи нет исполнителя, и
    `/readyz` процесса это показывает (`readiness_checks` в `apps/jobs/main.py`). Процесс `jobs`
    при этом обязан оставаться живым: `liveness` не зависит от базы ровно как у `web` (иначе
    healthcheck ломает состав, а не только задачу).

    Адрес обязательно прогоняется через `sqlalchemy_url`: на площадке `db_url` лежит в форме
    `postgresql+psycopg://…`, а в CI переменная — в прямой `postgresql://…` (`packages/common/db.py`).

    Движок, а не `sessionmaker`: задача выполняет один Core-`DELETE`, ей не нужны ни identity map,
    ни `commit()` слоя ORM — транзакцию задаёт `engine.begin()`.
    """
    if settings.db_url is None:
        return None
    return create_engine(
        sqlalchemy_url(settings.db_url.get_secret_value()),
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=3,
    )


def purge_expired_rate_buckets(engine: Engine, *, moment: datetime | None = None) -> int:
    """Удалить окна счётчика старше `RATE_BUCKET_RETENTION`; вернуть число удалённых строк.

    Один `DELETE` по индексу `window_start`, а не «прочитать и удалить по одной строке»: таблица
    между чистками на активном переборе — тысячи строк, и вычитывать их в процесс с 2 vCPU незачем.

    Идемпотентность обязательна: повторный прогон не должен менять ничего, кроме нуля удалённых
    строк (`ADR-002` требует возможности повторить операцию после сбоя).
    """
    cutoff = (moment or utc_now()) - RATE_BUCKET_RETENTION
    with engine.begin() as connection:
        result = connection.execute(delete(RateBucket).where(RateBucket.window_start < cutoff))
        return int(result.rowcount)
