"""Реестр периодических задач виден из кода и из `/readyz` (docs/tz/12 §12.3, `ADR-007`).

Задача, исполнителя которой ещё нет, не может числиться «выполненной успешно»: она отсутствует
в исполнителях, и готовность процесса это показывает. Отсюда два разных объекта:

* `JOB_REGISTRY` — декларативное объявление (имя, интервал, веха, задача плана); оно видно без
  подключения к базе и без исполнителя;
* `build_job_registry(engine)` — то же, но с подключёнными исполнителями: исполнитель появляется
  только когда для него есть всё нужное (для чистки окон счётчика — движок базы, то есть адрес);
* `readiness_checks(settings, registry)` — ответ `/readyz` по тому же реестру, которым процесс
  собирается работать (а не по собственной копии).

Срез `R3d` (`T-102`, `docs/adr/ADR-007`) принёс первую исполненную задачу — `rate_bucket_purge`
(раз в час, окна старше 24 часа, ask `abb0151c`): без неё «временные» строки счётчика остаются
навсегда, поэтому регламент проверяется здесь, а не комментарием.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import SecretStr
from sqlalchemy.engine import Engine

import apps.jobs.main as jobs_main
from apps.jobs.main import (
    APP_NAME,
    JOB_REGISTRY,
    JobSpec,
    build_job_registry,
    due_jobs,
    readiness_checks,
    run_job,
)
from apps.jobs.maintenance import (
    PURGE_JOB_NAME,
    RATE_BUCKET_PURGE_INTERVAL_S,
    RATE_BUCKET_RETENTION,
    build_job_engine,
)
from packages.common.config import Settings

# Интервалы соответствуют docs/tz/12 §12.3; нижняя граница — чтобы задача не превратилась
# в «крутиться постоянно» на площадке с 2 vCPU.
MIN_INTERVAL_S = 60.0
MAX_INTERVAL_S = 7 * 24 * 3600.0

#: Адрес базы «без подключения»: `create_engine` соединение не открывает, поэтому проверка
#: появления исполнителя не требует живой базы (живая чистка окон — в job `migrations`).
_DSN = "postgresql+psycopg://tbot:ci-only@127.0.0.1:5432/tbot_jobs_check"


def _registry_with_db(settings: Settings) -> tuple[JobSpec, ...]:
    """Реестр с подключённым движком базы.

    `create_engine` соединения не открывает, поэтому проверка остаётся офлайновой: живая чистка
    окон проверяется в job `migrations` (`tests/integration/test_rate_limit_mechanism_db.py`).
    """
    engine: Engine | None = build_job_engine(settings)
    if engine is None:
        raise AssertionError("ожидался настроенный адрес базы")
    try:
        return build_job_registry(engine)
    finally:
        engine.dispose()


def test_имена_задач_уникальны() -> None:
    names = [job.name for job in JOB_REGISTRY]
    assert len(names) == len(set(names)), "две задачи с одним именем невозможно различить в логах"


def test_каждая_задача_привязана_к_вехе_и_задаче_плана() -> None:
    for job in JOB_REGISTRY:
        assert job.milestone in {"M1", "M2", "M3", "M4", "M5", "M6", "M7"}, job
        assert job.task.startswith("T-"), f"{job.name}: ссылка на задачу плана обязательна"
        assert MIN_INTERVAL_S <= job.interval_s <= MAX_INTERVAL_S, job.name


def test_объявленные_задачи_не_имеют_исполнителей_в_декларации() -> None:
    """В `JOB_REGISTRY` исполнителей нет: они подключает `build_job_registry`.

    Иначе «задача есть» означала бы «исполнитель есть» даже там, где неоткуда взять адрес базы, а
    `/readyz` врал бы о готовности — ровно то, ради чего этот файл и написан.
    """
    assert all(job.handler is None for job in JOB_REGISTRY), (
        "исполнитель, зашитый в декларативный реестр, невозможно отключить честным состоянием "
        "«нет адреса базы»"
    )


def test_чистка_окон_счётчика_объявлена_с_регламентом_adr_007() -> None:
    """Регламент выбран заказчиком: раз в час; окна старше 24 часов (`ADR-007`).

    Отдельно держится соотношение «порог хранения > самое широкое окно + срок бана»: иначе чистка
    могла бы удалить окно, которое ещё действующий бан (`ADR-007` прямо называет это опасностью).
    """
    purge = next(job for job in JOB_REGISTRY if job.name == PURGE_JOB_NAME)
    assert (
        purge.interval_s == RATE_BUCKET_PURGE_INTERVAL_S == 3600.0
    ), f"регламент чистки окон: {purge.interval_s} с, решено — раз в час"
    assert purge.milestone == "M1"
    assert purge.task == "T-102"

    widest_window_s = 300
    ban_s = 15 * 60
    assert RATE_BUCKET_RETENTION.total_seconds() > widest_window_s + ban_s, (
        f"порог чистки {RATE_BUCKET_RETENTION} короче действующего бана: "
        "удалялось бы окно, которое ещё запрещает вход"
    )


def test_исполнитель_чистки_появляется_только_при_адресе_базы(
    settings: Settings,
) -> None:
    """Без `db_url` исполнителя нет, и готовность это называет; с адресом — он появляется.

    Проверка не трогает базу: движок строится лениво. Смысл проверки в другом — состояние «базы
    нет» остаётся честным, а не превращается в падающую каждую минуту задачу.
    """
    without = build_job_registry(None)
    assert all(
        job.handler is None for job in without
    ), "исполнитель появился без адреса базы: задача выглядела бы исполняемой"

    with_db = Settings(
        secrets_dir=settings.secrets_dir, instance_name="test", db_url=SecretStr(_DSN)
    )
    handlers = {job.name: job.handler for job in _registry_with_db(with_db)}
    assert handlers[PURGE_JOB_NAME] is not None, "чистка окон не подключена при настроенном адресе"
    for name, handler in handlers.items():
        if name != PURGE_JOB_NAME:
            assert handler is None, f"{name}: исполнитель раньше своей вехи"


def test_готовность_сообщает_исполнителей_и_ожидающих(settings: Settings) -> None:
    """Без адреса базы ни один исполнитель не подключён — `/readyz` отвечает «не готово»."""
    handlers = dict(readiness_checks(settings, build_job_registry(None)))
    assert set(handlers) == {"retention", "job_executors"}
    ok, detail = handlers["job_executors"]()
    assert ok is False
    for job in JOB_REGISTRY:
        assert f"{job.name}@{job.milestone}" in detail


def test_готовость_становится_истинной_с_первым_исполнителем(settings: Settings) -> None:
    """Срез `R3d`: с настроенным адресом базы хотя бы одна задача исполнима — готовность `True`."""
    with_db = Settings(
        secrets_dir=settings.secrets_dir, instance_name="test", db_url=SecretStr(_DSN)
    )
    ok, detail = dict(readiness_checks(with_db, _registry_with_db(with_db)))["job_executors"]()
    assert ok is True, f"исполнитель чистки окон не отражён в готовности: {detail}"
    assert PURGE_JOB_NAME in detail
    for job in JOB_REGISTRY:
        if job.name != PURGE_JOB_NAME:
            assert f"{job.name}@{job.milestone}" in detail, "остальные вехи пропали из готовности"


def test_задача_с_исполнителем_считается_реализованной(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Проверка `job_executors` меняет ответ, когда появляется хотя бы один исполнитель.

    Реестр с явным исполнителем передаётся в `readiness_checks` и в `build_job_registry(None)`
    отдельно не затирается: иначе подключение движка молча отменяло бы явную привязку, а готовность
    отвечала бы по собственной копии реестра — расхождение «что обещаем / что делаем» стало бы
    невидимым.
    """

    def handler() -> str:
        return "свечи загружены"

    implemented = JobSpec("history_load", 300, "M2", "T-201", handler=handler)
    updated = (implemented, *(job for job in JOB_REGISTRY if job.name != implemented.name))
    monkeypatch.setattr(jobs_main, "JOB_REGISTRY", updated)

    handlers = dict(readiness_checks(settings, build_job_registry(None)))
    ok, detail = handlers["job_executors"]()
    assert ok is True
    assert "history_load" in detail
    pending = next(job for job in updated if job.name != implemented.name and job.handler is None)
    assert f"{pending.name}@{pending.milestone}" in detail


# ─── планировщик (срез `R3d`) ──────────────────────────────────────────────────────────────────


def _job(name: str, interval_s: float, handler: Callable[[], str] | None = None) -> JobSpec:
    return JobSpec(name, interval_s, "M1", "T-102", handler=handler or (lambda: "готово"))


def test_первая_попытка_не_ждёт_полного_интервала() -> None:
    """Сразу после старта окна могли накопиться: ждать час после запуска незачем."""
    registry = (_job(PURGE_JOB_NAME, RATE_BUCKET_PURGE_INTERVAL_S),)
    due = due_jobs(registry, {}, moment=0.0)
    assert [job.name for job in due] == [PURGE_JOB_NAME]


def test_следующая_попытка_не_раньше_интервала() -> None:
    registry = (_job(PURGE_JOB_NAME, RATE_BUCKET_PURGE_INTERVAL_S),)
    last_run = {PURGE_JOB_NAME: 100.0}
    before = due_jobs(registry, last_run, moment=100.0 + RATE_BUCKET_PURGE_INTERVAL_S - 1)
    assert not before, "задача выполнилась раньше регламента"
    after = due_jobs(registry, last_run, moment=100.0 + RATE_BUCKET_PURGE_INTERVAL_S)
    assert [job.name for job in after] == [PURGE_JOB_NAME]


def test_задача_без_исполнителя_никогда_не_назначается() -> None:
    """Отсутствие исполнителя — не «пустая операция», а отсутствие задачи в прогоне."""
    registry = (JobSpec("history_load", 300, "M2", "T-201"),)
    assert not due_jobs(registry, {}, moment=0.0)


def test_провал_задачи_не_ломает_процесс_и_не_выдаётся_за_успех() -> None:
    """Падающая задача не должна ронять процесс и не должна повторяться каждые 15 секунд.

    Провал обязан остаться в журнале процесса (`run_job` пишет `job.exception`): неразбираемый
    отказ чистки окон выглядел бы как «всё хорошо», а таблица счётчика росла бы вечно.
    """
    failures: list[str] = []

    def handler() -> str:
        failures.append("вызов")
        raise RuntimeError("база недоступна")

    registry = (_job(PURGE_JOB_NAME, RATE_BUCKET_PURGE_INTERVAL_S, handler),)
    last_run: dict[str, float] = {}
    run_job(registry[0], last_run, moment=0.0)
    assert failures == ["вызов"]
    assert PURGE_JOB_NAME in last_run, "провал не отмечен: следующая попытка наступила бы сразу"
    assert not due_jobs(registry, last_run, moment=RATE_BUCKET_PURGE_INTERVAL_S - 1)


def test_успешная_задача_отмечается_и_возвращает_текст_для_журнала() -> None:
    last_run: dict[str, float] = {}
    registry = (_job(PURGE_JOB_NAME, RATE_BUCKET_PURGE_INTERVAL_S),)
    run_job(registry[0], last_run, moment=42.0)
    assert last_run[PURGE_JOB_NAME] == 42.0


def test_исполнитель_чистки_сообщает_число_удалённых_строк(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Исполнитель существует не ради галочки: он возвращает объяснение для журнала процесса.

    Сама чистка проверяется на живой базе (`test_rate_limit_mechanism_db.py`, job `migrations`);
    здесь проверяется только связка «реестр ↔ исполнитель ↔ текст» и то, что она не требует сети.
    """
    monkeypatch.setattr(jobs_main, "purge_expired_rate_buckets", lambda _factory: 7)
    with_db = Settings(
        secrets_dir=settings.secrets_dir, instance_name="test", db_url=SecretStr(_DSN)
    )
    handlers = {job.name: job.handler for job in _registry_with_db(with_db)}
    handler = handlers[PURGE_JOB_NAME]
    assert handler is not None
    assert handler() == "окон счётчика удалено: 7"


def test_имя_процесса_совпадает_с_именем_в_compose() -> None:
    assert APP_NAME == "jobs"
