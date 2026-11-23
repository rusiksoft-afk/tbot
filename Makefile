# Обязательный интерфейс разработки (TZ §4). Все цели тонкие: реальная логика в
# scripts/dev.py, чтобы один и тот же набор команд работал на dev-машине Windows, на Linux
# и в CI. Переопределение интерпретатора: make lint PY=py
PY ?= python
COMPOSE = docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml

.PHONY: help dev lint fmt typecheck test test-live e2e migrate revision seed-dev \
        history-load backtest deploy-check audit-verify suppressions backup restore-verify deploy ci-local clean

help:  ## список команд
	@$(PY) scripts/dev.py --list

dev:  ## compose up: postgres + web + engine + tgbot + jobs (sandbox/paper)
	@$(PY) scripts/dev.py dev

lint:  ## ruff format --check && ruff check && mypy
	@$(PY) scripts/dev.py lint

fmt:  ## отформатировать код (ruff format + ruff check --fix)
	@$(PY) scripts/dev.py fmt

typecheck:  ## только mypy
	@$(PY) scripts/dev.py typecheck

test:  ## pytest -m "not live_api and not e2e" с покрытием
	@$(PY) scripts/dev.py test

test-live:  ## pytest -m live_api (только песочница, нужен TBOT_SANDBOX_TOKEN)
	@$(PY) scripts/dev.py test-live

e2e:  ## pytest -m e2e (Playwright против dev-стенда)
	@$(PY) scripts/dev.py e2e

migrate:  ## alembic upgrade head
	@$(PY) scripts/dev.py migrate

revision:  ## alembic revision --autogenerate (m="текст")
	@$(PY) scripts/dev.py revision --message "$(m)"

seed-dev:  ## фикстуры dev-стенда
	@$(PY) scripts/dev.py seed-dev

history-load:  ## загрузчик истории: INSTRUMENT=SBER03 TF=1min FROM=2022-01-01
	@$(PY) scripts/dev.py history-load --instrument "$(INSTRUMENT)" --tf "$(TF)" --from "$(FROM)"

backtest:  ## прогон бэктеста: CFG=configs/backtests/grid_sber.yaml
	@$(PY) scripts/dev.py backtest --config "$(CFG)"

deploy-check:  ## проверка конфигурации/сертификатов/времени перед боевым контуром
	@$(PY) scripts/dev.py deploy-check

audit-verify:  ## разбор цепочки хэшей журнала (код 1 — находки, AC-identity-04)
	@$(PY) scripts/dev.py audit-verify

suppressions:  ## посчитать подавления проверок (noqa / nosec / pragma: no cover)
	@$(PY) scripts/dev.py suppressions

backup:  ## pg_dump в ./backups + чек-сумма
	@$(PY) scripts/dev.py backup

restore-verify:  ## восстановление дампа и сверка контрольных сумм
	@$(PY) scripts/dev.py restore-verify

deploy:  ## ручной прод-деплой (pull по digest + миграции); подтверждается отдельно
	@$(PY) scripts/dev.py deploy

ci-local:  ## то же, что исполняет CI, но локально
	@$(PY) scripts/dev.py ci-local

clean:  ## удалить артефакты сборки и кэши
	@$(PY) scripts/dev.py clean
