-- Правовая модель базы данных (T-009, REQ-identity-04, TZ §4.1 и §8.4).
--
-- Роли две: `tbot_app` — от неё работают `web`, `engine`, `jobs` (только DML);
-- `tbot` — владелец схемы, от неё идут `migrate` и административные команды. Разделение нужно
-- потому, что append-only к `audit_log` формулируется правами базы: у владельца таблицы отзыв
-- прав не работает (права владельца неявные), поэтому приложение обязано ходить НЕ владельцем.
--
-- Запускать после применения миграций: права выдаются по уже существующим таблицам, а исключение
-- для журнала выдаётся явно. После каждой ревизии, которая добавляет таблицу, файл тоже нужно
-- запускать повторно (он идемпотентен) — иначе новая таблица не получит прав.
--
-- Паролей здесь нет и быть не должно: значения — секреты (ADR-004), их вносит
-- `deploy/vps/secrets-setup.sh`; здесь только имена ролей и права.

BEGIN;

-- 1) Роль приложения. Создаётся без пароля и без права входа: пока шаг переключения не выдал
--    пароль и LOGIN, войти в неё нельзя, и это правильно. Повторный запуск файла права входа не
--    отзывает (иначе `roles.sql`, запущенный после переключения, отключил бы приложение).
DO $do$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tbot_app') THEN
        CREATE ROLE tbot_app NOLOGIN;
    END IF;
END
$do$;

ALTER ROLE tbot_app WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- 2) Схема: приложение пользуется `public`, но не создаёт в нём объектов (DDL — у владельца).
--    В PostgreSQL 15+ право CREATE на `public` есть только у владельца базы; строка ниже —
--    страховка от иного способа инициализации кластера.
GRANT USAGE ON SCHEMA public TO tbot_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- 3) Все таблицы текущей схемы: полный DML.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tbot_app;

-- 4) Журнал — только дописывание и чтение (REQ-identity-04).
--    `TRUNCATE`, `REFERENCES` и `TRIGGER` отзываются, потому что журнал не должен
--    перестраиваться, становиться целью внешних ключей из новых таблиц или обвешиваться
--    триггерами, которые меняют правило «дописали — и больше не трогают».
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE audit_log FROM tbot_app;

-- 5) Таблицы, которые появятся в следующих ревизиях, получают полный DML автоматически.
--    Без этого новая таблица была бы невидима для приложения до ближайшего ручного `GRANT`.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tbot_app;

-- Явные последовательности — только USAGE. У identity-колонки своя внутренняя последовательность
-- (например, `audit_log_id_seq`), отдельного права на неё не требуется: PostgreSQL проверяет
-- права на саму таблицу (`NextValueExpr` в движке вызывается без проверки прав последовательности).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO tbot_app;

-- 6) Членство: владелец может пересесть в роль приложения (`SET ROLE tbot_app`) и проверить права
--    без пароля — этим пользуются runbook и тест `test_audit_append_only_role`.
GRANT tbot_app TO CURRENT_USER;

COMMIT;
