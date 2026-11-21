"""`identity` — доступ: учётные записи, роли, сессии, 2FA, журнал (CAPABILITY_MAP №4, TZ §8).

Слой отвечает за правила допуска к системе: пароли и их политика, блокировка перебора,
приглашения, сессии, TOTP и резервные коды, роли и авторизация на уровне сервиса. Схема данных
при этом принадлежит `storage` (ORM-отображения таблиц), а не здесь: `identity` только меняет
поля объектов и проверяет правила. Импорт разрешён только «вниз» по Capability Map
(контракт `tests/contract/test_repo_layout.py`).

Границы по срезам (см. `tasks/todo.md`): первый срез `T-101` — политика паролей и Argon2id;
следующий срез той же задачи — блокировка перебора входа. Сессии (`T-102`), TOTP и резервные
коды (`T-103`, `T-104`), приглашения (`T-105`) и роли (`T-106`) добавляются здесь же отдельными
срезами.
"""

from __future__ import annotations

from packages.identity.passwords import (
    ARGON2_HASH_LEN,
    ARGON2_HASH_PREFIX,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    MIN_PASSWORD_LENGTH,
    MalformedPasswordHashError,
    PasswordPolicyError,
    check_password_policy,
    hash_password,
    policy_violations,
    verify_password,
)

__all__ = (
    "ARGON2_HASH_LEN",
    "ARGON2_HASH_PREFIX",
    "ARGON2_MEMORY_COST_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_SALT_LEN",
    "ARGON2_TIME_COST",
    "MIN_PASSWORD_LENGTH",
    "MalformedPasswordHashError",
    "PasswordPolicyError",
    "check_password_policy",
    "hash_password",
    "policy_violations",
    "verify_password",
)
