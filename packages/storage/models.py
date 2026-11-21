"""ORM-отображения таблиц идентичности и доступа (TZ §4.1, §8.1–8.5).

Это определение схемы, а не «модель предметной области»: правила входа, ролей и 2FA живут в
`identity` (T-101…T-109), здесь только то, что обязана выдержать база. Поэтому отображения
намеренно без `relationship()`: путь доступа задаёт модуль верхнего уровня, а не схема.

Три вещи закреплены здесь специально, чтобы они не всплыли позже как правка схемы.

1. **Формат хэшей и алгоритм.** `ck_users_password_hash_argon2id` отвергает другой формат,
   потому что §8.1 фиксирует Argon2id: случайно сохранённый bcrypt или открытый пароль — это
   ошибка приложения, и база обязана её отклонить. Аналогично
   `ck_backup_codes_code_hash_sha256` (§8.2: резервные коды хранятся хэшами SHA-256) и
   `ck_audit_log_hash_sha256` (REQ-identity-04: цепочка SHA-256).
2. **Одна активная привязка TOTP** — `ix_totp_enrollments_user_active`, уникальный частичный
   индекс по `user_id` при `revoked_at IS NULL`. Без него два незавершённых этапа привязки
   дают две действующие тайны, и «отзыв 2FA» превращается в неопределённый вопрос.
3. **Секрет куки не равен первичному ключу.** §8.3 требует «случайный id 256 бит», а UUID несёт
   122 случайных бита. Значит в куке живёт отдельное 256-битное значение, а в базе — его
   SHA-256 (`sessions.token_hash`); UUID остаётся внутренним идентификатором. Колонки нет в
   перечне §4.1; обоснование и запрос заказчику — `docs/HANDOFF.md §2`.

Вещественных типов в схеме нет (§4.11, `REQ-storage-02`) — за этим следит
`tests/contract/test_identity_schema.py`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from packages.common.ids import uuid7
from packages.storage.base import Base

# Везде timestamptz (TZ §4 «общие правила»); время в базе — UTC (TZ §2.7, `time_basis` из 0001).
TIMESTAMPTZ: Final = DateTime(timezone=True)

# Домены перечислений — ровно множества из §4.1 и §1.1. PG-enum не используется намеренно:
# в §4.1 перечисление записано как `text` с `check`, и расширение домена не требует DDL-шага
# с переименованием типа (для PG-enum пришлось бы пересоздавать колонку).
USER_ROLES: Final[tuple[str, ...]] = ("admin", "operator", "viewer")
USER_STATES: Final[tuple[str, ...]] = (
    "invited",
    "awaiting_approval",
    "active",
    "suspended",
    "archived",
)
SESSION_AUTH_STEPS: Final[tuple[str, ...]] = ("password", "totp", "full")
# «Просрочено» — не состояние: это производное от `expires_at` и часов. Хранить его флагом
# значит получить расхождение между состоянием и временем.
INVITATION_STATES: Final[tuple[str, ...]] = ("pending", "used", "revoked")

# §8.2: «допуск ±1 шаг (по умолчанию ±1, максимум ±2)».
TOTP_WINDOW_MIN: Final = 0
TOTP_WINDOW_DEFAULT: Final = 1
TOTP_WINDOW_MAX: Final = 2
# SHA-256 в нижнем регистре hex — ровно 64 символа; используется в проверках хэшей ниже.
_SHA256_HEX = "^[0-9a-f]{64}$"


def _new_uuid() -> uuid.UUID:
    """Первичные ключи генерирует приложение: UUIDv7 из `packages/common/ids.py`.

    Порядок нужен и базе: случайные UUIDv4 фрагментируют индексы, а UUIDv7 упорядочен по
    времени создания, поэтому `ORDER BY id` совпадает с хронологией появления строк.
    """
    return uuid7()


class User(Base):
    """Учётная запись закрытого клуба (§4.1; роли — §1.1; допуск — §1.2; пароль — §8.1).

    `password_hash` обязателен: строка `users` появляется вместе с паролем (принятие
    приглашения → установка пароля). Состояние «приглашение принято, пароля ещё нет» держит
    таблица `invitations`, а не пустой хэш в `users`: пустой хэш нельзя отличить от испорченного.

    `failed_attempts`/`locked_until` — блокировка после 5 неудач (§8.1, T-101). Счётчик живёт в
    базе, потому что процессов, которые трогают вход, несколько (`web`, позже API), и в памяти
    процесса они терялись бы при каждом рестарте.
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("login", name="uq_users_login"),
        CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="role"),
        CheckConstraint(
            "state IN ('invited', 'awaiting_approval', 'active', 'suspended', 'archived')",
            name="state",
        ),
        CheckConstraint("failed_attempts >= 0", name="failed_attempts_nonneg"),
        # §8.1: алгоритм один — Argon2id, канонический префикс `$argon2id$`. Сравнение через
        # `left(...)`, а не `LIKE '$argon2id$%'`: SQLAlchemy экранирует `%` для paramstyle драйвера,
        # и в сгенерированном `alembic upgrade --sql` появилось бы `%%` — семантически то же самое,
        # но человек, который сверяет DDL глазами перед прогоном на площадке, спотыкается об это.
        CheckConstraint("left(password_hash, 10) = '$argon2id$'", name="password_hash_argon2id"),
        {
            "comment": (
                "Учётные записи закрытого клуба (TZ §4.1). Строка не удаляется: только состояние "
                "`state='archived'`, иначе ссылки аудита, сессий и приглашений повиснут."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    # citext: логин и e-mail регистронезависимы (§4.1) — «Ivan» и «ivan» не две учётные записи.
    login: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    email: Mapped[str | None] = mapped_column(CITEXT())
    display_name: Mapped[str | None] = mapped_column(Text())
    role: Mapped[str] = mapped_column(Text(), nullable=False)
    # Начальное состояние — `invited` (§1.2: приглашение есть, шага одобрения ещё нет).
    # NOT NULL намеренно: пустое значение означало бы «неизвестно, можно ли входить».
    state: Mapped[str] = mapped_column(Text(), nullable=False, server_default=text("'invited'"))
    password_hash: Mapped[str] = mapped_column(
        Text(),
        nullable=False,
        comment="Argon2id (m=64 MiB, t=3, p=4), TZ §8.1; открытый пароль запрещён",
    )
    password_updated_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    # `default=0` на стороне Python — не дубль `server_default` ради красоты: без него у только что
    # созданного (ещё не сохранённого) объекта поле `None`, и арифметика счётчика неудач в
    # `packages/identity/users.py` падает на `NoneType + int`. В DDL это не меняет ничего:
    # ограничение `users_failed_attempts_nonneg_check` и `DEFAULT 0` остаются как есть.
    failed_attempts: Mapped[int] = mapped_column(
        Integer(), nullable=False, default=0, server_default=text("0")
    )
    locked_until: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )
    # `updated_at` ведёт приложение (`onupdate=now()`): в PostgreSQL нет `ON UPDATE` как в MySQL,
    # и умалчивать об этом нельзя — правка без явного требования даст устаревшую отметку.
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()"), onupdate=text("now()")
    )
    # Кто одобрил и когда (§1.2, шаг одобрения). Ссылка на себя же: одобряет другой админ или
    # тот же — база этого не различает, различает аудит (T-109).
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT")
    )
    approved_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)


class Invitation(Base):
    """Одноразовая ссылка допуска (§4.1, §1.2, `REQ-identity-02/03`, T-105).

    `expires_at` — срок 14 дней. Хэш токена, а не сам токен: утечка дампа не должна отдавать
    готовую ссылку допуска, а `REQ-identity-03` требует ещё и фиксировать все попытки
    использования в аудите.

    Роль назначает приглашение, а не выбирает приглашённый (§1.1: роли выдаёт `admin`).
    """

    __tablename__ = "invitations"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_invitations_token_hash"),
        CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="role"),
        CheckConstraint("state IN ('pending', 'used', 'revoked')", name="state"),
        # §1.2: приглашение адресуют либо по e-mail, либо по логину.
        CheckConstraint("email IS NOT NULL OR login IS NOT NULL", name="target_present"),
        {
            "comment": (
                "Приглашения закрытого допуска (TZ §1.2). Самостоятельной регистрации нет: "
                "ссылка одноразовая, срок 14 дней, все попытки использования — в audit_log."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    email: Mapped[str | None] = mapped_column(CITEXT())
    login: Mapped[str | None] = mapped_column(CITEXT())
    role: Mapped[str] = mapped_column(Text(), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        Text(), nullable=False, comment="SHA-256 от одноразового токена ссылки"
    )
    state: Mapped[str] = mapped_column(Text(), nullable=False, server_default=text("'pending'"))
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )


class TotpEnrollment(Base):
    """Привязка TOTP (§4.1, §8.2, T-103).

    Секрет — шифртекст AES-256-GCM (§8.4, KEK вне базы): открытого секрета в колонке быть не
    может, а `issuer` нужен для сборки URI `otpauth://` при выдаче QR-кода.

    Незавершённая привязка (`confirmed_at IS NULL`) — не «действующий второй фактор», а ожидание
    подтверждения двумя кодами (§8.2). Не активировать учётную запись в таком состоянии —
    правило приложения, база держит только различие «подтверждено/нет» и одну активную
    привязку на пользователя.
    """

    __tablename__ = "totp_enrollments"
    __table_args__ = (
        CheckConstraint(
            f"verify_window BETWEEN {TOTP_WINDOW_MIN} AND {TOTP_WINDOW_MAX}",
            name="verify_window",
        ),
        CheckConstraint("confirmed_at >= enrolled_at", name="confirmed_after_enrolled"),
        CheckConstraint("revoked_at >= enrolled_at", name="revoked_after_enrolled"),
        # Одна действующая привязка на пользователя (см. docstring модуля).
        Index(
            "ix_totp_enrollments_user_active",
            "user_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        {
            "comment": (
                "Привязки TOTP (TZ §8.2). Секрет — AES-256-GCM шифртекст, KEK вне БД (§8.4). "
                "Подтверждение — два последовательных кода, окно не выше ±2 шагов."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    secret_enc: Mapped[bytes] = mapped_column(
        LargeBinary(),
        nullable=False,
        comment="AES-256-GCM (nonce + тег + шифртекст); KEK вне БД, TZ §8.4",
    )
    issuer: Mapped[str] = mapped_column(
        Text(), nullable=False, comment="метка URI otpauth://; без неё QR-код не собрать"
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    verify_window: Mapped[int] = mapped_column(
        Integer(), nullable=False, server_default=text(str(TOTP_WINDOW_DEFAULT))
    )


class BackupCode(Base):
    """Резервный код входа (§4.1, §8.2, T-104).

    Коды одноразовые: `used_at` заполняется один раз, повторный вход по тому же коду обязан быть
    отвергнут приложением. Хранится хэш (§8.2 — SHA-256), поэтому проверка — сравнение хэша
    предъявленного значения.

    `uq_backup_codes_user_id_code_hash` не даёт выдать пользователю два одинаковых кода: иначе
    «10 шт.» из §8.2 тихо деградируют до «9 разных», а отказ при генерации — явный сигнал, а не
    потерянная строка.
    """

    __tablename__ = "backup_codes"
    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_backup_codes_user_id_code_hash"),
        CheckConstraint(f"code_hash ~ '{_SHA256_HEX}'", name="code_hash_sha256"),
        Index(
            "ix_backup_codes_user_id_unused",
            "user_id",
            postgresql_where=text("used_at IS NULL"),
        ),
        {
            "comment": (
                "Резервные коды 2FA (TZ §8.2): 10 шт. по 10 символов, хранятся хэшами SHA-256, "
                "одноразовые; расход кода = предупреждение + алерт админу + срок 7 дней."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(Text(), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )


class TotpFailure(Base):
    """Неудачные попытки кода 2FA (§4.1, §8.2).

    Лента, а не счётчик: из §8.2 следуют два разных правила — «5 неудачных кодов подряд у
    пользователя» и «3 попытки с одного IP за 5 минут». По одному счётчику второе не проверить,
    поэтому попытки пишутся строками, а окно считается запросом по `(user_id, at)` и `(ip, at)`.

    Записи не удаляются при успешном входе: иначе перебор «до блокировки» обнулялся бы успехом.
    Ретенция ленты — задача `jobs` (T-031), а не схемы.
    """

    __tablename__ = "totp_failures"
    __table_args__ = (
        Index("ix_totp_failures_user_id_at", "user_id", "at"),
        Index("ix_totp_failures_ip_at", "ip", "at"),
        {
            "comment": (
                "Попытки перебора кода 2FA (TZ §8.2): блокировка пользователя (5 подряд) "
                "и временный бан IP (3 за 5 минут)."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    ip: Mapped[str | None] = mapped_column(INET())
    # Источник попытки: 'web' / 'telegram'. Множество значений в §4.1 не закреплено, поэтому
    # проверку домена здесь не ставим — её определит T-103/T-110 вместе с маршрутами.
    source: Mapped[str] = mapped_column(Text(), nullable=False)


class UserSession(Base):
    """Сессия входа (§4.1, §8.3, T-102).

    `auth_step` держит двухшаговый вход (§8.2): `'password'` даёт доступ только к странице кода
    и к `/logout`, `'full'` — ко всему остальному. Значение живёт в базе, а не в куке: кука
    обязана быть только ссылкой на сессию, иначе шаг «поднимется» подменой значения на клиенте.

    `token_hash` — SHA-256 от 256-битного значения куки (§8.3). Первичный ключ наружу не
    показывается: случайных бит в UUID меньше, чем требует §8.3, а перебор UUID — это перебор
    сессий.

    `revoked_at` проверяется на каждом запросе (§8.3: «отзыв отражается немедленно»), поэтому
    частичный индекс по активным сессиям не нужен: активных строк мало, а смотрим по PK.
    """

    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
        CheckConstraint("auth_step IN ('password', 'totp', 'full')", name="auth_step"),
        # Сессия с просрочком в прошлом не может быть живой, а `expires_at <= created_at` —
        # ошибка приложения (idle 30 мин / abs 12 ч из §8.3 считаются от создания).
        CheckConstraint("expires_at > created_at", name="expires_after_created"),
        CheckConstraint("last_seen_at >= created_at", name="last_seen_not_before_created"),
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_expires_at", "expires_at"),
        {
            "comment": (
                "Сессии веб-входа (TZ §8.3): кука HttpOnly/Secure/SameSite=Lax, idle 30 мин, "
                "абсолютный срок 12 ч, шаг 2FA в `auth_step`, наружу — значение из `token_hash`."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(
        Text(), nullable=False, comment="SHA-256 от 256-битного значения куки (TZ §8.3)"
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()"), onupdate=text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False)
    ip: Mapped[str | None] = mapped_column(INET())
    user_agent: Mapped[str | None] = mapped_column(Text())
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMPTZ)
    auth_step: Mapped[str] = mapped_column(
        Text(), nullable=False, server_default=text("'password'")
    )


class IpAllowlist(Base):
    """Список допуска по IP (§4.1, §8.5, T-110).

    Строки — источник и для Caddy (`remote_ip`), и для приложения. Emergency-переключатель
    «только VPN-подсеть» делается тем же полем `enabled`, а не отдельной таблицей: два способа
    выключить допуск — это два способа разойтись.

    `cidr` уникален: одно значение не может быть одновременно включено и выключено. Индекса для
    «попадает ли адрес в список» нет намеренно: таблица из нескольких строк, выбор —
    последовательное сканирование, а путь проверки определит T-110.

    Тип — `inet`, как зафиксировано в §4.1 (`cidr inet not null`), а не `cidr`: в inet можно
    записать отдельный адрес (`203.0.113.7/32`) и сеть (`203.0.113.0/24`) в одном столбце, и
    приложение само решает, что сравнивать (`>>=` по сети или `=` по адресу). Нормализации к
    сети здесь нет — это отличие от типа `cidr` обязан учитывать T-110.
    """

    __tablename__ = "ip_allowlist"
    __table_args__ = (
        UniqueConstraint("cidr", name="uq_ip_allowlist_cidr"),
        {
            "comment": (
                "IP-allowlist периметра (TZ §8.5). Тип inet: значение — адрес с маской или сеть; "
                "в отличие от cidr, хостовые биты не обнуляются (учесть в T-110)."
            )
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_new_uuid)
    cidr: Mapped[str] = mapped_column(INET(), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text())
    # NULL допустим: строку мог добавить не пользователь (начальная настройка, восстановление из
    # дампа). Требовать «автора» у каждой строки — значит выдумывать служебную учётную запись.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMPTZ, nullable=False, server_default=text("now()")
    )
    enabled: Mapped[bool] = mapped_column(Boolean(), nullable=False, server_default=text("true"))


class AuditLogEntry(Base):
    """Журнал аудита с цепочкой хэшей (§4.1 `REQ-identity-04`, §8.7, T-109).

    Append-only держится правами базы, а не поведением приложения: роль приложения получает на
    `audit_log` только `SELECT` и `INSERT` (`deploy/postgres/roles.sql`, проверка
    `test_audit_append_only_role`). Цепочка `hash_prev`/`hash` (SHA-256 от канонического JSON
    записи + предыдущий хэш) позволяет найти разрыв, если запись меняли правами владельца схемы
    (`AC-identity-04`: изменённая вручную копия дампа должна быть найдена `audit-verify`).

    `actor` ссылается на `users`: события с неизвестным субъектом (неудачный вход по чужому
    логину) остаются с `actor IS NULL` — это различие «никого» и «неизвестно», а не пустое поле.

    Модель объявлена без `onupdate` и без мягкого удаления: у журнала нет редактируемых полей,
    а правка строк — ровно то, что цепочка обязана обнаружить.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(f"hash ~ '{_SHA256_HEX}'", name="hash_sha256"),
        CheckConstraint(
            f"hash_prev IS NULL OR hash_prev ~ '{_SHA256_HEX}'", name="hash_prev_sha256"
        ),
        Index("ix_audit_log_at", "at"),
        Index("ix_audit_log_actor_at", "actor", "at"),
        Index("ix_audit_log_entity", "entity", "entity_id"),
        {
            "comment": (
                "Append-only журнал (TZ §4.1, §8.7). Права приложения: SELECT + INSERT. "
                "Целостность цепочки — `make audit-verify` (T-109)."
            )
        },
    )

    # BIGINT GENERATED BY DEFAULT AS IDENTITY — postgres-эквивалент `bigserial` из §4.1: `serial`
    # в PG16 определён именно как identity. Явная форма читается в `\d+` и не даёт вставить свой
    # id молча (нужен OVERRIDING SYSTEM VALUE — как раз то, что делает pg_dump при восстановлении).
    id: Mapped[int] = mapped_column(BigInteger(), Identity(always=False), primary_key=True)
    at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    actor: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="RESTRICT")
    )
    action: Mapped[str] = mapped_column(Text(), nullable=False)
    entity: Mapped[str | None] = mapped_column(Text())
    entity_id: Mapped[str | None] = mapped_column(Text())
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB())
    ip: Mapped[str | None] = mapped_column(INET())
    request_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    hash_prev: Mapped[str | None] = mapped_column(
        Text(), comment="хэш предыдущей записи цепочки; NULL у первой записи"
    )
    hash: Mapped[str] = mapped_column(
        Text(), nullable=False, comment="SHA-256 от канонического JSON записи + hash_prev"
    )
