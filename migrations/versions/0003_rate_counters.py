"""Счётчик частоты запросов и формат хэша значения куки (T-102, веха M1).

Что появляется:

1. **Таблица `rate_buckets`** — прикладной счётчик частоты запросов (TZ §8.3). В перечне §4.1 её
   нет: §8.3 требует счётчик на уровне приложения (веб-сервером выбран Caddy, а у официального
   образа встроенного ограничения частоты запросов нет — ADR-003), но модель данных §4.1 места для
   него не отводила. Форма: строка на (область, субъект, начало минутного окна); четыре области —
   ровно четыре лимита §8.3 (`login_ip`, `totp_session`, `totp_ip`, `mutation_user`).
   Обоснование и отвергнутые альтернативы — `docs/adr/ADR-007` (решение заказчика, ask
   `fe0b025e`).
2. **CHECK формата `sessions.token_hash`** (`token_hash ~ '^[0-9a-f]{64}$'`) — та же форма, что
   держат проверки для `password_hash`, хэшей резервных кодов и цепочки аудита в ревизии `0002`.
   Заказчик решил не гнать отдельную миграцию ради одной проверки, поэтому она идёт здесь
   (ask `fe0b025e`, `docs/HANDOFF.md §4`).

Что сознательно не появляется:

- **Пятиминутное окно** из §8.2 («3 неудачные попытки с одного IP за 5 минут → временный бан
  IP»). Механизм, названный в этой фразе ТЗ (`nginx/fail2ban`), в нашем стеке не работает: nginx
  заменён на Caddy, `fail2ban` на ВМ относится к SSH. Пока заказчик не выбрал, кто держит бан
  (приложение, логи + `fail2ban`, или оба слоя), `window_seconds` остаётся ограниченным значением
  `60` — расширять CHECK «на будущее» незачем. Вопрос открыт в `docs/HANDOFF.md §4`.
- **Внешние ключи на `users`/`sessions`.** Общее правило §4 (`ON DELETE RESTRICT`) здесь не
  применяется намеренно: счётчики обязаны умирать по возрасту, а не удерживать удаление учётной
  записи. Исключение зафиксировано в ADR-007 и в `tests/contract/test_identity_schema.py`
  (таблица вне перечня §4.1 проверяется отдельно).
- **Индексов кроме одного — нет.** Единственный запрос слоя входа («счётчик по области, субъекту и
  текущему окну») обслуживает первичный ключ; `ix_rate_buckets_window_start` нужен фоновой чистке
  старых окон, без неё таблица росла бы всё время работы площадки.

Права: отдельных выдач прав нет и быть не должно — таблицу создаёт миграция, то есть роль
приложения (`ADR-006`, вариант Б), она и владелец. В реестр `APPEND_ONLY_TABLES` счётчик не входит: он
изменяемый по природе, и `deploy/postgres/roles.sql` его не касается.

Проверки: `upgrade head → downgrade base → upgrade head` (CI job `migrations`), офлайн-сверка
моделей и ревизии — `tests/contract/test_identity_schema.py` и
`tests/contract/test_rate_limits_schema.py`, поведение на живой базе —
`tests/integration/test_rate_buckets_db.py`.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Тот же шаблон, что в `packages/storage/models.py` и в ревизии 0002 для остальных хэшей:
# SHA-256 в нижнем регистре hex, ровно 64 символа.
_SHA256_HEX = "^[0-9a-f]{64}$"

# Области счётчика — закрытый перечень из четырёх лимитов TZ §8.3 (см. `RATE_SCOPES` в моделях).
_RATE_SCOPE_CHECK = "scope IN ('login_ip', 'totp_session', 'totp_ip', 'mutation_user')"
# §8.3 все лимиты заданы «в минуту»: окно ровно одно, и оно зафиксировано базой.
_RATE_WINDOW_SECONDS = 60


def upgrade() -> None:
    _rate_buckets()
    # op.f обязателен: конвенция имён `ck_%(table_name)s_%(constraint_name)s` иначе подставит
    # префикс повторно и получится ck_sessions_ck_sessions_… (проверено офлайн-генерацией).
    op.create_check_constraint(
        op.f("ck_sessions_token_hash_format"),
        "sessions",
        f"token_hash ~ '{_SHA256_HEX}'",
    )


def downgrade() -> None:
    # Порядок обратный созданию: сначала ограничение на `sessions`, затем индекс и таблица
    # счётчика. Снятие CHECK с чужой таблицы не должен переживать откат: если его забыть,
    # повторный `upgrade head` упадёт на «constraint already exists».
    op.drop_constraint(op.f("ck_sessions_token_hash_format"), "sessions", type_="check")
    op.drop_index("ix_rate_buckets_window_start", table_name="rate_buckets")
    op.drop_table("rate_buckets")


def _rate_buckets() -> None:
    op.create_table(
        "rate_buckets",
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column(
            "bucket_key",
            sa.Text(),
            nullable=False,
            comment=(
                "Субъект лимита: канонический текст адреса из X-Forwarded-For (login_ip, totp_ip) "
                "или строка UUID сессии/пользователя (totp_session, mutation_user)"
            ),
        ),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "window_seconds",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text(str(_RATE_WINDOW_SECONDS)),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint(
            "scope", "bucket_key", "window_start", name=op.f("pk_rate_buckets")
        ),
        sa.CheckConstraint(_RATE_SCOPE_CHECK, name=op.f("ck_rate_buckets_scope")),
        sa.CheckConstraint(
            f"window_seconds = {_RATE_WINDOW_SECONDS}", name=op.f("ck_rate_buckets_window_seconds")
        ),
        sa.CheckConstraint(
            "length(bucket_key) BETWEEN 1 AND 64", name=op.f("ck_rate_buckets_bucket_key_len")
        ),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_rate_buckets_attempts_not_negative")),
        comment=(
            "Прикладной счётчик частоты запросов (TZ §8.3, ADR-007): строка на "
            "(область, субъект, начало минутного окна). subject — IP из X-Forwarded-For "
            "либо строка UUID сессии/пользователя; чистка — по window_start."
        ),
    )
    op.create_index(
        "ix_rate_buckets_window_start", "rate_buckets", ["window_start"], unique=False
    )
