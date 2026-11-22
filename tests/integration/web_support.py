"""Общая обвязка HTTP-тестов слоя входа: приложение с репозиторием в памяти (срез `R3a`/`R3b`).

Зачем отдельный модуль, а не подстановка в каждом тесте: HTTP-проверки атрибутов куки, `403` без
CSRF-токена и объясняющих страниц должны запускаться на dev-машине, где PostgreSQL нет (тот же
приём пары «офлайн-половинка ↔ живая база», что у схемы и у прав роли). Живая проверка поиска по
`token_hash` при этом обязана остаться отдельной — `tests/integration/test_web_identity_db.py`, job
`migrations`: память не воспроизводит ни `citext`, ни `INET`, ни `CHECK` формата хэша, ни уникальный
индекс, ни то, что значение вообще доживает до базы.

Граница, о которой нельзя забывать: `MemoryStore` хранит **те же объекты ORM**, что и боевой путь, и
потому не проверяет ни `INSERT`, ни ограничения схемы, ни фиксацию транзакции. Он проверяет поведение
слоя входа. Поэтому проверки, которым важна база, живут в живом файле, и переносить их в память
нельзя.

Приложение строится боевым `create_app`: маршруты, обработчики исключений, шаблоны и порядок проверок
остаются теми же, что в контейнере; подменяется только зависимость `get_store`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, Final, cast
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.main import create_app
from apps.web.routes.sessions import RateLimitedMutation
from apps.web.security.sessions import (
    SESSION_COOKIE_NAME,
    Principal,
    require_full_session,
)
from apps.web.store import ACCOUNTS_LIST_LIMIT, BucketWindow, Store, get_store
from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.common.ids import uuid7
from packages.identity.authorization import ROLE_ADMIN
from packages.identity.backup_codes import BackupCodeError, is_sha256_hex
from packages.identity.sessions import IssuedSession, token_hash_of
from packages.identity.users import CONSOLE_STATE, new_user
from packages.storage.models import (
    BackupCode,
    Invitation,
    TotpEnrollment,
    TotpFailure,
    User,
    UserSession,
)

#: Пароль тестовой учётной записи: проходит §8.1 (длина, словарь, «пароль = логин/домен»), иначе
#: `new_user` откажется создавать запись и проверка дойдёт до входа уже с другим пользователем.
TEST_PASSWORD: Final = "Разработческий-пароль-2026"
TEST_LOGIN: Final = "op.srez-r3"


class MemoryStore:
    """Репозиторий слоя входа в памяти: тот же протокол `Store`, что у `SqlStore`.

    Объекты возвращаются одни и те же (как identity map у SQLAlchemy), поэтому правки доменного
    слоя — `failed_attempts`, `revoked_at`, `expires_at` — видны следующему запросу без сохранения.
    Это же и ограничение: отсутствие `commit()` тест не сломает, поэтому счётчик коммитов ведётся
    специально, и проверка «обработчик зафиксировал состояние до выдачи куки» существует отдельно.

    Регистронезависимость логина воспроизводится здесь намеренно: в схеме за неё отвечает `citext`,
    и без этого проверка «логин в другом регистре — та же учётная запись» зависела бы от наличия
    базы.
    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._sessions: dict[str, UserSession] = {}
        self._buckets: dict[tuple[str, str, datetime], tuple[int, int]] = {}
        self._enrollments: dict[UUID, TotpEnrollment] = {}
        self._totp_failures: list[TotpFailure] = []
        self._backup_codes: list[BackupCode] = []
        self._invitations: list[Invitation] = []
        self.commits: int = 0
        self.hash_lookups: list[str] = []

    # ─── наполнение ───────────────────────────────────────────────────────────────────────

    def seed_user(
        self,
        *,
        login: str = TEST_LOGIN,
        password: str = TEST_PASSWORD,
        role: str = "operator",
    ) -> User:
        """Учётная запись для проверок. Роль по умолчанию — `operator` (срез `R3a`).

        Параметр `role` появился вместе с матрицей допуска (`T-106`, `R6`): проверке нужны три
        учётные записи разных ролей, а не один пользователь с подменённым полем — иначе матрица
        «маршрут × роль» проверяла бы поведение одного объекта, а не трёх разных. Значение по
        умолчанию не менялось: все проверки `R3a`–`R5c` строят операторскую учётку, и смена роли
        по умолчанию молча переписала бы их смысл. Само значение проходит доменную проверку
        `new_user` → `ensure_role` (закрытый набор §1.1), так и должен проходит боевой путь.
        """
        user = new_user(login=login, password=password, role=role, state="active")
        self._users[login.casefold()] = user
        return user

    def seed_session(self, issued: IssuedSession) -> UserSession:
        self._sessions[issued.record.token_hash] = issued.record
        return issued.record

    def drop_user(self, login_value: str) -> User | None:
        """Снять учётную запись из репозитория — вспомогательное средство проверок (`T-106`).

        Нужен ровно одному классу проверок: «сеанс живой, а строки учётной записи больше нет» —
        состоянию, которое боевой путь получает из архивации учётной записи или из ручной правки
        таблицы (`ADR-017` п. 4), а не из кода приложения. В памяти иначе не получить: у протокола
        `Store` метода удаления нет, и заводить его в боевом протоколе ради проверки нельзя —
        приложение не должно уметь удалять учётную запись (`users` не удаляется, §4.1: только
        состояние `state='archived'`).
        """
        return self._users.pop(login_value.casefold(), None)

    # ─── протокол `Store` ─────────────────────────────────────────────────────────────────

    def user_by_login(self, login: str) -> User | None:
        return self._users.get(login.casefold())

    def session_by_token_hash(self, token_hash: str) -> UserSession | None:
        self.hash_lookups.append(token_hash)
        return self._sessions.get(token_hash)

    def user_sessions(
        self, user_id: UUID, *, not_expired_before: datetime
    ) -> tuple[UserSession, ...]:
        """Зеркало запроса `SqlStore.user_sessions` (срез `R3e`).

        Предикат скопирован побайтово (`user_id`, `revoked_at IS NULL`, `expires_at >` границы) —
        иначе офлайновая половина и живая проверяли бы разные наборы. При этом память не доказывает
        ничего из того, что делает запрос на базе: что ограничение `user_id` действительно уходит в
        SQL (а не отфильтровано потом), что колонка `INET` читается канонически и что предикат
        опирается на `ix_sessions_expires_at`, а не вычитывает все строки пользователя, — это
        держит живой файл `tests/integration/test_web_sessions_db.py` (job `миграции`).
        """
        return tuple(
            record
            for record in self._sessions.values()
            if record.user_id == user_id
            and record.revoked_at is None
            and record.expires_at > not_expired_before
        )

    def session_of_user(
        self, *, session_id: UUID, user_id: UUID, not_expired_before: datetime
    ) -> UserSession | None:
        """Зеркало `SqlStore.session_of_user`: поиск ограничен учётной записью (§8.8).

        Та же граница честности, что у `user_sessions`: на живой базе ограничение `user_id` стоит
        в самом запросе, и что оно там стоит — проверяет живой файл, а не память.
        """
        for record in self._sessions.values():
            if (
                record.id == session_id
                and record.user_id == user_id
                and record.revoked_at is None
                and record.expires_at > not_expired_before
            ):
                return record
        return None

    def user_of_id(self, user_id: UUID) -> User | None:
        """Зеркало `SqlStore.user_of_id`: учётка по `id`, логин в поиске не участвует (§8.1).

        Здесь проверяется только доступ по `id`. Что поиск идёт по первичному ключу и что чужое
        имя, подставленное в форму, к чужой учётке не приводит — держит живой файл
        `tests/integration/test_web_sessions_db.py` (job `миграции`): там проверяется текст
        запроса, а не поведение слоя.
        """
        return next((user for user in self._users.values() if user.id == user_id), None)

    def invitation_by_hash(self, token_hash: str) -> Invitation | None:
        """Зеркало `SqlStore.invitation_by_hash`: приглашение по хэшу значения ссылки.

        Предикат и проверка формы скопированы побайтово. Чего память не доказывает: что хэш
        доживает до базы в виде колонки с `UNIQUE` и что поиск попадает в индекс, а не
        вычитывает таблицу. Это держит `tests/integration/test_invitations_db.py` (job
        `миграции`) — там же, где проверяется `CHECK` формата хэша резервных кодов.
        """
        if not is_sha256_hex(token_hash):
            return None
        return next((row for row in self._invitations if row.token_hash == token_hash), None)

    def invitation_of_id(self, invitation_id: UUID) -> Invitation | None:
        """Зеркало `SqlStore.invitation_of_id`: приглашение по `id`."""
        return next((row for row in self._invitations if row.id == invitation_id), None)

    def accounts(
        self,
        *,
        states: Sequence[str] | None = None,
        role: str | None = None,
        limit: int = ACCOUNTS_LIST_LIMIT,
    ) -> tuple[User, ...]:
        """Зеркало `SqlStore.accounts`: фильтры по состоянию и роли.

        Порядок здесь — порядок добавления, а не `created_at`: у объектов, не проходивших `INSERT`,
        серверного значения `created_at` нет, и изобретать его в памяти означало бы проверять
        сортировку по выдуманному полю. Что список отсортирован по `created_at` и что потолок
        `LIMIT` применяется в запросе, держит живой файл `tests/integration/test_invitations_db.py`.
        """
        rows = [
            user
            for user in self._users.values()
            if (states is None or user.state in set(states)) and (role is None or user.role == role)
        ]
        return tuple(rows[: min(int(limit), ACCOUNTS_LIST_LIMIT)])

    def pending_invitations(self, *, limit: int = ACCOUNTS_LIST_LIMIT) -> tuple[Invitation, ...]:
        """Зеркало `SqlStore.pending_invitations`: только `pending`, срок не фильтруется.

        Просроченные выпуски остаются в списке и здесь — не потому, что память о сроке не знает,
        а потому что признак живости решает домен (`ensure_invitation_open`), и у слоя доступа
        не должно быть своего календаря.
        """
        return tuple(row for row in self._invitations if row.state == "pending")[
            : min(int(limit), ACCOUNTS_LIST_LIMIT)
        ]

    def claim_invitation(self, *, invitation_id: UUID, now: datetime) -> bool:
        """Зеркало `SqlStore.claim_invitation`: тот же предикат перехода, что в guarded-`UPDATE`.

        Чего память не доказывает: что переход атомарен. Два «параллельных» приёма одной ссылки
        физически не приходят, поэтому форма «нашли — пометили» прошла бы здесь так же зелёно;
        гонку приёма с отзывом держит живой файл `tests/integration/test_invitations_db.py`
        (job `миграции`) — ровно так же, как `test_backup_code_single_use` держит её для
        резервных кодов.
        """
        for row in self._invitations:
            if row.id == invitation_id and row.state == "pending" and row.expires_at > now:
                row.state = "used"
                row.used_at = now
                return True
        return False

    def revoke_invitation_row(self, *, invitation_id: UUID) -> bool:
        """Зеркало `SqlStore.revoke_invitation_row`: переход `pending` → `revoked`."""
        for row in self._invitations:
            if row.id == invitation_id and row.state == "pending":
                row.state = "revoked"
                return True
        return False

    def active_admin_count(self, *, except_user_id: UUID | None = None) -> int:
        """Зеркало `SqlStore.active_admin_count`: сколько `admin` остаются в `active`."""
        return sum(
            1
            for user in self._users.values()
            if user.role == ROLE_ADMIN
            and user.state == CONSOLE_STATE
            and (except_user_id is None or user.id != except_user_id)
        )

    def add(self, obj: User | UserSession | TotpEnrollment | TotpFailure | Invitation) -> None:
        if isinstance(obj, UserSession):
            self._sessions[obj.token_hash] = obj
        elif isinstance(obj, TotpEnrollment):
            self._enrollments[obj.id] = obj
        elif isinstance(obj, TotpFailure):
            self._totp_failures.append(obj)
        elif isinstance(obj, Invitation):
            # отдельный список, а не словарь: открытым может быть не более одного выпуска на
            # учётную запись, но это держит частичный уникальный индекс, а не структура памяти
            self._invitations.append(obj)
        else:
            # пользователь: `login` — ключ, регистронезависимость та же, что у `citext`
            self._users[obj.login.casefold()] = obj

    def active_enrollment(self, user_id: UUID) -> TotpEnrollment | None:
        """Зеркало `SqlStore.active_enrollment`: одна неотозванная привязка на учётку.

        Предикат скопирован побайтово (`user_id`, `revoked_at IS NULL`). Чего память не доказывает:
        что вторую неотозванную строку не даст частичный уникальный индекс
        `ix_totp_enrollments_user_active`, и что предикат попадает в индекс, а не вычитывает все
        строки учётной записи. Это держит живой файл
        `tests/integration/test_totp_enrollment_db.py` (job `миграции`).
        """
        return next(
            (
                row
                for row in self._enrollments.values()
                if row.user_id == user_id and row.revoked_at is None
            ),
            None,
        )

    def totp_failures(self, user_id: UUID, *, not_before: datetime) -> tuple[TotpFailure, ...]:
        """Зеркало `SqlStore.totp_failures`: лента неудач не раньше границы окна (§8.2).

        Порядок возврата — по `at`, как в запросе: иначе «5 подряд» в памяти и на базе считались бы
        по разным последовательностям. Границу окна задаёт вызывающий, и здесь она тоже в фильтре, а
        не «отфильтровано потом».
        """
        return tuple(
            row
            for row in sorted(self._totp_failures, key=lambda row: row.at)
            if row.user_id == user_id and row.at > not_before
        )

    def claim_totp_step(self, enrollment_id: UUID, *, step: int) -> bool:
        """Зеркало `SqlStore.claim_totp_step`: тот же предикат, что у guarded-`UPDATE`.

        Честная граница: в памяти нет ни `UPDATE`, ни блокировки строки, поэтому эта реализация не
        может доказать атомарность — два «параллельных» запроса в одном тесте физически не приходят.
        Здесь проверяется только то, что форма предиката (`last_used_step IS NULL OR
        last_used_step < step` плюс состояние строки `revoked_at IS NULL AND
        confirmed_at IS NOT NULL`) понята слоем одинаково: код, равный уже принятому шагу, не
        проходит, и отозванная/неподтверждённая привязка шаг не занимает. Собственно атомарность и
        `rowcount = 0` на повторе держит живая проверка
        `tests/integration/test_totp_enrollment_db.py` (job `миграции`) — ровно та же граница, что у
        счётчика частоты (`ADR-007`).
        """
        row = self._enrollments.get(enrollment_id)
        if row is None or row.revoked_at is not None or row.confirmed_at is None:
            return False
        if row.last_used_step is not None and row.last_used_step >= step:
            return False
        row.last_used_step = step
        return True

    def commit(self) -> None:
        self.commits += 1

    # ─── резервные коды (§8.2, `T-104`, срез `R5b`, `ADR-016` п. 7) ──────────────────
    #
    # Зеркало `SqlStore`: те же предикаты и тот же порядок вызовов. Чего память не доказывает,
    # и переносить это сюда нельзя: атомарность guarded-`UPDATE` (два «параллельных» входа в одном
    # тесте физически не приходят, поэтому «нашёл — пометил» прошёл бы в памяти так же зелёно),
    # наличие `used_at IS NULL` в тексте SQL и попадание в частичный индекс
    # `ix_backup_codes_user_id_unused`, `CHECK ck_backup_codes_code_hash_sha256`,
    # `uq_backup_codes_user_id_code_hash`, момент `now()` из базы и то, что значение кода не
    # уезжает ни в запрос, ни в связанные значения. Всё это держит живой файл
    # `tests/integration/test_backup_codes_db.py` (job `миграции`), включая обязательную
    # `test_backup_code_single_use`.

    def insert_backup_code_hashes(self, user_id: UUID, code_hashes: Sequence[str]) -> None:
        """Зеркало `SqlStore.insert_backup_code_hashes`: пачка только из хэшей (§8.2).

        Те же два отказа до «записи»: форма хэша и повторы внутри пачки. Их держат и `CHECK`, и
        уникальный индекс на базе, но проверка здесь нужна, чтобы офлайновая половина слоя
        видела тот же класс отказа, что и боевой путь, а не `IntegrityError`.
        """
        if not code_hashes:
            raise BackupCodeError("пустая пачка резервных кодов: ни одного хэша")
        seen: set[str] = set()
        for position, code_hash in enumerate(code_hashes, start=1):
            if not is_sha256_hex(code_hash):
                raise BackupCodeError(
                    f"хэш №{position} в пачке не формы SHA-256 hex: битая строка в наборе"
                )
            if code_hash in seen:
                raise BackupCodeError(
                    f"хэш №{position} повторяется в пачке: коды обязаны быть разными"
                )
            seen.add(code_hash)
        for code_hash in code_hashes:
            # `id` и `created_at` в памяти проставляются явно: на боевом пути их даёт база
            # (`default=_new_uuid` и `server_default=now()` срабатывают только при флеше, а здесь
            # флеша нет). Без этого `spend_backup_code(code_id=…)` в памяти не находил бы строк,
            # а `recovery_state` спотыкался бы о `created_at is None`.
            self._backup_codes.append(
                BackupCode(
                    id=uuid7(),
                    user_id=user_id,
                    code_hash=code_hash,
                    used_at=None,
                    created_at=utc_now(),
                )
            )

    def find_unused_backup_code(self, *, user_id: UUID, code_hash: str) -> BackupCode | None:
        """Зеркало `SqlStore.find_unused_backup_code`: поиск только среди неиспользованных.

        Предикат скопирован побайтово (`user_id`, `code_hash`, `used_at is None`) — иначе
        офлайн- и живая половины проверяли бы разные наборы, и «израсходованный код» в памяти стал
        бы различим там, где на базе он даёт один и тот же отказ (§8.8).
        """
        return next(
            (
                row
                for row in self._backup_codes
                if row.user_id == user_id and row.code_hash == code_hash and row.used_at is None
            ),
            None,
        )

    def spend_backup_code(self, *, code_id: UUID, user_id: UUID) -> bool:
        """Зеркало `SqlStore.spend_backup_code`: тот же предикат guarded-`UPDATE`.

        Честная граница, как у `claim_totp_step`: здесь проверяется только форма предиката —
        израсходованный код повторно не расходуется, чужой не находится и не меняется. Собственно
        атомарность и `rowcount = 0` на второй попытке держит живая `test_backup_code_single_use`
        (`tests/integration/test_backup_codes_db.py`, job `миграции`).
        """
        target = next(
            (
                row
                for row in self._backup_codes
                if row.id == code_id and row.user_id == user_id and row.used_at is None
            ),
            None,
        )
        if target is None:
            return False
        target.used_at = utc_now()
        return True

    def invalidate_unused_backup_codes(self, user_id: UUID) -> int:
        """Зеркало `SqlStore.invalidate_unused_backup_codes`: только неиспользованные остатки.

        Израсходованные не трогаются и не удаляются — по той же причине, что на базе: `used_at`
        держит след начала семидневного срока (`ADR-016` п. 6).
        """
        count = 0
        for row in self._backup_codes:
            if row.user_id == user_id and row.used_at is None:
                row.used_at = utc_now()
                count += 1
        return count

    def backup_code_rows(self, user_id: UUID) -> tuple[BackupCode, ...]:
        """Зеркало `SqlStore.backup_code_rows`: обе половины набора своей учётки.

        Порядок перенесён осознанно (`created_at`, `id`), хотя в памяти он и так был бы
        «порядком вставки»: без сортировки офлайновая половина читала бы другой набор, чем
        боевой путь, и расхождение порядка строк не поймал бы ни один офлайновый тест. Живая
        часть утверждения — в `tests/integration/test_backup_codes_db.py` (job `миграции`).

        Чего память не доказывает: что даты пришли из `now()` базы. В памяти `created_at` и
        `used_at` ставит процесс (`insert_backup_code_hashes` и `spend_backup_code`), поэтому
        «пара дат из одних часов» здесь выполняется по построению, а на базе это отдельная
        проверка живого файла.
        """
        return tuple(
            sorted(
                (row for row in self._backup_codes if row.user_id == user_id),
                key=lambda row: (row.created_at, row.id),
            )
        )

    # ─── счётчик частоты запросов (срез `R3d`, `ADR-007`) ────────────────────────────
    #
    # Здесь хранятся те же окна, что и в `rate_buckets`, но без схемы: атомарность
    # `INSERT … ON CONFLICT DO UPDATE`, CHECK перечня областей и набора окон, длина ключа и
    # то, что `DELETE` идёт по индексу `window_start`, проверяет живой файл
    # `tests/integration/test_rate_limit_mechanism_db.py` (job `migrations`). Переносить его
    # проверки в память нельзя.

    def bump_rate_bucket(
        self,
        *,
        scope: str,
        bucket_key: str,
        window_start: datetime,
        window_seconds: int,
    ) -> int:
        key = (scope, bucket_key, window_start)
        _, attempts = self._buckets.get(key, (window_seconds, 0))
        attempts += 1
        self._buckets[key] = (window_seconds, attempts)
        return attempts

    def newest_counted_window(
        self,
        *,
        scope: str,
        bucket_key: str,
        min_attempts: int,
        window_start_after: datetime,
    ) -> BucketWindow | None:
        candidates = [
            (start, window_seconds, attempts)
            for (row_scope, row_key, start), (window_seconds, attempts) in self._buckets.items()
            if row_scope == scope
            and row_key == bucket_key
            and attempts >= min_attempts
            and start > window_start_after
        ]
        if not candidates:
            return None
        start, window_seconds, attempts = max(candidates, key=lambda row: row[0])
        return BucketWindow(window_start=start, window_seconds=window_seconds, attempts=attempts)

    # ─── вспомогательное для проверок ─────────────────────────────────────────────────────

    def buckets(self) -> dict[tuple[str, str, datetime], int]:
        """Снимок окон счётчика для проверок: (область, ключ, начало окна) → attempts.

        Нужен ровно для одного класса проверок: «сколько окон завелось на запрос». Значение
        `window_seconds` в снимок не входит намеренно — окно проверяют живые проверки схемы.
        """
        return {key: attempts for key, (_, attempts) in self._buckets.items()}

    def enrollments(self) -> tuple[TotpEnrollment, ...]:
        """Снимок привязок для проверок: включая отозванные и неподтверждённые.

        Проверкам нужно различать «привязка не создалась» и «привязка создана и отозвана» —
        по странице ответа эти два состояния неотличимы намеренно.
        """
        return tuple(self._enrollments.values())

    def sessions(self) -> tuple[UserSession, ...]:
        return tuple(self._sessions.values())

    def find_by_secret(self, secret: str) -> UserSession | None:
        """Найти запись по предъявленному значению куки (не по хэшу) — только для проверок."""
        return self._sessions.get(token_hash_of(secret))


class TimingSpy:
    """Замена `LoginTiming`: вместо стоимости Argon2id пишет сам факт обращения.

    Проверять нужно одно: ветка «логина нет» обязана тратить то же, что ветка «пароль не тот»,
    иначе ответ по времени различает существование учётной записи (§8.1, закрытый допуск §1.2).
    Замерять время в тесте нельзя — он станет нестабильным, поэтому проверяется сам вызов.
    """

    def __init__(self) -> None:
        self.burned: list[str] = []

    def burn(self, password: str) -> None:
        self.burned.append(password)


def probe_router() -> APIRouter:
    """Два щупа: охраняемый `require_full_session` GET и мутация с пределом частоты.

    Боевых маршрутов консоли, требующих `'full'`, в этом срезе ещё нет: они появятся вместе с кодом
    2FA в `T-103`, где их проверит параметризованная `test_route_requires_full_auth`. Пока их нет,
    правило §8.2 («сессия на шаге `'password'` дальше страницы кода и `/logout` не пущена»)
    проверяется на щупе — иначе оно осталось бы записанным в код без единой проверки.

    `POST /probe-mutation` нужен счёту частоты: на настоящем `/logout` предел
    «60 мутаций в минуту на пользователя» недостижим — первая попытка отзывает сессию, и дальше
    маршрут отвечает редиректом «сессия не подходит», не доходя до счётчика. Щуп зависит от той же
    композитной зависимости `RateLimitedMutation`, что и реальный выход, поэтому проверяется именно
    механизм, а не подделка. Покрытие реальных мутаций держит контрактный тест.
    """
    router = APIRouter()

    @router.get("/probe-full")
    def probe(
        principal: Annotated[Principal, Depends(require_full_session)],
    ) -> dict[str, str]:
        return {"session_id": str(principal.session.id), "step": principal.session.auth_step}

    @router.post("/probe-mutation")
    def probe_mutation(
        principal: RateLimitedMutation,
    ) -> dict[str, str]:
        return {"session_id": str(principal.session.id), "step": principal.session.auth_step}

    return router


def build_client(store: Store, settings: Settings, *, with_probe: bool = False) -> TestClient:
    """Клиент боевого приложения с подменённым репозиторием.

    База — `https://testserver`, а не `http`, и это не косметика: кука сессии обязана быть `Secure`
    (§8.3), а `Secure`-куку обработчик cookiejar не отдаёт на http-адрес. На http тесты молча
    остались бы без куки, и половина проверок (§8.3 «отзыв отражается немедленно», продление idle)
    проверяла бы отсутствие сессии вместо поведения. Боевой путь тоже https: наружу работает только
    Caddy с TLS (TZ §8.5, ADR-003).

    `follow_redirects` у TestClient включён по умолчанию; там, где важен сам редирект, тест вызывает
    запрос с `follow_redirects=False` явно, иначе проверка увидит итоговую страницу, а не решение
    слоя входа.
    """
    app = create_app(settings)
    app.state.login_timing = TimingSpy()
    app.dependency_overrides[get_store] = lambda: store
    if with_probe:
        app.include_router(probe_router())
    return TestClient(app, base_url="https://testserver")


def login(
    client: TestClient,
    *,
    login_value: str = TEST_LOGIN,
    password: str = TEST_PASSWORD,
) -> Response:
    """Войти; кука остаётся в `client.cookies` (обычное поведение TestClient).

    `follow_redirects=False` обязателен: иначе тест получает итоговую страницу после редиректа, а не
    сам ответ входа — вместе с ним теряются и `Set-Cookie` (атрибуты §8.3), и `Location`.


    `Origin` передаётся явно: браузер шлёт его на мутациях всегда, и тесты должны идти по тому же
    пути, что и он. Проверка источника — второй слой (§8.3), и отсутствие заголовка его просто
    отключает, поэтому тестам, которым нужен именно отказ по источнику, нужен другой источник.
    """
    response: Response = client.post(
        "/login",
        data={"login": login_value, "password": password},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    return response


def timing_spy(client: TestClient) -> TimingSpy:
    """Подменённый планировщик стоимости Argon2id, доступный из теста.

    `TestClient.app` типизирован как ASGI-приложение (в Starlette это вызываемый объект), поэтому
    приложение приводится к `FastAPI` явно: `state` — то, чем боевое приложение держит
    планировщик, и подмена в тестах не должна требовать доступа к внутренностям клиента.
    """
    spy = cast(FastAPI, client.app).state.login_timing
    assert isinstance(spy, TimingSpy), "планировщик не подменён — проверка времени бессмысленна"
    return spy


def set_kek_file(client: TestClient, path: Path) -> None:
    """Путь файла ключей KEK для приложения клиента (срез `R4c`, `ADR-014` п. 5).

    Боевой путь (`/etc/tbot/keys/kek.json`) в проверке не используется: он требует POSIX-прав и root,
    а на dev-машине его нет. Приложение читает путь из состояния процесса (`create_app` кладёт туда
    `Settings.kek_file`), поэтому подмена пути — это ровно тот же код загрузки, что на площадке,
    включая разбор формата и проверку прав (на POSIX-ветке проверки живут в
    `tests/unit/test_envelope_crypto.py`).
    """
    cast(FastAPI, client.app).state.kek_file = path


def session_cookie(client: TestClient) -> str:
    """Значение куки сессии в клиенте; пустая строка, если куки нет."""
    return str(client.cookies.get(SESSION_COOKIE_NAME, ""))
