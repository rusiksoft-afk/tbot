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

from datetime import datetime
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
from apps.web.store import BucketWindow, Store, get_store
from packages.common.config import Settings
from packages.identity.sessions import IssuedSession, token_hash_of
from packages.identity.users import new_user
from packages.storage.models import User, UserSession

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
        self.commits: int = 0
        self.hash_lookups: list[str] = []

    # ─── наполнение ───────────────────────────────────────────────────────────────────────

    def seed_user(self, *, login: str = TEST_LOGIN, password: str = TEST_PASSWORD) -> User:
        user = new_user(login=login, password=password, role="operator", state="active")
        self._users[login.casefold()] = user
        return user

    def seed_session(self, issued: IssuedSession) -> UserSession:
        self._sessions[issued.record.token_hash] = issued.record
        return issued.record

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

    def add(self, obj: User | UserSession) -> None:
        if isinstance(obj, UserSession):
            self._sessions[obj.token_hash] = obj
            return
        self._users[obj.login.casefold()] = obj

    def commit(self) -> None:
        self.commits += 1

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


def session_cookie(client: TestClient) -> str:
    """Значение куки сессии в клиенте; пустая строка, если куки нет."""
    return str(client.cookies.get(SESSION_COOKIE_NAME, ""))
