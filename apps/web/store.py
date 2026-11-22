"""Доступ процесса `web` к базе: фабрика движка и узкий репозиторий слоя входа (T-102).

Три решения здесь неочевидны, поэтому они записаны прямо в коде.

1. **Адрес — только форма `postgresql+psycopg://…`** (секретный файл `db_url`, TZ §14.9), а в
   форму SQLAlchemy его переводит `packages/common/db.py:sqlalchemy_url`. Прямая форма
   (`postgresql://…`) в этом модуле появляться не должна: `/readyz` ходит в базу напрямую через
   `psycopg`, и эти два пути уже расходились на площадке (`ProgrammingError: missing "=" after
   postgresql+psycopg://…`, замер 2026-11-20 — нездоровый `web`, весь периметр не поднимается).
2. **Роль — приложения (`tbot_app`, ADR-006).** Отдельного подключения «под владельцем схемы» здесь
   нет и быть не может: слой входа обязан работать в правах роли приложения, иначе проверка
   «сессии и перебор живут в правах приложения» превращается в проверку несуществующего пути.
3. **Слой входа обращается к базе через узкий протокол `Store`, а не через `Session` напрямую.**
   Причина не в абстракции ради абстракции: проверки атрибутов куки, `403` без CSRF-токена и
   немедленного отзыва относятся к HTTP-уровню и обязаны запускаться на dev-машине, где PostgreSQL
   нет (`citext`, `INET`, `IDENTITY` и `JSONB` на SQLite не воспроизводятся). Живой поиск по
   `token_hash` при этом проверяется на настоящем PostgreSQL в job `migrations` —
   `tests/integration/test_web_identity_db.py`. Если бы единственный путь к базе был «настоящий
   `Session`», HTTP-проверки либо не писались бы, либо требовали бы базы на каждом тесте.

**Транзакция.** Коммит делает обработчик маршрута в точках мутации (`/login`, `/logout`), а не
зависимость и не доменный слой: `packages/identity/*` меняет объекты ORM и не открывает
соединений — иначе отзыв сессии и запись журнала разошлись бы по разным транзакциям (§8.7).

**Исключение — счётчик частоты.** `bump_rate_bucket` фиксируется сразу, в момент инкремента
(`apps/web/security/rate_limit.py`), а не в конце обработчика. Причина не в стиле: отказ «лимит
исчерпан» обязан оставить след в базе (`ADR-007` — каждый лимитируемый запрос стоит запись), и
обработчик отказа живёт в обработчике исключения, где никакого вызова `commit()` нет. Отсюда
порядок вызовов в маршрутах: счётчик двигается **до** того, как обработчик изменил что-то ещё,
иначе коммит счётчика попутно зафиксировал бы незавершённое состояние.

**`expire_on_commit=False`.** После `commit()` обработчик ещё читает объект сессии (шаг входа,
`id` для вывода CSRF-токена, отметки для списка устройств). При значении по умолчанию каждое такое
чтение ушло бы новым запросом, а после закрытия соединения — ошибкой.

**Резервные коды (`T-104`, срез `R5b`).** Одноразовость — свойство перехода, а не значения
(`ADR-016` п. 7), поэтому в слое доступа есть guarded-`UPDATE` расхода и аннулирования, а не
«прочитали `used_at`, решили, записали». Момент расхода ставит **база** (`SET used_at = now()`),
а не процесс: семидневный срок (`ADR-016` п. 6) считается по паре `created_at` / `used_at`, и если
одну дату даёт база, а другую — часы контейнера, то при расхождении часов на несколько секунд
перевыпуск пачки перестал бы сниматься с обязательства перевыпустить (новая строка оказалась бы
«создана раньше расхода») — ровно та ничья, ради которой в `ADR-016` выбрано `>=`.

**Движок живёт вместе с приложением.** Отдельного `dispose` нет: процесс `web` один на приложение и
завершается вместе с ним (в составе — `restart` контейнера, а не пересоздание приложения).
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast
from uuid import UUID

from fastapi import Request
from sqlalchemy import create_engine, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.engine import CursorResult, Engine
from sqlalchemy.orm import Session, sessionmaker

from packages.common.config import Settings
from packages.common.db import sqlalchemy_url
from packages.identity.backup_codes import BackupCodeError, is_sha256_hex
from packages.identity.passwords import hash_password, verify_password
from packages.storage.models import (
    BackupCode,
    RateBucket,
    TotpEnrollment,
    TotpFailure,
    User,
    UserSession,
)

#: Верхняя граница длины `user_agent`: значение приходит из заголовка, которое контролирует клиент,
#: а колонка `sessions.user_agent` — `TEXT` без CHECK (при этом §8.3 показывает её пользователю в
#: списке устройств). Ограничение держит приложение, потому что база его не держит.
USER_AGENT_MAX_LEN: int = 256


class StoreUnavailableError(RuntimeError):
    """К базе слоя входа обратиться нельзя: адрес базы не настроен.

    Обработчик в `create_app` отвечает `503` теми же словами, что и `/readyz`, — и человек, и
    интеграционный тест видят одну причину в одном месте, а не `AttributeError` из обработчика.
    """


class Store(Protocol):
    """Набор запросов слоя входа.

    Список narrow намеренно: он повторяет то, что требует §8.3 (найти учётную запись по логину,
    найти сессию по хэшу значения куки, поставить объект в транзакцию, зафиксировать), и не
    превращается в generic repository со `query(sql)`, в котором проверка прав перестала бы быть
    проверкой.
    """

    def user_by_login(self, login: str) -> User | None:
        """Найти учётную запись по логину.

        `citext` в схеме делает сравнение регистронезависимым: «Ivan» и «ivan» — одна учётная
        запись, а не две (TZ §4.1).
        """

    def session_by_token_hash(self, token_hash: str) -> UserSession | None:
        """Найти сессию по SHA-256 значения куки (§8.3: поиск идёт по хэшу, а не по `id`).

        Вызывающий обязан передать **уже** вычисленный канонический хэш: значение куки в базу не
        передаётся ни при каких условиях.
        """

    def user_sessions(
        self, user_id: UUID, *, not_expired_before: datetime
    ) -> tuple[UserSession, ...]:
        """Все сессии пользователя, которые ещё могут быть живыми (срез `R3e`, §8.3).

        Граница `not_expired_before` обязана быть в запросе, а не «отфильтровано потом»: набор
        живых сессий мал, а набор строк `sessions` за всё время работы площадки — нет. Без
        ограничения список устройств читал бы все строки пользователя, включая отозванные и
        завершившиеся по сроку, и превращался бы в самую дорогую страницу консоли. Граничащий
        предикат совпадает с индексом `ix_sessions_expires_at` (ревизия `0001`).

        Отозванные строки исключаются запросом, а не проверкой: список §9.3 п. 4 держит активные
        сессии, а историю входов ведёт `audit_log` (`T-109`), а не эта страница.

        Отобранные строки — только **кандидаты**: окончательное решение о живости принимает
        доменный слой (`packages/identity.sessions.session_is_active`), который знает про шаг
        входа, отзыв и сессии «из будущего».
        """

    def session_of_user(
        self, *, session_id: UUID, user_id: UUID, not_expired_before: datetime
    ) -> UserSession | None:
        """Найти сессию по `id`, ограничив её учётной записью пользователя (срез `R3e`).

        Ограничение `user_id` живёт в самом запросе, а не в проверке «нашёл — сверил»: тогда
        обращение к чужой сессии физически не может ничего найти и ничего изменить (§8.8: «доступ
        к чужим данным → 403/404 без утечки»). Предикат тот же, что у `user_sessions`: страница
        отзыва и список обязаны описывать один и тот же набор строк, иначе ссылка со страницы
        вела бы на строку, которую страница отзыва отказывается видеть.
        """

    def user_of_id(self, user_id: UUID) -> User | None:
        """Учётная запись по `id` — по тому, что хранит запись сессии (срез `R3f`, §8.1).

        Логин в поиске не участвует принципиально: смена пароля обязана относиться к той
        учётной записи, у которой живая сессия, а не к той, чьё имя продиктовала форма. Если бы
        поиск шёл по логину из формы, подстановка чужого имени превращалась бы в попытку менять
        чужую учётную запись; здесь такой запрос просто ничего не находит (§8.8: «чужие данные →
        403/404 без утечки»). Ключ — `id` первичный, поэтому отдельного индекса не требуется.
        """

    def add(self, obj: User | UserSession | TotpEnrollment | TotpFailure) -> None:
        """Поставить объект в транзакцию текущего запроса.

        `RateBucket` в перечне намеренно нет: счётчик двигается только через `bump_rate_bucket`, а
        не через `add` — иначе два запроса в одно окно дали бы `IntegrityError` вместо одного
        счётчика (`ADR-007`: окно живёт в первичном ключе).
        """

    def bump_rate_bucket(
        self,
        *,
        scope: str,
        bucket_key: str,
        window_start: datetime,
        window_seconds: int,
    ) -> int:
        """Увеличить окно счётчика на единицу и вернуть новое значение (`ADR-007`).

        Один запрос, а не «прочитать — сложить — записать»: `INSERT … ON CONFLICT
        (scope, bucket_key, window_start) DO UPDATE SET attempts = rate_buckets.attempts + 1
        RETURNING attempts` — единственный способ не потерять попытки, когда в одно окно пришли
        два запроса из разных процессов.
        """

    def newest_counted_window(
        self,
        *,
        scope: str,
        bucket_key: str,
        min_attempts: int,
        window_start_after: datetime,
    ) -> BucketWindow | None:
        """Самое свежее окно области по субъекту, где счётчик не меньше порога.

        Форма запроса повторяет первичный ключ счётчика («область + субъект + окна не старше
        границы») — ровно то, для чего составной PK и заведён. Состояние читается из базы, а не
        держится в памяти: отказ «адрес закрыт» обязан переживать рестарт контейнера (`ADR-007`).
        """

    def active_enrollment(self, user_id: UUID) -> TotpEnrollment | None:
        """Неотозванная привязка учётной записи, если она есть (срез `R4c`, §8.2).

        Одна на учётку, и это держит база, а не приложение: частичный уникальный индекс
        `ix_totp_enrollments_user_active` (`WHERE revoked_at IS NULL`, ревизия `0002`) не даёт
        второй неотозванной строки. Реализация на базе обязана искать именно по этому предикату
        (`user_id` + `revoked_at IS NULL`) — иначе она не попадёт в индекс, а «привязка есть, но
        приложение её не видит» превратится в вечный отказ привязки.

        Подтверждена привязка или нет — решает домен (`enrollment_state`): здесь только строка.
        Отзывать и подтверждать этот метод не может, и не должен: право менять `confirmed_at` и
        `revoked_at` у `packages/identity/totp_enrollment.py`.
        """

    def totp_failures(self, user_id: UUID, *, not_before: datetime) -> tuple[TotpFailure, ...]:
        """Неудачи кода учётной записи не раньше `not_before` (§8.2, лента `totp_failures`).

        Граница окна обязана быть в запросе: индекс `ix_totp_failures_user_id_at` (ревизия `0002`)
        построен ровно на пару `(user_id, at)`, и без неё страница кода читала бы всю ленту
        учётной записи за всё время работы площадки, а порог «5 неудач подряд» (`TOTP_FAILURE_HORIZON`)
        считался бы по значениям, которые база уже выбросила из окна.

        Строки не удаляются при успехе — так решила схема (`ADR-013` п. 4), и это тот случай, где
        память и база обязаны читаться одинаково: окно задаёт вызывающий.
        """

    def claim_totp_step(self, enrollment_id: UUID, *, step: int) -> bool:
        """Занять шаг кода: `True`, если шаг ещё не был израсходован, иначе `False` (`ADR-013`).

        Один `UPDATE` с условием, а не «прочитать `last_used_step`, сравнить, записать»: два
        параллельных запроса с одним кодом прочитали бы одно и то же значение и прошли бы оба, и
        правило §8.2 «коды принимаются один раз» перестало бы выполняться именно под нагрузкой —
        там, где оно и нужно. Условие вида `(last_used_step IS NULL OR last_used_step < :step)`
        переносит проверку в базу, где она атомарна относительно этой строки.

        Условие держит и состояние строки (`revoked_at IS NULL AND confirmed_at IS NOT NULL`):
        между чтением привязки маршрутом и этим `UPDATE` её могут отозвать, и шаг, занятый на
        мёртвой строке, означал бы «доступ выдан по второму фактору, которого уже нет». Окно между
        проверкой и записью закрывает именно то, что состояние стоит в том же `UPDATE`.

        `False` означает и «этот шаг уже принят», и «принят более свежий», и «строка перестала быть
        действующей привязкой»: различать их незачем, для вызывающего это один отказ `replay`.
        """

    # ─── резервные коды (§8.2, `T-104`, срез `R5b`, `ADR-016` п. 7) ──────────────────────

    def insert_backup_code_hashes(self, user_id: UUID, code_hashes: Sequence[str]) -> None:
        """Вставить пачку хэшей резервных кодов учётной записи (§8.2: «10 шт.», «10 разных»).

        Значений здесь нет и быть не может: метод принимает хэши, потому что открытое значение
        живёт ровно один момент — между генерацией и показом человеку (`ADR-016` п. 2). Иначе
        секрет входа уехал бы в связанные значения запроса (`pg_stat_statements`) и в журнал.

        Пачка проверяется до обращения к базе, и обе проверки не косметика:

        * форма хэша (`is_sha256_hex`) — та же, что у `CHECK ck_backup_codes_code_hash_sha256`.
          Строка другой формы — «битая» запись, которую уже не отличить от «кода нет»
          (`ADR-016` п. 7); отказ здесь виден как дефект кода, а не как `IntegrityError`
          посреди HTTP-запроса;
        * повторы внутри пачки — их держит и `uq_backup_codes_user_id_code_hash`, но ценой
          `UniqueViolation` на половине вставленных строк: транзакт откатился бы целиком, а
          человек увидел бы «коды выпущены» без единого кода.

        Метод ничего не возвращает: он либо вставляет всю пачку, либо не вставляет ничего
        (отказ — исключение до запроса). Сколько строк в таблице — проверяет живая проверка
        запросом к таблице, а не числом из драйвера: `rowcount` у многострочного `INSERT` —
        деталь реализации.

        Порядок при повторной генерации: сначала `invalidate_unused_backup_codes`, потом этот
        метод. Наоборот — нельзя, и это отдельная живая проверка: аннулирование идёт по
        предикату `used_at IS NULL`, поэтому вызванное **после** вставки задевает и новую пачку,
        то есть выпускает учётную запись без единого рабочего кода.
        """

    def find_unused_backup_code(self, *, user_id: UUID, code_hash: str) -> BackupCode | None:
        """Неиспользованная строка кода по хэшу; `None`, если такой строки нет (§8.2).

        Предикат `used_at IS NULL` — часть поиска, а не «нашли и проверили потом». Без него
        страница резервного кода начала бы различать «такого кода нет» и «такой код уже
        потрачен»: это бесплатный оракул для того, кто знает чужое значение (например подсмотрел
        экран при выпуске пачки) — `ADR-016` п. 3 и п. 5.

        Ограничение `user_id` стоит в самом запросе по той же причине, что у `session_of_user`
        (§8.8: чужие данные → один отказ без утечки): поиск чужого значения не находит ничего и
        ничего не меняет. Форма `WHERE user_id = … AND code_hash = … AND used_at IS NULL`
        попадает в частичный индекс `ix_backup_codes_user_id_unused` (`WHERE used_at IS NULL`);
        без предиката поиск выродился бы в чтение всех строк учётки, и «индекс есть» перестал бы
        что-либо значить.

        Строка возвращается как есть, со своим `code_hash`: решение «сверять» принимает домен
        (`backup_code_matches`), а различие «хэш в строке битый» и «кода нет» остаётся
        различимым (`is_sha256_hex`), а не прячется самим фактом неудачного поиска.
        """

    def spend_backup_code(self, *, code_id: UUID, user_id: UUID) -> bool:
        """Израсходовать код: `True`, если строка ещё не была израсходована (`ADR-016` п. 7).

        Один `UPDATE` с условием, а не «прочитать `used_at`, сравнить, записать»: два входа с
        одним кодом прочитали бы одно и то же состояние и прошли бы оба, и правило §8.2
        «одноразовые» перестало бы выполняться именно под параллельными входами — там, где оно и
        нужно. Тот же дефект уже закрывался для TOTP-кода (`ADR-015` п. 5, `claim_totp_step`).

        Состояние строки в условии здесь одно (`used_at IS NULL`): в отличие от
        `claim_totp_step`, где между чтением привязки и записью шага привязку могут отозвать,
        `user_id` строки резервного кода не меняется никогда. Он в условии всё равно стоит — по
        той же причине, что у `session_of_user`: мутация ограничена учётной записью в самом
        запросе, и ошибка вызывающего (id из формы) физически не может израсходовать чужой код.

        Момент расхода ставит база (`now()`), а не часы процесса — иначе семидневный срок
        `ADR-016` п. 6 считался бы по часам двух разных машин (подробности — в шапке модуля).

        `False` означает и «код уже потрачен», и «такого кода у этой учётной записи нет»:
        различать их нельзя намеренно (§8.8), для вызывающего это один и тот же отказ.
        """

    def invalidate_unused_backup_codes(self, user_id: UUID) -> int:
        """Аннулировать неиспользованные остатки прежних пачек учётки (§8.2, срез `R5b`).

        «Повторная генерация аннулирует прежние» — и аннулируются именно неиспользованные:
        израсходованные строки не трогаются и не удаляются. В них держится `used_at` — единственный
        след начала семидневного срока (`ADR-016` п. 6): удалив их, приложение молча сняло
        бы обязательство перевыпустить и блокировку входа по просрочке. Аннулированные тоже
        остаются: `DELETE` стёр бы сам факт выпуска пачки, а ретенция — задача `jobs` (`T-031`),
        не слой входа.

        Отдельного столбца «аннулирован» в `backup_codes` нет (схемы `0001`…`0004` его не
        заводили, и новая ревизия под него означала бы два места одного правила — как в `ADR-016`
        п. 6 про срок). `used_at` для аннулирования — осознанная замена: для `recovery_state`
        «неиспользованных строк нет» и «расход был» — разные признаки, и обязательство перевыпуска
        снимается выпуском новой пачки (`created_at >= max(used_at)`), который идёт в том же
        переходе и том же транзакте, где `now()` у базы один на обе операции.

        Возвращает число аннулированных строк — его обязан проверить тот, кто вызвал: «аннулировано
        ноль» при повторной генерации означает, что вызывающий перепутал порядок (сначала надо
        аннулировать, потом вставлять).
        """

    def commit(self) -> None:
        """Зафиксировать изменения текущего запроса.

        Точку вызова выбирает обработчик: у неудачной попытки входа коммит обязателен (счётчик
        неудач обязан пережить запрос, §8.1), у отказа CSRF — нет (состояние не менялось).
        """


@dataclass(frozen=True)
class BucketWindow:
    """Окно счётчика частоты в том виде, в каком его читает механизм лимитов (`ADR-007`).

    `window_seconds` возвращается вместе с `window_start`, а не подставляется из константы
    приложения: срок бана выводится из **сохранённой** пары (`window_start + window_seconds +
    IP_BAN_DURATION`, `docs/adr/ADR-009`, ask `c53daa01`). Правка окна в коде не должна задним
    числом менять срок уже выданного отказа.
    """

    window_start: datetime
    window_seconds: int
    attempts: int


class SqlStore:
    """Реализация `Store` поверх одного соединения текущего запроса."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def user_by_login(self, login: str) -> User | None:
        return self._session.execute(select(User).where(User.login == login)).scalar_one_or_none()

    def session_by_token_hash(self, token_hash: str) -> UserSession | None:
        return self._session.execute(
            select(UserSession).where(UserSession.token_hash == token_hash)
        ).scalar_one_or_none()

    def user_sessions(
        self, user_id: UUID, *, not_expired_before: datetime
    ) -> tuple[UserSession, ...]:
        statement = (
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > not_expired_before,
            )
            .order_by(UserSession.last_seen_at.desc())
        )
        return tuple(self._session.execute(statement).scalars())

    def session_of_user(
        self, *, session_id: UUID, user_id: UUID, not_expired_before: datetime
    ) -> UserSession | None:
        statement = select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > not_expired_before,
        )
        return self._session.execute(statement).scalar_one_or_none()

    def user_of_id(self, user_id: UUID) -> User | None:
        return self._session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

    def add(self, obj: User | UserSession | TotpEnrollment | TotpFailure) -> None:
        self._session.add(obj)

    def active_enrollment(self, user_id: UUID) -> TotpEnrollment | None:
        statement = select(TotpEnrollment).where(
            TotpEnrollment.user_id == user_id,
            TotpEnrollment.revoked_at.is_(None),
        )
        # `scalar_one_or_none`, а не `first()`: двух неотозванных строк быть не может
        # (`ix_totp_enrollments_user_active`), и появление второй — нарушение инварианта, которое
        # обязано быть слышно, а не «молча выбрали первую попавшую»: выбор без порядка менялся бы от
        # плана запроса, а вместе с ним и то, какой секрет реально действует.
        return self._session.execute(statement).scalar_one_or_none()

    def totp_failures(self, user_id: UUID, *, not_before: datetime) -> tuple[TotpFailure, ...]:
        statement = (
            select(TotpFailure)
            .where(TotpFailure.user_id == user_id, TotpFailure.at > not_before)
            .order_by(TotpFailure.at)
        )
        return tuple(self._session.execute(statement).scalars())

    def claim_totp_step(self, enrollment_id: UUID, *, step: int) -> bool:
        statement = (
            update(TotpEnrollment)
            .where(
                TotpEnrollment.id == enrollment_id,
                # Состояние строки — часть условия, а не «проверено же до запроса». Между чтением
                # привязки и этим `UPDATE` привязку могли отозвать (сброс администратором, §8.2
                # случай 2), и условие только по шагу приняло бы код из уже несуществующего второго
                # фактора: шаг был бы израсходован на мёртвой строке, а сессия поднялась бы до 'full'.
                # Один `UPDATE` закрывает и шаг, и состояние, поэтому между проверкой и записью
                # не остаётся окна (живая проверка — `tests/integration/test_totp_enrollment_db.py`).
                TotpEnrollment.revoked_at.is_(None),
                TotpEnrollment.confirmed_at.is_not(None),
                or_(
                    TotpEnrollment.last_used_step.is_(None),
                    TotpEnrollment.last_used_step < step,
                ),
            )
            .values(last_used_step=step)
            # `synchronize_session=False`: объект, из которого маршрут читал привязку, обновляет
            # доменный слой (`verify_enrollment_code`), и делает это после успешного занятия шага.
            # Иначе SQLAlchemy перед `UPDATE` сделала бы дополнительный `SELECT` по строке ради
            # синхронизации identity map — лишний запрос на каждый код входа.
            .execution_options(synchronize_session=False)
        )
        # `CursorResult`: `Session.execute` для DML типизирован как `Result`, а число затронутых
        # строк живёт на уровне драйвера (`CursorResult`). Приведение здесь честнее, чем обход через
        # `session.connection.execute`: запрос идёт в том же транзакте текущего запроса, и никакое
        # «два соединения на один запрос» из этого не вырастает.
        result = cast("CursorResult[Any]", self._session.execute(statement))
        # `rowcount == 1` — единственный честный ответ: условие не выполнено, если шаг уже принят
        # (или принят более свежий) либо если строка перестала быть действующей привязкой, и тогда
        # затронутых строк ноль.
        return bool(result.rowcount == 1)

    def commit(self) -> None:
        self._session.commit()

    # ─── резервные коды (§8.2, `T-104`, срез `R5b`) ───────────────────────────────────────
    #
    # Значений кодов здесь нет: в слой доступа приходят хэши. Что значение не уезжает ни в
    # запросы, ни в связанные значения, ни в текст отказа, проверяет живой файл
    # `tests/integration/test_backup_codes_db.py` (job `миграции`) — в памяти этой границы нет
    # вообще, потому что там нет ни SQL, ни `pg_stat_statements`.

    def insert_backup_code_hashes(self, user_id: UUID, code_hashes: Sequence[str]) -> None:
        if not code_hashes:
            raise BackupCodeError("пустая пачка резервных кодов: ни одного хэша")
        seen: set[str] = set()
        for position, code_hash in enumerate(code_hashes, start=1):
            # Значение и сам хэш в текст отказа не подставляются: хэш резервного кода —
            # проверочное значение входа (`ADR-016` п. 3), он не уходит в журнал.
            if not is_sha256_hex(code_hash):
                raise BackupCodeError(
                    f"хэш №{position} в пачке не формы SHA-256 hex: битая строка в наборе"
                )
            if code_hash in seen:
                raise BackupCodeError(
                    f"хэш №{position} повторяется в пачке: коды обязаны быть разными"
                )
            seen.add(code_hash)

        statement = insert(BackupCode).values(
            [{"user_id": user_id, "code_hash": code_hash} for code_hash in code_hashes]
        )
        self._session.execute(statement)

    def find_unused_backup_code(self, *, user_id: UUID, code_hash: str) -> BackupCode | None:
        statement = select(BackupCode).where(
            BackupCode.user_id == user_id,
            BackupCode.code_hash == code_hash,
            # Предикат живой строки — в запросе: иначе «израсходован» и «не существует»
            # становятся разными ответами страницы (§8.8).
            BackupCode.used_at.is_(None),
        )
        return self._session.execute(statement).scalar_one_or_none()

    def spend_backup_code(self, *, code_id: UUID, user_id: UUID) -> bool:
        statement = (
            update(BackupCode)
            .where(
                BackupCode.id == code_id,
                BackupCode.user_id == user_id,
                BackupCode.used_at.is_(None),
            )
            .values(used_at=func.now())
            # `synchronize_session=False` — как у `claim_totp_step`: объект, который вызывающий
            # читал перед расходом, намеренно остаётся несинхронизированным, а лишний `SELECT`
            # перед `UPDATE` только добавил бы окно между чтением и переходом.
            .execution_options(synchronize_session=False)
        )
        result = cast("CursorResult[Any]", self._session.execute(statement))
        return bool(result.rowcount == 1)

    def invalidate_unused_backup_codes(self, user_id: UUID) -> int:
        statement = (
            update(BackupCode)
            .where(
                BackupCode.user_id == user_id,
                # Только неиспользованные: израсходованные держат след начала семидневного
                # срока (`ADR-016` п. 6 и п. 11), их аннулирование сняло бы блокировку входа.
                BackupCode.used_at.is_(None),
            )
            .values(used_at=func.now())
            .execution_options(synchronize_session=False)
        )
        result = cast("CursorResult[Any]", self._session.execute(statement))
        return int(result.rowcount)

    def bump_rate_bucket(
        self,
        *,
        scope: str,
        bucket_key: str,
        window_start: datetime,
        window_seconds: int,
    ) -> int:
        statement = (
            postgresql_insert(RateBucket)
            .values(
                scope=scope,
                bucket_key=bucket_key,
                window_start=window_start,
                window_seconds=window_seconds,
                attempts=1,
            )
            .on_conflict_do_update(
                index_elements=["scope", "bucket_key", "window_start"],
                set_={"attempts": RateBucket.attempts + 1},
            )
            .returning(RateBucket.attempts)
        )
        value = self._session.execute(statement).scalar_one()
        return int(value)

    def newest_counted_window(
        self,
        *,
        scope: str,
        bucket_key: str,
        min_attempts: int,
        window_start_after: datetime,
    ) -> BucketWindow | None:
        statement = (
            select(RateBucket.window_start, RateBucket.window_seconds, RateBucket.attempts)
            .where(
                RateBucket.scope == scope,
                RateBucket.bucket_key == bucket_key,
                RateBucket.attempts >= min_attempts,
                RateBucket.window_start > window_start_after,
            )
            .order_by(RateBucket.window_start.desc())
            .limit(1)
        )
        row = self._session.execute(statement).first()
        if row is None:
            return None
        window_start: datetime = row[0]
        window_seconds: int = row[1]
        attempts: int = row[2]
        return BucketWindow(
            window_start=window_start, window_seconds=window_seconds, attempts=attempts
        )


def build_session_factory(settings: Settings) -> tuple[Engine | None, sessionmaker[Session] | None]:
    """Движок и фабрика сессий для `app.state`.

    Пара `None`-значений возвращается, если адрес базы не настроен: процесс `web` обязан оставаться
    живым и отвечать на `/healthz` и `/readyz` (готовность честно назовёт причину), а маршруты входа
    — ответить `503`. Причина не в удобстве: healthcheck `web` держит весь периметр (Caddy зависит
    от здорового `web`), поэтому «нет базы → процесс мёртв» ломает приёмку периметра.
    """
    if settings.db_url is None:
        return None, None
    engine = create_engine(
        sqlalchemy_url(settings.db_url.get_secret_value()),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )
    return engine, sessionmaker(engine, expire_on_commit=False)


def get_store(request: Request) -> Iterator[Store]:
    """Зависимость FastAPI: репозиторий на текущий запрос.

    Соединение берётся из пула на время запроса и возвращается в пул, когда ответ сформирован.
    Неполученный транзакт при этом откатывается закрытием сессии — отказа CSRF «недокоммиченное
    состояние» не оставит.
    """
    factory: sessionmaker[Session] | None = request.app.state.session_factory
    if factory is None:
        raise StoreUnavailableError
    session = factory()
    try:
        yield SqlStore(session)
    finally:
        session.close()


def clamp_user_agent(raw: str | None) -> str | None:
    """Значение `user_agent` для записи сессии: не длиннее `USER_AGENT_MAX_LEN`.

    Значение показывают самому пользователю (§8.3), поэтому оно обязано быть ограниченным, а не
    «ровно тем, что прислал клиент»: список устройств не должен становиться каналом для мегасимволов.
    """
    if raw is None:
        return None
    return raw[:USER_AGENT_MAX_LEN]


class LoginTiming:
    """Одинаковая стоимость двух веток отказа входа: «нет такой учётной записи» и «неверный пароль».

    Если у неизвестного логина не тратить стоимость Argon2id, ответ по времени различает
    существование учётной записи — а §8.1 как раз закрывает учётные записи от перебора, и утечка
    «такой логин есть» прямо в этот контур не входит.

    Фиктивный хэш считается один раз на процесс и только когда ветка «логина нет» реально случилась:
    поднимать 64 МиБ Argon2 на старте процесса незачем, а стартовать с фиктивным значением,
    сгенерированным при импорте, — значит делать поведение зависимости от порядка импорта.

    Фиктивный хэш — не материал доступа и не секрет: он соответствует паролю, который никто не
    знает и не передаёт, поэтому результат сравнения всегда «нет совпадения».
    """

    def __init__(self) -> None:
        self._stored_hash: str | None = None

    def burn(self, password: str) -> None:
        """Потратить стоимость проверки, заведомо не имея шанса на совпадение."""
        if self._stored_hash is None:
            self._stored_hash = hash_password(f"<фиктивный>{secrets.token_urlsafe(24)}")
        verify_password(password=password, stored_hash=self._stored_hash)
