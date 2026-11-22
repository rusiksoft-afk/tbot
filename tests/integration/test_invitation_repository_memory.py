"""Репозиторий приглашений и состояний учётных записей: офлайн-половинка (TZ §1.2, §4.1, §9.3 п. 6,
задача `T-105`, срез `R7a`, `ADR-020` п. 4).

Файл проверяет `MemoryStore` — то же зеркало протокола `Store`, на котором стоят HTTP-проверки
слоя входа (`tests/integration/web_support.py`). Смысл ровно тот же, что у пары «офлайн ↔ живая
база» в `T-104`: предикаты перехода можно прочитать глазами и в памяти, но память не доказывает ни
атомарность, ни индексы, ни `CHECK`.

Что здесь проверяется:

* **список ожидающих отсекает закрытые выпуски** (`pending_invitations`): `used` и `revoked` в
  очередь одобрения (§1.2) попадать не должны, а просроченные должны — признак живости решает
  домен, а не запрос (§2.7);
* **приём и отзыв — переходы, а не присваивание**: повторный вызов возвращает `False`, а не
  «тихо получилось снова» (`ADR-020` п. 4);
* **отзыв побеждает приём, а не наоборот**: отозванный выпуск нельзя заявить, и это направление
  гонки — единственное, которое видно из одной последовательности вызовов (настоящую параллельную
  гонку держит живой файл `tests/integration/test_invitations_db.py`, срез `R7b`, job `миграции`);
* **счёт администраторов считается по `active`** (`ADR-020` п. 6): строки `admin` в `suspended` и
  `archived` правом «в системе ещё есть администратор» не являются.

Чего память не доказывает (и переносить эти проверки сюда нельзя): атомарность guarded-`UPDATE`
при двух параллельных приёмах одной ссылки; наличие частичного индекса по `state`; то, что
`token_hash` в базе уникален и что `CHECK ck_invitations_state` отвергает четвёртое состояние;
сортировку по `created_at` и потолок `LIMIT` в запросе; что `id` строки выдаёт python-side default
при `flush` — здесь идентификаторы проставлены руками, потому что `INSERT` в памяти нет.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from packages.identity.invitations import IssuedInvitation, new_invitation
from packages.identity.users import CONSOLE_STATE
from tests.integration.web_support import MemoryStore

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
CREATOR = uuid4()


def _issue(
    store: MemoryStore, *, login: str, expires_at: datetime | None = None
) -> IssuedInvitation:
    """Выпустить приглашение и поставить его в репозиторий.

    `id` проставляется вручную: в памяти нет `INSERT`, а python-side default колонки применяется
    именно при записи. Это не «костыль ради теста», а граница памяти: генерацию идентификатора
    доказывает живая половина.
    """
    issued = new_invitation(created_by=CREATOR, role="operator", login=login, now=NOW)
    issued.record.id = uuid4()
    if expires_at is not None:
        issued.record.expires_at = expires_at
    store.add(issued.record)
    return issued


def test_список_ожидающих_держит_pending_и_просроченные_но_не_закрытые() -> None:
    """`used` и `revoked` из очереди убираются состоянием, просроченные — нет (§1.2, §2.7).

    Просроченный выпуск обязан остаться в списке: если его отсекает запрос, администратор теряет
    строку из списка молча, и «приглашение протухло» перестаёт быть чем-то, что видно в интерфейсе.
    """
    store = MemoryStore()
    open_one = _issue(store, login="ivan.petrov")
    expired = _issue(store, login="petr.ivanov", expires_at=NOW - timedelta(minutes=1))
    revoked = _issue(store, login="sidor.sidorov")
    store.revoke_invitation_row(invitation_id=revoked.record.id)
    used = _issue(store, login="nikolay.nikolaev")
    store.claim_invitation(invitation_id=used.record.id, now=NOW)

    listed = {record.login for record in store.pending_invitations()}
    assert listed == {"ivan.petrov", "petr.ivanov"}
    assert expired.record.state == "pending", "срок — не состояние: колонка остаётся `pending`"
    assert open_one.record.state == "pending"


def test_приём_одноразовый_второй_вызов_отказывается() -> None:
    """Второй приём одной ссылки отвечает `False`, а не второй учётной записью (§1.2, `ADR-020` п. 4).

    На живой базе это тот же guarded-`UPDATE` с `WHERE state = 'pending'`; здесь проверяется только
    форма ответа — «переход не состоялся» обязан быть различим, иначе вызывающий построит учётную
    запись по уже истраченной ссылке.
    """
    store = MemoryStore()
    issued = _issue(store, login="ivan.petrov")
    assert store.claim_invitation(invitation_id=issued.record.id, now=NOW) is True
    assert issued.record.state == "used"
    assert issued.record.used_at == NOW
    assert store.claim_invitation(invitation_id=issued.record.id, now=NOW) is False
    assert issued.record.used_at == NOW, "повторный приём не двигает штамп"


def test_просроченную_ссылку_заявить_нельзя_и_состояние_не_меняется() -> None:
    """Условие срока живёт в самом переходе, а не в проверке перед ним (`ADR-020` п. 4).

    Разделение нужно не для вежливости: маршрут обязан отличить «ссылки нет» от «ссылка была, но
    срок вышел», и оба варианта — отказ без создания учётной записи.
    """
    store = MemoryStore()
    issued = _issue(store, login="ivan.petrov", expires_at=NOW - timedelta(seconds=1))
    assert store.claim_invitation(invitation_id=issued.record.id, now=NOW) is False
    assert issued.record.state == "pending"
    assert issued.record.used_at is None


def test_отзыв_блокирует_приём_а_не_наоборот() -> None:
    """Единственное направление гонки, видимое из последовательности: отзыв раньше приёма.

    Порядок важен: если бы приём мог победить отзыв, администратор, нажавший «отозвать», оставил
    бы доступ уже созданной учётной записи, а журнал показал бы приглашение, по которому доступ
    выдан и одновременно отозван (§1.2).
    """
    store = MemoryStore()
    issued = _issue(store, login="ivan.petrov")
    assert store.revoke_invitation_row(invitation_id=issued.record.id) is True
    assert issued.record.state == "revoked"
    assert (
        store.revoke_invitation_row(invitation_id=issued.record.id) is False
    ), "повторный отзыв — переход, который не состоялся"
    assert store.claim_invitation(invitation_id=issued.record.id, now=NOW) is False


def test_несуществующий_идентификатор_перехода_не_создаёт() -> None:
    """`rowcount = 0` для идентификатора, которого нет: ответ не отличается от «уже закрыто» (§8.8)."""
    store = MemoryStore()
    assert store.claim_invitation(invitation_id=uuid4(), now=NOW) is False
    assert store.revoke_invitation_row(invitation_id=uuid4()) is False
    assert store.pending_invitations() == ()


@pytest.mark.parametrize("state", ["active", "suspended", "archived", "invited"])
def test_счёт_администраторов_считает_только_одобренных(state: str) -> None:
    """`active_admin_count` — про доступ, а не про строку: в `suspended` и `archived` администратор
    ни пригласить, ни одобрить не может (`ADR-020` п. 6).

    `invited` и `awaiting_approval` в счёт тоже не входят: у такой учётной записи доступа к разделу
    администрирования ещё нет (§1.2), поэтому «есть второй администратор в очереди» не снимает
    запрет закрывать доступ единственному действующему.
    """
    store = MemoryStore()
    keeper = store.seed_user(login="root.admin", role="admin")
    keeper.id = uuid4()  # `INSERT` в памяти нет, поэтому идентификатор проставлен вручную
    keeper.state = state
    assert store.active_admin_count(except_user_id=keeper.id) == 0
    assert store.active_admin_count() == (1 if state == CONSOLE_STATE else 0)


def test_счёт_не_считает_ту_самую_учётную_запись() -> None:
    """`except_user_id` — это «кроме той, которой применяем переход»: без него проверка всегда
    насчитала бы себя и разрешила закрыть последнего."""
    store = MemoryStore()
    first = store.seed_user(login="root.admin", role="admin")
    first.id = uuid4()
    second = store.seed_user(login="second.admin", role="admin")
    second.id = uuid4()
    assert store.active_admin_count(except_user_id=first.id) == 1
    assert store.active_admin_count(except_user_id=second.id) == 1
    assert store.active_admin_count(except_user_id=uuid4()) == 2
