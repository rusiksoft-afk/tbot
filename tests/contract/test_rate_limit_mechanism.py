"""Контракт механизма лимитов частоты и бана адреса (`T-102`, срез `R3d`; ТЗ §8.2, §8.3; ADR-007, ADR-009).

Живой базы и HTTP не нужен: сверяются текст техзадания, два ADR, константы кода и расстановка
вызовов в слое входа. Именно эти соответствия уезжают молча, когда лимит «подправляют по ходу»:

* пределы по областям расходятся с §8.3 (число в коде забывают поменять вместе с ТЗ, или наоборот);
* область механизма перестаёт входить в `RATE_SCOPES` схемы — и на первом же запросе прилетает
  `23514`, а выясняется это на площадке;
* окно перебора (§8.2) и срок бана (`ADR-007`) превращаются в настройку YAML, хотя решение
  заказчика — константа кода (то же правило, что у сроков сессий в `test_sessions_contract.py`);
* счётчик переезжает в память процесса (`ADR-007` прямо это запрещает: память обнуляется при
  рестарте контейнера и не согласуется между процессами, то есть «10 запросов в минуту на IP»
  перестаёт быть лимитом по IP);
* проверка бана переезжает в middleware всего `web` — «бан IP» становится блокировкой сайта для
  всех за провайдерским NAT (решение заказчика ask `ba6a9076`: зона отказа — слой входа);
* чистка окон получает порог короче, чем живёт бан, и начинает «съедать» действующую блокировку;
* кто-то «дописывает» журнал на `429`, ломая инвариант цепочки хэшей, — перенос записи в `T-109`
  зафиксирован `ADR-009` (ask `c53daa01`), и это отклонение от буквы `ADR-007`, а не недосмотр.

Поведение (что именно отвечает HTTP-слой) проверяют `tests/integration/test_web_rate_limit.py`
(память) и `tests/integration/test_rate_limit_mechanism_db.py` (живой PostgreSQL: конкурентный
инкремент, чтение окна, чистка). Здесь держится соответствие «документ ↔ константа ↔ вызов», без
которого те проверки становятся зелёными при другом договоре.
"""

from __future__ import annotations

import ast
import re
from datetime import timedelta
from pathlib import Path
from typing import Final

from apps.jobs.main import JOB_REGISTRY
from apps.jobs.maintenance import (
    PURGE_JOB_NAME,
    RATE_BUCKET_PURGE_INTERVAL_S,
    RATE_BUCKET_RETENTION,
)
from apps.web.security.rate_limit import (
    IP_BAN_DURATION,
    IP_BAN_SCOPE,
    IP_BAN_THRESHOLD,
    LOGIN_IP_SCOPE,
    MUTATION_USER_SCOPE,
    RATE_LIMITS,
    TOTP_IP_SCOPE,
    TOTP_SESSION_SCOPE,
)
from packages.common.config import Settings
from packages.identity.users import LOCK_DURATION
from packages.storage.models import (
    RATE_BAN_WINDOW_SECONDS,
    RATE_SCOPES,
    RATE_WINDOW_SECONDS,
    RATE_WINDOWS,
    RateBucket,
)

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
ADR_RATE: Final = ROOT / "docs" / "adr" / "ADR-007-rate-limit-counter-table.md"
ADR_FORMS: Final = ROOT / "docs" / "adr" / "ADR-009-form-parsing-without-multipart.md"
MECHANISM: Final = ROOT / "apps" / "web" / "security" / "rate_limit.py"
CLIENTS: Final = ROOT / "apps" / "web" / "security" / "clients.py"
LOGIN_ROUTE: Final = ROOT / "apps" / "web" / "routes" / "login.py"
TOTP_ROUTE: Final = ROOT / "apps" / "web" / "routes" / "totp.py"
#: Модули зоны входа (§8.2): шаг пароля и шаг кода. Окно перебора по адресу относится к
#: церемонии входа целиком, поэтому счётчик `ip_ban` читается и двигается в обоих.
LOGIN_ZONE: Final = (LOGIN_ROUTE, TOTP_ROUTE)
WEB_DIR: Final = ROOT / "apps" / "web"
ROUTES_DIR: Final = WEB_DIR / "routes"
MAIN_MODULE: Final = WEB_DIR / "main.py"


def _tz() -> str:
    return TZ_SECURITY.read_text(encoding="utf-8")


def _rate_limit_bullet() -> str:
    """Абзац §8.3 про Rate limit — единственный источник чисел лимитов."""
    bullet = re.search(r"^- Rate limit:(.*?)\n- ", _tz(), re.M | re.S)
    assert bullet, "в §8.3 не найден абзац «Rate limit:» — проверка теряет смысл"
    return bullet.group(1)


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _mutable_module_state(tree: ast.Module) -> list[str]:
    """Имена изменяемых переменных уровня модуля (константы в ВЕРХНЕМ_РЕГИСТРЕ не считаются).

    Нужен именно синтаксический разбор: объяснительный текст в этих модулях длинный, и поиск по
    строке нашёл бы слово «словарь» в комментарии.
    """
    found: list[str] = []
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None or not isinstance(value, ast.Dict | ast.List | ast.Set | ast.Call):
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id.isupper() or target.id.startswith("__"):
                # Константы в ВЕРХНЕМ_РЕГИСТРЕ и объявления вида `__all__` — не состояние процесса.
                continue
            found.append(target.id)
    return found


def _tree(path: Path) -> ast.Module:
    return ast.parse(_source(path), filename=str(path))


def _code_names(path: Path) -> set[str]:
    """Идентификаторы, которые модуль использует в коде (прозу и строки не считает).

    Нужно ровно для одного: отличить «модуль вызывает журнал аудита» от объяснительной прозы про
    журнал. Проза в этих модулях как раз объясняет, чего здесь нет, поэтому поиск по тексту файла
    дал бы противоположный результат.
    """
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def _string_constants(path: Path) -> set[str]:
    """Строковые литералы модуля: по ним сверяют имена заголовков и полей формы."""
    return {
        node.value
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


# ─── пределы и области (§8.3) ──────────────────────────────────────────────────────────────────


def test_пределы_механизма_совпадают_с_числами_из_8_3() -> None:
    """Числа лимитов берутся из ТЗ, а не из удобства реализации.

    Расхождение в обе стороны одинаково опасно: «починили» лимит в коде, и ТЗ врёт о защите;
    изменили ТЗ, а счётчик считает по-старому. Поэтому проверка сравнивает константы механизма
    с разобранным абзацем §8.3, а не с другим числом в коде.
    """
    bullet = _rate_limit_bullet()
    login = re.search(r"`/login`\s*—\s*(\d+)\s*запросов/мин/IP", bullet)
    totp = re.search(r"`/totp`\s*—\s*(\d+)/мин/сесси\w+\s*и\s*(\d+)/мин/IP", bullet)
    mutation = re.search(r"mutation-эндпоинты\s*—\s*(\d+)/мин/пользовател\w+", bullet)
    assert login, f"в абзаце Rate limit не читается формулировка `/login`: {bullet!r}"
    assert totp, f"в абзаце Rate limit не читается формулировка `/totp`: {bullet!r}"
    assert mutation, f"в абзаце Rate limit не читается формулировка mutation-эндпоинтов: {bullet!r}"

    expected = {
        LOGIN_IP_SCOPE: int(login.group(1)),
        TOTP_SESSION_SCOPE: int(totp.group(1)),
        TOTP_IP_SCOPE: int(totp.group(2)),
        MUTATION_USER_SCOPE: int(mutation.group(1)),
    }
    assert (
        dict(RATE_LIMITS) == expected
    ), f"пределы механизма {dict(RATE_LIMITS)} расходятся с §8.3 {expected}"


def test_области_механизма_допустимы_схемой_и_без_лишних() -> None:
    """Каждая область, под которую пишет механизм, есть в `CHECK` схемы.

    Иначе первая же запись прилетает `23514` на площадке: список областей держит база, а не
    приложение. Отдельно держится, что `ip_ban` — не предел частоты: это окно перебора §8.2, и
    попытка выдать его за «ещё один лимит в минуту» ломает и смысл, и порог (`attempts` там
    сравнивается с числом неудач, а не с числом запросов).
    """
    used = {*RATE_LIMITS, IP_BAN_SCOPE}
    unknown = used - set(RATE_SCOPES)
    assert not unknown, f"механизм пишет в области, которых нет в схеме: {sorted(unknown)}"
    assert set(RATE_SCOPES) == used, (
        f"области схемы {sorted(RATE_SCOPES)} и механизма {sorted(used)} разошлись: "
        "для одной из них нет ни предела, ни порога"
    )
    assert (
        IP_BAN_SCOPE not in RATE_LIMITS
    ), "окно перебора §8.2 попало в пределы частоты §8.3: у него другой смысл счётчика"


def test_порог_перебора_и_окно_из_8_2() -> None:
    """§8.2: «3 неудачные попытки с одного IP за 5 минут» → порог 3 и окно 300 секунд.

    Окно берётся из схемы (`RATE_BAN_WINDOW_SECONDS`), а не из механизма: третий вариант окна база
    отклоняет, и механизм обязан считаться с тем, что уже решено (`ADR-007`).
    """
    sentence = re.search(r"(\d+)\s+неудачные попытки с одного IP за (\d+)\s+минут", _tz())
    assert sentence, "в §8.2 не найдено правило перебора по IP — проверка теряет смысл"
    assert (
        int(sentence.group(1)) == IP_BAN_THRESHOLD
    ), f"порог окна перебора {IP_BAN_THRESHOLD}, в §8.2 — {sentence.group(1)}"
    minutes = int(sentence.group(2))
    assert (
        minutes * 60 == RATE_BAN_WINDOW_SECONDS
    ), f"окно перебора {RATE_BAN_WINDOW_SECONDS} с не соответствует «за {minutes} минут» из §8.2"
    assert (
        RATE_WINDOW_SECONDS,
        RATE_BAN_WINDOW_SECONDS,
    ) == RATE_WINDOWS, f"решённая пара (60, 300) не равна набору в моделях {RATE_WINDOWS}"


def test_срок_бана_константа_кода_а_не_настройка() -> None:
    """15 минут бана — решение заказчика (`ADR-007`, ask `ba6a9076`), а не переменная окружения.

    То же правило, что у сроков сессий и блокировок: если значение уезжает в YAML, его меняет
    любой, кто имеет доступ к составу, и обещание «временный бан длится 15 минут» перестаёт
    быть частью кода, который рецензируется.
    """
    adr = ADR_RATE.read_text(encoding="utf-8")
    assert re.search(
        r"бана IP\s*—\s*15 минут", adr
    ), "в ADR-007 не осталось формулировки срока бана — константа теряет источник"
    assert IP_BAN_DURATION.total_seconds() == 15 * 60, f"срок бана: {IP_BAN_DURATION}"

    settings_fields = {name.lower() for name in Settings.model_fields}
    suspicious = [name for name in settings_fields if "ban" in name or "rate" in name]
    assert not suspicious, f"сроки или лимиты уехали в настройки приложения: {suspicious}"


def test_срок_бана_не_колонка_и_считается_от_окна_строки() -> None:
    """`ADR-009`: колонки `ban_until` в счётчике нет, срок выводится из `window_start` + окно + срок.

    Проверка держит и обратное: в механизме нет самостоятельных секунд бана, прилетевших из
    «удобного» числа. Иначе две величины (окно и срок) начали бы жить отдельно, и бан то продлевался
    бы сам собой, то исчезал раньше срока.
    """
    columns = {column.name for column in RateBucket.__table__.columns}
    assert not any(
        "ban" in name or "until" in name for name in columns
    ), f"в {RateBucket.__tablename__} появилась колонка срока бана: {sorted(columns)}"
    adr_forms = ADR_FORMS.read_text(encoding="utf-8")
    assert "Своя колонка/ревизия" in adr_forms, (
        "ADR-009 потерял разбор отказа от отдельной колонки со сроком бана: следующая сессия "
        "вернёт `0004` молча"
    )
    assert (
        "ban_until" in adr_forms
    ), "ADR-009 потерял имя отвергнутого варианта (`ban_until`) — разбор становится непонятным"
    assert (
        "window_start + window_seconds + IP_BAN_DURATION" in adr_forms
    ), "ADR-009 потерял формулу срока бана — механизм теряет источник правила"

    mechanism = _source(MECHANISM)
    assert "window_start + timedelta(seconds=RATE_BAN_WINDOW_SECONDS) + IP_BAN_DURATION" in (
        mechanism
    ), "механизм больше не выводит срок бана из полей строки (ADR-009)"
    assert re.search(r"\b(900|1200|1800)\b", mechanism) is None, (
        "в механизме появились секунды бана отдельным числом: срок обязан считаться от "
        "IP_BAN_DURATION и окна строки"
    )


# ─── где живёт счётчик и где стоит граница отказа ──────────────────────────────────────────────


def test_счётчика_в_памяти_процесса_нет() -> None:
    """`ADR-007`: единственное хранилище счётчика — таблица `rate_buckets`.

    Счётчик в памяти выглядит безобидно и проходит офлайновые проверки, но на площадке
    обнуляется при `docker restart` и не согласуется между воркерами: «10 запросов в минуту на IP»
    перестаёт быть лимитом по IP. Проверка ищет саму конструкцию — модульное изменяемое состояние
    и пословарный учёт, — а не только слово в комментарии.
    """
    mechanism = _source(MECHANISM)
    module_state = _mutable_module_state(_tree(MECHANISM))
    assert not module_state, (
        f"в механизме появились изменяемые переменные уровня модуля: {module_state} — счётчик "
        "переехал в память процесса (ADR-007)"
    )
    for forbidden in ("defaultdict", "Counter(", ".cache", "lru_cache"):
        assert forbidden not in mechanism, f"в механизме появился учёт в памяти: {forbidden}"
    assert (
        mechanism.count("bump_rate_bucket") >= 2
    ), "механизм должен двигать счётчик в базе и для пределов, и для окна перебора"
    assert (
        "newest_counted_window" in mechanism
    ), "проверка бана перестала читать базу: бан не переживёт рестарт контейнера"


def test_граница_отказа_слой_входа_а_не_весь_веб() -> None:
    """Бан адреса держат маршруты зоны входа, а не middleware всего `web` (ask `ba6a9076`).

    Проверка в middleware превратила бы «бан IP» в блокировку всего сайта для всех, кто сидит за
    одним провайдерским NAT, и каждое ложное срабатывание наказало бы не переборщика. Держится
    двусторонне: вызов есть в зоне входа, и его нет больше нигде в `apps/web`.

    Зона входа с `T-103` — это два модуля: шаг пароля (`login.py`) и шаг кода (`totp.py`). Окно
    «3 неудачные попытки с одного адреса за 15 минут» (§8.2) описывает вход как церемонию, а не
    один запрос: попытка кода — такая же попытка подобрать второй фактор, поэтому окно читается и
    двигается в обоих модулях по одним основаниям и по одному счётчику `ip_ban`. Общий счётчик
    здесь не удобство: если бы у пароля и у кода были разные окна адреса, перебор обходился бы
    чередованием полей («пароль — код — пароль»), и лимит 3 попытки на адрес терял бы смысл.
    Расширять список можно только вместе с §8.2: у зон профиля и администрирования окна перебора
    нет, и проверка ниже это держит.
    """
    for module in LOGIN_ZONE:
        calls = _code_names(module)
        for needed in ("ban_until", "enforce_scope", "register_address_failure"):
            assert needed in calls, f"{module.name} больше не вызывает {needed}"

    readers = sorted(
        path.name
        for path in ROUTES_DIR.glob("*.py")
        if "ban_until" in _code_names(path) and path not in LOGIN_ZONE
    )
    assert not readers, f"проверку бана адреса подключили ещё и в {readers}: зона отказа шире входа"

    main_source = _source(MAIN_MODULE)
    assert (
        "RateLimitExceeded" in main_source
    ), "обработчик отказа по лимиту исчез из приложения: отказ станет 500 вместо 429"
    # Middleware в приложении навешивается декоратором `@app.middleware("http")` (срез `R3c`),
    # поэтому ищем имена функций под декоратором, а не вызовы `add_middleware`.
    decorated = re.findall(r'@app\.middleware\("http"\)\s*(?:async\s+)?def\s+(\w+)', main_source)
    assert {"_trace_middleware", "_security_headers_middleware"} <= set(
        decorated
    ), f"разметка middleware в приложении изменилась, проверка слепнет: {sorted(decorated)}"
    forbidden = [name for name in decorated if re.search(r"(rate|limit|ban|throttle)", name)]
    assert not forbidden, (
        f"лимиты или бан адреса переехали в middleware всего web: {forbidden} — зона отказа "
        "шире слоя входа (ask `ba6a9076`)"
    )


def test_обе_области_кода_применяются_в_слое_кода_а_не_только_объявлены() -> None:
    """`ADR-007` заводит две области для приёма кода; объявить их и не вызвать — то же, что не завести.

    `totp_session` (10 в минуту на сеанс) и `totp_ip` (5 в минуту на адрес) из §8.3 рассчитаны на
    разные модели перебора: первая держит перебор «в одном сеансе», вторая — распыление сеансов с
    одного адреса. Если в слое кода останется одна вызванная область, вторая строка `RATE_LIMITS`
    начнёт выглядеть как покрытие, которого нет, а §8.3 останется выполненным на бумаге.

    Отдельно держится, что области называются константами модуля `rate_limit`, а не строковыми
    литералами в маршрутах: `RATE_LIMITS`, CHECK-перечень схемы и живая проверка ссылаются на те же
    значения, и литерал разошёлся бы с ними молча.

    Парность вызовов — не стиль: у приёма кода входа и у подтверждения привязки основания отказа
    одинаковые (один сеанс, один адрес), поэтому обе точки ограничиваются обоими лимитами. Мутация
    «выдать секрет» при этом держится на счётчике мутаций пользователя (`ADR-007`), который
    подключён зависимостью страницы, а не отдельным числом в обработчике.
    """
    код = _source(TOTP_ROUTE)
    вызовы = {
        область: len(re.findall(rf"enforce_scope\(store, {область},", код))
        for область in ("TOTP_SESSION_SCOPE", "TOTP_IP_SCOPE")
    }
    assert all(
        вызовы[область] >= 1 for область in вызовы
    ), f"одна из областей кода не применяется в слое кода: {вызовы}"
    assert (
        вызовы["TOTP_SESSION_SCOPE"] == вызовы["TOTP_IP_SCOPE"]
    ), f"области кода применяются не парами: {вызовы} — у одной точки приёма кода лимит пропущен"
    assert not re.search(r'enforce_scope\([^,]+,\s*"', код), (
        "в маршрутах появилась область, названная строковым литералом: перечень держит `rate_limit` "
        "и схема, литерал разойдётся с ними молча"
    )
    assert "RateLimitedMutation" in код, (
        "счётчик мутаций пользователя исчез из страницы привязки: выдача секрета перестанет "
        "лимитироваться (§8.3)"
    )


def test_объяснение_блокировки_на_странице_совпадает_со_сроком_из_кода() -> None:
    """Страница кода обещает ровно тот срок, который на самом деле ставит код (§8.2, §9.3 п. 2).

    Человек читает «вход закрывается на 15 минут», а блокировку считает `users.LOCK_DURATION`.
    Расхождение здесь не косметика: объяснение перестаёт быть правдой, а проверить его поведением
    нельзя — блокировка наступает через 15 минут реального времени, и тест на это не запускается.

    Сверяется число, а не весь текст: падеж («минут»/«минуту») правится человеком осознанно вместе
    с константой, и автоматика не должна подменять решение о формулировке.
    """
    код = _source(TOTP_ROUTE)
    названные_минут = re.findall(r"(\d+)\s*мин", код)
    минуты = int(LOCK_DURATION.total_seconds() // 60)
    assert str(минуты) in названные_минут, (
        f"в объяснении блокировки нет числа {минуты}: текст разошёлся с `LOCK_DURATION` "
        f"(найдено: {названные_минут})"
    )


def test_адрес_для_счётчика_и_для_сессии_один_и_тот_же() -> None:
    """Ключ счётчика и поле `sessions.ip` берутся из одного источника (ТЗ §8.3, `ADR-009`).

    Если «блокируем» по одному адресу, а «показываем» по другому, то журнал входа и бан расходятся,
    а переборщик прячется за левым элементом `X-Forwarded-For`, который присылает он сам.
    """
    assert "X-Forwarded-For" in _source(CLIENTS), "clients.py перестал разбирать заголовок прокси"
    header_readers = sorted(
        path.relative_to(WEB_DIR).as_posix()
        for path in WEB_DIR.rglob("*.py")
        if "X-Forwarded-For" in _string_constants(path)
    )
    assert header_readers == [
        "security/clients.py"
    ], f"заголовок прокси читают в нескольких модулях: {header_readers} — адреса разъедутся"

    login_calls = _code_names(LOGIN_ROUTE)
    assert "session_ip" in login_calls, (
        "слой входа больше не берёт адрес через sessions.session_ip: ключ счётчика и запись "
        "сессии могут разойтись"
    )


def test_журнала_на_429_здесь_нет_и_это_зафиксировано_решением() -> None:
    """Перенос записи в журнал на `T-109` — осознанное отклонение от буквы `ADR-007`.

    Без проверки «здесь журнала нет» следующая сессия «допишет» частичную запись, а `hash_prev`
    сделает весь журнал непроверяемым (`make audit-verify` — вторая половина `AC-identity-04`).
    Поэтому держится и факт (в механизме и маршруте входа нет обращений к журналу), и документ,
    который объясняет, почему так.
    """
    adr_forms = ADR_FORMS.read_text(encoding="utf-8")
    assert "T-109" in adr_forms, "ADR-009 потерял отсылку к задаче, где появляется запись журнала"

    for path in (MECHANISM, LOGIN_ROUTE):
        names = _code_names(path)
        forbidden = {name for name in names if "audit" in name.lower()}
        assert not forbidden, f"{path.name}: обращения к журналу аудита ({sorted(forbidden)})"


# ─── чистка окон (ADR-007: регламент и безопасность порога) ────────────────────────────────────


def test_чистка_объявлена_в_реестре_задач_с_регламентом_adr_007() -> None:
    """Чистка окон — не «желательна»: строки счётчика копятся каждый лимитируемый запрос.

    Регламент («jobs, раз в час, окна старше 24 часов») обязан быть виден в реестре задач с
    привязкой к задаче плана, иначе фоновая работа остаётся обещанием в ADR.
    """
    adr = ADR_RATE.read_text(encoding="utf-8")
    for marker in ("раз в час", "24 часов", "jobs"):
        assert marker in adr, f"в ADR-007 не осталось маркера чистки {marker!r}"

    purge = next(job for job in JOB_REGISTRY if job.name == PURGE_JOB_NAME)
    assert (
        purge.interval_s == RATE_BUCKET_PURGE_INTERVAL_S
    ), f"интервал задачи {purge.interval_s} с и константа {RATE_BUCKET_PURGE_INTERVAL_S} с разошлись"
    assert RATE_BUCKET_PURGE_INTERVAL_S == 3600.0, "ADR-007: прогон раз в час"
    assert timedelta(hours=24) == RATE_BUCKET_RETENTION, "ADR-007: окна старше 24 часов"


def test_порог_чистки_длиннее_действующего_бана() -> None:
    """Чистка не имеет права удалить окно, которое ещё запрещает вход.

    Действующий бан живёт до `window_start + окно + IP_BAN_DURATION`, поэтому порог хранения обязан
    быть строго больше суммы окна перебора и срока бана. Это ровно та опасность, которую `ADR-007`
    называет прямым текстом; проверка не даёт порогу уехать в меньшую сторону молча.
    """
    assert timedelta(seconds=RATE_BAN_WINDOW_SECONDS) + IP_BAN_DURATION < RATE_BUCKET_RETENTION, (
        f"порог чистки {RATE_BUCKET_RETENTION} не длиннее окна "
        f"{RATE_BAN_WINDOW_SECONDS} с плюс срок бана {IP_BAN_DURATION}"
    )
