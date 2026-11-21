"""Инструмент создания файла ключей KEK (`deploy/vps/keys_setup.py`) исполняется по-настоящему.

Повод для формата проверок — урок среза `R4b` (`docs/HANDOFF.md §1.37`): две проверки оказались
невидимы локально, потому что их содержание никто не исполнял. Здесь инструмент запускается
`subprocess`-ом, и проверяются его коды возврата, вывод и то, что реально лежит на диске после
него. Что держится этим файлом:

*   документ, созданный инструментом, принимает `parse_key_ring_document` из приложения. Числа
    формата продублированы в двух файлах (на хосте нельзя импортировать `packages`: нужна
    `cryptography`), и именно эта проверка превращает дублирование в договор, а не в надежду.
    Расхождение означало бы «файл создан, а процесс не стартует» — на площадке это обнаружилось бы
    при первом же `up -d`;
*   значение ключа не появляется ни в stdout, ни в stderr — ни в одном из трёх режимов
    (TZ §8.4 «красное правило»: `repr`, логи, исключения);
*   повторный запуск не перезаписывает существующий файл: потеря KEK делает уже зашифрованные
    привязки нечитаемыми, поэтому перезапись требует отдельных флагов, а в неинтерактивном
    прогоне не происходит вовсе;
*   `--remed` меняет только владельца и режим (байты совпадают), а `--check` падает на режиме
    шире нормы и на режиме «теснее нормы» — площадка живёт в варианте монтируемого секрета
    `0640 root:gid 10001` (`ADR-005`, решение заказчика от 2026-11-21), и молчаливое `0400`
    означает нечитаемый внутри контейнера ключ;
*   на платформе без бит POSIX инструмент не выдаёт зелёный вердикт о правах. Это не придирка к
    dev-машине: зелёное «права в порядке» там, где прав не существует, — тот же дефект, что
    `ADR-005` разобрал на `db_url` («файл есть, размер верный, а процесс не читает»).

Отдельно держится, что владелец на не-root прогоне не проверяется, но это произносится отдельной
строкой `WARN`, а не молчаливым пропуском.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from packages.common.crypto import (
    AES_KEY_BYTES,
    EnvelopeError,
    KeyRingError,
    ensure_envelope,
    parse_key_ring_document,
)
from tests.paths import VPS

TOOL: Path = VPS / "keys_setup.py"
_IS_POSIX = os.name == "posix"

posix_only = pytest.mark.skipif(not _IS_POSIX, reason="биты POSIX и владелец есть только на Linux")
non_posix_only = pytest.mark.skipif(_IS_POSIX, reason="проверка поведения платформы без POSIX-бит")

# Пути во всех проверках — внутри `tmp_path`: инструмент по умолчанию пишет в /etc/tbot/keys,
# и тесты не имеют права трогать системный каталог машины (ни dev, ни раннёра).
ANY_OWNER = ("--expect-owner", "any")


def _run(*args: str, stdin: int = subprocess.DEVNULL) -> subprocess.CompletedProcess[str]:
    """Запустить инструмент с UTF-8 выводом.

    `PYTHONUTF8` обязателен: на Windows локаль консоли — cp866, и без неё текст выводится
    кракозябрами, из-за чего проверки по тексту содержали бы не текст (тот же урок, что
    `docs/AGENTS.md` записал для `pytest`).
    """
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        stdin=stdin,
        check=False,
    )


def _create(path: Path) -> subprocess.CompletedProcess[str]:
    return _run("--path", str(path), *ANY_OWNER)


def _check(path: Path) -> subprocess.CompletedProcess[str]:
    return _run("--path", str(path), "--check", *ANY_OWNER)


def _document(path: Path) -> dict[str, Any]:
    parsed: Any = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _key_values(path: Path) -> list[str]:
    return [str(entry["key"]) for entry in _document(path)["keys"]]


def _posix_ids() -> tuple[int, int]:
    """uid и gid раннера.

    Только POSIX: под Windows стабы `os` этих атрибутов не объявляют, поэтому вызов идёт через
    `getattr` с проверкой наличия — без подавлений и без «на Windows просто промолчим».
    """
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        raise AssertionError("на этой машине нет POSIX-идентификаторов")
    return int(getuid()), int(getgid())


def test_инструмент_существует_и_разбирается_интерпретатором() -> None:
    assert TOOL.is_file(), f"нет инструмента создания файла ключей: {TOOL}"
    result = _run("--help")
    assert result.returncode == 0, result.stderr
    for flag in ("--check", "--remed", "--force", "--expect-owner", "--path"):
        assert flag in result.stdout, f"в справке нет флага {flag}: оператор узнаёт о нём из --help"


def test_созданный_документ_принимает_парсер_приложения(tmp_path: Path) -> None:
    """Главная связка среза: то, что пишет хостовый инструмент, читает приложение.

    Дублирование чисел формата (`KEY_BYTES`, `DOCUMENT_FORMAT_VERSION`, диапазон версий) держится
    не комментарием, а этой проверкой: документ разбирается `parse_key_ring_document`, активная
    версия и длина ключа совпадают с тем, что обещает инструмент.
    """
    path = tmp_path / "keys" / "kek.json"
    created = _create(path)
    assert created.returncode in (0, 1), created.stderr
    assert path.is_file(), f"файл не создан: {created.stdout}{created.stderr}"

    ring = parse_key_ring_document(path.read_text(encoding="utf-8"), source=str(path))
    assert (
        ring.active.version == 1
    ), "первый ключ обязан быть версии 1 — версия в заголовке конверта"
    assert len(ring.active.key) == AES_KEY_BYTES, "KEK обязан быть 32 байта (§8.4: AES-256)"
    assert sorted(ring.keys) == [1], f"в свежем файле одна версия, найдено {sorted(ring.keys)}"
    assert "скрыт" in repr(ring), f"repr связки обязан прятать ключ: {ring!r}"


def test_значение_ключа_не_попадает_ни_в_stdout_ни_в_stderr(tmp_path: Path) -> None:
    """Ни в одном из трёх режимов значение не уходит наружу.

    Проверка сравнивает вывод со значением, которое реально лежит в созданном файле: это не
    «в тексте нет слова key», а «в тексте нет этих байтов».
    """
    path = tmp_path / "kek.json"
    created = _create(path)
    keys = _key_values(path)
    assert len(keys) == 1
    value, encoded = keys[0], keys[0][:12]

    runs = [created, _check(path), _run("--path", str(path), "--remed", *ANY_OWNER)]
    for run in runs:
        output = run.stdout + run.stderr
        assert value not in output, f"значение ключа в выводе: {output!r}"
        assert encoded not in output, f"фрагмент значения ключа в выводе ({encoded!r})"
        base32ish = value.upper().replace("+", "-").replace("/", "_")
        assert base32ish not in output, "вывод не должен содержать и перекодированное значение"


def test_два_запуска_дают_разные_значения(tmp_path: Path) -> None:
    first = tmp_path / "a" / "kek.json"
    second = tmp_path / "b" / "kek.json"
    assert _create(first).returncode in (0, 1)
    assert _create(second).returncode in (0, 1)
    assert _key_values(first) != _key_values(second), "значение обязано быть случайным запуском"


def test_повторный_запуск_не_перезаписывает_файл(tmp_path: Path) -> None:
    """Существование файла означает, что привязки уже могли быть зашифрованы: перезапись — отказ.

    Молчаливая перезапись KEK превращает базу в набор нечитаемых шифртекстов, поэтому единственный
    легальный путь — `--force` с подтверждением (или неинтерактивный `--force --yes`), а плановая
    смена ключа — это `T-107` с бэкапом и журналом.
    """
    path = tmp_path / "kek.json"
    assert _create(path).returncode in (0, 1)
    before = path.read_bytes()

    again = _create(path)
    assert again.returncode == 1, "повтор без --force обязан отказаться"
    assert "--force" in again.stderr, "отказ обязан объяснять, какой флаг разрешает перезапись"
    assert "T-107" in again.stderr, "отказ обязан сослаться на ротацию, а не на этот скрипт"
    assert path.read_bytes() == before, "содержимое файла ключей при отказе не меняется"


def test_в_неинтерактивном_прогоне_force_не_перезаписывает(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    assert _create(path).returncode in (0, 1)
    before = path.read_bytes()
    forced = _run("--path", str(path), "--force", *ANY_OWNER)
    assert forced.returncode == 1, "без терминала подтверждение получить нечем — отказ"
    assert "перезапись не выполнена" in forced.stderr, forced.stderr
    assert path.read_bytes() == before


def test_check_на_отсутствующем_файле_называет_путь(tmp_path: Path) -> None:
    path = tmp_path / "нет-такого" / "kek.json"
    result = _check(path)
    assert result.returncode == 1
    assert "нет файла" in result.stdout
    assert path.name in result.stdout


def test_битый_документ_отказывается_списком_дефектов_без_значений(tmp_path: Path) -> None:
    """Все дефекты формы — за один проход, и ни один текст не содержит значения.

    Список важен: подсказка по одной за запуск означала бы «починили — снова красный» до бесконечности.
    Значение не печатается даже когда оно заведомо фиктивное: диагностика оперирует длинами.
    """
    path = tmp_path / "kek.json"
    secret_value = "Zm9vYmFyYmF6UXV1eDEyMzQ1Njc4OTBhYmNkZWY="
    path.write_text(
        json.dumps(
            {
                "format_version": 2,
                "active_version": 7,
                "keys": [
                    {
                        "version": 1,
                        "key": secret_value,
                        "comment": "КОММЕНТАРИЙ_НЕ_ПЕЧАТАЕТСЯ",
                    },
                    {"version": 1, "key": "AAAA"},
                    {"version": 99999, "key": "hexhexhexhex"},
                ],
                "секрет": "ЗНАЧЕНИЕ_ПОЛЯ_НЕ_ПЕЧАТАЕТСЯ",
            }
        ),
        encoding="utf-8",
    )
    result = _check(path)
    assert result.returncode == 1
    failures = [line for line in result.stdout.splitlines() if line.startswith("FAIL:")]
    assert len(failures) >= 5, f"ожидались все дефекты сразу: {failures}"
    output = result.stdout + result.stderr
    assert secret_value not in output, "значение ключа не печатается"
    for marker in ("КОММЕНТАРИЙ_НЕ_ПЕЧАТАЕТСЯ", "ЗНАЧЕНИЕ_ПОЛЯ_НЕ_ПЕЧАТАЕТСЯ"):
        assert marker not in output, f"значение поля {marker!r} ушло в вывод"
    joined = "\n".join(failures)
    assert "неизвестные поля" in joined, joined
    assert "секрет" in joined, f"имя неизвестного поля обязано быть названо: {joined}"
    for marker in ("format_version", "неизвестные поля", "повторяется", "99999", "base64"):
        assert marker in joined, f"в списке дефектов нет разбора про {marker}: {failures}"
    assert "длина строки" in joined, "про base64 печатается длина строки, а не значение"


def test_приложение_тоже_отвергает_то_что_отверг_инструмент(tmp_path: Path) -> None:
    """Пара к предыдущей проверке: отказ инструмента и отказ приложения совпадают по составу.

    Иначе возможен файл, который `--check` считает битым, а приложение принимает (или наоборот) —
    и «файл ключей готов» перестаёт быть предсказуемым свойством.
    """
    path = tmp_path / "kek.json"
    path.write_text(
        json.dumps(
            {"format_version": 1, "active_version": 3, "keys": [{"version": 2, "key": "AAAA"}]}
        ),
        encoding="utf-8",
    )
    assert _check(path).returncode == 1
    with pytest.raises(KeyRingError):
        parse_key_ring_document(path.read_text(encoding="utf-8"), source=str(path))


def test_кривая_норма_владельца_отказывается_объяснением(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    result = _run("--path", str(path), "--check", "--expect-owner", "root:tbot")
    assert result.returncode == 1
    assert (
        "UID:GID" in result.stderr
    ), "числовая форма обязана быть названа: gid 10001 вне хостовой группы"


@non_posix_only
def test_на_платформе_без_posix_о_правах_зелёного_вердикта_нет(tmp_path: Path) -> None:
    """На Windows проверка прав не «пропускается», а краснеет с объяснением.

    Зелёное «права в порядке» там, где битов POSIX нет, — это обещание, которого среда не даёт.
    Площадка — Linux, и инструмент обязан говорить, где он ничего не проверяет.
    """
    path = tmp_path / "kek.json"
    created = _create(path)
    assert "платформа без бит POSIX" in created.stdout + created.stderr
    assert _check(path).returncode == 1


@posix_only
def test_режим_файла_после_создания_ровно_норма_площадки(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    _create(path)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o640, f"норма монтируемого секрета 640 (ADR-005), получено {oct(mode)[2:]}"
    assert (
        _check(path).returncode == 0
    ), "на собственной записи инструмент обязан краснеть только на Windows"


@posix_only
def test_каталог_файла_ключей_создаётся_с_режимом_0700(tmp_path: Path) -> None:
    """Имена файлов ключей не должны читаться чужими учётными записями (тот же режим, что у

    каталога `/etc/tbot/secrets` в `secrets-setup.sh`).
    """
    path = tmp_path / "keys" / "kek.json"
    _create(path)
    mode = path.parent.stat().st_mode & 0o777
    assert mode == 0o700, f"каталог обязан быть 700, получено {oct(mode)[2:]}"
    assert _check(path).returncode == 0


@posix_only
@pytest.mark.parametrize("mode", [0o644, 0o666, 0o755, 0o604])
def test_режим_шире_нормы_отказывается(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "kek.json"
    _create(path)
    path.chmod(mode)
    result = _check(path)
    assert result.returncode == 1, f"режим {oct(mode)[2:]} обязан быть красным"
    assert oct(mode)[2:] in result.stdout, "в отказе обязан быть назван сам режим"
    assert "шире" in result.stdout, "режим шире нормы обязан быть объяснён как доступ чужим"


@posix_only
@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_режим_теснее_нормы_площадки_тоже_отказывается(tmp_path: Path, mode: int) -> None:
    """`0400` — буква TZ §8.4, но не норма этой площадки.

    Приложение такой режим принимает (`kek_file_mode_error` разрешает всё, что не шире `0640`), а
    `--check` требует `0640 root:gid 10001`: файл монтируется в контейнер, и режим «только
    владельцу» даёт ровно тот дефект, который `ADR-005` замерял на `db_url` —
    `PermissionError` при зелёной диагностике. Разница двух уровней зафиксирована в `ADR-014` п. 5.
    """
    path = tmp_path / "kek.json"
    _create(path)
    path.chmod(mode)
    result = _check(path)
    assert result.returncode == 1
    assert "вместо 640" in result.stdout, f"отказ обязан назвать норму: {result.stdout}"


@posix_only
def test_remed_приводит_режим_не_касаясь_байтов(tmp_path: Path) -> None:
    """`--remed` — режим «права без касания значений».

    Перезапись KEK невозможна (привязки теряются), поэтому на площадке права приводятся именно этим
    режимом. Совпадение байтов проверяется хэшем: «значение не менялось» должно быть фактом, а не
    обещанием.
    """
    path = tmp_path / "kek.json"
    _create(path)
    path.chmod(0o600)
    assert _check(path).returncode == 1
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    result = _run("--path", str(path), "--remed", *ANY_OWNER)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "не читалось" in result.stdout, "вывод обязан назвать содержимое нечитанным"
    assert path.stat().st_mode & 0o777 == 0o640
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@posix_only
def test_владелец_сверятся_с_нормой_и_несовпадение_красное(tmp_path: Path) -> None:
    """Несовпадение владельца — отказ, а не предупреждение.

    Проверка выполняется с числовой нормой: `0:10001` на прогоне без root недостижим (сменить
    владелец может только root), поэтому здесь проверяется ровно то, что доступно без привилегий:
    инструмент не имеет права называть зелёным файл с чужим владельцем.
    """
    path = tmp_path / "kek.json"
    _create(path)
    result = _run(
        "--path", str(path), "--check", "--expect-owner", f"{_posix_ids()[0] + 1}:{_posix_ids()[1]}"
    )
    assert result.returncode == 1
    assert "вместо" in result.stdout, result.stdout
    assert (
        "ADR-005" in result.stdout
    ), "отказ обязан сослаться на политику прав монтируемого секрета"


@posix_only
def test_прогон_без_root_явно_говорит_что_владелец_не_проверялся(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    _create(path)
    result = _check(path)
    assert result.returncode == 0
    warn = [line for line in result.stdout.splitlines() if line.startswith("WARN:")]
    assert any(
        "владелец не проверялся" in line for line in warn
    ), f"нет честной строки WARN: {warn}"


def test_создание_с_нормой_владельца_без_root_отказывается(tmp_path: Path) -> None:
    """Сменить владельца на `root:gid 10001` может только root — инструмент это требует явно."""
    if _IS_POSIX and _posix_ids()[0] == 0:
        pytest.skip("раннер работает от root: требование root проверить нечем")
    path = tmp_path / "kek.json"
    result = _run("--path", str(path))
    assert result.returncode == 1
    assert "root" in result.stderr
    assert not path.exists(), "отказ обязан произойти до записи файла"


def test_проверка_прав_документа_не_оставляет_временных_файлов(tmp_path: Path) -> None:
    """Атомарная запись: временный файл либо переименован, либо удалён.

    Окно, в котором ключ лежит в файле с правами «какие дал umask», — это окно, в котором его читает
    кто угодно. Проверка простая: после успешного создания в каталоге ровно один файл.
    """
    keys_dir = tmp_path / "keys"
    path = keys_dir / "kek.json"
    _create(path)
    leftovers = sorted(item.name for item in keys_dir.iterdir())
    assert leftovers == ["kek.json"], f"в каталоге остались временные файлы: {leftovers}"


def test_содержимое_документа_читается_приложением_как_связка_для_шифрования(
    tmp_path: Path,
) -> None:
    """Не «JSON разбирается», а «связкой можно воспользоваться».

    Отвязка от криптографии стоила бы того, чтобы проверка осталась декоративной: здесь значение
    проходит через `parse_key_ring_document` и годится как активный ключ, а кривой формат даёт
    различимую ошибку (`KeyRingError`), а не `EnvelopeError`.
    """
    path = tmp_path / "kek.json"
    _create(path)
    ring = parse_key_ring_document(path.read_text(encoding="utf-8"), source=str(path))
    assert isinstance(ring.active.key, bytes)
    assert ring.key_for(1) is ring.active
    with pytest.raises(KeyRingError):
        ring.key_for(2)
    with pytest.raises(EnvelopeError) as caught:
        # Открытое значение не проходит как конверт: правило модели остаётся в силе и здесь.
        ensure_envelope(b"JBSWY3DPEHPK3PXP", column="totp_enrollments.secret_enc")
    assert "totp_enrollments.secret_enc" in str(caught.value), "отказ обязан назвать колонку"
