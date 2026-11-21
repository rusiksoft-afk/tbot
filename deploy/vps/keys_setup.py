#!/usr/bin/env python3
"""Файл ключей KEK на хосте площадки: создание, диагностика, приведение прав.

TZ §8.4 требует, чтобы KEK лежал файлом `/etc/tbot/keys/kek.json`, не в базе и не в образе.
`ADR-014` п. 5 описал формат документа и политику прав на уровне приложения, а заказчик решением
от 2026-11-21 (ask `05f7f262-0c56-41e6-9959-12aac2a45edb`) задал норму площадки: значение
генерирует скрипт, права — `0640 root:gid 10001` (вариант `ADR-005`, потому что файл монтируется
в контейнер и читается процессом под gid 10001). `secrets-setup.sh` создать этот файл не может:
он умеет «строка секрета», а здесь JSON с версиями ключей.

Запуск на площадке:

    sudo python3 deploy/vps/keys_setup.py             # создать (значение генерируется само)
    sudo python3 deploy/vps/keys_setup.py --check     # только диагностика
    sudo python3 deploy/vps/keys_setup.py --remed     # только права, байты не трогаются

Тот же инструмент без root и с другим путём — локальный прогон и CI (пустышка для разбора
состава и для проверки монтирования в контейнер):

    python3 deploy/vps/keys_setup.py --path /tmp/tbot-keys/kek.json --check --expect-owner any

Что гарантирует скрипт:

  - значение (32 случайных байта из `secrets`) генерируется само и **никогда не печатается**: ни
    в stdout, ни в stderr, ни в argv, ни в тексте отказа. наружу выходят только метаданные
    документа — номер формата, версии ключей, длины, режим и владелец (§8.4 «красное правило»
    про `repr`, логи и исключения);
  - запись атомарная: временный файл с `O_EXCL` и `0600`, затем права и владелец, затем
    `os.replace`. Окна, в котором ключ лежит в файле с правами «какие дал umask», нет;
  - права ставит скрипт, а не оператор: каталог `0700 root:root`, файл `0640 root:gid 10001`.
    Это ровно тот класс дефекта, который `ADR-005` разобрал на `db_url`: `0600 root:root` у
    монтируемого файла даёт `PermissionError: /run/secrets/db_url` при зелёной диагностике,
    потому что bind-маунт приносит хостовые права в контейнер, где процесс работает под
    uid/gid 10001;
  - `--check` сверяет путь, размер, режим, владельца и форму документа; дефекты собираются
    списком за один проход (чинить файл по одной подсказке за запуск — значит перезапускать
    процесс вслепую). Значение не выводится ни целиком, ни по частям;
  - `--remed` меняет только владельца и режим: «перезалить» KEK нельзя — привязки, зашифрованные
    старым ключом, после перезаписи значения не читаются вообще (это `T-107` с журналом и
    обязательным бэкапом, а не этот скрипт);
  - перезапись существующего файла требует `--force --yes` (в терминале — подтверждения).

Чего здесь сознательно нет:

  - ротации ключей и добавления второй версии — `T-107` (`make rotate-keys`: бэкап до операции,
    журнал, идемпотентность). Заказчик тем же ответом отказался ждать `T-107` до первой
    привязки: стартует файл, созданный этим инструментом;
  - шифрования самого файла: §8.4 требует хранения вне базы и вне образа, а не шифрования KEK;
  - резервного копирования, но обязанность названа прямо: без этого файла все привязки TOTP
    невосстановимы, поэтому копия обязана попасть в бэкап площадки (`ADR-002`, `T-702`). Скрипт
    напоминает об этом при каждом создании.

Нормы прав здесь строже, чем проверка приложения. `packages.common.crypto.kek_file_mode_error`
разрешает любые биты до `0640` включительно (буква §8.4 — `0400`, когда ключ читает хозяйственный
процесс), а площадка по решению заказчика живёт в варианте монтируемого секрета: `0640 root:gid
10001`. Поэтому `--check` требует ровно этого режима и ровно этого владельца, а приложение
остаётся снисходительным к `0400`: расхождение двух уровней зафиксировано в `ADR-014` п. 5 и не
является противоречием. То же касается платформы: на Windows (её нет на площадке) POSIX-бит нет, и
`--check` честно краснеет, а не выдаёт зелёный вердикт о правах, которых не существует.

Числа формата продублированы из `packages/common/crypto.py` намеренно: импортировать `packages`
на хосте нельзя (там нужна `cryptography`, которой на хосте нет), а расхождение означало бы «файл
создан, приложение его не принимает». Сверку констант по исходникам держит контрактный тест
`tests/contract/test_vps_artifacts.py`.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Final

#: Путь из TZ §8.4. Меняется только аргументом `--path` — для локального прогона и CI.
DEFAULT_PATH: Final = "/etc/tbot/keys/kek.json"

# Числа формата. Дублируют константы `packages/common/crypto.py` (`AES_KEY_BYTES`,
# `KEY_FILE_FORMAT_VERSION`, `KEY_VERSION_MIN`/`KEY_VERSION_MAX`, `KEK_FILE_MODE_MAX`) и держатся
# контрактной проверкой по исходникам обоих файлов.
KEY_BYTES: Final = 32
DOCUMENT_FORMAT_VERSION: Final = 1
KEY_VERSION_MIN: Final = 1
KEY_VERSION_MAX: Final = 65535
MODE_MAX: Final = 0o640

# Норма прав площадки (`ADR-005`, решение заказчика от 2026-11-21): файл монтируется в контейнер,
# процессы состава работают под uid/gid 10001 (`deploy/Dockerfile: USER 10001:10001`).
OWNER_UID: Final = 0
CONTAINER_GID: Final = 10001
DIR_MODE: Final = 0o700
FILE_MODE: Final = 0o640

# Канонический base64 ровно 32 байт: 44 символа с одним дополнением. hex, base64url и PEM
# отклоняются, потому что «длина та, а байты другие» выглядит на площадке отказом тега, а не
# ошибкой формата.
_KEY_B64_RE: Final = re.compile(r"[A-Za-z0-9+/]{43}=")
_DOCUMENT_FIELDS: Final = frozenset({"format_version", "active_version", "keys"})
_KEY_FIELDS: Final = frozenset({"version", "key"})

EXIT_OK: Final = 0
EXIT_PROBLEM: Final = 1


class SafeError(RuntimeError):
    """Отказ, в тексте которого нет ключевого материала (как в `packages.common.crypto`)."""


def new_document() -> str:
    """Текст документа с одним сгенерированным ключом версии 1.

    Возвращённый текст содержит значение ключа — и отдавать его разрешено только функции записи.
    Поэтому функция называется «документ», а не «ключ»: наружу из этого модуля ходят метаданные,
    а значение живёт между генератором и файлом.
    """
    key = base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii")
    document: dict[str, object] = {
        "format_version": DOCUMENT_FORMAT_VERSION,
        "active_version": KEY_VERSION_MIN,
        "keys": [{"version": KEY_VERSION_MIN, "key": key}],
    }
    return f"{json.dumps(document, indent=2, sort_keys=True)}\n"


def document_problems(text: str) -> tuple[list[str], list[int], int | None, int | None]:
    """Проверить форму текста документа.

    Вернуть: дефекты (пусто, если форма верна), версии ключей по возрастанию, активную версию и
    длину ключа в байтах. Правила совпадают с `parse_key_ring_document`: неизвестные поля —
    ошибка, а не «игнорируем» (опечатка в имени поля обязана быть видна сразу, иначе файл с
    ключом, который приложение не читает, выглядит рабочим); активная версия обязана входить в
    набор; версии лежат в диапазоне двух байтов заголовка конверта; ключ — канонический base64
    ровно 32 байт (AES-256 обязателен по §8.4: `AESGCM` молча принимает и 16, и 24 байта).

    Значений в ответе нет: версии и длины — метаданные.
    """
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        return ([f"файл не разбирается как JSON: {exc.msg}, строка {exc.lineno}"], [], None, None)
    if not isinstance(parsed, dict):
        return (
            ["ожидался JSON-объект с полями format_version, active_version, keys"],
            [],
            None,
            None,
        )

    document: dict[str, object] = {str(name): value for name, value in parsed.items()}
    problems: list[str] = []

    unknown = sorted(set(document) - _DOCUMENT_FIELDS)
    if unknown:
        problems.append(f"неизвестные поля документа: {unknown}")
    for field in sorted(_DOCUMENT_FIELDS):
        if field not in document:
            problems.append(f"нет поля {field!r}")

    format_version = document.get("format_version")
    if format_version is not None and format_version != DOCUMENT_FORMAT_VERSION:
        problems.append(
            f"format_version: ожидалось {DOCUMENT_FORMAT_VERSION}, получено {format_version!r}"
        )

    versions: list[int] = []
    key_length: int | None = None
    entries = document.get("keys")
    if entries is not None and not isinstance(entries, list):
        problems.append("keys: ожидался список объектов {version, key}")
    elif isinstance(entries, list):
        if not entries:
            problems.append("keys: список пуст — ключей в файле нет")
        for position, entry in enumerate(entries, start=1):
            entry_problems, entry_version, entry_key_length = _key_entry_info(
                position, entry, versions
            )
            problems.extend(entry_problems)
            if entry_version is not None:
                versions.append(entry_version)
            if entry_key_length is not None:
                key_length = entry_key_length

    active = document.get("active_version")
    if active is not None and (isinstance(active, bool) or not isinstance(active, int)):
        problems.append("active_version: ожидалось целое число версии ключа")
        active = None
    active_version = active if isinstance(active, int) else None
    if active_version is not None and versions and active_version not in versions:
        problems.append(f"active_version: версии {active_version} нет среди ключей {versions}")

    return (problems, versions, active_version, key_length)


def _key_entry_info(
    position: int, entry: object, seen_versions: list[int]
) -> tuple[list[str], int | None, int | None]:
    """Одна запись `keys[]`: дефекты, её версия (если корректна и не дублирует) и длина ключа.

    `seen_versions` — версии уже принятых записей: дубль версии обязан быть виден именно как
    дефект, потому что две записи с одной версией означают «ключ не тот» без диагностики.
    """
    if not isinstance(entry, dict):
        return ([f"keys[{position}]: ожидался объект, получено {type(entry).__name__}"], None, None)
    fields = {str(name): value for name, value in entry.items()}
    problems: list[str] = []
    extra = sorted(set(fields) - _KEY_FIELDS)
    if extra:
        problems.append(f"keys[{position}]: неизвестные поля {extra}")
    missing = sorted(_KEY_FIELDS - set(fields))
    if missing:
        problems.append(f"keys[{position}]: нет полей {missing}")
        return (problems, None, None)

    accepted_version: int | None = None
    version = fields["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        problems.append(f"keys[{position}]: version: ожидалось целое число версии ключа")
    elif not KEY_VERSION_MIN <= version <= KEY_VERSION_MAX:
        problems.append(
            f"keys[{position}]: версия {version} вне диапазона {KEY_VERSION_MIN}…{KEY_VERSION_MAX} "
            "(в заголовке конверта 2 байта)"
        )
    elif version in seen_versions:
        problems.append(f"keys[{position}]: версия {version} повторяется")
    else:
        accepted_version = version

    key_length: int | None = None
    key = fields["key"]
    if not isinstance(key, str):
        problems.append(f"keys[{position}]: key: ожидалась строка base64")
    elif not _KEY_B64_RE.fullmatch(key):
        problems.append(
            f"keys[{position}]: key: не канонический base64 ровно 32 байт (длина строки "
            f"{len(key)}; hex, base64url и PEM отклоняются)"
        )
    else:
        try:
            decoded = base64.b64decode(key, validate=True)
        except (binascii.Error, ValueError):
            problems.append(f"keys[{position}]: key: base64 не декодируется")
        else:
            if len(decoded) != KEY_BYTES:
                problems.append(
                    f"keys[{position}]: key: {len(decoded)} байт вместо {KEY_BYTES} "
                    "(AES-256 обязателен по §8.4: 16 и 24 байта GCM принимает молча)"
                )
            else:
                key_length = len(decoded)
    return (problems, accepted_version, key_length)


def mode_problems(mode: int) -> list[str]:
    """Дефекты режима файла: политика площадки строже политики приложения (`ADR-014` п. 5)."""
    permissions = stat.S_IMODE(mode)
    problems: list[str] = []
    extra = permissions & ~MODE_MAX
    if extra:
        problems.append(
            f"режим {oct(permissions)[2:]} даёт доступ шире {oct(MODE_MAX)[2:]} "
            f"(лишние биты {oct(extra)[2:]})"
        )
    if permissions != FILE_MODE:
        problems.append(
            f"режим {oct(permissions)[2:]} вместо {oct(FILE_MODE)[2:]}: файл монтируется в "
            f"контейнер под gid {CONTAINER_GID}, поэтому нужен ровно {oct(FILE_MODE)[2:]} "
            "(ADR-005: 0600 root:root даёт PermissionError внутри контейнера)"
        )
    return problems


def set_owner(path: Path, uid: int, gid: int) -> None:
    """Поставить владельца числами, без имени группы.

    `os.chown` принимает числовой gid, и это важно: в системе группы с gid 10001 может не быть
    (`ADR-005`: на хосте такой учётной записи нет, она существует только внутри образа), поэтому
    имя группы здесь не используется вовсе. На платформе без `os.chown` (Windows) операция
    невозможна — хост площадки это Linux, и вместо молчаливого пропуска скрипт краснеет.
    """
    posix_chown: object = getattr(os, "chown", None)
    if not callable(posix_chown):
        raise SafeError(f"{path}: платформа не умеет менять владельца (нужен {uid}:{gid})")
    posix_chown(path, uid, gid)


def ensure_directory(path: Path, *, owner: tuple[int, int] | None) -> None:
    """Создать каталог файла ключей с правами `0700 root:root`.

    Каталог не обязан быть читаемым для gid контейнера: файл в контейнер приносит compose (свой
    маунт), а хостовый демон открывает его от root. `0700` повторяет каталог `/etc/tbot/secrets`
    из `secrets-setup.sh`, чтобы имена файлов ключей не читала любая учётная запись на хосте.
    """
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=DIR_MODE, exist_ok=True)
    parent.chmod(DIR_MODE)
    if owner is not None:
        set_owner(parent, *owner)


def write_document(path: Path, text: str, *, owner: tuple[int, int] | None) -> None:
    """Записать документ атомарно и с правами площадки.

    Порядок важен: файл создаётся с `0600` и `O_EXCL`, права и владелец ставятся временному файлу,
    и только потом `os.replace` открывает его наружу. Запись «сразу в файл» дала бы окно, в котором
    ключ доступен чужим процессам, а усечённый после сбоя файл — отказ на старте процесса без
    объяснений.
    """
    ensure_directory(path, owner=owner)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(FILE_MODE)
        if owner is not None:
            set_owner(temporary, *owner)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def file_report(path: Path, expected: tuple[int, int] | None) -> tuple[str, list[str], list[str]]:
    """Вернуть метаданные файла одной строкой, отказы и предупреждения.

    Отказ означает «файл непригоден»: нет файла, не файл, режим не по норме, неверный владелец,
    документ не разборный. Предупреждение — то, что работоспособность не отменяет, но обязано быть
    видно: пропуск проверки владельца в прогоне без root, режим каталога.
    """
    if not path.exists():
        return ("", [f"нет файла: {path}"], [])
    if not path.is_file():
        return ("", [f"{path} — не файл: compose смонтировал бы пустой каталог"], [])

    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    description = (
        f"{info.st_size} байт, режим {oct(mode)[2:]}, владелец {info.st_uid}:{info.st_gid}"
    )
    problems: list[str] = []
    notes: list[str] = []

    if os.name != "posix":
        problems.append(
            "платформа без бит POSIX: режим "
            f"{oct(mode)[2:]} ничего не значит, проверка прав возможна только на Linux-хосте"
        )
    else:
        problems.extend(mode_problems(info.st_mode))

    if expected is None:
        notes.append(
            "владелец не проверялся (--expect-owner any): на площадке нужен прогон от root "
            f"с нормой {OWNER_UID}:{CONTAINER_GID}"
        )
    elif (info.st_uid, info.st_gid) != expected:
        problems.append(
            f"владелец {info.st_uid}:{info.st_gid} вместо {expected[0]}:{expected[1]}: файл читает "
            f"процесс под gid {expected[1]} (ADR-005)"
        )

    if info.st_size == 0:
        problems.append("пустой файл")
        return (description, problems, notes)

    text = path.read_text(encoding="utf-8", errors="replace")
    form_problems, versions, active, key_length = document_problems(text)
    problems.extend(form_problems)
    if not form_problems:
        description += (
            f", формат {DOCUMENT_FORMAT_VERSION}, ключей {len(versions)} "
            f"(версии: {', '.join(str(version) for version in versions)}), активная {active}, "
            f"длина ключа {key_length} байта"
        )
    return (description, problems, notes)


def check(path: Path, expected: tuple[int, int] | None) -> int:
    """Диагностика: наружу читаются только метаданные, файл не пишется."""
    description, problems, notes = file_report(path, expected)
    for problem in problems:
        print(f"FAIL: {path.name}: {problem}")
    if problems:
        return EXIT_PROBLEM
    print(f"OK:   {path.name}: {description}")
    for note in notes:
        print(f"WARN: {path.name}: {note}")
    if os.name == "posix":
        parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
        if parent_mode != DIR_MODE:
            print(
                f"WARN: каталог {path.parent}: режим {oct(parent_mode)[2:]} вместо "
                f"{oct(DIR_MODE)[2:]} — имена файлов ключей видны чужим учётным записям"
            )
    print("готово: файл ключей на месте, права по норме площадки, документ разборный")
    return EXIT_OK


def remediate(path: Path, expected: tuple[int, int] | None) -> int:
    """Привести владельца и режим, не читая и не переписывая значения."""
    if not path.is_file():
        print(f"FAIL: нет файла: {path} — привести нечего, сначала создание")
        return EXIT_PROBLEM
    before = path.stat()
    if expected is not None:
        set_owner(path, *expected)
    path.chmod(FILE_MODE)
    after = path.stat()
    print(
        f"FIX:  {path.name}: было {oct(stat.S_IMODE(before.st_mode))[2:]} "
        f"{before.st_uid}:{before.st_gid} -> стало {oct(stat.S_IMODE(after.st_mode))[2:]} "
        f"{after.st_uid}:{after.st_gid} (содержимое не читалось и не менялось)"
    )
    return check(path, expected)


def explain_existing_file(path: Path) -> None:
    """Объяснение, почему файл ключей просто так не перезаписывается.

    Молчаливый отказ — отдельный дефект: оператор видит код возврата 1 и не понимает, какой флаг
    он должен применить (а неверный флаг здесь означает потерю привязок).
    """
    info = path.stat()
    print(
        f"файл уже есть: {path} ({info.st_size} байт, "
        f"{oct(stat.S_IMODE(info.st_mode))[2:]} {info.st_uid}:{info.st_gid})",
        file=sys.stderr,
    )
    print(
        "  существование файла KEK означает, что привязки уже могли быть зашифрованы этим ключом:"
        " перезапись делает их нечитаемыми. Плановая смена ключа — это T-107 (ротация с бэкапом"
        " и журналом), а не этот скрипт.",
        file=sys.stderr,
    )


def confirm_overwrite(path: Path, assume_yes: bool) -> bool:
    """Согласие на перезапись существующего файла ключей."""
    explain_existing_file(path)
    if assume_yes:
        print("  перезапись подтверждена флагом --yes", file=sys.stderr)
        return True
    if not sys.stdin.isatty():
        print(
            "  прогон без терминала (stdin не терминал): перезапись не выполнена", file=sys.stderr
        )
        return False
    print("  перезаписать? [y/N]: ", end="", file=sys.stderr)
    try:
        answer = input().strip().lower()
    except EOFError:
        print("  stdin закрыт: ответа нет, перезапись не выполнена", file=sys.stderr)
        return False
    return answer in {"y", "yes"}


def create(path: Path, *, force: bool, assume_yes: bool, expected: tuple[int, int] | None) -> int:
    if expected is not None and not is_root():
        raise SafeError(
            "нужен root (файл принадлежит "
            f"{OWNER_UID}:{CONTAINER_GID}) либо явный прогон без норм владельца: --expect-owner any"
        )
    if path.is_file():
        if not force:
            explain_existing_file(path)
            print(
                "  без --force файл не перезаписывается; диагностика — --check, только права —"
                " --remed",
                file=sys.stderr,
            )
            return EXIT_PROBLEM
        if not confirm_overwrite(path, assume_yes):
            return EXIT_PROBLEM

    text = new_document()
    problems, _, _, _ = document_problems(text)
    if problems:
        # Проверка до записи: «файл создан, приложение его не принимает» — тот же класс дефекта,
        # что зелёный `--check` при значениях не по форме на площадке 2026-11-20.
        raise SafeError(f"сгенерированный документ не по форме: {problems}")

    write_document(path, text, owner=expected)
    description, _, _ = file_report(path, expected)
    print(f"создан файл ключей: {path}")
    print(f"  {description}")
    print("  значение сгенерировано (32 случайных байта) и не выводилось ни разу")
    if expected is not None:
        print(
            f"  права: {oct(FILE_MODE)[2:]} {expected[0]}:{expected[1]} — норма ADR-005 для"
            " файла, который монтируется в контейнер"
        )
    else:
        print("  владелец не менялся (--expect-owner any): это прогон без root, не площадка")
    print(
        "  НАПОМИНАНИЕ: без этого файла все привязки TOTP невосстановимы — копия обязана попасть "
        "в бэкап площадки (ADR-002, T-702); ротация ключей — T-107, не этот скрипт"
    )
    return check(path, expected)


def is_root() -> bool:
    """Запущен ли скрипт от root (на Windows `os.getuid` нет — считается «не root»)."""
    getuid = getattr(os, "getuid", None)
    return callable(getuid) and getuid() == 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="keys_setup.py",
        description=(
            "Создание и проверка файла ключей KEK (TZ §8.4, ADR-014 п. 5, ADR-005). "
            "Значение генерируется скриптом и не печатается."
        ),
        epilog=(
            "Ротация ключей и добавление второй версии — не здесь: это T-107 (make rotate-keys). "
            "Без копии этого файла привязки TOTP невосстановимы (ADR-002, T-702)."
        ),
    )
    parser.add_argument(
        "--path",
        default=DEFAULT_PATH,
        metavar="ПУТЬ",
        help=f"путь файла (по умолчанию {DEFAULT_PATH})",
    )
    parser.add_argument(
        "--check", action="store_true", help="только диагностика, ничего не пишется"
    )
    parser.add_argument(
        "--remed",
        action="store_true",
        help="привести владельца и режим; значения не читаются и не переписываются",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="разрешить перезапись существующего файла (значение теряет уже зашифрованные строки)",
    )
    parser.add_argument(
        "--yes", action="store_true", help="не спрашивать подтверждения вместе с --force"
    )
    parser.add_argument(
        "--expect-owner",
        default=f"{OWNER_UID}:{CONTAINER_GID}",
        metavar="UID:GID|any",
        help="норма владельца; `any` — прогон без root (CI и локальная проверка)",
    )
    return parser.parse_args(argv)


def parse_expect_owner(expected: str) -> tuple[int, int] | None:
    """Разобрать норму владельца: `UID:GID` или `any` (не проверять и не менять).

    Форма — числовая, а не именовая: gid 10001 это gid процесса внутри образа, и в хостовой
    группе такой записи может не быть вовсе (`ADR-005`), поэтому имя группы здесь не используется.
    """
    if expected == "any":
        return None
    parts = expected.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise SafeError("--expect-owner ждёт вид `UID:GID` (например 0:10001) или `any`")
    return (int(parts[0]), int(parts[1]))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    path = Path(args.path)
    if args.check and args.remed:
        print("отказ: --check и --remed исключают друг друга: сначала диагностика", file=sys.stderr)
        return EXIT_PROBLEM
    try:
        expected = parse_expect_owner(args.expect_owner)
        if args.remed:
            return remediate(path, expected)
        if args.check:
            return check(path, expected)
        return create(path, force=args.force, assume_yes=args.yes, expected=expected)
    except SafeError as exc:
        print(f"отказ: {exc}", file=sys.stderr)
        return EXIT_PROBLEM
    except OSError as exc:
        # Путь и причина остаются, содержимое файла — нет: значения в текст отказа не попадают.
        print(f"отказ: {path}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_PROBLEM


if __name__ == "__main__":
    raise SystemExit(main())
