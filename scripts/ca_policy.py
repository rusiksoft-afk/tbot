#!/usr/bin/env python3
"""Политика доверия к TLS брокера: какой корень НУЦ допустим и где он лежит.

Модуль намеренно на чистой стандартной библиотеке и без разбора X.509: его исполняют
`scripts/deploy_check.py` (проверка площадки), `scripts/tls_trust_probe.py` (приёмочная проба)
и CI- job «доверие TLS брокера», где зависимостей приложения нет. Так отпечаток живёт в одном
месте: продублировать его в workflow или Dockerfile — значит однажды проверить не тот сертификат.

Что закреплено и почему:

* отпечаток (SHA-256 DER) вместо имени. Сертификат с тем же CN, но другим ключом — это и есть
  подмена; по имени её не отличить (docs/research/03 §3.3).
* значение получено по двум независимым AIA-выдачам одного корня
  (`nuc-cdp.digital.gov.ru` и `nuc-cdp.voskhod.ru`) — файлы совпали байт в байт.
* срок действия проверяет `deploy_check.check_ca_bundle`: он работает там, где есть
  зависимости приложения (площадка, контейнер, dev-машина), а здесь остаётся только то, для
  чего разбор не нужен: наличие файла и его идентичность закреплённому якорю.

Порядок действий при смене удостоверяющего центра — docs/runbook/nucc-ca.md §5.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Артефакт в репозитории и его место в образе/на хосте. Расширение `.crt` и верхний уровень
# каталога — требование Debian: `update-ca-certificates` читает только `*.crt` из
# `/usr/local/share/ca-certificates`, файл `*.pem` или файл в подкаталоге он не замечает
# (проверено в CI: сборка оставалась зелёной, а связки — без корня).
CA_FILE = ROOT / "deploy" / "ca" / "ru-trusted-root-ca.pem"
CA_IMAGE_DIR = "/usr/local/share/ca-certificates"
CA_IMAGE_FILE = f"{CA_IMAGE_DIR}/ru-trusted-root-ca.crt"
CA_SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

# Якорь доверия: SHA-256 DER-тела корня НУЦ «Russian Trusted Root CA»
# (subject CN=Russian Trusted Root CA, O=The Ministry of Digital Development and
#  Communications, C=RU; срок 2022-03-01…2032-02-27).
EXPECTED_CA_FINGERPRINT = "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31"

# Границы срока действия: корень меняют заранее (выдача нового — месяцы), сертификат брокера — тем более.
MIN_ROOT_DAYS_LEFT = 90
MIN_LEAF_DAYS_LEFT = 14

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)


class CaPolicyError(Exception):
    """Связка или файл корня не разбираются: молча считать их «без корня» нельзя."""


def normalize_fingerprint(fingerprint: str) -> str:
    """Отпечаток к каноническому виду: без префикса схемы, пробелов и двоеточий, в нижнем регистре."""
    return fingerprint.lower().strip().removeprefix("sha256:").replace(":", "").replace(" ", "")


def pem_ders(bundle: Path) -> list[bytes]:
    """DER-тела всех PEM-сертификатов связки. Битый base64 — ошибка, а не пустой список.

    Пропустить битый блок молча означало бы «корня нет там, где он есть»: так повреждённая
    связка выглядит как неподготовленная площадка, и приёмка принимает неверный вывод.
    """
    blocks: list[bytes] = []
    for block in PEM_BLOCK_RE.findall(bundle.read_bytes().decode("utf-8", errors="replace")):
        try:
            blocks.append(base64.b64decode("".join(block.split()), validate=True))
        except (binascii.Error, ValueError) as exc:
            raise CaPolicyError(
                f"в {bundle} не декодируется base64-блок сертификата: {exc}"
            ) from exc
    return blocks


def fingerprints(bundle: Path) -> list[str]:
    """SHA-256 отпечатки сертификатов PEM-связки (DER — как `openssl x509 -outform DER`)."""
    return [hashlib.sha256(der).hexdigest() for der in pem_ders(bundle)]


def contains_fingerprint(bundle: Path, fingerprint: str) -> bool:
    return normalize_fingerprint(fingerprint) in set(fingerprints(bundle))


def file_fingerprint(path: Path) -> str:
    """SHA-256 DER первого сертификата PEM-файла (для PEM-файла из одного сертификата — это и есть его отпечаток)."""
    ders = pem_ders(path)
    if not ders:
        raise CaPolicyError(f"{path} не разбирается как PEM-сертификат: нет блока CERTIFICATE")
    return hashlib.sha256(ders[0]).hexdigest()


def check_root(path: Path = CA_FILE) -> list[str]:
    """Нарушения политики для файла корня; пустой список — файл подходит под якорь.

    Проверка локальная и сетью не пользуется: она отвечает за то, что в образ
    (`deploy/Dockerfile` копирует `deploy/ca/` в `CA_IMAGE_DIR`) и на хост попадает ровно тот
    корень, чей отпечаток закреплён выше.
    """
    if not path.is_file():
        return [f"{path} отсутствует — порядок получения корня: docs/runbook/nucc-ca.md"]
    ders = pem_ders(path)
    if not ders:
        return [f"{path} не разбирается как PEM-сертификат: нет блока CERTIFICATE"]
    if len(ders) > 1:
        return [f"{path}: найдено {len(ders)} сертификатов, а нужен один корень"]
    fingerprint = hashlib.sha256(ders[0]).hexdigest()
    if fingerprint != normalize_fingerprint(EXPECTED_CA_FINGERPRINT):
        return [
            f"{path}: отпечаток {fingerprint} не совпадает с закреплённым "
            f"{EXPECTED_CA_FINGERPRINT} — в репозитории чужой корень "
            "(подмена или устаревший файл); запуск блокируется"
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="сверить корень НУЦ с закреплённой политикой (отпечаток и наличие в связке)"
    )
    parser.add_argument(
        "--file", type=Path, default=CA_FILE, help="PEM корня (по умолчанию — артефакт репозитория)"
    )
    parser.add_argument(
        "--verify-bundle",
        type=Path,
        help="дополнительно проверить, что этот корень входит в PEM-связку "
        "(например, /etc/ssl/certs/ca-certificates.crt)",
    )
    parser.add_argument(
        "--print-fingerprint",
        action="store_true",
        help="напечатать только отпечаток закреплённого корня (для передачи в другие шаги CI)",
    )
    arguments = parser.parse_args(argv)

    if arguments.print_fingerprint:
        problems = check_root(arguments.file)
        if problems:
            print("; ".join(problems), file=sys.stderr)
            return 1
        print(file_fingerprint(arguments.file))
        return 0

    problems = check_root(arguments.file)
    if not problems:
        fingerprint = file_fingerprint(arguments.file)
        print(
            f"{arguments.file}: отпечаток {fingerprint}, "
            f"sha256 файла {hashlib.sha256(arguments.file.read_bytes()).hexdigest()}"
        )
        if arguments.verify_bundle is not None:
            if contains_fingerprint(arguments.verify_bundle, fingerprint):
                print(f"OK: корень с этим отпечатком входит в {arguments.verify_bundle}")
            else:
                problems.append(f"корня с отпечатком {fingerprint} нет в {arguments.verify_bundle}")
    if problems:
        print("; ".join(problems))
        return 1
    print("OK: корень НУЦ соответствует закреплённой политике")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
