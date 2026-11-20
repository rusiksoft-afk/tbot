#!/usr/bin/env python3
"""Проба доверия TLS: различает «цепочка не доверена» и «связи нет» (AC-broker-gateway-02).

Зачем нужен именно отдельный инструмент: отказ TLS бывает двух принципиально разных видов,
и перепутать их — значит либо запугать ложной тревогой, либо пропустить подмену сертификата.

* `unverified` — соединение установлено, но цепочка не проходит проверку штатным набором
  доверия (нет корневого сертификата НУЦ, подмена имени, отозванный сертификат). Это тот
  самый случай `docs/research/03 §3.3`: «Verify return code: 19».
* `unreachable` — нет ни DNS, ни TCP, или handshake оборвался до обмена сертификатами.
  Делать вывод о доверии по такому исходу нельзя.

Инструмент сознательно использует только стандартную библиотеку: его запускают внутри
любого образа Python 3.12 (в том числе базового, где зависимостей проекта нет). Проверка
сертификата не отключается ни при каком режиме — это требование `REQ-broker-gateway-02`.

Замеры по реальным адресам выполняет `make deploy-check` (`scripts/deploy_check.py`), здесь —
одиночная проба с явным ожиданием, удобная для CI и для ручного разбора на площадке.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path

from _bootstrap import ensure_repo_root_on_path

ensure_repo_root_on_path()

VERIFIED = "verified"
UNVERIFIED = "unverified"
UNREACHABLE = "unreachable"

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
    re.DOTALL,
)


@dataclass(frozen=True)
class Outcome:
    """Итог одной пробы. `verdict` — один из `verified` / `unverified` / `unreachable`."""

    verdict: str
    host: str
    port: int
    detail: str
    verify_code: int | None = None
    not_after: str | None = None
    anchors: int = 0


def probe(
    host: str,
    port: int,
    *,
    sni: str | None = None,
    extra_ca: Path | None = None,
    timeout: float = 10.0,
) -> Outcome:
    """TLS-рукопожатие со штатным набором доверия; при `extra_ca` — с дополнительным якорем.

    Дополнительный якорь нужен для проверки «с установленным сертификатом — может» на
    подставной цепочке: настоящий ключ корня НУЦ получить нельзя, поэтому механизм
    `update-ca-certificates` проверяется на собственной ЦС (CI, job `доверие TLS брокера`).
    """
    context = ssl.create_default_context()
    if extra_ca is not None:
        context.load_verify_locations(cafile=str(extra_ca))
    anchors = len(context.get_ca_certs())
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=sni or host) as tls,
        ):
            certificate = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return Outcome(
            UNVERIFIED,
            host,
            port,
            f"цепочка не доверена штатному набору: {exc.verify_message}",
            exc.verify_code,
            None,
            anchors,
        )
    except (ssl.SSLError, OSError) as exc:
        return Outcome(
            UNREACHABLE,
            host,
            port,
            f"соединение не установлено: {type(exc).__name__}: {exc}",
            None,
            None,
            anchors,
        )
    if not certificate:
        return Outcome(
            VERIFIED, host, port, "цепочка доверена, но сертификат не разобран", None, None, anchors
        )
    not_after = str(certificate.get("notAfter") or "") or None
    return Outcome(
        VERIFIED, host, port, "цепочка доверена штатному набору", None, not_after, anchors
    )


def bundle_fingerprints(bundle: Path) -> list[str]:
    """SHA-256 отпечатки сертификатов PEM-связки (DER как в `openssl x509 -outform DER`)."""
    fingerprints: list[str] = []
    for block in _PEM_BLOCK.findall(bundle.read_bytes()):
        try:
            der = base64.b64decode(b"".join(block.split()))
        except (binascii.Error, ValueError) as exc:
            msg = f"в связке {bundle} не декодируется base64-блок сертификата"
            raise ValueError(msg) from exc
        fingerprints.append(hashlib.sha256(der).hexdigest())
    return fingerprints


def find_fingerprint(bundle: Path, fingerprint: str) -> bool:
    return fingerprint.lower().removeprefix("sha256:") in bundle_fingerprints(bundle)


def _default_bundle() -> Path:
    """PEM-связка системного набора доверия (Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt).

    На Windows своего PEM-файла нет: набор доверия лежит в системном реестре, и `probe`
    подхватывает его через `ssl.create_default_context()`. Проверка отпечатка именно в
    PEM-связке — инструмент Linux-площадки и контейнеров, поэтому на dev-машине здесь
    возвращается честная ошибка, а не «всё в порядке».
    """
    cafile = ssl.get_default_verify_paths().cafile
    if cafile:
        return Path(cafile)
    msg = (
        "системный PEM-набор доверия не найден: cafile пуст (на Windows так и есть —"
        " там набор доверия в реестре; проверка отпечатка применима к Linux и контейнерам)"
    )
    raise ValueError(msg)


def check_anchor(fingerprint: str, bundle: Path | None) -> tuple[bool, str]:
    """Есть ли сертификат с таким отпечатком в системном наборе доверия."""
    try:
        target = bundle or _default_bundle()
    except ValueError as exc:
        return False, str(exc)
    known = bundle_fingerprints(target)
    if not known:
        return False, f"в {target} нет ни одного сертификата"
    if find_fingerprint(target, fingerprint):
        return (
            True,
            f"корень с отпечатком {fingerprint[:16]}… найден в {target} ({len(known)} сертификатов)",
        )
    return (
        False,
        f"корня с отпечатком {fingerprint[:16]}… в {target} нет ({len(known)} сертификатов)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="проба доверия TLS (AC-broker-gateway-02)")
    parser.add_argument("--host", help="адрес TLS-сервера")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", help="имя в handshake, если отличается от --host")
    parser.add_argument("--extra-ca", type=Path, help="дополнительный якорь (PEM) для пробы «с»")
    parser.add_argument(
        "--expect",
        choices=(VERIFIED, UNVERIFIED, UNREACHABLE, "reachable"),
        help="ожидаемый исход; reachable = verified или unverified (сеть есть, доверие отдельный вопрос)",
    )
    parser.add_argument(
        "--expect-anchor",
        help="требовать наличие отпечатка (sha256 hex) в системной связке доверия",
    )
    parser.add_argument("--bundle", type=Path, help="PEM-связка вместо системной")
    parser.add_argument("--json", action="store_true", help="машинный вывод")
    arguments = parser.parse_args(argv)

    if arguments.expect_anchor is None and arguments.host is None:
        parser.error("нужен либо --host, либо --expect-anchor")

    results: list[Outcome] = []
    anchor_note: tuple[bool, str] | None = None
    if arguments.host is not None:
        results.append(
            probe(arguments.host, arguments.port, sni=arguments.sni, extra_ca=arguments.extra_ca)
        )
    if arguments.expect_anchor is not None:
        anchor_note = check_anchor(arguments.expect_anchor, arguments.bundle)

    failure = 0
    for item in results:
        if (
            arguments.expect in (VERIFIED, UNVERIFIED, UNREACHABLE)
            and item.verdict != arguments.expect
        ):
            failure = 1
        if arguments.expect == "reachable" and item.verdict == UNREACHABLE:
            failure = 1
    if anchor_note is not None and not anchor_note[0]:
        failure = 1

    if arguments.json:
        print(
            json.dumps(
                {
                    "probes": [asdict(item) for item in results],
                    "anchor": (
                        {"ok": anchor_note[0], "detail": anchor_note[1]} if anchor_note else None
                    ),
                    "passed": failure == 0,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        for item in results:
            print(f"[{item.verdict:<11}] {item.host}:{item.port} — {item.detail}")
        if anchor_note is not None:
            print(f"[{'anchor-ok' if anchor_note[0] else 'anchor-miss'}] {anchor_note[1]}")
    return failure


if __name__ == "__main__":
    raise SystemExit(main())
