"""Доверие TLS брокера (T-006, `REQ-broker-gateway-02`, `AC-broker-gateway-02`) — офлайн-тесты.

Сети и боевого ключа здесь нет. Проверяются три вещи, которые «на глаз» не видны:

1. артефакт в репозитории — ровно тот корень НУЦ, чей отпечаток закреплён в `scripts/ca_policy.py`
   (отсутствие файла, подмена с тем же CN, истёкший срок, «до замены осталось мало»;
   `check_root` в `ca_policy.py` и `check_ca_bundle` в `deploy_check.py` проверяют одно и то же
   значение из одного места);
2. адрес брокера выбирается по контуру, а срок действия сертификата брокера участвует в вердиктe;
3. проба `scripts/tls_trust_probe.py` различает «цепочка не доверена» и «связи нет» — на
   подставном TLS-сервере с собственной самоподписанной цепочкой (тот же приём, что в CI).
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from packages.common.config import Settings
from tests.paths import CA_FILE, ROOT, load_script

deploy_check = load_script("deploy_check")
probe_tool = load_script("tls_trust_probe")
ca_policy = load_script("ca_policy")


def _self_signed_ca(
    *, days: int = 3650, start_days_ago: int = 1, common_name: str = "Russian Trusted Root CA"
) -> bytes:
    """PEM самоподписанного сертификата — «похожий на правду» корень с другим ключом."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.now(UTC) - timedelta(days=start_days_ago)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days))
    ).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def server_chain(tmp_path: Path) -> tuple[Path, Path]:
    """Самоподписанный сертификат на `localhost` + ключ: цепочка подставного TLS-сервера."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "server.pem"
    key_file = tmp_path / "server.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@pytest.fixture
def tls_server(server_chain: tuple[Path, Path]) -> Iterator[tuple[int, Path]]:
    """Подставной TLS-сервер в loopback: возвращает порт и файл цепочки."""
    cert_file, key_file = server_chain
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(connection, server_side=True) as tls_socket:
                    tls_socket.settimeout(2.0)
                    with contextlib.suppress(OSError):
                        tls_socket.recv(64)  # клиент вправе оборвать handshake — это ожидаемо
            except (ssl.SSLError, OSError):
                pass  # клиент не принял сертификат: рукопожатие оборвано на проверке
            finally:
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, cert_file
    finally:
        listener.close()
        thread.join(timeout=3)


# --- 1. артефакт: корень, лежащий в репозитории ---------------------------------------------


def test_закреплённый_отпечаток_совпадает_с_файлом_в_репозитории() -> None:
    certificate = x509.load_pem_x509_certificate(CA_FILE.read_bytes())
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    assert (
        fingerprint == deploy_check.EXPECTED_CA_FINGERPRINT
    ), "отпечаток deploy/ca/ru-trusted-root-ca.pem и значение в scripts/ca_policy.py разошлись"
    assert certificate.subject == certificate.issuer, "корень обязан быть самоподписанным"
    assert "Russian Trusted Root CA" in certificate.subject.rfc4514_string()
    assert certificate.not_valid_after_utc > datetime.now(UTC)


def test_проверка_корня_в_репозитории_проходит() -> None:
    result = deploy_check.check_ca_bundle()
    assert result.ok, result.detail
    assert "отпечаток совпадает" in result.detail


def test_отсутствующий_корень_блокирует_запуск(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deploy_check, "CA_FILE", ROOT / "deploy" / "ca" / "нет-такого-файла.pem")
    result = deploy_check.check_ca_bundle()
    assert not result.ok
    assert result.severity == deploy_check.FATAL
    assert "docs/runbook/nucc-ca.md" in result.detail


def _pin_fingerprint_of(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Закрепить отпечаток подставного файла, чтобы проверка дошла до разбора срока.

    Иначе подменный сертификат спотыкается о сверку отпечатка — что само по себе правильно
    (чужой корень не должен доходить до дат), но тогда тест проверял бы не срок действия.
    """
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    monkeypatch.setattr(deploy_check, "EXPECTED_CA_FINGERPRINT", fingerprint)


def test_подмена_корня_ловится_по_отпечатку(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Тот же CN, но другой ключ — именно это ловит сравнение с закреплённым отпечатком."""
    forged = tmp_path / "ru-trusted-root-ca.pem"
    forged.write_bytes(_self_signed_ca())
    monkeypatch.setattr(deploy_check, "CA_FILE", forged)
    result = deploy_check.check_ca_bundle()
    assert not result.ok
    assert "подмена" in result.detail
    assert result.severity == deploy_check.FATAL


def test_истёкший_корень_не_проходит(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    expired = tmp_path / "expired.pem"
    expired.write_bytes(_self_signed_ca(days=1, start_days_ago=400))
    _pin_fingerprint_of(monkeypatch, expired)
    monkeypatch.setattr(deploy_check, "CA_FILE", expired)
    result = deploy_check.check_ca_bundle()
    assert not result.ok
    assert "истёк" in result.detail


def test_до_конца_срока_корня_осталось_мало(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    soon = tmp_path / "soon.pem"
    soon.write_bytes(_self_signed_ca(days=10))
    _pin_fingerprint_of(monkeypatch, soon)
    monkeypatch.setattr(deploy_check, "CA_FILE", soon)
    result = deploy_check.check_ca_bundle()
    assert not result.ok
    assert "замена заранее" in result.detail


def test_чужой_файл_не_разбирается_как_корень(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = tmp_path / "ru-trusted-root-ca.pem"
    broken.write_text("это не сертификат\n", encoding="utf-8")
    monkeypatch.setattr(deploy_check, "CA_FILE", broken)
    result = deploy_check.check_ca_bundle()
    assert not result.ok
    assert "не разбирается" in result.detail


def test_разбор_pem_связки_находит_закреплённый_отпечаток() -> None:
    """CI проверяет связку контейнера этим же кодом: он не должен «слепнуть» на PEM-файле."""
    fingerprint = str(deploy_check.EXPECTED_CA_FINGERPRINT)
    assert probe_tool.find_fingerprint(CA_FILE, fingerprint)
    assert not probe_tool.find_fingerprint(CA_FILE, "0" * 64)


# --- 1b. политика корня: единственный источник закреплённого значения -----------------------


def test_политика_и_проверка_площадки_сверяют_одно_значение() -> None:
    """Расхождение между `ca_policy` и `deploy-check` означает, что один из них врёт."""
    assert deploy_check.EXPECTED_CA_FINGERPRINT == ca_policy.EXPECTED_CA_FINGERPRINT
    assert deploy_check.CA_FILE == ca_policy.CA_FILE
    assert ca_policy.check_root(CA_FILE) == []


def test_политика_ловит_подмену_по_отпечатку(tmp_path: Path) -> None:
    forged = tmp_path / "root.pem"
    forged.write_bytes(_self_signed_ca())
    problems = ca_policy.check_root(forged)
    assert len(problems) == 1
    assert "не совпадает с закреплённым" in problems[0]


def test_политика_сообщает_об_отсутствующем_файле(tmp_path: Path) -> None:
    problems = ca_policy.check_root(tmp_path / "нет-такого.pem")
    assert len(problems) == 1
    assert "docs/runbook/nucc-ca.md" in problems[0]


def test_политика_требует_один_сертификат_в_файле(tmp_path: Path) -> None:
    """Связка из двух корней вместо одного — не «первый подошёл», а ошибка приёмки."""
    doubled = tmp_path / "two.pem"
    doubled.write_bytes(CA_FILE.read_bytes() + CA_FILE.read_bytes())
    problems = ca_policy.check_root(doubled)
    assert len(problems) == 1
    assert "нужен один корень" in problems[0]


def test_политика_падает_на_битом_base64_а_не_считает_файл_пустым(tmp_path: Path) -> None:
    broken = tmp_path / "broken.pem"
    broken.write_text(
        "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n", encoding="utf-8"
    )
    with pytest.raises(ca_policy.CaPolicyError, match="не декодируется base64"):
        ca_policy.check_root(broken)


def test_наличие_корня_в_связке_доверия_проверяется_по_отпечатку(tmp_path: Path) -> None:
    """Так CI проверяет, что `update-ca-certificates` в образе действительно пересобрал связку."""
    fingerprint = ca_policy.EXPECTED_CA_FINGERPRINT
    forged = _self_signed_ca()
    without = tmp_path / "without.pem"
    without.write_bytes(forged)
    assert not ca_policy.contains_fingerprint(without, fingerprint)
    with_root = tmp_path / "with.pem"
    with_root.write_bytes(forged + CA_FILE.read_bytes())
    assert ca_policy.contains_fingerprint(with_root, f"SHA256:{fingerprint.upper()}")


def test_отпечаток_принимается_в_любой_записи() -> None:
    canonical = ca_policy.EXPECTED_CA_FINGERPRINT
    for variant in (canonical.upper(), f"sha256:{canonical}", canonical.replace("", " ")):
        assert ca_policy.normalize_fingerprint(variant) == canonical


def test_битый_base64_блок_в_связке_не_принимается_за_отсутствие_корня(tmp_path: Path) -> None:
    """Разрыв связи в списке якорей обязан быть слышен, а не выглядеть как «корня нет»."""
    broken = tmp_path / "bundle.pem"
    broken.write_text(
        "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="не декодируется base64"):
        probe_tool.bundle_fingerprints(broken)


# --- 2. контур и срок действия сертификата брокера ------------------------------------------


def test_адрес_брокера_выбирается_по_контуру() -> None:
    sandbox = Settings.model_validate({"contour": "sandbox"})
    production = Settings.model_validate({"contour": "production", "confirm_production": True})
    assert deploy_check.broker_endpoints(sandbox)[0][0] == sandbox.broker.sandbox_host
    assert deploy_check.broker_endpoints(production)[0][0] == production.broker.production_host
    without_config = {host for host, _, _ in deploy_check.broker_endpoints(None)}
    assert without_config == {host for host, _ in deploy_check.BROKER_TLS_TARGETS}


def test_отказ_вторичного_адреса_не_блокирует_песочицу(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate({"contour": "sandbox"})
    sandbox_host = settings.broker.sandbox_host

    def fake(host: str, _port: int) -> tuple[bool, str, None]:
        if host == sandbox_host:
            return False, "цепочка не доверена (20): unable to get local issuer certificate", None
        return True, "цепочка доверена", None

    monkeypatch.setattr(deploy_check, "_verify_chain", fake)
    result = deploy_check.check_broker_tls(settings)
    assert not result.ok
    assert result.severity == deploy_check.WARN


def test_отказ_первичного_адреса_блокирует_боевой_контур(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = Settings.model_validate({"contour": "production", "confirm_production": True})
    production_host = production.broker.production_host

    def fake(host: str, _port: int) -> tuple[bool, str, None]:
        if host == production_host:
            return False, "цепочка не доверена (19): self signed certificate in chain", None
        return True, "цепочка доверена", None

    monkeypatch.setattr(deploy_check, "_verify_chain", fake)
    result = deploy_check.check_broker_tls(production)
    assert not result.ok
    assert result.severity == deploy_check.FATAL


def test_почти_истёкший_сертификат_брокера_не_годится(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.model_validate({"contour": "sandbox"})
    almost_expired = datetime.now(UTC) + timedelta(days=3)
    monkeypatch.setattr(
        deploy_check,
        "_verify_chain",
        lambda _host, _port: (True, "цепочка доверена", almost_expired),
    )
    result = deploy_check.check_broker_tls(settings)
    assert not result.ok
    assert "почти истёк" in result.detail
    assert "сертификат до 202" in result.detail  # дата окончания видна в выводе


def test_срок_действия_из_разобранного_сертификата_читается() -> None:
    not_after = deploy_check.cert_not_after({"notAfter": "Aug 24 11:38:26 2027 GMT"})
    assert not_after is not None
    assert not_after.year == 2027
    assert not_after.month == 8
    assert deploy_check.cert_not_after({}) is None
    assert deploy_check.cert_not_after({"notAfter": "не дата"}) is None


# --- 3. проба: «не доверено» и «нет связи» — принципиально разные исходы --------------------


def test_проба_без_установленного_корня_это_unverified(tls_server: tuple[int, Path]) -> None:
    port, _ = tls_server
    outcome = probe_tool.probe("127.0.0.1", port, sni="localhost")
    assert outcome.verdict == probe_tool.UNVERIFIED
    assert outcome.verify_code not in (None, 0)
    assert "не доверена" in outcome.detail


def test_проба_с_дополнительным_якорем_проходит(tls_server: tuple[int, Path]) -> None:
    port, cert_file = tls_server
    outcome = probe_tool.probe("127.0.0.1", port, sni="localhost", extra_ca=cert_file)
    assert outcome.verdict == probe_tool.VERIFIED, outcome.detail
    assert outcome.not_after is not None


def test_проба_без_соединения_не_выводит_вердикт_о_доверии() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sampler:
        sampler.bind(("127.0.0.1", 0))
        free_port = sampler.getsockname()[1]
    outcome = probe_tool.probe("127.0.0.1", free_port, timeout=2.0)
    assert outcome.verdict == probe_tool.UNREACHABLE
    assert outcome.verify_code is None


def test_код_возврата_следует_за_ожиданием(tls_server: tuple[int, Path]) -> None:
    port, cert_file = tls_server
    base = ["--host", "127.0.0.1", "--port", str(port), "--sni", "localhost"]
    assert probe_tool.main([*base, "--expect", probe_tool.UNVERIFIED]) == 0
    assert probe_tool.main([*base, "--expect", probe_tool.VERIFIED]) == 1
    assert probe_tool.main([*base, "--extra-ca", str(cert_file), "--expect", "verified"]) == 0
    assert probe_tool.main([*base, "--expect", "reachable"]) == 0


def test_проверка_наличия_корня_в_pem_связке(tmp_path: Path) -> None:
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_bytes(CA_FILE.read_bytes() + _self_signed_ca(common_name="Прочий корень"))
    ok, detail = probe_tool.check_anchor(str(deploy_check.EXPECTED_CA_FINGERPRINT), bundle)
    assert ok, detail
    missing, _ = probe_tool.check_anchor("1" * 64, bundle)
    assert not missing
