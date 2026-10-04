"""Frozen upstream is an oracle only on the explicitly shared support domain."""

import hashlib
import importlib.util
import ipaddress
import json
import sys
from pathlib import Path

import pytest
from cryptography import x509

from certificate_name_policy import evaluate_bytes

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "tests" / "oracle" / "service_identity"
spec = importlib.util.spec_from_file_location(
    "_cnp_frozen_service_identity", ORACLE / "__init__.py", submodule_search_locations=[str(ORACLE)]
)
upstream = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upstream
spec.loader.exec_module(upstream)


def upstream_dns(data, reference):
    try:
        upstream.cryptography.verify_certificate_hostname(
            x509.load_der_x509_certificate(data), reference
        )
    except (upstream.CertificateError, upstream.VerificationError):
        return False
    return True


@pytest.mark.parametrize(
    ("pattern", "reference", "expected"),
    [
        ("www.example.test", "www.example.test", True),
        ("WWW.EXAMPLE.TEST", "www.example.test", True),
        ("www.example.test", "WWW.EXAMPLE.TEST", True),
        ("www.example.test", "other.example.test", False),
        ("www.example.test", "www.example.test.evil.test", False),
        ("www.example.test", "prefixwww.example.test", False),
        ("www.example.test", "example.test", False),
        ("*.example.test", "www.example.test", True),
        ("*.example.test", "other.example.test", True),
        ("*.example.test", "a.b.example.test", False),
        ("*.example.test", "example.test", False),
        ("*.example.test", "www.other.test", False),
        ("*.example.test", "WWW.EXAMPLE.TEST", True),
        ("xn--bcher-kva.example.test", "bücher.example.test", True),
        ("xn--bcher-kva.example.test", "xn--bcher-kva.example.test", True),
        ("xn--fa-hia.example.test", "faß.example.test", True),
        ("xn--fa-hia.example.test", "fass.example.test", False),
        ("*.xn--bcher-kva.test", "www.bücher.test", True),
    ],
)
def test_shared_dns_domain(make_cert, pattern, reference, expected):
    cert = make_cert([x509.DNSName(pattern)])
    assert upstream_dns(cert, reference) is expected
    assert (evaluate_bytes(cert, reference).status == "PASS") is expected


@pytest.mark.parametrize(
    ("pattern", "reference", "expected"),
    [
        ("192.0.2.1", "192.0.2.1", True),
        ("192.0.2.1", "192.0.2.2", False),
        ("2001:db8::1", "2001:0db8:0:0:0:0:0:1", True),
        ("2001:db8::1", "2001:db8::2", False),
        ("::ffff:192.0.2.1", "192.0.2.1", False),
    ],
)
def test_shared_ip_domain(make_cert, pattern, reference, expected):
    cert = make_cert([x509.IPAddress(ipaddress.ip_address(pattern))])
    try:
        upstream.cryptography.verify_certificate_ip_address(
            x509.load_der_x509_certificate(cert), reference
        )
    except (upstream.CertificateError, upstream.VerificationError):
        original_matches = False
    else:
        original_matches = True
    assert original_matches is expected
    assert (evaluate_bytes(cert, reference).status == "PASS") is expected


@pytest.mark.parametrize(
    ("pattern", "reference"),
    [
        ("*.example.test", "bücher.example.test"),
        ("*.test", "service.test"),
    ],
)
def test_documented_rfc9525_differences(make_cert, pattern, reference):
    cert = make_cert([x509.DNSName(pattern)])
    assert upstream_dns(cert, reference) is False
    assert evaluate_bytes(cert, reference).status == "PASS"


def test_oracle_frozen_file_and_license_hashes():
    manifest = json.loads((ROOT / "项目文档/SOURCE_AUDIT.json").read_text())
    assert manifest["commit"] == "5d0a376d74042920edf3dd03942602b52cb100c8"
    assert manifest["runtime_source_files_reviewed"] == 5
    for source in manifest["files"]:
        file = ORACLE / Path(source["path"]).name
        assert hashlib.sha256(file.read_bytes()).hexdigest() == source["sha256"]
    license_bytes = (
        ROOT / "项目文档/THIRD_PARTY_LICENSES" / "service-identity-MIT.txt"
    ).read_bytes()
    assert hashlib.sha256(license_bytes).hexdigest() == manifest["license_sha256"]
