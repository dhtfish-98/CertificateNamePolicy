import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certificate_name_policy import Limits, evaluate_bytes


@pytest.mark.parametrize("encoding", [Encoding.PEM, Encoding.DER])
def test_real_certificate_formats(make_cert, encoding):
    result = evaluate_bytes(
        make_cert([x509.DNSName("example.test")], encoding=encoding), "example.test"
    )
    assert result.status == "PASS"
    assert len(result.certificate_sha256) == 64


@pytest.mark.parametrize(
    "data",
    [
        b"",
        "not bytes",
        b"not a certificate",
        b"\x30\x82\xff\xff",
        b"-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n",
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        b"-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n",
        b"x" * 262145,
    ],
)
def test_bad_input_is_open(data):
    result = evaluate_bytes(data, "example.test")
    assert result.status == "OPEN"
    assert result.certificate_sha256 is None


def test_single_certificate_no_bundle_or_trailing_data(make_cert):
    der = make_cert([x509.DNSName("example.test")])
    pem = make_cert([x509.DNSName("example.test")], encoding=Encoding.PEM)
    for content in (der + der, der + b"garbage", pem + pem, pem + b"garbage", b"comment\n" + pem):
        assert evaluate_bytes(content, "example.test").status == "OPEN"


def test_pem_whitespace_and_fingerprint_identity(make_cert):
    pem = make_cert([x509.DNSName("example.test")], encoding=Encoding.PEM)
    der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    a = evaluate_bytes(b" \r\n" + pem + b"\t\n", "example.test")
    b = evaluate_bytes(der, "example.test")
    assert a.status == b.status == "PASS"
    assert a.certificate_sha256 == b.certificate_sha256


def test_malicious_ia5_encoding(make_cert):
    der = make_cert([x509.DNSName("unique.example.test")])
    assert der.count(b"unique.example.test") == 1
    malformed = der.replace(b"unique.example.test", b"\xffnique.example.test")
    assert evaluate_bytes(malformed, "unique.example.test").status == "OPEN"


def test_invalid_ip_san_length(make_cert):
    malformed = x509.UnrecognizedExtension(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, b"\x30\x05\x87\x03\x01\x02\x03"
    )
    assert evaluate_bytes(make_cert(extensions=[malformed]), "192.0.2.1").status == "OPEN"


def test_unknown_general_name_tag(make_cert):
    malformed = x509.UnrecognizedExtension(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, b"\x30\x03\x89\x01\x00"
    )
    assert evaluate_bytes(make_cert(extensions=[malformed]), "example.test").status == "OPEN"


def test_duplicate_extension_rejected(make_cert):
    cert = make_cert(
        [x509.DNSName("example.test")],
        extensions=[x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])],
    )
    malformed = cert.replace(b"\x06\x03\x55\x1d\x25", b"\x06\x03\x55\x1d\x11")
    assert malformed != cert
    assert evaluate_bytes(malformed, "example.test").status == "OPEN"


@pytest.mark.parametrize(
    "other",
    [
        x509.UniformResourceIdentifier("https://example.test"),
        x509.RFC822Name("audit@example.test"),
        x509.OtherName(x509.ObjectIdentifier("1.3.6.1.5.5.7.8.7"), b"\x16\x12_xmpp.example.test"),
        x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4")),
        x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic service")])
        ),
    ],
)
def test_unsupported_types_explicitly_reported(make_cert, other):
    alone = evaluate_bytes(make_cert([other]), "example.test")
    mixed = evaluate_bytes(make_cert([other, x509.DNSName("example.test")]), "example.test")
    assert alone.status == "OPEN"
    assert alone.name_status == "UNSUPPORTED"
    assert mixed.status == "PASS"
    assert type(other).__name__ in mixed.ignored_san_types
    assert mixed.scope == "DNS/IP SAN name matching only"


@pytest.mark.parametrize(
    "other",
    [
        x509.UniformResourceIdentifier("https://exam\x00ple.test"),
        x509.RFC822Name("audit\x00@example.test"),
        x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"\x04\x82\x10\x01" + b"a" * 4097),
        x509.UniformResourceIdentifier("https://" + "x" * 2049),
    ],
)
def test_unsupported_san_payloads_still_bounded(make_cert, other):
    assert evaluate_bytes(make_cert([other]), "example.test").status == "OPEN"


@pytest.mark.parametrize(("count", "expected"), [(64, "PASS"), (65, "OPEN")])
def test_dns_entry_limit(make_cert, count, expected):
    cert = make_cert([x509.DNSName("example.test")] * count)
    assert evaluate_bytes(cert, "example.test").status == expected


@pytest.mark.parametrize(("count", "expected"), [(64, "PASS"), (65, "OPEN")])
def test_ip_entry_limit(make_cert, count, expected):
    cert = make_cert([x509.IPAddress(ipaddress.ip_address("192.0.2.1"))] * count)
    assert evaluate_bytes(cert, "192.0.2.1").status == expected


@pytest.mark.parametrize(("count", "expected"), [(32, "OPEN"), (33, "OPEN")])
def test_other_entry_limit_reason(make_cert, count, expected):
    cert = make_cert([x509.UniformResourceIdentifier("https://example.test")] * count)
    result = evaluate_bytes(cert, "example.test")
    assert result.status == expected
    assert result.name_status == ("UNSUPPORTED" if count == 32 else "MALFORMED")


def test_total_entry_boundary(make_cert):
    names = [x509.DNSName("example.test")] * 64 + [
        x509.IPAddress(ipaddress.ip_address("192.0.2.1"))
    ] * 64
    assert evaluate_bytes(make_cert(names), "example.test").status == "PASS"
    result = evaluate_bytes(
        make_cert(names + [x509.RFC822Name("audit@example.test")]), "example.test"
    )
    assert result.status == "OPEN"
    assert result.reason == "san_entry_limit"


def test_lower_byte_limit_is_enforced(make_cert):
    cert = make_cert([x509.DNSName("example.test")])
    assert evaluate_bytes(cert, "example.test", limits=Limits(max_bytes=10)).status == "OPEN"


def test_exact_byte_limit_boundary(make_cert):
    cert = make_cert([x509.DNSName("example.test")])
    exact = evaluate_bytes(cert, "example.test", limits=Limits(max_bytes=len(cert)))
    short = evaluate_bytes(cert, "example.test", limits=Limits(max_bytes=len(cert) - 1))
    assert exact.status == "PASS"
    assert short.status == "OPEN"


def test_corrupted_signature_does_not_claim_trust(make_cert):
    cert = make_cert([x509.DNSName("example.test")])
    changed = cert[:-1] + bytes([cert[-1] ^ 1])
    result = evaluate_bytes(changed, "example.test")
    assert result.status == "PASS"
    assert result.trust_status == "OPEN"
    assert "signature" in result.trust_reason


def test_unexpected_decoder_errors_never_pass(make_cert, monkeypatch):
    cert = make_cert([x509.DNSName("example.test")])

    def failing_decoder(data):
        raise RuntimeError("untrusted contents must not appear")

    monkeypatch.setattr(x509, "load_der_x509_certificate", failing_decoder)
    result = evaluate_bytes(cert, "example.test")
    assert result.status == "OPEN"
    assert "untrusted" not in str(result.to_dict())
