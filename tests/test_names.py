import ipaddress
import socket

import pytest
from cryptography import x509

from certificate_name_policy import Limits, evaluate_bytes


@pytest.mark.parametrize(
    ("presented", "reference", "status"),
    [
        ("www.example.test", "www.example.test", "PASS"),
        ("WWW.EXAMPLE.TEST", "www.example.test", "PASS"),
        ("www.example.test", "WWW.EXAMPLE.TEST", "PASS"),
        ("www.example.test.", "www.example.test", "PASS"),
        ("www.example.test", "www.example.test.", "PASS"),
        ("www.example.test", "xwww.example.test", "FAIL"),
        ("www.example.test", "www.example.test.evil.test", "FAIL"),
        ("www.example.test", "www-example.test", "FAIL"),
        ("*.example.test", "www.example.test", "PASS"),
        ("*.example.test", "a.b.example.test", "FAIL"),
        ("*.example.test", "example.test", "FAIL"),
        ("*.example.test", "www.other.test", "FAIL"),
        ("*.test", "service.test", "PASS"),
        ("*.example.test", "xn--bcher-kva.example.test", "PASS"),
        ("*.example.test", "bücher.example.test", "PASS"),
        ("*.xn--bcher-kva.test", "www.bücher.test", "PASS"),
        ("xn--bcher-kva.example.test", "bücher.example.test", "PASS"),
        ("xn--fa-hia.example.test", "faß.example.test", "PASS"),
        ("xn--fa-hia.example.test", "fass.example.test", "FAIL"),
        ("xn--bcher-kva.example.test", "other.example.test", "FAIL"),
    ],
)
def test_dns_and_idna(make_cert, presented, reference, status):
    result = evaluate_bytes(make_cert([x509.DNSName(presented)]), reference)
    assert result.status == status
    assert result.trust_status == "OPEN"
    assert result.name_status == ("NAME_MATCH" if status == "PASS" else "NAME_MISMATCH")


@pytest.mark.parametrize(
    "name",
    [
        "",
        "w*.example.test",
        "*w.example.test",
        "*.*.example.test",
        "www.*.test",
        "*example.test",
        "*",
        "*.",
        "*.example..test",
        "*.example.test..",
        " www.example.test",
        "www.example.test ",
        "www\x00.example.test",
        "www\n.example.test",
        "www_example.test",
        ".example.test",
        "www..example.test",
        "-www.example.test",
        "www-.example.test",
        "xn--.example.test",
        "localhost",
        "a" * 64 + ".example.test",
        "a." * 127 + "test",
        "www.example.test..",
    ],
)
def test_invalid_dns_sans_are_open_even_with_other_match(make_cert, name):
    cert = make_cert([x509.DNSName(name), x509.DNSName("www.example.test")])
    result = evaluate_bytes(cert, "www.example.test")
    assert result.status == "OPEN"
    assert result.name_status == "MALFORMED"
    assert not result.matched_san_indices


@pytest.mark.parametrize(
    "reference",
    [
        "",
        " example.test",
        "example.test ",
        "example\x00.test",
        "example\n.test",
        "*.example.test",
        "www..example.test",
        "example.test..",
        "localhost",
        "_srv.example.test",
        "https://example.test",
        "_xmpp.example.test",
        "192.0.2.01",
        "192.0.2.999",
        "2001:db8:::1",
        "[2001:db8::1]",
        "fe80::1%en0",
        "bücher\u3002example.test",
        "ＢＵＣＨＥＲ.example.test",
        "bu\u0308cher.example.test",
        "x" * 1025,
        "\ud800.example.test",
        "example.test:443",
        "foo/bar.example.test",
    ],
)
def test_invalid_or_unsupported_reference_is_open(make_cert, reference):
    result = evaluate_bytes(make_cert([x509.DNSName("example.test")]), reference)
    assert result.status == "OPEN"
    assert result.normalized_reference is None


@pytest.mark.parametrize(
    ("san", "reference", "status"),
    [
        ("192.0.2.1", "192.0.2.1", "PASS"),
        ("192.0.2.1", "192.0.2.2", "FAIL"),
        ("2001:db8::1", "2001:0db8:0:0:0:0:0:1", "PASS"),
        ("2001:db8::1", "2001:db8::2", "FAIL"),
        ("::ffff:192.0.2.1", "192.0.2.1", "FAIL"),
        ("192.0.2.1", "::ffff:192.0.2.1", "FAIL"),
    ],
)
def test_ip_octets_and_family(make_cert, san, reference, status):
    result = evaluate_bytes(make_cert([x509.IPAddress(ipaddress.ip_address(san))]), reference)
    assert result.status == status
    assert result.reference_kind == "ip"


def test_dns_literal_ip_cannot_substitute_for_ip_san(make_cert):
    cert = make_cert([x509.DNSName("192.0.2.1")])
    assert evaluate_bytes(cert, "192.0.2.1").status == "FAIL"
    assert evaluate_bytes(cert, "192.0.2.1", kind="dns").status == "OPEN"


def test_dns_and_ip_type_separation(make_cert):
    cert = make_cert([x509.IPAddress(ipaddress.ip_address("192.0.2.1"))])
    assert evaluate_bytes(cert, "example.test").status == "FAIL"
    assert evaluate_bytes(cert, "example.test", kind="ip").status == "OPEN"


@pytest.mark.parametrize("sans", [None, []])
def test_no_cn_fallback(make_cert, sans):
    result = evaluate_bytes(make_cert(sans, cn="expected.example.test"), "expected.example.test")
    assert result.status == "FAIL"
    assert result.name_status == "NAME_MISMATCH"


def test_duplicate_sans_and_multiple_names(make_cert):
    cert = make_cert(
        [
            x509.DNSName("other.example.test"),
            x509.DNSName("expected.example.test"),
            x509.DNSName("expected.example.test"),
        ]
    )
    result = evaluate_bytes(cert, "expected.example.test")
    assert result.status == "PASS"
    assert result.matched_san_indices == (1, 2)
    assert result.san_counts == {"DNSName": 3}


def test_trust_outside_scope_even_for_expired_self_signed(make_cert):
    result = evaluate_bytes(make_cert([x509.DNSName("example.test")], expired=True), "example.test")
    assert result.status == "PASS"
    assert result.trust_status == "OPEN"
    assert "time" in result.trust_reason


def test_name_policy_performs_no_network(make_cert, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network API called")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert (
        evaluate_bytes(make_cert([x509.DNSName("example.test")]), "example.test").status == "PASS"
    )


@pytest.mark.parametrize(
    "limits", [Limits(max_bytes=0), Limits(max_bytes=262145), Limits(max_san_entries=True), None]
)
def test_invalid_limit_contract(make_cert, limits):
    result = evaluate_bytes(
        make_cert([x509.DNSName("example.test")]), "example.test", limits=limits
    )
    assert result.status == "OPEN"
    assert result.reason == "invalid_limits"


def test_unsupported_reference_kind(make_cert):
    result = evaluate_bytes(make_cert([x509.DNSName("example.test")]), "example.test", kind="srv")
    assert result.status == "OPEN"


def test_long_valid_wildcard_name(make_cert):
    suffix = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 58])
    pattern = "*." + suffix
    assert len(pattern) == 252
    result = evaluate_bytes(make_cert([x509.DNSName(pattern)]), "z." + suffix)
    assert result.status == "PASS"
