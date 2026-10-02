"""Bounded local certificate parsing and independent RFC 9525 DNS/IP matching.

No network, chain building, signature checking, validity, or revocation checking.
Errors are observable OPEN results; raw certificate and untrusted errors are not echoed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from typing import Literal

import idna
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

ReferenceKind = Literal["auto", "dns", "ip"]
Status = Literal["PASS", "FAIL", "OPEN"]
_PEM = re.compile(
    rb"\A[ \t\r\n]*-----BEGIN CERTIFICATE-----\r?\n"
    rb"(?P<body>[A-Za-z0-9+/=\r\n]+)"
    rb"-----END CERTIFICATE-----[ \t\r\n]*\Z"
)


@dataclass(frozen=True)
class Limits:
    """Limits may be lowered by callers, but never raised above audited defaults."""

    max_bytes: int = 262144
    max_san_entries: int = 128
    max_dns_entries: int = 64
    max_ip_entries: int = 64
    max_other_entries: int = 32

    def valid(self) -> bool:
        ceilings = (262144, 128, 64, 64, 32)
        return all(
            type(value) is int and 1 <= value <= ceiling
            for value, ceiling in zip(asdict(self).values(), ceilings, strict=True)
        )


_DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class Report:
    """PASS/FAIL applies only to this DNS/IP name check; trust remains OPEN."""

    status: Status
    name_status: str
    reason: str
    reference_kind: str | None = None
    normalized_reference: str | None = None
    certificate_sha256: str | None = None
    san_counts: dict[str, int] = field(default_factory=dict)
    matched_san_indices: tuple[int, ...] = ()
    ignored_san_types: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    schema_version: str = "1.0"
    policy: str = "RFC9525-DNS-IP/local-v1"
    scope: str = "DNS/IP SAN name matching only"
    trust_status: str = "OPEN"
    trust_reason: str = "chain/signature/time/revocation/handshake not evaluated"

    def to_dict(self) -> dict:
        """Return a JSON-ready copy; includes no certificate contents or key material."""
        return asdict(self)


class _Rejected(ValueError):
    """Stable diagnostic code, never a raw parser error or untrusted string."""


def _check_text(text: str, max_chars: int) -> None:
    if (
        not isinstance(text, str)
        or not text
        or len(text) > max_chars
        or any(ord(c) < 33 or ord(c) == 127 for c in text)
    ):
        raise _Rejected("invalid_text")


def _ascii_fold(value: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in value)


def _dns(value: str, *, presented: bool = False, fully_qualified: bool = True) -> str:
    _check_text(value, 1024 if not presented else 254)
    if presented and not value.isascii():
        raise _Rejected("dns_san_not_ia5_ascii")
    # Explicit local policy: a single final ASCII root dot is normalized on both sides.
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or "*" in value:
        raise _Rejected("invalid_dns_name")
    try:
        normalized = (
            idna.encode(_ascii_fold(value), strict=True, uts46=False, std3_rules=True)
            .decode("ascii")
            .lower()
        )
    except (idna.IDNAError, UnicodeError) as exc:
        raise _Rejected("invalid_idna2008") from exc
    # The tool deliberately supports fully qualified names only.
    if len(normalized) > 253 or (fully_qualified and len(normalized.split(".")) < 2):
        raise _Rejected("dns_not_fully_qualified_or_too_long")
    return normalized


def _reference(value: str, kind: ReferenceKind) -> tuple[str, str, bytes | None]:
    if kind not in ("auto", "dns", "ip"):
        raise _Rejected("unsupported_reference_kind")
    _check_text(value, 1024)
    if "%" in value or "[" in value or "]" in value:
        raise _Rejected("scoped_or_bracketed_ip_not_supported")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if kind == "ip" or (kind == "auto" and address is not None):
        if address is None:
            raise _Rejected("invalid_ip_reference")
        return "ip", str(address), address.packed
    if address is not None:
        raise _Rejected("ip_literal_is_not_dns_reference")
    if ":" in value or "/" in value or (kind == "auto" and re.fullmatch(r"[0-9.]+", value)):
        raise _Rejected("ambiguous_or_unsupported_reference")
    return "dns", _dns(value), None


def _dns_pattern(value: str) -> str:
    _check_text(value, 254)
    if "*" not in value:
        return _dns(value, presented=True)
    if value.count("*") != 1 or not value.startswith("*."):
        raise _Rejected("invalid_wildcard_ignored")
    # RFC 9525 permits *.example; upstream's minimum-three-label rule is not copied.
    suffix = _dns(value[2:], presented=True, fully_qualified=False)
    pattern = "*." + suffix
    if len(pattern) > 253:
        raise _Rejected("dns_pattern_too_long")
    return pattern


def _dns_matches(pattern: str, reference: str) -> bool:
    if pattern.startswith("*."):
        parts = reference.split(".")
        return len(parts) >= 2 and ".".join(parts[1:]) == pattern[2:]
    return pattern == reference


def _decode_certificate(data: bytes, limits: Limits) -> tuple[x509.Certificate, bytes]:
    if not isinstance(data, bytes) or not data or len(data) > limits.max_bytes:
        raise _Rejected("input_empty_wrong_type_or_too_large")
    if data.lstrip().startswith(b"-----"):
        match = _PEM.fullmatch(data)
        if not match:
            raise _Rejected("pem_requires_exactly_one_certificate_no_other_blocks")
        try:
            der = base64.b64decode(re.sub(rb"[\r\n]", b"", match["body"]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise _Rejected("invalid_pem_base64") from exc
    else:
        der = data
    try:
        certificate = x509.load_der_x509_certificate(der)
        # Require the decoder's reserialized certificate to cover the whole input.
        # DER structural validation is delegated to cryptography, not reimplemented.
        if certificate.public_bytes(Encoding.DER) != der:
            raise _Rejected("der_not_exact_single_certificate")
        # Access all extensions once so duplicate/malformed extensions cannot be skipped.
        _ = certificate.extensions
        return certificate, der
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
        raise _Rejected("malformed_certificate_or_extensions") from exc


def _other_san_bounded(name: x509.GeneralName) -> None:
    if isinstance(name, (x509.UniformResourceIdentifier, x509.RFC822Name)):
        _check_text(name.value, 2048)
        if not name.value.isascii():
            raise _Rejected("unsupported_san_invalid_ia5")
    elif isinstance(name, x509.OtherName):
        if len(name.value) > 4096 or len(name.type_id.dotted_string) > 128:
            raise _Rejected("other_name_too_large")
    elif isinstance(name, x509.DirectoryName):
        if len(name.value) > 128:
            raise _Rejected("directory_name_too_large")
        for attribute in name.value:
            if not isinstance(attribute.value, str):
                raise _Rejected("directory_name_unsupported_attribute")
            if len(attribute.value) > 1024 or any(
                ord(c) < 32 or ord(c) == 127 for c in attribute.value
            ):
                raise _Rejected("directory_name_invalid_text")
    elif isinstance(name, x509.RegisteredID):
        _check_text(name.value.dotted_string, 128)
    else:
        raise _Rejected("unknown_san_type")


def _evaluate(
    certificate: x509.Certificate, der: bytes, reference: str, kind: ReferenceKind, limits: Limits
) -> Report:
    ref_kind, normalized, ref_octets = _reference(reference, kind)
    common = {
        "reference_kind": ref_kind,
        "normalized_reference": normalized,
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
    }
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return Report("FAIL", "NAME_MISMATCH", "no_san_no_cn_fallback", **common)
    if len(san) > limits.max_san_entries:
        raise _Rejected("san_entry_limit")
    counts: dict[str, int] = {}
    ignored: set[str] = set()
    diagnostics: list[str] = []
    matches: list[int] = []
    dns_count = ip_count = other_count = 0
    for index, name in enumerate(san):
        label = type(name).__name__
        counts[label] = counts.get(label, 0) + 1
        try:
            if isinstance(name, x509.DNSName):
                dns_count += 1
                if dns_count > limits.max_dns_entries:
                    raise _Rejected("dns_san_entry_limit")
                pattern = _dns_pattern(name.value)
                if ref_kind == "dns" and _dns_matches(pattern, normalized):
                    matches.append(index)
            elif isinstance(name, x509.IPAddress):
                ip_count += 1
                if ip_count > limits.max_ip_entries:
                    raise _Rejected("ip_san_entry_limit")
                if not isinstance(name.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    raise _Rejected("ip_san_network_is_not_address")
                if ref_kind == "ip" and name.value.packed == ref_octets:
                    matches.append(index)
            else:
                other_count += 1
                if other_count > limits.max_other_entries:
                    raise _Rejected("other_san_entry_limit")
                _other_san_bounded(name)
                ignored.add(label)
        except _Rejected as exc:
            # Invalid entries never match. Conservative outcome remains OPEN even if
            # another entry matches; this is stricter than RFC 9525's ignore-and-continue.
            diagnostics.append(f"san[{index}]:{exc}")
    common.update(
        san_counts=counts, ignored_san_types=tuple(sorted(ignored)), diagnostics=tuple(diagnostics)
    )
    if diagnostics:
        return Report("OPEN", "MALFORMED", "invalid_san_entries_ignored", **common)
    if matches:
        return Report(
            "PASS",
            "NAME_MATCH",
            "supported_san_matches",
            matched_san_indices=tuple(matches),
            **common,
        )
    if not dns_count and not ip_count and other_count:
        return Report("OPEN", "UNSUPPORTED", "only_unsupported_san_types", **common)
    return Report("FAIL", "NAME_MISMATCH", "no_supported_san_matches", **common)


def evaluate_bytes(
    data: bytes, reference: str, *, kind: ReferenceKind = "auto", limits: Limits = _DEFAULT_LIMITS
) -> Report:
    """Evaluate exactly one local PEM/DER certificate; never raises input errors.

    kind='auto' selects IP before DNS. URI/SRV references are unsupported. Only
    DNSName and IPAddress SANs can match. See README for stricter policy choices.
    """
    try:
        if not isinstance(limits, Limits) or not limits.valid():
            raise _Rejected("invalid_limits")
        certificate, der = _decode_certificate(data, limits)
        return _evaluate(certificate, der, reference, kind, limits)
    except _Rejected as exc:
        return Report("OPEN", "MALFORMED", str(exc))
    except Exception:
        # Unexpected dependency exceptions cannot become success and reveal no input.
        return Report("OPEN", "MALFORMED", "unexpected_parser_or_policy_error")


def _read_regular_file(path: os.PathLike[str] | str, max_bytes: int) -> bytes:
    """Open from root using no-follow directory descriptors, including parents.

    No O_CREAT, no output writes; O_NONBLOCK avoids blocking on FIFO/device input
    before fstat establishes that the opened descriptor is a regular file.
    """
    if not all(hasattr(os, option) for option in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
        raise _Rejected("safe_file_open_unsupported_platform")
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096 or "\0" in raw_path:
        raise _Rejected("invalid_file_path")
    if ".." in raw_path.split(os.sep):
        raise _Rejected("parent_traversal_not_allowed")
    parts = os.path.abspath(raw_path).split(os.sep)[1:]
    if not parts or not parts[-1]:
        raise _Rejected("not_regular_file")
    dir_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
            )
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise _Rejected("not_regular_file")
            if before.st_size > max_bytes:
                raise _Rejected("input_too_large")
            chunks: list[bytes] = []
            size = 0
            while size <= max_bytes:
                chunk = os.read(file_fd, min(65536, max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            if size > max_bytes:
                raise _Rejected("input_too_large")
            after = os.fstat(file_fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise _Rejected("input_changed_while_reading")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)


def evaluate_file(
    path: os.PathLike[str] | str,
    reference: str,
    *,
    kind: ReferenceKind = "auto",
    limits: Limits = _DEFAULT_LIMITS,
) -> Report:
    """Read one bounded regular file; all symlink path components are rejected."""
    try:
        if not isinstance(limits, Limits) or not limits.valid():
            raise _Rejected("invalid_limits")
        data = _read_regular_file(path, limits.max_bytes)
    except _Rejected as exc:
        return Report("OPEN", "MALFORMED", str(exc))
    except (OSError, ValueError, TypeError):
        return Report("OPEN", "MALFORMED", "file_open_failed_or_symlink")
    return evaluate_bytes(data, reference, kind=kind, limits=limits)
