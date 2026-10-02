from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


@pytest.fixture
def make_cert():
    """Use an ephemeral key in memory, never serialize or retain private material."""
    key = ed25519.Ed25519PrivateKey.generate()

    def build(
        sans=None, *, cn="cn-only.example.test", encoding=Encoding.DER, extensions=(), expired=False
    ):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1001)
            .not_valid_before(datetime(2000, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime(2001 if expired else 2099, 1, 1, tzinfo=UTC))
        )
        if sans is not None:
            cert = cert.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        for extension in extensions:
            cert = cert.add_extension(extension, critical=False)
        return cert.sign(key, algorithm=None).public_bytes(encoding)

    return build
