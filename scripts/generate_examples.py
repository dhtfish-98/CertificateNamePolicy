"""Create synthetic public fixtures; the ephemeral private key is never saved."""

from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def main():
    root = Path(__file__).resolve().parents[1]
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic example only")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(9525)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("www.example.test"),
                    x509.DNSName("*.service.example.test"),
                    x509.DNSName("xn--bcher-kva.example.test"),
                    x509.IPAddress(ip_address("192.0.2.1")),
                    x509.IPAddress(ip_address("2001:db8::1")),
                ]
            ),
            critical=False,
        )
        .sign(key, algorithm=None)
    )
    (root / "examples" / "synthetic.pem").write_bytes(certificate.public_bytes(Encoding.PEM))
    (root / "examples" / "synthetic.der").write_bytes(certificate.public_bytes(Encoding.DER))
    print("Created synthetic public PEM/DER fixtures; no private key serialized.")


if __name__ == "__main__":
    main()
