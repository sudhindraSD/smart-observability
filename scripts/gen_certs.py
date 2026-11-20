"""Generate a self-signed TLS certificate + RSA-2048 key for the local
collector <-> SaaS link.

Usage:
    python scripts/gen_certs.py [--cert-dir certs] [--lan-ip 192.168.1.20] [--days 825]

Writes ``<cert-dir>/cert.pem`` and ``<cert-dir>/key.pem``. The key is written
PKCS#8 unencrypted (the collector runs headless in the customer network);
best-effort ``chmod 0600`` is applied where the OS supports it.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

COMMON_NAME = "smart-observability-local"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a self-signed TLS cert/key pair."
    )
    parser.add_argument(
        "--cert-dir",
        default="certs",
        help="directory for cert.pem/key.pem (default: certs)",
    )
    parser.add_argument(
        "--lan-ip",
        default=None,
        help="optional LAN IP to add as an IP Subject Alternative Name",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=825,
        help="validity period in days (default: 825)",
    )
    return parser.parse_args(argv)


def generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_cert(key: rsa.RSAPrivateKey, lan_ip: str | None, days: int) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Smart Observability"),
            x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    san_entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    if lan_ip:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(lan_ip)))

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))  # clock skew slack
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.days <= 0:
        print("--days must be positive", file=sys.stderr)
        return 2
    if args.lan_ip:
        try:
            ipaddress.ip_address(args.lan_ip)
        except ValueError:
            print(f"--lan-ip is not a valid IP address: {args.lan_ip}", file=sys.stderr)
            return 2

    key = generate_key()
    cert = build_cert(key, args.lan_ip, args.days)

    os.makedirs(args.cert_dir, exist_ok=True)
    cert_path = os.path.join(args.cert_dir, "cert.pem")
    key_path = os.path.join(args.cert_dir, "key.pem")

    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as fh:
        fh.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # best effort (e.g. Windows/POSIX differences)

    print(f"Wrote {cert_path}")
    print(f"Wrote {key_path}")
    print(f"Subject CN: {COMMON_NAME} (self-signed, {args.days} days)")
    sans = ", ".join(
        [
            "DNS:localhost",
            "IP:127.0.0.1",
            "IP:::1",
            *( [f"IP:{args.lan_ip}"] if args.lan_ip else [] ),
        ]
    )
    print(f"SANs: {sans}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
