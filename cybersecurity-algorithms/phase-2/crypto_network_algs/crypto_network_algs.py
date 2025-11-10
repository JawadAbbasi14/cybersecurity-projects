"""
crypto_network_algs.py

Single-file practical examples for:
- HMAC (pycryptodome + stdlib fallback)
- DSA / ECDSA (cryptography)
- X.509 self-signed cert (cryptography)
- Diffie-Hellman / X25519 key exchange (cryptography)
- Packet crafting & sniffing with Scapy

Dependencies (install before running):
  pip install cryptography pycryptodome scapy

Run: python3 crypto_network_algs.py

Note: Scapy parts may require root privileges to send/receive raw packets.
"""

from __future__ import annotations
import os
import sys
import hmac as _hmac_std
import hashlib
from typing import Tuple
from datetime import datetime, timedelta

# =======================================================================
# == 1. HMAC (Hash-based Message Authentication Code)
# =======================================================================
try:
    from Crypto.Hash import HMAC as PyCrypto_HMAC
    from Crypto.Hash import SHA256 as PyCrypto_SHA256
    _HAS_PYCRYPTO = True
except Exception:
    _HAS_PYCRYPTO = False

def hmac_compute(message: bytes, key: bytes) -> Tuple[str, str]:
    """Return (hex_using_pycryptodome_or_na, hex_using_stdlib)

    - Uses pycryptodome HMAC if available (recommended by user list)
    - Always computes with stdlib hmac as a fallback/verification.
    """
    # stdlib
    mac_std = _hmac_std.new(key, message, hashlib.sha256).hexdigest()

    # pycryptodome (if present)
    if _HAS_PYCRYPTO:
        h = PyCrypto_HMAC.new(key=key, msg=message, digestmod=PyCrypto_SHA256)
        mac_pc = h.hexdigest()
    else:
        mac_pc = "pycryptodome-not-installed"

    return mac_pc, mac_std

# =======================================================================
# == 2. DSA / ECDSA (Digital Signature Algorithm)
# =======================================================================
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature, decode_dss_signature,
    )
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False

def dsa_sign_verify_demo(message: bytes) -> bool:
    """Generate DSA key, sign and verify. Returns verification result."""
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library required for DSA/ECDSA examples")

    # DSA
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    signature = private_key.sign(message, hashes.SHA256())
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except Exception:
        return False

def ecdsa_sign_verify_demo(message: bytes) -> bool:
    """Generate ECDSA (SECP256R1) key, sign and verify."""
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library required for DSA/ECDSA examples")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# =======================================================================
# == 3. X.509 Certificate (Self-Signed)
# =======================================================================

# Imports used only by this section (from cryptography)
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except Exception:
    if _HAS_CRYPTOGRAPHY:
        print("Note: X.509 imports failed, but cryptography core seems present.")

def generate_self_signed_cert(common_name: str = "example.local") -> Tuple[bytes, bytes]:
    """Return (private_key_pem, cert_pem) as bytes.

    Uses cryptography to create a self-signed cert suitable for testing.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library required for X.509 example")

    # Key
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    # Subject / Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256(), default_backend())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem

# =======================================================================
# == 4. Diffie-Hellman Key Exchange (X25519)
# =======================================================================

# Imports used only by this section (from cryptography)
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
except Exception:
    if _HAS_CRYPTOGRAPHY:
        print("Note: X25519 imports failed, but cryptography core seems present.")


def x25519_key_exchange_demo() -> Tuple[bytes, bytes, bytes]:
    """Generate two X25519 keypairs, compute shared secret, derive symmetric key via HKDF.

    Returns (alice_key_bytes, bob_key_bytes, derived_key)
    """
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library required for DH/X25519 example")

    # Alice
    a_priv = X25519PrivateKey.generate()
    a_pub = a_priv.public_key()

    # Bob
    b_priv = X25519PrivateKey.generate()
    b_pub = b_priv.public_key()

    # Shared secrets
    shared_a = a_priv.exchange(b_pub)
    shared_b = b_priv.exchange(a_pub)
    assert shared_a == shared_b

    # Derive key (HKDF)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    )
    derived = hkdf.derive(shared_a)

    return (
        a_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
        b_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
        derived,
    )

# =======================================================================
# == 5. Packet Crafting & Sniffing (Scapy)
# =======================================================================
try:
    from scapy.all import IP, TCP, sr1, send, sniff, conf
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

def scapy_syn_scan(dst: str, dport: int = 80, timeout: float = 2.0):
    """Send a single TCP SYN and return response summary. Requires scapy and privileges."""
    if not _HAS_SCAPY:
        raise RuntimeError("scapy required for packet crafting demo")

    pkt = IP(dst=dst)/TCP(dport=dport, flags='S')
    resp = sr1(pkt, timeout=timeout, verbose=False)
    if resp is None:
        return "no-response"
    # Check for SYN/ACK (open) or RST (closed)
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        return f"tcp-flags:{flags}"
    return "unknown-response"

def scapy_sniff_iface(count: int = 5, timeout: int = 10):
    """Sniff 'count' packets (or until timeout) and return their summaries."""
    if not _HAS_SCAPY:
        raise RuntimeError("scapy required for packet sniffing demo")

    pkts = sniff(count=count, timeout=timeout)
    return [p.summary() for p in pkts]

# =======================================================================
# == MAIN DEMO (Execution)
# =======================================================================
def main():
    print("--- 1. HMAC Demo ---")
    msg = b"hello-MJ-demo"
    key = b"supersecretkey123"
    mac_pc, mac_std = hmac_compute(msg, key)
    print(f"HMAC (pycryptodome): {mac_pc}")
    print(f"HMAC (stdlib)     : {mac_std}")
    print("-" * 20)

    # DSA / ECDSA
    print("--- 2. DSA / ECDSA Demo ---")
    try:
        print(f"DSA sign/verify: {dsa_sign_verify_demo(msg)}")
        print(f"ECDSA sign/verify: {ecdsa_sign_verify_demo(msg)}")
    except RuntimeError as e:
        print(f"DSA/ECDSA demo skipped: {e}")
    print("-" * 20)

    # X.509
    print("--- 3. X.509 Self-Signed Cert Demo ---")
    try:
        key_pem, cert_pem = generate_self_signed_cert(common_name="mj.local")
        print(f"Generated self-signed cert PEM length: {len(cert_pem)}")
    except RuntimeError as e:
        print(f"X.509 demo skipped: {e}")
    print("-" * 20)

    # X25519 DH
    print("--- 4. X25519 Key Exchange Demo ---")
    try:
        a_pub, b_pub, derived = x25519_key_exchange_demo()
        print(f"X25519 public lengths: {len(a_pub)}, {len(b_pub)}")
        print(f"Derived symmetric key (hex): {derived.hex()}")
    except RuntimeError as e:
        print(f"X25519 demo skipped: {e}")
    print("-" * 20)

    # Scapy
    print("--- 5. Scapy Packet Demo ---")
    if _HAS_SCAPY:
        try:
            # WARNING: may require root. Use a reachable IP (example 1.1.1.1) or use local host.
            target = os.environ.get('SCAPY_TARGET', '1.1.1.1')
            print(f"Scapy SYN scan result ({target}:80): {scapy_syn_scan(target, dport=80)}")
            # sniff example (non-intrusive)
            print("Scapy sniff summary (3 pkts):")
            summaries = scapy_sniff_iface(count=3, timeout=5)
            for s in summaries:
                print(f"  > {s}")
        except Exception as e:
            print(f"Scapy demo error: {e}")
    else:
        print("Scapy not installed; packet crafting demo skipped.")
    print("=" * 20)

if __name__ == '__main__':
    main()
