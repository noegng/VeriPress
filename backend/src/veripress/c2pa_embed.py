"""C2PA manifest in the published image (decisions.md Q10, Q20). OWNER: Dev A.

The PNG we publish carries a standard C2PA manifest (Content Credentials) with:
  - c2pa.actions: created, digitalSourceType = digital capture or AI-generated;
  - org.veripress.anchor: chain, XRPL tx hash, signed manifest digest, explorer link.
It lives in the file's metadata (not in the pixels), so the Merkle trees are unaffected — and
it is stripped by WhatsApp & co, which is exactly the gap VeriPress closes (watermark + XRPL).

Signing uses an ES256 certificate from a local *test* CA (keys/c2pa_*.pem, created on first
use, never committed): C2PA readers show the manifest as valid but the signer as untrusted.
In production: a certificate from a CA on the C2PA trust list.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
from pathlib import Path

ASSERTION = "org.veripress.anchor"
IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"
SOURCE_TYPES = {"ai_generate": IPTC + "trainedAlgorithmicMedia"}  # everything else: a camera capture


def enabled() -> bool:
    return os.environ.get("VERIPRESS_C2PA", "1") != "0"


def _paths() -> tuple[Path, Path]:
    from .signing import keys_dir

    return keys_dir() / "c2pa_chain.pem", keys_dir() / "c2pa_key.pem"


def ensure_test_certificate() -> tuple[bytes, bytes]:
    """(certificate chain PEM, private key PEM): leaf ES256 signed by a local test CA."""
    chain_p, key_p = _paths()
    if chain_p.exists() and key_p.exists():
        return chain_p.read_bytes(), key_p.read_bytes()

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VeriPress (test)")])

    def usage(sign: bool, ca: bool) -> x509.KeyUsage:
        return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=False,
                             data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                             crl_sign=ca, encipher_only=False, decipher_only=False)

    now = dt.datetime.now(dt.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder().subject_name(name("VeriPress Test CA")).issuer_name(name("VeriPress Test CA"))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(usage(sign=False, ca=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder().subject_name(name("VeriPress signer")).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(usage(sign=True, ca=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION,
                                              ObjectIdentifier("1.3.6.1.5.5.7.3.36")]), critical=False)  # documentSigning
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    chain = leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM)
    pkey = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    chain_p.parent.mkdir(parents=True, exist_ok=True)
    chain_p.write_bytes(chain)
    key_p.write_bytes(pkey)
    key_p.chmod(0o600)
    return chain, pkey


def embed(png: bytes, tx_hash: str, manifest_digest: str, op: str, explorer_url: str) -> bytes:
    """Return `png` with a signed C2PA manifest pointing to the XRPL anchor (same pixels)."""
    import c2pa

    chain, pkey = ensure_test_certificate()
    manifest = {
        "claim_generator_info": [{"name": "VeriPress", "version": "0.1"}],
        "title": "VeriPress signed image",
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created", "digitalSourceType": SOURCE_TYPES.get(op, IPTC + "digitalCapture")},
            ]}},
            {"label": ASSERTION, "data": {
                "chain": "xrpl", "tx_hash": tx_hash, "manifest_digest": manifest_digest, "explorer": explorer_url,
            }},
        ],
    }
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(c2pa.C2paSigningAlg.ES256, chain, pkey, None))
    out = io.BytesIO()
    c2pa.Builder(json.dumps(manifest)).sign(signer, "image/png", io.BytesIO(png), out)
    return out.getvalue()


def _mime(data: bytes) -> str | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    return None


def read(data: bytes) -> dict | None:
    """VeriPress anchor carried by the file's C2PA manifest, or None if there is none.
    {"tx_hash", "manifest_digest", "explorer", "source_type", "state", "signer_trusted"}"""
    import c2pa

    mime = _mime(data)
    if mime is None:
        return None
    try:
        reader = c2pa.Reader(mime, io.BytesIO(data))
        report = json.loads(reader.json())
        state = str(reader.get_validation_state())
    except Exception:  # noqa: BLE001 — no manifest, or unreadable: nothing to report
        return None
    active = report.get("manifests", {}).get(report.get("active_manifest") or "", {})
    data_by_label = {a.get("label"): a.get("data", {}) for a in active.get("assertions", [])}
    anchor = data_by_label.get(ASSERTION)
    if anchor is None:
        return None
    actions = (data_by_label.get("c2pa.actions.v2") or data_by_label.get("c2pa.actions") or {}).get("actions", [])
    return {
        "tx_hash": anchor.get("tx_hash"),
        "manifest_digest": anchor.get("manifest_digest"),
        "explorer": anchor.get("explorer"),
        "source_type": next((a.get("digitalSourceType") for a in actions if a.get("digitalSourceType")), None),
        "state": state.split(".")[-1],
        "signer_trusted": state.split(".")[-1] == "Trusted",
    }
