"""X.509 and serialized key discovery. Never returns private key bytes."""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448, dh


def asset(name, location, kind, details, issues=None):
    return {"type": "cryptographic-asset", "bom-ref": str(uuid.uuid4()), "name": name,
            "description": f"Discovered {kind}", "cryptoProperties": {"assetType": kind},
            "evidence": {"occurrences": [{"location": location}]},
            "properties": [{"name": "ecdat:category", "value": kind}],
            "discovery": {**details, "issues": issues or []}}


def key_info(key):
    public = key.public_key() if hasattr(key, "public_key") else key
    families = [(rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "ECDSA"),
                (dsa.DSAPublicKey, "DSA"), (ed25519.Ed25519PublicKey, "Ed25519"),
                (ed448.Ed448PublicKey, "Ed448"), (x25519.X25519PublicKey, "X25519"),
                (x448.X448PublicKey, "X448"), (dh.DHPublicKey, "DH")]
    family = next((name for cls, name in families if isinstance(public, cls)), "Unknown")
    bits = getattr(public, "key_size", {"Ed25519": 256, "Ed448": 448, "X25519": 256, "X448": 448}.get(family))
    issues = []
    if (family in ("RSA", "DSA", "DH") and bits < 2048) or (family == "ECDSA" and bits < 256):
        issues.append(f"Weak {family} key size: {bits} bits")
    if family == "DSA":
        issues.append("Legacy DSA key")
    encoded = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return family, {"key_bits": bits, "curve": getattr(getattr(public, "curve", None), "name", None),
                    "public_key_sha256": hashlib.sha256(encoded).hexdigest()}, issues


def certificate_asset(cert, location, now=None):
    now = now or datetime.now(timezone.utc)
    family, details, issues = key_info(cert.public_key())
    if cert.not_valid_after_utc < now:
        issues.append("Certificate expired")
    elif (cert.not_valid_after_utc - now).days <= 30:
        issues.append("Certificate expires within 30 days")
    if cert.not_valid_before_utc > now:
        issues.append("Certificate not yet valid")
    signature_hash = cert.signature_hash_algorithm
    if signature_hash and signature_hash.name.lower() in ("md5", "sha1"):
        issues.append(f"Weak certificate signature hash: {signature_hash.name}")
    details.update({"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": str(cert.serial_number), "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(), "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                    "signature_algorithm": cert.signature_algorithm_oid.dotted_string, "usage": "signature"})
    try:
        details["dns_names"] = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        details["dns_names"] = []
    return asset(f"{family} X.509 certificate", location, "certificate", details, issues)


def scan_materials(target):
    root = Path(target).resolve()
    findings, errors = [], []
    if not root.exists():
        return {"components": [], "errors": [{"target": str(root), "error": "Target does not exist"}]}
    paths = [root] if root.is_file() else root.rglob('*')
    for path in paths:
        if path.suffix.lower() not in {'.pem', '.crt', '.cer', '.der', '.key', '.pub'} or not path.is_file():
            continue
        if not path.resolve().is_relative_to(root if root.is_dir() else root.parent):
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                errors.append({"target": str(path), "error": "Key/certificate file exceeds 4 MB limit"})
                continue
            raw = path.read_bytes()
            blocks = re.findall(rb'-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----', raw, re.S)
            pem = re.findall(rb'-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----', raw, re.S)
            for index, blob in enumerate(pem or [raw]):
                label = blocks[index] if pem else b'DER'
                location = str(path)
                if b'CERTIFICATE' in label or (not pem and path.suffix.lower() in ('.crt', '.cer', '.der')):
                    try:
                        cert = x509.load_pem_x509_certificate(blob) if pem else x509.load_der_x509_certificate(blob)
                        findings.append(certificate_asset(cert, location))
                        continue
                    except ValueError:
                        if pem:
                            raise
                loaders = [serialization.load_pem_private_key, serialization.load_pem_public_key] if pem else [serialization.load_der_private_key, serialization.load_der_public_key, serialization.load_ssh_public_key]
                key = None
                for loader in loaders:
                    try:
                        key = loader(blob, password=None) if 'private' in loader.__name__ else loader(blob)
                        break
                    except TypeError:
                        if b'ENCRYPTED' in blob or b'PRIVATE' in label:
                            findings.append(asset("Encrypted private key", location, "related-crypto-material", {"encrypted": True, "key_type": "private-key", "inspection": "Password required to inspect algorithm"}))
                            break
                    except (ValueError, UnsupportedAlgorithm):
                        continue
                if key is not None:
                    family, details, issues = key_info(key)
                    private = hasattr(key, 'private_bytes')
                    if private:
                        issues.append("Unencrypted private key stored on disk")
                    findings.append(asset(f"{family} {'private' if private else 'public'} key", location, "related-crypto-material",
                                          {**details, "key_type": "private-key" if private else "public-key", "encrypted": False,
                                           "lifecycle": "Creation/rotation dates unavailable in serialized key format"}, issues))
                elif not any(f['evidence']['occurrences'][0]['location'] == location for f in findings):
                    errors.append({"target": location, "error": "Unsupported, encrypted, or malformed key material"})
        except (OSError, ValueError, UnsupportedAlgorithm) as exc:
            errors.append({"target": str(path), "error": str(exc)})
    return {"components": findings, "errors": errors}
