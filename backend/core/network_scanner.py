"""Bounded live TLS handshakes with explicit probe coverage."""
import socket
import ssl
from cryptography import x509
from core.material_scanner import asset, certificate_asset


def scan_tls(host, port=443, timeout=3, server_name=None):
    findings, probes = [], []
    server_name = server_name or host
    location = f"tls://{host}:{port}"
    certificate = None
    for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = context.maximum_version = version
            context.set_ciphers('ALL:@SECLEVEL=0')
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name) as tls:
                    cipher = tls.cipher()
                    certificate = certificate or tls.getpeercert(binary_form=True)
                    issues = []
                    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                        issues.append("Deprecated TLS version enabled")
                    if any(term in cipher[0] for term in ('RC4', 'DES', 'NULL', 'EXPORT', 'MD5')):
                        issues.append("Weak negotiated cipher suite")
                    findings.append(asset(f"TLS {tls.version()} {cipher[0]}", location, "protocol",
                                          {"version": tls.version(), "cipher_suite": cipher[0], "cipher_bits": cipher[2],
                                           "usage": "key-establishment"}, issues))
                    probes.append({"version": version.name, "status": "supported", "cipher": cipher[0]})
        except (OSError, ValueError) as exc:
            probes.append({"version": version.name, "status": "not-negotiated", "detail": str(exc)})
    trust = {"verified": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=server_name):
                trust = {"verified": True}
    except (OSError, ValueError) as exc:
        trust["error"] = str(exc)
    if certificate:
        cert = certificate_asset(x509.load_der_x509_certificate(certificate), location)
        cert['discovery']['trust'] = trust
        if not trust['verified']:
            cert['discovery']['issues'].append("Certificate chain or hostname verification failed")
        findings.append(cert)
    # Enumerate individually offered TLS <=1.2 suites supported by local OpenSSL.
    suites, suite_errors = [], []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers('ALL:@SECLEVEL=0')
    for cipher in context.get_ciphers()[:128]:
        if cipher['protocol'] == 'TLSv1.3':
            continue  # Python ssl cannot select individual TLS 1.3 suites.
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.check_hostname = False
        probe.verify_mode = ssl.CERT_NONE
        probe.minimum_version = ssl.TLSVersion.TLSv1
        probe.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            probe.set_ciphers(cipher['name'] + ':@SECLEVEL=0')
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with probe.wrap_socket(sock, server_hostname=server_name) as tls:
                    suites.append(tls.cipher()[0])
        except OSError as exc:
            suite_errors.append({"cipher": cipher['name'], "detail": str(exc)})
            if isinstance(exc, (TimeoutError, ConnectionRefusedError)):
                break
    weak = [s for s in suites if any(term in s for term in ('RC4', 'DES', 'NULL', 'EXPORT', 'MD5'))]
    if findings:
        findings[0]['discovery'].update({"accepted_cipher_suites": suites, "probes": probes,
            "cipher_probe_failures": suite_errors, "coverage": "TLS 1.0–1.3 version probes; up to 128 local OpenSSL TLS <=1.2 suites. TLS 1.3 suite is negotiated, not exhaustively enumerated."})
        findings[0]['discovery']['issues'].extend(f"Weak accepted cipher: {s}" for s in weak)
    return {"components": findings, "errors": [] if findings else [{"target": location, "error": "No TLS handshake succeeded", "probes": probes}]}
