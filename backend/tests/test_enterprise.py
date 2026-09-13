import asyncio
import copy
import io
import json
import socket
import ssl
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

import main
from core.material_scanner import scan_materials, asset
from core.context import ScanContext, apply_context
from core.cbom import finalize_bom
from core.connectors import scan_aws, scan_azure, scan_gcp, scan_vault, scan_hsm
from core.network_scanner import scan_tls


def certificate(key, expired=False):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=60))
            .not_valid_after(now + timedelta(days=-1 if expired else 60))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .sign(key, hashes.SHA256()))


def extension(bom, name):
    return json.loads(next(p['value'] for p in bom['properties'] if p['name'] == f'ecdat:{name}'))


def test_materials_certificate_expiry_keys_and_no_private_bytes(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = certificate(key, expired=True)
    (tmp_path / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    for index, item in enumerate([key, ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()]):
        (tmp_path / f'{index}.key').write_bytes(item.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / 'encrypted.key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b'password')))
    (tmp_path / 'broken.crt').write_bytes(b'not a certificate')
    result = scan_materials(tmp_path)
    assert len(result['components']) == 6
    issues = [issue for c in result['components'] for issue in c['discovery']['issues']]
    assert 'Certificate expired' in issues
    assert 'Weak RSA key size: 1024 bits' in issues
    assert 'PRIVATE KEY-----' not in json.dumps(result)
    assert result['errors']
    bom = finalize_bom(result)
    assert not JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom), all_errors=True)


def test_business_risk_differs_and_overrides_match():
    report = {'components': [asset('RSA', '/payments/key', 'algorithm', {})]}
    public = apply_context(copy.deepcopy(report), ScanContext(data_sensitivity='public', business_criticality='low', data_lifetime_years=0, migration_years=0))
    sensitive = apply_context(copy.deepcopy(report), ScanContext(data_sensitivity='restricted', business_criticality='critical', data_types=['PII']))
    assert public['components'][0]['risk']['score'] < sensitive['components'][0]['risk']['score']
    assert sensitive['components'][0]['risk']['hndl_exposure']
    assert sensitive['summary']['sensitive_data_count'] == 1
    override = ScanContext(asset_contexts=[{'path_pattern': '/payments/*', 'context': {'application': 'Payments', 'data_sensitivity': 'restricted'}}])
    assert apply_context(report, override)['components'][0]['risk']['application'] == 'Payments'


def test_cost_latency_ranking_and_budgets():
    report = {'components': [asset('ECDSA', 'test', 'algorithm', {})]}
    latency = apply_context(copy.deepcopy(report), ScanContext(latency_weight=1, cost_weight=0))
    cost = apply_context(copy.deepcopy(report), ScanContext(latency_weight=0, cost_weight=1))
    assert latency['components'][0]['recommendation']['pqc_algorithm'] == 'ML-DSA-65'
    assert cost['components'][0]['recommendation']['pqc_algorithm'] == 'SLH-DSA-SHA2-128s'
    measured = ScanContext(max_latency_ms=2, benchmarks=[
        {'algorithm': 'ML-DSA-65', 'latency_ms': 10, 'cost_per_million': 1},
        {'algorithm': 'SLH-DSA-SHA2-128s', 'latency_ms': 1, 'cost_per_million': 3}])
    rec = apply_context(copy.deepcopy(report), measured)['components'][0]['recommendation']
    assert rec['model'] == 'measured' and rec['pqc_algorithm'].startswith('SLH')
    unmeasured = apply_context(report, ScanContext(max_latency_ms=2))['components'][0]['recommendation']
    assert not unmeasured['budget_satisfied']


def test_aws_pagination_and_partial_denial():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{'Keys': [{'KeyId': 'a'}]}, {'Keys': [{'KeyId': 'b'}]}]
    client.describe_key.side_effect = [{'KeyMetadata': {'KeyState': 'Enabled', 'KeySpec': 'SYMMETRIC_DEFAULT', 'Origin': 'AWS_KMS', 'Arn': 'arn:a'}}, RuntimeError('denied')]
    client.get_key_rotation_status.return_value = {'KeyRotationEnabled': False}
    result = scan_aws('us-east-1', client=client)
    assert len(result['components']) == 1 and len(result['errors']) == 1
    assert 'Automatic key rotation disabled' in result['components'][0]['discovery']['issues']


def test_azure_versions():
    client = MagicMock()
    client.list_properties_of_keys.return_value = [NS(name='key')]
    client.list_properties_of_key_versions.return_value = [NS(version='v1', enabled=False, created_on=None, expires_on=None)]
    client.get_key.return_value = NS(key_type='RSA', key=NS(crv=None, n=b'x' * 256), key_operations=['sign'], id='https://vault/keys/key/v1')
    result = scan_azure('https://vault', client=client)
    assert result['components'][0]['discovery']['key_bits'] == 2048
    assert result['components'][0]['discovery']['issues']


def test_gcp_and_vault_versions():
    client = MagicMock()
    client.list_key_rings.return_value = [NS(name='ring')]
    client.list_crypto_keys.return_value = [NS(name='key', rotation_period=None, purpose=NS(name='ASYMMETRIC_SIGN'))]
    client.list_crypto_key_versions.return_value = [NS(name='v1', state=NS(name='DISABLED'), create_time=datetime.now(timezone.utc), protection_level=NS(name='HSM'), algorithm=NS(name='RSA_SIGN_PSS_2048_SHA256'))]
    result = scan_gcp('projects/test/locations/global', client=client)
    assert result['components'][0]['discovery']['protection_level'] == 'HSM'
    vault = MagicMock()
    vault.secrets.transit.list_keys.return_value = {'data': {'keys': ['key']}}
    vault.secrets.transit.read_key.return_value = {'data': {'type': 'aes256-gcm96', 'exportable': True, 'keys': {'1': {}}, 'latest_version': 1}}
    assert scan_vault('https://vault', client=vault)['components'][0]['discovery']['exportable']


def test_hsm_never_requests_key_value():
    import pkcs11
    queried = []
    values = {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY, pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
              pkcs11.Attribute.LABEL: 'key', pkcs11.Attribute.MODULUS_BITS: 2048}
    class Object:
        def __getitem__(self, key):
            queried.append(key)
            if key not in values:
                raise pkcs11.AttributeTypeInvalid()
            return values[key]
    token = MagicMock(label='test', serial=b'123', manufacturer_id='vendor', model='HSM')
    token.open.return_value.__enter__.return_value.get_objects.return_value = [Object()]
    library = MagicMock()
    library.get_tokens.return_value = [token]
    result = scan_hsm('module', library=library)
    assert len(result['components']) == 2
    assert pkcs11.Attribute.VALUE not in queried


def test_live_tls_local_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / 'cert.pem').write_bytes(certificate(key).public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tmp_path / 'cert.pem', tmp_path / 'key.pem')
    server = socket.socket()
    server.bind(('127.0.0.1', 0)); server.listen(10); server.settimeout(0.2)
    port = server.getsockname()[1]
    stop = threading.Event()
    def serve():
        while not stop.is_set():
            try:
                sock, _ = server.accept()
                try:
                    with context.wrap_socket(sock, server_side=True):
                        pass
                except ssl.SSLError:
                    sock.close()
            except (TimeoutError, OSError):
                continue
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    try:
        result = scan_tls('127.0.0.1', port, timeout=0.3, server_name='localhost')
        assert any(c['cryptoProperties']['assetType'] == 'certificate' for c in result['components'])
        assert any(c['discovery'].get('version') == 'TLSv1.2' for c in result['components'])
        finalize_bom(result)
    finally:
        stop.set(); server.close(); thread.join(timeout=2)


def test_api_context_schema_auth_and_upload(tmp_path, monkeypatch):
    async def semgrep(_):
        return {'results': [{'path': '/app/key.py', 'start': {'line': 1}, 'end': {'line': 1}, 'extra': {'metadata': {'algorithm': 'RSA'}}}]}
    monkeypatch.setattr(main, 'run_semgrep_scan', semgrep)
    client = TestClient(main.app)
    monkeypatch.setenv('ECDAT_API_KEY', 'test-key')
    assert client.post('/scan', json={'target_directory': str(tmp_path)}).status_code == 401
    headers = {'Authorization': 'Bearer test-key'}
    response = client.post('/scan', headers=headers, json={'target_directory': str(tmp_path), 'context': {'data_sensitivity': 'restricted', 'business_criticality': 'critical'}})
    assert response.status_code == 200, response.text
    assert extension(response.json(), 'summary')['critical_count'] == 1
    assert 'summary' not in response.json()
    invalid = client.post('/scan', headers=headers, json={'target_directory': str(tmp_path), 'context': {'data_lifetime_years': -1}})
    assert invalid.status_code == 422
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('app.py', 'pass')
    response = client.post('/scan/upload', headers=headers, files={'file': ('app.zip', archive.getvalue())}, data={'context': '{"data_sensitivity":"restricted"}'})
    assert response.status_code == 200, response.text


def test_batch_partial_failure_and_context(tmp_path, monkeypatch):
    monkeypatch.delenv('ECDAT_API_KEY', raising=False)
    from core import enterprise
    monkeypatch.setattr(enterprise, 'scan_tls', lambda *a: {'components': [asset('RSA', 'tls://test:443', 'algorithm', {})], 'errors': []})
    response = TestClient(main.app).post('/discover', json={'targets': [
        {'kind': 'tls', 'target': 'test', 'context': {'application': 'Payments', 'data_sensitivity': 'restricted'}},
        {'kind': 'hsm', 'target': 'unconfigured'},
    ]})
    assert response.status_code == 200, response.text
    assert len(extension(response.json(), 'discovery_errors')) == 1
    risk = extension(response.json()['components'][0], 'risk')
    assert risk['application'] == 'Payments'


def test_git_auth_is_host_scoped_and_not_in_arguments(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_GIT_TOKEN', 'secret-token')
    monkeypatch.setenv('ECDAT_GIT_HOST', 'github.com')
    run = MagicMock()
    monkeypatch.setattr(main.subprocess, 'run', run)
    main._clone_repo('https://github.com/org/private.git', tmp_path / 'repo')
    assert 'secret-token' not in str(run.call_args.args)
    assert 'Authorization: Basic' in run.call_args.kwargs['env']['GIT_CONFIG_VALUE_0']
    main._clone_repo('https://other.example/repo.git', tmp_path / 'other')
    assert 'GIT_CONFIG_VALUE_0' not in run.call_args.kwargs['env']


def test_binary_endpoint_produces_valid_schema(monkeypatch):
    monkeypatch.delenv('ECDAT_API_KEY', raising=False)
    monkeypatch.setattr(main, 'scan_binary', lambda _: [{'algorithm': 'RSA', 'file': 'test.exe', 'offset': 0, 'symbol': 'RSA_generate_key'}])
    response = TestClient(main.app).post('/scan/binary', files={'file': ('test.exe', b'MZtest')})
    assert response.status_code == 200, response.text
    assert not JsonStrictValidator(SchemaVersion.V1_6).validate_str(response.text, all_errors=True)


def test_cli_exit_gates_and_partial_results(tmp_path, monkeypatch):
    import cli
    config = tmp_path / 'targets.json'
    config.write_text('{"targets":[{"kind":"tls","target":"test"}]}')
    output = tmp_path / 'bom.json'
    monkeypatch.setattr('sys.argv', ['cli', '--config', str(config), '--output', str(output)])
    response = MagicMock()
    response.json.return_value = {'properties': [{'name': 'ecdat:summary', 'value': '{"critical_count":1}'}]}
    monkeypatch.setattr(cli.httpx, 'post', lambda *a, **kw: response)
    assert cli.main() == 1 and output.exists()
    response.json.return_value['properties'].append({'name': 'ecdat:discovery_errors', 'value': '[{"error":"denied"}]'})
    assert cli.main() == 2


def test_merge_preserves_sca_versions_advisories_and_severity():
    from core.translator import transform_semgrep_to_cyclonedx
    report = transform_semgrep_to_cyclonedx({'results': []}, [{
        'package': 'legacy-crypto', 'version': '1.2.3', 'ecosystem': 'npm', 'file': '/app/package.json',
        'severity': 'medium', 'cve_ids': ['CVE-2020-0001'], 'recommendation': 'Upgrade package',
    }])
    bom = finalize_bom(report, ScanContext(data_sensitivity='public', business_criticality='low'))
    component = bom['components'][0]
    assert component['version'] == '1.2.3'
    assert bom['vulnerabilities'][0]['id'] == 'CVE-2020-0001'
    assert bom['vulnerabilities'][0]['affects'][0]['ref'] == component['bom-ref']
    assert extension(component, 'risk')['level'] == 'MEDIUM'


def test_merge_preserves_custom_sensitive_keywords_and_context(tmp_path, monkeypatch):
    monkeypatch.delenv('ECDAT_API_KEY', raising=False)
    source = tmp_path / 'app.py'
    source.write_text('patient_identifier = "example"\nkey = generate()\n')
    async def semgrep(_):
        return {'results': [{'path': str(source), 'start': {'line': 2}, 'end': {'line': 2},
                            'extra': {'severity': 'WARNING', 'metadata': {'algorithm': 'RSA'}}}]}
    monkeypatch.setattr(main, 'run_semgrep_scan', semgrep)
    response = TestClient(main.app).post('/scan', json={
        'target_directory': str(tmp_path), 'sensitive_keywords': ['patient_identifier'],
        'context': {'application': 'Medical', 'data_sensitivity': 'public', 'business_criticality': 'low',
                    'data_lifetime_years': 0, 'migration_years': 0},
    })
    assert response.status_code == 200, response.text
    risk = extension(response.json()['components'][0], 'risk')
    assert risk['application'] == 'Medical'
    assert risk['correlated_sensitive_data'] and risk['level'] == 'CRITICAL'
