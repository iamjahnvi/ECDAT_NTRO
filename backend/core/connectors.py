"""Read-only provider discovery using server-side credential chains."""
import os
from datetime import datetime, timezone
from core.material_scanner import asset


def managed_key(name, location, provider, details, rotation_max_days=365):
    issues = []
    bits = details.get('key_bits')
    if bits and (('RSA' in name.upper() and bits < 2048) or ('EC' in name.upper() and bits < 256)):
        issues.append(f'Weak managed key size: {bits} bits')
    state = str(details.get('state', '')).lower()
    if state in ('disabled', 'pendingdeletion', 'destroyed', 'destroy_scheduled'):
        issues.append(f"Key lifecycle state: {state}")
    if details.get('rotation_enabled') is False:
        issues.append("Automatic key rotation disabled")
    if details.get('exportable') is True:
        issues.append("Key is exportable")
    created = details.get('last_rotated') or details.get('created')
    if created:
        try:
            date = datetime.fromisoformat(str(created).replace('Z', '+00:00'))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - date).days > rotation_max_days:
                issues.append(f"Key age exceeds {rotation_max_days}-day rotation policy")
        except ValueError:
            pass
    expiry = details.get('expires')
    if expiry:
        expires = datetime.fromisoformat(str(expiry).replace('Z', '+00:00'))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            issues.append("Key expired")
    return asset(name, location, 'related-crypto-material', {"provider": provider, **details}, issues)


def scan_aws(region, rotation_max_days=365, client=None):
    if client is None:
        import boto3
        from botocore.config import Config
        client = boto3.client('kms', region_name=region, config=Config(connect_timeout=5, read_timeout=15, retries={'max_attempts': 2}))
    findings, errors = [], []
    for page in client.get_paginator('list_keys').paginate():
        for item in page['Keys']:
            try:
                key = client.describe_key(KeyId=item['KeyId'])['KeyMetadata']
                details = {"state": key['KeyState'], "created": str(key.get('CreationDate', '')),
                           "key_spec": key.get('KeySpec'), "origin": key.get('Origin'),
                           "key_manager": key.get('KeyManager'), "usage": 'signature' if key.get('KeyUsage') == 'SIGN_VERIFY' else 'encryption'}
                if key.get('KeySpec') == 'SYMMETRIC_DEFAULT' and key.get('Origin') == 'AWS_KMS':
                    try:
                        details['rotation_enabled'] = client.get_key_rotation_status(KeyId=item['KeyId'])['KeyRotationEnabled']
                    except Exception as exc:
                        errors.append({"target": item['KeyId'], "error": f"Rotation status unavailable: {type(exc).__name__}"})
                findings.append(managed_key(key.get('KeySpec', 'KMS key'), key['Arn'], 'aws-kms', details, rotation_max_days))
            except Exception as exc:
                errors.append({"target": item['KeyId'], "error": type(exc).__name__})
    return {"components": findings, "errors": errors}


def scan_azure(vault_url, rotation_max_days=365, client=None):
    if client is None:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        client = KeyClient(vault_url=vault_url, credential=DefaultAzureCredential())
    findings, errors = [], []
    for props in client.list_properties_of_keys():
        try:
            rotation = {}
            try:
                policy = client.get_key_rotation_policy(props.name)
                rotation['rotation_enabled'] = bool(policy.lifetime_actions)
            except Exception:
                errors.append({'target': props.name, 'error': 'Key rotation policy unavailable'})
            for version in client.list_properties_of_key_versions(props.name):
                key = client.get_key(props.name, version.version)
                details = {**rotation, "state": 'disabled' if version.enabled is False else 'enabled', "created": str(version.created_on or ''),
                           "expires": version.expires_on.isoformat() if version.expires_on else None,
                           "key_type": str(key.key_type), "curve": str(key.key.crv or ''),
                           "key_bits": len(key.key.n) * 8 if key.key.n else None,
                           "usage": 'signature' if 'sign' in (key.key_operations or []) else 'encryption'}
                findings.append(managed_key(str(key.key_type), key.id, 'azure-key-vault', details, rotation_max_days))
        except Exception as exc:
            errors.append({"target": props.name, "error": type(exc).__name__})
    return {"components": findings, "errors": errors}


def scan_gcp(parent, rotation_max_days=365, client=None):
    if client is None:
        from google.cloud import kms_v1
        client = kms_v1.KeyManagementServiceClient()
    findings, errors = [], []
    for ring in client.list_key_rings(request={'parent': parent}):
        for key in client.list_crypto_keys(request={'parent': ring.name}):
            try:
                for version in client.list_crypto_key_versions(request={'parent': key.name}):
                    details = {"state": version.state.name, "created": version.create_time.isoformat(),
                               "protection_level": version.protection_level.name,
                               "rotation_enabled": bool(key.rotation_period), "usage": 'signature' if 'SIGN' in key.purpose.name else 'encryption'}
                    findings.append(managed_key(version.algorithm.name, version.name, 'gcp-kms', details, rotation_max_days))
            except Exception as exc:
                errors.append({"target": key.name, "error": type(exc).__name__})
    return {"components": findings, "errors": errors}


def scan_vault(address, mount='transit', rotation_max_days=365, client=None):
    if client is None:
        import hvac
        client = hvac.Client(url=address, token=os.environ.get('VAULT_TOKEN'), timeout=15)
    findings, errors = [], []
    keys = client.secrets.transit.list_keys(mount_point=mount)['data']['keys']
    for name in keys:
        try:
            key = client.secrets.transit.read_key(name=name, mount_point=mount)['data']
            details = {"exportable": key.get('exportable'), "rotation_enabled": bool(key.get('auto_rotate_period')),
                       "latest_version": key.get('latest_version'), "min_decryption_version": key.get('min_decryption_version'),
                       "usage": 'signature' if key.get('supports_signing') else 'encryption',
                       "versions": list(key.get('keys', {}))}
            findings.append(managed_key(key['type'], f"{address}/{mount}/keys/{name}", 'vault-transit', details, rotation_max_days))
        except Exception as exc:
            errors.append({"target": name, "error": type(exc).__name__})
    return {"components": findings, "errors": errors}


def scan_hsm(module, token_label=None, rotation_max_days=365, library=None):
    import pkcs11
    library = library or pkcs11.lib(module)
    findings, errors = [], []
    for token in library.get_tokens():
        if token_label and token.label != token_label:
            continue
        findings.append({"type": "device", "bom-ref": f"hsm:{token.serial.decode() if isinstance(token.serial, bytes) else token.serial}",
                         "name": token.label, "description": "PKCS#11 hardware token",
                         "properties": [{"name": "ecdat:category", "value": "hsm"}],
                         "discovery": {"manufacturer": str(token.manufacturer_id), "model": str(token.model), "issues": []}})
        try:
            kwargs = {'rw': False}
            if os.environ.get('ECDAT_HSM_PIN'):
                kwargs['user_pin'] = os.environ['ECDAT_HSM_PIN']
            with token.open(**kwargs) as session:
                for obj in session.get_objects():
                    def read(attribute, default=None):
                        try:
                            value = obj[attribute]
                            return value.name if hasattr(value, 'name') else value
                        except pkcs11.PKCS11Error:
                            return default
                    kind = read(pkcs11.Attribute.CLASS)
                    if kind not in ('PUBLIC_KEY', 'PRIVATE_KEY', 'SECRET_KEY'):
                        continue
                    details = {"key_type": kind, "key_bits": read(pkcs11.Attribute.MODULUS_BITS),
                               "exportable": read(pkcs11.Attribute.EXTRACTABLE), "sensitive": read(pkcs11.Attribute.SENSITIVE),
                               "state": 'active', "lifecycle": "Dates unavailable unless supplied by token",
                               "usage": 'signature' if read(pkcs11.Attribute.SIGN) else 'encryption'}
                    findings.append(managed_key(str(read(pkcs11.Attribute.KEY_TYPE, 'Unknown')), f"pkcs11:token={token.label};object={read(pkcs11.Attribute.LABEL, '')}", 'pkcs11', details, rotation_max_days))
        except pkcs11.PKCS11Error as exc:
            errors.append({"target": token.label, "error": type(exc).__name__})
    return {"components": findings, "errors": errors}
