"""Generate with the official CycloneDX library and validate every response."""
import json
from datetime import datetime
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilitySource, VulnerabilitySeverity, BomTarget
from cyclonedx.model.crypto import (CryptoProperties, CryptoAssetType, AlgorithmProperties,
    CertificateProperties, ProtocolProperties, ProtocolPropertiesType, RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType)
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from core.context import apply_context


def finalize_bom(report, context=None):
    report = apply_context(report, context)
    components = []
    vulnerabilities = []
    for source in report.get('components', []):
        props = [Property(name=p['name'], value=str(p['value'])) for p in source.get('properties', [])
                 if p['name'] not in ('ecdat:mosca', 'ecdat:risk', 'ecdat:recommendation', 'ecdat:discovery')]
        for field in ('mosca', 'risk', 'recommendation', 'discovery'):
            if field in source:
                props.append(Property(name=f'ecdat:{field}', value=json.dumps(source[field], default=str)))
        occurrences = []
        for occurrence in source.get('evidence', {}).get('occurrences', []):
            line = occurrence.get('line')
            occurrences.append(Occurrence(location=occurrence['location'], line=line if line and line > 0 else None,
                symbol=occurrence.get('symbol'), additional_context=f"End line: {occurrence['endLine']}" if occurrence.get('endLine') else None))
        kind = source.get('cryptoProperties', {}).get('assetType', 'algorithm')
        discovery = source.get('discovery', {})
        crypto = None
        if source['type'] == 'cryptographic-asset':
            crypto = CryptoProperties(asset_type=CryptoAssetType(kind))
            if kind == 'algorithm':
                crypto.algorithm_properties = AlgorithmProperties(parameter_set_identifier=source['name'])
            elif kind == 'certificate':
                crypto.certificate_properties = CertificateProperties(subject_name=discovery.get('subject'), issuer_name=discovery.get('issuer'),
                    not_valid_before=datetime.fromisoformat(discovery['not_before']) if discovery.get('not_before') else None,
                    not_valid_after=datetime.fromisoformat(discovery['not_after']) if discovery.get('not_after') else None,
                    certificate_format='X.509')
            elif kind == 'protocol':
                crypto.protocol_properties = ProtocolProperties(type=ProtocolPropertiesType.TLS, version=discovery.get('version'))
            elif kind == 'related-crypto-material':
                key_type = discovery.get('key_type', 'unknown')
                valid_types = {v.value for v in RelatedCryptoMaterialType}
                crypto.related_crypto_material_properties = RelatedCryptoMaterialProperties(
                    type=RelatedCryptoMaterialType(key_type if key_type in valid_types else 'unknown'), size=discovery.get('key_bits'))
        components.append(Component(name=source['name'], type=ComponentType(source['type']), bom_ref=source['bom-ref'],
            version=source.get('version'), description=source.get('description'), properties=props, crypto_properties=crypto,
            evidence=ComponentEvidence(occurrences=occurrences) if occurrences else None))
        for finding in source.get('vulnerabilities', []):
            vulnerabilities.append(Vulnerability(id=finding.get('id'), description=finding.get('description'),
                source=VulnerabilitySource(name=finding['source']['name']) if finding.get('source', {}).get('name') else None,
                ratings=[VulnerabilityRating(severity=VulnerabilitySeverity(r.get('severity', 'unknown'))) for r in finding.get('ratings', [])],
                affects=[BomTarget(ref=source['bom-ref'])]))
    metadata = report.get('metadata', {}).get('component', {})
    props = [Property(name=f'ecdat:{key}', value=json.dumps(report[key], default=str))
             for key in ('summary', 'scan_context', 'discovery_errors', 'coverage') if key in report]
    root = Component(name=metadata.get('name', 'ECDAT Scan Target'), bom_ref='ecdat:scan-target', type=ComponentType(metadata.get('type', 'application')))
    bom = Bom(components=components, vulnerabilities=vulnerabilities, properties=props, metadata=BomMetaData(component=root))
    bom.register_dependency(root, components)
    serialized = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6).output_as_string()
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(serialized, all_errors=True)
    if errors:
        raise ValueError(f"CycloneDX schema validation failed: {list(errors)}")
    return json.loads(serialized)
