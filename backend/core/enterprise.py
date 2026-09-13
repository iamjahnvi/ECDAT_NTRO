"""Enterprise discovery API: bounded batches, provider connectors and TLS."""
import asyncio
import os
from typing import Literal
from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from core.context import ScanContext
from core.material_scanner import scan_materials
from core.network_scanner import scan_tls
from core import connectors
from core.cbom import finalize_bom

router = APIRouter()


class DiscoveryTarget(BaseModel):
    kind: Literal['materials', 'tls', 'aws', 'azure', 'gcp', 'vault', 'hsm', 'repository']
    target: str = Field(min_length=1, max_length=2048)
    port: int = Field(default=443, ge=1, le=65535)
    server_name: str | None = None
    mount: str = 'transit'
    token_label: str | None = None
    context: ScanContext | None = None


class DiscoveryRequest(BaseModel):
    targets: list[DiscoveryTarget] = Field(min_length=1, max_length=100)
    context: ScanContext | None = None
    concurrency: int = Field(default=4, ge=1, le=8)


@router.post('/discover', tags=['enterprise'])
async def discover(request: DiscoveryRequest):
    semaphore = asyncio.Semaphore(request.concurrency)

    async def run(target):
        async with semaphore:
            context = target.context or request.context
            rotation = context.rotation_max_days if context else 365
            try:
                if target.kind == 'repository':
                    from main import scan, ScanRequest
                    # Existing endpoint returns validated CycloneDX; decode its extensions.
                    result = await scan(ScanRequest(target_directory=target.target, context=context))
                    import json
                    components = result.get('components', [])
                    for component in components:
                        for prop in component.get('properties', []):
                            if prop['name'] in ('ecdat:discovery',):
                                component['discovery'] = json.loads(prop['value'])
                    errors = next((json.loads(p['value']) for p in result.get('properties', []) if p['name'] == 'ecdat:discovery_errors'), [])
                    result = {'components': components, 'errors': errors}
                elif target.kind == 'materials':
                    result = await run_in_threadpool(scan_materials, target.target)
                elif target.kind == 'tls':
                    result = await run_in_threadpool(scan_tls, target.target, target.port, 2, target.server_name)
                elif target.kind == 'aws':
                    result = await run_in_threadpool(connectors.scan_aws, target.target, rotation)
                elif target.kind == 'azure':
                    result = await run_in_threadpool(connectors.scan_azure, target.target, rotation)
                elif target.kind == 'gcp':
                    result = await run_in_threadpool(connectors.scan_gcp, target.target, rotation)
                elif target.kind == 'vault':
                    result = await run_in_threadpool(connectors.scan_vault, target.target, target.mount, rotation)
                else:
                    allowed = os.environ.get('ECDAT_PKCS11_MODULE')
                    if not allowed or target.target != allowed:
                        raise ValueError('HSM target must match server ECDAT_PKCS11_MODULE')
                    result = await run_in_threadpool(connectors.scan_hsm, allowed, target.token_label, rotation)
                # Apply per-target business inputs before aggregation.
                from core.context import apply_context
                result = apply_context(result, context)
                result['target'] = target.target
                return result
            except Exception as exc:
                return {'components': [], 'errors': [{'target': target.target, 'error': str(exc) if isinstance(exc, (ValueError, ImportError)) else type(exc).__name__}], 'target': target.target}

    results = await asyncio.gather(*(run(t) for t in request.targets))
    components = [c for result in results for c in result['components']]
    errors = [e for result in results for e in result.get('errors', [])]
    if not components and errors:
        raise HTTPException(502, detail={'message': 'Discovery failed for all targets', 'errors': errors})
    # Preserve per-target context through path mappings for final scoring.
    context = request.context or ScanContext()
    context = context.model_copy(deep=True)
    from core.context import AssetContext
    for target, result in zip(request.targets, results):
        if target.context:
            for component in result['components']:
                location = component.get('evidence', {}).get('occurrences', [{}])[0].get('location')
                if location:
                    context.asset_contexts.insert(0, AssetContext(path_pattern=location, context=target.context))
    return finalize_bom({'components': components, 'discovery_errors': errors,
                         'coverage': [{'target': r['target'], 'findings': len(r['components']), 'errors': len(r.get('errors', []))} for r in results]}, context)
