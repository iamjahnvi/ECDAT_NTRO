"""Validated business inputs and transparent, context-dependent risk scoring."""
from __future__ import annotations

import fnmatch
from typing import Literal
from pydantic import BaseModel, Field, model_validator


class Benchmark(BaseModel):
    algorithm: str
    latency_ms: float = Field(ge=0)
    cost_per_million: float = Field(ge=0)


class BusinessContext(BaseModel):
    application: str = "Unclassified application"
    data_sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    data_types: list[str] = Field(default_factory=list, max_length=30)
    data_lifetime_years: float = Field(default=5, ge=0, le=100)
    migration_years: float = Field(default=3, ge=0, le=50)
    quantum_horizon_years: float = Field(default=7, gt=0, le=100)
    business_criticality: Literal["low", "medium", "high", "critical"] = "medium"
    usage: Literal["auto", "signature", "key-establishment", "encryption", "hash"] = "auto"
    latency_weight: float = Field(default=0.5, ge=0, le=1)
    cost_weight: float = Field(default=0.5, ge=0, le=1)
    max_latency_ms: float | None = Field(default=None, gt=0)
    max_cost_per_million: float | None = Field(default=None, gt=0)
    benchmarks: list[Benchmark] = Field(default_factory=list, max_length=30)
    rotation_max_days: int = Field(default=365, ge=1, le=3650)

    @model_validator(mode="after")
    def valid_weights(self):
        if self.cost_weight + self.latency_weight == 0:
            raise ValueError("At least one recommendation weight must be positive")
        return self


class AssetContext(BaseModel):
    path_pattern: str = Field(min_length=1)
    context: BusinessContext


class ScanContext(BusinessContext):
    asset_contexts: list[AssetContext] = Field(default_factory=list, max_length=100)


def apply_context(bom: dict, context: ScanContext | None = None) -> dict:
    from core.recommendation_engine import contextual_recommendation
    supplied = context is not None
    context = context or ScanContext()
    for component in bom.get("components", []):
        location = component.get("evidence", {}).get("occurrences", [{}])[0].get("location", "")
        selected = next((rule.context for rule in context.asset_contexts
                         if fnmatch.fnmatch(location.replace('\\', '/'), rule.path_pattern)), context)
        name = component.get("name", "").upper().replace('-', '')
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        quantum = any(a in name for a in ("RSA", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "DSA", "DH"))
        if any(a in name for a in ("MLDSA", "SLHDSA")):
            quantum = False
        broken = any(a in name for a in ("MD5", "SHA1", "3DES", "RC4")) or name == "DES"
        issues = component.get("discovery", {}).get("issues", [])
        classical = broken or bool(issues) or props.get("ecdat:category") in (
            "dependency-vulnerability", "weak-key-size", "weak-cipher", "broken-cipher", "weak-hash")
        x, y, z = selected.data_lifetime_years, selected.migration_years, selected.quantum_horizon_years
        exposed = quantum and x + y > z
        sensitivity = {"public": 0, "internal": 5, "confidential": 15, "restricted": 25}[selected.data_sensitivity]
        criticality = {"low": 0, "medium": 5, "high": 15, "critical": 25}[selected.business_criticality]
        score = min(100, (55 if classical else 40 if exposed else 20 if quantum else 0) +
                    (sensitivity + criticality if classical or quantum else 0))
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        component["mosca"] = {
            "x_years_data_sensitivity": x, "y_years_migration_time": y, "z_years_until_crqc": z,
            "equation": f"{x} + {y} > {z} => {x + y > z}", "risk_level": level,
        }
        component["risk"] = {
            "score": score, "level": level, "quantum_vulnerable": quantum,
            "hndl_exposure": exposed and selected.data_sensitivity in ("confidential", "restricted"),
            "sensitive_data": selected.data_types, "data_sensitivity": selected.data_sensitivity,
            "business_criticality": selected.business_criticality, "application": selected.application,
            "context_source": "user" if supplied else "default-assumptions",
            "reasons": issues + (["Classically weak cryptography"] if broken else []) +
                       (["Data lifetime plus migration exceeds quantum horizon"] if exposed else []),
        }
        component["recommendation"] = contextual_recommendation(component, selected)
    components = bom.get("components", [])
    bom["summary"] = {
        "total_findings": len(components),
        **{f"{level.lower()}_count": sum(c["risk"]["level"] == level for c in components)
           for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "sensitive_data_count": sum(c["risk"]["hndl_exposure"] for c in components),
    }
    bom["scan_context"] = context.model_dump()
    return bom
