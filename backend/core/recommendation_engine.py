"""
core/recommendation_engine.py
NIST FIPS 203/204 Post-Quantum migration lookup table.

Each entry maps a legacy / broken algorithm keyword (upper-cased) to a
structured recommendation record that is embedded into CycloneDX output.
"""

from __future__ import annotations

# ── Migration mapping ─────────────────────────────────────────────────────────
# Key   : upper-cased algorithm name or family substring (matched via `in`)
# Value : recommendation record
MIGRATION_MAP: dict[str, dict] = {
    # ── Key Encapsulation / Asymmetric Encryption ───────────────────────────
    "RSA": {
        "pqc_standard": "NIST FIPS 203",
        "pqc_algorithm": "ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)",
        "action": "Migrate to NIST FIPS 203 ML-KEM",
        "rationale": (
            "RSA is vulnerable to Shor's algorithm on quantum computers. "
            "ML-KEM provides IND-CCA2 security and is NIST-standardised."
        ),
        "priority": "HIGH",
    },
    "ECDH": {
        "pqc_standard": "NIST FIPS 203",
        "pqc_algorithm": "ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)",
        "action": "Migrate to NIST FIPS 203 ML-KEM",
        "rationale": (
            "ECDH relies on the elliptic-curve discrete-log problem, broken by "
            "quantum Shor's algorithm. Transition to ML-KEM."
        ),
        "priority": "HIGH",
    },
    # ── Digital Signatures ──────────────────────────────────────────────────
    "ECDSA": {
        "pqc_standard": "NIST FIPS 204",
        "pqc_algorithm": "ML-DSA (Module-Lattice-Based Digital Signature Algorithm)",
        "action": "Migrate to NIST FIPS 204 ML-DSA",
        "rationale": (
            "ECDSA is vulnerable to quantum attacks. ML-DSA (formerly CRYSTALS-Dilithium) "
            "provides strong post-quantum digital signature security."
        ),
        "priority": "HIGH",
    },
    "DSA": {
        "pqc_standard": "NIST FIPS 204",
        "pqc_algorithm": "ML-DSA (Module-Lattice-Based Digital Signature Algorithm)",
        "action": "Migrate to NIST FIPS 204 ML-DSA",
        "rationale": (
            "DSA key security is based on discrete logarithm, solvable by quantum "
            "computers. Replace with ML-DSA."
        ),
        "priority": "HIGH",
    },
    # ── Broken / Legacy Symmetric & Hash ───────────────────────────────────
    "MD5": {
        "pqc_standard": "N/A (Classical)",
        "pqc_algorithm": "SHA-3-256 / SHA-3-512 (NIST FIPS 202)",
        "action": "Deprecate immediately. Upgrade to AES-256 / SHA-3",
        "rationale": (
            "MD5 produces 128-bit digests and is collision-broken. "
            "Replace with SHA-3 for hashing or HMAC-SHA-256 for MACs."
        ),
        "priority": "CRITICAL",
    },
    "DES": {
        "pqc_standard": "N/A (Classical)",
        "pqc_algorithm": "AES-256-GCM (NIST FIPS 197 / SP 800-38D)",
        "action": "Deprecate immediately. Upgrade to AES-256 / SHA-3",
        "rationale": (
            "DES has a 56-bit key and was publicly broken in 1997. "
            "Use AES-256-GCM for authenticated encryption."
        ),
        "priority": "CRITICAL",
    },
    "3DES": {
        "pqc_standard": "N/A (Classical)",
        "pqc_algorithm": "AES-256-GCM (NIST FIPS 197 / SP 800-38D)",
        "action": "Deprecate immediately. Upgrade to AES-256 / SHA-3",
        "rationale": (
            "Triple-DES provides only ~112 bits of effective security and is "
            "deprecated by NIST. Migrate to AES-256-GCM."
        ),
        "priority": "CRITICAL",
    },
    "RC4": {
        "pqc_standard": "N/A (Classical)",
        "pqc_algorithm": "ChaCha20-Poly1305 or AES-256-GCM",
        "action": "Deprecate immediately. Upgrade to AES-256 / SHA-3",
        "rationale": (
            "RC4 is a stream cipher with multiple biases and is fully broken. "
            "Replace with ChaCha20-Poly1305 or AES-256-GCM."
        ),
        "priority": "CRITICAL",
    },
    "SHA1": {
        "pqc_standard": "N/A (Classical)",
        "pqc_algorithm": "SHA-3-256 (NIST FIPS 202)",
        "action": "Deprecate immediately. Upgrade to AES-256 / SHA-3",
        "rationale": (
            "SHA-1 is collision-broken (SHAttered attack, 2017). "
            "Upgrade to SHA-256 or SHA-3."
        ),
        "priority": "HIGH",
    },
}

_DEFAULT_RECOMMENDATION: dict = {
    "pqc_standard": "Review Required",
    "pqc_algorithm": "Consult NIST SP 800-131Ar3",
    "action": "Evaluate and migrate to NIST-approved algorithm",
    "rationale": "Algorithm not in ECDAT knowledge base. Manual review required.",
    "priority": "MEDIUM",
}


def get_recommendation(algorithm_name: str) -> dict:
    """
    Return the migration recommendation for *algorithm_name*.

    Matching is case-insensitive and substring-based so that identifiers like
    ``weak-rsa-key-size`` still resolve to the RSA entry.

    Parameters
    ----------
    algorithm_name : str
        The algorithm identifier extracted from a Semgrep finding.

    Returns
    -------
    dict
        Recommendation record from MIGRATION_MAP, or a default record.
    """
    upper = algorithm_name.upper().replace("SHA-1", "SHA1")
    for key, rec in sorted(MIGRATION_MAP.items(), key=lambda item: -len(item[0])):
        if key in upper:
            return dict(rec)
    return dict(_DEFAULT_RECOMMENDATION)


# Relative planning units, not invented hardware measurements. Real budgets are
# enforced only against user-supplied benchmark latency and monetary costs.
CANDIDATES = {
    "signature": [("ML-DSA-65", "NIST FIPS 204", 1, 2), ("SLH-DSA-SHA2-128s", "NIST FIPS 205", 8, 1)],
    "key-establishment": [("ML-KEM-768", "NIST FIPS 203", 1, 1), ("X25519 + ML-KEM-768 (hybrid)", "FIPS 203 + protocol-specific hybrid", 2, 2)],
    "encryption": [("AES-256-GCM", "NIST FIPS 197 / SP 800-38D", 1, 2), ("ChaCha20-Poly1305", "RFC 8439", 2, 1)],
    "hash": [("SHA-256", "NIST FIPS 180-4", 1, 1), ("SHA3-256", "NIST FIPS 202", 2, 2)],
}


def contextual_recommendation(component, context):
    name = component.get("name", "").upper()
    if component.get('type') in ('library', 'device'):
        return {'action': component.get('description', 'Review provider lifecycle and firmware support.'),
                'pqc_algorithm': '', 'pqc_standard': 'Not algorithm-specific',
                'rationale': 'Review the dependency or hardware provider upgrade path.', 'alternatives': []}
    usage = context.usage
    if usage == "auto":
        usage = component.get("discovery", {}).get("usage", "auto")
    if usage == "auto":
        usage = "signature" if any(k in name for k in ("DSA", "ED25519", "ED448")) else (
            "key-establishment" if any(k in name for k in ("RSA", "DH", "X25519", "X448", "TLS")) else (
                "hash" if any(k in name for k in ("SHA", "MD5", "HASH")) else "encryption"))
    benchmarks = {b.algorithm: b for b in context.benchmarks}
    candidates = []
    for algorithm, standard, latency, cost in CANDIDATES[usage]:
        benchmark = benchmarks.get(algorithm)
        candidates.append({"algorithm": algorithm, "standard": standard,
                           "relative_latency": latency, "relative_cost": cost,
                           "latency_ms": benchmark.latency_ms if benchmark else None,
                           "cost_per_million": benchmark.cost_per_million if benchmark else None})
    measured = all(c["algorithm"] in benchmarks for c in candidates)
    max_latency = max((c["latency_ms"] if measured else c["relative_latency"]) for c in candidates) or 1
    max_cost = max((c["cost_per_million"] if measured else c["relative_cost"]) for c in candidates) or 1
    for candidate in candidates:
        latency = candidate["latency_ms"] if measured else candidate["relative_latency"]
        cost = candidate["cost_per_million"] if measured else candidate["relative_cost"]
        candidate["weighted_score"] = round(context.latency_weight * latency / max_latency + context.cost_weight * cost / max_cost, 4)
        candidate["within_budget"] = all(limit is None or (value is not None and value <= limit) for limit, value in (
            (context.max_latency_ms, candidate["latency_ms"]), (context.max_cost_per_million, candidate["cost_per_million"])))
    candidates.sort(key=lambda c: (not c["within_budget"], c["weighted_score"]))
    chosen = candidates[0]
    issues = component.get("discovery", {}).get("issues", [])
    return {
        "pqc_algorithm": chosen["algorithm"], "pqc_standard": chosen["standard"],
        "action": f"Evaluate {chosen['algorithm']} for {usage}." + (" Remediate: " + "; ".join(issues) if issues else ""),
        "rationale": "Ranked using supplied benchmark measurements." if measured else "Ranked using relative planning estimates; benchmark on target hardware before deployment.",
        "usage": usage, "model": "measured" if measured else "relative-estimate",
        "budget_satisfied": chosen["within_budget"], "alternatives": candidates,
        "priority": component.get("risk", {}).get("level", "MEDIUM"),
    }
