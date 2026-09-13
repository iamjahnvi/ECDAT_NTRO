"""
risk_engine.py
Correlates cryptographic findings with sensitive data identifiers to escalate severity.
"""

import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

# Scope distance in lines to consider a sensitive finding "correlated" with a crypto finding
CORRELATION_DISTANCE = 15

def _normalize_path(path_str: str) -> str:
    """Normalize path strings for reliable comparison."""
    try:
        return str(Path(path_str).resolve())
    except Exception:
        return path_str

def correlate_and_escalate(crypto_findings: list[dict], sensitive_findings: list[dict]) -> list[dict]:
    """
    Correlates crypto findings with sensitive findings.
    If a sensitive data identifier is found within ±15 lines of a crypto operation,
    we escalate the risk.
    """
    if not sensitive_findings:
        return crypto_findings
        
    # Group sensitive findings by file
    sens_by_file = defaultdict(list)
    for sf in sensitive_findings:
        norm_path = _normalize_path(sf["file_path"])
        sens_by_file[norm_path].append(sf)
        
    for finding in crypto_findings:
        finding_path = finding.get("path")
        if not finding_path:
            continue
            
        norm_finding_path = _normalize_path(finding_path)
        file_sens_findings = sens_by_file.get(norm_finding_path, [])
        
        if not file_sens_findings:
            continue
            
        start_line = finding.get("start", {}).get("line", 0)
        end_line = finding.get("end", {}).get("line", start_line)
        
        # We find the closest sensitive finding
        correlated = None
        for sf in file_sens_findings:
            sf_line = sf["line_number"]
            # Check if sf_line is within ±15 lines of the crypto block
            if start_line - CORRELATION_DISTANCE <= sf_line <= end_line + CORRELATION_DISTANCE:
                correlated = sf
                break
                
        if correlated:
            # We found a correlation!
            # Let's escalate.
            current_severity = finding.get("extra", {}).get("severity", "WARNING").upper()
            alg = finding.get("extra", {}).get("metadata", {}).get("algorithm", "unknown algorithm")
            
            # The metadata dict might be missing or read-only, ensure we can mutate it
            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Attach context
            metadata["sensitive_data_context"] = {
                "is_sensitive": True,
                "data_type": correlated["sensitivity_type"],
                "variable": correlated["variable_name"],
                "escalation_reason": f"Severity escalated due to {correlated['sensitivity_type']} handled near cryptographic operation."
            }
            
            # Escalate severity to ERROR (CRITICAL in CycloneDX)
            if current_severity in ("WARNING", "INFO"):
                extra["severity"] = "ERROR"
                logger.info(f"Escalated finding in {finding_path} from {current_severity} to ERROR due to sensitive data.")
                
            # Write back
            extra["metadata"] = metadata
            finding["extra"] = extra
            
    return crypto_findings
