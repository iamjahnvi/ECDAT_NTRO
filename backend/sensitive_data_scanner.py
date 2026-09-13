"""
sensitive_data_scanner.py
Scans source files for sensitive data identifiers (PII, credentials, etc.) using regex.
Matches user-provided keywords in variable names and standard literal patterns.
"""

import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Standard literal regex patterns for sensitive data
LITERAL_PATTERNS = {
    "Credit Card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    "Private Key": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
}

def build_keyword_regex(keywords: list[str]) -> re.Pattern:
    """Build a regex to match any of the keywords case-insensitively as substrings in a word."""
    # We want to match variable names containing the keywords. e.g. user_password
    # so we just check if the keyword is inside a word boundary or simply present.
    # To avoid matching standard text, we can match word characters surrounding the keyword.
    # Actually, (?i).*(pass|ssn|credit|card|cvv|auth|token|secret|medical|iban).* was requested.
    escaped_keywords = [re.escape(k) for k in keywords if k]
    if not escaped_keywords:
        # If no keywords, match nothing
        return re.compile(r"(?!x)x")
    
    # We will match words that contain the keyword.
    # Example: \b\w*(?:password|ssn|secret)\w*\b
    pattern_str = r"\b\w*(?:" + "|".join(escaped_keywords) + r")\w*\b"
    return re.compile(pattern_str, re.IGNORECASE)

def scan_file_for_sensitive_data(file_path: Path, keyword_regex: re.Pattern) -> list[dict]:
    """Scan a single file for sensitive data line by line."""
    findings = []
    
    try:
        # Attempt to read as UTF-8 text
        text = file_path.read_text(encoding="utf-8", errors="replace")
        
        for line_idx, line in enumerate(text.splitlines()):
            line_num = line_idx + 1
            
            # Check literal patterns
            for data_type, regex in LITERAL_PATTERNS.items():
                if regex.search(line):
                    findings.append({
                        "file_path": str(file_path),
                        "line_number": line_num,
                        "variable_name": "Literal Match",
                        "sensitivity_type": f"Hardcoded {data_type}"
                    })
                    
            # Check keywords
            for match in keyword_regex.finditer(line):
                variable_name = match.group(0)
                findings.append({
                    "file_path": str(file_path),
                    "line_number": line_num,
                    "variable_name": variable_name,
                    "sensitivity_type": "Sensitive Keyword Match"
                })
                
    except Exception as e:
        logger.debug(f"Failed to scan file {file_path} for sensitive data: {e}")
        
    return findings

def scan_for_sensitive_data(target_dir: str, keywords: list[str]) -> list[dict]:
    """
    Recursively scan a directory for files and look for sensitive data.
    """
    target = Path(target_dir).resolve()
    findings = []
    
    if not target.exists():
        return findings

    keyword_regex = build_keyword_regex(keywords)
    
    # Skip directories that we usually ignore
    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__"}
    
    # We just walk all text-like files, filtering out typical binary extensions.
    # Since binary_scanner handles binaries, here we focus on source code.
    binary_exts = {".exe", ".dll", ".so", ".elf", ".bin", ".dylib", ".sys", ".o", ".jpg", ".png", ".pdf", ".zip", ".tar", ".gz"}
    
    if target.is_file():
        if target.suffix.lower() not in binary_exts:
            findings.extend(scan_file_for_sensitive_data(target, keyword_regex))
        return findings
    
    for root, dirs, files in os.walk(target):
        # Mutate dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() not in binary_exts:
                findings.extend(scan_file_for_sensitive_data(file_path, keyword_regex))
                
    return findings

# need os
import os
