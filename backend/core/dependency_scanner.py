"""
core/dependency_scanner.py
--------------------------
Production-grade recursive Software Composition Analysis (SCA) engine.

Ecosystems supported
---------------------
  Python  : requirements.txt, pyproject.toml, setup.py
  Node.js : package.json, package-lock.json
  Java    : pom.xml, build.gradle
  C/C++   : vcpkg.json, conanfile.txt, CMakeLists.txt

Advisory database
-----------------
A lightweight local advisory DB maps (normalised_package_name, ecosystem) →
list of advisory entries with CVE IDs, affected version constraints, severity,
and migration guidance.

Version constraints use ``packaging.version`` for reliable PEP 440-compatible
comparisons. For non-Python ecosystems, semver-style strings are normalised via
the same library. If a version cannot be parsed the advisory still fires at a
reduced confidence (``version_match="unparseable"``).

Return format (per finding)
---------------------------
{
    "package":         str,        # normalised package name
    "version":         str,        # detected version string (or "" if unknown)
    "ecosystem":       str,        # "python" | "nodejs" | "java" | "cpp"
    "file":            str,        # relative or absolute path to the manifest
    "cve_ids":         list[str],  # e.g. ["CVE-2013-7459"]
    "severity":        str,        # "critical" | "high" | "medium" | "info"
    "recommendation":  str,        # human-readable migration guidance
    "version_match":   str,        # "matched" | "unversioned" | "unparseable"
}
"""

from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

# ── Try packaging; fall back gracefully if somehow absent ─────────────────────
try:
    from packaging.version import Version, InvalidVersion
    _PACKAGING_AVAILABLE = True
except ImportError:
    logger.warning("'packaging' library not available — version comparisons disabled")
    _PACKAGING_AVAILABLE = False


# ── Advisory entry dataclass ──────────────────────────────────────────────────

class Advisory(NamedTuple):
    """A single vulnerability advisory record."""
    cve_ids:        list[str]
    severity:       str          # "critical" | "high" | "medium" | "info"
    affected_lt:    str | None   # flagged if detected_version < affected_lt  (None = all versions)
    affected_gte:   str | None   # flagged if detected_version >= affected_gte (None = no lower bound)
    recommendation: str


def _make_adv(cve_ids, severity, recommendation, affected_lt=None, affected_gte=None):
    return Advisory(cve_ids, severity, recommendation, affected_lt, affected_gte)


# ── Local cryptographic advisory database ─────────────────────────────────────
# Key: (normalised_package_name, ecosystem)
# Value: list[Advisory]  — multiple advisories per package are supported.

ADVISORY_DB: dict[tuple[str, str], list[Advisory]] = {

    # ── Python ────────────────────────────────────────────────────────────────

    ("pycrypto", "python"): [_make_adv(
        cve_ids=["CVE-2013-7459", "CVE-2018-6594"],
        severity="critical",
        recommendation=(
            "pycrypto is unmaintained and contains multiple critical vulnerabilities. "
            "Migrate to the `cryptography` package (pip install cryptography)."
        ),
    )],

    ("pycryptodome", "python"): [_make_adv(
        cve_ids=["CVE-2023-52323"],
        severity="high",
        affected_lt="3.19.1",
        recommendation=(
            "pycryptodome < 3.19.1 is vulnerable to CVE-2023-52323 (Bleichenbacher timing side-channel in PKCS#1 v1.5). "
            "Upgrade to pycryptodome >= 3.19.1."
        ),
    )],

    ("pyopenssl", "python"): [_make_adv(
        cve_ids=["CVE-2023-49083"],
        severity="high",
        affected_lt="23.3.0",
        recommendation=(
            "pyOpenSSL < 23.3.0 may expose vulnerabilities via bundled OpenSSL < 3.0. "
            "Upgrade to pyOpenSSL >= 23.3.0 and ensure OpenSSL >= 3.0 is installed on the host."
        ),
    )],

    ("cryptography", "python"): [_make_adv(
        cve_ids=["CVE-2023-49083", "CVE-2024-26130"],
        severity="high",
        affected_lt="42.0.4",
        recommendation=(
            "cryptography < 42.0.4 contains known vulnerabilities including a NULL pointer dereference "
            "(CVE-2024-26130). Upgrade to >= 42.0.4."
        ),
    )],

    ("md5-hash", "python"): [_make_adv(
        cve_ids=[],
        severity="critical",
        recommendation=(
            "md5-hash uses the cryptographically broken MD5 algorithm. "
            "Migrate to hashlib.sha256() or SHA-3."
        ),
    )],

    ("paramiko", "python"): [_make_adv(
        cve_ids=["CVE-2023-48795"],
        severity="medium",
        affected_lt="3.4.0",
        recommendation=(
            "paramiko < 3.4.0 is vulnerable to CVE-2023-48795 (Terrapin SSH prefix truncation attack). "
            "Upgrade to >= 3.4.0."
        ),
    )],

    ("itsdangerous", "python"): [_make_adv(
        cve_ids=["CVE-2022-2068"],
        severity="medium",
        affected_lt="2.0.0",
        recommendation=(
            "itsdangerous < 2.0.0 uses HMAC with a deprecated hash function. "
            "Upgrade to >= 2.0.0."
        ),
    )],

    # ── Node.js ───────────────────────────────────────────────────────────────

    ("node-forge", "nodejs"): [_make_adv(
        cve_ids=["CVE-2022-0122", "CVE-2022-24771", "CVE-2022-24772", "CVE-2022-24773"],
        severity="critical",
        affected_lt="1.3.0",
        recommendation=(
            "node-forge < 1.3.0 has multiple critical vulnerabilities including RSA PKCS#1 padding oracle "
            "(CVE-2022-24771) and URL parsing bypass (CVE-2022-0122). Upgrade to >= 1.3.0 or migrate to WebCrypto."
        ),
    )],

    ("crypto-js", "nodejs"): [_make_adv(
        cve_ids=["CVE-2023-46233"],
        severity="critical",
        affected_lt="4.2.0",
        recommendation=(
            "crypto-js < 4.2.0 is vulnerable to CVE-2023-46233 — PBKDF2 1000x less secure than expected due "
            "to insecure default. Upgrade to >= 4.2.0."
        ),
    )],

    ("md5", "nodejs"): [_make_adv(
        cve_ids=[],
        severity="critical",
        recommendation=(
            "The `md5` npm package uses the cryptographically broken MD5 algorithm. "
            "Migrate to native `crypto.createHash('sha256')` or the `sha.js` package."
        ),
    )],

    ("sha1", "nodejs"): [_make_adv(
        cve_ids=[],
        severity="high",
        recommendation=(
            "The `sha1` npm package uses the cryptographically weak SHA-1 algorithm. "
            "Migrate to native `crypto.createHash('sha256')`."
        ),
    )],

    ("bcryptjs", "nodejs"): [_make_adv(
        cve_ids=[],
        severity="info",
        recommendation=(
            "bcryptjs is a pure-JS bcrypt implementation — it is suitable for password hashing "
            "but consider argon2 (via the `argon2` package) for new implementations."
        ),
    )],

    ("elliptic", "nodejs"): [_make_adv(
        cve_ids=["CVE-2020-28498"],
        severity="high",
        affected_lt="6.5.4",
        recommendation=(
            "elliptic < 6.5.4 is vulnerable to CVE-2020-28498 (timing side-channel in ECDSA). "
            "Upgrade to >= 6.5.4."
        ),
    )],

    ("jsonwebtoken", "nodejs"): [_make_adv(
        cve_ids=["CVE-2022-23529", "CVE-2022-23539"],
        severity="high",
        affected_lt="9.0.0",
        recommendation=(
            "jsonwebtoken < 9.0.0 is vulnerable to multiple CVEs including CVE-2022-23529 "
            "(insecure secret verification). Upgrade to >= 9.0.0."
        ),
    )],

    # ── Java ──────────────────────────────────────────────────────────────────

    ("org.bouncycastle:bcprov-jdk15on", "java"): [_make_adv(
        cve_ids=["CVE-2023-33201", "CVE-2023-33202"],
        severity="high",
        affected_lt="1.76",
        recommendation=(
            "BouncyCastle bcprov-jdk15on < 1.76 is vulnerable to CVE-2023-33201 (LDAP injection in X.500 names) "
            "and CVE-2023-33202 (DoS in ASN.1 parsing). Upgrade to bcprov-jdk18on >= 1.76."
        ),
    )],

    ("org.bouncycastle:bcprov-jdk18on", "java"): [_make_adv(
        cve_ids=["CVE-2024-34447"],
        severity="medium",
        affected_lt="1.78",
        recommendation=(
            "BouncyCastle bcprov-jdk18on < 1.78 is vulnerable to CVE-2024-34447. "
            "Upgrade to >= 1.78."
        ),
    )],

    ("commons-codec:commons-codec", "java"): [_make_adv(
        cve_ids=[],
        severity="info",
        recommendation=(
            "Apache Commons Codec includes MD5 and SHA-1 utilities. "
            "Audit usages to ensure only SHA-256 or stronger hashes are used in security-sensitive paths."
        ),
    )],

    ("io.jsonwebtoken:jjwt", "java"): [_make_adv(
        cve_ids=["CVE-2022-21449"],
        severity="critical",
        affected_lt="0.12.0",
        recommendation=(
            "jjwt < 0.12.0 uses algorithms susceptible to CVE-2022-21449 (Psychic Signatures — "
            "blank ECDSA signature accepted on JDK 15-17). Upgrade to >= 0.12.0."
        ),
    )],

    # ── C/C++ (via vcpkg / conan / CMake) ────────────────────────────────────

    ("openssl", "cpp"): [_make_adv(
        cve_ids=["CVE-2022-0778", "CVE-2023-0286", "CVE-2024-0727"],
        severity="critical",
        affected_lt="3.0.0",
        recommendation=(
            "OpenSSL < 3.0.0 is end-of-life and has numerous critical CVEs including "
            "CVE-2022-0778 (infinite loop DoS) and CVE-2023-0286 (GeneralName type confusion). "
            "Upgrade to OpenSSL >= 3.0.8."
        ),
    )],

    ("libsodium", "cpp"): [_make_adv(
        cve_ids=[],
        severity="info",
        recommendation=(
            "libsodium is a secure, modern cryptographic library. "
            "No known critical vulnerabilities in current stable release."
        ),
    )],

    ("botan", "cpp"): [_make_adv(
        cve_ids=["CVE-2023-49922"],
        severity="medium",
        affected_lt="3.2.0",
        recommendation=(
            "Botan < 3.2.0 is vulnerable to CVE-2023-49922 (timing side-channel in ECDSA). "
            "Upgrade to >= 3.2.0."
        ),
    )],
}


# ── Ignored manifest files (avoid scanning our own backend's lock files) ──────
_IGNORE_DIRS = frozenset({
    ".git", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".tox", "dist", "build", "target",
    ".gradle", ".mvn", "vendor", "bin", "obj",
})

_IGNORE_DIR_PATTERNS = [
    re.compile(r"^\."),          # hidden dirs
]


def _should_skip_dir(name: str) -> bool:
    if name in _IGNORE_DIRS:
        return True
    return any(p.match(name) for p in _IGNORE_DIR_PATTERNS)


# ── Version comparison helpers ────────────────────────────────────────────────

def _parse_version(v: str) -> "Version | None":
    if not _PACKAGING_AVAILABLE or not v:
        return None
    try:
        return Version(v.strip().lstrip("v=^~"))
    except Exception:
        return None


def _version_is_affected(detected_ver: str, adv: Advisory) -> tuple[bool, str]:
    """
    Return (is_affected, match_reason).
    match_reason: "matched" | "unversioned" | "unparseable"
    """
    if not detected_ver:
        return True, "unversioned"  # no version info → assume affected (conservative)

    parsed = _parse_version(detected_ver)
    if parsed is None:
        return True, "unparseable"

    # Check lower bound (gte)
    if adv.affected_gte is not None:
        gte_parsed = _parse_version(adv.affected_gte)
        if gte_parsed and parsed < gte_parsed:
            return False, "not_in_range"

    # Check upper bound (lt)
    if adv.affected_lt is not None:
        lt_parsed = _parse_version(adv.affected_lt)
        if lt_parsed and parsed >= lt_parsed:
            return False, "patched"

    return True, "matched"


# ── Per-ecosystem manifest parsers ────────────────────────────────────────────

def _norm_pkg(name: str) -> str:
    """Normalise a package name: lowercase, replace hyphens/underscores uniformly."""
    return name.lower().replace("_", "-").strip()


# ─── Python ───────────────────────────────────────────────────────────────────

_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~^]+\s*([\d][^\s,;#]*))?"
)

def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Return list of (normalised_package, version) from requirements.txt."""
    results = []
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQ_LINE_RE.match(line)
            if m:
                results.append((_norm_pkg(m.group(1)), m.group(2) or ""))
    except Exception as exc:
        logger.debug("requirements.txt parse error %s: %s", path, exc)
    return results


_TOML_DEP_RE = re.compile(
    r'"?([A-Za-z0-9_\-\.]+)"?\s*=\s*["\{]?\s*\*?[><=!~^]?\s*([\d][^"\s,}]*)?'
)

def _parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    """Lightweight regex-based pyproject.toml parser (avoids tomllib compat issues)."""
    results = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        # Find [project] or [tool.poetry.dependencies] sections
        in_dep_section = False
        for line in text.splitlines():
            stripped = line.strip()
            if re.match(r"^\[(tool\.poetry\.dependencies|project)\]", stripped):
                in_dep_section = True
                continue
            if stripped.startswith("[") and in_dep_section:
                in_dep_section = False
            if in_dep_section:
                m = _TOML_DEP_RE.match(stripped)
                if m and m.group(1).lower() not in ("python", "requires-python"):
                    results.append((_norm_pkg(m.group(1)), m.group(2) or ""))
    except Exception as exc:
        logger.debug("pyproject.toml parse error %s: %s", path, exc)
    return results


_SETUP_REQUIRES_RE = re.compile(
    r'["\']([A-Za-z0-9_\-\.]+)\s*(?:[><=!~^]+\s*([\d][^"\']*))?"\'',
)

def _parse_setup_py(path: Path) -> list[tuple[str, str]]:
    """Regex scan of install_requires=[...] in setup.py."""
    results = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        in_requires = False
        for line in text.splitlines():
            if "install_requires" in line:
                in_requires = True
            if in_requires:
                for m in _SETUP_REQUIRES_RE.finditer(line):
                    results.append((_norm_pkg(m.group(1)), m.group(2) or ""))
                if "]" in line:
                    break
    except Exception as exc:
        logger.debug("setup.py parse error %s: %s", path, exc)
    return results


# ─── Node.js ──────────────────────────────────────────────────────────────────

def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse dependencies + devDependencies from package.json."""
    results = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver_spec in (data.get(section) or {}).items():
                # ver_spec may be "^1.2.3", "~2.0", "1.x", "latest", "file:...", etc.
                ver = re.sub(r"^[\^~>=<]", "", str(ver_spec)).strip()
                results.append((_norm_pkg(pkg), ver))
    except Exception as exc:
        logger.debug("package.json parse error %s: %s", path, exc)
    return results


def _parse_package_lock_json(path: Path) -> list[tuple[str, str]]:
    """Parse locked versions from package-lock.json (v2/v3 format)."""
    results = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        # v2/v3: 'packages' key; v1: 'dependencies' key
        packages = data.get("packages", data.get("dependencies", {}))
        for raw_name, info in packages.items():
            # v2 format uses "node_modules/pkg" as the key
            pkg = raw_name.lstrip("/").removeprefix("node_modules/")
            if not pkg:
                continue  # skip root entry
            ver = info.get("version", "") if isinstance(info, dict) else ""
            results.append((_norm_pkg(pkg), ver))
    except Exception as exc:
        logger.debug("package-lock.json parse error %s: %s", path, exc)
    return results


# ─── Java ─────────────────────────────────────────────────────────────────────

_POM_NS_RE = re.compile(r"\{[^}]+\}")

def _strip_ns(tag: str) -> str:
    return _POM_NS_RE.sub("", tag)

def _parse_pom_xml(path: Path) -> list[tuple[str, str]]:
    """Extract groupId:artifactId + version from pom.xml dependencies."""
    results = []
    try:
        root = ET.parse(path).getroot()
        # properties for ${...} interpolation
        props: dict[str, str] = {}
        for prop_el in root.iter():
            if _strip_ns(prop_el.tag) == "properties":
                for child in prop_el:
                    props[_strip_ns(child.tag)] = (child.text or "").strip()

        def _resolve(val: str) -> str:
            m = re.search(r"\$\{([^}]+)\}", val)
            if m:
                return props.get(m.group(1), val)
            return val

        for dep in root.iter():
            if _strip_ns(dep.tag) != "dependency":
                continue
            children = {_strip_ns(c.tag): (c.text or "").strip() for c in dep}
            group_id    = _resolve(children.get("groupId", ""))
            artifact_id = _resolve(children.get("artifactId", ""))
            version     = _resolve(children.get("version", ""))
            if group_id and artifact_id:
                # Key used in advisory DB: "groupId:artifactId"
                coord = f"{group_id}:{artifact_id}"
                results.append((_norm_pkg(coord), version))
    except Exception as exc:
        logger.debug("pom.xml parse error %s: %s", path, exc)
    return results


_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s+
        ['"]([\w\.\-]+):([\w\.\-]+):([\d][^'"]*)['"]\s*""",
    re.VERBOSE,
)

def _parse_build_gradle(path: Path) -> list[tuple[str, str]]:
    """Regex parse of Gradle build files (Groovy & Kotlin DSL)."""
    results = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _GRADLE_DEP_RE.finditer(text):
            coord = f"{m.group(1)}:{m.group(2)}"
            results.append((_norm_pkg(coord), m.group(3)))
    except Exception as exc:
        logger.debug("build.gradle parse error %s: %s", path, exc)
    return results


# ─── C / C++ ──────────────────────────────────────────────────────────────────

def _parse_vcpkg_json(path: Path) -> list[tuple[str, str]]:
    """Parse vcpkg.json dependencies."""
    results = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                results.append((_norm_pkg(dep), ""))
            elif isinstance(dep, dict):
                name = dep.get("name", "")
                ver  = dep.get("version", dep.get("version-string", ""))
                if name:
                    results.append((_norm_pkg(name), ver))
    except Exception as exc:
        logger.debug("vcpkg.json parse error %s: %s", path, exc)
    return results


_CONAN_REQUIRES_RE = re.compile(r"^([A-Za-z0-9_\-]+)/([0-9][^\s@#]*)(?:@|$)")

def _parse_conanfile_txt(path: Path) -> list[tuple[str, str]]:
    """Parse [requires] section of conanfile.txt."""
    results = []
    try:
        in_requires = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped == "[requires]":
                in_requires = True
                continue
            if stripped.startswith("[") and in_requires:
                break
            if in_requires and stripped:
                m = _CONAN_REQUIRES_RE.match(stripped)
                if m:
                    results.append((_norm_pkg(m.group(1)), m.group(2)))
    except Exception as exc:
        logger.debug("conanfile.txt parse error %s: %s", path, exc)
    return results


_CMAKE_FIND_PKG_RE = re.compile(
    r"find_package\s*\(\s*([A-Za-z0-9_]+)\s+([0-9][^\s)]*)?",
    re.IGNORECASE,
)
_CMAKE_LINK_RE = re.compile(
    r"target_link_libraries\s*\([^)]*\b(ssl|crypto|openssl|libsodium|botan)\b",
    re.IGNORECASE,
)

def _parse_cmakelists(path: Path) -> list[tuple[str, str]]:
    """Detect cryptographic library links in CMakeLists.txt."""
    results = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _CMAKE_FIND_PKG_RE.finditer(text):
            pkg_name = m.group(1).lower()
            ver      = (m.group(2) or "").strip()
            if pkg_name in ("openssl", "libsodium", "botan", "mbedtls", "wolfssl"):
                results.append((_norm_pkg(pkg_name), ver))
        for m in _CMAKE_LINK_RE.finditer(text):
            pkg = m.group(1).lower()
            if pkg in ("ssl", "crypto"):
                pkg = "openssl"
            results.append((_norm_pkg(pkg), ""))
    except Exception as exc:
        logger.debug("CMakeLists.txt parse error %s: %s", path, exc)
    # Deduplicate
    seen: set[tuple[str, str]] = set()
    deduped = []
    for item in results:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


# ── Manifest dispatch table ───────────────────────────────────────────────────

# (filename, ecosystem, parser_function)
MANIFEST_PARSERS: list[tuple[str, str, callable]] = [
    ("requirements.txt",    "python",  _parse_requirements_txt),
    ("pyproject.toml",      "python",  _parse_pyproject_toml),
    ("setup.py",            "python",  _parse_setup_py),
    ("package.json",        "nodejs",  _parse_package_json),
    ("package-lock.json",   "nodejs",  _parse_package_lock_json),
    ("pom.xml",             "java",    _parse_pom_xml),
    ("build.gradle",        "java",    _parse_build_gradle),
    ("build.gradle.kts",    "java",    _parse_build_gradle),
    ("vcpkg.json",          "cpp",     _parse_vcpkg_json),
    ("conanfile.txt",       "cpp",     _parse_conanfile_txt),
    ("CMakeLists.txt",      "cpp",     _parse_cmakelists),
]

# Build fast filename → (ecosystem, parser) lookup
_PARSER_BY_FILENAME: dict[str, tuple[str, callable]] = {
    fname: (ecosystem, fn)
    for fname, ecosystem, fn in MANIFEST_PARSERS
}


# ── Advisory lookup ───────────────────────────────────────────────────────────

def _check_advisories(
    package: str,
    version: str,
    ecosystem: str,
    manifest_path: str,
) -> list[dict]:
    """Return zero or more findings for a (package, version, ecosystem) triple."""
    advisories = ADVISORY_DB.get((package, ecosystem), [])
    findings = []
    for adv in advisories:
        is_affected, match_reason = _version_is_affected(version, adv)
        if not is_affected:
            continue
        findings.append({
            "package":        package,
            "version":        version,
            "ecosystem":      ecosystem,
            "file":           manifest_path,
            "cve_ids":        adv.cve_ids,
            "severity":       adv.severity,
            "recommendation": adv.recommendation,
            "version_match":  match_reason,
        })
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_dependencies(target_directory: str) -> list[dict]:
    """
    Recursively scan *target_directory* for package manifests across all
    supported ecosystems and return advisory findings.

    Parameters
    ----------
    target_directory : str
        Root directory of the project to scan.

    Returns
    -------
    list[dict]
        Zero or more finding dicts (format described in module docstring).
    """
    target = Path(target_directory).resolve()
    all_findings: list[dict] = []

    if not target.exists() or not target.is_dir():
        logger.warning("scan_dependencies: target does not exist or is not a dir: %s", target)
        return all_findings

    logger.info("SCA recursive scan starting at: %s", target)
    manifest_count = 0

    for root_str, dirs, files in os.walk(target):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if not _should_skip_dir(d)]

        for filename in files:
            if filename not in _PARSER_BY_FILENAME:
                continue

            manifest_path = Path(root_str) / filename
            ecosystem, parser = _PARSER_BY_FILENAME[filename]
            manifest_count += 1

            try:
                packages = parser(manifest_path)
            except Exception as exc:
                logger.warning("Parser error for %s: %s", manifest_path, exc)
                continue

            for pkg_name, pkg_version in packages:
                findings = _check_advisories(
                    package=pkg_name,
                    version=pkg_version,
                    ecosystem=ecosystem,
                    manifest_path=str(manifest_path),
                )
                all_findings.extend(findings)

    logger.info(
        "SCA complete — %d manifest(s) scanned, %d finding(s) across %s",
        manifest_count, len(all_findings), target,
    )
    return all_findings
