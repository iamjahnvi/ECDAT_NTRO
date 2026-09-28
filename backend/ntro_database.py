"""
ntro_database.py — SQLite-backed prototype store (SEPARATE from ECDAT Supabase auth).

A REAL persistent relational database (no server, no paid service) holding,
for the NTRO prototype only:
  1. ntro_employees        — fictional demo employee records (hashes, never plaintext)
  2. ntro_sessions         — opaque server-side sessions (revocable → logout really logs out)
  3. github_authorizations  — one row per employee (UNIQUE employee_id), token
     Fernet-encrypted at rest with an environment-provided secret.

Location: backend/data/ntro.db by default ($NTRO_DB_PATH overrides).
The data directory is created automatically; the file is git-ignored but
ALWAYS created locally by initialization — never a theoretical schema.
Every operation opens a short-lived connection, so a backend restart sees the
same persisted data with no cache to invalidate. Repeated initialization is
idempotent: demo employees are seeded only when missing (no duplicates).

Seed passwords come ONLY from the environment (NTRO_SEED_PASSWORD_001/002).
No plaintext password exists anywhere in this module. If a seed variable is
absent, a strong random password is generated for that account and the log
explains how to configure known demo credentials — the generated value itself
is never logged, returned, or committed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("ecdat.ntro_database")

SESSION_TTL_SECONDS = 8 * 3600
_PBKDF2_ROUNDS = 210_000
_initialized_paths: set[str] = set()
_warned_insecure_key = False


# ── Paths & connections ──────────────────────────────────────────────────────

def db_path() -> Path:
    configured = os.environ.get("NTRO_DB_PATH", "")
    if configured:
        return Path(configured)
    return Path(__file__).parent / "data" / "ntro.db"


def _connect() -> sqlite3.Connection:
    path = db_path()
    parent = path.parent
    if str(parent) not in ("", "."):
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Password hashing (PBKDF2-HMAC-SHA256, same strength as before) ───────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), _PBKDF2_ROUNDS
        ).hex()
        return hmac.compare_digest(candidate, hash_hex)
    except Exception:
        return False


# ── Token encryption at rest (Fernet, env-provided secret) ───────────────────

def _fernet():
    from cryptography.fernet import Fernet
    global _warned_insecure_key
    secret = (os.environ.get("NTRO_TOKEN_ENCRYPTION_KEY")
              or os.environ.get("NTRO_DB_ENCRYPTION_KEY")
              or os.environ.get("NTRO_JWT_SECRET") or "")
    if not secret:
        if not _warned_insecure_key:
            logger.warning(
                "NTRO_TOKEN_ENCRYPTION_KEY is not set — GitHub tokens are encrypted "
                "with an insecure dev-only key. Set NTRO_TOKEN_ENCRYPTION_KEY.")
            _warned_insecure_key = True
        secret = "ntro-prototype-dev-only-do-not-use-in-prod"
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_token(access_token: str) -> str:
    return _fernet().encrypt(access_token.encode()).decode()


def decrypt_token(blob: str) -> str:
    return _fernet().decrypt(blob.encode()).decode()


# ── Schema + seed ────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ntro_employees (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id   TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    department    TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ntro_sessions (
    token_hash  TEXT PRIMARY KEY,
    employee_id TEXT NOT NULL REFERENCES ntro_employees(employee_id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS github_authorizations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id   TEXT NOT NULL UNIQUE REFERENCES ntro_employees(employee_id),
    github_user   TEXT NOT NULL DEFAULT '{}',
    access_token  TEXT NOT NULL,
    scope         TEXT NOT NULL DEFAULT '',
    connected_at  TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
"""

# Fictional demo employees (prototype only). Seed passwords are supplied via
# NTRO_SEED_PASSWORD_001 / NTRO_SEED_PASSWORD_002; when absent, strong random
# passwords are generated so no plaintext credential ever lives in this file.
_SEED_EMPLOYEES = [
    {"employee_id": "NTRO-DEMO-001", "name": "Aarav Sharma",
     "department": "Quantum Security Lab", "email": "aarav.sharma@ntro.demo",
     "active": True, "env_password": "NTRO_SEED_PASSWORD_001"},
    {"employee_id": "NTRO-DEMO-002", "name": "Meera Iyer",
     "department": "Cryptography Review Cell", "email": "meera.iyer@ntro.demo",
     "active": True, "env_password": "NTRO_SEED_PASSWORD_002"},
    {"employee_id": "NTRO-DEMO-003", "name": "Avika Goel",
      "department": "Cryptography Review Cell", "email": "avika.geol@ntro.demo",
      "active": True, "env_password": "NTRO_SEED_PASSWORD_003"},
]


def _seed_password(entry: dict) -> str:
    password = os.environ.get(entry["env_password"], "")
    if password:
        return password
    generated = secrets.token_urlsafe(24)
    logger.warning(
        "%s is not set — generated a random password for %s. To use known "
        "demo credentials, set %s before (re)creating the database.",
        entry["env_password"], entry["employee_id"], entry["env_password"])
    return generated


def init_db() -> Path:
    """Create directory/file/tables and seed demo employees (idempotent)."""
    path = db_path()
    if str(path) in _initialized_paths:
        return path
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        for entry in _SEED_EMPLOYEES:
            exists = conn.execute(
                "SELECT 1 FROM ntro_employees WHERE employee_id = ?",
                (entry["employee_id"],)).fetchone()
            if exists is None:
                now = _now_iso()
                conn.execute(
                    "INSERT INTO ntro_employees "
                    "(employee_id, name, department, email, password_hash, active, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (entry["employee_id"], entry["name"], entry["department"],
                     entry["email"], hash_password(_seed_password(entry)),
                     1 if entry["active"] else 0, now, now))
                logger.info("Seeded NTRO demo employee %s", entry["employee_id"])
    _initialized_paths.add(str(path))
    return path


def _ensure() -> None:
    init_db()


# ── Employees ────────────────────────────────────────────────────────────────

def find_employee(employee_id: str) -> dict | None:
    """Safe public record (never includes password hash)."""
    _ensure()
    with _connect() as conn:
        row = conn.execute(
            "SELECT employee_id, name, department, email, active FROM ntro_employees "
            "WHERE employee_id = ?", (employee_id.strip(),)).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["active"] = bool(record["active"])
    return record


def verify_employee_password(employee_id: str, password: str) -> dict | None:
    """DB-backed credential check: unknown / wrong / inactive → None."""
    _ensure()
    with _connect() as conn:
        row = conn.execute(
            "SELECT employee_id, name, department, email, password_hash, active "
            "FROM ntro_employees WHERE employee_id = ?", (employee_id.strip(),)).fetchone()
    if row is None or not row["active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return {"employee_id": row["employee_id"], "name": row["name"],
            "department": row["department"], "email": row["email"], "active": True}


def create_employee(employee_id: str, name: str, department: str, password: str,
                    email: str = "", active: bool = True) -> dict:
    """Insert a new employee (password hashed, never stored plaintext)."""
    _ensure()
    now = _now_iso()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO ntro_employees "
            "(employee_id, name, department, email, password_hash, active, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (employee_id.strip(), name, department, email,
             hash_password(password), 1 if active else 0, now, now))
    record = find_employee(employee_id)
    assert record is not None
    return record


# ── Sessions (opaque, revocable) ─────────────────────────────────────────────

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(employee_id: str, ttl: int = SESSION_TTL_SECONDS) -> str:
    from datetime import timedelta
    _ensure()
    token = "ntro_" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO ntro_sessions (token_hash, employee_id, created_at, expires_at, revoked)"
            " VALUES (?, ?, ?, ?, 0)",
            (_token_hash(token), employee_id, now.isoformat(),
             (now + timedelta(seconds=ttl)).isoformat()))
    return token


def lookup_session(token: str) -> dict | None:
    """Resolve a session token to its ACTIVE employee, or None.

    Identity always comes from this server-side lookup — never from a
    frontend-supplied employee ID.
    """
    _ensure()
    if not token or not token.startswith("ntro_"):
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT s.employee_id, s.expires_at, s.revoked, e.name, e.department, e.email, e.active"
            " FROM ntro_sessions s JOIN ntro_employees e ON e.employee_id = s.employee_id"
            " WHERE s.token_hash = ?", (_token_hash(token),)).fetchone()
        if row is None or row["revoked"]:
            return None
        try:
            expired = datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc)
        except ValueError:
            return None
        if expired or not row["active"]:
            return None
        # Opportunistically purge expired sessions.
        conn.execute("DELETE FROM ntro_sessions WHERE expires_at <= ?",
                     (datetime.now(timezone.utc).isoformat(),))
    return {"employee_id": row["employee_id"], "name": row["name"],
            "department": row["department"], "email": row["email"], "active": True}


def revoke_session(token: str) -> bool:
    _ensure()
    with _connect() as conn:
        cur = conn.execute("UPDATE ntro_sessions SET revoked = 1 WHERE token_hash = ?",
                           (_token_hash(token),))
        return cur.rowcount > 0


# ── GitHub authorizations (one row per employee, token encrypted) ────────────

def save_github_auth(employee_id: str, access_token: str, scope: str, github_user: dict) -> None:
    """Upsert (reconnect cleanly replaces) the employee's authorization."""
    import json
    _ensure()
    safe_user = {"login": github_user.get("login"), "id": github_user.get("id"),
                 "type": github_user.get("type"), "avatar_url": github_user.get("avatar_url")}
    now = _now_iso()
    blob = encrypt_token(access_token)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO github_authorizations "
            "(employee_id, github_user, access_token, scope, connected_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(employee_id) DO UPDATE SET github_user=excluded.github_user,"
            " access_token=excluded.access_token, scope=excluded.scope, updated_at=excluded.updated_at",
            (employee_id, json.dumps(safe_user), blob, scope or "", now, now))


def get_github_auth(employee_id: str) -> dict | None:
    import json
    _ensure()
    with _connect() as conn:
        row = conn.execute(
            "SELECT github_user, access_token, scope, connected_at FROM github_authorizations"
            " WHERE employee_id = ?", (employee_id,)).fetchone()
    if row is None:
        return None
    try:
        access_token = decrypt_token(row["access_token"])
    except Exception:
        logger.warning("Stored GitHub authorization for employee is undecryptable")
        return None
    return {"access_token": access_token, "scope": row["scope"],
            "github_user": json.loads(row["github_user"]),
            "connected_at": row["connected_at"]}


def delete_github_auth(employee_id: str) -> bool:
    _ensure()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM github_authorizations WHERE employee_id = ?",
                           (employee_id,))
        return cur.rowcount > 0
