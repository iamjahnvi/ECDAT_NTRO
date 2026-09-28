"""
ntro_auth.py — Prototype NTRO identity boundary (DEMO / FICTIONAL).

This is a PROTOTYPE authentication layer. It does NOT verify that a real
person is an NTRO employee. Employee records live in a SEPARATE SQLite
prototype database (see ntro_database.py) — never in the ECDAT Supabase user system.

Modularity contract:
    class NtroProvider — interface with `authenticate()` / `get_employee()`.
    class DbNtroProvider(NtroProvider) — database-backed implementation.
    A future real NTRO SSO / LDAP / AD provider only needs to implement
    NtroProvider and be swapped in `get_provider()` — GitHub and scanning
    code depends on the interface, never on the store.

Security properties:
  - Passwords are NEVER stored in plaintext (PBKDF2-HMAC-SHA256, 210k rounds,
    `salt$hash` in the database; only hashes are ever compared).
  - Passwords are NEVER logged and NEVER returned by any endpoint.
  - Sessions are opaque server-side rows (8h TTL) looked up per request, so
    logout genuinely revokes: an old token stops working immediately.
  - The employee identity for every request comes from the authenticated
    backend session — never from a frontend-supplied employee ID.
  - Unknown employee / wrong password / inactive account all rejected with
    identical generic error text.
"""

from __future__ import annotations

import logging
from typing import Protocol

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

import ntro_database

logger = logging.getLogger("ecdat.ntro_auth")

router = APIRouter(prefix="/ntro", tags=["ntro"])

SESSION_TTL_SECONDS = ntro_database.SESSION_TTL_SECONDS
TOKEN_PREFIX = "ntro_"


def mint_session_token(employee_id: str, ttl: int = SESSION_TTL_SECONDS) -> str:
    """Create a persisted, revocable session. Kept by name for compatibility."""
    return ntro_database.create_session(employee_id, ttl=ttl)


def verify_session_token(token: str) -> str | None:
    """Return employee_id if the session is valid, else None."""
    employee = ntro_database.lookup_session(token or "")
    return employee["employee_id"] if employee else None


# ── Provider interface (swap point for real NTRO SSO/LDAP/AD) ────────────────

class NtroProvider(Protocol):
    def authenticate(self, employee_id: str, password: str) -> dict | None: ...
    def get_employee(self, employee_id: str) -> dict | None: ...


class DbNtroProvider:
    """Database-backed fictional-demo provider for the prototype."""

    def get_employee(self, employee_id: str) -> dict | None:
        return ntro_database.find_employee(employee_id)

    def authenticate(self, employee_id: str, password: str) -> dict | None:
        return ntro_database.verify_employee_password(employee_id, password)


def get_provider() -> NtroProvider:
    # Future: return RealNtroSsoProvider() when configured, without touching
    # GitHub or scanner code.
    return DbNtroProvider()


# ── FastAPI dependency ───────────────────────────────────────────────────────

def _extract_token(x_ntro_token: str | None, authorization: str | None) -> str | None:
    if x_ntro_token:
        return x_ntro_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()
        if candidate.startswith(TOKEN_PREFIX):
            return candidate
    return None


async def require_ntro_employee(
    x_ntro_token: str | None = Header(default=None, alias="X-NTRO-Token"),
    authorization: str | None = Header(default=None),
) -> dict:
    token = _extract_token(x_ntro_token, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="NTRO session required")
    employee = ntro_database.lookup_session(token)
    if not employee:
        raise HTTPException(status_code=401, detail="NTRO session expired or invalid")
    return employee


# ── Routes ───────────────────────────────────────────────────────────────────

class NtroLoginRequest(BaseModel):
    employee_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class NtroLoginResponse(BaseModel):
    token: str
    employee: dict


@router.post("/login", response_model=NtroLoginResponse, summary="Prototype NTRO demo login")
async def ntro_login(body: NtroLoginRequest):
    employee_id = body.employee_id.strip()
    employee = get_provider().authenticate(employee_id, body.password)
    if employee is None:
        # Log identity only — NEVER the password.
        logger.warning("NTRO demo login rejected for employee_id=%r", employee_id)
        raise HTTPException(status_code=401, detail="Invalid employee ID or password")
    token = ntro_database.create_session(employee["employee_id"])
    logger.info("NTRO demo login accepted for employee_id=%r", employee["employee_id"])
    return {"token": token, "employee": employee}


@router.get("/me", summary="Current prototype NTRO session")
async def ntro_me(employee: dict = Depends(require_ntro_employee)):
    return {"employee": employee, "demo": True, "prototype": True}


@router.post("/logout", summary="Revoke the current prototype NTRO session")
async def ntro_logout(
    employee: dict = Depends(require_ntro_employee),
    x_ntro_token: str | None = Header(default=None, alias="X-NTRO-Token"),
    authorization: str | None = Header(default=None),
):
    # Server-side revocation: the old token stops working immediately.
    # The ECDAT (Supabase) account session is untouched.
    token = _extract_token(x_ntro_token, authorization)
    if token:
        ntro_database.revoke_session(token)
    logger.info("NTRO session revoked for employee_id=%r", employee["employee_id"])
    return {"ok": True}
