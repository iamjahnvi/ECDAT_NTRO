# NTRO prototype + private GitHub repository flow (privacy-feature branch)

## 0. Prototype database (SQLite — separate from Supabase)

- **Technology:** stdlib `sqlite3`, zero new dependencies. File: `backend/data/ntro.db`
  (override with `NTRO_DB_PATH`; data dir auto-created; git-ignored, persists
  between restarts). Explicit init/seed: `python backend/seed_ntro_db.py`
  (also auto-initializes on first backend use).
- **Tables:** `ntro_employees` (id, employee_id UNIQUE, name, department, email,
  password_hash `salt$hash`, active, created_at, updated_at),
  `ntro_sessions` (token_hash PK, employee_id, created_at, expires_at, revoked),
  `github_authorizations` (UNIQUE employee_id → github_user JSON, Fernet-encrypted
  access token, scope, connected_at, updated_at). Reconnect = upsert.
- **Init/seed:** `python backend/seed_ntro_db.py` (`--reset` to reseed) or
  auto-created on first backend use (`ntro_database.init_db()`); demo
  employees seeded when missing (same `NTRO-DEMO-001/002` identities; only
  hashes stored). Delete `backend/data/ntro.db` (or `--reset`) to start over.
- **Seed passwords:** env-only (`NTRO_SEED_PASSWORD_001/002`, set before first
  init); absent → strong random passwords + log guidance (values never logged).
  No plaintext credential exists in code. Demo values for local testing are
  documented ONLY here: `demo-ntro-001` / `demo-ntro-002` (fictional prototype
  accounts) — export them as the seed env vars before first run to use them.
- **Token encryption at rest:** Fernet (existing `cryptography` dep), key from
  `NTRO_TOKEN_ENCRYPTION_KEY` (else legacy `NTRO_DB_ENCRYPTION_KEY` / `NTRO_JWT_SECRET`,
  else insecure dev default + warning). Placeholders only in
  `backend/.env.example`; real secrets stay in the ignored local `.env`, never committed.
- **Employee → GitHub relationship:** one authorization row per employee; every
  request resolves the token from the authenticated NTRO session identity —
  never from frontend input, never a global token.

## 1. Prototype NTRO authentication — WHY IT IS FICTIONAL/DEMO

`backend/ntro_auth.py` implements a **prototype identity boundary**, not real
employment verification. Accounts (`NTRO-DEMO-001` active, `NTRO-DEMO-002`
inactive-by-design) are fictional demo rows in the prototype database so the
end-to-end workflow can be exercised. The UI labels every such account
**DEMO / PROTOTYPE**.

- Passwords: PBKDF2-HMAC-SHA256 (210k rounds), `salt$hash` in SQLite only.
- Sessions: opaque `ntro_…` tokens backed by `ntro_sessions` rows (8h expiry,
  revocable — logout genuinely invalidates), sent via `X-NTRO-Token`
  (avoids clashing with the existing `ECDAT_API_KEY` bearer scheme).
- Demo credentials for local testing (prototype only, fictional accounts):
  `demo-ntro-001` / `demo-ntro-002` — export as `NTRO_SEED_PASSWORD_001/002`
  BEFORE first database initialization (see §0). Secrets `NTRO_TOKEN_ENCRYPTION_KEY` /
  `NTRO_JWT_SECRET` should also be set in production.
- Swap point: `NtroProvider` protocol + `get_provider()`. A future real NTRO
  SSO / LDAP / AD IdP implements the protocol — GitHub and scanner code
  depend on the interface, never on the store.

## 2. GitHub App setup (REAL authorization, minimum permissions)

1. Create a GitHub App (or OAuth App for development): User settings →
   Developer settings → GitHub Apps → New.
2. Permissions: **Repository → Contents: Read-only, Metadata: Read-only**.
3. Set the callback/redirect URL to `http://<backend-host>:8000/github/callback`.
4. Copy Client ID / Client Secret into backend env:
   `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
   (`GITHUB_APP_ID` informational, `GITHUB_FRONTEND_URL` default
   `http://localhost:5173`). See `backend/.env.example`. Never commit values.
5. Restart the backend (`.\start_backend.bat`).

If credentials are missing, `/github/config` reports `configured:false`,
the UI shows a setup error, and **local scanning keeps working**.

## 3. Required environment variables

| Variable | Where | Purpose |
|---|---|---|
| `NTRO_DB_PATH` | backend (opt) | SQLite file (default `backend/data/ntro.db`) |
| `NTRO_TOKEN_ENCRYPTION_KEY` | backend | Secret for stored GitHub tokens (set in prod) |
| `NTRO_SEED_PASSWORD_001/002` | backend | Demo seed passwords, set BEFORE first init |
| `NTRO_JWT_SECRET` | backend | Fallback secret (legacy name; set in prod) |
| `GITHUB_CLIENT_ID` | backend | GitHub App/OAuth client id |
| `GITHUB_CLIENT_SECRET` | backend | GitHub secret (backend only, never frontend) |
| `GITHUB_APP_ID` | backend (opt) | Informational |
| `GITHUB_FRONTEND_URL` | backend (opt) | Post-authorization redirect target |

## 4. Minimum permissions, multi-employee model & private repository flow

One GitHub App (or OAuth App) identity serves ALL employees: the Client
ID/Secret identify the ECDAT application, never an employee. Each employee
completes the OAuth consent screen with their own GitHub account and receives
a separate user-to-server token stored in their own `github_authorizations`
row — no App-installation reconfiguration is needed per employee, and no
repository-permission weakening was required. The current user-token model
supports the intended multi-employee prototype as-is (verified by
cross-employee isolation tests); moving to per-installation tokens later only
changes the token-exchange step, not the relationship model.

`repo,read:org` OAuth scope: the user sees **only** repos the authorized
identity can access (`GET /github/repos`, live from GitHub, private flagged
🔒/🌐 with description/branch/updated metadata). Selecting a repo +
`Analyze Repository` calls `POST /scan/github {repository, ref?}` which:
validates NTRO → loads THAT employee's token from the database → re-checks
`GET /repos/{owner}/{repo}` against the token (browser values never trusted)
→ shallow-clones with the existing `extraheader` credential model → optional
validated `ref` checkout.

## 5. How repository data enters the EXISTING scanner

`POST /scan/github` (`backend/main.py`) is an **adapter, not a scanner**:
temp dir → `run_semgrep_scan` → `scan_for_sensitive_data` +
`correlate_and_escalate` → `scan_dependencies` →
`transform_semgrep_to_cyclonedx` → `scan_materials` → `finalize_bom` — the
identical call sequence as `POST /scan`. No `github_scanner.py` exists.

## 6. Security assumptions

- Tokens backend-only (Fernet-encrypted SQLite vault); never in frontend
  storage/state, CBOM, Supabase history, logs, errors, URLs, or git. Clone
  token via process-env `extraheader`, never URL/argv. `GIT_TERMINAL_PROMPT=0`,
  120s clone timeout, `TemporaryDirectory` + `finally` cleanup,
  ZIP-slip/path-traversal/SSRF guards preserved. Cloned code is UNTRUSTED
  DATA: read-only analysis, never executed (no installs/builds/binaries/workflows).
- OAuth `state` is single-use, 10-min expiry (CSRF protection).
- NTRO sessions are server-side rows: logout revokes immediately; expiry purged
  opportunistically. The ECDAT (Supabase) account session is never touched by
  NTRO logout/disconnect.

## 7. Replacing the demo provider with real NTRO SSO

Implement `NtroProvider` (`authenticate`, `get_employee`) backed by the
official IdP, return it from `get_provider()` when configured, keep the
`X-NTRO-Token` session contract. No GitHub, retrieval, scanner, history, or
frontend-flow changes required.
