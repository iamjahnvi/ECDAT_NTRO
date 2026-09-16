"""Tests for the NTRO prototype + private GitHub adapter (privacy-feature).

All GitHub interactions are mocked — no real credentials required.
Runs against an isolated throwaway SQLite database (never the dev DB):
seed passwords are fixed test values, so demo logins are deterministic.
"""
import importlib
import json
import os
import sys
import tempfile
from types import SimpleNamespace as NS

_test_dir = tempfile.mkdtemp(prefix="ntro_test_")
os.environ["NTRO_DB_PATH"] = os.path.join(_test_dir, "test.db")
os.environ["NTRO_SEED_PASSWORD_001"] = "demo-ntro-001"
os.environ["NTRO_SEED_PASSWORD_002"] = "demo-ntro-002"
os.environ["NTRO_TOKEN_ENCRYPTION_KEY"] = "test-only-encryption-key"

from fastapi.testclient import TestClient

import main
import github_auth
import ntro_auth
import ntro_database
from github_auth import normalize_repo


def _client():
    return TestClient(main.app, raise_server_exceptions=False)


def _ntro_login(client, employee_id="NTRO-DEMO-001", password="demo-ntro-001"):
    return client.post("/ntro/login", json={"employee_id": employee_id, "password": password})


def _ntro_headers(client):
    resp = _ntro_login(client)
    assert resp.status_code == 200, resp.text
    return {"X-NTRO-Token": resp.json()["token"]}


def _seed_github(employee_id="NTRO-DEMO-001", token="gho_test_token_xyz"):
    github_auth.save_authorization(
        employee_id, token, "repo",
        {"login": "octo", "id": 1, "type": "User"})


# ── NTRO authentication boundary ─────────────────────────────────────────────

def test_ntro_login_succeeds():
    client = _client()
    resp = _ntro_login(client)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token"].startswith("ntro_")
    assert body["employee"]["employee_id"] == "NTRO-DEMO-001"
    assert body["employee"]["department"]
    me = client.get("/ntro/me", headers={"X-NTRO-Token": body["token"]})
    assert me.status_code == 200


def test_ntro_invalid_employee_rejected():
    client = _client()
    resp = _ntro_login(client, employee_id="NTRO-NOBODY-999", password="whatever")
    assert resp.status_code == 401


def test_ntro_invalid_password_rejected():
    client = _client()
    resp = _ntro_login(client, password="wrong-password")
    assert resp.status_code == 401
    assert "wrong-password" not in resp.text


def test_ntro_inactive_employee_rejected():
    client = _client()
    resp = _ntro_login(client, employee_id="NTRO-DEMO-002", password="demo-ntro-002")
    assert resp.status_code == 401


def test_ntro_session_required_and_expiry():
    client = _client()
    assert client.get("/ntro/me").status_code == 401
    assert client.get("/github/status").status_code == 401
    expired = ntro_auth.mint_session_token("NTRO-DEMO-001", ttl=-1)
    assert client.get("/ntro/me", headers={"X-NTRO-Token": expired}).status_code == 401


# ── GitHub authorization: config + state validation ──────────────────────────

def test_github_unconfigured_reports_setup_error(monkeypatch):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    client = _client()
    assert client.get("/github/config").json()["configured"] is False
    headers = _ntro_headers(client)
    assert client.post("/github/login", headers=headers).status_code == 503
    assert client.get("/github/repos", headers=headers).status_code == 503


def test_github_state_validation_rejects_bad_and_reused(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    # Unknown state → safe redirect, no exception, no token.
    r = client.get("/github/callback", params={"code": "x", "state": "bogus"}, follow_redirects=False)
    assert r.status_code == 302 and "github_error=invalid_state" in r.headers["location"]
    # Cancelled authorization (no code) → safe redirect.
    headers = _ntro_headers(client)
    login = client.post("/github/login", headers=headers)
    state = github_auth._states and next(iter(github_auth._states))
    assert login.status_code == 200 and state
    r = client.get("/github/callback", params={"state": state}, follow_redirects=False)
    assert r.status_code == 302 and "github_error=cancelled" in r.headers["location"]
    # Reused state → rejected (already consumed).
    r = client.get("/github/callback", params={"code": "x", "state": state}, follow_redirects=False)
    assert r.status_code == 302 and "github_error=invalid_state" in r.headers["location"]


def test_repo_metadata_normalization_keeps_safe_fields_only():
    repo = normalize_repo({
        "full_name": "octo/private-repo", "name": "private-repo",
        "owner": {"login": "octo", "avatar_url": "https://avatars.example/u/1"},
        "private": True,
        "default_branch": "main", "html_url": "https://github.com/octo/private-repo",
        "description": "demo repo", "pushed_at": "2026-09-01T00:00:00Z",
        "token": "must-never-appear", "secret": "x",
    })
    assert repo == {"full_name": "octo/private-repo", "name": "private-repo",
                    "owner": "octo", "private": True,
                    "default_branch": "main",
                    "html_url": "https://github.com/octo/private-repo",
                    "description": "demo repo", "updated_at": "2026-09-01T00:00:00Z",
                    "avatar_url": "https://avatars.example/u/1"}
    assert "token" not in json.dumps(repo)


def test_github_repos_come_from_github_not_hardcoded(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    headers = _ntro_headers(client)
    _seed_github()
    fake = [{"full_name": "octo/real-private", "name": "real-private",
             "owner": {"login": "octo"}, "private": True, "default_branch": "main",
             "html_url": "https://github.com/octo/real-private"}]
    monkeypatch.setattr(github_auth, "github_get",
                        lambda *a, **kw: NS(status_code=200, json=lambda: fake))
    body = client.get("/github/repos", headers=headers).json()
    assert body["repos"][0]["full_name"] == "octo/real-private"
    assert body["repos"][0]["private"] is True


# ── Secure retrieval + scanner adapter (mocked) ──────────────────────────────

def _mock_pipeline(monkeypatch, tmp_path):
    async def semgrep(_):
        return {"results": [{"path": "app.py", "start": {"line": 1}, "end": {"line": 1},
                             "extra": {"metadata": {"algorithm": "RSA"}}}]}
    monkeypatch.setattr(main, "run_semgrep_scan", semgrep)
    monkeypatch.setattr(main, "clone_with_token",
                        lambda url, dest, token: dest.mkdir(parents=True))
    monkeypatch.setattr(main, "checkout_ref", lambda *a: None)
    monkeypatch.setattr(main, "resolve_commit_sha", lambda _: "a" * 40)


def test_inaccessible_repository_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    headers = _ntro_headers(client)
    _seed_github()
    monkeypatch.setattr(main, "github_get",
                        lambda *a, **kw: NS(status_code=404, json=lambda: {"message": "Not Found"}))
    resp = client.post("/scan/github", headers=headers, json={"repository": "octo/nope"})
    assert resp.status_code == 404
    assert "gho_test_token_xyz" not in resp.text


def test_github_scan_uses_existing_pipeline_and_safe_provenance(monkeypatch, tmp_path):
    monkeypatch.delenv("ECDAT_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    headers = _ntro_headers(client)
    _seed_github()
    _mock_pipeline(monkeypatch, tmp_path)
    monkeypatch.setattr(
        main, "github_get",
        lambda *a, **kw: NS(status_code=200,
                            json=lambda: {"full_name": "octo/private-repo",
                                          "default_branch": "main"}))
    resp = client.post("/scan/github", headers=headers,
                       json={"repository": "octo/private-repo", "ref": "main"})
    assert resp.status_code == 200, resp.text
    text = resp.text
    assert "gho_test_token_xyz" not in text  # token never in response/CBOM
    assert "GITHUB_CLIENT_SECRET" not in text
    bom = resp.json()
    name = bom["metadata"]["component"]["name"]
    assert name.startswith("github:octo/private-repo@")  # history-safe target
    coverage = json.loads(next(p["value"] for p in bom["properties"]
                               if p["name"] == "ecdat:coverage"))
    assert coverage[0]["sourceType"] == "github"
    assert coverage[0]["repository"] == "octo/private-repo"
    assert coverage[0]["commitSha"] == "a" * 40
    assert "token" not in json.dumps(coverage).lower()
    assert bom["components"], "existing scanner findings must flow through"


def test_github_scan_rejects_malicious_identifiers(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    headers = _ntro_headers(client)
    _seed_github()
    for bad in ["../../etc", "https://github.com/o/r.git", "owner/", "", "o/r; rm -rf"]:
        assert client.post("/scan/github", headers=headers,
                           json={"repository": bad}).status_code == 400
    assert client.post("/scan/github", headers=headers,
                       json={"repository": "octo/r", "ref": "../../evil"}).status_code == 400


def test_local_scan_regression(monkeypatch, tmp_path):
    monkeypatch.delenv("ECDAT_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("pass\n")

    async def semgrep(_):
        return {"results": []}
    monkeypatch.setattr(main, "run_semgrep_scan", semgrep)
    resp = _client().post("/scan", json={"target_directory": str(tmp_path)})
    assert resp.status_code == 200, resp.text


# ── Per-employee isolation (prompt.md: A must never see/use B's GitHub) ─────
# Runs against an isolated throwaway database with a real second employee,
# exercising the production DbNtroProvider + session + vault path end to end.

def _isolated_two_employee_env(monkeypatch, tmp_path):
    monkeypatch.setenv("NTRO_DB_PATH", str(tmp_path / "isolated.db"))
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    ntro_database.create_employee("NTRO-TEST-B", "Test B", "Lab B", "pw-b",
                            email="b@ntro.demo", active=True)


def _login_as(client, who):
    pw = {"NTRO-DEMO-001": "demo-ntro-001", "NTRO-TEST-B": "pw-b"}[who]
    resp = client.post("/ntro/login", json={"employee_id": who, "password": pw})
    assert resp.status_code == 200, resp.text
    assert resp.json()["employee"]["employee_id"] == who
    return {"X-NTRO-Token": resp.json()["token"]}


def test_employee_b_cannot_use_employee_a_github(monkeypatch, tmp_path):
    _isolated_two_employee_env(monkeypatch, tmp_path)
    client = _client()
    headers_a = _login_as(client, "NTRO-DEMO-001")
    headers_b = _login_as(client, "NTRO-TEST-B")
    # Only A connects GitHub.
    assert client.post("/github/login", headers=headers_a).status_code == 200
    github_auth.save_authorization(
        "NTRO-DEMO-001", "gho_token_for_A", "repo",
        {"login": "alice-gh", "id": 11, "type": "User"})
    # B is unconnected: status false, repos + scan rejected — A's token nowhere.
    assert client.get("/github/status", headers=headers_b).json() == {"connected": False}
    for resp in (client.get("/github/repos", headers=headers_b),
                 client.post("/scan/github", headers=headers_b,
                             json={"repository": "alice-gh/a-private"})):
        assert resp.status_code == 409
        assert "gho_token_for_A" not in resp.text


def test_each_employee_sees_only_own_repositories(monkeypatch, tmp_path):
    _isolated_two_employee_env(monkeypatch, tmp_path)
    client = _client()
    headers_a = _login_as(client, "NTRO-DEMO-001")
    headers_b = _login_as(client, "NTRO-TEST-B")
    github_auth.save_authorization(
        "NTRO-DEMO-001", "gho_token_for_A", "repo",
        {"login": "alice-gh", "id": 11, "type": "User"})
    github_auth.save_authorization(
        "NTRO-TEST-B", "gho_token_for_B", "repo",
        {"login": "bob-gh", "id": 22, "type": "User"})

    def fake_github_list(access_token, path, params=None):
        if access_token == "gho_token_for_A":
            repos = [{"full_name": "alice-gh/a-private", "name": "a-private",
                      "owner": {"login": "alice-gh"}, "private": True,
                      "default_branch": "main", "html_url": "https://github.com/alice-gh/a-private"}]
        elif access_token == "gho_token_for_B":
            repos = [{"full_name": "bob-gh/b-private", "name": "b-private",
                      "owner": {"login": "bob-gh"}, "private": True,
                      "default_branch": "main", "html_url": "https://github.com/bob-gh/b-private"}]
        else:
            return NS(status_code=401, json=lambda: {"message": "Bad credentials"})
        if path == "/user/repos":
            return NS(status_code=200, json=lambda: repos)
        wanted = path.removeprefix("/repos/")
        match = next((r for r in repos if r["full_name"].lower() == wanted.lower()), None)
        if match is None:  # GitHub itself denies cross-employee access
            return NS(status_code=404, json=lambda: {"message": "Not Found"})
        return NS(status_code=200, json=lambda: match)

    monkeypatch.setattr(github_auth, "github_get", fake_github_list)
    monkeypatch.setattr(main, "github_get", fake_github_list)

    repos_a = client.get("/github/repos", headers=headers_a).json()["repos"]
    repos_b = client.get("/github/repos", headers=headers_b).json()["repos"]
    assert [r["full_name"] for r in repos_a] == ["alice-gh/a-private"]
    assert [r["full_name"] for r in repos_b] == ["bob-gh/b-private"]
    assert "gho_token_for_B" not in json.dumps(repos_a)
    assert "gho_token_for_A" not in json.dumps(repos_b)

    # Cross-employee scan attempts are denied by server-side revalidation.
    _mock_pipeline(monkeypatch, tmp_path)
    denied = client.post("/scan/github", headers=headers_b,
                         json={"repository": "alice-gh/a-private"})
    assert denied.status_code == 404
    assert "gho_token_for_A" not in denied.text
    assert "gho_token_for_B" not in denied.text


# ── Logout invalidation + persistence (Scenarios D / E) ──────────────────────

def test_ntro_logout_invalidates_session(monkeypatch, tmp_path):
    monkeypatch.setenv("NTRO_DB_PATH", str(tmp_path / "logout.db"))
    client = _client()
    headers = _ntro_headers(client)
    assert client.get("/ntro/me", headers=headers).status_code == 200
    assert client.post("/ntro/logout", headers=headers).status_code == 200
    # Old session must no longer work on any protected endpoint.
    assert client.get("/ntro/me", headers=headers).status_code == 401
    assert client.get("/github/status", headers=headers).status_code == 401
    assert client.post("/scan/github", headers=headers,
                       json={"repository": "octo/any"}).status_code == 401


def test_session_identifies_correct_employee(monkeypatch, tmp_path):
    _isolated_two_employee_env(monkeypatch, tmp_path)
    client = _client()
    headers_b = _login_as(client, "NTRO-TEST-B")
    me = client.get("/ntro/me", headers=headers_b).json()["employee"]
    assert me["employee_id"] == "NTRO-TEST-B"
    assert me["name"] == "Test B"
    assert "password_hash" not in json.dumps(me)


def test_records_persist_across_backend_restart(monkeypatch, tmp_path):
    db_file = tmp_path / "persist.db"
    monkeypatch.setenv("NTRO_DB_PATH", str(db_file))
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    client = _client()
    # Employee logs in and connects GitHub.
    headers = _ntro_headers(client)
    ntro_database.save_github_auth(
        "NTRO-DEMO-001", "gho_persisted_token", "repo",
        {"login": "octo", "id": 1, "type": "User"})
    # ── Simulate a backend restart: drop every in-memory cache. ──
    ntro_database._initialized_paths.clear()
    github_auth._states.clear()
    for mod in ("ntro_auth", "github_auth", "ntro_database", "main"):
        importlib.reload(sys.modules[mod])
    import main as main2
    client2 = TestClient(main2.app, raise_server_exceptions=False)
    # Old session token still validates (persisted server-side).
    assert client2.get("/ntro/me", headers=headers).status_code == 200
    # GitHub authorization record still exists — no reconnect required.
    status = client2.get("/github/status", headers=headers).json()
    assert status["connected"] is True
    assert status["github_user"]["login"] == "octo"
    assert "gho_persisted_token" not in json.dumps(status)
