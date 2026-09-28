/**
 * GithubConnect.jsx — REAL GitHub authorization + private repo selection.
 *
 * Stepped flow (prompt-2 §7):
 *   STEP 3 — Connect GitHub  →  STEP 4 — Repository selection  →  STEP 5 — Analyze
 * preceded by the verified-employee card (§9: makes obvious WHOSE GitHub
 * account is in use — the whole security model depends on it).
 *
 *  - Tokens stay backend-only: this component only ever sees safe metadata
 *    (connected flag, login, avatar, repo name/owner/visibility/description/
 *    branch/updated). Never tokens, never secrets.
 *  - Repository list comes from GitHub (`GET /github/repos`), never hardcoded.
 *  - Analyze posts `{repository, ref}` to `POST /scan/github` with the NTRO
 *    session header; the backend resolves the token from the authenticated
 *    NTRO employee record, clones into a temp workspace, and runs the
 *    EXISTING scanner.
 *  - Clean state model (§8): `github` enum + `scan` object, refreshed from
 *    the backend on mount (`/ntro/me` → `/github/status` → `/github/repos`).
 *  - Separate controls (§10): NTRO Sign out (revokes NTRO session, keeps the
 *    ECDAT account signed in) vs GitHub Disconnect (removes stored
 *    authorization, stays NTRO-authenticated).
 */
import { useCallback, useEffect, useState } from 'react'
import { GitBranch, AlertTriangle, CheckCircle, RefreshCw, Lock, LogOut, Unlink } from 'lucide-react'
import { NTRO_TOKEN_KEY, ntroHeaders, isValidRepoName, formatGithubTarget } from '../ntroGithub'
import { apiHeaders } from '../cbom'

const DS = {
  surfaceHigh: '#292932',
  onSurface: '#e4e1ed',
  onVariant: '#c7c4d7',
  outlineVar: '#464554',
  error: '#ffb4ab',
  primary: '#c0c1ff',
  secondary: '#4cd7f6',
  emerald: '#6ee7b7',
  muted: '#908fa0',
  violet: '#d8a2ff',
}

// STEP 5 phased messages — stages, never fake percentages.
const SCAN_PHASES = [
  'Connecting securely…',
  'Fetching repository…',
  'Running cryptographic discovery…',
  'Generating CBOM…',
  'Assessing quantum risk…',
]

function formatUpdated(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })
  } catch {
    return ''
  }
}

export default function GithubConnect({ apiBase, ntroToken, ntroEmployee, ecdatAccount, scanContext, sensitiveKeywords, onScanComplete, onNtroLogout }) {
  // ── Clean state model (§8) ──────────────────────────────────────────────
  const [github, setGithub] = useState('checking') // 'checking' | 'not-connected' | 'connected'
  const [githubUser, setGithubUser] = useState(null)
  // Employee identity always revalidated from GET /ntro/me (§12) — the login
  // response prop is only the initial value, never the source of truth.
  const [verified, setVerified] = useState(ntroEmployee || null)
  const [configMsg, setConfigMsg] = useState('')
  const [gitAvailable, setGitAvailable] = useState(null) // null=checking, true, false
  const [repos, setRepos] = useState([])
  const [selected, setSelected] = useState('')
  const [ref, setRef] = useState('')
  const [scan, setScan] = useState({ status: 'idle', phase: 0, elapsed: 0 }) // idle|scanning|completed|failed
  const [error, setError] = useState(null)

  const scanning = scan.status === 'scanning'

  const baseHeaders = useCallback(
    () => ({ ...apiHeaders(), ...ntroHeaders(ntroToken) }),
    [ntroToken],
  )

  function dropNtroSession() {
    sessionStorage.removeItem(NTRO_TOKEN_KEY)
    onNtroLogout()
  }

  // ── Refresh from backend on mount (§8): never assume authentication ─────
  const refresh = useCallback(async () => {
    setError(null)
    setGithub('checking')
    try {
      // 1. Is the stored NTRO session still valid server-side?
      const me = await fetch(`${apiBase}/ntro/me`, { headers: baseHeaders() })
      if (me.status === 401) { dropNtroSession(); return }
      try {
        const mj = await me.json()
        if (mj?.employee?.employee_id) setVerified(mj.employee)
      } catch { /* keep login-time identity on parse failure */ }
      // 2. Is GitHub authorization configured / connected for THIS employee?
      const cfg = await fetch(`${apiBase}/github/config`).then(r => r.json())
      setGitAvailable(cfg.configured === true)
      setConfigMsg(cfg.message || '')
      if (!cfg.configured) { setGithub('not-connected'); return }
      const st = await fetch(`${apiBase}/github/status`, { headers: baseHeaders() })
      if (st.status === 401) { dropNtroSession(); return }
      const sj = await st.json()
      if (sj.connected !== true) { setGithub('not-connected'); return }
      setGithubUser(sj.github_user || null)
      // 3. That employee's repositories, live from GitHub.
      const rj = await fetch(`${apiBase}/github/repos`, { headers: baseHeaders() }).then(r => r.json())
      if (Array.isArray(rj.repos)) {
        setRepos(rj.repos)
        setSelected(prev => (prev && rj.repos.some(r => r.full_name === prev) ? prev : (rj.repos[0]?.full_name || '')))
      }
      setGithub('connected')
    } catch {
      setError('Could not reach the ECDAT backend.')
      setGithub('not-connected')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, ntroToken])

  useEffect(() => { refresh() }, [refresh])

  // ── OAuth callback bounce-back (backend redirects with query flags) ──────
  useEffect(() => {
    const q = new URLSearchParams(window.location.search)
    if (q.get('github_connected') === '1') {
      window.history.replaceState({}, '', window.location.pathname)
      refresh()
    }
    if (q.get('github_error')) {
      const map = {
        invalid_state: 'GitHub authorization expired or was reused. Please try Connect GitHub again.',
        cancelled: 'GitHub authorization was cancelled. Nothing was connected.',
        exchange_failed: 'GitHub authorization failed during token exchange. Try again.',
        user_failed: 'Connected to GitHub but could not read your account. Try again.',
      }
      setError(map[q.get('github_error')] || 'GitHub authorization failed. Try again.')
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [refresh])

  // ── Scan timers (elapsed + honest stage rotation) ────────────────────────
  useEffect(() => {
    if (!scanning) return
    const t1 = setInterval(() => setScan(s => ({ ...s, elapsed: s.elapsed + 1 })), 1000)
    const t2 = setInterval(() => setScan(s => ({ ...s, phase: Math.min(s.phase + 1, SCAN_PHASES.length - 1) })), 12000)
    return () => { clearInterval(t1); clearInterval(t2) }
  }, [scanning])

  async function handleConnect() {
    setError(null)
    try {
      const res = await fetch(`${apiBase}/github/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...baseHeaders() } })
      if (res.status === 401) { dropNtroSession(); return }
      const body = await res.json()
      if (!res.ok) { setError(body.detail || 'GitHub connection failed.'); return }
      // REAL GitHub authorization — leave ECDAT for github.com.
      window.location.href = body.auth_url
    } catch {
      setError('Could not start GitHub authorization.')
    }
  }

  async function handleDisconnect() {
    setError(null)
    try {
      await fetch(`${apiBase}/github/logout`, { method: 'POST', headers: baseHeaders() })
    } catch { /* best effort — state below is authoritative after refresh */ }
    setGithub('not-connected')
    setGithubUser(null)
    setRepos([])
    setSelected('')
  }

  async function handleNtroSignOut() {
    try {
      await fetch(`${apiBase}/ntro/logout`, { method: 'POST', headers: baseHeaders() })
    } catch { /* session expires server-side regardless */ }
    dropNtroSession() // ECDAT (Supabase) account stays signed in — only NTRO is revoked.
  }

  async function handleAnalyze() {
    setError(null)
    if (!isValidRepoName(selected)) { setError('Select a repository from the list.'); return }
    setScan({ status: 'scanning', phase: 0, elapsed: 0 })
    const controller = new AbortController()
    const tid = setTimeout(() => controller.abort(), 300_000)
    try {
      const res = await fetch(`${apiBase}/scan/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...baseHeaders() },
        body: JSON.stringify({
          repository: selected.trim(),
          ref: ref.trim() || null,
          context: scanContext,
          sensitive_keywords: sensitiveKeywords,
        }),
        signal: controller.signal,
      })
      clearTimeout(tid)
      if (res.status === 401) { dropNtroSession(); return }
      if (!res.ok) {
        let detail = `Scan failed (HTTP ${res.status})`
        try { const b = await res.json(); detail = b.detail || detail } catch { /* non-JSON */ }
        setError(detail)
        setScan(s => ({ ...s, status: 'failed' }))
        return
      }
      const bom = await res.json()
      const repo = selected.trim()
      const sha = bom?.metadata?.component?.name?.split('@')[1] || ''
      setScan(s => ({ ...s, status: 'completed' }))
      onScanComplete(bom, formatGithubTarget(repo, sha))
    } catch (err) {
      setError(err.name === 'AbortError' ? 'Scan timed out. Try a smaller repository.' : 'Scan failed. Check the backend and try again.')
      setScan(s => ({ ...s, status: 'failed' }))
    } finally {
      clearTimeout(tid)
    }
  }

  const selectedRepo = repos.find(r => r.full_name === selected)

  return (
    <div>
      {/* ── Verified employee card (§9: WHOSE GitHub is this?) ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12,
        padding: '10px 12px', borderRadius: 6,
        background: `${DS.secondary}08`, border: `1px solid ${DS.secondary}25`,
      }}>
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: DS.muted }}>NTRO EMPLOYEE</div>
          <div style={{ fontSize: 13, fontWeight: 700, color: DS.onSurface }}>
            {verified?.name || verified?.employee_id} · {verified?.employee_id}
          </div>
          <div style={{ fontSize: 11, color: DS.muted }}>
            {verified?.department}
            {ecdatAccount ? ` · ECDAT account: ${ecdatAccount}` : null}
          </div>
        </div>
        <span style={{
          display: 'flex', alignItems: 'center', gap: 4,
          fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 9999,
          background: `${DS.emerald}14`, color: DS.emerald,
          border: `1px solid ${DS.emerald}40`, whiteSpace: 'nowrap',
        }}>
          <CheckCircle size={11} /> Verified
        </span>
        <button
          onClick={handleNtroSignOut}
          title="Revoke this NTRO session (your ECDAT account stays signed in)"
          style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: DS.muted, fontSize: 11, cursor: 'pointer', textDecoration: 'underline', whiteSpace: 'nowrap' }}
        >
          <LogOut size={11} /> NTRO Sign out
        </button>
      </div>

      {/* ── STEP 3 — GitHub connection card ── */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', color: DS.muted, marginBottom: 6 }}>
          STEP 3 — GITHUB REPOSITORY ACCESS
        </div>
        {gitAvailable === false && (
          <div style={{
            display: 'flex', gap: 8, padding: '8px 12px', borderRadius: 6, marginBottom: 12,
            background: `${DS.error}08`, border: `1px solid ${DS.error}30`,
            fontSize: 12, color: DS.muted, lineHeight: 1.5,
          }}>
            <AlertTriangle size={13} color={DS.error} style={{ flexShrink: 0, marginTop: 1 }} />
            <span><strong style={{ color: DS.error }}>GitHub not configured.</strong> {configMsg} Local scanning still works.</span>
          </div>
        )}

        {github === 'checking' && (
          <div style={{ fontSize: 12, color: DS.muted }}>Checking GitHub connection…</div>
        )}

        {github === 'not-connected' && gitAvailable !== false && (
          <div>
            <p style={{ fontSize: 12, color: DS.onVariant, margin: '0 0 10px', lineHeight: 1.6 }}>
              Connect your authorized GitHub account to access repositories available to this NTRO employee.
            </p>
            <button
              id="btn-github-connect"
              onClick={handleConnect}
              title="Authorize via github.com (tokens stay on the backend)"
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '9px 16px',
                borderRadius: 6, border: `1px solid ${DS.secondary}40`,
                background: `${DS.secondary}14`, color: DS.secondary,
                fontSize: 13, fontWeight: 700, cursor: 'pointer',
              }}
            >
              <GitBranch size={13} />
              Connect GitHub
            </button>
            <p style={{ fontSize: 11, color: DS.muted, marginTop: 8 }}>
              Real GitHub authorization. ECDAT never asks for passwords, PATs, or SSH keys.
            </p>
          </div>
        )}

        {github === 'connected' && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 12px', borderRadius: 6,
            background: `${DS.emerald}08`, border: `1px solid ${DS.emerald}25`,
          }}>
            {githubUser?.avatar_url && (
              <img src={githubUser.avatar_url} alt="" width={22} height={22} style={{ borderRadius: '50%' }} />
            )}
            <span style={{ fontSize: 12, color: DS.onSurface }}>
              <strong>GitHub</strong> @{githubUser?.login || 'connected'}
            </span>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: '1px 7px', borderRadius: 9999,
              background: `${DS.emerald}18`, color: DS.emerald,
              border: `1px solid ${DS.emerald}40`, display: 'flex', alignItems: 'center', gap: 4,
            }}>
              <CheckCircle size={10} /> Connected
            </span>
            <button
              onClick={handleDisconnect}
              title="Remove this employee's stored GitHub authorization"
              style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: DS.muted, fontSize: 11, cursor: 'pointer', textDecoration: 'underline', whiteSpace: 'nowrap' }}
            >
              <Unlink size={11} /> Disconnect
            </button>
          </div>
        )}
      </div>

      {/* ── STEP 4 — Repository selection (cards, live from GitHub) ── */}
      {github === 'connected' && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', color: DS.muted }}>
              STEP 4 — SELECT REPOSITORY
            </span>
            <button
              onClick={refresh}
              title="Refresh repository list from GitHub"
              style={{ marginLeft: 'auto', background: 'none', border: 'none', color: DS.muted, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}
            >
              <RefreshCw size={11} /> Refresh
            </button>
          </div>

          {repos.length === 0 ? (
            <div style={{ fontSize: 12, color: DS.muted }}>No repositories accessible to this GitHub account.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 260, overflowY: 'auto', paddingRight: 2 }}>
              {repos.map(r => {
                const active = r.full_name === selected
                return (
                  <button
                    key={r.full_name}
                    onClick={() => setSelected(r.full_name)}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: 10, textAlign: 'left',
                      width: '100%', boxSizing: 'border-box',
                      background: active ? `${DS.secondary}0c` : DS.surfaceHigh,
                      border: `1px solid ${active ? DS.secondary : DS.outlineVar}`,
                      borderRadius: 6, padding: '9px 12px', cursor: 'pointer',
                    }}
                  >
                    {r.avatar_url && (
                      <img src={r.avatar_url} alt="" width={26} height={26} style={{ borderRadius: '50%', flexShrink: 0, marginTop: 1 }} />
                    )}
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 13 }}>{r.private ? '🔒' : '🌐'}</span>
                        <span style={{ fontSize: 13, fontWeight: 700, color: DS.onSurface, fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.owner}/{r.name}
                        </span>
                      </span>
                      {r.description ? (
                        <span style={{ display: 'block', fontSize: 11, color: DS.onVariant, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.description}
                        </span>
                      ) : null}
                      <span style={{ display: 'block', fontSize: 10, color: DS.muted, marginTop: 3 }}>
                        default: {r.default_branch || 'main'}
                        {formatUpdated(r.updated_at) ? ` · updated ${formatUpdated(r.updated_at)}` : ''}
                      </span>
                    </span>
                    {active && <CheckCircle size={14} color={DS.secondary} style={{ flexShrink: 0, marginTop: 2 }} />}
                  </button>
                )
              })}
            </div>
          )}

          <label style={{ display: 'block', fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: DS.muted, margin: '10px 0 6px' }}>
            Ref <span style={{ fontWeight: 400, textTransform: 'none' }}>(optional — branch / tag, default branch if empty)</span>
          </label>
          <input
            id="github-ref-input"
            type="text"
            value={ref}
            onChange={e => setRef(e.target.value)}
            placeholder="main"
            style={{
              width: '100%', background: DS.surfaceHigh, border: `1px solid ${DS.outlineVar}`,
              borderRadius: 6, color: DS.onSurface, fontSize: 13,
              padding: '9px 10px', outline: 'none', boxSizing: 'border-box',
              fontFamily: "'JetBrains Mono', monospace",
            }}
            onFocus={e => (e.target.style.borderColor = DS.secondary)}
            onBlur={e => (e.target.style.borderColor = DS.outlineVar)}
          />
        </div>
      )}

      {/* ── STEP 5 — Analyze ── */}
      {github === 'connected' && repos.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', color: DS.muted, marginBottom: 6 }}>
            STEP 5 — ANALYZE
          </div>
          <button
            id="btn-github-analyze"
            onClick={handleAnalyze}
            disabled={scanning || !selected}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              padding: '12px 24px', borderRadius: 6,
              background: scanning || !selected ? '#374151' : '#f4f4f5', border: 'none',
              color: scanning || !selected ? '#9ca3af' : '#09090b',
              fontSize: 14, fontWeight: 700, cursor: scanning || !selected ? 'not-allowed' : 'pointer',
            }}
          >
            {scanning ? (
              <>{SCAN_PHASES[scan.phase]}{scan.elapsed > 3 ? ` (${scan.elapsed}s)` : ''}</>
            ) : (
              <><Lock size={13} /> Analyze Repository{selectedRepo ? ` — ${selectedRepo.owner}/${selectedRepo.name}` : ''}</>
            )}
          </button>
          {scan.status === 'failed' && !error && (
            <p style={{ fontSize: 11, color: DS.muted, marginTop: 6 }}>Scan failed — adjust the selection and try again.</p>
          )}
        </div>
      )}

      {error && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
          borderRadius: 4, background: `${DS.error}10`, border: `1px solid ${DS.error}40`,
          color: DS.error, fontSize: 12, marginTop: 12, fontFamily: "'JetBrains Mono', monospace",
        }}>
          <AlertTriangle size={12} style={{ flexShrink: 0 }} />
          {error}
        </div>
      )}
    </div>
  )
}
