import { useState } from 'react'
import { apiHeaders } from '../cbom'

const examples = {
  materials: '/path/to/certificates', tls: 'internal.example.com', aws: 'us-east-1',
  azure: 'https://your-vault.vault.azure.net', gcp: 'projects/PROJECT/locations/global',
  vault: 'https://vault.example.com', hsm: '/usr/local/lib/softhsm/libsofthsm2.so', repository: 'git@github.com:org/private-repo.git',
}

export default function EnterpriseDiscovery({ context, onScanComplete }) {
  const [kind, setKind] = useState('tls')
  const [target, setTarget] = useState('')
  const [port, setPort] = useState(443)
  const [batch, setBatch] = useState('')
  const [token, setToken] = useState(() => sessionStorage.getItem('ecdat-api-token') || '')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  async function scan(event) {
    event.preventDefault()
    setLoading(true); setError('')
    try {
      const targets = batch.trim() ? JSON.parse(batch) : [{ kind, target, port }]
      const response = await fetch(`http://${window.location.hostname}:8000/discover`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...apiHeaders() },
        body: JSON.stringify({ targets, context }), signal: AbortSignal.timeout(900000),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : JSON.stringify(result.detail))
      onScanComplete(result, targets.map(t => t.target).join(', '))
    } catch (err) { setError(err.message) } finally { setLoading(false) }
  }
  return (
    <form className="info-card enterprise-discovery" onSubmit={scan}>
      <h2>Enterprise discovery</h2>
      <p>Scan certificates and keys, live TLS endpoints, cloud key stores, HSM tokens, or authenticated repositories. Provider credentials are configured on the backend.</p>
      <div className="context-grid">
        <label>Discovery type<select value={kind} onChange={e => setKind(e.target.value)}>{Object.keys(examples).map(k => <option key={k}>{k}</option>)}</select></label>
        <label>Target<input required={!batch.trim()} value={target} placeholder={examples[kind]} onChange={e => setTarget(e.target.value)} /></label>
        {kind === 'tls' && <label>TLS port<input type="number" min="1" max="65535" value={port} onChange={e => setPort(Number(e.target.value))} /></label>}
        <label>API bearer token (if configured)<input type="password" value={token} autoComplete="off" onChange={e => { setToken(e.target.value); sessionStorage.setItem('ecdat-api-token', e.target.value) }} /></label>
      </div>
      <details><summary>Batch targets / per-application context (JSON)</summary>
        <textarea rows={7} value={batch} onChange={e => setBatch(e.target.value)} placeholder={'[{"kind":"tls","target":"app.example.com","context":{"application":"Payments","data_sensitivity":"restricted","data_types":["cardholder data"]}}]'} />
        <p>Up to 100 targets, four concurrent by default. Each target can override context and supply benchmarks or path-based asset_contexts.</p>
      </details>
      {error && <p role="alert" style={{ color: 'var(--error)' }}>{error}</p>}
      <button className="utility-button" disabled={loading}>{loading ? 'Discovering…' : 'Start enterprise discovery'}</button>
    </form>
  )
}
