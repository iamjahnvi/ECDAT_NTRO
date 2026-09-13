export default function ScanContextForm({ value, onChange }) {
  function set(key, next) { onChange({ ...value, [key]: next }) }
  return (
    <details className="scan-context">
      <summary>Business context & recommendation constraints</summary>
      <div className="context-grid">
        <label>Application<input value={value.application} onChange={e => set('application', e.target.value)} /></label>
        <label>Sensitivity<select value={value.data_sensitivity} onChange={e => set('data_sensitivity', e.target.value)}>{['public', 'internal', 'confidential', 'restricted'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label>Business criticality<select value={value.business_criticality} onChange={e => set('business_criticality', e.target.value)}>{['low', 'medium', 'high', 'critical'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label>Sensitive data categories<input placeholder="PII, payments, medical records" value={value.data_types.join(', ')} onChange={e => set('data_types', e.target.value.split(',').map(v => v.trim()))} /></label>
        {[
          ['data_lifetime_years', 'Data lifetime (years)', 0, 100], ['migration_years', 'Migration time (years)', 0, 50],
          ['quantum_horizon_years', 'Quantum horizon (years)', 0.1, 100], ['rotation_max_days', 'Maximum key age (days)', 1, 3650],
          ['latency_weight', 'Latency weight (0–1)', 0, 1], ['cost_weight', 'Cost weight (0–1)', 0, 1],
        ].map(([key, label, min, max]) => <label key={key}>{label}<input type="number" min={min} max={max} step="any" value={value[key]} onChange={e => set(key, Number(e.target.value))} /></label>)}
        <label>Cryptographic use<select value={value.usage} onChange={e => set('usage', e.target.value)}>{['auto', 'signature', 'key-establishment', 'encryption', 'hash'].map(v => <option key={v}>{v}</option>)}</select></label>
        {[['max_latency_ms', 'Latency budget (ms)'], ['max_cost_per_million', 'Cost budget / million operations']].map(([key, label]) => <label key={key}>{label}<input type="number" min="0.001" step="any" value={value[key] ?? ''} onChange={e => set(key, e.target.value ? Number(e.target.value) : null)} /></label>)}
      </div>
      <p>Weights use relative estimates unless you provide benchmark measurements for every candidate through the discovery JSON/API. Unsupplied budgets remain unverified.</p>
    </details>
  )
}
