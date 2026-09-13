/**
 * CryptoHeatmap.jsx
 * Grid-based Risk Assessment Heatmap
 *
 * Rows    = Algorithm families (always shows a full set for visual density)
 * Columns = Assessment dimensions (Quantum Resistance, Key Strength, NIST Compliance, Mosca Risk)
 * Cell color = green → yellow → orange → red gradient based on risk score
 */
import { useMemo, useState } from 'react'

const DS = {
  surfaceLow:  '#1b1b23',
  surfaceHigh: '#292932',
  outlineVar:  '#464554',
  onSurface:   '#e4e1ed',
  onVariant:   '#c7c4d7',
  muted:       '#908fa0',
}

// ── Assessment dimensions (columns) ──────────────────────────────────────────
const DIMENSIONS = [
  { key: 'quantum',    label: 'Quantum Resistance' },
  { key: 'keyStr',     label: 'Key Strength' },
  { key: 'nist',       label: 'NIST Compliance' },
  { key: 'mosca',      label: 'Mosca Risk' },
  { key: 'deprecation', label: 'Deprecation' },
]

// ── Full algorithm catalog with baseline risk profiles ───────────────────────
// Score: 0 = safe (green), 1 = low, 2 = medium, 3 = high, 4 = critical (red)
const ALGO_CATALOG = {
  'RSA':        { quantum: 4, keyStr: 2, nist: 3, mosca: 4, deprecation: 2, category: 'Asymmetric' },
  'ECDSA':      { quantum: 4, keyStr: 1, nist: 3, mosca: 4, deprecation: 2, category: 'Asymmetric' },
  'ECDH':       { quantum: 4, keyStr: 1, nist: 3, mosca: 4, deprecation: 2, category: 'Asymmetric' },
  'Ed25519':    { quantum: 4, keyStr: 0, nist: 3, mosca: 4, deprecation: 1, category: 'Asymmetric' },
  'DH':         { quantum: 4, keyStr: 2, nist: 3, mosca: 4, deprecation: 3, category: 'Asymmetric' },
  'DSA':        { quantum: 4, keyStr: 2, nist: 4, mosca: 4, deprecation: 4, category: 'Asymmetric' },
  'MD5':        { quantum: 1, keyStr: 4, nist: 4, mosca: 3, deprecation: 4, category: 'Hash' },
  'SHA-1':      { quantum: 1, keyStr: 3, nist: 3, mosca: 2, deprecation: 3, category: 'Hash' },
  'SHA-256':    { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'Hash' },
  'SHA-3':      { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'Hash' },
  'DES':        { quantum: 1, keyStr: 4, nist: 4, mosca: 3, deprecation: 4, category: 'Symmetric' },
  '3DES':       { quantum: 1, keyStr: 3, nist: 3, mosca: 2, deprecation: 3, category: 'Symmetric' },
  'RC4':        { quantum: 1, keyStr: 4, nist: 4, mosca: 3, deprecation: 4, category: 'Symmetric' },
  'Blowfish':   { quantum: 1, keyStr: 3, nist: 3, mosca: 2, deprecation: 3, category: 'Symmetric' },
  'AES-GCM':    { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'Symmetric' },
  'AES':        { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'Symmetric' },
  'ML-KEM':     { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'PQC' },
  'ML-DSA':     { quantum: 0, keyStr: 0, nist: 0, mosca: 0, deprecation: 0, category: 'PQC' },
}

// ── Color ramp: score 0..4 → green..red ──────────────────────────────────────
const CELL_COLORS = [
  '#1a5c2a',  // 0 — safe / dark green
  '#2d7a3a',  // 1 — low risk / green
  '#8a7a24',  // 2 — medium / dark yellow
  '#b85c2a',  // 3 — high / orange
  '#a63b3b',  // 4 — critical / red
]
const CELL_COLORS_HOVER = [
  '#22763a',
  '#3a9148',
  '#a08f2c',
  '#d06a30',
  '#c04545',
]
const CELL_TEXT = [
  'rgba(130,255,170,0.9)',
  'rgba(130,255,170,0.8)',
  'rgba(255,230,130,0.9)',
  'rgba(255,200,150,0.9)',
  'rgba(255,180,170,0.9)',
]

// Score labels for tooltip
const SCORE_LABELS = ['Safe', 'Low Risk', 'Medium', 'High Risk', 'Critical']

// Category badge colors
const CAT_COLORS = {
  Asymmetric: { bg: '#ba4f4d22', color: '#ff8a85', border: '#ba4f4d44' },
  Hash:       { bg: '#b89e4122', color: '#ffd966', border: '#b89e4144' },
  Symmetric:  { bg: '#4f7fba22', color: '#85b8ff', border: '#4f7fba44' },
  PQC:        { bg: '#55a36222', color: '#6ee7b7', border: '#55a36244' },
}

// ── Classify which algos are present in the scan ─────────────────────────────
function matchAlgo(componentName) {
  const u = (componentName || '').toUpperCase()
  if (u.includes('ML-KEM') || u.includes('KYBER'))     return 'ML-KEM'
  if (u.includes('ML-DSA') || u.includes('DILITHIUM')) return 'ML-DSA'
  if (u.includes('AES') && u.includes('GCM'))          return 'AES-GCM'
  if (u.includes('AES'))                                return 'AES'
  if (u.includes('SHA-3') || u.includes('SHA3'))        return 'SHA-3'
  if (u.includes('SHA-256') || u.includes('SHA256') || u.includes('SHA-2') || u.includes('SHA512')) return 'SHA-256'
  if (u.includes('SHA-1') || u.includes('SHA1'))        return 'SHA-1'
  if (u.includes('MD5'))                                return 'MD5'
  if (u.includes('ECDSA'))                              return 'ECDSA'
  if (u.includes('ECDH'))                               return 'ECDH'
  if (u.includes('ED25519'))                            return 'Ed25519'
  if (u.includes('RSA'))                                return 'RSA'
  if (u.includes('3DES') || u.includes('TRIPLE'))       return '3DES'
  if (u.includes('DES') && !u.includes('3DES'))         return 'DES'
  if (u.includes('RC4') || u.includes('ARC4'))          return 'RC4'
  if (u.includes('BLOWFISH'))                           return 'Blowfish'
  if (u.includes('DH') && !u.includes('ECDH'))         return 'DH'
  if (u.includes('DSA') && !u.includes('ECDSA') && !u.includes('ML-DSA')) return 'DSA'
  return null
}

export default function CryptoHeatmap({ components = [] }) {
  const [hoveredCell, setHoveredCell] = useState(null)

  // Find which algorithms are present in the scan results
  const rows = useMemo(() => {
    const found = new Set()
    components.forEach(c => {
      const algo = matchAlgo(c.name)
      if (algo) found.add(algo)
    })

    // Only return algorithms that were actually detected
    const allAlgos = Object.keys(ALGO_CATALOG)
    return allAlgos.filter(a => found.has(a))
  }, [components])

  if (components.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: DS.muted }}>
        <p style={{ fontSize: 12 }}>No data — run a scan</p>
      </div>
    )
  }

  const CELL_W = 120
  const CELL_H = 32
  const LABEL_W = 100
  const CAT_W = 80

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* Header */}
      <div
        style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 14,
        }}
      >
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#f8f8f2', margin: 0 }}>
          Cryptographic Risk Heatmap
        </h3>
        <span style={{ fontSize: 13, color: '#6272a4', fontFamily: "'JetBrains Mono', monospace" }}>
          {rows.length}{' '}
          <span style={{ fontFamily: 'Inter, sans-serif' }}>algorithms detected</span>
        </span>
      </div>

      {/* Heatmap grid */}
      <div style={{ overflowX: 'auto', position: 'relative' }}>
        <table
          style={{
            borderCollapse: 'separate',
            borderSpacing: 3,
            width: '100%',
            minWidth: LABEL_W + CAT_W + DIMENSIONS.length * CELL_W,
          }}
        >
          {/* Column headers */}
          <thead>
            <tr>
              <th style={{ width: LABEL_W, padding: '6px 8px', textAlign: 'left', fontSize: 10, fontWeight: 700, color: DS.muted, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                Algorithm
              </th>
              <th style={{ width: CAT_W, padding: '6px 4px', textAlign: 'center', fontSize: 10, fontWeight: 700, color: DS.muted, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                Type
              </th>
              {DIMENSIONS.map(dim => (
                <th
                  key={dim.key}
                  style={{
                    width: CELL_W, padding: '6px 4px',
                    textAlign: 'center', fontSize: 10, fontWeight: 700,
                    color: DS.muted, letterSpacing: '0.04em', textTransform: 'uppercase',
                  }}
                >
                  {dim.label}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {rows.map((algo, ri) => {
              const profile  = ALGO_CATALOG[algo]
              const cat      = profile.category
              const catStyle = CAT_COLORS[cat] || CAT_COLORS.Symmetric

              return (
                <tr key={algo}>
                  {/* Algorithm name */}
                  <td
                    style={{
                      padding: '4px 8px',
                      fontSize: 12, fontWeight: 700,
                      color: DS.onSurface,
                      fontFamily: "'JetBrains Mono', monospace",
                      whiteSpace: 'nowrap',
                      borderRadius: 3,
                      background: DS.surfaceHigh,
                    }}
                  >
                    {algo}
                  </td>

                  {/* Category badge */}
                  <td style={{ padding: '4px 4px', textAlign: 'center' }}>
                    <span
                      style={{
                        fontSize: 9, fontWeight: 700,
                        padding: '2px 8px', borderRadius: 9999,
                        background: catStyle.bg,
                        color: catStyle.color,
                        border: `1px solid ${catStyle.border}`,
                        letterSpacing: '0.02em',
                      }}
                    >
                      {cat}
                    </span>
                  </td>

                  {/* Risk cells */}
                  {DIMENSIONS.map((dim, ci) => {
                    const score     = profile[dim.key]
                    const cellKey   = `${ri}-${ci}`
                    const isHovered = hoveredCell === cellKey

                    return (
                      <td
                        key={dim.key}
                        onMouseEnter={() => setHoveredCell(cellKey)}
                        onMouseLeave={() => setHoveredCell(null)}
                        style={{
                          padding: 0,
                          position: 'relative',
                        }}
                      >
                        <div
                          style={{
                            height: CELL_H,
                            borderRadius: 3,
                            background: isHovered ? CELL_COLORS_HOVER[score] : CELL_COLORS[score],
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            transition: 'background 0.15s, transform 0.1s',
                            transform: isHovered ? 'scale(1.05)' : 'scale(1)',
                            cursor: 'default',
                            border: isHovered ? '1px solid rgba(255,255,255,0.2)' : '1px solid transparent',
                          }}
                        >
                          <span
                            style={{
                              fontSize: 10, fontWeight: 700,
                              color: CELL_TEXT[score],
                              fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            {SCORE_LABELS[score]}
                          </span>
                        </div>

                        {/* Tooltip */}
                        {isHovered && (
                          <div
                            style={{
                              position: 'absolute',
                              bottom: '100%', left: '50%',
                              transform: 'translateX(-50%)',
                              marginBottom: 6,
                              background: '#12121a',
                              border: `1px solid ${DS.outlineVar}`,
                              borderRadius: 6,
                              padding: '6px 10px',
                              zIndex: 50,
                              whiteSpace: 'nowrap',
                              boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                              pointerEvents: 'none',
                            }}
                          >
                            <div style={{ fontSize: 11, fontWeight: 700, color: DS.onSurface }}>
                              {algo} — {dim.label}
                            </div>
                            <div style={{ fontSize: 10, color: CELL_TEXT[score], marginTop: 2 }}>
                              Risk: {SCORE_LABELS[score]} ({score}/4)
                            </div>
                          </div>
                        )}
                      </td>
                    )
                  })}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingTop: 4 }}>
        <span style={{ fontSize: 11, color: DS.muted, marginRight: 4 }}>Risk:</span>
        {SCORE_LABELS.map((label, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span
              style={{
                width: 14, height: 14, borderRadius: 3,
                background: CELL_COLORS[i],
                display: 'inline-block',
              }}
            />
            <span style={{ fontSize: 11, color: '#6272a4', marginRight: 8 }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
