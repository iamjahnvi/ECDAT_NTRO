import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Code, X } from 'lucide-react'

export default function CodeViewer({ component, onClose }) {
  const dialogRef = useRef(null)
  const properties = Object.fromEntries((component.properties || []).map(property => [property.name, property.value]))
  const occurrence = component.evidence?.occurrences?.[0]
  const snippet = properties['ecdat:source:snippet']
  const startLine = Number(properties['ecdat:source:start-line']) || occurrence?.line || 1
  const binary = properties['ecdat:source'] === 'binary'
  const symbol = properties['ecdat:symbol'] || occurrence?.symbol

  useEffect(() => {
    const previousFocus = document.activeElement
    const dialog = dialogRef.current
    dialog.showModal()
    return () => {
      dialog.close()
      previousFocus?.focus()
    }
  }, [])

  return createPortal(
    <dialog ref={dialogRef} className="code-viewer" aria-labelledby="code-viewer-title"
      onCancel={event => { event.preventDefault(); onClose() }}
      onClick={event => { if (event.target === event.currentTarget) onClose() }}>
      <div className="code-viewer-content">
        <header className="code-viewer-header">
          <div className="info-heading"><Code size={20} /><h2 id="code-viewer-title">{component.name} — {binary ? 'Binary Evidence' : 'Source Code'}</h2></div>
          <button className="utility-button" aria-label="Close code viewer" onClick={onClose} autoFocus><X size={18} /></button>
        </header>
        <div className="code-viewer-body">
          <p className="code-location">{occurrence?.location || 'Source location unavailable'}
            {!binary && occurrence?.line > 0 && `:${occurrence.line}${occurrence.endLine > occurrence.line ? `–${occurrence.endLine}` : ''}`}
          </p>
          {snippet ? (
            <>
              <pre className="source-code"><code>{snippet.split('\n').map((line, index) => (
                <span className="source-line" key={index}><span className="source-line-number" aria-hidden="true">{startLine + index}</span><span>{line || ' '}</span></span>
              ))}</code></pre>
              {properties['ecdat:source:truncated'] === 'true' && <p className="code-note">This long match has been truncated for display.</p>}
            </>
          ) : (
            <div className="info-card">
              {binary ? (
                <><h3>Compiled binary evidence</h3><p>Source code is not available for compiled binaries.</p>
                  {symbol && <p>Symbol: <code>{symbol}</code></p>}
                  {Number.isInteger(occurrence?.line) && <p>Byte offset: {occurrence.line} (0x{occurrence.line.toString(16)})</p>}
                </>
              ) : (
                <><h3>Source snippet unavailable</h3><p>{component.type === 'library'
                  ? 'This finding comes from dependency metadata. Inspect the manifest at the location above.'
                  : 'This report does not include captured source code. Run a new source scan to view the matched lines. Saved history and offline sample reports do not contain source snippets.'}</p></>
              )}
            </div>
          )}
          {properties['semgrep:rule_id'] && <p className="code-note">Detection rule: {properties['semgrep:rule_id']}</p>}
          {component.description && <section className="info-card"><h2>Finding</h2><p>{component.description}</p></section>}
          {component.recommendation?.action && <section className="info-card"><h2>Migration recommendation</h2><p>{component.recommendation.action}</p></section>}
        </div>
      </div>
    </dialog>,
    document.body,
  )
}
