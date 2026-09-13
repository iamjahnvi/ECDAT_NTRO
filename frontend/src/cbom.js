// Keep schema-valid wire data separate from convenient dashboard fields.
export function decodeBom(bom) {
  if (!bom) return bom
  function extensions(value, fields) {
    const result = { ...value }
    for (const property of value.properties || []) {
      const field = property.name.replace(/^ecdat:/, '')
      if (fields.includes(field)) {
        try { result[field] = JSON.parse(property.value) } catch { /* retain malformed metadata as a property */ }
      }
    }
    return result
  }
  return {
    ...extensions(bom, ['summary', 'scan_context', 'discovery_errors', 'coverage']),
    components: (bom.components || []).map(component => extensions(component, ['mosca', 'risk', 'recommendation', 'discovery'])),
  }
}

export function encodeBom(bom, { stripSource = false } = {}) {
  const wire = { ...bom }
  for (const key of ['_offlineMode', 'summary', 'scan_context', 'discovery_errors', 'coverage']) delete wire[key]
  wire.components = (wire.components || []).map(component => {
    const clean = { ...component }
    for (const key of ['mosca', 'risk', 'recommendation', 'discovery', 'vulnerabilities']) delete clean[key]
    if (stripSource && clean.properties) {
      clean.properties = clean.properties.filter(property => !property.name.startsWith('ecdat:source:'))
    }
    return clean
  })
  return wire
}

export function apiHeaders() {
  const token = sessionStorage.getItem('ecdat-api-token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}
