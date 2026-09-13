import test from 'node:test'
import assert from 'node:assert/strict'
import { decodeBom, encodeBom } from './cbom.js'

test('CycloneDX round-trip preserves extensions and removes dashboard-only fields', () => {
  const wire = { bomFormat: 'CycloneDX', specVersion: '1.6', properties: [{ name: 'ecdat:summary', value: '{"total_findings":1}' }],
    components: [{ name: 'RSA', properties: [{ name: 'ecdat:risk', value: '{"score":90}' }, { name: 'ecdat:source:snippet', value: 'key = generate()' }] }] }
  const decoded = decodeBom(wire)
  assert.equal(decoded.summary.total_findings, 1)
  assert.equal(decoded.components[0].risk.score, 90)
  assert.deepEqual(encodeBom(decoded), wire)
  const saved = encodeBom(decoded, { stripSource: true })
  assert.equal(saved.components[0].properties.length, 1)
  assert.equal(decoded.components[0].properties.length, 2)
})
