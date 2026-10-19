// U-27: hostile inputs must not make any detector backtrack catastrophically.
import { test } from 'vitest'
import assert from 'node:assert/strict'
import { Engine } from '../src/core/engine.js'

const SIZE = 100_000
const PATHOLOGICAL = {
  'long segment': 'a'.repeat(SIZE),
  slashes: '/a'.repeat(SIZE / 2),
  backslashes: 'C:' + '\\a'.repeat(SIZE / 2),
  unc: '\\\\s\\' + 'x'.repeat(SIZE),
  'key=value spam': 'password='.repeat(SIZE / 9),
  'email-ish': 'a.'.repeat(SIZE / 2) + '@',
  'at-spam': '@a'.repeat(SIZE / 2),
  'idn email-ish': 'a@' + '例.'.repeat(SIZE / 4) + 'テ'.repeat(SIZE / 2),
  digits: '4'.repeat(SIZE),
  'spaced digits': '4 '.repeat(SIZE / 2),
  'base64 run': 'Ab+/'.repeat(SIZE / 4),
  'percent run': '%4'.repeat(SIZE / 2),
  'pem header only': '-----BEGIN PRIVATE KEY-----' + 'A'.repeat(SIZE),
  kanji: '田中'.repeat(SIZE / 2),
  'address-ish': '東京都' + '1-'.repeat(SIZE / 2),
  'capitalised words': 'Dear Aa '.repeat(SIZE / 8),
  'url query': 'https://x.test/?' + 'token=a&'.repeat(SIZE / 8),
  bearer: 'Bearer '.repeat(SIZE / 7),
  'ts.net': 'a.'.repeat(SIZE / 2) + 'ts.net',
}

for (const [name, input] of Object.entries(PATHOLOGICAL)) {
  test(`ReDoS: ${name} (${input.length} chars)`, () => {
    const engine = new Engine({ usernames: ['exampleuser'] })
    const t0 = performance.now()
    engine.redactString(input, engine.scope('r'), {})
    const ms = performance.now() - t0
    // Generous bound for slow CI machines; linear-time scans take tens of ms.
    assert.ok(ms < 250, `${name} took ${ms.toFixed(0)} ms`)
  })
}
