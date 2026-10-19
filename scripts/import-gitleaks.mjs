#!/usr/bin/env node
// Convert Gitleaks' default rule set (config/gitleaks.toml, MIT License,
// Copyright (c) 2019 Zachary Rice) into a JavaScript module the runtime engine
// loads without any TOML or RE2 dependency.
//
// Usage: node scripts/import-gitleaks.mjs <path/to/gitleaks.toml> <gitleaks-commit> [out]
//
// Translation rules (Go RE2 → ECMAScript):
//   - a leading (?i) becomes the `i` flag; a (?i) later in the pattern also
//     widens the whole pattern to `i` (ECMAScript in Node 22 has no inline
//     modifiers) — this only ever matches more, never less;
//   - (?s) becomes the `s` flag, (?-i:...) groups are kept as plain groups;
//   - POSIX classes ([:alnum:] etc.) are expanded inside bracket expressions;
//   - \A / \z become ^ / $, (?P<name> becomes (?<name>.
// Rules that still fail to compile are reported and dropped; the generated
// file records how many were dropped so a drop never goes unnoticed.

import { readFileSync, writeFileSync } from 'node:fs'

const [, , src, commit = 'unknown', out = 'src/core/rules/gitleaks.generated.js'] = process.argv
if (!src) {
  console.error('usage: import-gitleaks.mjs <gitleaks.toml> <commit> [out]')
  process.exit(2)
}

/** Minimal TOML reader for the subset gitleaks.toml uses. */
function parseToml(text) {
  const root = {}
  let current = root
  let i = 0
  const n = text.length
  const skipWs = () => {
    while (i < n && (text[i] === ' ' || text[i] === '\t')) i++
  }
  const skipWsNl = () => {
    for (;;) {
      while (i < n && /\s/.test(text[i])) i++
      if (text[i] === '#') {
        while (i < n && text[i] !== '\n') i++
        continue
      }
      break
    }
  }
  const readValue = () => {
    skipWs()
    if (text.startsWith("'''", i)) {
      const end = text.indexOf("'''", i + 3)
      const v = text.slice(i + 3, end)
      i = end + 3
      return v.startsWith('\n') ? v.slice(1) : v
    }
    if (text[i] === "'") {
      const end = text.indexOf("'", i + 1)
      const v = text.slice(i + 1, end)
      i = end + 1
      return v
    }
    if (text[i] === '"') {
      let v = ''
      i++
      while (text[i] !== '"') {
        if (text[i] === '\\') {
          const c = text[i + 1]
          v += c === 'n' ? '\n' : c === 't' ? '\t' : c === '\\' ? '\\' : c === '"' ? '"' : c
          i += 2
        } else v += text[i++]
      }
      i++
      return v
    }
    if (text[i] === '[') {
      i++
      const arr = []
      for (;;) {
        skipWsNl()
        if (text[i] === ']') {
          i++
          break
        }
        arr.push(readValue())
        skipWsNl()
        if (text[i] === ',') i++
      }
      return arr
    }
    const m = /^[^\s#,\]]+/.exec(text.slice(i))
    i += m[0].length
    if (m[0] === 'true') return true
    if (m[0] === 'false') return false
    return Number(m[0])
  }
  while (i < n) {
    skipWsNl()
    if (i >= n) break
    if (text.startsWith('[[', i)) {
      const end = text.indexOf(']]', i)
      const path = text
        .slice(i + 2, end)
        .trim()
        .split('.')
      i = end + 2
      let parent = root
      for (const key of path.slice(0, -1)) {
        const holder = parent[key]
        parent = Array.isArray(holder) ? holder[holder.length - 1] : (parent[key] ??= {})
      }
      const last = path[path.length - 1]
      parent[last] ??= []
      current = {}
      parent[last].push(current)
      continue
    }
    if (text[i] === '[') {
      const end = text.indexOf(']', i)
      const key = text.slice(i + 1, end).trim()
      i = end + 1
      current = root[key] ??= {}
      continue
    }
    const m = /^([A-Za-z0-9_-]+)\s*=/.exec(text.slice(i))
    if (!m) throw new Error(`unexpected TOML at offset ${i}: ${text.slice(i, i + 40)}`)
    i += m[0].length
    current[m[1]] = readValue()
  }
  return root
}

const POSIX = {
  alnum: 'a-zA-Z0-9',
  alpha: 'a-zA-Z',
  digit: '0-9',
  xdigit: '0-9a-fA-F',
  lower: 'a-z',
  upper: 'A-Z',
  space: '\\s',
  punct: '!-\\/:-@\\[-`{-~',
  word: '\\w',
}

/** Translate one RE2 pattern; returns { source, flags } or throws. */
export function translate(pattern) {
  let source = pattern
  let flags = ''
  const lead = /^\(\?([is]+)\)/.exec(source)
  if (lead) {
    flags += lead[1]
    source = source.slice(lead[0].length)
  }
  if (/\(\?i\)/.test(source)) {
    flags += 'i'
    source = source.replace(/\(\?i\)/g, '')
  }
  if (/\(\?s\)/.test(source)) {
    flags += 's'
    source = source.replace(/\(\?s\)/g, '')
  }
  source = source
    .replace(/\(\?s:\.\)/g, '[\\s\\S]')
    .replace(/\(\?-?i:/g, '(?:')
    .replace(/\(\?P</g, '(?<')
    .replace(/\\A/g, '^')
    .replace(/\\z/g, '$')
    .replace(/\[:(\w+):\]/g, (all, name) => POSIX[name] ?? all)
  flags = [...new Set(flags)].join('')
  RegExp(source, flags) // compiling validates the translation; throws on failure
  return { source, flags }
}

function translateList(list = [], dropped, where) {
  const outList = []
  for (const p of list) {
    try {
      outList.push(translate(p))
    } catch (e) {
      dropped.push(`${where}: ${e.message}`)
    }
  }
  return outList
}

const toml = parseToml(readFileSync(src, 'utf8'))
const dropped = []
const rules = []
for (const r of toml.rules ?? []) {
  if (!r.regex) continue // path-only rules do not apply to request payloads
  let re
  try {
    re = translate(r.regex)
  } catch (e) {
    dropped.push(`${r.id}: ${e.message}`)
    continue
  }
  const allow = (r.allowlists ?? []).map((a) => ({
    target: a.regexTarget ?? 'secret',
    regexes: translateList(a.regexes, dropped, `${r.id} allowlist`),
    stopwords: (a.stopwords ?? []).map((s) => s.toLowerCase()),
    condition: a.condition ?? 'OR',
  }))
  rules.push({
    id: r.id,
    source: re.source,
    flags: re.flags,
    keywords: (r.keywords ?? []).map((k) => k.toLowerCase()),
    ...(r.entropy ? { entropy: r.entropy } : {}),
    ...(r.secretGroup ? { secretGroup: r.secretGroup } : {}),
    ...(allow.length ? { allow } : {}),
  })
}
const globalAllow = {
  regexes: translateList(toml.allowlist?.regexes, dropped, 'global allowlist'),
  stopwords: (toml.allowlist?.stopwords ?? []).map((s) => s.toLowerCase()),
}

const header = `// GENERATED by scripts/import-gitleaks.mjs — do not edit by hand.
// Source: https://github.com/gitleaks/gitleaks config/gitleaks.toml @ ${commit}
// Gitleaks is MIT licensed, Copyright (c) 2019 Zachary Rice. See THIRD_PARTY_NOTICES.md.
// Rules imported: ${rules.length}; patterns dropped during RE2 → ECMAScript translation: ${dropped.length}.
`
writeFileSync(
  out,
  `${header}
export const GITLEAKS_COMMIT = ${JSON.stringify(commit)}
export const GITLEAKS_DROPPED = ${JSON.stringify(dropped, null, 1)}
export const GITLEAKS_GLOBAL_ALLOW = ${JSON.stringify(globalAllow)}
export const GITLEAKS_RULES = ${JSON.stringify(rules, null, 0).replace(/\},\{"id"/g, '},\n{"id"')}
`,
)
console.log(`imported ${rules.length} rules, dropped ${dropped.length}`)
for (const d of dropped) console.log('  dropped:', d)
