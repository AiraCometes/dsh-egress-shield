// Runs the imported Gitleaks rule set. Rules are compiled lazily and only run
// when one of their keywords occurs in the text (the same prefilter Gitleaks
// itself uses), which keeps the cost close to one pass over the input.

import { AhoCorasick } from '../aho-corasick.js'
import { shannonEntropy } from '../entropy.js'
import { GITLEAKS_GLOBAL_ALLOW, GITLEAKS_RULES } from '../rules/gitleaks.generated.js'

function categoryFor(id) {
  if (id.includes('private-key')) return 'SSH_KEY'
  if (id.includes('password')) return 'PASSWORD'
  return 'API_KEY'
}

const compiled = GITLEAKS_RULES.map((rule) => ({
  rule,
  category: categoryFor(rule.id),
  re: null,
  allow: (rule.allow ?? []).map((a) => ({
    ...a,
    res: a.regexes.map((r) => new RegExp(r.source, r.flags)),
  })),
}))
const globalAllow = GITLEAKS_GLOBAL_ALLOW.regexes.map((r) => new RegExp(r.source, r.flags))
const globalStop = GITLEAKS_GLOBAL_ALLOW.stopwords

const keywordOwners = new Map()
for (const [index, entry] of compiled.entries()) {
  for (const keyword of entry.rule.keywords) {
    if (!keywordOwners.has(keyword)) keywordOwners.set(keyword, [])
    keywordOwners.get(keyword).push(index)
  }
}
const keywords = [...keywordOwners.keys()]
const automaton = new AhoCorasick(keywords)

function lineAround(text, start, end) {
  const s = text.lastIndexOf('\n', start) + 1
  const e = text.indexOf('\n', end)
  return text.slice(s, e === -1 ? text.length : e)
}

function allowed(entry, secret, match, line) {
  for (const re of globalAllow) if (re.test(secret)) return true
  const lowered = secret.toLowerCase()
  for (const word of globalStop) if (lowered.includes(word)) return true
  for (const a of entry.allow) {
    const target = a.target === 'match' ? match : a.target === 'line' ? line : secret
    const byRegex = a.res.some((re) => re.test(target))
    const byStop = a.stopwords.some((w) => lowered.includes(w))
    if (a.condition === 'AND' ? byRegex && byStop && (a.res.length > 0 || a.stopwords.length > 0) : byRegex || byStop)
      return true
  }
  return false
}

/**
 * @param {string} text
 * @param {string} lower lower-cased text
 * @param {Array} spans output
 */
export function detectGitleaks(text, lower, spans) {
  const present = automaton.present(lower)
  if (present.size === 0) return
  const ruleIndexes = new Set()
  for (const id of present) for (const index of keywordOwners.get(keywords[id])) ruleIndexes.add(index)
  for (const index of ruleIndexes) {
    const entry = compiled[index]
    entry.re ??= new RegExp(entry.rule.source, `${entry.rule.flags}gd`)
    const re = entry.re
    re.lastIndex = 0
    let m
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++
        continue
      }
      // Gitleaks reports the first non-empty group as the secret unless a
      // rule names its group explicitly.
      let group = entry.rule.secretGroup ?? 0
      if (!group) {
        for (let g = 1; g < m.length; g++)
          if (m[g]) {
            group = g
            break
          }
      }
      const [s, e] = m.indices[group] ?? m.indices[0]
      const secret = text.slice(s, e)
      if (entry.rule.entropy && shannonEntropy(secret) < entry.rule.entropy) continue
      if (allowed(entry, secret, m[0], lineAround(text, s, e))) continue
      spans.push({ s, e, c: entry.category, r: entry.rule.id })
    }
  }
}

export const GITLEAKS_RULE_COUNT = compiled.length
