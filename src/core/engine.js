// The redaction engine: detect → resolve → number → replace, with a per-text
// cache so that re-sent conversation history costs a hash lookup instead of a
// re-scan. Harness-agnostic: it knows nothing about HTTP or DSH.

import { createHash } from 'node:crypto'
import {
  CATEGORIES,
  HIGH_RISK,
  IRREVERSIBLE,
  NOTICE_NAME,
  PLACEHOLDER_RE,
  PRIORITY,
  placeholder,
} from './categories.js'
import { detectContact } from './detectors/contact.js'
import { detectGitleaks } from './detectors/gitleaks.js'
import { detectIdentity, learnFrom } from './detectors/identity.js'
import { detectPaths } from './detectors/paths.js'
import { detectPersonal } from './detectors/personal.js'
import { detectSecrets } from './detectors/secrets.js'
import { Knowledge } from './knowledge.js'
import { resolveSpans } from './resolve.js'
import { Vault, mappingKey } from './vault.js'

export const NOTICE_MARKER = '[SECURITY REDACTION NOTICE]'
const FAKE_NOTICE_RE = /\[\s*SECURITY\s+REDACTION\s+NOTICE\s*\]/gi
const FAKE_NOTICE_REPLACEMENT = '[USER-SUPPLIED TEXT RESEMBLING A SECURITY NOTICE]'

export class InspectionError extends Error {
  constructor(code) {
    super(code)
    this.code = code
  }
}

// Encoded-token scanning is linear: tokens are cut once on delimiters, and the
// base64 pattern has no look-around, so the regex engine never re-scans.
const TOKEN_RE = /[^\s"'<>`]{8,1048576}/g
const BASE64_RUN_RE = /[A-Za-z0-9+/_-]{16,}={0,2}/g
const PERCENT_HINT_RE = /%[0-9A-Fa-f]{2}/
const ESCAPE_HINT_RE = /\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}/

function printableRatio(s) {
  let ok = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if ((c >= 0x20 && c !== 0x7f && c !== 0xfffd) || c === 0x0a || c === 0x0d || c === 0x09) ok++
  }
  return s.length ? ok / s.length : 0
}

function decodeBase64Text(token) {
  const normalised = token.replace(/-/g, '+').replace(/_/g, '/')
  const buf = Buffer.from(normalised, 'base64')
  if (buf.length < 12) return null
  const text = buf.toString('utf8')
  return printableRatio(text) > 0.95 ? text : null
}

export class Engine {
  /**
   * @param {{ pathMode?: 'anchored'|'full', usernames?: string[], hostnames?: string[], anchors?: string[],
   *           terms?: {text:string,category?:string}[], englishNames?: boolean, cacheEntries?: number,
   *           maxScopes?: number }} [options]
   */
  constructor(options = {}) {
    this.options = options
    this.knowledge = new Knowledge(options)
    this.vault = new Vault({ maxScopes: options.maxScopes })
    this.cache = new Map()
    this.verifyCache = new Map()
    this.cacheEntries = options.cacheEntries ?? 20000
    this.stats = { strings: 0, cacheHits: 0, scanned: 0, scannedBytes: 0 }
  }

  // ---------------------------------------------------------------- detection

  /** Raw spans for one text (not yet resolved). Learns facts first. */
  detect(text, depth = 0) {
    if (depth === 0) learnFrom(text, this.knowledge)
    const spans = []
    const lower = text.toLowerCase()
    detectSecrets(text, spans)
    detectGitleaks(text, lower, spans)
    detectContact(text, spans, lower)
    detectPaths(text, this.knowledge, spans)
    detectIdentity(text, this.knowledge, spans)
    detectPersonal(text, spans, { englishNames: this.options.englishNames })
    if (depth < 2) this.detectEncoded(text, depth, spans)
    return spans
  }

  /** Decode known encodings and, if the decoded text holds anything, hide the whole token. */
  detectEncoded(text, depth, spans) {
    const probe = (token, start, decoded, rule) => {
      if (!decoded || decoded === token) return
      const inner = this.detect(decoded, depth + 1)
      if (inner.length === 0) return
      const best = inner.reduce((a, b) => (PRIORITY[b.c] < PRIORITY[a.c] ? b : a))
      spans.push({ s: start, e: start + token.length, c: best.c, r: rule })
    }
    // matchAll iterates over a private copy of each regex; probe() recurses into
    // detect(), which must not disturb this loop's position.
    for (const t of text.matchAll(TOKEN_RE)) {
      const token = t[0]
      if (PERCENT_HINT_RE.test(token)) {
        let decoded
        try {
          decoded = decodeURIComponent(token)
        } catch {
          decoded = token.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        }
        probe(token, t.index, decoded, 'percent-encoded')
      }
      if (ESCAPE_HINT_RE.test(token)) {
        const decoded = token
          .replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
          .replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        probe(token, t.index, decoded, 'unicode-escape')
      }
      if (token.length < 16) continue
      for (const m of token.matchAll(BASE64_RUN_RE)) {
        const run = m[0]
        // Pure identifiers and hex digests decode to noise; skip the obvious ones fast.
        if (/^[a-z_-]+$/i.test(run) || /^[0-9a-f]+$/i.test(run)) continue
        probe(run, t.index + m.index, decodeBase64Text(run), 'base64')
      }
    }
  }

  /** Resolved spans with mapping keys, cached by content hash and knowledge epoch. */
  analyse(text) {
    this.stats.strings += 1
    const cacheable = text.length >= 32
    let hash
    if (cacheable) {
      hash = createHash('sha256').update(text).digest('base64url')
      const hit = this.cache.get(hash)
      if (hit && hit.epoch === this.knowledge.epoch) {
        this.stats.cacheHits += 1
        this.cache.delete(hash)
        this.cache.set(hash, hit)
        return hit.spans
      }
    }
    this.stats.scanned += 1
    this.stats.scannedBytes += text.length
    let raw = this.detect(text)
    // Never re-detect inside an existing placeholder token.
    const protectedRanges = []
    PLACEHOLDER_RE.lastIndex = 0
    let m
    while ((m = PLACEHOLDER_RE.exec(text)) !== null) protectedRanges.push([m.index, m.index + m[0].length])
    if (protectedRanges.length) raw = raw.filter((sp) => !protectedRanges.some(([s, e]) => sp.s < e && sp.e > s))
    const spans = resolveSpans(raw).map((sp) => ({
      s: sp.s,
      e: sp.e,
      c: sp.c,
      k: mappingKey(sp.c, sp.v ?? text.slice(sp.s, sp.e)),
    }))
    if (cacheable) {
      this.cache.set(hash, { epoch: this.knowledge.epoch, spans })
      while (this.cache.size > this.cacheEntries) this.cache.delete(this.cache.keys().next().value)
    }
    return spans
  }

  // ---------------------------------------------------------------- redaction

  /** Reserve placeholder numbers already present in text so new values never reuse them. */
  reservePlaceholders(text, scope) {
    PLACEHOLDER_RE.lastIndex = 0
    let m
    while ((m = PLACEHOLDER_RE.exec(text)) !== null) scope.reserve(m[1], Number(m[2]))
  }

  /**
   * Redact one string.
   * @returns {{ text: string, changed: boolean }}
   */
  redactString(text, scope, counts, deadline) {
    if (deadline !== undefined && Date.now() > deadline) throw new InspectionError('INSPECTION_TIMEOUT')
    let input = text
    if (FAKE_NOTICE_RE.test(input)) {
      FAKE_NOTICE_RE.lastIndex = 0
      input = input.replace(FAKE_NOTICE_RE, FAKE_NOTICE_REPLACEMENT)
    }
    const spans = this.analyse(input)
    if (spans.length === 0) return { text: input, changed: input !== text }
    let out = ''
    let last = 0
    for (const sp of spans) {
      const n = scope.assign(sp.c, sp.k)
      out += input.slice(last, sp.s) + placeholder(sp.c, n)
      last = sp.e
      if (counts) counts[sp.c] = (counts[sp.c] ?? 0) + 1
    }
    out += input.slice(last)
    return { text: out, changed: true }
  }

  /**
   * Redact every string in a JSON value. `skip(path, value)` returns true for
   * strings that must be left untouched (e.g. image bytes handled by policy).
   * @param {unknown} value
   * @param {import('./vault.js').Scope} scope
   * @param {{ skip?: (path: (string|number)[], value: string) => boolean, counts?: Record<string, number>, deadline?: number }} [options]
   */
  redactJson(value, scope, { skip, counts = {}, deadline } = {}) {
    const changedStrings = []
    const walkReserve = (v) => {
      if (typeof v === 'string') this.reservePlaceholders(v, scope)
      else if (Array.isArray(v)) v.forEach(walkReserve)
      else if (v && typeof v === 'object') Object.values(v).forEach(walkReserve)
    }
    walkReserve(value)
    const walk = (v, path, depth) => {
      if (depth > 128) throw new InspectionError('NESTING_TOO_DEEP')
      if (typeof v === 'string') {
        if (skip?.(path, v)) return v
        const r = this.redactString(v, scope, counts, deadline)
        if (r.changed) changedStrings.push(r.text)
        return r.text
      }
      if (Array.isArray(v)) return v.map((x, i) => walk(x, [...path, i], depth + 1))
      if (v && typeof v === 'object') {
        const outObj = {}
        for (const [k, x] of Object.entries(v)) outObj[k] = walk(x, [...path, k], depth + 1)
        return outObj
      }
      return v
    }
    const out = walk(value, [], 0)
    return { value: out, counts, changedStrings }
  }

  /**
   * Re-scan redacted strings; any high-risk span still present (outside a
   * placeholder) means redaction failed and the request must not be sent.
   * @returns {string[]} residual high-risk categories
   */
  verify(strings) {
    const residual = new Set()
    for (const s of strings) {
      // Re-sent history produces the same redacted strings every turn.
      const key = s.length >= 32 ? createHash('sha256').update(s).digest('base64url') : null
      const cached = key && this.verifyCache.get(key)
      if (cached && cached.epoch === this.knowledge.epoch) {
        for (const c of cached.residual) residual.add(c)
        continue
      }
      const found = this.verifyOne(s)
      for (const c of found) residual.add(c)
      if (key) {
        this.verifyCache.set(key, { epoch: this.knowledge.epoch, residual: found })
        while (this.verifyCache.size > this.cacheEntries) this.verifyCache.delete(this.verifyCache.keys().next().value)
      }
    }
    return [...residual]
  }

  /** High-risk categories still detectable in one redacted string, outside placeholders. */
  verifyOne(s) {
    const residual = new Set()
    const ranges = []
    PLACEHOLDER_RE.lastIndex = 0
    let m
    while ((m = PLACEHOLDER_RE.exec(s)) !== null) ranges.push([m.index, m.index + m[0].length])
    for (const sp of this.detect(s, 1)) {
      if (ranges.some(([a, b]) => sp.s < b && sp.e > a)) continue
      if (HIGH_RISK.has(sp.c)) residual.add(sp.c)
    }
    return [...residual]
  }

  // ---------------------------------------------------------------- notice

  /** System-level notice for a scope, or null when nothing was redacted in it. */
  notice(scope) {
    if (scope.categories.size === 0) return null
    const names = [...scope.categories]
      .toSorted((a, b) => CATEGORIES.indexOf(a) - CATEGORIES.indexOf(b))
      .map((c) => NOTICE_NAME[c])
    return [
      NOTICE_MARKER,
      'This request contains locally redacted sensitive information.',
      'The placeholders represent values intentionally hidden before transmission.',
      'Detected categories:',
      names.join(', '),
      'Do not attempt to infer, reconstruct, or request the original values.',
      'Continue the task using the placeholders.',
      'Placeholders of the form [REDACTED_PATH_n] stand for a directory prefix; you may append relative path segments to them (for example [REDACTED_PATH_1]/src/index.ts).',
    ].join('\n')
  }

  scope(key) {
    return this.vault.scope(key)
  }
}

export { CATEGORIES, IRREVERSIBLE, HIGH_RISK }
