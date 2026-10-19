// Structural secret detectors that complement the Gitleaks rules: key blocks,
// auth headers, key=value assignments, connection strings, URL credentials, and
// a few token shapes Gitleaks leaves to its generic rule.
//
// Every regex here uses bounded quantifiers so a hostile input cannot trigger
// catastrophic backtracking (see test/redos.test.js).

const PEM_RE = /-----BEGIN ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY( BLOCK)?-----[\s\S]{0,20000}?-----END \1PRIVATE KEY\2-----/g
const PEM_OPEN_RE = /-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----/g
const PUTTY_RE = /PuTTY-User-Key-File-\d+:[\s\S]{0,20000}?Private-MAC:\s*[0-9a-fA-F]{20,128}/g
const SSH_PUB_RE =
  /\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+AAAA[0-9A-Za-z+/]{20,8000}={0,3}(?:[ \t]+[^\s'"`]{1,200})?/g
const AUTH_SCHEME_RE = /\b(?:Bearer|Basic|Token|Digest)[ \t]+([A-Za-z0-9._~+/=-]{8,4096})/g
const COOKIE_LINE_RE = /\b(?:Set-)?Cookie[ \t]*:[ \t]*([^\r\n]{1,8192})/gi
const COOKIE_PAIR_RE = /([A-Za-z0-9_.!#$%&'*+^`|~-]{1,128})=("[^"\r\n]{0,4096}"|[^;,\s]{1,4096})/g
const CONN_RE = /\b[a-zA-Z][a-zA-Z0-9+.-]{1,30}:\/\/([^\s:@/?#'"`<>]{1,256}):([^\s@/?#'"`<>]{1,512})@/g
const URL_QUERY_RE =
  /[?&;]((?:access_?token|refresh_?token|id_?token|token|api_?key|apikey|key|sig|signature|auth|code|password|passwd|pwd|secret|client_secret|session|sessionid|sid|x-amz-signature|x-amz-credential|x-goog-signature)=)([^&#\s"'`<>]{4,4096})/gi
const OPENAI_LIKE_RE = /\b(?:sk|pk|rk)-(?:proj-|svcacct-|admin-|ant-[a-z0-9]+-|live-|test-)?[A-Za-z0-9_-]{16,256}/g
const TSKEY_RE = /\btskey-(?:auth|client|api|scim|webhook)?-?[A-Za-z0-9]{6,64}-[A-Za-z0-9]{10,128}\b/g
// Well-known token prefixes, matched without the entropy/allowlist filters
// Gitleaks applies for repository scanning: on the way to a third party, a
// documentation-looking key is still not worth sending.
const WELL_KNOWN_RE =
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{22,255}|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,255}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,64}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,64}|sk_(?:live|test)_[A-Za-z0-9]{16,128}|rk_(?:live|test)_[A-Za-z0-9]{16,128}|SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}|dop_v1_[a-f0-9]{64}|pypi-[A-Za-z0-9_-]{50,})/g
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}/g

// key = value / key: value in .env, YAML, JSON, INI, TOML, logs, and code.
const KV_KEYS = String.raw`(?:[A-Za-z0-9_.-]{0,40}?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key(?:[_.-]?id)?|private[_.-]?key|client[_.-]?secret|auth(?:[_.-]?token)?|credentials?|session[_.-]?(?:id|key|token)|cookie|signature)[A-Za-z0-9_.-]{0,20})`
// URL query parameters (?token=…&x=1) are left to URL_QUERY_RE, which stops at '&'.
const KV_RE = new RegExp(
  String.raw`(?<![A-Za-z0-9_?&])(["']?)(${KV_KEYS})\1[ \t]{0,8}(?:=|:=|:|=>)[ \t]{0,8}(?:"([^"\r\n]{1,4096})"|'([^'\r\n]{1,4096})'|([^\s,;'"\x60)\]}]{1,4096}))`,
  'gi',
)
const CLI_FLAG_RE =
  /(?<![\w-])--?(?:password|passwd|pass|token|api-?key|secret|client-secret|auth-token|access-key|secret-key)(?:=|[ \t]+)(?:"([^"\r\n]{1,1024})"|'([^'\r\n]{1,1024})'|([^\s'"]{1,1024}))/gi

// Values that are clearly not secrets (references, empty, placeholders, code).
const NOT_A_SECRET = [
  /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/, // $VAR, ${VAR}
  /^%[A-Za-z_][A-Za-z0-9_]*%$/, // %VAR%
  /^\$\{\{.*\}\}$/, // ${{ secrets.X }}
  /^\{\{.*\}\}$/, // {{ template }}
  /^<[^<>]{1,64}>$/, // <your-token>
  /^\*+$|^x+$|^\.+$|^-+$/i,
  /^(?:true|false|null|none|nil|undefined|yes|no|on|off|required|optional|string|number|boolean|object|bearer|basic|token|password|secret|redacted|changeme|example|xxx+|\?\?\?)$/i,
  /^(?:process\.env|os\.environ|env|config|settings|self|this|options|opts|args|params|props|req|request|ctx)\b/,
  /^[A-Za-z_$][\w$]*(?:\.[\w$]+)*\(/, // function call
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/, // property access a.b.c
  /^\[REDACTED_[A-Z_]+_\d+\]$/,
  /^\d{1,6}$/, // ports, counts, ids
]

function looksLikeSecret(value) {
  if (value.length < 4) return false
  for (const re of NOT_A_SECRET) if (re.test(value)) return false
  return true
}

function each(re, text, fn) {
  re.lastIndex = 0
  let m
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++
      continue
    }
    fn(m)
  }
}

/**
 * Push the span of the first defined capture group among `groups`. Every
 * caller's value group ends the match (at most a closing quote follows), so
 * the last occurrence of the value inside the match is the capture itself.
 * @param {object[]} spans
 * @param {RegExpExecArray} m
 * @param {number[]} groups
 * @param {string} category
 * @param {string} rule
 * @param {(value: string) => boolean} [check]
 */
function pushGroup(spans, m, groups, category, rule, check = () => true) {
  for (const g of groups) {
    const value = m[g]
    if (value === undefined) continue
    const s = m.index + m[0].lastIndexOf(value)
    if (check(value)) spans.push({ s, e: s + value.length, c: category, r: rule })
    return
  }
}

export function detectSecrets(text, spans) {
  // Private keys: whole block, including an unterminated (truncated) block.
  let covered = []
  each(PEM_RE, text, (m) => {
    spans.push({ s: m.index, e: m.index + m[0].length, c: 'SSH_KEY', r: 'pem' })
    covered.push([m.index, m.index + m[0].length])
  })
  each(PEM_OPEN_RE, text, (m) => {
    if (covered.some(([s, e]) => m.index >= s && m.index < e)) return
    // Truncated output: hide everything from the header to the end of text
    // (bounded) rather than leave key material behind.
    const end = Math.min(text.length, m.index + 20000)
    spans.push({ s: m.index, e: end, c: 'SSH_KEY', r: 'pem-unterminated' })
  })
  if (text.includes('PuTTY-User-Key-File'))
    each(PUTTY_RE, text, (m) => spans.push({ s: m.index, e: m.index + m[0].length, c: 'SSH_KEY', r: 'putty' }))
  each(SSH_PUB_RE, text, (m) => spans.push({ s: m.index, e: m.index + m[0].length, c: 'SSH_KEY', r: 'ssh-public-key' }))

  each(AUTH_SCHEME_RE, text, (m) => {
    // After an auth scheme any opaque value is a credential; only variable
    // references and placeholders are exempt (no code heuristics here).
    const v = m[1]
    if (/^[a-z]+$/.test(v) || /^\$\{?\w+\}?$|^\[REDACTED_|^<[^>]+>$/.test(v)) return
    pushGroup(spans, m, [1], 'API_KEY', 'auth-scheme')
  })
  each(WELL_KNOWN_RE, text, (m) =>
    spans.push({ s: m.index, e: m.index + m[0].length, c: 'API_KEY', r: 'well-known-prefix' }),
  )
  if (/cookie/i.test(text))
    each(COOKIE_LINE_RE, text, (m) => {
      const line = m[1]
      const base = m.index + m[0].length - line.length
      each(COOKIE_PAIR_RE, line, (p) => {
        const value = p[2]
        if (/^(?:path|domain|expires|max-age|samesite|secure|httponly)$/i.test(p[1])) return
        if (value.length < 4) return
        const s = base + p.index + p[0].length - value.length
        spans.push({ s, e: s + value.length, c: 'API_KEY', r: 'cookie' })
      })
    })
  if (text.includes('://'))
    each(CONN_RE, text, (m) => {
      const userStart = m.index + m[0].indexOf('://') + 3
      spans.push({ s: userStart, e: userStart + m[1].length, c: 'USERNAME', r: 'url-userinfo' })
      const passStart = userStart + m[1].length + 1
      spans.push({ s: passStart, e: passStart + m[2].length, c: 'PASSWORD', r: 'url-userinfo' })
    })
  each(URL_QUERY_RE, text, (m) => {
    const s = m.index + 1 + m[1].length
    if (looksLikeSecret(m[2]))
      spans.push({ s, e: s + m[2].length, c: /pass|pwd/i.test(m[1]) ? 'PASSWORD' : 'API_KEY', r: 'url-query' })
  })
  each(OPENAI_LIKE_RE, text, (m) => {
    if (/[0-9]/.test(m[0]) || m[0].length >= 28)
      spans.push({ s: m.index, e: m.index + m[0].length, c: 'API_KEY', r: 'sk-token' })
  })
  if (text.includes('tskey-'))
    each(TSKEY_RE, text, (m) => spans.push({ s: m.index, e: m.index + m[0].length, c: 'API_KEY', r: 'tailscale-key' }))
  if (text.includes('eyJ'))
    each(JWT_RE, text, (m) => spans.push({ s: m.index, e: m.index + m[0].length, c: 'API_KEY', r: 'jwt' }))

  each(KV_RE, text, (m) => {
    const key = m[2]
    const category = /pass|pwd/i.test(key) ? 'PASSWORD' : 'API_KEY'
    pushGroup(spans, m, [3, 4, 5], category, 'key-value', looksLikeSecret)
  })
  if (text.includes('-'))
    each(CLI_FLAG_RE, text, (m) => {
      const category = /pass/i.test(m[0]) ? 'PASSWORD' : 'API_KEY'
      pushGroup(spans, m, [1, 2, 3], category, 'cli-flag', looksLikeSecret)
    })
}
