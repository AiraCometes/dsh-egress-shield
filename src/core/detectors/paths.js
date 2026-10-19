// Absolute path detection with "anchored" pseudonymisation.
//
// A path is identifying because of its *anchor*: the home directory (which
// carries the account name), the workspace root, a UNC server/share, or a WSL
// distro home. In `anchored` mode only that anchor is replaced, so
//   /home/exampleuser/projects/app/.env  →  [REDACTED_PATH_1]/projects/app/.env
// and the model can still reason about the project layout. In `full` mode the
// entire path is replaced. Paths that have no identifying anchor (/usr/lib/…,
// /etc/hosts, API routes such as /v1/chat/completions) are left alone; the
// other detectors still scan their segments for names, user names, etc.

export const GENERIC_ACCOUNTS = new Set([
  'root',
  'user',
  'users',
  'admin',
  'administrator',
  'ubuntu',
  'debian',
  'public',
  'default',
  'guest',
  'shared',
  'all users',
  'default user',
  'node',
  'runner',
  'vscode',
  'codespace',
  'app',
  'home',
])

// Segment characters: anything except separators, quotes, control and shell
// metacharacters. Bounded to keep matching linear.
const SEG = String.raw`[^\s/\\'"\x60<>|;,(){}\[\]*?]{1,255}`
// Segments are separated by a *required* separator: an optional one would let
// the engine split a long segment in exponentially many ways (ReDoS).
const POSIX_RE = new RegExp(String.raw`(?<![\w.~:/\\%-])/${SEG}(?:/${SEG}){0,63}/?`, 'g')
const WIN_SEG = String.raw`[^\\/\r\n\t"'<>|:*?]{1,255}`
const WIN_SEP = String.raw`(?:\\\\|\\|/)`
const WIN_RE = new RegExp(
  String.raw`(?<![A-Za-z0-9_])[A-Za-z]:${WIN_SEP}(?:${WIN_SEG}(?:${WIN_SEP}${WIN_SEG}){0,63}${WIN_SEP}?)?`,
  'g',
)
const UNC_RE =
  /(?<![\w\\])\\\\(?:\\\\)?[A-Za-z0-9._$-]{1,64}(?:\\\\|\\)[^\\\s"'<>|:*?]{1,80}(?:(?:\\\\|\\)[^\\\r\n\t"'<>|:*?]{1,255}){0,64}/g
// /mnt/c/Users/<name with spaces>/… — the generic POSIX pattern stops at the
// first space, which would leave the rest of a "First Last" profile name behind.
const WSL_PROFILE_RE = /(?<![\w.~:/\\%-])\/mnt\/[A-Za-z]\/Users\/[^/\r\n"'<>|:*?]{1,64}?(?=\/)/gi
const FILE_URI_RE = /\bfile:\/\/(?:localhost)?(\/{1,2}[^\s'"<>`]{1,4096})/gi

// Anchor shapes, tried on the path string itself. Group 1 is the account
// segment when the anchor names one.
const SEP = String.raw`(?:\\\\|\\|/)`
const HOME_ANCHORS = [
  // WSL view of a Windows profile: /mnt/c/Users/<name>
  new RegExp(String.raw`^/mnt/[A-Za-z]/Users/([^/\r\n]{1,64}?)(?=/|$)`, 'i'),
  // Windows profile: C:\Users\<name> (spaces allowed inside the name)
  new RegExp(String.raw`^[A-Za-z]:${SEP}Users${SEP}([^\\/\r\n"'<>|:*?]{1,64}?)(?=${SEP}|$|\s)`, 'i'),
  // Windows view of a WSL home: \\wsl$\Ubuntu\home\<name>, \\wsl.localhost\...
  new RegExp(
    String.raw`^${SEP}{2}(?:wsl\$|wsl\.localhost)${SEP}[^\\/]{1,64}${SEP}home${SEP}([^\\/\r\n]{1,64}?)(?=${SEP}|$)`,
    'i',
  ),
  // Linux and macOS homes
  /^\/home\/([^/\s]{1,64})(?=\/|$)/,
  /^\/Users\/([^/\s]{1,64})(?=\/|$)/,
  /^\/var\/home\/([^/\s]{1,64})(?=\/|$)/,
  /^\/root(?=\/|$)/,
]
const UNC_ANCHOR = new RegExp(String.raw`^${SEP}{2}[A-Za-z0-9._$-]{1,64}${SEP}[^\\/\s]{1,80}`)

const TRAILING = /[.,:;!?)\]}'"]+$/

function isWindowsLike(p) {
  return /^[A-Za-z]:|^\\\\/.test(p)
}

function startsWithAnchor(path, anchor) {
  const windows = isWindowsLike(anchor)
  const a = windows ? anchor.toLowerCase().replace(/\\\\/g, '\\') : anchor
  const p = windows ? path.toLowerCase().replace(/\\\\/g, '\\') : path
  if (!p.startsWith(a)) return 0
  const next = p[a.length]
  if (next !== undefined && next !== '/' && next !== '\\') return 0
  // Map the normalised length back onto the original spelling.
  if (!windows) return a.length
  let i = 0
  let consumed = 0
  while (consumed < a.length && i < path.length) {
    if (path[i] === '\\' && path[i + 1] === '\\') i += 2
    else i += 1
    consumed += 1
  }
  return i
}

/**
 * Find the identifying anchor of an absolute path.
 * @returns {{ length: number, account?: string } | null}
 */
export function findAnchor(path, knowledge) {
  let best = null
  for (const anchor of knowledge.anchors) {
    const length = startsWithAnchor(path, anchor)
    if (length && (!best || length > best.length)) best = { length }
  }
  for (const re of HOME_ANCHORS) {
    const m = re.exec(path)
    if (!m) continue
    if (!best || m[0].length > best.length) best = { length: m[0].length, account: m[1] }
    break
  }
  if (!best) {
    const m = UNC_ANCHOR.exec(path)
    if (m) best = { length: m[0].length }
  }
  return best
}

function classify(raw, start, knowledge, spans) {
  const path = raw.replace(TRAILING, '')
  if (path.length < 2) return
  const anchor = findAnchor(path, knowledge)
  if (!anchor) return
  if (anchor.account && !GENERIC_ACCOUNTS.has(anchor.account.toLowerCase())) knowledge.learnUsername(anchor.account)
  if (knowledge.pathMode === 'full') {
    spans.push({ s: start, e: start + path.length, c: 'PATH', r: 'path-full' })
  } else {
    let length = anchor.length
    // Keep the anchor spelling canonical so C:\Users\X and C:/Users/X map to
    // one placeholder.
    const value = path.slice(0, length).replace(/\\\\/g, '\\')
    spans.push({
      s: start,
      e: start + length,
      c: 'PATH',
      r: 'path-anchor',
      v: isWindowsLike(value) ? value.toLowerCase() : value,
    })
  }
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

export function detectPaths(text, knowledge, spans) {
  each(FILE_URI_RE, text, (m) => {
    let inner = m[1]
    let offset = m.index + m[0].length - inner.length
    // file:///C:/Users/x → C:/Users/x
    const drive = /^\/([A-Za-z]:[\\/])/.exec(inner)
    if (drive) {
      inner = inner.slice(1)
      offset += 1
    }
    let decoded = inner
    try {
      decoded = decodeURI(inner)
    } catch {}
    if (decoded !== inner) {
      // Percent-encoded spelling: hide the whole URI path when it is anchored.
      if (findAnchor(decoded, knowledge))
        spans.push({ s: offset, e: offset + inner.replace(TRAILING, '').length, c: 'PATH', r: 'file-uri' })
      return
    }
    classify(inner, offset, knowledge, spans)
  })
  each(WSL_PROFILE_RE, text, (m) => classify(m[0], m.index, knowledge, spans))
  each(POSIX_RE, text, (m) => classify(m[0], m.index, knowledge, spans))
  each(WIN_RE, text, (m) => classify(m[0], m.index, knowledge, spans))
  each(UNC_RE, text, (m) => classify(m[0], m.index, knowledge, spans))
}
