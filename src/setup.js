// Shared start-up: build an Engine seeded with facts about this machine and the
// user's private term list. Used by both the DSH plugin and the standalone CLI.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir, hostname, userInfo } from 'node:os'
import { Engine } from './core/engine.js'
import { CATEGORIES } from './core/categories.js'

const WINDOWS_PROFILE_SKIP = new Set([
  'public',
  'default',
  'default user',
  'all users',
  'desktop.ini',
  'defaultapppool',
  'wdagutilityaccount',
])

/** Account names, host names, and anchors this machine reveals about itself. */
export function discoverLocalFacts() {
  const usernames = new Set()
  const hostnames = new Set()
  const anchors = new Set()
  try {
    usernames.add(userInfo().username)
  } catch {}
  for (const v of ['USER', 'LOGNAME', 'USERNAME', 'SUDO_USER']) if (process.env[v]) usernames.add(process.env[v])
  try {
    const h = hostname()
    hostnames.add(h)
    hostnames.add(h.split('.')[0])
  } catch {}
  try {
    anchors.add(homedir())
  } catch {}
  // WSL: Windows profile names under /mnt/<drive>/Users
  for (const drive of ['c', 'd']) {
    try {
      for (const name of readdirSync(`/mnt/${drive}/Users`)) {
        if (!WINDOWS_PROFILE_SKIP.has(name.toLowerCase())) usernames.add(name)
      }
    } catch {}
  }
  return { usernames: [...usernames], hostnames: [...hostnames], anchors: [...anchors] }
}

/**
 * Load the private term list. Format, one entry per line:
 *   CATEGORY: text      (CATEGORY is one of PERSON, ADDRESS, EMAIL, USERNAME, …)
 *   text                (defaults to PERSON)
 *   # comment
 * The file must not be readable by group/other; otherwise it is refused so a
 * misconfigured file cannot silently become world-readable.
 */
export function loadTerms(file) {
  if (!file) return { terms: [], status: 'none' }
  let st
  try {
    st = statSync(file)
  } catch {
    return { terms: [], status: 'missing' }
  }
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) return { terms: [], status: 'insecure-permissions' }
  const terms = []
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const m = /^([A-Z_]+)\s*:\s*(.+)$/.exec(trimmed)
    if (m && CATEGORIES.includes(m[1])) terms.push({ category: m[1], text: m[2].trim() })
    else terms.push({ category: 'PERSON', text: trimmed })
  }
  return { terms, status: 'loaded' }
}

export function expandHome(p) {
  if (!p) return p
  return p === '~' ? homedir() : p.startsWith('~/') ? `${homedir()}${p.slice(1)}` : p
}

/**
 * @param {{ pathMode?: 'anchored'|'full', termsFile?: string, usernames?: string[], hostnames?: string[],
 *           anchors?: string[], discover?: boolean, englishNames?: boolean }} options
 */
export function buildEngine(options = {}) {
  const facts = options.discover === false ? { usernames: [], hostnames: [], anchors: [] } : discoverLocalFacts()
  const { terms, status } = loadTerms(expandHome(options.termsFile))
  const engine = new Engine({
    pathMode: options.pathMode ?? 'anchored',
    usernames: [...facts.usernames, ...(options.usernames ?? [])],
    hostnames: [...facts.hostnames, ...(options.hostnames ?? [])],
    anchors: [...facts.anchors, ...(options.anchors ?? []).map(expandHome)],
    terms,
    englishNames: options.englishNames,
  })
  return { engine, termsStatus: status }
}
