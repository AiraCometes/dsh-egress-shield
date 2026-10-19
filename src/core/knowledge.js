// Process-wide facts the detectors use: account names, host names, workspace
// anchors, and the user's own term list. Facts are added at start-up (from the
// OS and configuration) and learned from traffic (e.g. the account segment of
// /home/<name>). Every change bumps `epoch`, which invalidates cached results.
//
// Nothing here is ever logged; only counts are exposed.

import { GENERIC_ACCOUNTS } from './detectors/paths.js'

/** Case- and space-insensitive form used to compare terms. */
function normTerm(s) {
  return s.toLowerCase().replace(/[ \u3000]/g, '')
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export class Knowledge {
  /** @type {RegExp | false | null} */
  #identityRe = null
  /** @type {RegExp | false | null} */
  #termsRe = null

  constructor({ pathMode = 'anchored', usernames = [], hostnames = [], anchors = [], terms = [] } = {}) {
    this.pathMode = pathMode
    this.usernames = new Set()
    this.hostnames = new Set()
    this.anchors = []
    /** @type {{ text: string, category: string }[]} */
    this.terms = []
    this.epoch = 0
    for (const u of usernames) this.learnUsername(u)
    for (const h of hostnames) this.learnHostname(h)
    for (const a of anchors) this.addAnchor(a)
    this.setTerms(terms)
  }

  #changed() {
    this.epoch += 1
    this.#identityRe = null
  }

  learnUsername(name) {
    if (!name || name.length < 3 || GENERIC_ACCOUNTS.has(name.toLowerCase())) return
    if (this.usernames.has(name)) return
    this.usernames.add(name)
    this.#changed()
  }

  learnHostname(name) {
    if (!name || name.length < 3 || /^(localhost|ip6-localhost)$/i.test(name)) return
    if (this.hostnames.has(name)) return
    this.hostnames.add(name)
    this.#changed()
  }

  /** Add a workspace root or other directory whose spelling is identifying. */
  addAnchor(path) {
    if (!path || path.length < 2) return
    const clean = path.replace(/[\\/]+$/, '')
    if (!clean || this.anchors.includes(clean)) return
    this.anchors.push(clean)
    this.anchors.sort((a, b) => b.length - a.length)
    this.epoch += 1
  }

  setTerms(terms) {
    this.terms = terms
      .filter((t) => t && typeof t.text === 'string' && t.text.trim().length >= 2)
      .map((t) => ({ text: t.text.trim(), category: t.category ?? 'PERSON' }))
    this.#termsRe = null
    this.epoch += 1
  }

  /** Regex over known account and host names (case-insensitive, word-bounded). */
  identityRe() {
    if (this.#identityRe === null) {
      const names = [...this.usernames, ...this.hostnames].toSorted((a, b) => b.length - a.length).map(escapeRe)
      this.#identityRe = names.length
        ? new RegExp(`(?<![A-Za-z0-9_])(${names.join('|')})(?![A-Za-z0-9_])`, 'gi')
        : false
    }
    return this.#identityRe
  }

  termsRe() {
    if (this.#termsRe === null) {
      const texts = this.terms.map((t) => t.text).toSorted((a, b) => b.length - a.length)
      this.#termsRe = texts.length
        ? new RegExp(
            texts
              .map((t) => {
                // Latin terms match on word boundaries; CJK terms match anywhere, and
                // a space inside a term also matches a full-width or missing space.
                const body = escapeRe(t).replace(/[ 　]+/g, '[ \\u3000]?')
                return /^[A-Za-z0-9]/.test(t) ? `(?<![A-Za-z0-9_])${body}(?![A-Za-z0-9_])` : body
              })
              .join('|'),
            'gi',
          )
        : false
    }
    return this.#termsRe
  }

  categoryOfTerm(matched) {
    const key = normTerm(matched)
    return this.terms.find((t) => normTerm(t.text) === key)?.category ?? 'PERSON'
  }

  stats() {
    return {
      usernames: this.usernames.size,
      hostnames: this.hostnames.size,
      anchors: this.anchors.length,
      terms: this.terms.length,
      epoch: this.epoch,
    }
  }
}
