// Per-session placeholder numbering.
//
// - Same (category, value) → same number within a scope; different values never
//   share a number.
// - Irreversible categories store only an HMAC under a per-process random key;
//   the original value is not retained anywhere.
// - Pseudonymised categories keep value ↔ number in memory so trusted local
//   code (tool-argument restoration) can map back. Nothing is persisted.
// - Placeholder-shaped tokens that were not issued here (typed by a user, or
//   left over from before a restart) are *reserved*: their numbers are never
//   handed to a new value, so they cannot collide with a real mapping.

import { createHmac, randomBytes } from 'node:crypto'
import { IRREVERSIBLE } from './categories.js'

const HMAC_KEY = randomBytes(32)

export function keyedHash(value) {
  return createHmac('sha256', HMAC_KEY).update(value).digest('base64url')
}

export class Scope {
  constructor(key) {
    this.key = key
    this.counters = new Map()
    this.forward = new Map() // `${cat}\0${key}` → n
    this.reverse = new Map() // `${cat}\0${n}` → value (pseudonyms only)
    this.issued = new Set() // `${cat}\0${n}`
    this.reserved = new Set() // `${cat}\0${n}`
    this.categories = new Set()
    this.approvedImages = new Set()
    this.imageGrants = 0
    this.touched = Date.now()
  }

  /**
   * @param {string} category
   * @param {string} key value for pseudonyms, keyed hash for irreversible categories
   */
  assign(category, key) {
    const fk = `${category}\0${key}`
    let n = this.forward.get(fk)
    if (n === undefined) {
      n = this.counters.get(category) ?? 0
      do {
        n += 1
      } while (this.reserved.has(`${category}\0${n}`))
      this.counters.set(category, n)
      this.forward.set(fk, n)
      this.issued.add(`${category}\0${n}`)
      if (!IRREVERSIBLE.has(category)) this.reverse.set(`${category}\0${n}`, key)
    }
    this.categories.add(category)
    return n
  }

  reserve(category, n) {
    const k = `${category}\0${n}`
    if (!this.issued.has(k)) this.reserved.add(k)
  }

  isIssued(category, n) {
    return this.issued.has(`${category}\0${n}`)
  }

  /** Original value of a pseudonym, or undefined (always undefined for irreversible). */
  lookup(category, n) {
    return this.reverse.get(`${category}\0${n}`)
  }
}

export class Vault {
  constructor({ maxScopes = 256, ttlMs = 24 * 3600 * 1000 } = {}) {
    this.maxScopes = maxScopes
    this.ttlMs = ttlMs
    this.scopes = new Map()
  }

  /** @param {string | undefined} key session identifier; undefined → a throwaway scope */
  scope(key) {
    if (!key) return new Scope(undefined)
    let s = this.scopes.get(key)
    const now = Date.now()
    if (s && now - s.touched > this.ttlMs) {
      this.scopes.delete(key)
      s = undefined
    }
    if (!s) {
      s = new Scope(key)
      this.scopes.set(key, s)
      while (this.scopes.size > this.maxScopes) this.scopes.delete(this.scopes.keys().next().value)
    } else {
      // refresh LRU position
      this.scopes.delete(key)
      this.scopes.set(key, s)
    }
    s.touched = now
    return s
  }

  get size() {
    return this.scopes.size
  }
}

export function mappingKey(category, value) {
  return IRREVERSIBLE.has(category) ? keyedHash(`${category}\0${value}`) : value
}
