// Category vocabulary shared by detectors, the vault, notices, and restoration.

/** Lower number wins when spans overlap. */
export const PRIORITY = Object.freeze({
  SSH_KEY: 1,
  API_KEY: 2,
  PASSWORD: 2,
  CARD: 3,
  TAILSCALE_URL: 4,
  EMAIL: 5,
  ADDRESS: 6,
  PERSON: 7,
  PATH: 8,
  HOSTNAME: 9,
  USERNAME: 10,
})

export const CATEGORIES = Object.freeze(Object.keys(PRIORITY))

/**
 * Irreversible categories never keep the original value, not even in memory:
 * the vault only holds a keyed hash for them, so nothing can restore them.
 */
export const IRREVERSIBLE = new Set(['SSH_KEY', 'API_KEY', 'PASSWORD', 'CARD'])

/** Categories whose residue after redaction blocks the request outright. */
export const HIGH_RISK = new Set(['SSH_KEY', 'API_KEY', 'PASSWORD', 'CARD'])

/** Notice wording uses these names (requirement §6 example). */
export const NOTICE_NAME = Object.freeze({
  SSH_KEY: 'SSH_KEY',
  API_KEY: 'API_KEY',
  PASSWORD: 'PASSWORD',
  CARD: 'CREDIT_CARD',
  TAILSCALE_URL: 'TAILSCALE_URL',
  EMAIL: 'EMAIL',
  ADDRESS: 'ADDRESS',
  PERSON: 'PERSON',
  PATH: 'FILE_PATH',
  HOSTNAME: 'HOSTNAME',
  USERNAME: 'USERNAME',
})

export function placeholder(category, n) {
  return `[REDACTED_${category}_${n}]`
}

/** Matches any placeholder-shaped token, issued by us or typed by someone else. */
export const PLACEHOLDER_RE =
  /\[REDACTED_(SSH_KEY|API_KEY|PASSWORD|CARD|TAILSCALE_URL|EMAIL|ADDRESS|PERSON|PATH|HOSTNAME|USERNAME)_(\d{1,9})\]/g
