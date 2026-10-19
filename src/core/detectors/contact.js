// Credit cards (Luhn + issuer length), e-mail addresses, and Tailscale
// identifiers (MagicDNS names, tailnet CGNAT / ULA addresses).

const CARD_CUE_RE = /(?:card|カード|クレジット|credit|visa|master|amex|jcb|cc[-_ ]?(?:num|no)|pan)[^\n]{0,20}$/i
const CARD_RE = /(?<![\d.,-])\d(?:[ -]?\d){12,18}(?![\d])/g
// Labels may be internationalised (letters and digits of any script), but the top-level domain is either all ASCII or
// all non-ASCII letters, so `taro@example.com）、住所は…` stops at `com` instead of running into the Japanese text.
const EMAIL_RE =
  /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.){1,8}(?:[A-Za-z]{2,24}(?![A-Za-z0-9-])|[^\P{L}A-Za-z]{2,24}(?![\p{L}\p{N}-]))/gu
// host[.sub].ts.net with an optional :port. The scheme and path are left alone
// so credentials or query secrets inside the URL are still judged separately.
const TS_HOST_RE =
  /(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,4}ts\.net(?::\d{1,5})?(?![A-Za-z0-9-])/gi
const TS_CGNAT_RE =
  /(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)/g
const TS_ULA_RE = /(?<![0-9A-Fa-f:])fd7a:115c:a1e0(?::[0-9A-Fa-f]{0,4}){1,5}(?![0-9A-Fa-f:])/gi

export function luhn(digits) {
  let sum = 0
  let double = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (double) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    double = !double
  }
  return sum % 10 === 0
}

/** Issuer prefix and length check (major schemes). */
export function plausibleIssuer(d) {
  const n = d.length
  const p2 = Number(d.slice(0, 2))
  const p3 = Number(d.slice(0, 3))
  const p4 = Number(d.slice(0, 4))
  const p6 = Number(d.slice(0, 6))
  if (d[0] === '4') return n === 13 || n === 16 || n === 19 // Visa
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16 // Mastercard
  if (p2 === 34 || p2 === 37) return n === 15 // Amex
  if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || (p6 >= 622126 && p6 <= 622925)) return n >= 16 && n <= 19 // Discover
  if (p4 >= 3528 && p4 <= 3589) return n >= 16 && n <= 19 // JCB
  if (p2 === 36 || p2 === 38 || p2 === 39 || (p3 >= 300 && p3 <= 305)) return n >= 14 && n <= 19 // Diners
  if (p2 === 62) return n >= 16 && n <= 19 // UnionPay
  if (/^(?:50|5[6-9]|6[0-9])/.test(d)) return n >= 12 && n <= 19 // Maestro
  return false
}

function each(re, text, fn) {
  re.lastIndex = 0
  let m
  while ((m = re.exec(text)) !== null) fn(m)
}

export function detectContact(text, spans, lower = text.toLowerCase()) {
  // Cheap required-substring checks skip whole regex scans on most texts.
  if (/\d/.test(text))
    each(CARD_RE, text, (m) => {
      const raw = m[0]
      // Mixed separators ("4111 1111-1111") are fine; a separator every digit is not a card.
      const digits = raw.replace(/[ -]/g, '')
      if (digits.length < 13 || digits.length > 19) return
      if (!luhn(digits)) return
      // Issuer/length rules cut false positives on bare numbers; with an explicit
      // card cue nearby, any Luhn-valid number is treated as a card.
      const cue = CARD_CUE_RE.test(text.slice(Math.max(0, m.index - 24), m.index))
      if (!cue && !plausibleIssuer(digits)) return
      spans.push({ s: m.index, e: m.index + raw.length, c: 'CARD', r: 'card', v: digits })
    })
  if (text.includes('@'))
    each(EMAIL_RE, text, (m) => {
      // user:password@host inside a URL is userinfo, judged by the secrets detector.
      if (/:\/\/[^\s/@]{0,256}:$/.test(text.slice(Math.max(0, m.index - 300), m.index))) return
      spans.push({ s: m.index, e: m.index + m[0].length, c: 'EMAIL', r: 'email', v: m[0].toLowerCase() })
    })
  if (lower.includes('ts.net'))
    each(TS_HOST_RE, text, (m) => {
      spans.push({ s: m.index, e: m.index + m[0].length, c: 'TAILSCALE_URL', r: 'magicdns', v: m[0].toLowerCase() })
    })
  if (text.includes('100.'))
    each(TS_CGNAT_RE, text, (m) =>
      spans.push({ s: m.index, e: m.index + m[0].length, c: 'TAILSCALE_URL', r: 'tailnet-ipv4' }),
    )
  if (lower.includes('fd7a:'))
    each(TS_ULA_RE, text, (m) =>
      spans.push({
        s: m.index,
        e: m.index + m[0].length,
        c: 'TAILSCALE_URL',
        r: 'tailnet-ipv6',
        v: m[0].toLowerCase(),
      }),
    )
}
