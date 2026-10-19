// Overlap resolution. Spans only ever grow when merged, so a partial overlap
// can never leave a fragment of a secret behind.

import { PRIORITY } from './categories.js'

/**
 * @param {{ s: number, e: number, c: string, v?: string, r?: string }[]} spans
 * @returns merged, non-overlapping spans sorted by start
 */
export function resolveSpans(spans) {
  if (spans.length <= 1) return spans.slice()
  const sorted = spans.toSorted((a, b) => a.s - b.s || b.e - a.e)
  const out = []
  let cur = { ...sorted[0] }
  for (let i = 1; i < sorted.length; i++) {
    const next = sorted[i]
    if (next.s < cur.e) {
      const winner = PRIORITY[next.c] < PRIORITY[cur.c] ? next : cur
      /** @type {{ s: number, e: number, c: string, r?: string, v?: string }} */
      const union = { s: cur.s, e: Math.max(cur.e, next.e), c: winner.c, r: winner.r }
      // Keep a canonical value only when the winner already spans the union.
      if (winner.s === union.s && winner.e === union.e && winner.v !== undefined) union.v = winner.v
      cur = union
    } else {
      out.push(cur)
      cur = { ...next }
    }
  }
  out.push(cur)
  return out
}
