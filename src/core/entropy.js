/** Shannon entropy in bits per character, as Gitleaks computes it. */
export function shannonEntropy(text) {
  if (!text) return 0
  const counts = new Map()
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let entropy = 0
  const n = text.length
  for (const count of counts.values()) {
    const p = count / n
    entropy -= p * Math.log2(p)
  }
  return entropy
}
