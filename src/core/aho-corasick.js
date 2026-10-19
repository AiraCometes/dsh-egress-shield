// Aho-Corasick automaton compiled to a DFA: one pass over the text reports
// which of many keywords occur. Used to prefilter the imported Gitleaks rules
// (only rules whose keyword appears are run).
//
// ASCII transitions live in a flat Int32Array (states × 128) so the hot loop
// is charCodeAt + one array read; non-ASCII transitions use a per-state Map.

export class AhoCorasick {
  /** @param {string[]} words already normalised (e.g. lower-cased) */
  constructor(words) {
    const goto = [new Map()]
    const fail = [0]
    const out = [[]]
    this.words = []
    for (const word of words) {
      if (!word) continue
      const id = this.words.push(word) - 1
      let state = 0
      for (let i = 0; i < word.length; i++) {
        const c = word.charCodeAt(i)
        let next = goto[state].get(c)
        if (next === undefined) {
          next = goto.push(new Map()) - 1
          fail.push(0)
          out.push([])
          goto[state].set(c, next)
        }
        state = next
      }
      out[state].push(id)
    }
    // Breadth-first failure links.
    const order = []
    const queue = [...goto[0].values()]
    while (queue.length) {
      const state = queue.shift()
      order.push(state)
      for (const [c, next] of goto[state]) {
        queue.push(next)
        let f = fail[state]
        while (f !== 0 && !goto[f].has(c)) f = fail[f]
        const target = goto[f].get(c)
        fail[next] = target !== undefined && target !== next ? target : 0
        out[next] = out[next].concat(out[fail[next]])
      }
    }
    // Full DFA for ASCII.
    const n = goto.length
    const ascii = new Int32Array(n * 128)
    const resolve = (state, c) => {
      while (state !== 0 && !goto[state].has(c)) state = fail[state]
      return goto[state].get(c) ?? 0
    }
    for (let c = 0; c < 128; c++) ascii[c] = goto[0].get(c) ?? 0
    for (const state of order) for (let c = 0; c < 128; c++) ascii[state * 128 + c] = resolve(state, c)
    this.ascii = ascii
    this.resolve = resolve
    this.out = out
    this.hasOut = Uint8Array.from(out, (o) => (o.length ? 1 : 0))
  }

  /** @returns {Set<number>} ids of words present in text */
  present(text) {
    const found = new Set()
    const { ascii, hasOut, out, resolve } = this
    let state = 0
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i)
      state = c < 128 ? ascii[state * 128 + c] : resolve(state, c)
      if (hasOut[state] === 1) for (const id of out[state]) found.add(id)
    }
    return found
  }
}
