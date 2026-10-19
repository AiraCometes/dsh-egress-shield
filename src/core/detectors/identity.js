// Known account names, host names, and the user's term list; plus learning
// of new ones from shell prompts (user@host:~$) and DSH's own statements of
// the working directory.

const PROMPT_RE =
  /(?<![\w.@-])([a-z_][a-z0-9_-]{2,31})@([A-Za-z0-9][A-Za-z0-9-]{1,62})(?=:[~/]|[ \t]+[~/]|[:][^\s]{0,200}[$#][ \t])/g
// DSH system prompt / runtime context phrases naming the workspace.
const WORKDIR_RE =
  /(?:[Ww]orking directory is|session workspace:|[Ww]orkspace(?: root)?:)[ \t]*["']?([/\\A-Za-z][^\s"'\n]{1,4095})/g

function each(re, text, fn) {
  re.lastIndex = 0
  let m
  while ((m = re.exec(text)) !== null) fn(m)
}

/** Learn facts before detection so the same pass already uses them. */
export function learnFrom(text, knowledge) {
  each(PROMPT_RE, text, (m) => {
    knowledge.learnUsername(m[1])
    knowledge.learnHostname(m[2])
  })
  each(WORKDIR_RE, text, (m) => {
    const path = m[1].replace(/[.,;:]+$/, '')
    if (/^(?:\/|[A-Za-z]:[\\/]|\\\\)/.test(path)) knowledge.addAnchor(path)
  })
}

export function detectIdentity(text, knowledge, spans) {
  const idRe = knowledge.identityRe()
  if (idRe) {
    each(idRe, text, (m) => {
      const value = m[1]
      const lower = value.toLowerCase()
      const isHost = [...knowledge.hostnames].some((h) => h.toLowerCase() === lower)
      spans.push({
        s: m.index,
        e: m.index + value.length,
        c: isHost ? 'HOSTNAME' : 'USERNAME',
        r: 'known-identity',
        v: lower,
      })
    })
  }
  const termsRe = knowledge.termsRe()
  if (termsRe) {
    each(termsRe, text, (m) => {
      spans.push({
        s: m.index,
        e: m.index + m[0].length,
        c: knowledge.categoryOfTerm(m[0]),
        r: 'user-term',
        v: m[0].toLowerCase().replace(/[ 　]/g, ''),
      })
    })
  }
}
