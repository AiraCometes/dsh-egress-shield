// In-process egress guard: wraps Node's global undici dispatcher so that any
// request to a protected LLM endpoint that does not come from the gateway
// fails before a socket is opened. This catches a provider whose baseURL was
// never pointed at the gateway (or was changed later), which the gateway alone
// cannot see.
//
// The gateway forwards through `inner()` — the dispatcher that was installed
// before us (DSH's proxy-aware Agent) — so it keeps DSH's proxy policy.

const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1')

export class EgressBlockedError extends Error {
  constructor(code) {
    super(
      `egress-shield: direct request to a protected LLM endpoint was blocked (${code}). Route the provider through the egress-shield gateway.`,
    )
    this.code = code
  }
}

function normalisePrefix(url) {
  const u = new URL(url)
  return { origin: u.origin.toLowerCase(), path: u.pathname.replace(/\/+$/, '') }
}

/**
 * @param {string[]} protectedPrefixes absolute URL prefixes, e.g. https://opencode.ai/zen
 * @param {{ onBlock?: (origin: string) => void }} [hooks]
 */
export function installEgressGuard(protectedPrefixes, hooks = {}) {
  const prefixes = protectedPrefixes.map(normalisePrefix)
  let inner = globalThis[GLOBAL_DISPATCHER]
  let wrapper = null
  let blocked = 0

  const isProtected = (origin, path) => {
    const o = String(origin ?? '')
      .toLowerCase()
      .replace(/\/+$/, '')
    const p = String(path ?? '/').split('?')[0]
    return prefixes.some((x) => x.origin === o && (x.path === '' || p === x.path || p.startsWith(`${x.path}/`)))
  }

  const wrap = (target) =>
    new Proxy(target, {
      get(t, prop) {
        if (prop === 'dispatch') {
          return (opts, handler) => {
            if (isProtected(opts.origin, opts.path)) {
              blocked += 1
              hooks.onBlock?.(String(opts.origin))
              const err = new EgressBlockedError('DIRECT_PROVIDER_EGRESS')
              queueMicrotask(() => {
                if (typeof handler.onError === 'function') handler.onError(err)
                else if (typeof handler.onResponseError === 'function') handler.onResponseError(null, err)
              })
              return true
            }
            return t.dispatch(opts, handler)
          }
        }
        const value = Reflect.get(t, prop, t)
        return typeof value === 'function' ? value.bind(t) : value
      },
    })

  /** Re-wrap if something (e.g. a proxy policy reload) replaced the global dispatcher. */
  const ensure = () => {
    const current = globalThis[GLOBAL_DISPATCHER]
    if (current && current === wrapper) return
    if (current === undefined) {
      // No fetch has run yet; let Node create its default dispatcher first.
      return
    }
    inner = current
    wrapper = wrap(current)
    globalThis[GLOBAL_DISPATCHER] = wrapper
  }
  ensure()

  return {
    ensure,
    inner: () => inner,
    get blocked() {
      return blocked
    },
    isProtected: (url) => {
      const u = new URL(url)
      return isProtected(u.origin, u.pathname)
    },
    uninstall() {
      if (globalThis[GLOBAL_DISPATCHER] === wrapper) globalThis[GLOBAL_DISPATCHER] = inner
      wrapper = null
    },
  }
}
