// Loopback redaction gateway. A provider adapter's baseURL points here
// (http://127.0.0.1:<port>/r/<route>); every request is parsed, redacted,
// verified, annotated with a system notice, and only then forwarded. Any
// failure before forwarding answers locally with an error and sends nothing
// upstream (fail-closed).

import { createServer } from 'node:http'
import { appendFile } from 'node:fs/promises'
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { InspectionError } from '../core/engine.js'
import { DEFAULT_RESTORE_POLICY, restoreToolArguments } from '../core/restore.js'
import { codecFor, underAny } from './codecs.js'
import { SseParser, createSseTransformer } from './sse.js'

export const DEFAULTS = Object.freeze({
  listen: { host: '127.0.0.1', port: 47821 },
  routes: {},
  sessionHeaders: ['x-deepseek-harness-session-id', 'x-opencode-session', 'x-session-id'],
  stripFields: ['dsh_session_log'],
  attachments: 'ask', // ask | block | allow
  maxBodyBytes: 64 * 1024 * 1024,
  inspectionBudgetMs: 10000,
  audit: { file: '' },
})

// Credentials and protocol headers are forwarded verbatim and never inspected
// or logged; every other request header is inspected.
const UNINSPECTED_HEADERS = new Set([
  'authorization',
  'x-api-key',
  'api-key',
  'x-goog-api-key',
  'proxy-authorization',
  'anthropic-version',
  'anthropic-beta',
  'content-type',
  'accept',
  'content-length',
  'host',
  'connection',
  'accept-encoding',
  'accept-language',
  'sec-fetch-mode',
  'openai-organization',
  'openai-project',
])
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
  'accept-encoding',
  'proxy-connection',
  'te',
  'trailer',
])
const ATTACHMENT_DATA_KEYS = new Set(['data', 'url', 'image_url', 'file_data', 'file_id'])

const AUDIT_KEY = randomBytes(32)

class Blocked extends Error {
  constructor(code, status = 400, detail = '') {
    super(code)
    this.code = code
    this.status = status
    this.detail = detail
  }
}

function isLoopback(host) {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost' || host.startsWith('127.')
}

function blockedBody(wire, code, detail) {
  const message = `[egress-shield] Request blocked before leaving this machine: ${code}${detail ? ` (${detail})` : ''}. Nothing was sent to the provider.`
  if (wire === 'anthropic-messages') return { type: 'error', error: { type: 'invalid_request_error', message } }
  return { error: { message, type: 'egress_shield_blocked', code } }
}

function upstreamUrl(route, rest, search) {
  const base = route.upstream.replace(/\/+$/, '')
  return `${base}/${rest.replace(/^\/+/, '')}${search}`
}

function forwardHeaders(req) {
  const headers = {}
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(name)) continue
    headers[name] = Array.isArray(value) ? value.join(', ') : value
  }
  headers['accept-encoding'] = 'identity'
  return headers
}

/**
 * @typedef {object} GatewayConfig
 * @property {{ host?: string, port?: number }} [listen] loopback address only
 * @property {Record<string, { upstream: string, wire?: string, allowGenericJson?: boolean }>} [routes]
 * @property {string[]} [sessionHeaders]
 * @property {string[]} [stripFields]
 * @property {'ask' | 'block' | 'allow'} [attachments]
 * @property {number} [maxBodyBytes]
 * @property {number} [inspectionBudgetMs]
 * @property {{ file?: string }} [audit]
 * @property {Partial<import('../core/restore.js').RestorePolicy>} [restore]
 * @property {{ warn: (msg: string) => void, info: (msg: string) => void }} [logger]
 * @property {() => any} [dispatcher] undici dispatcher used for forwarding
 */

/**
 * @param {import('../core/engine.js').Engine} engine
 * @param {GatewayConfig} config
 */
export function createGateway(engine, config = {}) {
  /** @type {Required<Omit<GatewayConfig, 'restore' | 'logger' | 'dispatcher'>>} */
  const cfg = { ...DEFAULTS, ...config, listen: { ...DEFAULTS.listen, ...config.listen } }
  if (!isLoopback(cfg.listen.host)) throw new Error('egress-shield: the gateway must listen on a loopback address')
  const restorePolicy = { ...DEFAULT_RESTORE_POLICY, ...config.restore }
  const logger = config.logger ?? { warn: () => {}, info: () => {} }
  const counters = { requests: 0, forwarded: 0, blocked: 0, clean: 0, masked: 0, restoredArgs: 0, errors: 0 }
  const recent = []
  let auditWarned = false

  function audit(entry) {
    const record = { ts: new Date().toISOString(), ...entry }
    recent.push(record)
    if (recent.length > 200) recent.shift()
    if (cfg.audit?.file) {
      appendFile(cfg.audit.file, JSON.stringify(record) + '\n', { mode: 0o600 }).catch(() => {
        if (!auditWarned) {
          auditWarned = true
          logger.warn('egress-shield: audit log is not writable (AUDIT_WRITE_FAILED)')
        }
      })
    }
  }

  function scopeKeyOf(req) {
    for (const h of cfg.sessionHeaders) {
      const v = req.headers[h]
      if (typeof v === 'string' && v) return v
    }
    return undefined
  }

  function inspectHeaders(req) {
    for (const [name, value] of Object.entries(req.headers)) {
      if (UNINSPECTED_HEADERS.has(name) || cfg.sessionHeaders.includes(name)) continue
      const text = Array.isArray(value) ? value.join(', ') : String(value)
      if (engine.analyse(text).length) throw new Blocked('HEADER_CONTAINS_SENSITIVE_VALUE')
    }
  }

  function applyAttachmentPolicy(found, scope) {
    if (found.length === 0) return
    if (cfg.attachments === 'allow') return
    if (cfg.attachments === 'block') throw new Blocked('ATTACHMENT_BLOCKED', 400, `${found.length} attachment(s)`)
    const unapproved = found.filter((a) => !scope.approvedImages.has(a.id))
    const distinct = [...new Set(unapproved.map((a) => a.id))]
    if (distinct.length === 0) return
    if (scope.imageGrants >= distinct.length) {
      scope.imageGrants -= distinct.length
      for (const id of distinct) scope.approvedImages.add(id)
      return
    }
    throw new Blocked('ATTACHMENT_APPROVAL_REQUIRED', 400, `${distinct.length} attachment(s) not approved by the user`)
  }

  async function readBody(req) {
    const chunks = []
    let size = 0
    for await (const chunk of req) {
      size += chunk.length
      if (size > cfg.maxBodyBytes) throw new Blocked('BODY_TOO_LARGE', 413)
      chunks.push(chunk)
    }
    return Buffer.concat(chunks)
  }

  /** Inspect and rewrite one JSON request body. */
  function processJson(raw, codec, scope, counts) {
    let body
    try {
      body = JSON.parse(raw.toString('utf8'))
    } catch {
      throw new Blocked('UNPARSEABLE_BODY')
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new Blocked('UNSUPPORTED_PAYLOAD')
    for (const field of cfg.stripFields) delete body[field]
    const attachments = codec ? codec.attachments(body) : []
    applyAttachmentPolicy(attachments, scope)
    const prefixes = attachments.map((a) => a.path)
    const deadline = Date.now() + cfg.inspectionBudgetMs
    const skip = (path, value) =>
      prefixes.length > 0 &&
      underAny(path, prefixes) &&
      (ATTACHMENT_DATA_KEYS.has(String(path[path.length - 1])) || value.startsWith('data:'))
    const { value, changedStrings } = engine.redactJson(body, scope, { skip, counts, deadline })
    const residual = engine.verify(changedStrings)
    if (residual.length) throw new Blocked('RESIDUAL_SECRET', 400, residual.join(','))
    const notice = engine.notice(scope)
    return codec && notice ? codec.injectNotice(value, notice) : value
  }

  async function handle(req, res) {
    const started = Date.now()
    const requestId = randomUUID()
    const url = new URL(req.url, 'http://gateway.invalid')
    if (req.method === 'GET' && url.pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(
        JSON.stringify({
          ok: true,
          routes: Object.keys(cfg.routes),
          counters,
          scopes: engine.vault.size,
          cache: engine.cache.size,
          engine: engine.stats,
          knowledge: engine.knowledge.stats(),
        }),
      )
      return
    }
    const m = /^\/r\/([A-Za-z0-9_.-]+)(\/.*)?$/.exec(url.pathname)
    const route = m ? cfg.routes[m[1]] : undefined
    const rest = m?.[2] ?? '/'
    const codec = codecFor(rest)
    const wire = codec?.name ?? route?.wire
    counters.requests += 1
    const counts = {}
    let scope
    try {
      if (!route) throw new Blocked('UNKNOWN_ROUTE', 404)
      scope = engine.scope(scopeKeyOf(req))
      let outBody
      if (req.method === 'GET' || req.method === 'HEAD') {
        outBody = undefined
      } else {
        inspectHeaders(req)
        const encoding = String(req.headers['content-encoding'] ?? 'identity').toLowerCase()
        if (encoding !== 'identity') throw new Blocked('UNSUPPORTED_CONTENT_ENCODING')
        const raw = await readBody(req)
        const type = String(req.headers['content-type'] ?? '').toLowerCase()
        if (type.includes('multipart/form-data')) {
          // Provider file uploads (e.g. DeepSeek Files API): opaque bytes.
          applyAttachmentPolicy(
            [{ id: createHash('sha256').update(raw).digest('base64url'), kind: 'upload', path: [] }],
            scope,
          )
          outBody = raw
        } else if (type.includes('json') || raw.length === 0) {
          if (raw.length === 0) outBody = raw
          else {
            if (!codec && !route.allowGenericJson) throw new Blocked('UNSUPPORTED_ENDPOINT', 400, rest)
            outBody = Buffer.from(JSON.stringify(processJson(raw, codec, scope, counts)))
          }
        } else {
          throw new Blocked('UNSUPPORTED_CONTENT_TYPE')
        }
      }

      const masked = Object.keys(counts).length > 0
      counters[masked ? 'masked' : 'clean'] += 1
      const controller = new AbortController()
      res.on('close', () => {
        if (!res.writableEnded) controller.abort()
      })
      const dispatcher = config.dispatcher?.()
      let upstream
      try {
        upstream = await fetch(upstreamUrl(route, rest, url.search), {
          method: req.method,
          headers: forwardHeaders(req),
          body: outBody,
          redirect: 'manual',
          signal: controller.signal,
          ...(dispatcher ? { dispatcher } : {}),
        })
      } catch {
        throw new Blocked('UPSTREAM_UNREACHABLE', 502)
      }
      counters.forwarded += 1
      audit({
        id: requestId,
        route: m[1],
        path: rest,
        decision: masked ? 'masked' : 'clean',
        counts,
        ms: Date.now() - started,
        bytes: outBody?.length ?? 0,
        status: upstream.status,
        hmac: outBody ? createHmac('sha256', AUDIT_KEY).update(outBody).digest('hex').slice(0, 8) : undefined,
      })
      await relayResponse(upstream, res, wire, scope)
    } catch (error) {
      const blocked =
        error instanceof Blocked
          ? error
          : error instanceof InspectionError
            ? new Blocked(error.code)
            : new Blocked('INSPECTION_FAILED', 500)
      if (!(error instanceof Blocked) && !(error instanceof InspectionError)) {
        counters.errors += 1
        // Log only the error class: messages can embed input fragments.
        logger.warn(
          `egress-shield: internal error during inspection (${error?.constructor?.name ?? 'Error'}); request blocked`,
        )
      }
      counters.blocked += 1
      audit({
        id: requestId,
        route: m?.[1],
        path: rest,
        decision: 'blocked',
        code: blocked.code,
        counts,
        ms: Date.now() - started,
      })
      if (!res.headersSent) {
        res.writeHead(blocked.status, { 'content-type': 'application/json', 'x-egress-shield-blocked': blocked.code })
        res.end(JSON.stringify(blockedBody(wire, blocked.code, blocked.detail)))
      } else {
        res.destroy()
      }
    }
  }

  async function relayResponse(upstream, res, wire, scope) {
    const headers = {}
    upstream.headers.forEach((value, name) => {
      if (!HOP_BY_HOP.has(name) && name !== 'content-encoding') headers[name] = value
    })
    const type = upstream.headers.get('content-type') ?? ''
    const restore = (name, args) => {
      const r = restoreToolArguments(name, args, scope, restorePolicy)
      counters.restoredArgs += r.restored
      return r.text
    }
    if (!upstream.ok || !upstream.body) {
      const text = upstream.body ? Buffer.from(await upstream.arrayBuffer()) : Buffer.alloc(0)
      res.writeHead(upstream.status, headers)
      res.end(text)
      return
    }
    if (type.includes('text/event-stream') && wire) {
      res.writeHead(upstream.status, headers)
      const parser = new SseParser()
      const transformer = createSseTransformer(wire, restore)
      const decoder = new TextDecoder()
      for await (const chunk of upstream.body) {
        for (const ev of parser.push(decoder.decode(chunk, { stream: true }))) {
          const out = transformer.onEvent(ev)
          if (out) res.write(out)
        }
      }
      for (const ev of parser.push(decoder.decode())) res.write(transformer.onEvent(ev))
      for (const ev of parser.flush()) res.write(transformer.onEvent(ev))
      const tail = transformer.end()
      if (tail) res.write(tail)
      res.end()
      return
    }
    if (type.includes('json') && wire) {
      const raw = Buffer.from(await upstream.arrayBuffer())
      let out = raw
      try {
        const codec = codecFor(
          wire === 'openai-chat' ? '/chat/completions' : wire === 'anthropic-messages' ? '/messages' : '/responses',
        )
        out = Buffer.from(JSON.stringify(codec.restoreJson(JSON.parse(raw.toString('utf8')), restore)))
      } catch {}
      res.writeHead(upstream.status, headers)
      res.end(out)
      return
    }
    res.writeHead(upstream.status, headers)
    for await (const chunk of upstream.body) res.write(chunk)
    res.end()
  }

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500)
        res.end()
      } else res.destroy()
    })
  })

  return {
    config: cfg,
    counters,
    recent,
    async listen() {
      await /** @type {Promise<void>} */ (
        new Promise((resolve, reject) => {
          server.once('error', reject)
          server.listen(cfg.listen.port, cfg.listen.host, () => {
            server.off('error', reject)
            resolve()
          })
        })
      )
      return /** @type {import('node:net').AddressInfo} */ (server.address()).port
    },
    get port() {
      return /** @type {import('node:net').AddressInfo | null} */ (server.address())?.port
    },
    close() {
      return /** @type {Promise<void>} */ (
        new Promise((resolve) => {
          server.close(() => resolve())
          server.closeAllConnections?.()
        })
      )
    },
    /** Allow `count` not-yet-approved attachments in the next request(s) of a session. */
    grantAttachments(scopeKey, count) {
      engine.scope(scopeKey).imageGrants += count
    },
  }
}
