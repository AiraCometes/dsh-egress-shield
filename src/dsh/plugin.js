// DeepSeek Harness integration for egress-shield.
//
//  1. Runs the redaction gateway inside the DSH process (no extra daemon).
//  2. Guards Node's global HTTP dispatcher so a provider that bypasses the
//     gateway cannot reach a protected LLM endpoint (fail-closed).
//  3. On `llm/stream`: refuses providers not routed through the gateway, and
//     asks the user (ctx.approval) before any image is sent, since image
//     content cannot be inspected.
//
// DSH files are not modified; everything here uses public extension points.

import { createHash } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { createGateway } from '../gateway/server.js'
import { buildEngine, expandHome } from '../setup.js'
import { installEgressGuard } from './egress-guard.js'

export const name = 'dsh-egress-shield'

export const DEFAULT_PROTECTED_ENDPOINTS = [
  'https://api.deepseek.com/anthropic',
  'https://api.deepseek.com/chat',
  'https://api.deepseek.com/v1',
  'https://api.deepseek.com/beta',
  'https://opencode.ai/zen',
  'https://api.openai.com/v1',
  'https://api.anthropic.com/v1',
  'https://openrouter.ai/api',
  'https://generativelanguage.googleapis.com',
  'https://api.moonshot.ai/v1',
  'https://api.moonshot.cn/v1',
  'https://dashscope.aliyuncs.com',
  'https://api.x.ai/v1',
  'https://api.mistral.ai/v1',
  'https://api.groq.com/openai',
]

export const DEFAULTS = Object.freeze({
  enabled: true,
  listen: { host: '127.0.0.1', port: 47821 },
  routes: {},
  routedProviders: [],
  protectedEndpoints: DEFAULT_PROTECTED_ENDPOINTS,
  guardDirectEgress: true,
  pathMode: 'anchored',
  attachments: 'ask',
  restore: { enabled: true },
  stripFields: ['dsh_session_log'],
  termsFile: '~/.config/egress-shield/terms.txt',
  auditFile: '~/.local/state/egress-shield/audit.jsonl',
  approvalTimeoutMs: 300000,
  usernames: [],
  hostnames: [],
  anchors: [],
})

function failureStream(code, message) {
  return (async function* () {
    yield { type: 'finish', reason: { kind: 'error', failure: { code, message: `[egress-shield] ${message}` } } }
  })()
}

/** Image blocks anywhere in the request's message contents (tool results included). */
function collectImages(messages) {
  const ids = new Set()
  const visit = (v) => {
    if (Array.isArray(v)) {
      v.forEach(visit)
      return
    }
    if (!v || typeof v !== 'object') return
    if (v.type === 'image' && v.attachment && !v.offloaded) {
      ids.add(
        String(v.attachment.attachmentId ?? createHash('sha256').update(JSON.stringify(v.attachment)).digest('hex')),
      )
    }
    if (Array.isArray(v.content)) visit(v.content)
  }
  for (const m of messages ?? []) visit(m?.content)
  return [...ids]
}

function makeLogger(ctx) {
  const target = typeof ctx.logger === 'function' ? ctx.logger('egress-shield') : ctx.logger
  return {
    info: (msg) => (target?.info ? target.info(msg) : console.info(msg)),
    warn: (msg) => (target?.warn ? target.warn(msg) : console.warn(msg)),
  }
}

/**
 * The subset of a Cordis context this plugin uses (kept local so the plugin
 * has no type or runtime dependency on @deepseek-ai/cordis).
 * @typedef {object} CordisContext
 * @property {(event: string, listener: (...args: any[]) => any) => void} on
 * @property {(name: string) => any} [get]
 * @property {(execute: () => () => void, label?: string) => void} [effect]
 * @property {any} [logger]
 */

/**
 * @typedef {object} PluginConfig
 * @property {boolean} [enabled]
 * @property {{ host?: string, port?: number }} [listen]
 * @property {Record<string, { upstream: string, wire?: string }>} [routes]
 * @property {string[]} [routedProviders] DSH provider ids allowed to dispatch
 * @property {string[]} [protectedEndpoints] URL prefixes direct requests may not reach
 * @property {boolean} [guardDirectEgress]
 * @property {'anchored' | 'full'} [pathMode]
 * @property {'ask' | 'block' | 'allow'} [attachments]
 * @property {Partial<import('../core/restore.js').RestorePolicy>} [restore]
 * @property {string[]} [stripFields]
 * @property {string} [termsFile]
 * @property {string} [auditFile]
 * @property {number} [approvalTimeoutMs]
 * @property {string[]} [usernames]
 * @property {string[]} [hostnames]
 * @property {string[]} [anchors]
 */

/**
 * @param {CordisContext} ctx
 * @param {PluginConfig} config
 */
export async function apply(ctx, config = {}) {
  /** @type {Required<PluginConfig>} */
  const cfg = { ...DEFAULTS, ...config, listen: { ...DEFAULTS.listen, ...config.listen } }
  const logger = makeLogger(ctx)
  if (!cfg.enabled) {
    logger.warn('egress-shield is disabled by configuration; LLM requests are NOT protected')
    return
  }

  const { engine, termsStatus } = buildEngine(cfg)
  if (termsStatus === 'insecure-permissions')
    logger.warn('egress-shield: terms file ignored because it is readable by group/other (chmod 600 it)')

  const auditFile = expandHome(cfg.auditFile)
  if (auditFile) {
    try {
      mkdirSync(dirname(auditFile), { recursive: true, mode: 0o700 })
    } catch {}
  }

  let guard = null

  const gateway = createGateway(engine, {
    listen: cfg.listen,
    routes: cfg.routes,
    attachments: cfg.attachments,
    restore: cfg.restore,
    stripFields: cfg.stripFields,
    audit: { file: auditFile },
    logger,
    // Forward through the dispatcher underneath the guard (resolved lazily:
    // the guard is installed only after the gateway is listening).
    dispatcher: () => guard?.inner(),
  })
  const port = await gateway.listen()
  logger.info(
    `egress-shield gateway listening on 127.0.0.1:${port} (routes: ${Object.keys(cfg.routes).join(', ') || 'none'})`,
  )

  if (cfg.guardDirectEgress) {
    // Make sure Node has created its global dispatcher (DSH's proxy layer
    // normally has), then wrap it. A loopback health probe is enough.
    try {
      await (await fetch(`http://127.0.0.1:${port}/healthz`)).arrayBuffer()
    } catch {}
    const protectedPrefixes = [
      ...new Set([...cfg.protectedEndpoints, ...Object.values(cfg.routes).map((r) => r.upstream)]),
    ]
    guard = installEgressGuard(protectedPrefixes, {
      onBlock: () =>
        logger.warn(
          'egress-shield: blocked a direct request to a protected LLM endpoint (provider not routed through the gateway)',
        ),
    })
  }

  const dispose = async () => {
    guard?.uninstall()
    await gateway.close()
  }
  if (typeof ctx.effect === 'function')
    ctx.effect(
      () => () => {
        void dispose()
      },
      'egress-shield gateway',
    )
  else ctx.on('dispose', dispose)

  // Start-up check: name (never config values of) providers that are registered
  // but not routed. Their requests will be refused below.
  try {
    const providers = ctx.get?.('llm')?.listProviders?.() ?? []
    const unrouted = providers.map((p) => p.id).filter((id) => !cfg.routedProviders.includes(id))
    if (unrouted.length)
      logger.warn(`egress-shield: providers not routed through the gateway will be refused: ${unrouted.join(', ')}`)
  } catch {}

  const routed = new Set(cfg.routedProviders)
  /** sessionId → image attachment ids the user approved */
  const approved = new Map()

  ctx.on('llm/stream', function (options, next) {
    guard?.ensure()
    if (!routed.has(options.provider)) {
      return failureStream(
        'EGRESS_SHIELD_UNROUTED_PROVIDER',
        `provider "${options.provider}" is not routed through the egress-shield gateway; the request was not sent. Add it to routedProviders and point its baseURL at the gateway.`,
      )
    }
    if (cfg.attachments !== 'ask') return next()
    const images = collectImages(options.messages)
    if (images.length === 0) return next()
    const sessionKey = options.sessionId === undefined ? undefined : String(options.sessionId)
    const seen = sessionKey ? (approved.get(sessionKey) ?? new Set()) : new Set()
    const fresh = images.filter((id) => !seen.has(id))
    if (sessionKey) engine.scope(sessionKey).imageGrants = 0
    if (fresh.length === 0) return next()

    return (async function* () {
      const approval = ctx.get?.('approval')
      const agent = sessionKey ? ctx.get?.('agents')?.get?.(options.sessionId) : undefined
      if (!approval || !agent) {
        yield* failureStream(
          'EGRESS_SHIELD_ATTACHMENT_APPROVAL_UNAVAILABLE',
          `this request contains ${fresh.length} image(s), which cannot be inspected for secrets, and no user approval channel is available. Nothing was sent.`,
        )
        return
      }
      const timeout = AbortSignal.timeout(cfg.approvalTimeoutMs)
      const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout
      let outcome
      try {
        outcome = await approval.request({
          agent,
          toolName: 'egress-shield.send-images',
          reason: `Send ${fresh.length} image(s) to provider "${options.provider}". Images cannot be inspected for secrets before sending.`,
          displayReason: {
            en: `This message includes ${fresh.length} image(s). egress-shield cannot check images for secrets. Send them to "${options.provider}"?`,
            ja: `このメッセージには画像が ${fresh.length} 枚含まれています。egress-shield は画像内の機密情報を検査できません。「${options.provider}」へ送信しますか？`,
          },
          signal,
        })
      } catch {
        outcome = 'unavailable'
      }
      if (outcome !== 'allowed-once') {
        yield* failureStream(
          'EGRESS_SHIELD_ATTACHMENT_NOT_APPROVED',
          `sending ${fresh.length} image(s) was not approved (${outcome}). Nothing was sent.`,
        )
        return
      }
      for (const id of fresh) seen.add(id)
      if (sessionKey) {
        approved.set(sessionKey, seen)
        gateway.grantAttachments(sessionKey, fresh.length)
      }
      yield* next()
    })()
  })
}
