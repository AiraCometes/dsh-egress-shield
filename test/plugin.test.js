// DSH integration layer, exercised with a minimal fake Cordis context.
import { test } from 'vitest'
import assert from 'node:assert/strict'
import { apply } from '../src/dsh/plugin.js'
import { installEgressGuard } from '../src/dsh/egress-guard.js'
import { startMockProvider } from './support/mock-provider.mjs'

/** @param {{ approval?: any, agents?: any }} [deps] */
function fakeCtx({ approval, agents } = {}) {
  /** @type {Record<string, Function[]>} */
  const listeners = {}
  const disposers = []
  return {
    listeners,
    dispose: async () => {
      for (const d of disposers) await d()
    },
    logger: { info: () => {}, warn: () => {} },
    on(event, fn) {
      ;(listeners[event] ??= []).push(fn)
    },
    effect(fn) {
      disposers.push(fn())
    },
    get(name) {
      if (name === 'approval') return approval
      if (name === 'agents') return agents
      if (name === 'llm') return { listProviders: () => [{ id: 'opencode-go' }, { id: 'deepseek-official' }] }
      return undefined
    },
  }
}

async function collect(stream) {
  const out = []
  for await (const chunk of stream) out.push(chunk)
  return out
}

/** @returns {import('../src/dsh/plugin.js').PluginConfig} */
const baseConfig = (mockUrl) => ({
  listen: { port: 0 },
  routes: { 'opencode-go': { upstream: `${mockUrl}/v1` } },
  routedProviders: ['opencode-go'],
  termsFile: '',
  auditFile: '',
  guardDirectEgress: false,
})

test('unrouted providers are refused before anything is sent', async () => {
  const mock = await startMockProvider()
  const ctx = fakeCtx()
  await apply(ctx, baseConfig(mock.url))
  try {
    const [listener] = ctx.listeners['llm/stream']
    let nextCalled = false
    const chunks = await collect(
      listener({ provider: 'deepseek-official', messages: [] }, () => {
        nextCalled = true
        return (async function* () {})()
      }),
    )
    assert.equal(nextCalled, false)
    assert.equal(chunks[0].type, 'finish')
    assert.equal(chunks[0].reason.failure.code, 'EGRESS_SHIELD_UNROUTED_PROVIDER')
  } finally {
    await ctx.dispose()
    await mock.close()
  }
})

const imageMessage = {
  role: 'user',
  content: [
    { type: 'text', text: 'see' },
    { type: 'image', attachment: { attachmentId: 'sha256:aaaa' } },
  ],
}

test('images: user approval is requested; approval grants exactly those images', async () => {
  const mock = await startMockProvider()
  const requests = []
  const approval = {
    request: async (req) => {
      requests.push(req)
      return 'allowed-once'
    },
  }
  const ctx = fakeCtx({ approval, agents: { get: () => ({ id: 'agent' }) } })
  await apply(ctx, baseConfig(mock.url))
  try {
    const [listener] = ctx.listeners['llm/stream']
    const opts = { provider: 'opencode-go', sessionId: 'sess-1', messages: [imageMessage] }
    const chunks = await collect(
      listener(opts, () =>
        (async function* () {
          yield { type: 'finish', reason: { kind: 'stop' } }
        })(),
      ),
    )
    assert.equal(chunks[0].reason.kind, 'stop')
    assert.equal(requests.length, 1)
    assert.match(requests[0].displayReason.ja, /画像が 1 枚/)
    // Asked once per image: the same image later does not ask again.
    await collect(listener(opts, () => (async function* () {})()))
    assert.equal(requests.length, 1)
  } finally {
    await ctx.dispose()
    await mock.close()
  }
})

test('images: rejection or a missing approval channel fails closed', async () => {
  const mock = await startMockProvider()
  /** @type {[string, any, any, string][]} */
  const cases = [
    ['rejected', { request: async () => 'rejected' }, { get: () => ({}) }, 'EGRESS_SHIELD_ATTACHMENT_NOT_APPROVED'],
    ['unavailable', undefined, undefined, 'EGRESS_SHIELD_ATTACHMENT_APPROVAL_UNAVAILABLE'],
  ]
  for (const [label, approval, agents, code] of cases) {
    const ctx = fakeCtx({ approval, agents })
    await apply(ctx, { ...baseConfig(mock.url), listen: { port: 0 } })
    try {
      const [listener] = ctx.listeners['llm/stream']
      let nextCalled = false
      const chunks = await collect(
        listener({ provider: 'opencode-go', sessionId: `s-${label}`, messages: [imageMessage] }, () => {
          nextCalled = true
          return (async function* () {})()
        }),
      )
      assert.equal(nextCalled, false, label)
      assert.equal(chunks[0].reason.failure.code, code, label)
    } finally {
      await ctx.dispose()
    }
  }
  await mock.close()
})

test('egress guard blocks direct requests to protected endpoints, but not the gateway forward path', async () => {
  const mock = await startMockProvider()
  await fetch(`${mock.url}/warm`).catch(() => {})
  const guard = installEgressGuard([`${mock.url}/v1`])
  try {
    await assert.rejects(
      fetch(`${mock.url}/v1/chat/completions`, { method: 'POST', body: '{}' }),
      (/** @type {any} */ err) => /protected LLM endpoint/.test(err.cause?.message ?? err.message),
    )
    assert.equal(guard.blocked, 1)
    // Unprotected paths and the inner dispatcher still work.
    assert.equal((await fetch(`${mock.url}/other`)).status, 200)
    assert.equal(
      (
        await fetch(
          `${mock.url}/v1/chat/completions`,
          /** @type {RequestInit} */ ({
            method: 'POST',
            body: '{"messages":[]}',
            headers: { 'content-type': 'application/json' },
            dispatcher: guard.inner(),
          }),
        )
      ).status,
      200,
    )
  } finally {
    guard.uninstall()
    await mock.close()
  }
})
