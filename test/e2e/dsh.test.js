// End-to-end: the real DeepSeek Harness (headless profile) → egress-shield
// plugin/gateway → local mock provider. Every payload the mock receives is
// checked against the fictitious corpus; any hit fails the test.
//
// Requires a DSH installation. Set DSH_BIN to `.../@deepseek-ai/dsh/lib/bin.js`
// (default: the `dsh` on PATH). Network access to external LLMs is never used.

import { test, beforeAll, afterAll } from 'vitest'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { startMockProvider } from '../support/mock-provider.mjs'
import { makeCorpus, findLeaks } from '../support/corpus.mjs'

const REPO = resolve(import.meta.dirname, '../..')
const DSH_BIN =
  process.env.DSH_BIN ??
  (() => {
    try {
      return execFileSync('which', ['dsh']).toString().trim()
    } catch {
      return ''
    }
  })()
const available = DSH_BIN && existsSync(DSH_BIN)
const C = makeCorpus()
const GATEWAY_PORT = 47000 + Math.floor(Math.random() * 900)

let home, mock, workspace

// Async on purpose: the mock provider runs in this process, so blocking the
// event loop (spawnSync) would deadlock DSH against it.
function dsh(args, { env = {}, cwd = workspace, timeout = 180000 } = {}) {
  const isJs = DSH_BIN.endsWith('.js')
  return new Promise((resolvePromise) => {
    const child = spawn(isJs ? process.execPath : DSH_BIN, [...(isJs ? [DSH_BIN] : []), ...args], {
      cwd,
      env: {
        ...process.env,
        DSH_HOME: home,
        DSH_TELEMETRY_DISABLED: '1',
        OPENCODE_API_KEY: 'sk-FAKE-opencode-credential-0000',
        DEEPSEEK_API_KEY: 'sk-FAKE-deepseek-credential-0000',
        ...env,
      },
    })
    let out = ''
    child.stdout.on('data', (d) => {
      out += d
    })
    child.stderr.on('data', (d) => {
      out += d
    })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout)
    child.on('close', (code) => {
      clearTimeout(timer)
      resolvePromise({ code, out })
    })
  })
}

function writePatch(
  name,
  {
    routedProviders = ['opencode-go'],
    baseURL = `http://127.0.0.1:${GATEWAY_PORT}/r/opencode-go`,
    extraShield = '',
    extra = '',
  } = {},
) {
  const file = join(home, `${name}.patch.yml`)
  writeFileSync(
    file,
    `
- id: agent-default-model
  config:
    provider: opencode-go
    model: deepseek-v4.1-flash
- id: llm-pi-ai
  config:
    providers:
      opencode-go:
        apiKeyEnv: OPENCODE_API_KEY
        baseURL: ${baseURL}
- id: egress-shield
  config:
    listen: { host: 127.0.0.1, port: ${GATEWAY_PORT} }
    routes:
      opencode-go: { upstream: '${mock.url}/v1' }
      deepseek: { upstream: '${mock.url}/anthropic' }
    routedProviders: [${routedProviders.join(', ')}]
    termsFile: ''
    auditFile: ''
    usernames: ['${C.personal.username}']
${extraShield}
${extra}
`,
  )
  return file
}

const isTitle = (body) => JSON.stringify(body.messages?.[0] ?? body.system ?? '').includes('concise title')
// DSH appends the compaction instruction as the final user message.
const isSummary = (body) => JSON.stringify(body.messages?.at(-1)?.content ?? '').includes('compaction engine')

function assertNoLeaks(fromIndex = 0) {
  const sent = mock.captured.slice(fromIndex)
  for (const r of sent) {
    const leaks = findLeaks(r.body + JSON.stringify(r.headers), C)
    assert.deepEqual(
      leaks.map((l) => l.slice(0, 12) + '…'),
      [],
      `leak in ${r.url}`,
    )
    assert.ok(!r.body.includes(workspace), `workspace path leaked in ${r.url}`)
  }
  return sent
}

beforeAll(async () => {
  if (!available) return
  home = mkdtempSync(join(tmpdir(), 'egress-shield-dsh-'))
  workspace = join(home, 'work', C.personal.username, 'projects', 'app')
  mkdirSync(workspace, { recursive: true })
  writeFileSync(
    join(workspace, '.env'),
    [
      `OPENAI_API_KEY=${C.secrets.openaiKey}`,
      `GITHUB_TOKEN=${C.secrets.githubToken}`,
      `DATABASE_URL=postgres://app:${C.secrets.dbPassword}@${C.personal.tailnetHost}:5432/app`,
      `OWNER=${C.personal.email}`,
      `ADDRESS=${C.personal.jaAddress}`,
    ].join('\n'),
  )
  writeFileSync(join(workspace, 'id_ed25519'), `${C.secrets.pem}\n`)
  mock = await startMockProvider({
    responder: (body) =>
      isTitle(body)
        ? { text: 'Session title' }
        : isSummary(body)
          ? { text: '<summary>Summary of [REDACTED_PATH_1] work.</summary>' }
          : undefined,
  })
  const add = await dsh(['plugin', '--profile', 'headless', 'add', `link:${REPO}`], { cwd: home, timeout: 300000 })
  assert.equal(add.code, 0, add.out)
}, 300_000)

afterAll(async () => {
  await mock?.close()
})

test.skipIf(!available)(
  'E-01/02/03/04/06/11 prompt, file read, shell output, title and system prompt carry no secrets',
  async () => {
    const start = mock.captured.length
    mock.push({ text: 'Reading.', toolCalls: [{ name: 'read', arguments: { file_path: '[REDACTED_PATH_1]/.env' } }] })
    mock.push({
      text: 'Shell.',
      toolCalls: [
        { name: 'bash', arguments: { command: 'cat id_ed25519; echo $HOME; whoami', description: 'inspect' } },
      ],
    })
    mock.push({ text: 'All done with [REDACTED_API_KEY_1].' })
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e1'),
      `Check .env for me. I am ${C.personal.jaName} (${C.personal.email}), card ${C.secrets.card}, token ${C.secrets.githubToken}, server ${C.personal.tailnetHost}.`,
    ])
    assert.equal(r.code, 0, r.out)
    const sent = assertNoLeaks(start)
    assert.ok(sent.length >= 4, `expected main + title + tool steps, got ${sent.length}`)
    const last = JSON.parse(sent.filter((s) => !isTitle(JSON.parse(s.body))).at(-1).body)
    const all = JSON.stringify(last.messages)
    assert.match(all, /\[REDACTED_SSH_KEY_\d+\]/, 'shell output with a private key must be redacted')
    assert.match(all, /\[REDACTED_API_KEY_\d+\]/)
    assert.match(last.messages[0].content, /\[SECURITY REDACTION NOTICE\]/)
  },
  300_000,
)

test.skipIf(!available)(
  'E-05 compaction summarisation requests are redacted',
  async () => {
    // Compaction is driven by DSH's own replay-based token meter; the reliable
    // way to force it from outside is the overflow-recovery path: the provider
    // reports a context-window overflow, DSH summarises, then retries.
    const start = mock.captured.length
    mock.push({ text: 'Reading.', toolCalls: [{ name: 'read', arguments: { file_path: '[REDACTED_PATH_1]/.env' } }] })
    mock.push({
      text: 'Again.',
      toolCalls: [{ name: 'read', arguments: { file_path: '[REDACTED_PATH_1]/id_ed25519' } }],
    })
    mock.push({
      status: 400,
      body: JSON.stringify({
        error: {
          message:
            "This model's maximum context length is 1000000 tokens. However, your messages resulted in 1200000 tokens.",
          type: 'invalid_request_error',
          code: 'context_length_exceeded',
        },
      }),
    })
    mock.push({ text: 'Done.' })
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e5'),
      `Summarise .env; my mail is ${C.personal.email}`,
    ])
    assert.equal(r.code, 0, r.out)
    const sent = assertNoLeaks(start)
    const summaries = sent.filter((s) => isSummary(JSON.parse(s.body)))
    assert.ok(summaries.length >= 1, 'no compaction request observed')
    // The summariser sees the conversation with the .env contents already masked.
    assert.match(summaries[0].body, /\[REDACTED_API_KEY_\d+\]/)
  },
  300_000,
)

test.skipIf(!available)(
  'E-07 subagent requests are redacted',
  async () => {
    const start = mock.captured.length
    mock.push({
      text: 'Delegating.',
      toolCalls: [
        {
          name: 'subagent',
          arguments: { description: 'check env', prompt: 'Read [REDACTED_PATH_1]/.env and report the variable names.' },
        },
      ],
    })
    mock.push({
      text: 'Sub reading.',
      toolCalls: [{ name: 'read', arguments: { file_path: '[REDACTED_PATH_1]/.env' } }],
    })
    mock.push({ text: 'Sub done.' })
    mock.push({ text: 'Main done.' })
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e7'),
      'Delegate the .env check to a subagent.',
    ])
    assert.equal(r.code, 0, r.out)
    const sent = assertNoLeaks(start)
    const sessions = new Set(sent.map((s) => s.headers['x-opencode-session']))
    assert.ok(sessions.size >= 2, 'subagent should run in its own session')
  },
  300_000,
)

test.skipIf(!available)(
  'E-08 retried requests are redacted on every attempt',
  async () => {
    const start = mock.captured.length
    mock.push({ status: 500 })
    mock.push({ text: 'ok after retry' })
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e8'),
      `retry me ${C.secrets.openaiKey} ${C.personal.email}`,
    ])
    assert.equal(r.code, 0, r.out)
    const sent = assertNoLeaks(start).filter((s) => !isTitle(JSON.parse(s.body)))
    assert.ok(sent.length >= 2, 'expected the failed attempt and the retry')
  },
  300_000,
)

test.skipIf(!available)(
  'E-09 a provider not routed through the gateway is refused',
  async () => {
    const start = mock.captured.length
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e9', { routedProviders: [] }),
      `secret ${C.secrets.openaiKey}`,
    ])
    assert.notEqual(r.code, 0)
    assert.match(r.out, /EGRESS_SHIELD_UNROUTED_PROVIDER|not routed/)
    assert.equal(mock.captured.length, start)
  },
  300_000,
)

test.skipIf(!available)(
  'E-10 a routed provider whose baseURL bypasses the gateway is blocked by the egress guard',
  async () => {
    const start = mock.captured.length
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      writePatch('e10', {
        baseURL: `${mock.url}/v1`,
        extraShield: `    protectedEndpoints: ['${mock.url}/v1']`,
      }),
      `secret ${C.secrets.openaiKey}`,
    ])
    assert.notEqual(r.code, 0)
    assert.equal(mock.captured.length, start, 'direct request reached the provider')
  },
  300_000,
)

test.skipIf(!available)(
  'E-12 DeepSeek official route: dsh_session_log is stripped and content redacted',
  async () => {
    const start = mock.captured.length
    const patch = writePatch('e12', {
      routedProviders: ['opencode-go', 'deepseek-official'],
      extra: `- id: agent-default-model
  config:
    provider: deepseek-official
    model: deepseek-v4-flash
- id: llm-deepseek
  config:
    baseURL: http://127.0.0.1:${GATEWAY_PORT}/r/deepseek`,
    })
    const r = await dsh([
      '--profile',
      'headless',
      '--patch',
      patch,
      `official route ${C.secrets.githubToken} ${C.personal.email}`,
    ])
    const sent = assertNoLeaks(start)
    const official = sent.filter((s) => s.url.endsWith('/messages'))
    assert.ok(official.length >= 1, `no request on the official route (exit ${r.code}): ${r.out.slice(-400)}`)
    for (const s of official) assert.ok(!('dsh_session_log' in JSON.parse(s.body)))
    assert.ok(readFileSync(join(home, 'profiles', 'headless', 'package.json'), 'utf8').includes('dsh-egress-shield'))
  },
  300_000,
)
