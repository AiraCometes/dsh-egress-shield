#!/usr/bin/env node
// Performance benchmark (test plan P-01..P-04). Prints a Markdown table.
//   node --expose-gc scripts/bench.mjs

import { buildEngine } from '../src/setup.js'
import { createGateway } from '../src/gateway/server.js'
import { startMockProvider } from '../test/support/mock-provider.mjs'
import { makeCorpus } from '../test/support/corpus.mjs'

const C = makeCorpus()
const gc = globalThis.gc ?? (() => {})
const mb = (b) => (b / 2 ** 20).toFixed(1)

function realisticText(bytes, salt) {
  // Mixed source code, logs, and prose with a sprinkling of sensitive values.
  const parts = [
    `export async function handler${salt}(req, res) {\n  const user = await db.users.find(req.params.id)\n  return res.json({ ok: true, user })\n}\n`,
    `2026-10-19T06:22:07.123Z INFO request id=${salt} path=/v1/items status=200 duration=12ms\n`,
    `The deployment pipeline builds the container image, runs the unit tests, and publishes artifacts for build ${salt}.\n`,
    `[warn] retrying connection to db.internal:5432 (attempt ${salt % 5})\n`,
    `会議の議事録: 次回は仕様の確認と性能測定の結果共有を行う。番号 ${salt}\n`,
  ]
  const secrets = [
    `OPENAI_API_KEY=${C.secrets.openaiKey}\n`,
    `owner: ${C.personal.email}\n`,
    `cd /home/${C.personal.username}/projects/app\n`,
  ]
  let out = ''
  let i = 0
  while (out.length < bytes) {
    out += parts[i % parts.length].replace(/\$\{salt\}/g, String(i))
    if (i % 40 === 0) out += secrets[i % secrets.length]
    i++
  }
  return out
}

const rows = []
const p95 = (a) => a.toSorted((x, y) => x - y)[Math.floor(a.length * 0.95) - 1]

// P-01: first pass over 1 MB of new text — cold (first request after start,
// includes lazy rule compilation and JIT warm-up) and warm (steady state).
{
  const { engine } = buildEngine({ discover: false })
  let t0 = performance.now()
  engine.redactString(realisticText(1 << 20, 1), engine.scope('p1'), {})
  rows.push(['P-01a first scan of 1 MB, cold process', `${(performance.now() - t0).toFixed(0)} ms`, '(one-off)'])
  const samples = []
  for (let i = 2; i < 7; i++) {
    const text = realisticText(1 << 20, i).replace(/\n/g, ` ${i}\n`)
    t0 = performance.now()
    engine.redactString(text, engine.scope('p1'), {})
    samples.push(performance.now() - t0)
  }
  samples.sort((a, b) => a - b)
  rows.push(['P-01b scan of 1 MB new text, warm (median of 5)', `${samples[2].toFixed(0)} ms`, '≤ 100 ms'])
}

// P-02: 50-turn history (≈4 MB in 100 messages) re-sent, plus 10 KB of new text.
{
  const { engine } = buildEngine({ discover: false })
  const history = Array.from({ length: 100 }, (_, i) => ({
    role: i % 2 ? 'assistant' : 'user',
    content: realisticText(40 * 1024, i),
  }))
  const scope = engine.scope('p2')
  engine.redactJson({ messages: history }, scope)
  const body = { messages: [...history, { role: 'user', content: realisticText(10 * 1024, 999) }] }
  const t0 = performance.now()
  engine.redactJson(body, scope)
  rows.push([
    'P-02 re-sent 4 MB history + 10 KB new (cache warm)',
    `${(performance.now() - t0).toFixed(0)} ms`,
    '≤ 30 ms',
  ])
}

// P-03: resident memory added by an engine with a full cache.
{
  gc()
  gc()
  const before = process.memoryUsage().rss
  const { engine } = buildEngine({ discover: false })
  for (let i = 0; i < 2000; i++) engine.redactString(realisticText(2048, i), engine.scope(`s${i % 50}`), {})
  gc()
  gc()
  rows.push([
    'P-03 RSS added (engine, 2,000 cached texts, 50 sessions)',
    `${mb(process.memoryUsage().rss - before)} MB`,
    '≤ 30 MB',
  ])
}

// P-04: added time-to-first-byte through the gateway (SSE), warm cache.
{
  const mock = await startMockProvider({ defaultReply: { text: 'streamed reply text' } })
  const { engine } = buildEngine({ discover: false })
  const gw = createGateway(engine, { listen: { port: 0 }, routes: { m: { upstream: `${mock.url}/v1` } } })
  const port = await gw.listen()
  const body = JSON.stringify({
    model: 'm',
    stream: true,
    messages: [
      { role: 'system', content: realisticText(200 * 1024, 7) },
      { role: 'user', content: `hi ${C.personal.email}` },
    ],
  })
  const ttfb = async (url) => {
    const t0 = performance.now()
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-opencode-session': 'bench' },
      body,
    })
    const reader = res.body.getReader()
    await reader.read()
    const t = performance.now() - t0
    await reader.cancel()
    return t
  }
  const samples = { direct: [], gateway: [] }
  for (let i = 0; i < 30; i++) {
    samples.direct.push(await ttfb(`${mock.url}/v1/chat/completions`))
    samples.gateway.push(await ttfb(`http://127.0.0.1:${port}/r/m/chat/completions`))
  }
  rows.push([
    'P-04 added TTFB p95, 200 KB request (gateway − direct)',
    `${(p95(samples.gateway) - p95(samples.direct)).toFixed(1)} ms`,
    '≤ 30 ms',
  ])
  await gw.close()
  await mock.close()
}

console.log(`| benchmark | result | target |\n|---|---|---|\n${rows.map((r) => `| ${r.join(' | ')} |`).join('\n')}`)
console.log(`\nNode ${process.version}, ${process.platform}/${process.arch}`)
