// Local mock LLM provider for tests. Speaks OpenAI Chat Completions and Anthropic
// Messages (streaming and non-streaming), records every request it receives, and
// answers from a scripted queue so tests can drive tool calls deterministically.
//
// It never contacts the network. Captured requests keep every header except
// credentials, so tests can assert on exactly what left the gateway.

import { createServer } from 'node:http'
import { appendFileSync } from 'node:fs'

/**
 * @typedef {{ text?: string, toolCalls?: { name: string, arguments: object | string }[], status?: number, body?: string,
 *            promptTokens?: number }} ScriptedReply
 */

/**
 * Start the mock provider.
 * @param {{ port?: number, captureFile?: string, script?: ScriptedReply[], defaultReply?: ScriptedReply,
 *           responder?: (body: object, url: string) => ScriptedReply | undefined }} [options]
 *   `responder` answers first when it returns a reply (e.g. for title requests),
 *   so concurrent side requests do not consume the scripted queue.
 */
export async function startMockProvider(options = {}) {
  const captured = []
  const script = [...(options.script ?? [])]
  const defaultReply = options.defaultReply ?? { text: 'OK' }
  let counter = 0

  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks)
      const headers = { ...req.headers }
      delete headers.authorization
      delete headers['x-api-key']
      const record = { method: req.method, url: req.url, headers, body: raw.toString('utf8') }
      captured.push(record)
      if (options.captureFile) appendFileSync(options.captureFile, JSON.stringify(record) + '\n')

      if (req.method === 'GET') return json(res, 200, { object: 'list', data: [] })
      let body
      try {
        body = JSON.parse(record.body)
      } catch {
        return json(res, 400, { error: 'bad json' })
      }
      const reply = options.responder?.(body, req.url) ?? (script.length > 0 ? script.shift() : defaultReply)
      if (reply.status && reply.status >= 400) {
        res.writeHead(reply.status, { 'content-type': 'application/json' })
        return res.end(reply.body ?? JSON.stringify({ error: { message: 'scripted failure' } }))
      }
      counter += 1
      const id = `mock-${counter}`
      if (req.url.endsWith('/messages')) return anthropic(res, body, reply, id)
      return openai(res, body, reply, id)
    })
  })
  await new Promise((resolve) => server.listen(options.port ?? 0, '127.0.0.1', () => resolve(undefined)))
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address())
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    captured,
    push: (reply) => script.push(reply),
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(value))
}

function argString(a) {
  return typeof a === 'string' ? a : JSON.stringify(a)
}

function openai(res, body, reply, id) {
  const model = body.model ?? 'mock'
  const toolCalls = (reply.toolCalls ?? []).map((t, i) => ({
    index: i,
    id: `call_${id}_${i}`,
    type: 'function',
    function: { name: t.name, arguments: argString(t.arguments) },
  }))
  const finish = toolCalls.length > 0 ? 'tool_calls' : 'stop'
  if (!body.stream) {
    return json(res, 200, {
      id,
      object: 'chat.completion',
      created: 0,
      model,
      choices: [
        {
          index: 0,
          finish_reason: finish,
          message: {
            role: 'assistant',
            content: reply.text ?? '',
            ...(toolCalls.length ? { tool_calls: toolCalls.map(({ index: _index, ...t }) => t) } : {}),
          },
        },
      ],
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    })
  }
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
  const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`)
  const base = { id, object: 'chat.completion.chunk', created: 0, model }
  send({ ...base, choices: [{ index: 0, delta: { role: 'assistant', content: '' }, finish_reason: null }] })
  const text = reply.text ?? ''
  for (let i = 0; i < text.length; i += 7) {
    send({ ...base, choices: [{ index: 0, delta: { content: text.slice(i, i + 7) }, finish_reason: null }] })
  }
  for (const call of toolCalls) {
    send({
      ...base,
      choices: [
        {
          index: 0,
          delta: {
            tool_calls: [
              {
                index: call.index,
                id: call.id,
                type: 'function',
                function: { name: call.function.name, arguments: '' },
              },
            ],
          },
          finish_reason: null,
        },
      ],
    })
    const a = call.function.arguments
    // Split arguments into small fragments, as real providers do, so placeholder
    // tokens straddle chunk boundaries.
    for (let i = 0; i < a.length; i += 5) {
      send({
        ...base,
        choices: [
          {
            index: 0,
            delta: { tool_calls: [{ index: call.index, function: { arguments: a.slice(i, i + 5) } }] },
            finish_reason: null,
          },
        ],
      })
    }
  }
  send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: finish }] })
  const prompt = reply.promptTokens ?? 10
  send({ ...base, choices: [], usage: { prompt_tokens: prompt, completion_tokens: 5, total_tokens: prompt + 5 } })
  res.write('data: [DONE]\n\n')
  res.end()
}

function anthropic(res, body, reply, id) {
  const model = body.model ?? 'mock'
  const toolCalls = reply.toolCalls ?? []
  const stop = toolCalls.length > 0 ? 'tool_use' : 'end_turn'
  if (!body.stream) {
    const content = []
    if (reply.text) content.push({ type: 'text', text: reply.text })
    toolCalls.forEach((t, i) =>
      content.push({
        type: 'tool_use',
        id: `toolu_${id}_${i}`,
        name: t.name,
        input: typeof t.arguments === 'string' ? JSON.parse(t.arguments) : t.arguments,
      }),
    )
    return json(res, 200, {
      id,
      type: 'message',
      role: 'assistant',
      model,
      content,
      stop_reason: stop,
      usage: { input_tokens: 10, output_tokens: 5 },
    })
  }
  res.writeHead(200, { 'content-type': 'text/event-stream' })
  const send = (event, obj) => res.write(`event: ${event}\ndata: ${JSON.stringify(obj)}\n\n`)
  send('message_start', {
    type: 'message_start',
    message: {
      id,
      type: 'message',
      role: 'assistant',
      model,
      content: [],
      stop_reason: null,
      usage: { input_tokens: 10, output_tokens: 0 },
    },
  })
  let index = 0
  if (reply.text) {
    send('content_block_start', { type: 'content_block_start', index, content_block: { type: 'text', text: '' } })
    for (let i = 0; i < reply.text.length; i += 7)
      send('content_block_delta', {
        type: 'content_block_delta',
        index,
        delta: { type: 'text_delta', text: reply.text.slice(i, i + 7) },
      })
    send('content_block_stop', { type: 'content_block_stop', index })
    index += 1
  }
  for (const [i, t] of toolCalls.entries()) {
    send('content_block_start', {
      type: 'content_block_start',
      index,
      content_block: { type: 'tool_use', id: `toolu_${id}_${i}`, name: t.name, input: {} },
    })
    const a = argString(t.arguments)
    for (let j = 0; j < a.length; j += 5)
      send('content_block_delta', {
        type: 'content_block_delta',
        index,
        delta: { type: 'input_json_delta', partial_json: a.slice(j, j + 5) },
      })
    send('content_block_stop', { type: 'content_block_stop', index })
    index += 1
  }
  send('message_delta', { type: 'message_delta', delta: { stop_reason: stop }, usage: { output_tokens: 5 } })
  send('message_stop', { type: 'message_stop' })
  res.end()
}

// CLI: node test/support/mock-provider.mjs <port> <captureFile>
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.argv[2] ?? 0)
  const mock = await startMockProvider({ port, captureFile: process.argv[3], defaultReply: { text: 'OK from mock' } })
  process.stdout.write(`mock provider listening on ${mock.url}\n`)
}
