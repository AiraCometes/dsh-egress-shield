// Server-sent-events relay that holds back tool-call argument fragments,
// restores eligible placeholders once a call's arguments are complete, and
// re-emits them as a single fragment. Text deltas pass through untouched and
// immediately, so streaming latency for ordinary output is unchanged.

/** Incremental SSE parser: feed text, get complete events. */
export class SseParser {
  constructor() {
    this.buffer = ''
  }

  /** @returns {{ event?: string, data: string, raw: string }[]} */
  push(text) {
    this.buffer += text
    const out = []
    for (;;) {
      const m = /\r?\n\r?\n/.exec(this.buffer)
      if (!m) break
      const raw = this.buffer.slice(0, m.index)
      this.buffer = this.buffer.slice(m.index + m[0].length)
      out.push(parseEvent(raw))
    }
    return out
  }

  flush() {
    const rest = this.buffer
    this.buffer = ''
    return rest.trim() ? [parseEvent(rest)] : []
  }
}

function parseEvent(raw) {
  let event
  const data = []
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('event:')) event = line.slice(6).trim()
    else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''))
  }
  return { event, data: data.join('\n'), raw }
}

function frame(event, dataObj) {
  return `${event ? `event: ${event}\n` : ''}data: ${typeof dataObj === 'string' ? dataObj : JSON.stringify(dataObj)}\n\n`
}

/**
 * @param {'openai-chat'|'openai-responses'|'anthropic-messages'} wire
 * @param {(name: string, args: string) => string} restore
 * @returns {{ onEvent(ev): string, end(): string }}
 */
export function createSseTransformer(wire, restore) {
  if (wire === 'openai-chat') return openaiChatTransformer(restore)
  if (wire === 'anthropic-messages') return anthropicTransformer(restore)
  if (wire === 'openai-responses') return responsesTransformer(restore)
  return { onEvent: (ev) => `${ev.raw}\n\n`, end: () => '' }
}

function openaiChatTransformer(restore) {
  /** key `${choice}:${index}` → { name, args } */
  const pending = new Map()
  let template = null
  const flush = (choiceIndex) => {
    let out = ''
    for (const [key, call] of pending) {
      const [c, i] = key.split(':').map(Number)
      if (choiceIndex !== undefined && c !== choiceIndex) continue
      pending.delete(key)
      if (!call.args) continue
      const args = restore(call.name, call.args)
      out += frame(undefined, {
        ...template,
        choices: [
          { index: c, delta: { tool_calls: [{ index: i, function: { arguments: args } }] }, finish_reason: null },
        ],
      })
    }
    return out
  }
  return {
    onEvent(ev) {
      if (ev.data === '[DONE]') return flush() + `${ev.raw}\n\n`
      let chunk
      try {
        chunk = JSON.parse(ev.data)
      } catch {
        return `${ev.raw}\n\n`
      }
      if (!Array.isArray(chunk.choices)) return `${ev.raw}\n\n`
      template ??= { id: chunk.id, object: chunk.object, created: chunk.created, model: chunk.model }
      let prefix = ''
      let touched = false
      const choices = []
      for (const choice of chunk.choices) {
        const delta = choice?.delta
        if (delta && Array.isArray(delta.tool_calls)) {
          touched = true
          const kept = []
          for (const tc of delta.tool_calls) {
            const key = `${choice.index ?? 0}:${tc.index ?? 0}`
            const entry = pending.get(key) ?? { name: '', args: '' }
            if (tc.function?.name) entry.name = tc.function.name
            if (typeof tc.function?.arguments === 'string') entry.args += tc.function.arguments
            pending.set(key, entry)
            // Forward the call header (id/name) without its argument fragment.
            if (tc.id || tc.function?.name || tc.type) {
              kept.push({ ...tc, function: { ...tc.function, arguments: '' } })
            }
          }
          const nextDelta = { ...delta }
          if (kept.length) nextDelta.tool_calls = kept
          else delete nextDelta.tool_calls
          // A chunk that carried only argument fragments is dropped entirely.
          if (Object.keys(nextDelta).length > 0 || choice.finish_reason) choices.push({ ...choice, delta: nextDelta })
        } else {
          choices.push(choice)
        }
        if (choice?.finish_reason) prefix += flush(choice.index ?? 0)
      }
      if (!touched) return prefix + `${ev.raw}\n\n`
      if (choices.length === 0 && !chunk.usage) return prefix
      return prefix + frame(ev.event, { ...chunk, choices })
    },
    end() {
      return flush()
    },
  }
}

function anthropicTransformer(restore) {
  /** content block index → { name, args } */
  const pending = new Map()
  return {
    onEvent(ev) {
      let obj
      try {
        obj = JSON.parse(ev.data)
      } catch {
        return `${ev.raw}\n\n`
      }
      if (obj.type === 'content_block_start' && obj.content_block?.type === 'tool_use') {
        pending.set(obj.index, { name: obj.content_block.name, args: '' })
        return `${ev.raw}\n\n`
      }
      if (obj.type === 'content_block_delta' && obj.delta?.type === 'input_json_delta' && pending.has(obj.index)) {
        pending.get(obj.index).args += obj.delta.partial_json ?? ''
        return ''
      }
      if (obj.type === 'content_block_stop' && pending.has(obj.index)) {
        const call = pending.get(obj.index)
        pending.delete(obj.index)
        let out = ''
        if (call.args) {
          out += frame('content_block_delta', {
            type: 'content_block_delta',
            index: obj.index,
            delta: { type: 'input_json_delta', partial_json: restore(call.name, call.args) },
          })
        }
        return out + `${ev.raw}\n\n`
      }
      return `${ev.raw}\n\n`
    },
    end() {
      return ''
    },
  }
}

function responsesTransformer(restore) {
  /** item_id → { name, args } */
  const pending = new Map()
  const restored = new Map()
  const finalArgs = (id) => {
    if (restored.has(id)) return restored.get(id)
    const call = pending.get(id)
    const value = call ? restore(call.name, call.args) : undefined
    restored.set(id, value)
    return value
  }
  return {
    onEvent(ev) {
      let obj
      try {
        obj = JSON.parse(ev.data)
      } catch {
        return `${ev.raw}\n\n`
      }
      if (obj.type === 'response.output_item.added' && obj.item?.type === 'function_call') {
        pending.set(obj.item.id, { name: obj.item.name, args: '' })
        return `${ev.raw}\n\n`
      }
      if (obj.type === 'response.function_call_arguments.delta' && pending.has(obj.item_id)) {
        pending.get(obj.item_id).args += obj.delta ?? ''
        return ''
      }
      if (obj.type === 'response.function_call_arguments.done' && pending.has(obj.item_id)) {
        if (typeof obj.arguments === 'string') pending.get(obj.item_id).args = obj.arguments
        const args = finalArgs(obj.item_id)
        return (
          frame(ev.event, {
            type: 'response.function_call_arguments.delta',
            item_id: obj.item_id,
            output_index: obj.output_index,
            delta: args,
          }) + frame(ev.event, { ...obj, arguments: args })
        )
      }
      if (obj.type === 'response.output_item.done' && obj.item?.type === 'function_call') {
        const args = finalArgs(obj.item.id) ?? restore(obj.item.name, obj.item.arguments ?? '')
        return frame(ev.event, { ...obj, item: { ...obj.item, arguments: args } })
      }
      if (obj.type === 'response.completed' && Array.isArray(obj.response?.output)) {
        const output = obj.response.output.map((item) =>
          item?.type === 'function_call'
            ? { ...item, arguments: finalArgs(item.id) ?? restore(item.name, item.arguments ?? '') }
            : item,
        )
        return frame(ev.event, { ...obj, response: { ...obj.response, output } })
      }
      return `${ev.raw}\n\n`
    },
    end() {
      return ''
    },
  }
}
