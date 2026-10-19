// Provider wire formats. A codec knows, for one request/response shape:
//   - which strings are opaque attachments (images, files) that the text
//     detectors must not touch and the attachment policy must decide on;
//   - where the system-level notice goes;
//   - where tool-call arguments live in a non-streamed response.
// Streamed responses are handled in sse.js.

import { createHash } from 'node:crypto'

const sha = (s) => createHash('sha256').update(s).digest('base64url')

function isObj(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** Append text to an OpenAI/Anthropic content value (string or parts array). */
function appendText(content, text, partType = 'text') {
  if (typeof content === 'string') return content ? `${content}\n\n${text}` : text
  if (Array.isArray(content)) return [...content, { type: partType, text }]
  return text
}

// ------------------------------------------------------------ OpenAI Chat

const openaiChat = {
  name: 'openai-chat',
  match: (path) => /\/chat\/completions\/?$/.test(path),

  /** @returns {{ id: string, path: (string|number)[] }[]} */
  attachments(body) {
    const found = []
    for (const [i, msg] of (body.messages ?? []).entries()) {
      if (!Array.isArray(msg?.content)) continue
      for (const [j, part] of msg.content.entries()) {
        if (!isObj(part)) continue
        if (part.type === 'image_url' && part.image_url) {
          const url = typeof part.image_url === 'string' ? part.image_url : part.image_url.url
          found.push({ id: sha(String(url)), kind: 'image', path: ['messages', i, 'content', j] })
        } else if (part.type === 'input_audio' || part.type === 'file' || part.type === 'input_file') {
          found.push({ id: sha(JSON.stringify(part)), kind: part.type, path: ['messages', i, 'content', j] })
        }
      }
    }
    return found
  },

  injectNotice(body, notice) {
    const messages = Array.isArray(body.messages) ? [...body.messages] : []
    const first = messages[0]
    if (first && (first.role === 'system' || first.role === 'developer')) {
      messages[0] = { ...first, content: appendText(first.content, notice) }
    } else {
      messages.unshift({ role: 'system', content: notice })
    }
    return { ...body, messages }
  },

  restoreJson(body, restore) {
    for (const choice of body.choices ?? []) {
      for (const call of choice?.message?.tool_calls ?? []) {
        if (call?.function && typeof call.function.arguments === 'string') {
          call.function.arguments = restore(call.function.name, call.function.arguments)
        }
      }
    }
    return body
  },
}

// ------------------------------------------------------------ OpenAI Responses

const openaiResponses = {
  name: 'openai-responses',
  match: (path) => /\/responses\/?$/.test(path),

  attachments(body) {
    const found = []
    const input = Array.isArray(body.input) ? body.input : []
    for (const [i, item] of input.entries()) {
      if (!Array.isArray(item?.content)) continue
      for (const [j, part] of item.content.entries()) {
        if (!isObj(part)) continue
        if (part.type === 'input_image')
          found.push({
            id: sha(String(part.image_url ?? part.file_id ?? '')),
            kind: 'image',
            path: ['input', i, 'content', j],
          })
        else if (part.type === 'input_file' || part.type === 'input_audio')
          found.push({ id: sha(JSON.stringify(part)), kind: part.type, path: ['input', i, 'content', j] })
      }
    }
    return found
  },

  injectNotice(body, notice) {
    return { ...body, instructions: appendText(typeof body.instructions === 'string' ? body.instructions : '', notice) }
  },

  restoreJson(body, restore) {
    for (const item of body.output ?? []) {
      if (item?.type === 'function_call' && typeof item.arguments === 'string')
        item.arguments = restore(item.name, item.arguments)
    }
    return body
  },
}

// ------------------------------------------------------------ Anthropic Messages

function anthropicBlocks(body, visit) {
  for (const [i, msg] of (body.messages ?? []).entries()) {
    if (!Array.isArray(msg?.content)) continue
    for (const [j, block] of msg.content.entries()) {
      visit(block, ['messages', i, 'content', j])
      if (block?.type === 'tool_result' && Array.isArray(block.content)) {
        for (const [k, inner] of block.content.entries()) visit(inner, ['messages', i, 'content', j, 'content', k])
      }
    }
  }
}

const anthropicMessages = {
  name: 'anthropic-messages',
  match: (path) => /\/messages\/?$/.test(path),

  attachments(body) {
    const found = []
    anthropicBlocks(body, (block, path) => {
      if (!isObj(block)) return
      if (block.type === 'image' || block.type === 'document') {
        const src = block.source ?? {}
        const id = sha(String(src.data ?? src.url ?? src.file_id ?? JSON.stringify(src)))
        // A plain-text document source is inspectable text, not an opaque blob.
        if (block.type === 'document' && src.type === 'text') return
        found.push({ id, kind: block.type, path })
      }
    })
    return found
  },

  injectNotice(body, notice) {
    if (Array.isArray(body.system)) return { ...body, system: [...body.system, { type: 'text', text: notice }] }
    return { ...body, system: appendText(typeof body.system === 'string' ? body.system : '', notice) }
  },

  restoreJson(body, restore) {
    for (const block of body.content ?? []) {
      if (block?.type === 'tool_use' && block.input !== undefined) {
        const text = restore(block.name, JSON.stringify(block.input))
        try {
          block.input = JSON.parse(text)
        } catch {}
      }
    }
    return body
  },
}

export const CODECS = [openaiChat, openaiResponses, anthropicMessages]

export function codecFor(path) {
  return CODECS.find((c) => c.match(path)) ?? null
}

/** True when `path` lies inside one of the attachment subtrees. */
export function underAny(path, prefixes) {
  return prefixes.some((p) => p.length <= path.length && p.every((seg, i) => path[i] === seg))
}
