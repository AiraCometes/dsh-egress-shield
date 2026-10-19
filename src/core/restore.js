// Restoration of pseudonymised placeholders inside tool-call arguments, so a
// tool the model calls with "[REDACTED_PATH_1]/src/a.ts" runs on the real
// path. Restoration is deliberately narrow:
//
// - only PATH and USERNAME placeholders (never secrets: irreversible values
//   are not even held, and never names, e-mails, addresses, Tailscale names);
// - only into local file tools, and into shell commands that contain no
//   network-capable command;
// - never into web, MCP, subagent, or unknown tools.
//
// A placeholder that is not restored stays as-is: the tool fails harmlessly.

import { PLACEHOLDER_RE } from './categories.js'

/**
 * @typedef {object} RestorePolicy
 * @property {boolean} enabled
 * @property {string[]} categories placeholder categories eligible for restoration
 * @property {string[]} fileTools tool names that receive restored values
 * @property {string[]} shellTools shell tools, restored only without network commands
 */

/** @type {Readonly<RestorePolicy>} */
export const DEFAULT_RESTORE_POLICY = Object.freeze({
  enabled: true,
  categories: ['PATH', 'USERNAME'],
  fileTools: [
    'read',
    'read_image',
    'write',
    'edit',
    'glob',
    'grep',
    'ls',
    'list_directory',
    'str_replace_editor',
    'view',
  ],
  shellTools: ['bash', 'pwsh', 'powershell', 'shell'],
})

// A command mentioning any of these could carry the restored value off the
// machine, so shell restoration is refused for it.
const NETWORK_COMMAND_RE = new RegExp(
  [
    String.raw`\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|tftp|telnet|nslookup|dig|host|ping|aria2c|httpie|http|xh)\b`,
    String.raw`\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|New-Object\s+(?:System\.)?Net\.)`,
    String.raw`\bgit\s+(?:push|clone|fetch|pull|remote|ls-remote|submodule|send-email)\b`,
    String.raw`\b(?:npm|pnpm|yarn)\s+(?:publish|login|adduser|whoami)\b`,
    String.raw`\b(?:python[0-9.]*|node|deno|bun|perl|ruby|php|osascript)\s+(?:-[A-Za-z]*[ce]\b|-)`,
    String.raw`\beval\b|\bbase64\b|/dev/(?:tcp|udp)/|https?://|\bmail\b|\bsendmail\b`,
  ].join('|'),
  'i',
)

/**
 * @param {string} toolName
 * @param {string} argsJson model-produced arguments (JSON text)
 * @param {import('./vault.js').Scope} scope
 * @param {Readonly<RestorePolicy>} policy
 * @returns {{ text: string, restored: number, refused: string | null }}
 */
export function restoreToolArguments(toolName, argsJson, scope, policy = DEFAULT_RESTORE_POLICY) {
  if (!policy.enabled || !argsJson || !argsJson.includes('[REDACTED_'))
    return { text: argsJson, restored: 0, refused: null }
  const name = String(toolName ?? '').toLowerCase()
  const isFile = policy.fileTools.includes(name)
  const isShell = policy.shellTools.includes(name)
  if (!isFile && !isShell) return { text: argsJson, restored: 0, refused: 'TOOL_NOT_ELIGIBLE' }
  let args
  try {
    args = JSON.parse(argsJson)
  } catch {
    return { text: argsJson, restored: 0, refused: 'UNPARSEABLE_ARGUMENTS' }
  }
  if (isShell) {
    const command = [args.command, args.script, args.cmd].filter((x) => typeof x === 'string').join('\n')
    if (NETWORK_COMMAND_RE.test(command)) return { text: argsJson, restored: 0, refused: 'NETWORK_COMMAND' }
  }
  let restored = 0
  const restoreString = (s) =>
    s.replace(PLACEHOLDER_RE, (whole, category, n) => {
      if (!policy.categories.includes(category)) return whole
      const value = scope.lookup(category, Number(n))
      if (value === undefined) return whole
      restored += 1
      return value
    })
  const walk = (v) => {
    if (typeof v === 'string') return restoreString(v)
    if (Array.isArray(v)) return v.map(walk)
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]))
    return v
  }
  const out = walk(args)
  return restored
    ? { text: JSON.stringify(out), restored, refused: null }
    : { text: argsJson, restored: 0, refused: null }
}

export { NETWORK_COMMAND_RE }
