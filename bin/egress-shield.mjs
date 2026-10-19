#!/usr/bin/env node
// Standalone gateway for harnesses other than DSH.
//
//   egress-shield serve --config ~/.config/egress-shield/config.json
//   egress-shield scan  < file.txt          # print the redacted text (local only)
//
// The config file is JSON: { "listen": {...}, "routes": {...}, "pathMode": "anchored",
// "attachments": "block", "termsFile": "...", "auditFile": "..." }. In standalone mode
// there is no interactive approval channel, so "ask" behaves like "block".

import { readFileSync } from 'node:fs'
import { createGateway } from '../src/gateway/server.js'
import { buildEngine, expandHome } from '../src/setup.js'

const [command = 'help', ...rest] = process.argv.slice(2)
const flag = (name) => {
  const i = rest.indexOf(name)
  return i === -1 ? undefined : rest[i + 1]
}

if (command === 'serve') {
  const file = expandHome(flag('--config') ?? '~/.config/egress-shield/config.json')
  const cfg = JSON.parse(readFileSync(file, 'utf8'))
  const { engine, termsStatus } = buildEngine(cfg)
  if (termsStatus === 'insecure-permissions') console.warn('egress-shield: terms file ignored (chmod 600 it)')
  const gateway = createGateway(engine, {
    listen: cfg.listen,
    routes: cfg.routes ?? {},
    attachments: cfg.attachments === 'allow' ? 'allow' : 'block',
    restore: cfg.restore,
    stripFields: cfg.stripFields,
    audit: { file: expandHome(cfg.auditFile ?? '') },
    logger: console,
  })
  const port = await gateway.listen()
  console.log(`egress-shield gateway listening on 127.0.0.1:${port}`)
  const stop = () => gateway.close().then(() => process.exit(0))
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
} else if (command === 'scan') {
  const chunks = []
  for await (const c of process.stdin) chunks.push(c)
  const { engine } = buildEngine({
    termsFile: flag('--terms'),
    pathMode: flag('--path-mode') === 'full' ? 'full' : 'anchored',
  })
  const scope = engine.scope('cli')
  const counts = {}
  const input = Buffer.concat(chunks).toString('utf8')
  // Like the gateway: placeholders typed into the input are reserved so a real value never reuses their number.
  engine.reservePlaceholders(input, scope)
  process.stdout.write(engine.redactString(input, scope, counts).text)
  console.error(`\n[egress-shield] ${JSON.stringify(counts)}`)
} else {
  console.log(
    'usage: egress-shield serve [--config file.json] | egress-shield scan [--terms file] [--path-mode anchored|full] < input',
  )
}
