// Labelled, fictitious evaluation corpus. Each line carries one expected
// category (or NONE) and the exact value that must be hidden. Deterministic
// (seeded) so results are comparable across runs and tools.
//
// It deliberately includes hard cases the rules are NOT designed to catch
// (names with no cue, surnames outside the dictionary) so measured recall is
// honest rather than flattering.

import { generateKeyPairSync } from 'node:crypto'

function rng(seed) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 2 ** 32
  }
}

export function buildLabelledCorpus(seed = 42) {
  const r = rng(seed)
  const pick = (a) => a[Math.floor(r() * a.length)]
  const chars = (set, n) => Array.from({ length: n }, () => set[Math.floor(r() * set.length)]).join('')
  const AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const az09 = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const Az09 = AZ + az09
  const lines = []
  const add = (category, value, text, hard = false) => lines.push({ category, value, text, hard })

  // ---- secrets (realistic shapes, random bodies)
  for (let i = 0; i < 40; i++) {
    const v = `ghp_${chars(Az09, 36)}`
    add('API_KEY', v, pick([`export GITHUB_TOKEN=${v}`, `git clone https://${v}@github.com/org/repo`, `token: ${v}`]))
  }
  for (let i = 0; i < 40; i++) {
    const v = `sk-proj-${chars(Az09, 48)}`
    add(
      'API_KEY',
      v,
      pick([
        `OPENAI_API_KEY="${v}"`,
        `client = OpenAI(api_key="${v}")`,
        `curl -H "Authorization: Bearer ${v}" https://api.example.test`,
      ]),
    )
  }
  for (let i = 0; i < 30; i++) {
    const v = `AKIA${chars(AZ + '234567', 16)}`
    add('API_KEY', v, pick([`aws_access_key_id = ${v}`, `AWS_ACCESS_KEY_ID=${v}`, `{"AccessKeyId": "${v}"}`]))
  }
  for (let i = 0; i < 30; i++) {
    const v = `xoxb-${chars('0123456789', 11)}-${chars('0123456789', 12)}-${chars(Az09, 24)}`
    add('API_KEY', v, `SLACK_BOT_TOKEN=${v}`)
  }
  for (let i = 0; i < 30; i++) {
    const v = `tskey-auth-k${chars(Az09, 11)}-${chars(Az09, 33)}`
    add('API_KEY', v, pick([`tailscale up --authkey=${v}`, `TS_AUTHKEY=${v}`]))
  }
  for (let i = 0; i < 40; i++) {
    const v = `${chars(Az09, 6)}!${chars(Az09, 8)}`
    add(
      'PASSWORD',
      v,
      pick([
        `password: "${v}"`,
        `DB_PASSWORD=${v}`,
        `mysql -u app --password=${v}`,
        `postgres://app:${v}@db.internal:5432/app`,
        `<add key="Password" value="${v}" />`,
      ]),
    )
  }
  for (let i = 0; i < 10; i++) {
    const { privateKey } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    })
    const body = privateKey.trim()
    add('SSH_KEY', body.split('\n')[1], body.replace(/\n/g, '\\n'))
  }
  for (let i = 0; i < 30; i++) {
    const base = pick(['411111111111', '555555555555', '378282246310', '601111111111', '353011133330'])
    const length = base.startsWith('37') ? 15 : 16 // Amex numbers have 15 digits
    const digits = base + chars('0123456789', length - base.length - 1)
    let sum = 0
    for (let j = 0; j < digits.length; j++) {
      let d = Number(digits[digits.length - 1 - j])
      if (j % 2 === 0) {
        d *= 2
        if (d > 9) d -= 9
      }
      sum += d
    }
    const full = digits + ((10 - (sum % 10)) % 10)
    const shown = pick([full, full.replace(/(\d{4})(?=\d)/g, '$1 '), full.replace(/(\d{4})(?=\d)/g, '$1-')])
    add('CARD', shown, pick([`カード番号: ${shown}`, `card=${shown}`, `支払い ${shown} で決済`]))
  }

  // ---- contact / network
  for (let i = 0; i < 40; i++) {
    const v = `${pick(['taro', 'hanako', 'j.smith', 'dev-ops', 'yamada.t'])}${chars('0123456789', 2)}@${pick(['example.com', 'example.co.jp', 'mail.example.org'])}`
    add('EMAIL', v, pick([`連絡先: ${v}`, `From: ${v}`, `git config user.email "${v}"`, `<a href="mailto:${v}">`]))
  }
  for (let i = 0; i < 30; i++) {
    const v = `${pick(['nas', 'pi', 'desktop', 'mac-mini', 'wsl'])}${chars('0123456789', 2)}.${pick(['tail1234', 'example-tailnet', 'cat-crocodile'])}.ts.net`
    add('TAILSCALE_URL', v, pick([`ssh user@${v}`, `https://${v}:8443/`, `接続先: ${v}`]))
  }
  for (let i = 0; i < 20; i++) {
    const v = `100.${64 + Math.floor(r() * 63)}.${Math.floor(r() * 255)}.${Math.floor(r() * 255)}`
    add('TAILSCALE_URL', v, `tailscale ip -4 → ${v}`)
  }

  // ---- Japanese names: in-dictionary with cues, out-of-dictionary, and no cue
  const dictSurnames = ['佐藤', '鈴木', '高橋', '田中', '渡辺', '山本', '中村', '小林', '加藤', '吉田']
  const rareSurnames = ['勅使河原', '御手洗', '小鳥遊', '東海林', '四月一日']
  const given = ['太郎', '花子', '翔太', '美咲', '健一', '陽菜', 'さくら', '大輔']
  for (let i = 0; i < 40; i++) {
    const v = `${pick(dictSurnames)}${pick(['', ' '])}${pick(given)}`
    add('PERSON', v, pick([`${v}様`, `氏名: ${v}`, `担当者：${v}`, `${v}さんに確認しました`]))
  }
  for (let i = 0; i < 15; i++) {
    const v = `${pick(rareSurnames)}${pick(given)}`
    add('PERSON', v, pick([`氏名: ${v}`, `${v}様`]), true)
  }
  for (let i = 0; i < 15; i++) {
    const v = `${pick(dictSurnames)}${pick(given)}`
    add('PERSON', v, `今日は${v}と打ち合わせをした`, true)
  }
  // English names
  const first = ['John', 'Emily', 'Michael', 'Sarah', 'David', 'Olivia']
  const last = ['Appleseed', 'Johnson', 'Whitaker', 'Fernandez', 'Okafor']
  for (let i = 0; i < 30; i++) {
    const v = `${pick(first)} ${pick(last)}`
    add(
      'PERSON',
      v,
      pick([`Dear ${v},`, `Author: ${v} <a@example.com>`, `Signed-off-by: ${v}`, `Mr. ${v} will attend`]),
    )
  }
  for (let i = 0; i < 10; i++) {
    const v = `${pick(first)} ${pick(last)}`
    add('PERSON', v, `I met ${v} yesterday at the office`, true)
  }

  // ---- addresses
  const prefs = ['東京都', '大阪府', '神奈川県', '北海道', '福岡県']
  const cities = ['千代田区', '中央区', '横浜市西区', '札幌市北区', '福岡市博多区']
  for (let i = 0; i < 30; i++) {
    const v = `${pick(prefs)}${pick(cities)}${pick(['丸の内', '本町', '緑町', '栄'])}${1 + Math.floor(r() * 9)}-${1 + Math.floor(r() * 20)}-${1 + Math.floor(r() * 30)}`
    add('ADDRESS', v, pick([`住所: ${v}`, `〒100-0005 ${v}`, `${v} にお届け`]))
  }
  for (let i = 0; i < 10; i++) {
    const v = `${pick(cities)}${pick(['本町', '栄'])}${1 + Math.floor(r() * 9)}丁目${1 + Math.floor(r() * 9)}番${1 + Math.floor(r() * 9)}号`
    add('ADDRESS', v, `所在地 ${v}`)
  }
  for (let i = 0; i < 20; i++) {
    const v = `${100 + Math.floor(r() * 9000)} ${pick(['Maple', 'Oak', 'Pine', 'Example'])} ${pick(['Street', 'Avenue', 'Road', 'Lane'])}, ${pick(['Springfield', 'Riverton'])}, ${pick(['IL', 'CA', 'NY'])} ${10000 + Math.floor(r() * 89999)}`
    add('ADDRESS', v, `Ship to: ${v}`)
  }

  // ---- negatives: things that look technical but are not sensitive
  const negatives = [
    'commit 3f9a2c1d4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f90 merged',
    'uuid=550e8400-e29b-41d4-a716-446655440000',
    'version 1.2.3-rc.4',
    'const token = getToken(req)',
    'password: ${DB_PASSWORD}',
    'see src/core/engine.js:42',
    'npm install --save-dev typescript',
    'order id 4111111111111112',
    'phone 03-1234-5678',
    '2026-10-19T06:22:07Z',
    'sha256:ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12',
    'GET /v1/chat/completions 200',
    'The quick brown fox jumps over the lazy dog.',
    '東京タワーは高い。',
    '会議は明日の10時からです。',
    'export NODE_ENV=production',
    'https://github.com/gitleaks/gitleaks',
    'max_tokens: 65536',
    'Hello World from the Example team',
    '/usr/lib/node_modules/npm/bin/npm-cli.js',
    'img src="data:,"',
    'apiVersion: apps/v1',
    'kind: Deployment',
    '鈴木自動車の新型車',
  ]
  for (let i = 0; i < 300; i++) add('NONE', '', pick(negatives))
  return lines
}
