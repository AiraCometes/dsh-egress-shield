// Fictitious sensitive values used by every test. None of these are real
// credentials, people, or places. Keys are generated per run where a real
// format is needed (private keys), so nothing secret is ever committed.

import { generateKeyPairSync, randomBytes } from 'node:crypto'

const rnd = (n) => randomBytes(n).toString('base64url').replace(/[-_]/g, 'x').slice(0, n)

export function makeCorpus() {
  const { privateKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })
  const { privateKey: rsaKey } = generateKeyPairSync('rsa', {
    modulusLength: 1024,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })
  return {
    secrets: {
      openaiKey: `sk-proj-FAKE${rnd(40)}`,
      githubToken: `ghp_${rnd(36)}`,
      awsKey: `AKIA${rnd(16)
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, 'Q')}`,
      slackToken: `xoxb-1234567890-${rnd(24)}`,
      jwt: `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.${rnd(43)}`,
      bearer: `FAKEbearer${rnd(30)}`,
      tailscaleKey: `tskey-auth-k${rnd(10)}-${rnd(30)}`,
      password: `Fake-Pass-${rnd(12)}!`,
      dbPassword: `FakeDb${rnd(14)}`,
      card: '4111 1111 1111 1111',
      card2: '5555-5555-5555-4444',
      pem: privateKey.trim(),
      rsaPem: rsaKey.trim(),
    },
    personal: {
      email: 'taro.yamada@example.com',
      email2: 'hanako@example.co.jp',
      tailnetHost: 'myhost.example-tailnet.ts.net',
      tailnetIp: '100.101.102.103',
      username: 'exampleuser',
      winUser: 'Taro Yamada',
      jaName: '田中 太郎',
      jaAddress: '東京都千代田区千代田1-1-1',
      enName: 'John Appleseed',
      enAddress: '1600 Example Avenue, Springfield, IL 62704',
      term: '佐々木 美咲',
    },
  }
}

/** Every raw value that must never appear in an outbound payload. */
export function forbiddenValues(corpus) {
  const out = [...Object.values(corpus.secrets), ...Object.values(corpus.personal)]
  // Also check the distinctive inner parts of multi-line keys.
  for (const pem of [corpus.secrets.pem, corpus.secrets.rsaPem]) {
    const body = pem.split('\n').slice(1, -1).join('')
    out.push(body.slice(0, 40))
  }
  return out
}

export function findLeaks(text, corpus) {
  return forbiddenValues(corpus).filter((v) => text.includes(v))
}
