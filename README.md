# dsh-egress-shield

[![CI](https://github.com/AiraCometes/dsh-egress-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/AiraCometes/dsh-egress-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

English | [日本語](README.ja.md)

A local, **fail-closed** redaction gateway for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH).
It inspects every request DSH sends to an LLM provider **on your machine, immediately before it leaves**, and replaces
secrets and personal data with placeholders such as `[REDACTED_API_KEY_1]`. If a request cannot be inspected or
redacted safely, it is not sent.

> **Status: v0.1.0, early.** Tested against `@deepseek-ai/dsh@0.2.0-rc.2` with a capturing mock provider (no real LLM
> traffic). Detection is rule-based and cannot be perfect — read [What it does not protect](#what-it-does-not-protect).

## Why a gateway, not just a plugin hook

DSH's public extension points can rewrite user input and tool results, but not the final request: the `llm/stream`
hook cannot replace a request, and some content (for example the absolute path of an attached file) is added after
that hook runs. egress-shield therefore inspects the **bytes on the wire**. You point the provider's `baseURL` at a
loopback gateway that the plugin runs inside the DSH process — no DSH changes, no extra daemon.

```
DSH ── provider baseURL ──▶ http://127.0.0.1:47821/r/<route> ──▶ provider (opencode.ai, api.deepseek.com, …)
        └── dsh-egress-shield plugin: gateway in-process, refuses un-routed providers, blocks direct egress
```

Everything that goes through the provider adapter is covered: the conversation, system prompt, tool results, session
titles, compaction summaries, sub-agents, retries, and DeepSeek's `dsh_session_log` field (stripped by default).

## What it detects

| Category | Examples | Handling |
|---|---|---|
| `API_KEY` | 221 imported [Gitleaks](https://github.com/gitleaks/gitleaks) rules, `sk-…`, `ghp_…`, AWS, Slack, JWT, `Bearer …`, cookies, URL query tokens, `tskey-…` | irreversible |
| `SSH_KEY` | PEM / OpenSSH / PuTTY private keys (raw, `\n`-escaped, truncated), SSH public keys | irreversible |
| `PASSWORD` | `password=…`, `--password …`, `scheme://user:pass@host`, `Password=…;` | irreversible |
| `CARD` | card numbers validated with Luhn and issuer length | irreversible |
| `TAILSCALE_URL` | `*.ts.net` MagicDNS names, `100.64.0.0/10`, `fd7a:115c:a1e0::/48` | pseudonymised |
| `EMAIL`, `USERNAME`, `HOSTNAME` | e-mail addresses; OS accounts and host names discovered at start-up or learned from traffic | pseudonymised |
| `PERSON`, `ADDRESS` | Japanese and English names (honorifics, `氏名:`, `Dear …`, a surname dictionary, your term list) and postal addresses | pseudonymised |
| `PATH` | Linux, macOS, Windows, WSL (`/mnt/c/Users/…`, `\\wsl$\…`), UNC and `file://` paths | pseudonymised, anchored |

Encoded values (Base64, percent-encoding, `\uXXXX` escapes) are decoded and inspected too. The same value always maps
to the same placeholder within a session; irreversible values are not kept anywhere, not even in memory (only a keyed
hash).

**Anchored paths.** Only the identifying prefix of a path is replaced, so the model can still work with your project:
`/home/alice/projects/app/src/index.ts` → `[REDACTED_PATH_1]/src/index.ts`. Set `pathMode: full` to replace whole
paths instead.

**Model notice.** When anything was redacted, a `[SECURITY REDACTION NOTICE]` listing only the detected categories is
appended to the system prompt. Look-alike notices or placeholders typed into the conversation are neutralised.

**Tool arguments.** When the model calls a local file tool with `[REDACTED_PATH_1]/src/a.ts`, the gateway restores
the real path in the streamed tool call. Only `PATH` and `USERNAME` are restored, only for file tools and for shell
commands without network commands — never for web, MCP or sub-agent tools, and never secrets.

**Images.** Image content cannot be inspected, so DSH asks you (through its approval UI) before any image is sent.
Rejected or unanswered requests are not sent.

## What it does not protect

- Network access performed **by tools** (`web_fetch`, MCP servers, `curl` in a shell).
- DSH's OpenTelemetry feedback upload (set `DSH_TELEMETRY_DISABLED=1`, see below).
- Data stored locally (DSH session logs, attachments).
- A malicious plugin running in the same DSH process.
- The content of images you approve.
- Names in free text with no cue and not in your term list. Rule-based detection has gaps; add the names that matter
  to you (yourself, family, clients, company and project names) to the [term list](#term-list).

## Installation

Requirements: Node.js 22+, DSH 0.2.x, and pnpm on `PATH` (DSH's `dsh plugin add` uses it). Install from a reviewed commit rather than by package name (npm names are easy
to squat):

```sh
git clone https://github.com/AiraCometes/dsh-egress-shield ~/src/dsh-egress-shield
cd ~/src/dsh-egress-shield && git checkout <reviewed-commit-sha>
dsh plugin --profile web add "link:$HOME/src/dsh-egress-shield"
```

Until you configure routes, **every LLM request fails closed** — nothing leaks while you finish the setup.

### Configure

In `~/.dsh/profiles/web/cordis.patch.yml`:

```yaml
- id: egress-shield
  config:
    listen: { host: 127.0.0.1, port: 47821 } # loopback only
    routes:
      opencode-go: { upstream: 'https://opencode.ai/zen/go/v1' }
      deepseek: { upstream: 'https://api.deepseek.com/anthropic' }
    routedProviders: [opencode-go] # DSH provider ids allowed to send
    pathMode: anchored # anchored | full
    attachments: ask # ask | block | allow
    restore: { enabled: true }
    termsFile: ~/.config/egress-shield/terms.txt
    auditFile: ~/.local/state/egress-shield/audit.jsonl
```

Then point each provider at its route. Edit the **existing** provider entry (or use DSH's Settings → Models) so you do
not replace its other settings:

```yaml
- id: llm-pi-ai
  config:
    providers:
      opencode-go:
        baseURL: http://127.0.0.1:47821/r/opencode-go
```

For the DeepSeek API add `deepseek-official` to `routedProviders` and set `llm-deepseek.baseURL` to
`http://127.0.0.1:47821/r/deepseek`. Requests to known provider endpoints that bypass the gateway are blocked inside the
DSH process.

| Option | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:47821` | Gateway address; non-loopback addresses are refused |
| `routes` | `{}` | `name → { upstream }`; reached at `/r/<name>` |
| `routedProviders` | `[]` | DSH provider ids allowed to dispatch; others are refused |
| `protectedEndpoints` | major provider APIs | URL prefixes that may only be reached through the gateway |
| `pathMode` | `anchored` | `anchored` keeps relative path segments; `full` replaces whole paths |
| `attachments` | `ask` | Images and file uploads: ask the user, `block`, or `allow` |
| `restore` | enabled | Tool-argument restoration policy (`enabled`, `fileTools`, `shellTools`) |
| `stripFields` | `['dsh_session_log']` | Top-level request fields removed before sending |
| `termsFile` | `~/.config/egress-shield/terms.txt` | Your private term list (must be `chmod 600`) |
| `auditFile` | `~/.local/state/egress-shield/audit.jsonl` | Value-free audit log (counts and categories only) |
| `anchors`, `usernames`, `hostnames` | `[]` | Extra identifying directories, accounts and hosts |

### Term list

```sh
mkdir -p ~/.config/egress-shield && install -m 600 /dev/null ~/.config/egress-shield/terms.txt
```

```text
# one entry per line: "CATEGORY: text", or just text for PERSON
Alice Example
ADDRESS: 1-1 Example-cho, Chiyoda-ku
PERSON: Example Trading Co., Ltd.
```

The file never leaves your machine and is ignored unless only you can read it.

### Recommended DSH settings

- `DSH_TELEMETRY_DISABLED=1` in the service environment: stops DSH from uploading a raw session-log prefix to DeepSeek's
  telemetry collector when you submit feedback. That upload is not an LLM request, so the gateway cannot redact it.
- `session-log-deepseek` → `enabled: false` (or Settings → General → *Upload Session Log…*): stops the raw session log
  from being attached to DeepSeek API requests. The gateway strips it anyway; this is defence in depth.

### Verify

```sh
curl -s http://127.0.0.1:47821/healthz   # counters only, never values
echo 'key sk-proj-FAKEabcdef0123456789abcdef mail alice@example.com' | node bin/egress-shield.mjs scan
```

Blocked requests surface in DSH as `[egress-shield] Request blocked before leaving this machine: <CODE>`; the code
(for example `RESIDUAL_SECRET`, `ATTACHMENT_APPROVAL_REQUIRED`, `EGRESS_SHIELD_UNROUTED_PROVIDER`) never contains data.

### Uninstall

Restore the providers' original `baseURL` first, then remove the `egress-shield` entry and run
`dsh plugin --profile web remove dsh-egress-shield`. (In the other order requests simply fail; nothing leaks.)

### Other harnesses

`node bin/egress-shield.mjs serve --config config.json` runs the same gateway standalone (`attachments` behaves as
`block` there, and the in-process egress guard is not available).

## Evaluation

On a fictitious labelled corpus (810 lines) egress-shield found every in-scope value with no false positives on 300
negatives, in 49 ms and ~4 MB, compared with Gitleaks, TruffleHog (no verification) and Presidio (spaCy). The corpus
was written alongside the rules, so treat those numbers as optimistic; free-text names without cues were found only
13% of the time (Presidio: 75%, but with 24% false positives and 307 MB). Re-run with `just compare`. Steady-state
cost is ~93 ms per MB of new text and ~11 ms for a re-sent 4 MB history.

## Development

JavaScript (ES modules) for Node 22 with JSDoc types checked by TypeScript (`checkJs`); no build step and no runtime
dependencies.

| Purpose | Tool |
|---|---|
| Tool versions | [mise](https://mise.jdx.dev) (`mise.toml`) |
| Tasks | [just](https://just.systems) (`justfile`) |
| Format / lint | Oxfmt / Oxlint |
| Types | TypeScript 7 (`tsc --noEmit`) |
| Tests | vitest (unit, integration, ReDoS, plugin; E2E against a real DSH) |
| Git hooks | [prek](https://prek.j178.dev) (`prek.toml`) |
| Secret scanning | Gitleaks |

```sh
just setup                    # mise install, npm ci, prek install
just check                    # format, lint, types, tests, secret scan
just test-e2e /path/to/@deepseek-ai/dsh/lib/bin.js
```

Layout: `src/core` (harness-agnostic engine), `src/gateway` (loopback proxy and wire codecs), `src/dsh` (DSH plugin),
`bin` (standalone CLI), `test` (with `test/support` mocks and fictitious corpora), `scripts` (rule import, benchmark,
comparison, a read-only local DSH audit).

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Acknowledgements

- Secret detection rules are imported from [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- This project was designed and written with the assistance of [Claude](https://claude.com) (Anthropic); commits
  made with it carry a `Co-Authored-By` trailer.

## License

[MIT](LICENSE) © 2026 AiraCometes
