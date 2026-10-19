# Security Policy

egress-shield exists to stop sensitive data from leaving your machine, so a weakness in it is a security issue even
when nothing crashes. Thank you for reporting responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest commit on the default branch) | ✅ |
| older commits | ❌ |

Compatibility is tested against `@deepseek-ai/dsh` 0.2.0-rc.2. Issues that appear only with other DSH versions are
still welcome; please name the version.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** in this repository. Reports are visible only to the maintainer.

Please include:

- the egress-shield commit and DSH version;
- the provider route and wire format involved (OpenAI Chat, OpenAI Responses, Anthropic Messages);
- a minimal reproduction using **fictitious data only**.

**Never include a real secret, credential, private key or personal data — not even a revoked one.** Describe the
*shape* instead (for example: "a 40-character token starting with `abc_`, inside a JSON string in a tool result").
If you believe a real value has already left your machine, rotate it first; we cannot help recover it.

This is a personal project maintained on a best-effort basis. We aim to acknowledge reports within 7 days and to agree
on a disclosure date with you once a fix is available. Credit is given in the advisory unless you prefer otherwise.

## Scope

In scope — anything that lets protected data reach a provider, or weakens fail-closed behaviour:

- a value in a supported category that passes the gateway unredacted (detection bypass, encoding tricks, partial
  redaction that leaves a usable fragment);
- a request that is forwarded although inspection failed, timed out, or could not parse it (fail-open);
- a provider route that bypasses the gateway or the in-process egress guard;
- placeholder restoration that sends a restored value off the machine, or restores a category it should not;
- sensitive values written to logs, the audit file, error messages, or `/healthz`;
- the gateway becoming reachable from anything other than the loopback interface;
- denial of service through crafted input (for example catastrophic regex backtracking).

Out of scope — documented limitations (see README, *What it does not protect*):

- network access performed by tools (`web_fetch`, MCP servers, shell commands);
- DSH telemetry uploads and locally stored session logs;
- malicious plugins running in the same DSH process;
- the content of images the user approved;
- names in free text without contextual cues that are not in the user's term list (please still report patterns you
  think the rules should cover — as a normal issue, with fictitious examples).
