# Contributing

Thanks for helping make egress-shield better. Issues and pull requests are welcome in English or Japanese.

## Ground rules

- **Fictitious data only.** Never put a real secret, credential, private key or personal data in an issue, pull
  request, test or commit — not even a revoked one. Use obviously fake values (`sk-proj-FAKE…`, `alice@example.com`,
  `*.example-tailnet.ts.net`) or generate them at test time like `test/support/corpus.mjs` does.
- **Security problems go through private reporting**, not issues. See [SECURITY.md](SECURITY.md).
- **Fail closed.** A change must never turn "could not inspect" into "send anyway".
- **No runtime dependencies.** The plugin ships as plain JavaScript that DSH loads directly; development tools are
  fine as `devDependencies`.
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need [mise](https://mise.jdx.dev); it installs Node, just, prek and Gitleaks at the versions in `mise.toml`.

```sh
mise install
just setup     # npm ci and git hooks (prek)
just check     # format check, lint, type check, tests, secret scan
```

Useful recipes: `just fmt`, `just lint`, `just typecheck`, `just test`, `just bench`, `just compare`, and
`just test-e2e <path to @deepseek-ai/dsh/lib/bin.js>` for end-to-end tests against a real DSH (no external LLM is
contacted; a local mock provider captures every request).

The pre-commit hook runs formatting, lint, type checking and a Gitleaks scan of staged changes; the pre-push hook runs
the test suite. CI runs the same checks plus the end-to-end suite.

## Making changes

- **New or changed detection rules** need positive and negative tests in `test/core.test.js`, and a pathological input
  in `test/redos.test.js` if the rule adds a regular expression. Keep quantifiers bounded and avoid optional
  separators inside repeated groups.
- **Gateway or wire-format changes** need an integration test in `test/gateway.test.js` that proves nothing reaches the
  mock provider on failure.
- **Performance**: run `just bench` before and after changes to detectors and mention the numbers in the pull request.
- Imported Gitleaks rules live in `src/core/rules/gitleaks.generated.js`; regenerate them with `just import-gitleaks`
  rather than editing the file.
- Code style is enforced by Oxfmt and Oxlint; types are checked with TypeScript (`checkJs`) through JSDoc.

## Commit messages

Use a short imperative summary line (Conventional Commits prefixes such as `feat:`, `fix:`, `docs:`, `chore:` are
welcome). Explain *why* in the body when it is not obvious.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
