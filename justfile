# Development tasks. Tool versions: mise.toml (just, prek, gitleaks, node) and
# package-lock.json (oxfmt, oxlint, typescript, vitest).

# List recipes
default:
    @just --list

# Install pinned tools and dev dependencies, then the git hooks
setup:
    mise install
    npm ci --ignore-scripts
    prek install --hook-type pre-commit --hook-type pre-push

# Install the git hooks only
hooks:
    prek install --hook-type pre-commit --hook-type pre-push

# Format code in place
fmt:
    npx --no-install oxfmt

# Fail if code is not formatted
fmt-check:
    npx --no-install oxfmt --check

# Lint (warnings fail)
lint:
    npx --no-install oxlint --deny-warnings

# Type-check the JavaScript with TypeScript (checkJs, no output)
typecheck:
    npx --no-install tsc -p .

# Unit, integration, ReDoS and plugin tests
test:
    npx --no-install vitest run --project unit

# End-to-end tests against a real DSH: just test-e2e /path/to/@deepseek-ai/dsh/lib/bin.js
test-e2e dsh_bin:
    DSH_BIN={{dsh_bin}} npx --no-install vitest run --project e2e

# Scan the working tree and git history for secrets
secrets:
    gitleaks dir . --no-banner --redact
    gitleaks git . --no-banner --redact

# Everything CI should run
check: fmt-check lint typecheck test secrets

# Run every git hook against all files
hooks-all:
    prek run --all-files

# Performance benchmark
bench:
    node --expose-gc scripts/bench.mjs

# Compare with Gitleaks, TruffleHog and Presidio (see scripts/compare-scanners.mjs)
compare:
    node scripts/compare-scanners.mjs

# Re-import Gitleaks rules: just import-gitleaks path/to/gitleaks.toml <commit>
import-gitleaks toml commit:
    node scripts/import-gitleaks.mjs {{toml}} {{commit}}
