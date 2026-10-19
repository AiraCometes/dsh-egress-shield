## What and why

<!-- What does this change, and why is it needed? Link the issue if there is one. -->

## How it was tested

- [ ] `just check` passes (format, lint, types, tests, secret scan)
- [ ] New or changed detection rules have positive, negative and ReDoS tests
- [ ] Gateway changes keep failing closed (an integration test proves nothing reaches the provider on failure)
- [ ] `just test-e2e` was run, or this change cannot affect DSH integration
- [ ] `just bench` numbers are included if detectors changed

## Safety

- [ ] Only fictitious data appears in code, tests, logs and this description
- [ ] No runtime dependencies were added
