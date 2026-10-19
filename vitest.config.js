import { defineConfig } from 'vitest/config'

// Every entry point selects a project (`--project unit` or `--project e2e`); a bare `vitest run` would also start the
// end-to-end suite whenever a `dsh` is on PATH.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/*.test.js'],
          // One process per file: the egress-guard tests replace Node's global
          // undici dispatcher, which must not leak into other files.
          pool: 'forks',
          testTimeout: 30_000,
        },
      },
      {
        // End-to-end tests against a real DeepSeek Harness (set DSH_BIN).
        test: {
          name: 'e2e',
          include: ['test/e2e/*.test.js'],
          pool: 'forks',
          fileParallelism: false,
          testTimeout: 300_000,
          hookTimeout: 300_000,
        },
      },
    ],
  },
})
