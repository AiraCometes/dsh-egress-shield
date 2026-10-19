import { defineConfig } from 'vitest/config'

// End-to-end tests against a real DeepSeek Harness (set DSH_BIN).
export default defineConfig({
  test: {
    include: ['test/e2e/*.test.js'],
    pool: 'forks',
    fileParallelism: false,
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
})
