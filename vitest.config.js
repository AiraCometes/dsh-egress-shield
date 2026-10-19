import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/*.test.js'],
    // One process per file: the egress-guard tests replace Node's global
    // undici dispatcher, which must not leak into other files.
    pool: 'forks',
    testTimeout: 30_000,
  },
})
