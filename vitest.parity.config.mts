import { defineConfig } from 'vitest/config';

// The cross-language parity suite. Needs a Python with this package installed (`pip install -e .`);
// set AUDIT_CHAIN_PYTHON to pick the interpreter (default: `python`).
export default defineConfig({
  test: {
    include: ['test/parity/**/*.test.ts'],
    environment: 'node',
    testTimeout: 60_000,
    // beforeAll runs the whole Python side in one process: ~8 s unloaded, more on a slow CI runner.
    hookTimeout: 120_000,
  },
});
