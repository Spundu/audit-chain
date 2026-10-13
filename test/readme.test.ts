import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

// The README quick starts are the files in examples/, which CI runs (test/parity/readme.test.ts also
// compares their output with the README). This keeps the README copy from drifting from the files.
const REPO = join(__dirname, '..');
const README = readFileSync(join(REPO, 'README.md'), 'utf8');

describe('README', () => {
  it.each(['quickstart.mjs', 'quickstart.py'])('shows examples/%s exactly', (name) => {
    expect(README).toContain(readFileSync(join(REPO, 'examples', name), 'utf8'));
  });
});
