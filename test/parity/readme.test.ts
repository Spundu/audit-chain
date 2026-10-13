import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

// Runs both README quick starts (examples/) and requires the README to show exactly what they print.
// It lives with the parity suite because that is where both a built package and a Python are present.
const REPO = join(__dirname, '..', '..');
const README = readFileSync(join(REPO, 'README.md'), 'utf8');
const FENCE = '```';

function stdoutOf(command: string, args: string[]): string {
  const run = spawnSync(command, args, { cwd: REPO, encoding: 'utf8' });
  if (run.error) throw new Error(`could not start '${command}': ${run.error.message}`);
  if (run.status !== 0) throw new Error(`${args.join(' ')} exited ${run.status}:\n${run.stderr}`);
  return run.stdout.replace(/\r\n/g, '\n');
}

describe('the README quick starts print what the README shows', () => {
  it('examples/quickstart.mjs', () => {
    const output = stdoutOf(process.execPath, ['examples/quickstart.mjs']);
    expect(README).toContain(`${FENCE}\n${output}${FENCE}`);
  });

  it('examples/quickstart.py', () => {
    const output = stdoutOf(process.env.AUDIT_CHAIN_PYTHON ?? 'python', ['examples/quickstart.py']);
    expect(README).toContain(`${FENCE}\n${output}${FENCE}`);
  });
});
