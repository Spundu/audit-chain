import { spawnSync } from 'node:child_process';

// Runs the Python side of the parity suite (python/audit_chain/parity_worker.py) in one process.
// AUDIT_CHAIN_PYTHON selects the interpreter; it must have this package installed (`pip install -e .`).

export type CanonicalOutcome =
  | { ok: true; hex: string }
  | { ok: false; phase: 'parse' | 'domain' | 'crash'; error?: string };

export type VerifyOutcome =
  | { threw: false; ok: boolean; last_seq: number }
  | { threw: true; error: string };

export interface VerifyCase {
  chain: string;
  keyring: Record<string, string>;
  anchor?: { count: number; last_hash: string };
}

export interface JsonlCase {
  data_hex: string;
  keyring: Record<string, string>;
  anchor?: { count: number; last_hash: string };
}

export interface WorkerResponse {
  canonicalize: CanonicalOutcome[];
  verify: VerifyOutcome[];
  verify_jsonl: VerifyOutcome[];
}

export function runPython(request: {
  canonicalize: string[];
  verify: VerifyCase[];
  verify_jsonl: JsonlCase[];
}): WorkerResponse {
  const python = process.env.AUDIT_CHAIN_PYTHON ?? 'python';
  const run = spawnSync(python, ['-m', 'audit_chain.parity_worker'], {
    input: Buffer.from(JSON.stringify(request), 'utf8'),
    maxBuffer: 256 * 1024 * 1024,
  });
  if (run.error) throw new Error(`could not start '${python}': ${run.error.message}`);
  if (run.status !== 0) {
    throw new Error(`parity worker exited ${run.status}:\n${run.stderr.toString('utf8')}`);
  }
  return JSON.parse(run.stdout.toString('utf8')) as WorkerResponse;
}
