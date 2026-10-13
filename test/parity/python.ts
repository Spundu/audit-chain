import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { join, relative } from 'node:path';

// Runs the Python side of the parity suite (python/tests/parity_worker.py) in one process.
// AUDIT_CHAIN_PYTHON selects the interpreter; it must have THIS repository's package installed
// (`pip install -e .`): the worker reports where it imported audit_chain from, and any other copy is refused.
const REPO = join(__dirname, '..', '..');
const WORKER = join(REPO, 'python', 'tests', 'parity_worker.py');
const PACKAGE = join(REPO, 'python', 'audit_chain');

export type CanonicalOutcome =
  | { ok: true; hex: string }
  | { ok: false; phase: 'parse' | 'domain' | 'crash'; error?: string };

export type SealOutcome =
  | { ok: true; entry_hash: string; entry_hmac: string }
  | { ok: false; phase: 'parse' | 'domain' | 'not-an-object' | 'derived-fields' | 'crash'; error?: string };

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
  audit_chain: string;
  canonicalize: CanonicalOutcome[];
  seal: SealOutcome[];
  append: SealOutcome[];
  verify: VerifyOutcome[];
  verify_jsonl: VerifyOutcome[];
}

export function runPython(request: {
  canonicalize: string[];
  seal?: { key_hex: string; writer_key_id: string }; // also seal each canonicalize text
  append?: { key_hex: string; writer_key_id: string }; // also append each text that is a JSON object
  verify: VerifyCase[];
  verify_jsonl: JsonlCase[];
}): WorkerResponse {
  const python = process.env.AUDIT_CHAIN_PYTHON ?? 'python';
  const run = spawnSync(python, [WORKER], {
    input: Buffer.from(JSON.stringify(request), 'utf8'),
    maxBuffer: 256 * 1024 * 1024,
  });
  if (run.error) throw new Error(`could not start '${python}': ${run.error.message}`);
  if (run.status !== 0) {
    throw new Error(`parity worker exited ${run.status}:\n${run.stderr.toString('utf8')}`);
  }
  const response = JSON.parse(run.stdout.toString('utf8')) as WorkerResponse;
  if (relative(realpathSync(PACKAGE), realpathSync(response.audit_chain)) !== '') {
    throw new Error(`'${python}' imports audit_chain from ${response.audit_chain}, not ${PACKAGE}: run pip install -e .`);
  }
  return response;
}
