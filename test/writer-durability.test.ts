import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import { InMemoryKeyProvider } from '../src/keys.js';
import { JsonlChainWriter } from '../src/writer.js';
import { draft } from './draft.js';

// Behavioural: every append asks for its line to be flushed to disk (fsync) before append() returns.
const appended = vi.hoisted(() => [] as unknown[]);
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    appendFileSync: (...args: Parameters<typeof actual.appendFileSync>): void => {
      appended.push(args[2]);
      actual.appendFileSync(...args);
    },
  };
});

describe('JsonlChainWriter durability', () => {
  it('flushes every appended line to disk before append returns', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-chain-durable-'));
    try {
      const writer = new JsonlChainWriter(join(dir, 'audit.jsonl'), new InMemoryKeyProvider({ k1: Buffer.alloc(32, 2) }, 'k1'));
      writer.append(draft(0));
      writer.append(draft(1));
      expect(appended).toEqual([
        { encoding: 'utf8', flush: true },
        { encoding: 'utf8', flush: true },
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
