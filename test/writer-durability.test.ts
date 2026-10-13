import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { JsonlChainWriter } from '../src/writer.js';
import { draft } from './draft.js';

// Behavioural: records every fsync the writer really makes, and on what it was opened, rather than the
// options it passes (Node's appendFileSync silently skips its flush option for UTF-8 strings).
const seen = vi.hoisted(() => ({ opened: new Map<number, string>(), written: new Set<number>(), synced: [] as string[] }));
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    openSync: (...args: Parameters<typeof actual.openSync>): number => {
      const fd = actual.openSync(...args);
      seen.opened.set(fd, String(args[0]));
      seen.written.delete(fd); // the OS reuses descriptor numbers
      return fd;
    },
    writeSync: ((fd: number, ...rest: unknown[]): number => {
      seen.written.add(fd);
      return (actual.writeSync as (...args: unknown[]) => number)(fd, ...rest);
    }) as typeof actual.writeSync,
    fsyncSync: (fd: number): void => {
      // Recorded before the call: on Windows the directory fsync throws EPERM, which the writer tolerates.
      seen.synced.push(`${seen.written.has(fd) ? 'written' : 'opened'} ${seen.opened.get(fd)}`);
      actual.fsyncSync(fd);
    },
  };
});

describe('JsonlChainWriter durability', () => {
  beforeEach(() => {
    seen.opened.clear();
    seen.written.clear();
    seen.synced.length = 0;
  });

  it('fsyncs every line it wrote, and the directory of a file it created, before append returns', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-chain-durable-'));
    try {
      const path = join(dir, 'audit.jsonl');
      const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 2) }, 'k1');
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      expect(seen.synced).toEqual([`written ${path}`, `opened ${dir}`]);
      writer.append(draft(1));
      expect(seen.synced).toEqual([`written ${path}`, `opened ${dir}`, `written ${path}`]);
      expect(verifyJsonl(readFileSync(path), keys)).toMatchObject({ ok: true, lastSeq: 1 });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
