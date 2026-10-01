import { createHash, createHmac } from 'node:crypto';
import { afterEach, describe, it, expect, vi } from 'vitest';
import { CanonicalizationError, canonicalize } from '../src/canonicalize.js';
import { JsonSyntaxError } from '../src/json.js';
import { toJsonlLine, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { verifyChain, verifyEntries } from '../src/verify.js';

// Every place that catches an exception while verifying must let a stack overflow through (see
// src/stack.ts). Where V8 runs out of stack depends on JIT tiers and native stack reserves, so a real
// overflow can't be aimed at one call site; these tests inject a GENUINE stack-overflow error at each
// site in turn instead. test/stack.test.ts sweeps the real thing end to end.

const inject = vi.hoisted(() => ({ parse: null as unknown, canonicalizeOnce: null as unknown }));

vi.mock('../src/json.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/json.js')>();
  return {
    ...actual,
    parseJson: (...args: Parameters<typeof actual.parseJson>): unknown => {
      if (inject.parse !== null) throw inject.parse;
      return actual.parseJson(...args);
    },
  };
});

vi.mock('../src/canonicalize.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/canonicalize.js')>();
  return {
    ...actual,
    canonicalize: (value: unknown): string => {
      const err = inject.canonicalizeOnce;
      if (err !== null) {
        inject.canonicalizeOnce = null;
        throw err;
      }
      return actual.canonicalize(value);
    },
  };
});

afterEach(() => {
  inject.parse = null;
  inject.canonicalizeOnce = null;
  vi.restoreAllMocks();
});

const KEY = Buffer.alloc(32, 5);
const keys = new InMemoryKeyProvider({ k1: KEY }, 'k1');
const core = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', note: 'n' };
const bytes = canonicalize(core);
const entry = {
  ...core,
  entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
  entry_hmac: createHmac('sha256', KEY).update(bytes, 'utf8').digest('hex'),
};
const file = Buffer.from(toJsonlLine(entry), 'utf8');

function genuineRangeError(): unknown {
  const recurse = (n: number): number => recurse(n + 1) + 1;
  try {
    recurse(0);
  } catch (err) {
    return err;
  }
  throw new Error('the stack never overflowed');
}

/** The error a genuine V8 allocation failure throws (without allocating: each request is over V8's limits). */
function genuineAllocationFailure(allocate: () => unknown): unknown {
  try {
    allocate();
  } catch (err) {
    return err;
  }
  throw new Error('the allocation did not fail');
}

// Out of resources: running out of stack (two V8 shapes) or a catchable allocation failure.
const OVERFLOWS: [string, unknown][] = [
  ['a genuine RangeError', genuineRangeError()],
  ['the SyntaxError of a regex compiled out of stack', new SyntaxError('Invalid regular expression: /x/y: Stack overflow')],
  ['a failed array buffer allocation', genuineAllocationFailure(() => new ArrayBuffer(Number.MAX_SAFE_INTEGER))],
  ['a string too long to allocate', genuineAllocationFailure(() => 'x'.repeat(2 ** 30))],
  ['an array too long to allocate', genuineAllocationFailure(() => new Array(-1))],
];

/** A one-entry chain array whose `property` cannot be read (as a reactive or observable array can fail). */
function arrayThrowingOn(property: string, error: unknown): unknown[] {
  return new Proxy([entry], {
    get: (target, p, receiver) => {
      if (p === property) throw error;
      return Reflect.get(target, p, receiver) as unknown;
    },
  });
}

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}

describe.each(OVERFLOWS)('%s propagates from every catch site, never becoming a verdict', (_label, overflow) => {
  it('verifyJsonl: from the UTF-8 decoder', () => {
    vi.spyOn(TextDecoder.prototype, 'decode').mockImplementationOnce(() => {
      throw overflow;
    });
    expect(thrownBy(() => verifyJsonl(file, keys))).toBe(overflow);
  });

  it('verifyJsonl: from the JSON parser', () => {
    inject.parse = overflow;
    expect(thrownBy(() => verifyJsonl(file, keys))).toBe(overflow);
  });

  it('verifyJsonl: from canonicalizing the parsed line', () => {
    inject.canonicalizeOnce = overflow; // the first canonicalize call is parseLine's
    expect(thrownBy(() => verifyJsonl(file, keys))).toBe(overflow);
  });

  it('verifyChain: from canonicalizing the entry core', () => {
    inject.canonicalizeOnce = overflow;
    expect(thrownBy(() => verifyChain([entry], keys))).toBe(overflow);
  });

  it('verifyChain: from reading the entry', () => {
    const unreadable = { ...entry };
    Object.defineProperty(unreadable, 'seq', { enumerable: true, get: () => { throw overflow; } });
    expect(thrownBy(() => verifyChain([unreadable], keys))).toBe(overflow);
  });

  it('canonicalize: from reading the value', () => {
    const value = new Proxy({}, { ownKeys: () => { throw overflow; } });
    expect(thrownBy(() => canonicalize(value))).toBe(overflow);
  });

  it('verifyChain: from reading the length of the entries array', () => {
    expect(thrownBy(() => verifyChain(arrayThrowingOn('length', overflow), keys))).toBe(overflow);
  });

  it('verifyChain: from reading an element of the entries array', () => {
    expect(thrownBy(() => verifyChain(arrayThrowingOn('0', overflow), keys))).toBe(overflow);
  });

  it('verifyEntries: from turning an unreadable reason into text', () => {
    const reason = { toString: () => { throw overflow; } };
    expect(thrownBy(() => verifyEntries(() => ({ unreadable: reason as never }), keys))).toBe(overflow);
  });
});

describe('the same sites turn an ordinary error into a verdict (the controls)', () => {
  const ordinary = new TypeError('not about the stack');

  it('verifyJsonl: decoder, parser and canonicalize errors break the chain at the line', () => {
    vi.spyOn(TextDecoder.prototype, 'decode').mockImplementationOnce(() => {
      throw ordinary;
    });
    expect(verifyJsonl(file, keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'line is not valid UTF-8' });
    inject.parse = new JsonSyntaxError('bad');
    expect(verifyJsonl(file, keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'line is not valid JSON' });
    inject.parse = null;
    inject.canonicalizeOnce = new CanonicalizationError('outside');
    expect(verifyJsonl(file, keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'line is outside the canonical domain' });
    expect(verifyJsonl(file, keys)).toMatchObject({ ok: true, lastSeq: 0 }); // nothing left injected
  });

  it('verifyChain and canonicalize: an unreadable entry or value is a broken chain / CanonicalizationError', () => {
    const unreadable = { ...entry };
    Object.defineProperty(unreadable, 'seq', { enumerable: true, get: () => { throw ordinary; } });
    expect(verifyChain([unreadable], keys)).toMatchObject({ ok: false, brokenAt: 0 });
    const value = new Proxy({}, { ownKeys: () => { throw ordinary; } });
    expect(thrownBy(() => canonicalize(value))).toBeInstanceOf(CanonicalizationError);
  });

  it('verifyChain and verifyEntries: an unreadable array, element or reason is a broken chain', () => {
    expect(verifyChain(arrayThrowingOn('length', ordinary), keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'entries cannot be read' });
    expect(verifyChain(arrayThrowingOn('0', ordinary), keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'entry cannot be read' });
    const reason = { toString: () => { throw ordinary; } };
    expect(verifyEntries(() => ({ unreadable: reason as never }), keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'entry cannot be read' });
  });
});
