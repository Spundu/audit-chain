import { createHash, createHmac } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import ts from 'typescript';
import { describe, it, expect } from 'vitest';
import { MAX_DEPTH, canonicalize } from '../src/canonicalize.js';
import { isLowerHex, isSha256Hex } from '../src/hex.js';
import { JsonSyntaxError } from '../src/json.js';
import { parseJsonl, toJsonlLine, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { isOutOfResources, isStackOverflow } from '../src/stack.js';
import { verifyChain, verifyEntries, type VerifyResult } from '../src/verify.js';

// Running out of stack is an infrastructure error of the CALLER, never evidence about the data: it
// propagates, and a valid chain is never reported as broken for lack of stack (python/tests/test_stack.py
// is the Python twin). V8 has two shapes for it, so both the predicate and the absence of regular
// expressions on the verification path are pinned here. The sweeps below check the behaviour end to end;
// test/stack-sites.test.ts pins each catch site with an injected overflow, since where V8 really runs
// out of stack depends on JIT tiers and native stack reserves.

const KEY = Buffer.alloc(32, 7);
const keys = new InMemoryKeyProvider({ k1: KEY }, 'k1');
const LF = String.fromCharCode(10);
// The sweeps run verification thousands of times at the edge of the stack: far above vitest's 5 s default
// on a slow or loaded machine, so they get an explicit budget instead of failing at random.
const SWEEP_TIMEOUT_MS = 120_000;

function chainOf(extras: Record<string, unknown>[]): Record<string, unknown>[] {
  let prev = '0'.repeat(64);
  return extras.map((extra, seq) => {
    const core = { seq, prev_hash: prev, writer_key_id: 'k1', ...extra };
    const bytes = canonicalize(core);
    prev = createHash('sha256').update(bytes, 'utf8').digest('hex');
    return { ...core, entry_hash: prev, entry_hmac: createHmac('sha256', KEY).update(bytes, 'utf8').digest('hex') };
  });
}
const fileOf = (entries: Record<string, unknown>[]): Buffer => Buffer.from(entries.map((e) => toJsonlLine(e)).join(''), 'utf8');
const nest = (levels: number, inner: unknown): unknown => (levels === 0 ? inner : [nest(levels - 1, inner)]);

const CHAINS = {
  ascii: chainOf([{ note: 'a' }, { note: 'b' }, { note: 'c' }]),
  // Two-byte and astral text: V8 handles one-byte and two-byte strings on separate code paths.
  'two-byte and astral': chainOf([{ note: `caf${String.fromCharCode(0xe9)} ${String.fromCharCode(0x20ac, 0x4e2d)}` }, { note: String.fromCodePoint(0x1f600) }]),
  // A legitimate entry exactly MAX_DEPTH deep: the deepest recursion canonicalize ever does.
  [`${MAX_DEPTH}-deep`]: chainOf([{ deep: nest(MAX_DEPTH - 1, 0) }]),
};

type Outcome = 'ok' | 'broken' | 'overflow' | 'other error';

const atDepth = <T,>(n: number, fn: () => T): T => (n === 0 ? fn() : atDepth(n - 1, fn));

/** The deepest recursion of atDepth that still returns: from there, `run` has almost no stack left. */
function deepestReturningDepth(): number {
  const fits = (n: number): boolean => {
    try {
      atDepth(n, () => 0);
      return true;
    } catch (err) {
      if (!isStackOverflow(err)) throw err;
      return false;
    }
  };
  for (let i = 0; i < 200; i += 1) fits(500); // let V8 optimize atDepth first, so its frame size is stable
  let low = 1;
  let high = 2;
  while (fits(high)) [low, high] = [high, high * 2];
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (fits(mid)) low = mid;
    else high = mid;
  }
  return low;
}

/**
 * Runs `run` from every depth across the band where it runs out of stack, one frame of stack at a time:
 * from the deepest point upward, until it has succeeded 64 times in a row. The recursion has ONE call
 * target, and it and `run` are warmed up first, so V8 keeps the same frame sizes throughout. Otherwise a
 * function that tiers up (or deoptimizes) mid-sweep changes how much stack each step frees, and the sweep
 * jumps over whole regions of the verification instead of running out of stack inside each of them.
 */
function outcomesAcrossTheStackLimit(run: () => VerifyResult): Set<Outcome> {
  const PROBE: VerifyResult = { ok: true, lastSeq: -1, brokenAt: null, reason: null };
  let probing = true;
  const target = (): VerifyResult => (probing ? PROBE : run());
  const down = (n: number): VerifyResult => (n === 0 ? target() : down(n - 1));
  for (let i = 0; i < 300; i += 1) {
    probing = i % 2 === 0; // warm both branches of the one call target
    down(200);
  }
  probing = true;
  const fits = (n: number): boolean => {
    try {
      down(n);
      return true;
    } catch (err) {
      if (!isStackOverflow(err)) throw err;
      return false;
    }
  };
  let low = 1;
  let high = 2;
  while (fits(high)) [low, high] = [high, high * 2];
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (fits(mid)) low = mid;
    else high = mid;
  }
  probing = false;
  const seen = new Set<Outcome>();
  let okInARow = 0;
  for (let n = low; n > 0 && okInARow < 64; n -= 1) {
    let outcome: Outcome;
    try {
      outcome = down(n).ok ? 'ok' : 'broken';
    } catch (err) {
      outcome = isStackOverflow(err) ? 'overflow' : 'other error';
    }
    seen.add(outcome);
    okInARow = outcome === 'ok' ? okInARow + 1 : 0;
  }
  return seen;
}

describe('isStackOverflow', () => {
  it.each([
    ['the RangeError', new RangeError('Maximum call stack size exceeded')],
    ['a regex compile that ran out of stack', new SyntaxError('Invalid regular expression: /-?(?:0|[1-9][0-9]*)/y: Stack overflow')],
    ['the SyntaxError form of the RangeError text', new SyntaxError('Maximum call stack size exceeded')],
  ])('recognises %s', (_label, err) => {
    expect(isStackOverflow(err)).toBe(true);
  });

  it.each([
    ['a JSON syntax error', new JsonSyntaxError('Maximum call stack size exceeded')],
    // Near misses of the exact V8 texts: the match is exact at both ends, not a substring.
    ['a SyntaxError that only ends like one', new SyntaxError('x: Stack overflow')],
    ['a SyntaxError with a prefix', new SyntaxError('x Invalid regular expression: /a/: Stack overflow')],
    ['a SyntaxError with a suffix', new SyntaxError('Invalid regular expression: /a/: Stack overflow!')],
    ['a RangeError with extra text', new RangeError('Maximum call stack size exceeded!')],
    ['an ordinary SyntaxError', new SyntaxError('Unexpected token')],
    ['an invalid regex that is not about the stack', new SyntaxError('Invalid regular expression: /(/: Unterminated group')],
    ['another RangeError', new RangeError('Invalid array length')],
    ['a plain Error with the same text', new Error('Maximum call stack size exceeded')],
    ['a string', 'Maximum call stack size exceeded'],
    ['null', null],
  ])('does not mistake %s for one', (_label, err) => {
    expect(isStackOverflow(err)).toBe(false);
  });

  it('recognises every error V8 throws for a regular expression compiled with the stack nearly exhausted', () => {
    // Swept from the deepest point up to where compiling succeeds 64 times in a row: the SyntaxError
    // form appears only near that end of the band (the regex compiler needs a large stack reserve).
    const errors: unknown[] = [];
    let okInARow = 0;
    for (let n = deepestReturningDepth(); n > 0 && okInARow < 64; n -= 1) {
      try {
        // A new source each time, so every attempt parses AND compiles a fresh regex.
        atDepth(n, () => new RegExp(`(?:a|b${n})*c[0-9]{2,}`).exec('ab12c99'));
        okInARow += 1;
      } catch (err) {
        errors.push(err);
        okInARow = 0;
      }
    }
    expect(okInARow).toBe(64); // the sweep crossed the whole band
    expect(errors.length).toBeGreaterThan(0);
    for (const err of errors) expect(isStackOverflow(err), String(err)).toBe(true);
  }, SWEEP_TIMEOUT_MS);
});

describe('isOutOfResources', () => {
  it.each([
    ['the stack-overflow RangeError', new RangeError('Maximum call stack size exceeded')],
    ['a failed array buffer allocation', new RangeError('Array buffer allocation failed')],
    ['a string too long', new RangeError('Invalid string length')],
    ['an array too long', new RangeError('Invalid array length')],
    ['a typed array too long', new RangeError('Invalid typed array length: 99999999999')],
  ])('recognises %s', (_label, err) => {
    expect(isOutOfResources(err)).toBe(true);
  });

  it.each([
    ['another RangeError', new RangeError('Invalid time value')],
    ['a RangeError that only contains the text', new RangeError('x Invalid typed array length')],
    ['a RangeError with a suffix', new RangeError('Invalid string length!')],
    ['a TypeError with the same text', new TypeError('Invalid string length')],
    ['a plain Error with the same text', new Error('Array buffer allocation failed')],
    ['a string', 'Invalid array length'],
  ])('does not mistake %s for one', (_label, err) => {
    expect(isOutOfResources(err)).toBe(false);
  });
});

describe('the regex-free hex checks', () => {
  // Each character just outside the lowercase-hex ranges, and each range's ends.
  it.each(['0', '9', 'a', 'f', '0123456789abcdef', ''])('accept %j', (s) => {
    expect(isLowerHex(s)).toBe(true);
  });
  it.each(['/', ':', '`', 'g', 'A', 'F', 'G', ' ', 'ab c', String.fromCharCode(0xe9)])('reject %j', (s) => {
    expect(isLowerHex(s)).toBe(false);
  });
  it('isSha256Hex wants exactly 64 of them', () => {
    expect(isSha256Hex('a'.repeat(64))).toBe(true);
    expect(isSha256Hex('a'.repeat(63))).toBe(false);
    expect(isSha256Hex('a'.repeat(65))).toBe(false);
    expect(isSha256Hex(`${'a'.repeat(63)}g`)).toBe(false);
  });
});

describe('the verification path uses no regular expressions', () => {
  // A regex is compiled lazily; if that happens with the stack nearly exhausted, V8 throws a SyntaxError.
  // Checked for EVERY source module, so a new one cannot bring a regex onto the verification path.
  const REGEX_METHODS = new Set(['match', 'matchAll', 'search']); // each turns a string argument into a RegExp
  const SOURCES = readdirSync(join(__dirname, '..', 'src')).filter((f) => f.endsWith('.ts'));
  it('covers every source module', () => {
    expect(SOURCES).toEqual(expect.arrayContaining(['canonicalize.ts', 'json.ts', 'jsonl.ts', 'seal.ts', 'verify.ts', 'writer.ts']));
  });
  it.each(SOURCES)('%s', (file) => {
    const text = readFileSync(join(__dirname, '..', 'src', file), 'utf8');
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) found.push(node.getText(source));
      if (ts.isIdentifier(node) && node.text === 'RegExp') found.push('RegExp');
      if (ts.isPropertyAccessExpression(node) && REGEX_METHODS.has(node.name.text)) found.push(`.${node.name.text}()`);
      ts.forEachChild(node, visit);
    };
    visit(source);
    expect(found).toEqual([]);
  });
});

describe('running out of stack is never a verdict', () => {
  for (const [label, chain] of Object.entries(CHAINS)) {
    const file = fileOf(chain);
    const parsed = parseJsonl(file).entries; // unknown[]: verifyChain accepts it without a cast

    it(`verifyJsonl on a valid ${label} chain: only ok or an overflow, never "broken"`, () => {
      expect([...outcomesAcrossTheStackLimit(() => verifyJsonl(file, keys))].sort()).toEqual(['ok', 'overflow']);
    }, SWEEP_TIMEOUT_MS);

    it(`verifyChain on a valid ${label} chain: only ok or an overflow, never "broken"`, () => {
      expect([...outcomesAcrossTheStackLimit(() => verifyChain(parsed, keys, null))].sort()).toEqual(['ok', 'overflow']);
    }, SWEEP_TIMEOUT_MS);

    it(`verifyEntries on a valid ${label} chain: only ok or an overflow, never "broken"`, () => {
      const run = (): VerifyResult => verifyEntries((i) => (i < parsed.length ? { entry: parsed[i] } : null), keys);
      expect([...outcomesAcrossTheStackLimit(run)].sort()).toEqual(['ok', 'overflow']);
    }, SWEEP_TIMEOUT_MS);
  }

  it('a hostile, deeply nested appended line yields a verdict or an overflow, nothing else', () => {
    const hostile = Buffer.concat([fileOf(CHAINS.ascii), Buffer.from(`${'['.repeat(1000)}${']'.repeat(1000)}${LF}`, 'utf8')]);
    const outcomes = outcomesAcrossTheStackLimit(() => {
      const result = verifyJsonl(hostile, keys);
      expect(result).toMatchObject({ ok: false, brokenAt: 3 });
      return { ...result, ok: true }; // the expected verdict: count it as a success of the sweep
    });
    expect([...outcomes].sort()).toEqual(['ok', 'overflow']);
  }, SWEEP_TIMEOUT_MS);
});
