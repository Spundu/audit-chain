import { describe, it, expect, vi } from 'vitest';
import { CanonicalizationError, MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize } from '../src/canonicalize.js';

describe('canonicalize (JCS subset)', () => {
  it('is independent of key insertion order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(canonicalize({ a: 2, b: 1 })).toBe('{"a":2,"b":1}');
  });

  it('sorts nested object keys but preserves array order', () => {
    expect(canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 } })).toBe('{"a":{"x":2,"y":1},"z":[3,1,2]}');
  });

  it('drops undefined members (as JSON does)', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('sorts integer-like keys as strings, not in JS enumeration order', () => {
    expect(canonicalize({ 9: 'a', 10: 'b', x: 'c' })).toBe('{"10":"b","9":"a","x":"c"}');
  });

  it('keeps an own "__proto__" member inside the canonical bytes', () => {
    const value = JSON.parse('{"__proto__":{"amount":1},"b":2}') as unknown;
    expect(canonicalize(value)).toBe('{"__proto__":{"amount":1},"b":2}');
  });

  it('accepts null-prototype objects', () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.b = 1;
    o.a = 2;
    expect(canonicalize(o)).toBe('{"a":2,"b":1}');
  });

  it('serializes -0 as 0', () => {
    expect(canonicalize([-0])).toBe('[0]');
  });

  it.each([
    ['a non-integer', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['an unsafe integer', 2 ** 53],
    ['a bigint', 1n],
    ['a lone surrogate', '\ud800'],
    ['a lone-surrogate key', { '\udc00': 1 }],
    ['undefined', undefined],
    ['an undefined array element', [undefined]],
    ['an array hole', [1, , 2]], // eslint-disable-line no-sparse-arrays
    ['a function', () => 1],
    ['a symbol', Symbol('s')],
    ['a Date', new Date(0)],
    ['a Map', new Map()],
    ['a Buffer', Buffer.from('x')],
    ['a class instance', new (class Box {})()],
    ['a getter member', Object.defineProperty({}, 'a', { get: () => 1, enumerable: true })],
    ['a getter array element', Object.defineProperty([0], 0, { get: () => 1 })],
    ['a revoked proxy', (() => { const p = Proxy.revocable({}, {}); p.revoke(); return p.proxy; })()],
  ])('rejects %s with CanonicalizationError', (_label, value) => {
    expect(() => canonicalize(value)).toThrow(CanonicalizationError);
  });

  it(`allows exactly ${MAX_DEPTH} levels of nesting`, () => {
    const nest = (n: number): unknown => (n === 0 ? 0 : [nest(n - 1)]);
    expect(() => canonicalize(nest(MAX_DEPTH))).not.toThrow();
    expect(() => canonicalize(nest(MAX_DEPTH + 1))).toThrow(CanonicalizationError);
  });

  it('bounds work on shared-reference trees whose output would be huge (structure counts)', () => {
    const empty: unknown[] = [];
    const wide = Array.from({ length: 2_000_000 }, () => empty);
    const start = Date.now();
    expect(() => canonicalize(wide)).toThrow(CanonicalizationError);
    let tree: unknown = [];
    for (let i = 0; i < 60; i += 1) tree = [tree, tree];
    expect(() => canonicalize(tree)).toThrow(CanonicalizationError);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it('drops an undefined member that is NOT the last one, and keeps every member after it', () => {
    expect(canonicalize({ a: 1, b: undefined, c: 2, d: { e: undefined, f: 3 } })).toBe('{"a":1,"c":2,"d":{"f":3}}');
  });
});

describe('the per-string size pre-check', () => {
  it('refuses a string longer than the limit before serializing it (a huge string never reaches JSON.stringify)', () => {
    const huge = 'a'.repeat(MAX_CANONICAL_BYTES + 1);
    const stringify = vi.spyOn(JSON, 'stringify');
    try {
      expect(() => canonicalize({ s: huge })).toThrow(CanonicalizationError);
      expect(() => canonicalize({ [huge]: 1 })).toThrow(CanonicalizationError);
      const longest = Math.max(0, ...stringify.mock.calls.map(([v]) => (typeof v === 'string' ? v.length : 0)));
      expect(longest).toBeLessThanOrEqual(MAX_CANONICAL_BYTES);
    } finally {
      stringify.mockRestore();
    }
  });
});
