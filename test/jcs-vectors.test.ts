import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { CanonicalizationError, MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize } from '../src/canonicalize.js';
import { JsonSyntaxError, parseJson } from '../src/json.js';

// The committed cross-language vectors. This test keeps the file HONEST vs the authoritative TS
// canonicalize; python/tests/test_canonical_vectors.py asserts the Python port reproduces the same bytes.
const vectorsPath = join(__dirname, '..', 'vectors', 'jcs-vectors.json');

interface Vector {
  name: string;
  value: unknown;
  expected_canonical: string;
  expected_sha256: string;
}
interface TextVector {
  name: string;
  json_text: string;
  expected_canonical: string | null;
  expected_sha256: string | null;
}
const file = parseJson(readFileSync(vectorsPath, 'utf8')) as {
  vectors: Vector[];
  text_vectors: TextVector[];
  max_canonical_bytes: number;
  max_depth: number;
  size_vectors: {
    name: string;
    prefix: string;
    unit: string;
    count: number;
    suffix: string;
    expected_bytes: number | null;
    expected_sha256: string | null;
  }[];
};
const vectors = file.vectors;

describe('JCS cross-language vectors', () => {
  it('the committed vector file is non-empty', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it('implements the normative domain limits', () => {
    expect(MAX_CANONICAL_BYTES).toBe(file.max_canonical_bytes);
    expect(MAX_DEPTH).toBe(file.max_depth);
  });

  it('accepts a canonical form of exactly max_canonical_bytes and rejects one byte more', () => {
    const fits = 'a'.repeat(file.max_canonical_bytes - 2); // + 2 quotes
    expect(Buffer.byteLength(canonicalize(fits))).toBe(file.max_canonical_bytes);
    expect(() => canonicalize(`${fits}a`)).toThrow(CanonicalizationError);
    // UTF-16 length fits, UTF-8 length does not: the exact byte check decides.
    expect(() => canonicalize(String.fromCharCode(0xe9).repeat(file.max_canonical_bytes / 2))).toThrow(CanonicalizationError);
  });

  for (const v of vectors) {
    it(`canonicalizes "${v.name}" to the committed bytes + sha256`, () => {
      const canonical = canonicalize(v.value);
      expect(canonical).toBe(v.expected_canonical);
      expect(createHash('sha256').update(canonical, 'utf8').digest('hex')).toBe(v.expected_sha256);
    });
  }

  for (const v of file.text_vectors) {
    const verdict = v.expected_canonical === null ? 'rejects' : 'canonicalizes';
    it(`${verdict} text vector "${v.name}"`, () => {
      if (v.expected_canonical === null) {
        // Rejected at parse time (not JSON) or by canonicalize (outside the domain): either refuses.
        let error: unknown;
        try {
          canonicalize(parseJson(v.json_text));
        } catch (err) {
          error = err;
        }
        expect(error instanceof CanonicalizationError || error instanceof JsonSyntaxError).toBe(true);
        return;
      }
      const canonical = canonicalize(parseJson(v.json_text));
      expect(canonical).toBe(v.expected_canonical);
      expect(createHash('sha256').update(canonical, 'utf8').digest('hex')).toBe(v.expected_sha256);
    });
  }

  for (const v of file.size_vectors) {
    it(`size vector "${v.name}"`, () => {
      const parsed: unknown = parseJson(v.prefix + v.unit.repeat(v.count) + v.suffix);
      if (v.expected_sha256 === null) {
        expect(() => canonicalize(parsed)).toThrow(CanonicalizationError);
        return;
      }
      const canonical = canonicalize(parsed);
      expect(Buffer.byteLength(canonical, 'utf8')).toBe(v.expected_bytes);
      expect(createHash('sha256').update(canonical, 'utf8').digest('hex')).toBe(v.expected_sha256);
    });
  }
});
