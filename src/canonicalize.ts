// Deterministic JSON canonicalization: the RFC 8785 (JCS) serialization rules restricted to a strict
// value domain, used as the pre-image for both the hash and the HMAC. python/audit_chain/canonical.py
// must produce the same bytes for the same parsed JSON; vectors/jcs-vectors.json is the normative spec.
//
// Domain (anything outside it throws CanonicalizationError; never a best-effort serialization):
//   * null, booleans
//   * numbers that are integers with |n| <= 2^53 - 1 (so -0 serializes as 0). Non-integers, NaN,
//     +-Infinity and unsafe integers are rejected: they are where JS and other languages disagree.
//   * strings (and object keys) that are well-formed UTF-16: a lone surrogate is rejected
//   * arrays; plain objects (keys sorted by UTF-16 code unit, `undefined` members dropped)
//   * at most MAX_DEPTH nested arrays/objects
//   * a canonical form of at most MAX_CANONICAL_BYTES UTF-8 bytes. Without a bound, a large enough
//     value exceeds V8's maximum string length and TypeScript fails where Python succeeds.
//
// The serializer writes objects itself instead of building a sorted object for JSON.stringify: a JS
// object enumerates integer-like keys ("9", "10") numerically before all others, and assigning a
// "__proto__" key sets the prototype instead of creating a member. Both silently changed the bytes.

import { isOutOfResources } from './stack.js';
import { isPlainObject } from './plain.js';

export const MAX_DEPTH = 100;
/** Largest canonical form, in UTF-8 bytes (1 MiB). Normative: vectors/jcs-vectors.json repeats it. */
export const MAX_CANONICAL_BYTES = 1_048_576;

// Running count of UTF-16 units emitted so far. A string's UTF-8 byte length is never smaller than
// its UTF-16 length, so aborting once the count passes MAX_CANONICAL_BYTES never rejects anything
// that would have fit; the exact byte check happens once, at the end.
interface Budget {
  units: number;
}

function charge(budget: Budget, units: number): void {
  budget.units += units;
  if (budget.units > MAX_CANONICAL_BYTES) {
    throw new CanonicalizationError(`canonical form exceeds ${MAX_CANONICAL_BYTES} bytes`);
  }
}

function spend(budget: Budget, s: string): string {
  charge(budget, s.length);
  return s;
}

export class CanonicalizationError extends Error {
  override name = 'CanonicalizationError';
}

function serializeString(s: string, budget: Budget): string {
  if (s.length > MAX_CANONICAL_BYTES) {
    throw new CanonicalizationError(`canonical form exceeds ${MAX_CANONICAL_BYTES} bytes`);
  }
  // A native check, not a regular expression: a regex compiled while the stack is nearly exhausted
  // throws a SyntaxError instead of the usual RangeError (see stack.ts).
  if (!s.isWellFormed()) throw new CanonicalizationError('string contains a lone surrogate');
  return spend(budget, JSON.stringify(s));
}

function serialize(value: unknown, depth: number, budget: Budget): string {
  if (value === null) return spend(budget, 'null');
  switch (typeof value) {
    case 'boolean':
      return spend(budget, value ? 'true' : 'false');
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(`number ${String(value)} is not an integer in [-(2^53-1), 2^53-1]`);
      }
      return spend(budget, JSON.stringify(value));
    case 'string':
      return serializeString(value, budget);
    case 'object':
      break;
    default:
      throw new CanonicalizationError(`${typeof value} is not a JSON value`);
  }

  if (depth >= MAX_DEPTH) throw new CanonicalizationError(`nesting deeper than ${MAX_DEPTH}`);
  if (Array.isArray(value)) {
    const parts: string[] = [];
    charge(budget, 2); // [ ]: structure counts too, or a million empty arrays would cost nothing
    for (let i = 0; i < value.length; i += 1) {
      if (i > 0) charge(budget, 1); // ,
      const descriptor = Object.getOwnPropertyDescriptor(value, i);
      if (descriptor === undefined || !('value' in descriptor)) {
        throw new CanonicalizationError(`array element ${i} is a hole or not a data property`);
      }
      const item: unknown = descriptor.value;
      if (item === undefined) throw new CanonicalizationError('undefined array element');
      parts.push(serialize(item, depth + 1, budget));
    }
    return `[${parts.join(',')}]`;
  }
  if (!isPlainObject(value)) throw new CanonicalizationError('only plain objects are JSON objects');
  const parts: string[] = [];
  charge(budget, 2); // { }
  for (const key of Object.keys(value).sort()) {
    // Data properties only: a getter could return different values to the hash and to a later reader.
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      throw new CanonicalizationError(`member "${key}" is not a data property`);
    }
    const member: unknown = descriptor.value;
    if (member === undefined) continue;
    charge(budget, parts.length > 0 ? 2 : 1); // : and ,
    parts.push(`${serializeString(key, budget)}:${serialize(member, depth + 1, budget)}`);
  }
  return `{${parts.join(',')}}`;
}

/** Canonical, stable string form of a JSON value. Throws CanonicalizationError outside the domain. */
export function canonicalize(value: unknown): string {
  let text: string;
  try {
    text = serialize(value, 0, { units: 0 });
  } catch (err) {
    if (err instanceof CanonicalizationError || isOutOfResources(err)) throw err;
    // e.g. a revoked Proxy: whatever cannot even be read has no canonical form.
    throw new CanonicalizationError('value cannot be read as JSON', { cause: err });
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_CANONICAL_BYTES) {
    throw new CanonicalizationError(`canonical form exceeds ${MAX_CANONICAL_BYTES} bytes`);
  }
  return text;
}
