import { describe, it, expect } from 'vitest';
import { MAX_DEPTH, canonicalize } from '../src/canonicalize.js';
import { JsonSyntaxError, PARSE_MAX_DEPTH, parseJson } from '../src/json.js';

const BS = String.fromCharCode(92);
const LF = String.fromCharCode(10);

describe('parseJson', () => {
  it('is immune to the V8 (Node 23+) escaped-key cache bug that JSON.parse has', () => {
    JSON.parse(`{"a":1,"${BS}${BS}":2}`); // poison the host parser's cache
    const target = `{"a":1,"${BS}n":2}`;
    expect(Object.keys(parseJson(target) as object)).toEqual(['a', LF]);
  });

  it('agrees with JSON.parse on ordinary JSON', () => {
    const text = `{"s":"a${BS}"b${BS}u00e9${BS}ud83d${BS}ude00","n":[0,-1,1.5,1e2,-0],"t":true,"f":false,"z":null,"o":{}}`;
    expect(parseJson(text)).toEqual(JSON.parse(text));
  });

  it('keeps "__proto__" as an own member and resolves duplicate keys last-wins', () => {
    const value = parseJson('{"__proto__":{"x":1},"a":1,"a":2}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(canonicalize(value)).toBe('{"__proto__":{"x":1},"a":2}');
  });

  it('preserves escaped lone surrogates (canonicalize rejects them later)', () => {
    expect((parseJson(`"${BS}ud800"`) as string).charCodeAt(0)).toBe(0xd800);
  });

  it.each([
    ['whitespace before a colon', '{"a" :1}', { a: 1 }],
    ['whitespace inside an empty array', '[ ]', []],
    ['whitespace inside an empty object', '{ }', {}],
    ['all four JSON whitespace characters', `${String.fromCharCode(32, 9, 10, 13)}[1]${String.fromCharCode(13, 10)}`, [1]],
    ['upper- and lowercase unicode escape hex', `"${BS}u00C9${BS}u00e9"`, String.fromCharCode(0xc9, 0xe9)],
    ['exponent signs', '[1e+2,1E-2,1e2]', [100, 0.01, 100]],
    ['every digit in fraction and exponent', '[0.9,1.0123456789,9e9,1e19]', [0.9, 1.0123456789, 9e9, 1e19]],
    ['a long mantissa before an exponent', '1.00000000000000000001e1', 10],
    ['every short escape', `"${BS}"${BS}${BS}${BS}/${BS}b${BS}f${BS}n${BS}r${BS}t"`, `"${BS}/${String.fromCharCode(8, 12, 10, 13, 9)}`],
  ])('accepts %s', (_label, text, expected) => {
    expect(parseJson(text)).toEqual(expected);
  });

  it.each([
    ['form feed as whitespace', `${String.fromCharCode(12)}1`],
    ['vertical tab as whitespace', `${String.fromCharCode(11)}1`],
    ['NBSP as whitespace', `${String.fromCharCode(0xa0)}1`],
    ['a raw 0x1F in a string', `"a${String.fromCharCode(0x1f)}"`],
    ['a single-quote escape', `"${BS}'"`],
    ['a trailing comma in an object', '{"a":1,}'],
    ['a key missing its opening quote', '{xa":1}'],
    ['a single-quote-opened key', `{'a":1}`],
    ['a non-colon separator after a key', '{"a"x1}'],
    ['a comma in place of a colon', '{"a",1}'],
    ['a lone minus in an array', '[-,1]'],
    ['a lone minus as a member value', '{"a":-,"b":2}'],
    ['an exponent with no digits', '1e'],
    ['an exponent with only a sign', '1e+'],
    ['an uppercase exponent with only a sign', '[1E-]'],
    ['a fraction with no digits', '1.e5'],
    ['a misspelled true', 'tru1'],
    ['a misspelled null', 'nulx'],
    ['a truncated false', 'fals'],
    ['a non-hex unicode escape', `"${BS}u12G4"`],
    ['a non-hex FOURTH digit in a unicode escape', `"${BS}u004G"`],
    ['a unicode escape cut short by the closing quote', `"${BS}u004"x"`],
    ['an unknown escape followed by four hex digits', `"${BS}a0041"`],
    ['a missing comma in an array', '[1 2]'],
    ['a non-comma separator in an array', '[1x2]'],
    ['a missing comma in an object', '{"a":1 "b":2}'],
    ['a non-comma separator in an object', '{"a":1x"b":2}'],
    ['a missing colon', '{"a" 1}'],
    ['a number key', '{1:2}'],
    ['a bare-word key', '{a:1}'],
    ['empty text', ''],
    ['NaN', 'NaN'],
    ['Infinity', '-Infinity'],
    ['leading zero', '01'],
    ['bare fraction', '.5'],
    ['trailing dot', '1.'],
    ['plus sign', '+1'],
    ['hex', '0x10'],
    ['trailing comma', '[1,]'],
    ['single quotes', "{'a':1}"],
    ['raw control char in string', `"a${String.fromCharCode(9)}b"`],
    ['bad escape', `"${BS}x"`],
    ['short unicode escape', `"${BS}u12"`],
    ['unterminated string', '"abc'],
    ['trailing garbage', '{} x'],
    ['BOM', `${String.fromCharCode(0xfeff)}{}`],
    ['non-string key', '{1:2}'],
    ['a doubled minus', '--1'],
    ['a minus then a plus', '-+1'],
    ['two fractions', '[1.5.5]'],
    ['a doubled exponent sign', '1e+-2'],
    ['two minus signs in an exponent', '1e--2'],
    ['two exponents', '1e2e3'],
    ['a fraction after an exponent', '1e2.5'],
    ['a malformed number in an overwritten duplicate key', '{"seq":--1,"seq":0}'],
    ['a lowercase non-hex letter in a unicode escape', `"${BS}u004g"`],
    ['lowercase non-hex letters in a unicode escape', `"${BS}u00zz"`],
    ['a non-hex FIRST digit in a unicode escape', `"${BS}ug000"`],
    // A misspelled literal followed by the real one: matching must be at the position, not anywhere.
    ['a misspelled true before a true', '[tru1,true]'],
    ['a misspelled null before a null', '[nulx,null]'],
    ['a misspelled false before a false', '[falsx,false]'],
    ['a misspelled true before a true, in an object', '{"a":trux,"b":true}'],
  ])('rejects %s', (_label, text) => {
    expect(() => parseJson(text)).toThrow(JsonSyntaxError);
  });

  // The ends of every character class: hex digits 0 9 a f A F, and the characters just outside them.
  it.each(['0', '9', 'a', 'f', 'A', 'F'])('decodes a unicode escape whose last hex digit is %s, as JSON.parse does', (digit) => {
    const text = `"${BS}u00a${digit}${BS}u00${digit}9"`;
    expect(parseJson(text)).toBe(JSON.parse(text));
  });

  it.each(['/', ':', '@', 'G', '`', 'g'])('rejects %s as a hex digit of a unicode escape', (notHex) => {
    expect(() => parseJson(`"${BS}u00${notHex}9"`)).toThrow(JsonSyntaxError);
    expect(() => parseJson(`"${BS}u${notHex}000"`)).toThrow(JsonSyntaxError);
  });

  it.each(['[1/2]', '[1:2]', '[0/]', '[9:]', '[1./2]', '[1e/2]'])('rejects a digit-adjacent non-digit in %s', (text) => {
    expect(() => parseJson(text)).toThrow(JsonSyntaxError);
  });

  it.each([
    '0', '-0', '0.0', '-0.0', '0e0', '0E+0', '-0e-0', '1e-0', '-1.5e-3', '123456789.987654321e10', '9007199254740993',
    '1E400', '-1e-400', '5e-324', '1.7976931348623157e308', '0.1', '100', '-7',
  ])('reads the number %s exactly as JSON.parse does (the same correctly rounded double, sign of zero included)', (text) => {
    expect(Object.is(parseJson(text), JSON.parse(text))).toBe(true);
  });

  it.each(Array.from({ length: 32 }, (_, c) => c))('rejects the raw control character 0x%s inside a string', (c) => {
    expect(() => parseJson(`"a${String.fromCharCode(c)}b"`)).toThrow(JsonSyntaxError);
  });

  it(`refuses nesting deeper than ${PARSE_MAX_DEPTH} (a stack guard, not the canonical limit)`, () => {
    const nest = (n: number): string => '['.repeat(n) + ']'.repeat(n);
    expect(PARSE_MAX_DEPTH).toBe(1000); // documented in the README; literal so the test can't drift with it
    expect(() => parseJson(nest(1000))).not.toThrow();
    expect(() => parseJson(nest(1001))).toThrow(JsonSyntaxError);
    expect(() => parseJson(nest(PARSE_MAX_DEPTH))).not.toThrow();
    expect(() => parseJson(nest(PARSE_MAX_DEPTH + 1))).toThrow(JsonSyntaxError);
    const nestObjects = (n: number): string => '{"a":'.repeat(n) + '0' + '}'.repeat(n);
    expect(() => parseJson(nestObjects(PARSE_MAX_DEPTH))).not.toThrow();
    expect(() => parseJson(nestObjects(PARSE_MAX_DEPTH + 1))).toThrow(JsonSyntaxError);
  });

  it('refuses nesting deeper than a caller-chosen maxDepth, on the same scale as MAX_DEPTH', () => {
    const nest = (n: number): string => '['.repeat(n) + ']'.repeat(n);
    expect(() => parseJson(nest(MAX_DEPTH), MAX_DEPTH)).not.toThrow();
    expect(() => parseJson(nest(MAX_DEPTH + 1), MAX_DEPTH)).toThrow(JsonSyntaxError);
    expect(() => canonicalize(parseJson(nest(MAX_DEPTH), MAX_DEPTH))).not.toThrow(); // the same depth scale
    expect(parseJson('1', 0)).toBe(1);
    expect(() => parseJson('[]', 0)).toThrow(JsonSyntaxError);
  });

  it.each([-1, 1.5, Number.NaN, PARSE_MAX_DEPTH + 1, Number.POSITIVE_INFINITY])('rejects maxDepth %s', (maxDepth) => {
    expect(() => parseJson('[]', maxDepth)).toThrow(RangeError);
  });
});
