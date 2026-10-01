// A strict RFC 8259 JSON parser. The library parses untrusted text with this instead of JSON.parse,
// because the host parser cannot be trusted: V8 12.9 and later (Node 23 through at least 26) return the
// WRONG key for an escaped one-character object key (e.g. "\n" comes back as a backslash) once an
// earlier parse in the same process saw a backslash key, so an attacker could make JSON.parse hand the
// verifier a different value from the one the text encodes. On RFC 8259 text it produces the same
// values as a correct JSON.parse: duplicate keys resolve last-wins, "__proto__" is an ordinary key,
// numbers are read as correctly rounded IEEE-754 doubles, and escaped lone surrogates are preserved
// (canonicalize then rejects them). It is NOT identical to Python's json.loads at the edges, and doesn't
// try to be: it refuses nesting deeper than PARSE_MAX_DEPTH (a stack guard; json.loads stops at a
// platform- and version-dependent C-stack limit, on CPython 3.12 about 3,000 levels on Windows and
// about 10,000 on Linux/macOS, far more on 3.14, not tied to sys.getrecursionlimit), it reads an
// integer literal of more than 4,300 digits (as Infinity, which canonicalize rejects) where json.loads
// refuses it, and it rejects NaN/Infinity, which json.loads accepts. Where the two differ, value-level verification can differ too.
// Canonical JSONL is immune: no such text is canonical.
//
// It uses no regular expressions: V8 compiles a regex lazily, and a compile that runs out of stack
// throws a SyntaxError that would read as "invalid JSON" (see stack.ts).

export class JsonSyntaxError extends Error {
  override name = 'JsonSyntaxError';
}

/** Stack guard, not a spec limit: comfortably above MAX_DEPTH, and a whole chain wraps entries in one more level. */
export const PARSE_MAX_DEPTH = 1000;

const QUOTE = 34;
const BACKSLASH = 92;
const SIMPLE_ESCAPES: Record<number, string> = {
  34: '"', // \"
  92: String.fromCharCode(92), // \\
  47: '/', // \/
  98: String.fromCharCode(8), // \b
  102: String.fromCharCode(12), // \f
  110: String.fromCharCode(10), // \n
  114: String.fromCharCode(13), // \r
  116: String.fromCharCode(9), // \t
};

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57; // 0-9
}

/** The value of one hex digit, or -1 if `code` is not one (either case: RFC 8259 allows both). */
function hexValue(code: number): number {
  if (isDigit(code)) return code - 48;
  if (code >= 97 && code <= 102) return code - 87; // a-f
  if (code >= 65 && code <= 70) return code - 55; // A-F
  return -1;
}

class Parser {
  #pos = 0;

  constructor(
    private readonly text: string,
    private readonly maxDepth: number,
  ) {}

  parse(): unknown {
    this.#skipWhitespace();
    const value = this.#value(0);
    this.#skipWhitespace();
    if (this.#pos !== this.text.length) this.#fail('unexpected trailing characters');
    return value;
  }

  #fail(message: string): never {
    throw new JsonSyntaxError(`${message} at position ${this.#pos}`);
  }

  #skipWhitespace(): void {
    for (;;) {
      const c = this.text.charCodeAt(this.#pos);
      if (c !== 32 && c !== 9 && c !== 10 && c !== 13) return;
      this.#pos += 1;
    }
  }

  #expectWord(word: string): void {
    if (!this.text.startsWith(word, this.#pos)) this.#fail('unexpected token');
    this.#pos += word.length;
  }

  #value(depth: number): unknown {
    const c = this.text.charCodeAt(this.#pos);
    if (c === QUOTE) return this.#string();
    if (c === 123 /* { */ || c === 91 /* [ */) {
      if (depth >= this.maxDepth) this.#fail(`nesting deeper than ${this.maxDepth}`);
      return c === 123 ? this.#object(depth) : this.#array(depth);
    }
    if (c === 116 /* t */) return this.#expectWord('true'), true;
    if (c === 102 /* f */) return this.#expectWord('false'), false;
    if (c === 110 /* n */) return this.#expectWord('null'), null;
    return this.#number();
  }

  /** Advance past a run of digits; fail with `message` if there is not at least one. */
  #digits(message: string): void {
    if (!isDigit(this.text.charCodeAt(this.#pos))) this.#fail(message);
    while (isDigit(this.text.charCodeAt(this.#pos))) this.#pos += 1;
  }

  // RFC 8259: number = [ "-" ] ( "0" / 1-9 *DIGIT ) [ "." 1*DIGIT ] [ ( "e" / "E" ) [ "+" / "-" ] 1*DIGIT ]
  #number(): number {
    const start = this.#pos;
    if (this.text.charCodeAt(this.#pos) === 45 /* - */) this.#pos += 1;
    if (this.text.charCodeAt(this.#pos) === 48 /* 0 */) this.#pos += 1;
    else this.#digits('unexpected token');
    if (this.text.charCodeAt(this.#pos) === 46 /* . */) {
      this.#pos += 1;
      this.#digits('invalid number');
    }
    const e = this.text.charCodeAt(this.#pos);
    if (e === 101 /* e */ || e === 69 /* E */) {
      this.#pos += 1;
      const sign = this.text.charCodeAt(this.#pos);
      if (sign === 43 /* + */ || sign === 45 /* - */) this.#pos += 1;
      this.#digits('invalid number');
    }
    // Correctly rounded; 1e400 becomes Infinity, which canonicalize rejects.
    return Number(this.text.slice(start, this.#pos));
  }

  #string(): string {
    this.#pos += 1; // opening quote
    let out = '';
    let runStart = this.#pos;
    for (;;) {
      const c = this.text.charCodeAt(this.#pos);
      if (Number.isNaN(c)) this.#fail('unterminated string');
      if (c === QUOTE) {
        out += this.text.slice(runStart, this.#pos);
        this.#pos += 1;
        return out;
      }
      if (c < 0x20) this.#fail('raw control character in string');
      if (c !== BACKSLASH) {
        this.#pos += 1;
        continue;
      }
      out += this.text.slice(runStart, this.#pos);
      const escape = this.text.charCodeAt(this.#pos + 1);
      const simple = SIMPLE_ESCAPES[escape];
      if (simple !== undefined) {
        out += simple;
        this.#pos += 2;
      } else if (escape === 117 /* u */) {
        let code = 0;
        for (let k = 2; k < 6; k += 1) {
          const digit = hexValue(this.text.charCodeAt(this.#pos + k));
          if (digit < 0) this.#fail('invalid unicode escape');
          code = code * 16 + digit;
        }
        out += String.fromCharCode(code);
        this.#pos += 6;
      } else {
        this.#fail('invalid escape');
      }
      runStart = this.#pos;
    }
  }

  #array(depth: number): unknown[] {
    this.#pos += 1;
    const out: unknown[] = [];
    this.#skipWhitespace();
    if (this.text.charCodeAt(this.#pos) === 93 /* ] */) {
      this.#pos += 1;
      return out;
    }
    for (;;) {
      this.#skipWhitespace();
      out.push(this.#value(depth + 1));
      this.#skipWhitespace();
      const c = this.text.charCodeAt(this.#pos);
      this.#pos += 1;
      if (c === 93 /* ] */) return out;
      if (c !== 44 /* , */) this.#fail('expected , or ]');
    }
  }

  #object(depth: number): Record<string, unknown> {
    this.#pos += 1;
    const out: Record<string, unknown> = {};
    this.#skipWhitespace();
    if (this.text.charCodeAt(this.#pos) === 125 /* } */) {
      this.#pos += 1;
      return out;
    }
    for (;;) {
      this.#skipWhitespace();
      if (this.text.charCodeAt(this.#pos) !== QUOTE) this.#fail('expected a string key');
      const key = this.#string();
      this.#skipWhitespace();
      if (this.text.charCodeAt(this.#pos) !== 58 /* : */) this.#fail('expected :');
      this.#pos += 1;
      this.#skipWhitespace();
      // defineProperty, not assignment: "__proto__" must become an own member, and a duplicate key
      // simply redefines it (last wins).
      Object.defineProperty(out, key, {
        value: this.#value(depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
      this.#skipWhitespace();
      const c = this.text.charCodeAt(this.#pos);
      this.#pos += 1;
      if (c === 125 /* } */) return out;
      if (c !== 44 /* , */) this.#fail('expected , or }');
    }
  }
}

/**
 * Parse JSON text strictly (RFC 8259) without the host JSON.parse. Throws JsonSyntaxError.
 * @param maxDepth refuse nesting deeper than this many arrays/objects (an integer from 0 to
 *   PARSE_MAX_DEPTH). A caller that only accepts canonical values passes MAX_DEPTH: deeper text is
 *   invalid anyway, and refusing it early keeps a hostile document from using up the caller's stack.
 */
export function parseJson(text: string, maxDepth: number = PARSE_MAX_DEPTH): unknown {
  if (typeof text !== 'string') throw new TypeError('parseJson expects a string');
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > PARSE_MAX_DEPTH) {
    throw new RangeError(`maxDepth must be an integer from 0 to ${PARSE_MAX_DEPTH}`);
  }
  return new Parser(text, maxDepth).parse();
}
