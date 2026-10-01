// Lowercase-hex checks, written as character loops rather than regular expressions: V8 compiles a
// regex lazily, and a compile that runs out of stack throws a SyntaxError, so the verification path
// uses none (see stack.ts). Internal: not re-exported from index.ts.

function isLowerHexDigit(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 97 && code <= 102); // 0-9, a-f
}

/** True if `s` consists only of lowercase hex digits (0-9, a-f); the empty string qualifies. */
export function isLowerHex(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    if (!isLowerHexDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

/** True if `s` is exactly 64 lowercase hex digits: the spelling of every SHA-256 hash in a chain. */
export function isSha256Hex(s: string): boolean {
  return s.length === 64 && isLowerHex(s);
}
