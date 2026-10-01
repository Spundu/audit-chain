// Running out of call stack is an INFRASTRUCTURE error of the caller (verification started too deep in
// its own stack), never evidence about the data: every depth the data can reach is bounded far below it
// (MAX_DEPTH for canonical values and for canonical-JSONL lines, PARSE_MAX_DEPTH for parseJson on other
// text). So it always propagates, and is never reported as a broken chain. Internal: not re-exported
// from index.ts.
//
// V8 reports it in two shapes: a RangeError, and a SyntaxError when the stack runs out while COMPILING a
// regular expression ("Invalid regular expression: /.../: Stack overflow"; some versions also use the
// RangeError text). The verification path uses no regular expressions at all (test/stack.test.ts pins
// that), so a lazy regex compile can never happen mid-verification; recognising both shapes is the
// second line of defence. This function itself uses only string comparisons, for the same reason.

const V8_STACK_OVERFLOW = 'Maximum call stack size exceeded';

export function isStackOverflow(err: unknown): boolean {
  if (err instanceof RangeError) return err.message === V8_STACK_OVERFLOW;
  if (err instanceof SyntaxError) {
    const { message } = err;
    return (
      message === V8_STACK_OVERFLOW ||
      (message.startsWith('Invalid regular expression:') && message.endsWith(': Stack overflow'))
    );
  }
  return false;
}

// V8's CATCHABLE allocation failures (running out of heap proper aborts the process instead). The
// library's own limits keep every string, array and buffer it builds far below V8's maxima, so these,
// too, can only mean that the process is out of resources, never anything about the data.
const V8_ALLOCATION_FAILURES = ['Array buffer allocation failed', 'Invalid string length', 'Invalid array length'];

/** A stack overflow or an allocation failure: an infrastructure error that must propagate, never a verdict. */
export function isOutOfResources(err: unknown): boolean {
  if (isStackOverflow(err)) return true;
  if (!(err instanceof RangeError)) return false;
  return V8_ALLOCATION_FAILURES.includes(err.message) || err.message.startsWith('Invalid typed array length');
}
