// The generators' self-check, shared by both emitters and tested on its own (test/vector-guard.test.ts).
// A vector states its INTENT (must accept / must reject) by hand; the emitter refuses to write a file
// in which the TypeScript implementation disagrees, so a regression cannot quietly become the new
// "expected" output of the normative spec.

export function checkMust(kind: string, name: string, must: 'accept' | 'reject', canonical: string | null): void {
  if ((canonical === null) !== (must === 'reject')) {
    throw new Error(`${kind} "${name}": TS canonicalize does not ${must} it; refusing to emit`);
  }
}
