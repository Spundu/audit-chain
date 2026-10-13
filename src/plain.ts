// Internal helper, not exported from the package entry.

/** A plain object: what a JSON object parses to (or Object.create(null)). Arrays, class instances, Maps,
 * Dates and Errors are not. */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
