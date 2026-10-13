// audit-chain: tamper-evident audit chain primitives (hash-chain + HMAC seal + verify) for records of
// any JSON shape. The WRITER owns the key and appends; verifyChain / verifyJsonl re-derive everything
// to detect tampering.

export * from './canonicalize.js';
export * from './json.js';
export * from './jsonl.js';
export * from './keys.js';
export * from './seal.js';
export * from './verify.js';
export * from './writer.js';
