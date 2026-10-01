// audit-chain: tamper-evident audit chain primitives (hash-chain + HMAC seal + verify).
// The WRITER owns the key and calls appendEntry; verifyChain re-derives everything to detect tampering.

export * from './canonicalize.js';
export * from './json.js';
export * from './jsonl.js';
export * from './keys.js';
export * from './record.js';
export * from './seal.js';
export * from './verify.js';
export * from './writer.js';
