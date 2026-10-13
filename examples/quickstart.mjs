import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryKeyProvider, JsonlChainWriter, readChain, verifyJsonl } from 'sealed-audit-chain';

// A random 32-byte HMAC key. In production, load it from your secret manager.
const keys = new InMemoryKeyProvider({ k1: randomBytes(32) }, 'k1');
const file = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.jsonl');

// Append records of any JSON shape. Keep the head somewhere the log's writers cannot rewrite.
const writer = new JsonlChainWriter(file, keys);
writer.append({ event: 'user.login', user: 'alice' });
const last = writer.append({ event: 'payment.refund', user: 'alice', amount_pence: 1900 });
const head = { count: last.seq + 1, lastHash: last.entry_hash };

// Later, an auditor: every entry verifies, and the file ends exactly at the stored head.
console.log(verifyJsonl(readFileSync(file), keys, head));
console.log(readChain(file, keys, head).map((entry) => entry.event));

// Change one name in the history: verification now fails at that entry.
writeFileSync(file, readFileSync(file, 'utf8').replace('alice', 'mallory'));
console.log(verifyJsonl(readFileSync(file), keys, head));
