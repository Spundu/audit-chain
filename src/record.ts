import { z } from 'zod';

// The audit record. Every entry in a chain is one of these, plus the two derived fields
// (entry_hash, entry_hmac) added at seal time. The chain is tamper-EVIDENT and NON-AUTHORIZING:
// it records what happened; it never decides whether something may happen.
//
// This is an EXAMPLE record shape, the one the TypeScript writer enforces. The chain construction
// (canonicalize -> sha256 -> HMAC, linked by prev_hash) does not depend on it: seal/verify work on any
// JSON object core, and the shared test vectors deliberately use arbitrary cores that do not conform
// to this schema.

export const AUDIT_SCHEMA_VERSION = 1 as const;
export const GENESIS_HASH = '0'.repeat(64);
const SHA256_HEX = /^[0-9a-f]{64}$/;
const Sha256Hex = z.string().regex(SHA256_HEX, 'must be 64 lowercase hex chars');

export const TIERS = ['green', 'yellow', 'red'] as const;
export type Tier = (typeof TIERS)[number];

/** Two independent chains, each with its own writer and key. */
export const ChainSchema = z.enum(['brain', 'vault']);
export type Chain = z.infer<typeof ChainSchema>;

export const ToolKindSchema = z.enum([
  'read',
  'connector-read',
  'write',
  'exec',
  'network',
  'money',
  'account',
  'login',
  'irreversible',
  'vault',
  'meta',
]);
export type ToolKind = z.infer<typeof ToolKindSchema>;

export const AuditPhaseSchema = z.enum(['pre', 'approval', 'post', 'control']);
export type AuditPhase = z.infer<typeof AuditPhaseSchema>;

export const AuditDecisionSchema = z
  .object({
    tier: z.enum(TIERS),
    action: z.enum(['allow', 'ask', 'deny', 'executed', 'failed']),
    source: z.string(),
    reason: z.string(),
  })
  .strict();
export type AuditDecision = z.infer<typeof AuditDecisionSchema>;

export const AuditResultSchema = z
  .object({
    status: z.enum(['ok', 'error', 'denied', 'timeout', 'crashed']),
    duration_ms: z.number().int().nonnegative(),
    output_digest: z.string().optional(),
    spend_settled: z.string().optional(),
  })
  .strict();

const AuditCoreObject = z
  .object({
    v: z.literal(AUDIT_SCHEMA_VERSION),
    seq: z.number().int().nonnegative(),
    chain: ChainSchema,
    call_id: z.string(),
    session_id: z.string(),
    // SELF-DECLARED by the producer: recorded, never trusted for authorization.
    agent: z
      .object({
        name: z.string(),
        kind: z.enum(['main', 'subagent', 'vault']),
        parent: z.string().optional(),
      })
      .strict(),
    // STAMPED by the writer from the channel the draft arrived on, never self-declared.
    producer: z.enum(['agent-pipe', 'vault']),
    ts_unix_ms: z.number().int().nonnegative(),
    boot_id: z.string(),
    host_id: z.string(),
    phase: AuditPhaseSchema,
    tool: z.string().optional(),
    tool_kind: ToolKindSchema.optional(),
    // Tool arguments pre-serialized to one canonical string.
    args_canonical: z.string().optional(),
    redactions: z.array(z.string()).optional(),
    decision: AuditDecisionSchema.optional(),
    // Cross-chain join key: related records on different chains share one action_hash.
    action_hash: Sha256Hex.optional(),
    recap_hash: z.string().optional(),
    vault_receipt_digest: z.string().optional(),
    nonce: z.string().optional(),
    result: AuditResultSchema.optional(),
    prev_hash: Sha256Hex,
    writer_key_id: z.string(),
  })
  .strict();

const VAULT_ONLY_FIELDS = ['nonce', 'recap_hash', 'vault_receipt_digest'] as const;

// Example of a record-level invariant enforced at seal time: fields that are secret to the
// isolated 'vault' writer may never appear on the other chain.
function enforceVaultOnlyFields(data: z.infer<typeof AuditCoreObject>, ctx: z.RefinementCtx): void {
  if (data.chain === 'vault') return;
  for (const field of VAULT_ONLY_FIELDS) {
    if (data[field] !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field],
        message: `${field} may only appear on the vault chain`,
      });
    }
  }
}

export const AuditCoreSchema = AuditCoreObject.superRefine(enforceVaultOnlyFields);
export type AuditCore = z.infer<typeof AuditCoreSchema>;

export const SealedAuditEntrySchema = AuditCoreObject.extend({
  entry_hash: Sha256Hex,
  // HMAC-SHA256 as the seal emits it: 64 lowercase hex chars (the verifier accepts nothing else).
  entry_hmac: Sha256Hex,
})
  .strict()
  .superRefine(enforceVaultOnlyFields);
export type SealedAuditEntry = z.infer<typeof SealedAuditEntrySchema>;
