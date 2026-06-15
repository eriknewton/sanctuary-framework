/**
 * Phase-0 at-rest decrypt-fixture store registry (single source of truth).
 *
 * Shared by the fixture GENERATOR (scripts/gen-at-rest-fixtures.ts, run once on
 * pre-change origin/main) and the read-back TEST
 * (test/security/at-rest-decrypt-fixtures.test.ts). This module carries ONLY the
 * synthetic key + per-store WRITE closures + namespace metadata, and is
 * deliberately FREE of any `vitest` import so the generator (a plain vite-node
 * script) can import it without pulling in the vitest runner. The READ + assert
 * logic lives in the test file (it uses `expect`).
 *
 * Coverage in this wave: the cheap-to-construct, single-namespace
 * LAYER-TOKEN-EMBEDDING decryptable stores, which are the exact rename trap
 * (their HKDF label embeds an `lN` token): l2-context-gate, l3-policies,
 * l3-commitments. The remaining decryptable stores are inventoried +
 * presence-guarded in hkdf-label-classification.json + the frozen-surfaces
 * guard, and can get fixtures in a follow-up via this same harness. They are
 * deferred from THIS wave for one of two reasons: (a) the encrypted Operational
 * audit log (`audit-log`) chains across multiple namespaces (entries + a `_meta`
 * head anchor), so a single-namespace fixture trips its integrity check — it
 * needs a multi-namespace fixture; (b) others (l4-reputation, l2-honeypot-trap-v1,
 * the versioned l2-* / sdw-* stores) need richer writer inputs (a full
 * StoredIdentity, a TrapTrigger union, etc.).
 *
 * PRIVACY: the master key is a FIXED SYNTHETIC constant and every payload is
 * deterministic toy data. No operator data / real keys ever touch a fixture
 * (scoping §7 fixture-generation rule; invariants 2 + 6).
 */

import type { StorageBackend } from "../../../src/storage/interface.js";
import { ContextGatePolicyStore } from "../../../src/l2-operational/context-gate.js";
import { PolicyStore as DisclosurePolicyStore } from "../../../src/l3-disclosure/policies.js";
import { CommitmentStore } from "../../../src/l3-disclosure/commitments.js";

/**
 * Fixed synthetic 32-byte master key. NOT derived from any passphrase; a
 * constant so the committed ciphertext is reproducibly decryptable. Value is the
 * repeating byte 0x2a (ASCII "*") — obviously a test constant, never a real key.
 */
export const FIXTURE_MASTER_KEY: Uint8Array = new Uint8Array(32).fill(0x2a);

export interface FixtureStoreSpec {
  /** HKDF label this fixture exercises (matches hkdf-label-classification.json). */
  readonly label: string;
  /** The storage namespace the store persists under (the on-disk dir name). */
  readonly namespace: string;
  /** Write the toy payload through the store's real persist path. */
  readonly write: (
    storage: StorageBackend,
    masterKey: Uint8Array,
  ) => Promise<void>;
}

export const FIXTURE_STORES: readonly FixtureStoreSpec[] = [
  {
    label: "l2-context-gate",
    namespace: "_context_gate_policies",
    write: async (storage, masterKey) => {
      const store = new ContextGatePolicyStore(storage, masterKey);
      await store.create(
        "fixture-context-policy",
        [
          {
            provider: "*",
            allow: ["public_field"],
            redact: ["secret_*"],
            hash: [],
            summarize: [],
          },
        ],
        "redact",
        "fixture-identity",
      );
    },
  },
  {
    label: "l3-policies",
    namespace: "_policies",
    write: async (storage, masterKey) => {
      const store = new DisclosurePolicyStore(storage, masterKey);
      await store.create(
        "fixture-disclosure-policy",
        [
          {
            context: "negotiation",
            disclose: ["company"],
            withhold: ["salary"],
            proof_required: [],
          },
        ],
        "withhold",
        "fixture-identity",
      );
    },
  },
  {
    label: "l3-commitments",
    namespace: "_commitments",
    write: async (storage, masterKey) => {
      const store = new CommitmentStore(storage, masterKey);
      await store.store(
        {
          commitment: "Zml4dHVyZS1jb21taXRtZW50",
          blinding_factor: "Zml4dHVyZS1ibGluZGluZw",
          committed_at: "2026-01-01T00:00:00.000Z",
        },
        "fixture-secret-value",
      );
    },
  },
];
