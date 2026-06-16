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
 * Coverage: every LAYER-TOKEN-EMBEDDING decryptable store whose HKDF label
 * embeds an `lN` token — l2-context-gate, l3-policies, l3-commitments,
 * l4-reputation, l2-honeypot-trap-v1 — i.e. the exact rename trap. The last
 * two need richer writer inputs (a full StoredIdentity to sign an attestation;
 * a TrapSpec trigger union) but are now real pre-change fixtures rather than
 * presence-only entries, because their labels carry an `lN`/`l2` token and are
 * the highest rename risk. The remaining decryptable stores are inventoried +
 * presence-guarded in hkdf-label-classification.json + the frozen-surfaces
 * guard, and can get fixtures in a follow-up via this same harness. The
 * encrypted Operational audit log (`audit-log`) is deliberately NOT in this set:
 * it chains across multiple namespaces (entries + a `_meta` head anchor), so a
 * single-namespace fixture trips its integrity check (it needs a multi-namespace
 * fixture), AND its label carries no layer token, so it is not rename-critical —
 * it is classified `fixture: false` with a deferred note in
 * hkdf-label-classification.json.
 *
 * PRIVACY: the master key is a FIXED SYNTHETIC constant and every payload is
 * deterministic toy data. No operator data / real keys ever touch a fixture
 * (scoping §7 fixture-generation rule; invariants 2 + 6).
 */

import type { StorageBackend } from "../../../src/storage/interface.js";
import { ContextGatePolicyStore } from "../../../src/operational/context-gate.js";
import { PolicyStore as DisclosurePolicyStore } from "../../../src/disclosure/policies.js";
import { CommitmentStore } from "../../../src/disclosure/commitments.js";
import { ReputationStore } from "../../../src/reputation/reputation-store.js";
import { TrapStore } from "../../../src/honeypot/trap-store.js";
import { createIdentity } from "../../../src/core/identity.js";

/**
 * Fixed fortress id used by stores that scope their HKDF salt / metadata to a
 * fortress (e.g. TrapStore). A constant keeps the produced ciphertext
 * reproducible across generator runs.
 */
export const FIXTURE_FORTRESS_ID = "fixture-fortress-0000";

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
  {
    // LAYER-TOKEN-EMBEDDING — the `l4` token sits inside the HKDF info string
    // (derivePurposeKey(master, "l4-reputation")). An `s/l4/reputation/` rename
    // of the constant would change the derived key and make this pre-change
    // ciphertext undecryptable. record() signs the attestation with a synthetic
    // identity (the fixture master key doubles as the identity-encryption key);
    // record() does NOT trip the custody floor (importBundle does — deliberately
    // avoided here so the fixture stays a single-store decrypt probe).
    label: "l4-reputation",
    namespace: "_reputation",
    write: async (storage, masterKey) => {
      const { storedIdentity } = createIdentity(
        "fixture-reputation-identity",
        masterKey,
        "passphrase",
      );
      const store = new ReputationStore(storage, masterKey);
      await store.record(
        "fixture-interaction",
        "did:key:fixture-counterparty",
        { type: "transaction", result: "completed", metrics: { score: 42 } },
        "fixture-context",
        storedIdentity,
        masterKey,
        undefined,
        "self-attested",
      );
    },
  },
  {
    // LAYER-TOKEN-EMBEDDING — the `l2` token sits inside the HKDF info string
    // (derivePurposeKey(master, "l2-honeypot-trap-v1")). The envelope is also
    // AAD-bound to the trap_id, so the read path must reproduce both the derived
    // key and the AAD. TrapStore takes an options object (storage/masterKey/
    // fortressId); the fixed FIXTURE_FORTRESS_ID keeps the ciphertext stable.
    label: "l2-honeypot-trap-v1",
    namespace: "_honeypot_traps",
    write: async (storage, masterKey) => {
      const store = new TrapStore({
        storage,
        masterKey,
        fortressId: FIXTURE_FORTRESS_ID,
      });
      await store.save({
        trap_id: "fixture-trap",
        trap_class: "http_endpoint",
        trigger: {
          kind: "http_endpoint",
          path_pattern: "/admin/secret",
          method: "GET",
          expected_caller_types: ["external"],
        },
        finding_severity: "alert",
        english_text: "fixture honeypot trap",
        explanation_paragraph: "deterministic fixture trap for the rename net",
        compiled_at: "2026-01-01T00:00:00.000Z",
      });
    },
  },
];
