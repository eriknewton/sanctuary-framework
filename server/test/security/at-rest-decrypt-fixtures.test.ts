/**
 * Phase-0 at-rest decrypt fixtures — the byte-level rename safety net.
 *
 * For each decryptable store in the fixture registry, a COMMITTED encrypted
 * fixture was generated on pre-change origin/main (scripts/gen-at-rest-fixtures.ts)
 * from deterministic toy data under a fixed synthetic master key. This test
 * stages each fixture into a temp fortress and reads it back through the store's
 * REAL read path, asserting the toy payload survives byte-for-byte.
 *
 * What this PROVES that `npm test` alone does not: a rename/reorg that silently
 * changed an HKDF domain-separation label (e.g. `s/l2/operational/` touching the
 * `l2-context-gate` info string) or the on-disk storage encoder would change the
 * derived key (or the path) and make this PRE-CHANGE ciphertext undecryptable —
 * the read would return nothing and the test reds. Fresh-install unit tests
 * cannot catch this because they encrypt AND decrypt under the new code. The
 * fixture is old ciphertext the new code must still read. (Scoping §7,
 * "old-fixture decrypt/read tests, CREATED ON CURRENT main FIRST"; risk 2.)
 *
 * The READ+assert logic lives here (it uses `expect`); the WRITE closures live
 * in the vitest-free fixture-stores module so the generator can import them.
 *
 * Covered labels are the SELECTED HIGHEST-RISK LAYER-TOKEN-EMBEDDING decryptable
 * stores (labels whose HKDF info string carries an `lN` token): l2-context-gate,
 * l3-policies, l3-commitments, l4-reputation, l2-honeypot-trap-v1. These are a
 * REPRESENTATIVE backstop, not exhaustive: other layer-token-embedding
 * decryptable stores (e.g. l2-sentinel-finding-v1, l2-approval-aggregator-v1)
 * remain `fixture:false` in hkdf-label-classification.json and are covered by the
 * frozen-surfaces label-presence guard instead. That deferred set is NOT silent —
 * it is enumerated and tracked by the explicit DEFERRED-COVERAGE guard below
 * (`DEFERRED_LAYER_TOKEN_FIXTURES`), which reds if a new layer-token decryptable
 * store is added without either a real fixture or an entry in the deferred list.
 * (The rename leaves HKDF labels byte-unchanged, so the fixtures are a backstop;
 * a representative set + an explicit deferred list is honest and sufficient.)
 * Labels with no layer token carry no rename risk and are inventoried +
 * presence-guarded in hkdf-label-classification.json + the frozen-surfaces guard.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { ContextGatePolicyStore } from "../../src/operational/context-gate.js";
import { PolicyStore as DisclosurePolicyStore } from "../../src/disclosure/policies.js";
import { CommitmentStore } from "../../src/disclosure/commitments.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import { TrapStore } from "../../src/honeypot/trap-store.js";
import {
  FIXTURE_MASTER_KEY,
  FIXTURE_FORTRESS_ID,
  FIXTURE_STORES,
} from "../fixtures/at-rest/fixture-stores.js";

const FIXTURE_ROOT = fileURLToPath(new URL("../fixtures/at-rest/", import.meta.url));

/**
 * A label embeds a layer token when an `l1`/`l2`/`l3`/`l4` segment appears
 * delimited by `-`, `_`, `.`, or a string boundary. These are the rename-critical
 * labels: an `s/l2/operational/` reorg of the source could silently change the
 * HKDF info string and make pre-change ciphertext undecryptable. (Shared with the
 * deferred-coverage guard so "what counts as a rename trap" has one definition.)
 */
const LAYER_TOKEN_RE = /(^|[-_.])l[1-4]([-_.]|$)/;

/**
 * The SELECTED highest-risk layer-token labels that get a real at-rest fixture in
 * this file. Representative, not exhaustive (see DEFERRED_LAYER_TOKEN_FIXTURES).
 * Keep in sync with the `fixture: true` rows in hkdf-label-classification.json —
 * the guards below assert that correspondence in both directions.
 */
const SELECTED_LAYER_TOKEN_FIXTURES = [
  "l2-context-gate",
  "l3-policies",
  "l3-commitments",
  "l4-reputation",
  "l2-honeypot-trap-v1",
] as const;

/**
 * DEFERRED COVERAGE (codex-backstop finding on #571): layer-token-embedding
 * decryptable stores that are KNOWINGLY left `fixture:false` for now and covered
 * by the frozen-surfaces label-presence guard instead of a byte-level at-rest
 * fixture. This makes the gap explicit and tracked rather than silent. The guard
 * test below asserts this list is EXACTLY the set of layer-token decryptable-store
 * labels marked `fixture:false` in the classification — so adding a new such store
 * (or flipping one's fixture flag) without either building a fixture or updating
 * this list reds. To clear an item: build a fixture (write closure + reader, flip
 * the JSON to fixture:true, add it to SELECTED_LAYER_TOKEN_FIXTURES) and delete it
 * here.
 */
const DEFERRED_LAYER_TOKEN_FIXTURES = [
  "l2-privacy-policies-v1",
  "l2-privacy-placeholders",
  "l2-sentinel-finding-v1",
  "l2-anomaly-classifier-state-v1",
  "l2-auto-trigger-rules-v1",
  "l2-recognition-hosted-did-web-v1",
  "l2-query-anonymity-tier-b-v1",
  "l2-approval-aggregator-v1",
  "l2-approval-aggregator-payload-v1",
  "l2-english-policy-activation-v1",
] as const;

/**
 * Read each fixture back through its store and assert the toy payload. Keyed by
 * the same label the write closures use. Throws (via `expect`) if the payload
 * does not survive — which is exactly the wrong-key / changed-label signal.
 */
const READERS: Record<
  string,
  (
    storage: StorageBackend,
    masterKey: Uint8Array,
    fortress: string,
  ) => Promise<void>
> = {
  "l2-context-gate": async (storage, masterKey) => {
    const store = new ContextGatePolicyStore(storage, masterKey);
    const policies = await store.list();
    expect(policies.length).toBe(1);
    expect(policies[0]!.policy_name).toBe("fixture-context-policy");
    expect(policies[0]!.default_action).toBe("redact");
    expect(policies[0]!.identity_id).toBe("fixture-identity");
    expect(policies[0]!.rules[0]!.redact).toEqual(["secret_*"]);
  },
  "l3-policies": async (storage, masterKey) => {
    const store = new DisclosurePolicyStore(storage, masterKey);
    const policies = await store.list();
    expect(policies.length).toBe(1);
    expect(policies[0]!.policy_name).toBe("fixture-disclosure-policy");
    expect(policies[0]!.default_action).toBe("withhold");
    expect(policies[0]!.rules[0]!.withhold).toEqual(["salary"]);
  },
  "l3-commitments": async (storage, masterKey, fortress) => {
    // CommitmentStore reads by exact id (no list()). The committed fixture's
    // .enc filename IS the commitment id (cmt-...; all chars are storage-safe,
    // so no escape decoding is needed). Recover it from the staged dir.
    const nsDir = join(fortress, "_commitments");
    const encFile = readdirSync(nsDir).find((f) => f.endsWith(".enc"));
    expect(encFile, "commitment .enc fixture present").toBeDefined();
    const id = encFile!.slice(0, -".enc".length);
    const store = new CommitmentStore(storage, masterKey);
    const stored = await store.get(id);
    expect(stored, "commitment must decrypt under the fixture key").not.toBeNull();
    expect(stored!.value).toBe("fixture-secret-value");
    expect(stored!.committed_at).toBe("2026-01-01T00:00:00.000Z");
  },
  "l4-reputation": async (storage, masterKey) => {
    // loadAllForTierScoring returns the FULL decrypted StoredAttestations, so we
    // can assert the controlled payload survived. (The attestation_id + timestamp
    // are wall-clock at write time and not asserted; the fixture key, context,
    // outcome, counterparty + metrics are.) Under a wrong key the paginated
    // loader swallows the decrypt failure and yields nothing, so length !== 1
    // and this rejects — the wrong-key signal.
    const store = new ReputationStore(storage, masterKey);
    const all = await store.loadAllForTierScoring();
    expect(all.length).toBe(1);
    const data = all[0]!.attestation.data;
    expect(data.context).toBe("fixture-context");
    expect(data.outcome_type).toBe("transaction");
    expect(data.outcome_result).toBe("completed");
    expect(data.counterparty_did).toBe("did:key:fixture-counterparty");
    expect(data.metrics.score).toBe(42);
    expect(data.sovereignty_tier).toBe("self-attested");
  },
  "l2-honeypot-trap-v1": async (storage, masterKey) => {
    // TrapStore.loadAll rehydrates every persisted, AAD-bound TrapSpec. Under a
    // wrong key (or a changed HKDF label) decode() fails AEAD and drops the
    // record, so loadAll returns [] and length !== 1 rejects — the rename signal.
    const store = new TrapStore({
      storage,
      masterKey,
      fortressId: FIXTURE_FORTRESS_ID,
    });
    const specs = await store.loadAll();
    expect(specs.length).toBe(1);
    expect(specs[0]!.trap_id).toBe("fixture-trap");
    expect(specs[0]!.trap_class).toBe("http_endpoint");
    expect(specs[0]!.trigger.kind).toBe("http_endpoint");
    expect(specs[0]!.english_text).toBe("fixture honeypot trap");
  },
};

describe("at-rest decrypt fixtures (pre-change ciphertext must still read)", () => {
  it("the fixture set covers the selected highest-risk layer-token rename-trap labels", () => {
    const labels = FIXTURE_STORES.map((s) => s.label);
    for (const trap of SELECTED_LAYER_TOKEN_FIXTURES) {
      expect(labels, `missing fixture for rename-trap label ${trap}`).toContain(
        trap,
      );
    }
  });

  it("every fixture store has a matching reader", () => {
    for (const spec of FIXTURE_STORES) {
      expect(READERS[spec.label], `no reader for ${spec.label}`).toBeTypeOf(
        "function",
      );
    }
  });

  // HONESTY GUARD (the codex-backstop finding on #569): the classification
  // artifact marked some labels `fixture: true` that had no registered fixture,
  // so the JSON over-claimed coverage and nothing caught it. This ties the claim
  // to the artifact: every `fixture: true` decryptable-store label MUST have a
  // real entry in FIXTURE_STORES *and* a reader. A future flip of a label to
  // `fixture: true` without building the fixture now reds here.
  it("every `fixture: true` decryptable-store label has a real registered fixture + reader", () => {
    interface LabelEntry {
      label: string;
      class: string;
      fixture: boolean;
    }
    const classificationPath = join(
      FIXTURE_ROOT,
      "hkdf-label-classification.json",
    );
    const classification = JSON.parse(
      readFileSync(classificationPath, "utf-8"),
    ) as { labels: LabelEntry[] };

    const registered = new Set(FIXTURE_STORES.map((s) => s.label));
    const claimsFixture = classification.labels.filter(
      (l) => l.fixture === true,
    );

    // Defensive: the artifact must still mark *some* label as having a fixture,
    // so a bulk edit flipping every entry to false cannot vacuously pass.
    expect(
      claimsFixture.length,
      "no label in hkdf-label-classification.json is marked fixture:true — " +
        "the rename-trap labels must keep real fixtures",
    ).toBeGreaterThanOrEqual(5);

    for (const entry of claimsFixture) {
      expect(
        entry.class,
        `${entry.label} is fixture:true but not a decryptable-store class`,
      ).toBe("decryptable-store");
      expect(
        registered.has(entry.label),
        `${entry.label} is marked fixture:true in hkdf-label-classification.json ` +
          "but has NO entry in FIXTURE_STORES. Either build the fixture (add a " +
          "write closure + reader) or set fixture:false with a deferred note.",
      ).toBe(true);
      expect(
        READERS[entry.label],
        `${entry.label} is fixture:true but has no reader in this test`,
      ).toBeTypeOf("function");
    }
  });

  // DEFERRED-COVERAGE GUARD (codex-backstop finding on #571): the fixture set is
  // deliberately a representative subset, NOT every layer-token decryptable store.
  // To keep that honest, the labels we KNOWINGLY defer are enumerated in
  // DEFERRED_LAYER_TOKEN_FIXTURES, and this test asserts that list is EXACTLY the
  // set of layer-token-embedding decryptable-store labels currently `fixture:false`
  // in the classification. Net effect: adding a new layer-token decryptable store
  // (or flipping an existing one's fixture flag) forces a deliberate choice — build
  // a real fixture or add it to the deferred list — instead of silently widening
  // the coverage gap.
  it("the deferred-coverage list exactly matches the fixture:false layer-token decryptable stores", () => {
    interface LabelEntry {
      label: string;
      class: string;
      fixture: boolean;
    }
    const classification = JSON.parse(
      readFileSync(join(FIXTURE_ROOT, "hkdf-label-classification.json"), "utf-8"),
    ) as { labels: LabelEntry[] };

    const actualDeferred = classification.labels
      .filter(
        (l) =>
          l.class === "decryptable-store" &&
          l.fixture !== true &&
          LAYER_TOKEN_RE.test(l.label),
      )
      .map((l) => l.label)
      .sort();

    const declaredDeferred = [...DEFERRED_LAYER_TOKEN_FIXTURES].sort();

    // Equality both ways gives a precise diff message on failure.
    const missingFromList = actualDeferred.filter(
      (l) => !declaredDeferred.includes(l),
    );
    const staleInList = declaredDeferred.filter(
      (l) => !actualDeferred.includes(l),
    );
    expect(
      missingFromList,
      "new layer-token decryptable store(s) are fixture:false but NOT tracked in " +
        "DEFERRED_LAYER_TOKEN_FIXTURES — add a real at-rest fixture, or add the " +
        "label to the deferred list to acknowledge the gap",
    ).toEqual([]);
    expect(
      staleInList,
      "DEFERRED_LAYER_TOKEN_FIXTURES names label(s) that are no longer " +
        "fixture:false layer-token decryptable stores — remove them (likely now " +
        "covered by a real fixture, or the label/class changed)",
    ).toEqual([]);
    expect(actualDeferred).toEqual(declaredDeferred);
  });

  // The selected (fixtured) and deferred sets must be disjoint and together cover
  // EVERY layer-token decryptable store — so no such store can fall through both.
  it("selected + deferred together partition all layer-token decryptable stores", () => {
    interface LabelEntry {
      label: string;
      class: string;
    }
    const classification = JSON.parse(
      readFileSync(join(FIXTURE_ROOT, "hkdf-label-classification.json"), "utf-8"),
    ) as { labels: LabelEntry[] };

    const allLayerTokenDecryptable = classification.labels
      .filter(
        (l) => l.class === "decryptable-store" && LAYER_TOKEN_RE.test(l.label),
      )
      .map((l) => l.label)
      .sort();

    const union = [
      ...SELECTED_LAYER_TOKEN_FIXTURES,
      ...DEFERRED_LAYER_TOKEN_FIXTURES,
    ].sort();

    // Disjoint: a label cannot be both fixtured and deferred.
    const overlap = SELECTED_LAYER_TOKEN_FIXTURES.filter((l) =>
      (DEFERRED_LAYER_TOKEN_FIXTURES as readonly string[]).includes(l),
    );
    expect(overlap, "a label is in BOTH selected and deferred lists").toEqual([]);

    // Exhaustive: every layer-token decryptable store is accounted for in one set.
    expect(
      union,
      "a layer-token decryptable store is in neither the selected nor the " +
        "deferred list — classify it into one",
    ).toEqual(allLayerTokenDecryptable);
  });

  for (const spec of FIXTURE_STORES) {
    describe(`label ${spec.label}`, () => {
      let fortress = "";

      afterAll(() => {
        if (fortress) rmSync(fortress, { recursive: true, force: true });
      });

      beforeAll(() => {
        const fixtureDir = join(FIXTURE_ROOT, spec.label);
        if (!existsSync(fixtureDir)) {
          throw new Error(
            `Missing committed fixture dir for ${spec.label} at ${fixtureDir}. ` +
              "Generate it on origin/main: npm run gen-at-rest-fixtures",
          );
        }
        // Stage the fixture into a fresh temp fortress so the store reads real
        // on-disk ciphertext (never the repo working tree).
        fortress = mkdtempSync(join(tmpdir(), `sanctuary-fixread-${spec.label}-`));
        cpSync(fixtureDir, fortress, { recursive: true });
      });

      it("the committed fixture contains at least one .enc ciphertext file", () => {
        const nsDir = join(fortress, spec.namespace);
        expect(existsSync(nsDir), `namespace dir ${spec.namespace} present`).toBe(
          true,
        );
        const encFiles = readdirSync(nsDir).filter((f) => f.endsWith(".enc"));
        expect(encFiles.length).toBeGreaterThanOrEqual(1);
      });

      it("current code decrypts the pre-change fixture and the toy payload survives", async () => {
        const storage = new FilesystemStorage(fortress);
        // If the HKDF label or the storage encoder changed, this throws or the
        // payload assertions fail — the rename-safety signal.
        await READERS[spec.label]!(storage, FIXTURE_MASTER_KEY, fortress);
      });

      it("a WRONG master key does NOT recover the toy payload (proves it is real ciphertext)", async () => {
        const storage = new FilesystemStorage(fortress);
        const wrongKey = new Uint8Array(32).fill(0x99);
        // Stores swallow decrypt failures and surface empty/absent results, so
        // the payload assertion inside the reader fails under the wrong key.
        // Either path (throw or failed assertion) rejects — guarding against a
        // fixture accidentally committed as plaintext.
        await expect(
          READERS[spec.label]!(storage, wrongKey, fortress),
        ).rejects.toThrow();
      });
    });
  }
});
