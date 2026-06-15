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
 * Covered labels are the cheap-to-construct LAYER-TOKEN-EMBEDDING stores
 * (l2-context-gate, l3-policies, l3-commitments) plus audit-log. The remaining
 * decryptable labels are inventoried + presence-guarded in
 * hkdf-label-classification.json + the frozen-surfaces guard.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { ContextGatePolicyStore } from "../../src/l2-operational/context-gate.js";
import { PolicyStore as DisclosurePolicyStore } from "../../src/l3-disclosure/policies.js";
import { CommitmentStore } from "../../src/l3-disclosure/commitments.js";
import {
  FIXTURE_MASTER_KEY,
  FIXTURE_STORES,
} from "../fixtures/at-rest/fixture-stores.js";

const FIXTURE_ROOT = fileURLToPath(new URL("../fixtures/at-rest/", import.meta.url));

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
};

describe("at-rest decrypt fixtures (pre-change ciphertext must still read)", () => {
  it("the fixture set covers the layer-token-embedding rename-trap labels", () => {
    const labels = FIXTURE_STORES.map((s) => s.label);
    for (const trap of ["l2-context-gate", "l3-policies", "l3-commitments"]) {
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
