/**
 * Wired-consumer test: the local-intelligence load-integrity checkpoint runs
 * at boot on EVERY approval channel.
 *
 * The checkpoint is `SubstrateSelector.load()`. It classifies the persisted
 * `_intelligence` record as armed, absent (the honest legacy-unarmed default),
 * or integrity-invalid, and emits the `intelligence_load_integrity` audit row
 * for what it found. The selector used to be constructed only inside the
 * composition root's `dashboard` approval-channel branch, so a fortress on the
 * default `stderr` channel never ran it: a tampered armed record produced no
 * refusal and no audit row, and the boot reported a healthy start.
 *
 * The approval channel an operator picked says nothing about whether their
 * armed model state is intact, so these tests drive the REAL composition root
 * (`createSanctuaryServer`) on the default channel rather than the selector in
 * isolation. A unit test of `load()` passes either way; only the boot graph
 * shows whether anything calls it.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { createSanctuaryServer } from "../../src/index.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { canonicalJson } from "../../src/v1/operator-signed.js";
import {
  INTELLIGENCE_CONFIG_RESET_VERB,
  INTELLIGENCE_NAMESPACE,
  IntelligenceConfigUnreadableError,
  LocalIntegrityStateLoadError,
  SUBSTRATE_CONFIG_KEY,
  describeIntelligenceBootFailure,
} from "../../src/intelligence/policy-store.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import {
  IMMUNE_MODEL_LOAD_SURFACES,
  computeModelManifestV2BodyDigest,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
} from "../../src/intelligence/model-manifest-v2.js";
import { SURFACES, type Surface } from "../../src/intelligence/types.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { createTempHome } from "../helpers/temp-fortress.js";

const PASSPHRASE = "r2-boot-integrity-checkpoint-passphrase";

/**
 * A key that is NOT the pinned model-catalog root. An armed record signed with
 * it is exactly the shape the checkpoint must refuse: structurally complete,
 * decrypting cleanly under the fortress master key, and asserting an armed
 * posture no release signer ever attested.
 */
const FOREIGN_PRIVATE_KEY = new Uint8Array(32).fill(23);

const MODEL: ModelManifestModelV2 = {
  model_id: "qwen2.5-1.5b",
  model_name: "Qwen2.5 1.5B",
  model_version: "2.5",
  provider: "Alibaba Cloud",
  runtime: "ollama",
  ollama_identity: {
    registry: "registry.ollama.ai",
    namespace: "library",
    model: "qwen2.5",
    tag: "1.5b",
    // 64 = length in hex characters of a sha256 digest (32 bytes, 2 chars/byte).
    ollama_manifest_sha256: "1".repeat(64),
  },
  params_b: 1.5,
  license: {
    identifier: "Apache-2.0",
    name: "Apache License 2.0",
    url: "https://www.apache.org/licenses/LICENSE-2.0",
    osi_approved: true,
    redistribution: "permitted",
  },
  open_weights: true,
  open_source: false,
};

function manifestBody(): ModelManifestBodyV2 {
  const defaults = Object.fromEntries(
    SURFACES.map((surface) => [
      surface,
      surface === "gate-explanation" ? null : MODEL.model_id,
    ]),
  ) as Record<Surface, string | null>;
  return {
    schema_version: 2,
    manifest_version: 9,
    models: { [MODEL.model_id]: structuredClone(MODEL) },
    tiers: {
      baseline: [MODEL.model_id],
      mid: [MODEL.model_id],
      pro: [MODEL.model_id],
    },
    surface_defaults: {
      baseline: structuredClone(defaults),
      mid: structuredClone(defaults),
      pro: structuredClone(defaults),
    },
  };
}

function armedConfigSignedByAForeignKey(): Record<string, unknown> {
  const body = manifestBody();
  const bindings: Record<string, unknown> = {};
  for (const surface of SURFACES) {
    if (surface === "gate-explanation") continue;
    bindings[surface] = {
      model_id: MODEL.model_id,
      runtime_tag: "qwen2.5:1.5b",
      ollama_identity: structuredClone(MODEL.ollama_identity),
      assurance: IMMUNE_MODEL_LOAD_SURFACES.includes(
        surface as (typeof IMMUNE_MODEL_LOAD_SURFACES)[number],
      )
        ? "immune"
        : "light",
      manifest_version: body.manifest_version,
    };
  }
  // Must match MODEL_MANIFEST_V2_DOMAIN + its newline delimiter in
  // intelligence/model-manifest-v2.ts; the signature is valid over these bytes
  // and still fails, because the verifying key is pinned, not supplied.
  const signature = toBase64url(
    ed25519.sign(
      new TextEncoder().encode(
        `sanctuary.model-manifest.v2\n${canonicalJson(body)}`,
      ),
      FOREIGN_PRIVATE_KEY,
    ),
  );
  return {
    version: 2,
    perSurface: Object.fromEntries(SURFACES.map((s) => [s, "local"])),
    fallback: Object.fromEntries(SURFACES.map((s) => [s, "deny"])),
    customLocalModelTags: Object.fromEntries(
      Object.keys(bindings).map((s) => [s, "qwen2.5:1.5b"]),
    ),
    localIntegrityState: {
      state: "armed",
      schema_version: 2,
      manifest_version_floor: body.manifest_version,
      signed_manifest: { body, signature },
      signed_body_sha256: computeModelManifestV2BodyDigest(body),
      ollama_models_root: "/var/lib/ollama/models",
      bindings,
      committed_at: "2026-09-01T12:00:00.000Z",
    },
  };
}

/**
 * Write the `_intelligence` record straight into the fortress, bypassing every
 * writer-side check, the way an on-disk tamper would.
 *
 * Must match HKDF_INFO in intelligence/policy-store.ts. Failure mode if that
 * label drifts: the record simply fails to decrypt and the loader classifies
 * it as corrupt, so this test would exercise the wrong branch while still
 * looking like it exercised something.
 */
async function plantIntelligenceRecord(
  storage: StorageBackend,
  masterKey: Uint8Array,
  record: unknown,
): Promise<void> {
  const key = derivePurposeKey(masterKey, "intelligence-substrate-config");
  const encrypted = encrypt(stringToBytes(JSON.stringify(record)), key);
  await storage.write(
    INTELLIGENCE_NAMESPACE,
    SUBSTRATE_CONFIG_KEY,
    stringToBytes(JSON.stringify(encrypted)),
  );
}

let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
let savedPassphrase: string | undefined;

beforeEach(async () => {
  savedPassphrase = process.env.SANCTUARY_PASSPHRASE;
  delete process.env.SANCTUARY_PASSPHRASE;
  fortressHome = await createTempHome("sanctuary-r2-boot-integrity");
});

afterEach(async () => {
  if (savedPassphrase !== undefined) {
    process.env.SANCTUARY_PASSPHRASE = savedPassphrase;
  } else {
    delete process.env.SANCTUARY_PASSPHRASE;
  }
  await fortressHome.cleanup();
});

describe("local-intelligence load integrity is checked on the default approval channel", () => {
  it("reaches the selector at boot and audits the load on a stderr-channel fortress", async () => {
    const storage = new MemoryStorage();
    const booted = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });

    // The default channel, not the dashboard: this is the configuration under
    // which the checkpoint used to be skipped entirely.
    expect(booted.policy.approval_channel.type).toBe("stderr");

    const audited = await booted.auditLog.query({
      operation_type: INTEL_OPS.CONFIG_LOADED,
      limit: 20,
    });
    expect(audited.entries.length).toBeGreaterThan(0);
    // Absent state is the honest legacy-unarmed default, and it is still a
    // checkpoint result rather than a skipped checkpoint.
    expect(audited.entries[0]!.details?.was_default).toBe(true);
  });

  it("refuses the boot and audits the refusal when the armed record is tampered", async () => {
    const storage = new MemoryStorage();
    const first = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });
    const masterKey = first.masterKey;

    await plantIntelligenceRecord(
      storage,
      masterKey,
      armedConfigSignedByAForeignKey(),
    );

    await expect(
      createSanctuaryServer({ storage, passphrase: PASSPHRASE }),
    ).rejects.toThrow(/integrity/i);

    const auditLog = new AuditLog(storage, masterKey);
    const audited = await auditLog.query({
      operation_type: INTEL_OPS.LOAD_INTEGRITY,
      limit: 20,
    });
    const refusals = audited.entries.filter(
      (entry) => entry.details?.generation_refused === true,
    );
    expect(refusals.length).toBeGreaterThan(0);
    expect(refusals[0]!.result).toBe("failure");
    expect(refusals[0]!.details?.stage).toBe("state_validation");
  });

  it("PLANTED DIVERGENCE: an absent record still boots, so the refusal is about tampering", async () => {
    const storage = new MemoryStorage();
    await expect(
      createSanctuaryServer({ storage, passphrase: PASSPHRASE }),
    ).resolves.toBeDefined();
  });
});

/**
 * A record that EXISTS and cannot be read is indeterminate, and indeterminate
 * is not absent.
 *
 * The loader used to return a default config for a `corrupt` or
 * `version-too-new` record and the selector fell through to it, so a fortress
 * whose armed record had been damaged, or written by a newer build, started
 * clean and audited `was_default: true`. Absence claims nobody armed this
 * fortress; unreadability cannot claim that, because the evidence either way
 * is exactly what is missing. Both now refuse, and both name the one command
 * that clears the record.
 */
describe("an unreadable local-intelligence record refuses the boot, and names the remedy", () => {
  it("refuses a corrupt record and audits the classification", async () => {
    const storage = new MemoryStorage();
    const first = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });
    const masterKey = first.masterKey;

    // Ciphertext this fortress's key cannot open: the shape an on-disk bit-rot
    // or a partial write leaves behind. It decrypts to nothing, so the loader
    // can say only that a record is there.
    await storage.write(
      INTELLIGENCE_NAMESPACE,
      SUBSTRATE_CONFIG_KEY,
      stringToBytes(JSON.stringify({ v: 1, alg: "xchacha20poly1305", n: "AAAA", ct: "AAAA" })),
    );

    await expect(
      createSanctuaryServer({ storage, passphrase: PASSPHRASE }),
    ).rejects.toThrow(new RegExp(INTELLIGENCE_CONFIG_RESET_VERB));

    const auditLog = new AuditLog(storage, masterKey);
    const audited = await auditLog.query({
      operation_type: INTEL_OPS.LOAD_INTEGRITY,
      limit: 20,
    });
    const refusals = audited.entries.filter(
      (entry) => entry.details?.stage === "record_readability",
    );
    expect(refusals.length).toBeGreaterThan(0);
    expect(refusals[0]!.result).toBe("failure");
    expect(refusals[0]!.details?.classification).toBe("corrupt");
    expect(refusals[0]!.details?.generation_refused).toBe(true);
    expect(String(refusals[0]!.details?.remedy)).toContain(INTELLIGENCE_CONFIG_RESET_VERB);
  });

  it("refuses a record written by a newer build and audits its version", async () => {
    const storage = new MemoryStorage();
    const first = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });
    const masterKey = first.masterKey;

    // 99 = a schema version far past anything this build parses; the record
    // decrypts cleanly, so this exercises the version branch and not corrupt.
    await plantIntelligenceRecord(storage, masterKey, { version: 99 });

    await expect(
      createSanctuaryServer({ storage, passphrase: PASSPHRASE }),
    ).rejects.toThrow(new RegExp(INTELLIGENCE_CONFIG_RESET_VERB));

    const auditLog = new AuditLog(storage, masterKey);
    const audited = await auditLog.query({
      operation_type: INTEL_OPS.LOAD_INTEGRITY,
      limit: 20,
    });
    const refusals = audited.entries.filter(
      (entry) => entry.details?.stage === "record_readability",
    );
    expect(refusals.length).toBeGreaterThan(0);
    expect(refusals[0]!.details?.classification).toBe("version-too-new");
    expect(refusals[0]!.details?.persisted_version).toBe(99);
  });

  it("PLANTED DIVERGENCE: neither refusal is reported as an absent record", async () => {
    // The specific misreport this closes: `was_default: true` on a config-load
    // row asserts that nobody had armed this fortress. An unreadable record
    // must produce no such row at all, because the load did not complete.
    const storage = new MemoryStorage();
    const first = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });
    const masterKey = first.masterKey;
    const before = await new AuditLog(storage, masterKey).query({
      operation_type: INTEL_OPS.CONFIG_LOADED,
      limit: 50,
    });

    await plantIntelligenceRecord(storage, masterKey, { version: 99 });
    await expect(
      createSanctuaryServer({ storage, passphrase: PASSPHRASE }),
    ).rejects.toThrow();

    const after = await new AuditLog(storage, masterKey).query({
      operation_type: INTEL_OPS.CONFIG_LOADED,
      limit: 50,
    });
    expect(after.entries.length).toBe(before.entries.length);
  });
});

/**
 * The boot catch is an ALLOWLIST of degradable conditions, and that allowlist
 * is empty.
 *
 * The shape this replaced asked whether the error WAS a
 * `LocalIntegrityStateLoadError` and degraded otherwise, so an error class the
 * build did not recognize, or a tamper refusal wrapped by an intervening layer,
 * started a fortress with local intelligence quietly switched off. A denylist
 * has to recognize a danger in order to act; an allowlist has to recognize a
 * safety in order to relax, and only the second fails closed on the unknown.
 */
describe("an unclassifiable local-intelligence failure refuses startup", () => {
  it("names the unknown class and says startup refused rather than ran with it off", () => {
    class SomethingNobodyAnticipated extends Error {}
    const message = describeIntelligenceBootFailure(
      new SomethingNobodyAnticipated("selector wiring blew up"),
    );
    expect(message).toContain("does not");
    expect(message).toContain("classify");
    expect(message).toContain("refuses");
    expect(message).toContain("selector wiring blew up");
    // The unknown case must not borrow the integrity sentence: an operator who
    // is told the integrity check failed goes looking for tampering that did
    // not happen.
    expect(message).not.toContain("failed its boot integrity check");
  });

  it("distinguishes an unreadable record, and names the remedy verb", () => {
    const message = describeIntelligenceBootFailure(
      new IntelligenceConfigUnreadableError("corrupt"),
    );
    expect(message).toContain(INTELLIGENCE_CONFIG_RESET_VERB);
    expect(message).not.toContain("failed its boot integrity check");
  });

  it("distinguishes an IO condition from a tamper verdict, and still refuses", () => {
    const message = describeIntelligenceBootFailure(
      new LocalIntegrityStateLoadError("integrity_io_unavailable"),
    );
    expect(message).toContain("storage unavailable");
    expect(message).toContain("indeterminate");
    expect(message).not.toContain("failed its boot integrity check");
  });

  it("keeps the integrity sentence for an actual integrity verdict", () => {
    const message = describeIntelligenceBootFailure(
      new LocalIntegrityStateLoadError("integrity_state_invalid"),
    );
    expect(message).toContain("failed its boot integrity check");
  });

  it("STRUCTURAL: neither composition root has a degrade path out of that catch", () => {
    // A behavioral test cannot reach every unknown-error shape through the real
    // boot graph, and the property at stake is the ABSENCE of a branch. So this
    // reads the two catch blocks and asserts there is no path from a wiring
    // failure to a booted fortress. If a degrade is ever added deliberately, it
    // belongs in the classifier with a named condition, and this assertion is
    // what forces that conversation.
    const roots = ["index.ts", "dashboard-standalone.ts"] as const;
    for (const file of roots) {
      const source = readFileSync(
        fileURLToPath(new URL(`../../src/${file}`, import.meta.url)),
        "utf8",
      );
      const marker = source.indexOf("describeIntelligenceBootFailure(err)");
      expect(marker, `${file} must route its wiring failure through the shared classifier`)
        .toBeGreaterThan(-1);
      const block = source.slice(marker, marker + 400);
      expect(block, `${file} must rethrow`).toContain("throw err;");
      expect(block, `${file} must not degrade to a selector-less boot`)
        .not.toContain("intelligenceSelector = undefined");
    }
  });
});
