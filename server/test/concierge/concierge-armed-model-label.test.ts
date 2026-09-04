/**
 * `sanctuary concierge status` names the ARMED model, not the default pick (R2-F3c).
 *
 * The label used to come from `localModelPicks`, a configuration default, so a
 * fortress armed to one model reported another. These tests drive the real
 * selector (and the real `ConciergeService.status()` that renders its handle)
 * over an armed record and over an unarmed one, and assert the label follows
 * the verified binding and says which of the two it is.
 */

import { describe, expect, it, vi } from "vitest";

import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import { IntelligenceConfigStore } from "../../src/intelligence/policy-store.js";
import { ARMED_DIGEST_PREFIX_CHARS } from "../../src/intelligence/provisioning.js";
import { ConciergeService } from "../../src/concierge/index.js";
import type { ConciergeContextReaderLike } from "../../src/concierge/concierge-service.js";
import { runLocalIntelligenceSetup } from "../../src/wrap/local-intelligence.js";
import {
  CATALOG_PUBLIC_KEY,
  FIXTURE_MANIFEST_DIGEST,
  FIXTURE_RUNTIME_TAG,
  armedCeremonyDeps,
} from "../intelligence/__fixtures__/armed-local-intelligence.js";

/** Ollama probe stub: the armed tag is present, so the surface reads healthy. */
const fetchImpl = (async () =>
  new Response(JSON.stringify({ models: [{ name: FIXTURE_RUNTIME_TAG }] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as typeof fetch;

async function buildSelector(
  armed: boolean,
  customLocalModelTags?: Record<string, string>,
): Promise<SubstrateSelector> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  if (customLocalModelTags !== undefined) {
    const base = buildDefaultConfig();
    await new IntelligenceConfigStore(storage, masterKey).save({
      ...base,
      customLocalModelTags: {
        ...(base.customLocalModelTags ?? {}),
        ...customLocalModelTags,
      },
    });
  }
  if (armed) {
    const outcome = await runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "concierge-label-fixture",
      isTty: true,
      print: vi.fn(),
    }, armedCeremonyDeps());
    expect(outcome.kind).toBe("already-provisioned");
  }
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "concierge-label-fixture",
    fetchImpl,
    modelManifestV2PublicKey: CATALOG_PUBLIC_KEY,
    // The integrity gate has no real Ollama runtime or model store here; these
    // seams let it pass so the test observes the LABEL, which is what changed.
    runtimeIntegrityVerifier: {
      verify: async () => ({
        ok: true as const,
        state: "runtime_manifest_match" as const,
        runtimeTag: FIXTURE_RUNTIME_TAG,
        observedManifestDigest: FIXTURE_MANIFEST_DIGEST,
      }),
    },
    immuneIntegrityVerifier: {
      verify: async () => ({
        ok: true as const,
        state: "immune_verified" as const,
        runtimeTag: FIXTURE_RUNTIME_TAG,
        expectedManifestDigest: FIXTURE_MANIFEST_DIGEST,
        descriptorCount: 2,
        bytesHashed: 10,
        verifiedArtifactDigests: ["2".repeat(64)],
        completedAtMonotonicMs: 1,
        cached: false,
      }),
      invalidate: () => {},
      cacheSize: 0,
    },
  });
  await selector.load();
  return selector;
}

/** `status()` never reads context, so the reader is deliberately inert. */
const inertReader: ConciergeContextReaderLike = {
  readContext: async () => {
    throw new Error("status() must not read fortress context");
  },
};

describe("concierge status model label follows the armed binding (R2-F3c)", () => {
  it("names the armed model tag once local intelligence is provisioned", async () => {
    const selector = await buildSelector(true);
    const handle = await selector.getSubstrate("concierge");
    expect(handle.displayLabel).toContain(FIXTURE_RUNTIME_TAG);
    expect(handle.displayLabel).toContain("armed binding");
    // The default pick must not be presented as what is running.
    expect(handle.displayLabel).not.toContain("Gemma");

    const status = await new ConciergeService({ reader: inertReader, selector })
      .status();
    expect(status.model).toContain(FIXTURE_RUNTIME_TAG);
    expect(status.model).toContain("armed binding");
  });

  it("carries the manifest digest prefix beside the armed tag, at the ceremony's width", async () => {
    const selector = await buildSelector(true);
    const handle = await selector.getSubstrate("concierge");
    // The tag alone names a subject with nothing to check it against; the
    // prefix is the public manifest root the binding was verified to, and it
    // is truncated by the ONE shared constant the ceremony line uses.
    expect(handle.displayLabel).toContain(
      `manifest sha256 ${FIXTURE_MANIFEST_DIGEST.slice(0, ARMED_DIGEST_PREFIX_CHARS)}`,
    );
    expect(ARMED_DIGEST_PREFIX_CHARS).toBe(12);
  });

  it("leaves the unarmed label as the pre-existing pick string, with no armed claim", async () => {
    const selector = await buildSelector(false);
    const handle = await selector.getSubstrate("concierge");
    // The pre-PR string, unchanged: with no verified binding the configured
    // pick IS what this handle invokes, so the operator sees what they always
    // saw and no claim about arming is made either way.
    expect(handle.displayLabel).toContain("Local model");
    expect(handle.displayLabel).toContain("Gemma 2 2B (via Ollama)");
    expect(handle.displayLabel).not.toContain("armed binding");
    expect(handle.displayLabel).not.toContain("manifest sha256");

    const status = await new ConciergeService({ reader: inertReader, selector })
      .status();
    expect(status.model).toContain("Gemma 2 2B (via Ollama)");
  });

  it("names the operator's custom tag on an unarmed fortress, not the pick's friendly name", async () => {
    // `LocalSubstrate.fromPick` invokes `customTag ?? LOCAL_MODEL_TAGS[pick]`,
    // so a configured custom tag is what answers; a label that reads the total
    // `LOCAL_MODEL_LABELS` table first would name a model nothing is calling.
    const selector = await buildSelector(false, { concierge: "llama3.1:8b" });
    const handle = await selector.getSubstrate("concierge");
    expect(handle.displayLabel).toContain("llama3.1:8b");
    expect(handle.displayLabel).not.toContain("Gemma");
  });
});
