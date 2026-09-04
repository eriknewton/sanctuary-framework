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

async function buildSelector(armed: boolean): Promise<SubstrateSelector> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
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

  it("falls back to the default pick on an unarmed fortress and says so", async () => {
    const selector = await buildSelector(false);
    const handle = await selector.getSubstrate("concierge");
    expect(handle.displayLabel).toContain("Local model");
    expect(handle.displayLabel).toContain("Gemma");
    expect(handle.displayLabel).toContain("default pick, not armed");

    const status = await new ConciergeService({ reader: inertReader, selector })
      .status();
    expect(status.model).toContain("default pick, not armed");
  });
});
