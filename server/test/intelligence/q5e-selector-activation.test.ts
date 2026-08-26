import { describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import {
  IMMUNE_FULL_VERIFICATION_CADENCE_MS,
  createCadencedImmuneDiskVerifier,
  type CadencedImmuneDiskVerifier,
  type ImmuneDiskVerifier,
  type ImmuneVerificationClock,
} from "../../src/intelligence/immune-disk-verifier.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { IntelligenceConfigStore } from "../../src/intelligence/policy-store.js";
import {
  createSingleFlightLightRuntimeVerifier,
  type RuntimeLightVerificationResult,
  type RuntimeLightVerifier,
} from "../../src/intelligence/runtime-light-verifier.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import type { Surface } from "../../src/intelligence/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  Q5E_DEFAULT_DIGEST,
  Q5E_PUBLIC_KEY,
  Q5E_RUNTIME_TAG,
  q5eIntegrityState,
  q5eRuntimeTags,
} from "./q5e-fixtures.js";

const ROOT = "/var/lib/ollama/models";

function runtimeSuccess(): RuntimeLightVerificationResult {
  return {
    ok: true,
    state: "runtime_manifest_match",
    runtimeTag: Q5E_RUNTIME_TAG,
    observedManifestDigest: Q5E_DEFAULT_DIGEST,
  };
}

function runtimeFailure(
  reason: "runtime_manifest_digest_mismatch" | "integrity_io_unavailable",
): RuntimeLightVerificationResult {
  return reason === "runtime_manifest_digest_mismatch"
    ? {
      ok: false,
      state: "tags_digest_mismatch",
      reason,
      runtimeTag: Q5E_RUNTIME_TAG,
      observedManifestDigest: "2".repeat(64),
    }
    : {
      ok: false,
      state: "tags_transport_refused",
      reason,
      runtimeTag: Q5E_RUNTIME_TAG,
    };
}

function immuneSuccess(cached = false) {
  return {
    ok: true as const,
    state: "immune_verified" as const,
    runtimeTag: Q5E_RUNTIME_TAG,
    expectedManifestDigest: Q5E_DEFAULT_DIGEST,
    descriptorCount: 2,
    bytesHashed: 128,
    verifiedArtifactDigests: ["3".repeat(64)],
    completedAtMonotonicMs: 1,
    cached,
  };
}

function passiveImmuneVerifier(): CadencedImmuneDiskVerifier {
  return {
    cacheSize: 0,
    invalidate: vi.fn(),
    verify: vi.fn(async () => immuneSuccess()),
  };
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  return input instanceof Request
    ? input.url
    : typeof input === "string" ? input : input.toString();
}

function fetchRecorder() {
  const generated: string[] = [];
  const remote: string[] = [];
  const fetchImpl = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
    const url = requestUrl(input);
    if (new URL(url).pathname === "/api/generate") {
      generated.push(url);
      return new Response(JSON.stringify({ response: "local result" }), { status: 200 });
    }
    if (url.includes("venice.ai")) {
      remote.push(url);
      return new Response(JSON.stringify({
        choices: [{ message: { content: "remote result" } }],
      }), { status: 200 });
    }
    return new Response(JSON.stringify({ models: [] }), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, generated, remote };
}

async function armedFixture(options: { veniceKey?: boolean } = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  if (options.veniceKey) {
    await new IntelligenceConfigStore(storage, masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    }).save({
      ...buildDefaultConfig(),
      veniceApiKey: "test-venice-key",
    });
  }
  const provisioner = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "q5e-provisioner",
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
  });
  await provisioner.load();
  const state = q5eIntegrityState(ROOT);
  await provisioner.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
  return { storage, masterKey, auditLog };
}

function activatedSelector(
  fixture: Awaited<ReturnType<typeof armedFixture>>,
  args: {
    runtime: RuntimeLightVerifier;
    immune?: CadencedImmuneDiskVerifier;
    clock?: ImmuneVerificationClock;
    fetchImpl?: typeof fetch;
  },
) {
  return new SubstrateSelector({
    ...fixture,
    identityId: "q5e-activated",
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    runtimeIntegrityVerifier: args.runtime,
    immuneIntegrityVerifier: args.immune ?? passiveImmuneVerifier(),
    integrityClock: args.clock,
    fetchImpl: args.fetchImpl,
  });
}

describe("Q5E selector activation", () => {
  it("leaves legacy-unarmed local generation behavior unchanged and emits no verified claim", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const recorder = fetchRecorder();
    const runtime = { verify: vi.fn(() => Promise.reject(new Error("must stay inert"))) };
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "legacy",
      fetchImpl: recorder.fetchImpl,
      runtimeIntegrityVerifier: runtime,
      immuneIntegrityVerifier: passiveImmuneVerifier(),
    });
    const response = await selector.invokeSummarize("concierge", {
      kind: "summarize",
      context: "legacy",
      query: "unchanged",
    });
    expect(response.failureClass).toBeNull();
    expect(recorder.generated).toHaveLength(1);
    expect(runtime.verify).not.toHaveBeenCalled();
    const events = await auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    expect(events.entries).toHaveLength(0);
  });

  it("re-gates after handle issue and refuses a planted post-provision tag divergence before generation", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    const results = [runtimeSuccess(), runtimeFailure("runtime_manifest_digest_mismatch")];
    const runtime = { verify: vi.fn(async () => results.shift()!) };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    const handle = await selector.getSubstrate("concierge");
    expect(handle.capability.summarize).toBe(true);
    const response = await handle.summarize!({
      kind: "summarize",
      context: "post-provision divergence",
      query: "must refuse",
    });
    expect(recorder.generated).toHaveLength(0);
    expect(response.failureClass).toBe("substrate_misconfigured");
    expect(runtime.verify).toHaveBeenCalledTimes(2);
    const events = await fixture.auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    expect(events.entries.map((entry) => entry.details?.stage)).toEqual([
      "selector_load",
      "first_invocation",
    ]);
    expect(events.entries.at(-1)?.details).toMatchObject({
      reason: "runtime_manifest_digest_mismatch",
      generation_refused: true,
    });
  });

  it("refuses a tag divergence before selector load and deduplicates concurrent waiters", async () => {
    const fixture = await armedFixture();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const delegate = {
      verify: vi.fn(async () => {
        await gate;
        return runtimeFailure("runtime_manifest_digest_mismatch");
      }),
    };
    const runtime = createSingleFlightLightRuntimeVerifier(delegate);
    const selector = activatedSelector(fixture, { runtime });
    const first = selector.getSubstrate("concierge");
    const second = selector.getSubstrate("concierge");
    release();
    const [left, right] = await Promise.all([first, second]);
    expect(left.capability.summarize).toBe(false);
    expect(right.capability.summarize).toBe(false);
    expect(delegate.verify).toHaveBeenCalledTimes(1);
    const events = await fixture.auditLog.query({ operation_type: INTEL_OPS.LOAD_INTEGRITY });
    expect(events.entries).toHaveLength(1);
    expect(JSON.stringify(events.entries[0]!.details)).not.toContain(ROOT);
  });

  it("runs the immune runtime gate before the first invocation and refuses before disk or generation", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    const results = [runtimeSuccess(), runtimeFailure("runtime_manifest_digest_mismatch")];
    const runtime = { verify: vi.fn(async () => results.shift()!) };
    const immune = passiveImmuneVerifier();
    const selector = activatedSelector(fixture, {
      runtime,
      immune,
      fetchImpl: recorder.fetchImpl,
    });
    const handle = await selector.getSubstrate("sentinel-scoring");
    const response = await handle.classify!({
      kind: "classify",
      items: ["tool"],
      categories: ["deny"],
    });
    expect(response.failureClass).toBe("substrate_misconfigured");
    expect(runtime.verify).toHaveBeenCalledTimes(2);
    expect(immune.verify).toHaveBeenCalledTimes(1);
    expect(recorder.generated).toHaveLength(0);
  });

  it("invalidates an issued handle on config change so it cannot bypass a new gate", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    const runtime = { verify: vi.fn(async () => runtimeSuccess()) };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    const oldHandle = await selector.getSubstrate("concierge");
    await selector.setFallbackBehavior("concierge", "conservative-deny");
    const refusedOld = await oldHandle.summarize!({
      kind: "summarize",
      context: "old",
      query: "must refuse",
    });
    expect(refusedOld.failureClass).toBe("substrate_misconfigured");
    expect(recorder.generated).toHaveLength(0);

    const newHandle = await selector.getSubstrate("concierge");
    const acceptedNew = await newHandle.summarize!({
      kind: "summarize",
      context: "new",
      query: "re-gated",
    });
    expect(acceptedNew.failureClass).toBeNull();
    expect(recorder.generated).toHaveLength(1);
  });

  it("refuses an armed local binding when the configured Ollama endpoint is not loopback", async () => {
    const fixture = await armedFixture();
    const store = new IntelligenceConfigStore(fixture.storage, fixture.masterKey, {
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    const loaded = await store.loadAuthoritative();
    expect(loaded?.version).toBe(2);
    await store.save({ ...loaded!, ollamaEndpoint: "https://ollama.example.invalid" });
    const recorder = fetchRecorder();
    const runtime = { verify: vi.fn(async () => runtimeSuccess()) };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    const handle = await selector.getSubstrate("concierge");
    expect(handle.capability.summarize).toBe(false);
    expect(runtime.verify).not.toHaveBeenCalled();
    expect(recorder.generated).toHaveLength(0);
  });

  it("honors the light six-hour monotonic window and makes wall-clock rollback due", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    let monotonicMs = 1_000;
    let wallMs = 10_000;
    const clock = {
      monotonicNow: () => monotonicMs,
      wallNow: () => wallMs,
    };
    const results = [
      runtimeSuccess(),
      runtimeSuccess(),
      runtimeFailure("runtime_manifest_digest_mismatch"),
      runtimeFailure("runtime_manifest_digest_mismatch"),
    ];
    const runtime = { verify: vi.fn(async () => results.shift()!) };
    const selector = activatedSelector(fixture, {
      runtime,
      clock,
      fetchImpl: recorder.fetchImpl,
    });
    const handle = await selector.getSubstrate("concierge");
    await handle.summarize!({ kind: "summarize", context: "one", query: "one" });
    monotonicMs += IMMUNE_FULL_VERIFICATION_CADENCE_MS - 1;
    await handle.summarize!({ kind: "summarize", context: "two", query: "two" });
    expect(recorder.generated).toHaveLength(2);
    expect(runtime.verify).toHaveBeenCalledTimes(2);

    monotonicMs += 1;
    const expired = await handle.summarize!({
      kind: "summarize",
      context: "expired",
      query: "refuse",
    });
    expect(expired.failureClass).toBe("substrate_misconfigured");
    expect(recorder.generated).toHaveLength(2);

    wallMs -= 1;
    const rollback = await handle.summarize!({
      kind: "summarize",
      context: "rollback",
      query: "refuse",
    });
    expect(rollback.failureClass).toBe("substrate_misconfigured");
    expect(runtime.verify).toHaveBeenCalledTimes(4);
  });

  it("runs immune runtime evidence every invocation and single-flights a due full verification", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    let monotonicMs = 1_000;
    let wallMs = 10_000;
    const clock = {
      monotonicNow: () => monotonicMs,
      wallNow: () => wallMs,
    };
    let releaseDue!: () => void;
    const dueGate = new Promise<void>((resolve) => { releaseDue = resolve; });
    let diskCalls = 0;
    const delegate: ImmuneDiskVerifier = {
      verify: vi.fn(async () => {
        diskCalls += 1;
        if (diskCalls === 3) await dueGate;
        return immuneSuccess();
      }),
    };
    const immune = createCadencedImmuneDiskVerifier(delegate, { clock });
    const runtime = { verify: vi.fn(async () => runtimeSuccess()) };
    const selector = activatedSelector(fixture, {
      runtime,
      immune,
      clock,
      fetchImpl: recorder.fetchImpl,
    });
    const handle = await selector.getSubstrate("sentinel-scoring");
    await handle.classify!({ kind: "classify", items: ["one"], categories: ["safe"] });
    monotonicMs += IMMUNE_FULL_VERIFICATION_CADENCE_MS;
    wallMs += IMMUNE_FULL_VERIFICATION_CADENCE_MS;
    const left = handle.classify!({ kind: "classify", items: ["two"], categories: ["safe"] });
    const right = handle.classify!({ kind: "classify", items: ["three"], categories: ["safe"] });
    await vi.waitFor(() => expect(diskCalls).toBe(3));
    expect(recorder.generated).toHaveLength(1);
    releaseDue();
    await Promise.all([left, right]);
    expect(diskCalls).toBe(3);
    expect(runtime.verify).toHaveBeenCalledTimes(4);
    expect(recorder.generated).toHaveLength(3);
  });

  it("retries transient failures and retains a content mismatch until complete success", async () => {
    const fixture = await armedFixture();
    const recorder = fetchRecorder();
    const results = [
      runtimeSuccess(),
      runtimeFailure("runtime_manifest_digest_mismatch"),
      runtimeFailure("integrity_io_unavailable"),
      runtimeSuccess(),
    ];
    const runtime = { verify: vi.fn(async () => results.shift()!) };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    const handle = await selector.getSubstrate("concierge");
    await handle.summarize!({ kind: "summarize", context: "mismatch", query: "one" });
    await handle.summarize!({ kind: "summarize", context: "outage", query: "two" });
    let status = await selector.getOperatorVisibleStatus();
    expect(status.surfaces.find((entry) => entry.surface === "concierge")?.recentFailures)
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ snippet: "local load refused: runtime_manifest_digest_mismatch" }),
      ]));
    const recovered = await handle.summarize!({
      kind: "summarize",
      context: "recovered",
      query: "three",
    });
    expect(recovered.failureClass).toBeNull();
    status = await selector.getOperatorVisibleStatus();
    expect(status.surfaces.find((entry) => entry.surface === "concierge")?.recentFailures)
      .not.toEqual(expect.arrayContaining([
        expect.objectContaining({ snippet: expect.stringContaining("local load refused") }),
      ]));
  });

  it.each([
    ["concierge", true],
    ["direct-agent-gate-advisor", false],
    ["template-suggestion", true],
  ] as const)("keeps the existing fallback policy for light surface %s", async (surface, expectsRemote) => {
    const fixture = await armedFixture({ veniceKey: true });
    const recorder = fetchRecorder();
    const runtime = {
      verify: vi.fn(async () => runtimeFailure("runtime_manifest_digest_mismatch")),
    };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    await selector.invokeSummarize(surface, {
      kind: "summarize",
      context: "fallback",
      query: "policy",
    });
    expect(recorder.generated).toHaveLength(0);
    expect(recorder.remote.length > 0).toBe(expectsRemote);
  });

  it.each([
    ["sentinel-scoring", "classify"],
    ["privacy-filter-tier-2", "redact"],
  ] as const)("never enters a remote fallback for immune surface %s", async (surface, method) => {
    const fixture = await armedFixture({ veniceKey: true });
    const recorder = fetchRecorder();
    const runtime = {
      verify: vi.fn(async () => runtimeFailure("runtime_manifest_digest_mismatch")),
    };
    const selector = activatedSelector(fixture, { runtime, fetchImpl: recorder.fetchImpl });
    if (method === "classify") {
      await selector.invokeClassify(surface as Surface, {
        kind: "classify",
        items: ["tool"],
        categories: ["deny"],
      });
    } else {
      await selector.invokeRedact(surface as Surface, { kind: "redact", text: "name" });
    }
    expect(recorder.generated).toHaveLength(0);
    expect(recorder.remote).toHaveLength(0);
  });
});
