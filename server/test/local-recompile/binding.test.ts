// fail-before-exempt: new selector method and new module; base has no binding descriptor to compare against.
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { deriveOllamaRuntimeTag, type LocalIntegrityStateV2 } from "../../src/intelligence/model-manifest-v2.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import type { SubstrateConfig } from "../../src/intelligence/types.js";
import { LOCAL_TASK_SURFACE, parseBindingDescriptor } from "../../src/local-recompile/binding.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { Q5E_PUBLIC_KEY, q5eIntegrityState, q5eRuntimeTags } from "../intelligence/q5e-fixtures.js";

const fetchSpies: Array<ReturnType<typeof vi.fn>> = [];
afterEach(() => {
  fetchSpies.splice(0);
  vi.restoreAllMocks();
});

async function armedSelector() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const fetchImpl = vi.fn(async () => new Response("{}", { status: 200 }));
  fetchSpies.push(fetchImpl);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "local-binding-test",
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    fetchImpl: fetchImpl as unknown as typeof fetch,
  });
  await selector.load();
  const state = q5eIntegrityState("/var/lib/ollama/models");
  await selector.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
  return { selector, auditLog, fetchImpl, state };
}

/** The selector's live configuration, for rows that need a state the public setters refuse to build. */
function liveConfig(selector: SubstrateSelector): { config: SubstrateConfig } {
  return selector as unknown as { config: SubstrateConfig };
}

describe("local binding descriptor", () => {
  it("an armed concierge binding gives the descriptor", async () => {
    const { selector } = await armedSelector();
    const described = selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    expect(described.ok).toBe(true);
    if (!described.ok) return;
    expect(described.descriptor).toEqual({
      runtime_tag: "qwen2.5:1.5b",
      manifest_digest: "1".repeat(64),
      endpoint: { address: "127.0.0.1", port: 11434 },
    });
    expect(Object.isFrozen(described.descriptor)).toBe(true);
    expect(Object.isFrozen(described.descriptor.endpoint)).toBe(true);
    expect(parseBindingDescriptor(described.descriptor)).toEqual(described.descriptor);
  });

  it("the descriptor's tag and digest come from the signed identity", async () => {
    const { selector, state } = await armedSelector();
    const binding = state.bindings.concierge!;
    const described = selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    if (!described.ok) throw new Error("expected a descriptor");
    expect(described.descriptor.runtime_tag).toBe(deriveOllamaRuntimeTag(binding.ollama_identity));
    expect(described.descriptor.manifest_digest).toBe(binding.ollama_identity.ollama_manifest_sha256);
  });

  it("an unarmed fortress is refused", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const selector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog: new AuditLog(storage, masterKey),
      identityId: "local-binding-test",
      modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
    });
    await selector.load();
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "unarmed" });
  });

  it("a missing binding is refused", async () => {
    const { selector } = await armedSelector();
    const state = (liveConfig(selector).config as { localIntegrityState: LocalIntegrityStateV2 }).localIntegrityState;
    delete state.bindings.concierge;
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "binding_absent" });
  });

  it("a configuration change since the epoch was read is refused", async () => {
    const { selector, state } = await armedSelector();
    const first = selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    if (!first.ok) throw new Error("expected a descriptor");
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE, first.epoch).ok).toBe(true);
    await selector.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE, first.epoch)).toEqual({
      ok: false,
      refusal: "epoch_changed",
    });
  });

  it("a binding with the wrong assurance is refused", async () => {
    const { selector } = await armedSelector();
    const state = (liveConfig(selector).config as { localIntegrityState: LocalIntegrityStateV2 }).localIntegrityState;
    state.bindings.concierge = { ...state.bindings.concierge!, assurance: "immune" };
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "assurance_mismatch" });
  });

  it("a non-loopback endpoint is refused", async () => {
    const { selector } = await armedSelector();
    liveConfig(selector).config = { ...liveConfig(selector).config, ollamaEndpoint: "http://10.0.0.5:11434" };
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "not_loopback" });
  });

  it("a stored tag that disagrees with the signed identity is refused", async () => {
    const { selector } = await armedSelector();
    const state = (liveConfig(selector).config as { localIntegrityState: LocalIntegrityStateV2 }).localIntegrityState;
    state.bindings.concierge = { ...state.bindings.concierge!, runtime_tag: "other:latest" };
    expect(selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "identity_mismatch" });
  });

  it("describing the binding writes no audit row and makes no network call", async () => {
    const { selector, auditLog, fetchImpl } = await armedSelector();
    const append = vi.spyOn(auditLog, "append");
    const appendCritical = vi.spyOn(auditLog, "appendCritical");
    const globalFetch = vi.spyOn(globalThis, "fetch");
    fetchImpl.mockClear();
    for (let i = 0; i < 4; i += 1) selector.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    expect(append).not.toHaveBeenCalled();
    expect(appendCritical).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(globalFetch).not.toHaveBeenCalled();
  });
});
