// The authority's refusal causes and the descriptor shape rule, read from a real substrate selector.
import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import type { LocalIntegrityStateV2 } from "../../src/intelligence/model-manifest-v2.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import type { SubstrateConfig } from "../../src/intelligence/types.js";
import { LocalAuthority } from "../../src/local-recompile/authority.js";
import { LOCAL_TASK_SURFACE, parseBindingDescriptor } from "../../src/local-recompile/binding.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { Q5E_PUBLIC_KEY, q5eIntegrityState, q5eRuntimeTags } from "../intelligence/q5e-fixtures.js";

async function selector(options: { provision: boolean }) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const built = new SubstrateSelector({
    storage,
    masterKey,
    auditLog: new AuditLog(storage, masterKey),
    identityId: "binding-causes-test",
    modelManifestV2PublicKey: Q5E_PUBLIC_KEY,
  });
  await built.load();
  const state = q5eIntegrityState("/var/lib/ollama/models");
  if (options.provision) await built.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
  return { selector: built, masterKey, state };
}

function liveState(built: SubstrateSelector): LocalIntegrityStateV2 {
  return ((built as unknown as { config: SubstrateConfig }).config as { localIntegrityState: LocalIntegrityStateV2 }).localIntegrityState;
}

function authorityOver(built: SubstrateSelector, masterKey: Uint8Array): LocalAuthority {
  const authority = new LocalAuthority({ binding: built, policy: DEFAULT_POLICY, masterKey, identities: () => [] });
  authority.arm();
  return authority;
}

function causeOf(authority: LocalAuthority): string | undefined {
  const id = "cd".repeat(16);
  authority.register({ request_id: id, refs: [{ namespace: "notes", key: "one" }] });
  const reply = authority.reply(id);
  return reply.outcome === "refused" ? reply.cause : undefined;
}

describe("the authority reports the binding's own cause", () => {
  it("a boot with local integrity not provisioned refuses as unarmed and is not ready", async () => {
    const { selector: built, masterKey } = await selector({ provision: false });
    const authority = authorityOver(built, masterKey);
    expect(causeOf(authority)).toBe("unarmed");
    expect(authority.readiness()).toBe("unarmed");
  });

  it("a boot with a provisioned configuration and no concierge binding refuses as binding_absent", async () => {
    const { selector: built, masterKey } = await selector({ provision: true });
    delete liveState(built).bindings.concierge;
    const authority = authorityOver(built, masterKey);
    expect(causeOf(authority)).toBe("binding_absent");
    expect(authority.readiness()).toBe("binding_absent");
  });

  it("a boot with a binding of the wrong assurance refuses as assurance_mismatch", async () => {
    const { selector: built, masterKey } = await selector({ provision: true });
    const state = liveState(built);
    state.bindings.concierge = { ...state.bindings.concierge!, assurance: "immune" };
    expect(causeOf(authorityOver(built, masterKey))).toBe("assurance_mismatch");
  });

  it("a binding provisioned after boot still needs a restart to arm", async () => {
    const { selector: built, masterKey, state } = await selector({ provision: false });
    const authority = authorityOver(built, masterKey);
    await built.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
    expect(built.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE).ok).toBe(true);
    expect(causeOf(authority)).toBe("unarmed");
    expect(authority.readiness()).toBe("unarmed");
  });

  it("an armed boot is ready, and a later change reports epoch_changed", async () => {
    const { selector: built, masterKey, state } = await selector({ provision: true });
    const authority = authorityOver(built, masterKey);
    expect(authority.readiness()).toBeNull();
    await built.commitLocalIntegrityProvisioning(state, q5eRuntimeTags(state));
    expect(authority.readiness()).toBe("epoch_changed");
  });
});

describe("one descriptor rule on both sides of the worker boundary", () => {
  const good = { runtime_tag: "qwen2.5:1.5b", manifest_digest: "1".repeat(64), endpoint: { address: "127.0.0.1", port: 11434 } };

  it.each([
    ["a private network address", { ...good, endpoint: { address: "10.0.0.5", port: 11434 } }],
    ["a public address", { ...good, endpoint: { address: "8.8.8.8", port: 11434 } }],
    ["a host name", { ...good, endpoint: { address: "localhost", port: 11434 } }],
    ["an upper-case digest", { ...good, manifest_digest: "A".repeat(64) }],
    ["a short digest", { ...good, manifest_digest: "1".repeat(63) }],
    ["an over-long tag", { ...good, runtime_tag: "t".repeat(3 * 64 + 3) }],
  ])("the worker refuses a descriptor with %s", (_label, descriptor) => {
    expect(parseBindingDescriptor(descriptor)).toBeNull();
  });

  it("the worker accepts the IPv4 and IPv6 loopback literals", () => {
    expect(parseBindingDescriptor(good)).toEqual(good);
    expect(parseBindingDescriptor({ ...good, endpoint: { address: "::1", port: 11434 } })).not.toBeNull();
  });

  it.each([
    ["an empty digest", ""],
    ["an upper-case digest", "A".repeat(64)],
    ["a short digest", "1".repeat(63)],
  ])("the server refuses a binding whose signed identity names %s", async (_label, digest) => {
    const { selector: built } = await selector({ provision: true });
    const state = liveState(built);
    const binding = state.bindings.concierge!;
    state.bindings.concierge = { ...binding, ollama_identity: { ...binding.ollama_identity, ollama_manifest_sha256: digest } };
    expect(built.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE)).toEqual({ ok: false, refusal: "identity_mismatch" });
  });
});
