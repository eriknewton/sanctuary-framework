// fail-before-exempt: The resolver is a new module; production boot and router witnesses live in session-binding-wiring.test.ts.
/** Session views follow one durable boot decision and per-call named selection. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createSessionBindingAccessors, resolveSessionBinding, predictNextStartBinding, proveSoleIdentity, type SoleProofInputs, type SessionBindingState } from "../../src/agent-native/session-binding.js";
import { SessionIdentityError, SessionNotBoundError, UNBOUND_SESSION, fingerprintIdentityId, resolveActiveSessionIdentity } from "../../src/agent-native/safety-base.js";
import { isSessionNotBoundError } from "../../src/agent-native/session-not-bound.js";
import { argumentStageCause } from "../../src/tool-outcome.js";
import { createCognitiveTools, IdentityManager } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";

let storage: MemoryStorage;
let identityManager: IdentityManager;
let proofInputs: SoleProofInputs;
let id: string;
let masterKey: Uint8Array;
beforeEach(async () => {
  storage = new MemoryStorage();
  const key = masterKey = generateRandomKey();
  identityManager = new IdentityManager(storage, key);
  const { storedIdentity } = createIdentity("bound", key, "recovery-key");
  await identityManager.saveNew(storedIdentity);
  id = storedIdentity.identity_id;
  // The manager already validates the stored identity; proof inputs name the same singleton.
  proofInputs = { before: [id], after: [id], evidence: { total: 1, loaded: 1, failed: 0,
    skipped_null_reads: 0, duplicate_ids: 0, key_mismatches: 0, decrypted_keys: [id] } };
});

afterEach(() => { vi.restoreAllMocks(); });

const states: Array<[SessionBindingState, boolean, "absent" | "empty" | "loaded" | "missing", "sole" | "none" | "several" | "invalid"]> = [
  ["state_BOUND_NAMED", false, "loaded", "sole"],
  ["state_BOUND_SOLE_IDENTITY", true, "absent", "sole"],
  ["state_UNBOUND_FLAG_OFF", false, "absent", "sole"],
  ["state_UNBOUND_NO_IDENTITY", true, "absent", "none"],
  ["state_UNBOUND_SEVERAL_IDENTITIES", true, "absent", "several"],
  ["state_UNBOUND_UNPROVEN", true, "absent", "invalid"],
  ["state_NAMED_EMPTY", true, "empty", "sole"],
  ["state_NAMED_UNRESOLVED", true, "missing", "sole"],
];
async function resolve(row = states[1]!) {
  const [state, flag, named, proof] = row;
  const env: NodeJS.ProcessEnv = named === "absent" ? {} : { SANCTUARY_SESSION_IDENTITY_ID: named === "loaded" ? id : named === "empty" ? "" : "missing" };
  if (proof === "none") proofInputs = { before: [], after: [], evidence: { ...proofInputs.evidence, total: 0, loaded: 0, decrypted_keys: [] } };
  if (proof === "several") proofInputs = { ...proofInputs, before: [id, "second"], after: [id, "second"], evidence: { ...proofInputs.evidence, total: 2 } }; // Two stable candidates are several.
  if (proof === "invalid") proofInputs.evidence.failed = 1; // One failed record prevents proof.
  const auditLog = { appendCritical: vi.fn().mockResolvedValue(undefined) };
  const stderr = vi.fn();
  const resolver = await resolveSessionBinding({ identityManager, storage, flag, auditLog, stderr, env: () => env, proofInputs });
  return { state, resolver, auditLog, stderr, env };
}

it.each(states)("resolves each state from flag, variable and evidence: %s", async (...row) => {
  const { state, resolver, auditLog, stderr } = await resolve(row);
  expect(resolver.bootState).toBe(state);
  expect(auditLog.appendCritical).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
    identity_id: "system", operation: "session_binding_resolved",
    details: expect.objectContaining({ state, evidence: { ...proofInputs.evidence, decrypted_keys: proofInputs.evidence.decrypted_keys.length } }),
  }));
  expect(stderr).toHaveBeenCalledOnce();
  if (state.startsWith("state_BOUND")) {
    expect(resolver.cooperative()).toBe(resolver.primitive());
    expect(resolveActiveSessionIdentity(resolver.cooperative()).identity_id).toBe(id);
  }
});

it("every non-bound state returns the same frozen binding to cooperative consumers", async () => {
  for (const row of states.filter(([state]) => !state.startsWith("state_BOUND"))) {
    const { resolver } = await resolve(row);
    expect(resolver.cooperative()).toBe(UNBOUND_SESSION);
    expect(Object.isFrozen(resolver.cooperative())).toBe(true);
  }
  expect(() => resolveActiveSessionIdentity(UNBOUND_SESSION)).toThrow(SessionNotBoundError);
});

it("the primitive view returns undefined in every non-bound state except a named unresolved identity", async () => {
  for (const row of states.filter(([state]) => !state.startsWith("state_BOUND"))) {
    const { state, resolver } = await resolve(row);
    expect(resolver.primitive()).toEqual(state === "state_NAMED_UNRESOLVED" ? { identity_id: "missing" } : undefined);
  }
});

it("the boot row records load counters and never the identity keys", async () => {
  const { auditLog } = await resolve(states[4]);
  const { details } = auditLog.appendCritical.mock.calls[0]![0] as { details: Record<string, unknown> };
  expect(details.evidence).toEqual({ total: 2, loaded: 1, failed: 0, skipped_null_reads: 0, duplicate_ids: 0, key_mismatches: 0, decrypted_keys: 1 });
  expect(JSON.stringify(details)).not.toContain(id);
});

it.each([
  ["grew from empty", [], ["late"], 0, "state_UNBOUND_UNPROVEN"],
  ["shrank from several", ["first", "second"], ["first"], 2, "state_UNBOUND_UNPROVEN"],
  ["reordered several", ["first", "second"], ["second", "first"], 2, "state_UNBOUND_SEVERAL_IDENTITIES"],
] as const)("a relist that %s maps to its proof state", (_case, before, after, total, state) => {
  const evidence = { total, loaded: 0, failed: 0, skipped_null_reads: 0, duplicate_ids: 0, key_mismatches: 0, decrypted_keys: [] };
  expect(proveSoleIdentity({ before: [...before], after: [...after], evidence })).toMatchObject({ proven: false, state });
});

it("cognitive tools cannot take a session binding without its boot decision", () => {
  // A compile-time witness: the options type requires the boot decision beside any binding.
  const withoutDecision = () => createCognitiveTools(new StateStore(storage, masterKey), storage, masterKey, "recovery-key", undefined,
    // @ts-expect-error a binding supplied without its boot decision does not type-check
    { currentSessionBinding: () => undefined });
  expect(withoutDecision).toBeTypeOf("function");
});

it("a sole bind is not installed when its boot row fails", async () => {
  const stderr = vi.fn();
  const resolver = await resolveSessionBinding({ identityManager, storage, flag: true,
    auditLog: { appendCritical: vi.fn().mockRejectedValue(new Error("unavailable")) }, stderr, env: () => ({}), proofInputs });
  expect(resolver.bootState).toBe("state_UNBOUND_UNPROVEN");
  expect(resolver.cooperative()).toBe(UNBOUND_SESSION);
  expect(resolver.primitive()).toBeUndefined();
  expect(stderr.mock.calls).toEqual([["session not bound: identity set could not be proven"], ["session binding boot row failed"]]);
});

it("a named binding continues when its boot row fails", async () => {
  const stderr = vi.fn();
  const resolver = await resolveSessionBinding({ identityManager, storage, flag: false,
    auditLog: { appendCritical: vi.fn().mockRejectedValue(new Error("unavailable")) }, stderr,
    env: () => ({ SANCTUARY_SESSION_IDENTITY_ID: id }), proofInputs });
  expect(resolver.bootState).toBe("state_BOUND_NAMED");
  expect(resolver.cooperative().identity_id).toBe(id);
  expect(stderr.mock.calls).toEqual([["session bound to the identity named at launch"], ["session binding boot row failed"]]);
});

it("accessors throw before install", async () => {
  const accessors = createSessionBindingAccessors();
  expect(accessors.cooperative).toThrow("not installed");
  expect(accessors.primitive).toThrow("not installed");
  expect(accessors.bootState).toThrow("not installed");
  const { resolver } = await resolve();
  accessors.install(resolver);
  expect(accessors.cooperative()).toBe(resolver.cooperative());
  expect(() => accessors.install(resolver)).toThrow("already installed");
});

it("a sole decision never reads the environment again", async () => {
  const env = vi.fn(() => ({}));
  const resolver = await resolveSessionBinding({ identityManager, storage, flag: true,
    auditLog: { appendCritical: vi.fn().mockResolvedValue(undefined) }, stderr: vi.fn(), env, proofInputs });
  env.mockImplementation(() => { throw new Error("environment was reread"); });
  expect(resolver.cooperative()).toBe(resolver.primitive());
  expect(resolver.cooperative().binding_source).toBe("sole_identity");
});

it("named selection follows the environment without acquiring a default mid-process", async () => {
  const { resolver, env } = await resolve(states[2]);
  env.SANCTUARY_SESSION_IDENTITY_ID = id;
  expect(resolver.cooperative()).toMatchObject({ identity_id: id, binding_source: "launch_variable" });
  env.SANCTUARY_SESSION_IDENTITY_ID = "missing";
  expect(resolver.cooperative()).toBe(UNBOUND_SESSION);
  expect(resolver.primitive()).toEqual({ identity_id: "missing" });
  env.SANCTUARY_SESSION_IDENTITY_ID = "";
  expect(resolver.primitive()).toBeUndefined();
  delete env.SANCTUARY_SESSION_IDENTITY_ID;
  expect(resolver.cooperative()).toBe(UNBOUND_SESSION);
});

it("expired and mismatched bindings keep their existing error class", () => {
  const expiresAt = "2020-01-01T00:00:00.000Z";
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(expiresAt));
  for (const binding of [
    { identity_id: id, requester_identity_fingerprint: fingerprintIdentityId(id), expires_at: expiresAt },
    { identity_id: id, requester_identity_fingerprint: fingerprintIdentityId("different") },
  ]) {
    try { resolveActiveSessionIdentity(binding); throw new Error("expected refusal"); }
    catch (error) { expect(error).toBeInstanceOf(SessionIdentityError); expect(error).not.toBeInstanceOf(SessionNotBoundError); }
  }
});

it("sole access waits for its durable boot row", async () => {
  let durable!: () => void;
  const row = new Promise<void>(resolve => { durable = resolve; });
  const accessors = createSessionBindingAccessors();
  const stderr = vi.fn();
  const installing = resolveSessionBinding({ identityManager, storage, flag: true,
    auditLog: { appendCritical: vi.fn(() => row) }, stderr, env: () => ({}), proofInputs }).then(accessors.install);
  expect(accessors.cooperative).toThrow("not installed");
  expect(stderr).not.toHaveBeenCalled();
  durable();
  await installing;
  expect(accessors.cooperative()).toMatchObject({ binding_source: "sole_identity", identity_id: id });
  expect(stderr).toHaveBeenCalledOnce();
});

it("only the type brand selects the not-bound ledger cause", () => {
  const actual = new SessionNotBoundError();
  expect(isSessionNotBoundError(actual)).toBe(true);
  expect(argumentStageCause(actual)).toBe("session_not_bound");
  for (const error of [new SessionIdentityError(), new Error(actual.message), { name: actual.name }, null, undefined]) {
    expect(isSessionNotBoundError(error)).toBe(false);
    expect(argumentStageCause(error)).toBe("pre_gate_argument_refused");
  }
});

it.each([
  [false, "absent", true, "not bound: default binding is off"],
  [true, "empty", true, "not bound: launch variable is empty"],
  [false, "loaded", true, "named"],
  [true, "missing", true, "not bound: named identity not found"],
  [true, "absent", true, "sole"],
  [true, "absent", false, "no-key"],
] as const)("predicts next-start selection for flag %s and variable %s with key %s", async (flag, named, hasKey, expected) => {
  const env = named === "absent" ? {} : { SANCTUARY_SESSION_IDENTITY_ID: named === "loaded" ? id : named === "empty" ? "" : "missing" };
  const result = await predictNextStartBinding({ flag, configFilePath: "/fixture/sanctuary.json", storage,
    masterKey: hasKey ? masterKey : null, env });
  expect(result).toBe(expected === "no-key" ? "cannot predict: identities are encrypted and no key is available"
    : `A server started now would be: ${expected === "named" ? `bound to ${id} by the launch variable`
      : expected === "sole" ? `bound by default to ${id}` : expected}`);
});

it("predicts no default when the stored identity set is empty", async () => {
  await storage.delete("_identities", id);
  expect(await predictNextStartBinding({ flag: true, configFilePath: "/fixture/sanctuary.json", storage, masterKey, env: {} }))
    .toBe("A server started now would be: not bound: this fortress has no identity");
});

it("predicts no default when complete enumeration is unavailable", async () => {
  vi.spyOn(storage, "listKeys").mockRejectedValue(new Error("enumeration unavailable"));
  expect(await predictNextStartBinding({ flag: true, configFilePath: "/fixture/sanctuary.json", storage, masterKey, env: {} }))
    .toBe("A server started now would be: not bound: identity set could not be proven");
});

it("predicts no binding when identity loading throws", async () => {
  vi.spyOn(IdentityManager.prototype, "load").mockRejectedValue(new Error("load unavailable"));
  expect(await predictNextStartBinding({ flag: true, configFilePath: "/fixture/sanctuary.json", storage, masterKey, env: {} }))
    .toBe("A server started now would be: not bound: identity loading failed");
});
