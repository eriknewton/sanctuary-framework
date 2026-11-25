// fail-before-exempt: new module; base has no authority reply.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createIdentity } from "../../src/core/identity.js";
import { deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { LocalBindingDescription } from "../../src/intelligence/selector.js";
import {
  COVERAGE_OPERATION,
  LOCAL_TASK_DECOY_KEY_LABEL,
  LocalAuthority,
  coveredNamespace,
} from "../../src/local-recompile/authority.js";
import { AUTHORITY_PENDING_MAX, SOURCE_REFS_MAX } from "../../src/local-recompile/limits.js";
import { acceptMessage, type AuthorityReply } from "../../src/local-recompile/worker-protocol.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { MemoryStorage } from "../../src/storage/memory.js";

// Must match LOCAL_TASK_DECOY_KEY_LABEL in src/local-recompile/authority.ts.
const DECOY_LABEL = "local-recompile-decoy";
const REQUEST_ID = "ab".repeat(16);
const DESCRIPTOR = Object.freeze({
  runtime_tag: "qwen2.5:1.5b",
  manifest_digest: "1".repeat(64),
  endpoint: Object.freeze({ address: "127.0.0.1", port: 11434 }),
});

afterEach(() => vi.restoreAllMocks());

function binding(result: LocalBindingDescription = { ok: true, epoch: 1, descriptor: DESCRIPTOR }) {
  return { describeVerifiedLocalBinding: vi.fn((_surface: string, _epoch?: number) => result) };
}

function setup(options: { policy?: PrincipalPolicy; result?: LocalBindingDescription; identities?: number } = {}) {
  const masterKey = generateRandomKey();
  const labels: string[] = [];
  const issued: Uint8Array[] = [];
  const deriveKey = vi.fn((key: Uint8Array, label: string) => {
    labels.push(label);
    const derived = deriveNamespaceKey(key, label);
    issued.push(derived);
    return derived;
  });
  const stored = Array.from({ length: options.identities ?? 1 }, (_, i) =>
    createIdentity(`writer-${i}`, generateRandomKey(), "passphrase").storedIdentity);
  const authority = new LocalAuthority({
    binding: binding(options.result),
    policy: Object.freeze(options.policy ?? DEFAULT_POLICY),
    masterKey,
    identities: () => stored,
    deriveKey,
  });
  authority.arm();
  return { authority, deriveKey, labels, issued, masterKey, stored };
}

function refs(count: number, namespace = "notes") {
  return Array.from({ length: count }, (_, i) => ({ namespace, key: `entry-${i}` }));
}

const TIER1_STATE_READ: PrincipalPolicy = {
  ...DEFAULT_POLICY,
  tier1_always_approve: [...DEFAULT_POLICY.tier1_always_approve, "state_read"],
  tier3_always_allow: DEFAULT_POLICY.tier3_always_allow.filter((op) => op !== "state_read"),
};

describe("local task authority", () => {
  it("pins the decoy label and the coverage operation", () => {
    expect(LOCAL_TASK_DECOY_KEY_LABEL).toBe(DECOY_LABEL);
    expect(COVERAGE_OPERATION).toBe("state_read");
  });

  it("coverage is true only for an unreserved namespace while state_read is auto-allowed and not Tier 1", () => {
    expect(coveredNamespace(DEFAULT_POLICY, "notes")).toBe(true);
    expect(coveredNamespace(DEFAULT_POLICY, "_identities")).toBe(false);
    expect(coveredNamespace(DEFAULT_POLICY, "_local_results")).toBe(false);
    expect(coveredNamespace(TIER1_STATE_READ, "notes")).toBe(false);
    expect(coveredNamespace({ ...DEFAULT_POLICY, tier1_always_approve: [...DEFAULT_POLICY.tier1_always_approve, "state_read"] }, "notes")).toBe(false);
    expect(coveredNamespace({ ...DEFAULT_POLICY, tier3_always_allow: [] }, "notes")).toBe(false);
  });

  it.each([
    ["one covered ref", { count: 1, policy: DEFAULT_POLICY }],
    ["32 covered refs", { count: 32, policy: DEFAULT_POLICY }],
    ["one uncovered ref", { count: 1, policy: TIER1_STATE_READ }],
    ["32 uncovered refs", { count: 32, policy: TIER1_STATE_READ }],
  ])("authority derives the same number of keys whether coverage passes or fails: %s", (_label, row) => {
    const { authority, deriveKey, labels } = setup({ policy: row.policy });
    authority.register({ request_id: REQUEST_ID, refs: refs(row.count) });
    authority.reply(REQUEST_ID);
    expect(deriveKey).toHaveBeenCalledTimes(SOURCE_REFS_MAX);
    const decoys = labels.filter((label) => label === DECOY_LABEL).length;
    const covered = row.policy === DEFAULT_POLICY ? row.count : 0;
    expect(decoys).toBe(SOURCE_REFS_MAX - covered);
  });

  it("the derivation count is the same for a refused binding and an unknown request", () => {
    const refused = setup({ result: { ok: false, refusal: "not_loopback" } });
    refused.authority.register({ request_id: REQUEST_ID, refs: refs(3) });
    expect(refused.authority.reply(REQUEST_ID)).toMatchObject({ outcome: "refused", cause: "not_loopback" });
    expect(refused.deriveKey).toHaveBeenCalledTimes(SOURCE_REFS_MAX);
    const unknown = setup();
    expect(unknown.authority.reply(REQUEST_ID)).toMatchObject({ outcome: "refused", cause: "request_unknown" });
    expect(unknown.deriveKey).toHaveBeenCalledTimes(SOURCE_REFS_MAX);
  });

  it("a covered job gets one key per ref, equal to the namespace key, and every derived slot is zeroed after", () => {
    const { authority, issued, masterKey } = setup();
    authority.register({ request_id: REQUEST_ID, refs: [{ namespace: "notes", key: "a" }, { namespace: "diary", key: "b" }] });
    const reply = authority.reply(REQUEST_ID);
    expect(reply.outcome).toBe("granted");
    if (reply.outcome !== "granted") return;
    expect(reply.keys).toEqual([deriveNamespaceKey(masterKey, "notes"), deriveNamespaceKey(masterKey, "diary")]);
    expect(reply.descriptor).toEqual(DESCRIPTOR);
    expect(reply.writers).toHaveLength(1);
    for (const slot of issued) expect(slot.every((byte) => byte === 0)).toBe(true);
    expect(acceptMessage("to_worker", reply)).not.toBeNull();
  });

  it("an uncovered ref yields a refusal and no key bytes in the reply", () => {
    const { authority, issued } = setup();
    authority.register({ request_id: REQUEST_ID, refs: [{ namespace: "notes", key: "a" }, { namespace: "_identities", key: "b" }] });
    const reply = authority.reply(REQUEST_ID);
    expect(reply).toEqual({ type: "authority_reply", request_id: REQUEST_ID, outcome: "refused", cause: "uncovered" });
    expect(Object.keys(reply)).not.toContain("keys");
    for (const slot of issued) expect(slot.every((byte) => byte === 0)).toBe(true);
  });

  it("a binding refusal is passed through as the cause", () => {
    const { authority } = setup({ result: { ok: false, refusal: "epoch_changed" } });
    authority.register({ request_id: REQUEST_ID, refs: refs(1) });
    expect(authority.reply(REQUEST_ID)).toMatchObject({ outcome: "refused", cause: "epoch_changed" });
  });

  it("a writer table over the message cap refuses the job", () => {
    const { authority } = setup({ identities: 1_100 });
    authority.register({ request_id: REQUEST_ID, refs: refs(1) });
    const reply: AuthorityReply = authority.reply(REQUEST_ID);
    expect(reply).toMatchObject({ outcome: "refused", cause: "writer_table_too_large" });
  });

  it("a request is answered once, and the pending table stays bounded", () => {
    const { authority } = setup();
    for (let i = 0; i < AUTHORITY_PENDING_MAX * 3; i += 1) {
      authority.register({ request_id: i.toString(16).padStart(32, "0"), refs: refs(1) });
    }
    expect(authority.pendingCount).toBe(AUTHORITY_PENDING_MAX);
    // The oldest entries were evicted first.
    expect(authority.reply("0".repeat(32))).toMatchObject({ outcome: "refused", cause: "request_unknown" });
    const newest = (AUTHORITY_PENDING_MAX * 3 - 1).toString(16).padStart(32, "0");
    expect(authority.reply(newest).outcome).toBe("granted");
    expect(authority.reply(newest)).toMatchObject({ outcome: "refused", cause: "request_unknown" });
  });

  it("authority never touches the gate's baseline", async () => {
    const baseline = new BaselineTracker(new MemoryStorage(), generateRandomKey());
    const before = structuredClone(baseline.getProfile());
    const spies = (["recordToolCall", "recordNamespaceAccess", "recordNamespaceRead", "recordCounterparty", "recordSign"] as const)
      .map((name) => vi.spyOn(BaselineTracker.prototype, name));
    const { authority } = setup();
    authority.register({ request_id: REQUEST_ID, refs: refs(4) });
    authority.reply(REQUEST_ID);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    expect(baseline.getProfile()).toEqual(before);
  });
});
