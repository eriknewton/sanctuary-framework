/**
 * A state write's origin is decided by the session that makes it: a sole
 * binding names no author, so its writes are stamped unattributed and classify
 * shared_entangled.
 */
import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools, resolveStateWriteOrigin } from "../../src/cognitive/tools.js";
import { isOriginUnresolvedError, OriginUnresolvedError } from "../../src/cognitive/origin-unresolved.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  fingerprintIdentityId,
  SessionIdentityError,
  UNBOUND_SESSION,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";
import type { SessionBindingState } from "../../src/agent-native/session-binding-state.js";

type Tool = { name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }> };

async function buildTools(bootState: () => SessionBindingState, binding: (identityId: string) => SessionBinding | undefined) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  let identityId: string | undefined;
  const { tools, identityManager } = createL1Tools(stateStore, storage, masterKey, "passphrase", auditLog, {
    sessionBindingBootState: bootState,
    currentSessionBinding: () => (identityId === undefined ? undefined : binding(identityId)),
  });
  await identityManager.load();
  const call = async (name: string, args: Record<string, unknown>) =>
    (tools as Tool[]).find((tool) => tool.name === name)!.handler(args);
  const created = JSON.parse((await call("identity_create", { label: "origin-subject" })).content[0]!.text);
  identityId = created.identity_id as string;
  const rawStamp = async (namespace: string, key: string) => {
    const bytes = await storage.read(namespace, key);
    return bytes === null ? null : (JSON.parse(bytesToString(bytes)).provenance_stamp as Record<string, unknown>);
  };
  const successRows = async () =>
    (await auditLog.query({ operation_type: "state_write", limit: Number.MAX_SAFE_INTEGER })).total;
  return { storage, auditLog, call, rawStamp, successRows, identityId };
}

const boundTo = (identityId: string, binding_source?: "sole_identity" | "launch_variable"): SessionBinding => ({
  identity_id: identityId,
  requester_identity_fingerprint: fingerprintIdentityId(identityId),
  ...(binding_source !== undefined ? { binding_source } : {}),
});

describe("state_write origin", () => {
  it("a sole-bound write is unattributed and classifies shared_entangled", async () => {
    const t = await buildTools(() => "state_BOUND_SOLE_IDENTITY", (id) => boundTo(id, "sole_identity"));
    const result = JSON.parse((await t.call("state_write", { namespace: "notes", key: "k", value: "v" })).content[0]!.text);
    expect(result).toMatchObject({ namespace: "notes", key: "k" });
    const stamp = await t.rawStamp("notes", "k");
    expect(stamp).toMatchObject({ origin_actor: "unattributed", memory_class: "shared_entangled", derived_from: [] });
    expect(Object.hasOwn(stamp!, "derived_from_edges")).toBe(false);
  });
});

/** A binding accessor that counts its reads, so a fault can be placed on exactly one read of a call. */
function countingBinding(onRead: (read: number, identityId: string) => SessionBinding | undefined) {
  let reads = 0;
  const stacks: string[] = [];
  return {
    accessor: (identityId: string) => {
      reads += 1;
      stacks.push(new Error().stack ?? "");
      return onRead(reads, identityId);
    },
    reset() { reads = 0; stacks.length = 0; },
    get reads() { return reads; },
    stacks,
  };
}

/** The number of binding reads one named write makes, and the stack of its last read. */
async function calibrateReads(): Promise<{ k: number; lastStack: string }> {
  const counter = countingBinding((_read, id) => boundTo(id, "launch_variable"));
  const t = await buildTools(() => "state_BOUND_NAMED", counter.accessor);
  counter.reset();
  await t.call("state_write", { namespace: "calibration", key: "k", value: "v" });
  expect(await t.rawStamp("calibration", "k")).toMatchObject({ origin_actor: "agent" });
  return { k: counter.reads, lastStack: counter.stacks.at(-1)! };
}

async function expectFailedWrite(t: Awaited<ReturnType<typeof buildTools>>, namespace: string) {
  const before = await t.successRows();
  await expect(t.call("state_write", { namespace, key: "k", value: "v" })).rejects.toSatisfy(isOriginUnresolvedError);
  expect(await t.storage.read(namespace, "k")).toBeNull();
  expect(await t.successRows()).toBe(before);
}

describe("state_write origin fails closed", () => {
  it("the calibrated last binding read of a write is its stamping read", async () => {
    const { k, lastStack } = await calibrateReads();
    expect(k).toBeGreaterThan(0);
    expect(lastStack).toContain("resolveStateWriteOrigin");
  });

  it("an unreadable binding fails the write and stores nothing", async () => {
    const { k } = await calibrateReads();
    const counter = countingBinding((read, id) => {
      if (read === k) throw new Error("binding read failed");
      return boundTo(id, "launch_variable");
    });
    const t = await buildTools(() => "state_BOUND_NAMED", counter.accessor);
    counter.reset();
    await expectFailedWrite(t, "unreadable");
    expect(counter.reads).toBe(k);
    expect(counter.stacks.at(-1)).toContain("resolveStateWriteOrigin");
  });

  it("a throw in the sole arm fails the write", async () => {
    const t = await buildTools(() => { throw new Error("boot decision unreadable"); }, (id) => boundTo(id, "sole_identity"));
    await expectFailedWrite(t, "sole-throw");
  });

  it("a named unresolved binding fails the write", async () => {
    const { k } = await calibrateReads();
    const counter = countingBinding((read, id) => (read === k ? { identity_id: id } : boundTo(id, "launch_variable")));
    const t = await buildTools(() => "state_BOUND_NAMED", counter.accessor);
    counter.reset();
    await expectFailedWrite(t, "named-unresolved");
    expect(counter.reads).toBe(k);
    expect(counter.stacks.at(-1)).toContain("resolveStateWriteOrigin");
  });
});

const STATES: SessionBindingState[] = [
  "state_BOUND_NAMED",
  "state_BOUND_SOLE_IDENTITY",
  "state_UNBOUND_FLAG_OFF",
  "state_UNBOUND_NO_IDENTITY",
  "state_UNBOUND_SEVERAL_IDENTITIES",
  "state_UNBOUND_UNPROVEN",
  "state_NAMED_EMPTY",
  "state_NAMED_UNRESOLVED",
];
const OWN = "identity-own";
const OTHER = "identity-other";
type Expected = "operator" | "agent" | "unresolved";
// Each binding variant with the origin it yields outside a sole boot, for a write signed by OWN.
const BINDINGS: Array<[string, (() => SessionBinding | undefined) | undefined, Expected]> = [
  ["absent", undefined, "operator"],
  ["undefined", () => undefined, "operator"],
  ["UNBOUND_SESSION", () => UNBOUND_SESSION, "unresolved"],
  ["named own", () => boundTo(OWN, "launch_variable"), "agent"],
  ["named other", () => boundTo(OTHER, "launch_variable"), "operator"],
  ["unresolved", () => ({ identity_id: OWN }), "unresolved"],
  ["expired", () => ({ ...boundTo(OWN, "launch_variable"), expires_at: new Date(Date.now() - 1000).toISOString() }), "unresolved"],
  ["throwing", () => { throw new Error("binding read failed"); }, "unresolved"],
];
const swapIdentity = (expected: Expected, name: string): Expected =>
  name === "named own" ? "operator" : name === "named other" ? "agent" : expected;

const CASES = [undefined, ...STATES].flatMap((state) =>
  BINDINGS.flatMap(([name, binding, expected]) =>
    [OWN, OTHER].map((identityId) => ({
      state: state ?? "no boot decision",
      bootState: state === undefined ? undefined : () => state,
      name,
      binding,
      identityId,
      expected: state === "state_BOUND_SOLE_IDENTITY"
        ? "unattributed"
        : identityId === OWN ? expected : swapIdentity(expected, name),
    })),
  ),
);

describe("the state write origin table", () => {
  it.each(CASES)("no write under a sole binding stores operator: $state, binding $name, writer $identityId", ({ bootState, binding, identityId, expected }) => {
    let bindingReads = 0;
    const counted = binding === undefined ? undefined : () => { bindingReads += 1; return binding(); };
    const resolve = () => resolveStateWriteOrigin({ bootState, binding: counted, identityId });
    if (expected === "unresolved") {
      expect(resolve).toThrow(OriginUnresolvedError);
    } else {
      expect(resolve()).toBe(expected);
    }
    if (expected === "unattributed") expect(bindingReads).toBe(0);
  });

  it.each(BINDINGS)("an unreadable boot decision fails before the binding is read: binding %s", (_name, binding) => {
    let bindingReads = 0;
    const counted = binding === undefined ? undefined : () => { bindingReads += 1; return binding(); };
    const cause = new Error("boot decision unreadable");
    let thrown: unknown;
    try {
      resolveStateWriteOrigin({ bootState: () => { throw cause; }, binding: counted, identityId: OWN });
    } catch (error) {
      thrown = error;
    }
    expect(isOriginUnresolvedError(thrown)).toBe(true);
    expect((thrown as Error).cause).toBe(cause);
    expect(bindingReads).toBe(0);
  });
});

it("only the type brand identifies an undetermined write origin", () => {
  const actual = new OriginUnresolvedError({ cause: new SessionIdentityError() });
  expect(isOriginUnresolvedError(actual)).toBe(true);
  expect(actual.message).toBe("write origin could not be determined");
  expect(actual.cause).toBeInstanceOf(SessionIdentityError);
  for (const error of [new Error(actual.message), { name: actual.name, message: actual.message }, new SessionIdentityError(), null, undefined, "write origin could not be determined"]) {
    expect(isOriginUnresolvedError(error)).toBe(false);
  }
});
