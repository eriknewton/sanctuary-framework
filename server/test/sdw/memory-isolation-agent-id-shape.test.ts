/**
 * SDW owner pin: the agent id that establishes, claims or receives the pin
 * must have the wrapped harness id form.
 *
 * Capability: the one-owner-per-fortress binding for Sovereign Data Warehouse
 * memory can only ever be pinned to an id `sanctuary wrap` could have minted
 * (`<harness-kind>:fortress-<16 hex>`), through every entry point of the
 * shared rule (the MCP guard, the four memory-file CLI verbs' check and
 * precheck, `sdw-owner claim`, `sdw-owner transfer`'s new owner), so an
 * operator or a misconfigured harness cannot pin the store to a principal the
 * wrapped server never presents. A malformed legacy pin stays transferable.
 * Register row `SDW-OWNER-PIN-AGENT-ID-SHAPE-01`.
 *
 * Fail-before: on the base tree every "refuses" case below is red (the rule
 * accepted any non-empty string and pinned the store to it) and every
 * "accepts" case is green. This file imports only the shared rule's entry
 * points, never the pattern, so it compiles against the base tree.
 */
import { describe, expect, it } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  checkOrEstablishSdwOwnerPin,
  claimSdwOwnerForOperator,
  createPersistentMultiAgentIsolationGuard,
  precheckSdwOwnerPin,
  readSdwOwnerPin,
  transferSdwOwnerForOperator,
} from "../../src/sdw/memory-isolation.js";
import { createSdwOwnerPinIfAbsent } from "../../src/sdw/write-gate.js";
import { LOCAL_HARNESS_KINDS } from "../../src/contracts/v1.1/local-agent-records.js";

const MASTER = new Uint8Array(32).fill(43);
const FORTRESS_ID = "fortress:shape-test";
const OWNER_REF = "fleet-self";
const NOW = () => "2026-09-28T00:00:00.000Z";
// 16 = the hex characters fortressIdFromStoragePath keeps of a sha256
// (dashboard/v1_1/wiring.ts); must match WRAPPED_AGENT_ID_FORTRESS_HEX_LENGTH
// in src/sdw/memory-isolation.ts.
const GOOD = "claude_code:fortress-00000000000000a1";
const GOOD_OTHER = "cursor:fortress-00000000000000b2";
const MALFORMED: readonly string[] = [
  "cli-ingest",
  "claude_code:ic16",
  "codex:fortress-0000000000000001", // not a LOCAL_HARNESS_KINDS member
  "claude_code:fortress-00000000000000A1", // uppercase hex
  "claude_code:fortress-000000000000001", // 15 hex characters
  "claude_code:fortress-00000000000000a1 ", // trailing space
  "fortress-00000000000000a1", // no harness kind
  "claude_code:00000000000000a1", // no fortress- prefix
];

function base() {
  return { storage: new MemoryStorage(), masterKey: MASTER, fortressId: FORTRESS_ID, ownerRef: OWNER_REF, now: NOW };
}

describe("SDW owner pin agent id shape (shared rule, every entry point)", () => {
  it("checkOrEstablishSdwOwnerPin refuses a malformed id BEFORE establishing anything", async () => {
    for (const bad of MALFORMED) {
      const b = base();
      expect(await checkOrEstablishSdwOwnerPin({ ...b, agentId: bad }), bad).toEqual({
        allowed: false,
        reason: "owner_identity_malformed",
      });
      // Nothing was written: the store is still unpinned, so a later wrapped
      // caller can still establish it.
      expect((await readSdwOwnerPin(b.storage, MASTER)).status, bad).toBe("absent");
    }
  });

  it("checkOrEstablishSdwOwnerPin accepts every harness kind in the wrapped form", async () => {
    for (const kind of LOCAL_HARNESS_KINDS) {
      const b = base();
      const id = `${kind}:fortress-0123456789abcdef`;
      expect(await checkOrEstablishSdwOwnerPin({ ...b, agentId: id }), id).toEqual({ allowed: true });
      const pin = await readSdwOwnerPin(b.storage, MASTER);
      expect(pin.status).toBe("valid");
      if (pin.status === "valid") expect(pin.data.agent_id).toBe(id);
    }
  });

  it("precheckSdwOwnerPin refuses a malformed id without reading the store as fresh", async () => {
    for (const bad of MALFORMED) {
      const b = base();
      expect(await precheckSdwOwnerPin({ storage: b.storage, masterKey: MASTER, fortressId: FORTRESS_ID, ownerRef: OWNER_REF, agentId: bad }), bad).toEqual({
        status: "refuse",
        reason: "owner_identity_malformed",
      });
    }
    const b = base();
    expect(await precheckSdwOwnerPin({ storage: b.storage, masterKey: MASTER, fortressId: FORTRESS_ID, ownerRef: OWNER_REF, agentId: GOOD })).toEqual({ status: "fresh" });
  });

  it("the MCP guard (createPersistentMultiAgentIsolationGuard) refuses a malformed wrap-time id", async () => {
    for (const bad of MALFORMED) {
      const b = base();
      const guard = createPersistentMultiAgentIsolationGuard({ ...b, ownerIdentity: () => bad });
      expect(await guard("memory_count"), bad).toEqual({ allowed: false, reason: "owner_identity_malformed" });
      expect((await readSdwOwnerPin(b.storage, MASTER)).status).toBe("absent");
    }
    const b = base();
    const guard = createPersistentMultiAgentIsolationGuard({ ...b, ownerIdentity: () => GOOD });
    expect(await guard("memory_count")).toEqual({ allowed: true });
  });

  it("claimSdwOwnerForOperator refuses a malformed id and leaves the store unclaimed", async () => {
    for (const bad of MALFORMED) {
      const b = base();
      expect(await claimSdwOwnerForOperator({ ...b, agentId: bad }), bad).toEqual({ status: "agent_id_malformed" });
      expect((await readSdwOwnerPin(b.storage, MASTER)).status).toBe("absent");
    }
    const b = base();
    expect(await claimSdwOwnerForOperator({ ...b, agentId: GOOD })).toEqual({ status: "claimed" });
  });

  it("transferSdwOwnerForOperator refuses a malformed NEW owner and keeps the current pin", async () => {
    const b = base();
    expect(await claimSdwOwnerForOperator({ ...b, agentId: GOOD })).toEqual({ status: "claimed" });
    for (const bad of MALFORMED) {
      expect(await transferSdwOwnerForOperator({ ...b, expectedAgentId: GOOD, newAgentId: bad }), bad).toEqual({ status: "agent_id_malformed" });
      const pin = await readSdwOwnerPin(b.storage, MASTER);
      expect(pin.status).toBe("valid");
      if (pin.status === "valid") expect(pin.data.agent_id).toBe(GOOD);
    }
    expect(await transferSdwOwnerForOperator({ ...b, expectedAgentId: GOOD, newAgentId: GOOD_OTHER })).toEqual({ status: "transferred" });
  });

  it("a malformed LEGACY pin stays recoverable: transfer's expected owner is exempt from the shape rule", async () => {
    const b = base();
    // Written directly, the way a pre-rule operator claim could have.
    expect(
      await createSdwOwnerPinIfAbsent(b.storage, MASTER, {
        version: 1,
        fortress_id: FORTRESS_ID,
        owner_ref: OWNER_REF,
        agent_id: "cli-ingest",
        pinned_at: NOW(),
      }),
    ).not.toBe("unsupported");
    // The wrapped caller is still refused by the ordinary comparison ...
    expect(await checkOrEstablishSdwOwnerPin({ ...b, agentId: GOOD })).toEqual({ allowed: false, reason: "owner_scope_conflict" });
    // ... and the interactive transfer away from the legacy id is allowed.
    expect(await transferSdwOwnerForOperator({ ...b, expectedAgentId: "cli-ingest", newAgentId: GOOD })).toEqual({ status: "transferred" });
    expect(await checkOrEstablishSdwOwnerPin({ ...b, agentId: GOOD })).toEqual({ allowed: true });
  });
});
