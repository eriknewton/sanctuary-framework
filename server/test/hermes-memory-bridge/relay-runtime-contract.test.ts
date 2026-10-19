import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CHILD_READY_TIMEOUT_MS,
  validateHermesBridgeEnvironment,
  assertHermesBridgeBindings,
  RELAY_CHILD_EXIT_BOUND_MS,
  RELAY_CHILD_REAP_BOUND_MS,
  RELAY_CHILD_SIGTERM_GRACE_MS,
} from "../../src/hermes-memory-bridge/process-shell.js";
import { PROBE_REPLY_BOUND_MS } from "../../src/hermes-memory-bridge/constants.js";

const root = new URL("../../../", import.meta.url);
const swiftPath = "hermes-memory-relay/Sources/HermesMemoryRelayCore/Core.swift";

describe("relay runtime shared contracts", () => {
  it("relayStartupBudgetPinsNameRealSwiftDeclarations", async () => {
    const swift = await readFile(new URL(swiftPath, root), "utf8");
    const node = await readFile(new URL("server/src/hermes-memory-bridge/process-shell.ts", root), "utf8");
    const pairs = [
      ["childReadyTimeoutMilliseconds", CHILD_READY_TIMEOUT_MS],
      ["relayChildReapBoundMilliseconds", RELAY_CHILD_REAP_BOUND_MS],
      ["childSigtermGraceMilliseconds", RELAY_CHILD_SIGTERM_GRACE_MS],
      ["probeReplyBoundMilliseconds", PROBE_REPLY_BOUND_MS],
    ] as const;
    for (const [name, expected] of pairs) {
      const match = swift.match(new RegExp(`static let ${name} = ([0-9_]+)`));
      expect(match, name).not.toBeNull();
      expect(Number(match![1]!.replaceAll("_", "")), name).toBe(expected);
    }
    for (const name of ["childReadyTimeoutMilliseconds", "childSigtermGraceMilliseconds", "relayChildExitBoundMilliseconds"]) {
      expect(node).toContain(`Must match \`${name}\` in ${swiftPath}.`);
    }
    expect(swift).toContain("Must match CHILD_READY_TIMEOUT_MS in server/src/hermes-memory-bridge/process-shell.ts.");
    expect(swift).toContain("Must match RELAY_CHILD_SIGTERM_GRACE_MS in server/src/hermes-memory-bridge/process-shell.ts.");
    expect(swift).toContain("relayChildExitBoundMilliseconds = probeReplyBoundMilliseconds + childSigtermGraceMilliseconds");
    expect(RELAY_CHILD_EXIT_BOUND_MS).toBe(PROBE_REPLY_BOUND_MS + RELAY_CHILD_SIGTERM_GRACE_MS);
  });

  it("relayFixtureMatchesCanonicalSwiftBytes", async () => {
    const canonical = await readFile(new URL("hermes-memory-relay/Tests/HermesMemoryRelayCoreTests/Fixtures/relay-frames.json", root));
    const node = await readFile(fileURLToPath(new URL("./fixtures/relay-frames.json", import.meta.url)));
    expect(node.equals(canonical)).toBe(true);
  });
});


describe("native relay environment admission", () => {
  const env = {
    HOME: "/tmp/hmr-fixture", LANG: "C", TMPDIR: "/tmp/hmr-fixture",
    HERMES_MEMORY_AGENT_ID: "hermes", HERMES_MEMORY_FORTRESS_ID: "hermes-memory",
    HERMES_MEMORY_BRIDGE_IDENTITY: "a".repeat(64),
  };
  it("spawnUsesOnlyConfiguredEnvironment", () => {
    const native = { ...env, __CF_USER_TEXT_ENCODING: "0x1F5:0x0:0x0" };
    expect(validateHermesBridgeEnvironment(env, "darwin", 501)).toBe(env);
    expect(validateHermesBridgeEnvironment(native, "darwin", 501)).toBe(native);
    for (const planted of [
      { ...env, NODE_OPTIONS: "--trace-warnings" },
      { ...native, UNEXPECTED: "1" },
      { ...env, __CF_USER_TEXT_ENCODING: "0x1f5:0x0:0x0" },
      { ...env, __CF_USER_TEXT_ENCODING: "0x1F6:0x0:0x0" },
      { ...env, __CF_USER_TEXT_ENCODING: "0x1F5:0x0:0x0\n" },
      { ...env, __CF_USER_TEXT_ENCODING: "malformed" },
    ]) expect(() => validateHermesBridgeEnvironment(planted, "darwin", 501), "spawnUsesOnlyConfiguredEnvironment").toThrow();
    for (const platform of ["linux", "win32", "freebsd"] as const) {
      expect(() => validateHermesBridgeEnvironment(native, platform, 501), "nonDarwinHasNoEncodingTolerance").toThrow();
    }
    expect(() => validateHermesBridgeEnvironment(native, "darwin", undefined)).toThrow();
  });
});

// These state-machine witnesses bind the runtime regression ledger to the shared Node consumer.
import { HermesProbeWaiter } from "../../src/hermes-memory-bridge/probe-waiter.js";
import { ABANDONED_PROBE_NONCE_CAP } from "../../src/hermes-memory-bridge/constants.js";

describe("relay probe consumer contracts", () => {
  it("issuedNonceIsNeverEvicted", () => {
    let issued = 0;
    const waiter = new HermesProbeWaiter(() => (++issued).toString(16).padStart(32, "0"));
    for (let i = 0; i < ABANDONED_PROBE_NONCE_CAP; i++) {
      const nonce = (i + 1).toString(16).padStart(32, "0");
      expect(waiter.start(`e${i}`, "c1").actions).toHaveLength(1);
      waiter.timeout(`e${i}`, nonce);
    }
    const retained = waiter.snapshot().abandoned;
    for (let wave = 0; wave < 3; wave++) {
      expect(waiter.start(`overflow${wave}`, "c2").refusal, "issuedNonceIsNeverEvicted").toBe("abandoned_full");
      expect(waiter.snapshot().abandoned, "issuedNonceIsNeverEvicted").toEqual(retained);
    }
    expect(waiter.reply({ kind: "probe_reply", connectionId: "c1", nonce: retained[0]!.nonce })).toEqual({ actions: [] });
  });

  it("wrongProbePairIsImmediatelyFatal", () => {
    const nonce = "a".repeat(32);
    const waiter = new HermesProbeWaiter(() => nonce);
    waiter.start("entry", "c1");
    for (const reply of [
      { kind: "probe_reply" as const, connectionId: "c2", nonce },
      { kind: "probe_reply" as const, connectionId: "c1", nonce: "b".repeat(32) },
    ]) expect(waiter.reply(reply).fatal, "wrongProbePairIsImmediatelyFatal").toBe("unmatched_probe_reply");
  });

  it("probeWaitStopsOnTransportTermination", () => {
    for (const termination of ["closed", "relay_shutdown", "private_eof"]) {
      const waiter = new HermesProbeWaiter(() => "a".repeat(32));
      waiter.start("entry", "c1");
      const result = termination === "closed" ? waiter.connectionClosed("c1") : waiter.stop();
      expect(result.actions, "probeWaitStopsOnTransportTermination").toMatchObject([{ kind: "refused", entryRef: "entry" }]);
      expect(waiter.snapshot().live, "probeWaitStopsOnTransportTermination").toBeUndefined();
    }
  });
});


describe("bridge composition readiness", () => {
  it("requiredBridgeDependenciesRefuseStartup", () => {
    const bound = { adapter: true, audit: true, badSignerScanner: true, writer: true };
    expect(() => assertHermesBridgeBindings(bound)).not.toThrow();
    for (const key of Object.keys(bound)) {
      expect(() => assertHermesBridgeBindings({ ...bound, [key]: false }), "requiredBridgeDependenciesRefuseStartup").toThrow();
      expect(() => assertHermesBridgeBindings({ ...bound, [key]: undefined }), "requiredBridgeDependenciesRefuseStartup").toThrow();
    }
  });
});


import { buildMemorySearchResultBytes } from "../../src/hermes-memory-bridge/public-results.js";
import type { MemorySearchResult } from "../../src/sdw/adapters/memory-backend.js";
import { MAX_RESULT_FRAME_BYTES } from "../../src/hermes-memory-bridge/constants.js";

it("realSearchResponseHonorsEncodedCap", () => {
  const row: MemorySearchResult = { passage: {
    passage_id: "seed", owner_ref: "hermes", text: "Cedar lantern fixture text", tags: [], metadata: [],
    created_at: "2026-10-18T00:00:00.000Z", chunk_count: 1, content_hash: "a".repeat(43), provenance_status: "verified",
  }, match_count: 1 };
  // Projection boundary only: the full maximum legal search-shape derivation remains a separate contract.
  let last = buildMemorySearchResultBytes("search", []);
  let count = 1;
  for (; count <= MAX_RESULT_FRAME_BYTES; count++) {
    const result = buildMemorySearchResultBytes("search", Array.from({ length: count }, () => row));
    if (!result.ok) {
      expect(result.reason, "realSearchResponseHonorsEncodedCap").toBe("result_over_cap");
      break;
    }
    last = result;
    // Stop at the first actual byte overflow even if the product's guard was removed.
    expect(result.bytes.byteLength, "realSearchResponseHonorsEncodedCap").toBeLessThanOrEqual(MAX_RESULT_FRAME_BYTES);
  }
  expect(count, "realSearchResponseHonorsEncodedCap").toBeLessThan(MAX_RESULT_FRAME_BYTES);
  expect(last.ok, "realSearchResponseHonorsEncodedCap").toBe(true);
});
