/**
 * Phase S1 — Dashboard → supervisor bridge (response mapping + locked-fortress
 * fail-closed). The transient-key handoff itself is exercised by the socket
 * e2e test; here we cover the mapping logic and the "no resident master ⇒
 * forbidden, never launch" Tier-A invariant without opening a socket.
 */

import { describe, expect, it } from "vitest";
import { SupervisorBridge, mapSupervisorResponse } from "../../src/supervisor/dashboard-bridge.js";
import { mintAuthSecret } from "../../src/supervisor/protocol.js";

describe("mapSupervisorResponse", () => {
  it("maps protecting", () => {
    expect(
      mapSupervisorResponse({ ok: true, kind: "protecting", agent_id: "a", launch_id: "L" }),
    ).toEqual({ ok: true, status: "protecting", agent_id: "a", launch_id: "L" });
  });

  it("maps already-protected to the 200 no-op outcome", () => {
    expect(mapSupervisorResponse({ ok: true, kind: "already-protected", agent_id: "a" })).toEqual({
      ok: true,
      status: "protected",
      agent_id: "a",
    });
  });

  it("maps rotation_in_progress straight through (collapsed to 403 upstream)", () => {
    expect(mapSupervisorResponse({ ok: false, kind: "error", reason: "rotation_in_progress" })).toEqual({
      ok: false,
      reason: "rotation_in_progress",
    });
  });

  it("maps a not_found/unavailable error to unavailable (retryable)", () => {
    expect(mapSupervisorResponse({ ok: false, kind: "error", reason: "not_found" })).toEqual({
      ok: false,
      reason: "unavailable",
    });
  });
});

describe("SupervisorBridge fail-closed (Tier A)", () => {
  it("returns forbidden WITHOUT touching the socket when no master is resident", async () => {
    const bridge = new SupervisorBridge({
      socketPath: "/nonexistent/sup.sock", // would fail if a connect were attempted
      authSecret: mintAuthSecret(),
      resolveTransientKey: () => null, // fortress locked
    });
    const r = await bridge.launchProtect({ agentId: "a1", harness: "claude_code", configPath: "/c" });
    expect(r).toEqual({ ok: false, reason: "forbidden" });
  });

  it("maps an unreachable supervisor to unavailable (retryable)", async () => {
    const bridge = new SupervisorBridge({
      socketPath: "/nonexistent/sup.sock",
      authSecret: mintAuthSecret(),
      resolveTransientKey: () => new Uint8Array([1, 2, 3, 4]),
      timeoutMs: 500,
    });
    const r = await bridge.launchProtect({ agentId: "a1", harness: "claude_code", configPath: "/c" });
    expect(r).toEqual({ ok: false, reason: "unavailable" });
  });
});
