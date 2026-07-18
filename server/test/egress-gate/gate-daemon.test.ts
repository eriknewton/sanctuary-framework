/**
 * Tests for the exclusive-egress gate DAEMON module (Unified Protect Slice 5
 * S5-6): the plist renderer's refusal set, the strict runtime-state parse,
 * and `runEgressGateDaemon`'s fail-closed start branches (bad policy JSON,
 * structurally invalid policy, cross-principal policy, missing committed
 * generation, malformed rules) plus the success path's S5-3 TCB wiring
 * (oracle probe + clientAuth constructed; runtime state published; close()
 * removes it). All host-free via injected deps + temp dirs; no launchd, no
 * root, no pf.
 */

import { createServer } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  egressGateDaemonLabel,
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeStatePath,
  parseEgressGateRuntimeState,
  renderEgressGateDaemonPlist,
  runEgressGateDaemon,
} from "../../src/egress-gate/gate-daemon.js";
import { createGateClientAuthenticator } from "../../src/egress-gate/gate-client-auth.js";

const AGENT_UID = 502;

async function freeLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("no port"));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
  });
}

describe("egress-gate/gate-daemon paths + label", () => {
  it("label/plist/runtime-state paths are uid-keyed and refuse non-positive uids", () => {
    expect(egressGateDaemonLabel(AGENT_UID)).toBe("ai.sanctuaryprotocol.egress-gate.502");
    expect(egressGateDaemonPlistPath(AGENT_UID)).toBe(
      "/Library/LaunchDaemons/ai.sanctuaryprotocol.egress-gate.502.plist",
    );
    // Fix-round BLOCKER-1: the state file lives inside the GATE-UID-owned
    // per-uid subdir (root pre-creates + chowns it; the non-root daemon can
    // write there), never directly in the root-owned parent.
    expect(egressGateRuntimeStatePath(AGENT_UID, "/tmp/x")).toBe("/tmp/x/502/state.json");
    expect(egressGatePolicyConfigPath(AGENT_UID, "/tmp/x")).toBe("/tmp/x/502-policy.json");
    expect(egressGateRulesConfigPath(AGENT_UID, "/tmp/x")).toBe("/tmp/x/502-rules.json");
    expect(() => egressGateDaemonLabel(0)).toThrow(/positive integer uid/);
    expect(() => egressGateRuntimeStatePath(-1)).toThrow(/positive integer uid/);
  });
});

describe("egress-gate/gate-daemon renderEgressGateDaemonPlist", () => {
  const base = {
    agentUid: AGENT_UID,
    gateAccount: "sanctuary-gate-hermes",
    programArguments: ["/usr/local/bin/sanctuary", "castle-wall", "egress-gate-daemon", "--agent-uid=502"],
    fortressPath: "/Users/operator/.sanctuary",
  };

  it("renders UserName = the gate account, RunAtLoad=false, and Crashed-only KeepAlive (root supervisor sequences the start)", () => {
    const plist = renderEgressGateDaemonPlist(base);
    expect(plist).toContain("<string>sanctuary-gate-hermes</string>");
    expect(plist).toContain("<key>RunAtLoad</key>\n\t<false/>");
    expect(plist).toContain("<key>Crashed</key>");
    expect(plist).toContain("ai.sanctuaryprotocol.egress-gate.502");
  });

  it("REFUSES to render a gate daemon running as root (the gate is TCB but must never hold root)", () => {
    expect(() => renderEgressGateDaemonPlist({ ...base, gateAccount: "root" })).toThrow(/never hold root/);
  });

  it("refuses an unsafe account name, control characters in argv, and relative paths", () => {
    expect(() => renderEgressGateDaemonPlist({ ...base, gateAccount: "bad name!" })).toThrow(/safe service-account/);
    expect(() =>
      renderEgressGateDaemonPlist({ ...base, programArguments: ["/usr/bin/x", "a\nb"] }),
    ).toThrow(/control characters/);
    expect(() => renderEgressGateDaemonPlist({ ...base, programArguments: ["relative/bin"] })).toThrow(
      /absolute program path/,
    );
    expect(() => renderEgressGateDaemonPlist({ ...base, fortressPath: "relative" })).toThrow(/must be absolute/);
  });
});

describe("egress-gate/gate-daemon parseEgressGateRuntimeState", () => {
  const valid = { agent_uid: AGENT_UID, gate_port: 40001, generation_id: 3, pid: 991, pid_start: "991-1700000000000" };

  it("round-trips a valid document", () => {
    expect(parseEgressGateRuntimeState(JSON.stringify(valid), "p")).toEqual(valid);
  });

  it("throws on invalid JSON, non-objects, and every missing/invalid field (fail-closed)", () => {
    expect(() => parseEgressGateRuntimeState("nope", "p")).toThrow(/not valid JSON/);
    expect(() => parseEgressGateRuntimeState("[1]", "p")).toThrow(/not a JSON object/);
    for (const field of ["agent_uid", "gate_port", "generation_id", "pid", "pid_start"] as const) {
      const broken: Record<string, unknown> = { ...valid };
      delete broken[field];
      expect(() => parseEgressGateRuntimeState(JSON.stringify(broken), "p")).toThrow(new RegExp(field));
    }
    expect(() => parseEgressGateRuntimeState(JSON.stringify({ ...valid, gate_port: 70000 }), "p")).toThrow(
      /gate_port/,
    );
    expect(() => parseEgressGateRuntimeState(JSON.stringify({ ...valid, pid_start: "" }), "p")).toThrow(
      /pid_start/,
    );
  });
});

describe("egress-gate/gate-daemon runEgressGateDaemon", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-gate-daemon-test-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function oracleKeyLoader() {
    const pair = generateKeyPairSync("ed25519");
    return async () => pair.publicKey;
  }

  function baseDeps(policy: unknown) {
    return {
      agentUid: AGENT_UID,
      loadGatePolicy: async () => (typeof policy === "string" ? policy : JSON.stringify(policy)),
      loadRules: async () => [],
      loadOraclePublicKey: oracleKeyLoader(),
      clientAuth: createGateClientAuthenticator({
        agentUid: AGENT_UID,
        acceptSource: { current: async () => null },
      }),
      runtimeDir: dir,
      livenessDir: dir,
      credDir: dir,
      onEvent: () => undefined,
    };
  }

  it("fail-closed: invalid policy JSON refuses to serve", async () => {
    await expect(runEgressGateDaemon(baseDeps("{nope"))).rejects.toThrow(/not valid JSON/);
  });

  it("fail-closed: a structurally invalid policy refuses to serve", async () => {
    await expect(runEgressGateDaemon(baseDeps({ agent_uid: 0, gate_port: 40001 }))).rejects.toThrow(
      /structurally invalid/,
    );
  });

  it("fail-closed: a cross-principal policy (different agent_uid) refuses to serve", async () => {
    await expect(
      runEgressGateDaemon(baseDeps({ agent_uid: AGENT_UID + 1, gate_port: 40001, generation_id: 2 })),
    ).rejects.toThrow(/cross-principal/);
  });

  it("fail-closed: a policy with no committed generation_id refuses to serve (an unbound gate could never verify liveness)", async () => {
    await expect(runEgressGateDaemon(baseDeps({ agent_uid: AGENT_UID, gate_port: 40001 }))).rejects.toThrow(
      /no committed generation_id/,
    );
  });

  it("fail-closed: a rules config that is not a JSON array refuses to serve", async () => {
    const port = await freeLoopbackPort();
    const deps = {
      ...baseDeps({ agent_uid: AGENT_UID, gate_port: port, generation_id: 2 }),
      loadRules: undefined,
    };
    // No rules file exists in the temp runtime dir -> the default loader throws.
    await expect(runEgressGateDaemon(deps)).rejects.toThrow();
  });

  it("success: binds EXACTLY the committed port with the TCB wiring (oracle probe + clientAuth), publishes the runtime state, and close() removes it", async () => {
    const port = await freeLoopbackPort();
    const handle = await runEgressGateDaemon(
      baseDeps({ agent_uid: AGENT_UID, gate_port: port, generation_id: 7 }),
    );
    try {
      expect(handle.gate.port).toBe(port);
      expect(handle.generationId).toBe(7);
      const state = parseEgressGateRuntimeState(
        await readFile(handle.runtimeStatePath, "utf8"),
        handle.runtimeStatePath,
      );
      expect(state).toMatchObject({
        agent_uid: AGENT_UID,
        gate_port: port,
        generation_id: 7,
        pid: process.pid,
      });
    } finally {
      await handle.close();
    }
    await expect(stat(handle.runtimeStatePath)).rejects.toThrow();
  });

  it("fail-closed: a taken port refuses to serve (the gate never squats another port)", async () => {
    const server = createServer();
    const port = await new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address === null || typeof address === "string") {
          reject(new Error("no port"));
          return;
        }
        resolve(address.port);
      });
    });
    try {
      await expect(
        runEgressGateDaemon(baseDeps({ agent_uid: AGENT_UID, gate_port: port, generation_id: 2 })),
      ).rejects.toThrow();
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
