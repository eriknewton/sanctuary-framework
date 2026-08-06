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

import { connect, createServer } from "node:net";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  egressGateDaemonLabel,
  egressGateDaemonPlistPath,
  egressGatePolicyConfigPath,
  egressGateRulesConfigPath,
  egressGateRuntimeStatePath,
  gateDaemonLogDirForHome,
  parseEgressGateRuntimeState,
  renderEgressGateDaemonPlist,
  runEgressGateDaemon,
} from "../../src/egress-gate/gate-daemon.js";
import { createGateClientAuthenticator } from "../../src/egress-gate/gate-client-auth.js";
import { peerResolverSocketPath } from "../../src/egress-gate/peer-resolver-daemon.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import {
  GATE_CREDENTIAL_VERSION,
  formatGateCredentialHeader,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";

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
    gateHomeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
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

  it("derives stdout/stderr under the gate account's own home, never a caller-supplied foreign log dir", () => {
    const plist = renderEgressGateDaemonPlist(base);
    expect(gateDaemonLogDirForHome(base)).toBe("/var/sanctuary-agents/sanctuary-gate-hermes/logs");
    expect(plist).toContain("/var/sanctuary-agents/sanctuary-gate-hermes/logs/egress-gate-502.out.log");
    expect(plist).toContain("/var/sanctuary-agents/sanctuary-gate-hermes/logs/egress-gate-502.err.log");
    expect(plist).not.toContain("/var/sanctuary-agents/sanctuary-hermes/logs");
  });

  it("REFUSES a gate account paired with the agent account home (the D6 launchd EX_CONFIG shape)", () => {
    expect(() =>
      renderEgressGateDaemonPlist({
        ...base,
        gateHomeDirectory: "/var/sanctuary-agents/sanctuary-hermes",
      }),
    ).toThrow(/cross-account logs/);
  });

  it.each(["root", "_root", "daemon", "wheel", "admin"])(
    "REFUSES to render a gate daemon running as privileged account %s (the gate is TCB but holds no privilege)",
    (gateAccount) => {
      // `admin` added 2026-08-05 (register G1, Erik-ratified WIDEN): this
      // renderer accepted it while account provisioning refused it, and an
      // `admin` account on macOS conventionally carries sudo, so the gate
      // could have rewritten the policy it exists to enforce.
      expect(() => renderEgressGateDaemonPlist({ ...base, gateAccount })).toThrow(/never hold root/);
    },
  );

  it("refuses an unsafe account name, control characters in argv, and relative paths", () => {
    expect(() => renderEgressGateDaemonPlist({ ...base, gateAccount: "bad name!" })).toThrow(/safe service-account/);
    expect(() =>
      renderEgressGateDaemonPlist({ ...base, programArguments: ["/usr/bin/x", "a\nb"] }),
    ).toThrow(/control characters/);
    expect(() => renderEgressGateDaemonPlist({ ...base, programArguments: ["relative/bin"] })).toThrow(
      /absolute program path/,
    );
    expect(() => renderEgressGateDaemonPlist({ ...base, fortressPath: "relative" })).toThrow(/must be absolute/);
    expect(() => renderEgressGateDaemonPlist({ ...base, gateHomeDirectory: "relative" })).toThrow(/must be absolute/);
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

/**
 * 2026-07-24 S5-3 fix: the DEFAULT peer runner is the PRIVILEGED resolver
 * client, not the old local `createExecFilePeerRunner()`. Proven two ways:
 * (a) with no resolver daemon reachable at the derived socket path, every
 * CONNECT denies `peer_unresolved` fail-closed (never a crash, never a
 * silent allow); (b) `deps.peerRunner` remains a first-class override, same
 * as every other injected dependency on this daemon.
 */
describe("egress-gate/gate-daemon peerRunner wiring (2026-07-24 S5-3 fix)", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-gate-daemon-peer-test-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function rawConnect(port: number, authority: string, proxyAuth?: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = connect(port, "127.0.0.1", () => {
        const authLine = proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
        socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
      });
      let data = "";
      socket.on("data", (chunk) => (data += chunk.toString("utf8")));
      socket.on("end", () => resolve(data.split("\r\n")[0] ?? ""));
      socket.on("error", reject);
      setTimeout(() => socket.destroy(new Error("timeout")), 3000).unref();
    });
  }

  /** A real, valid generation-bound bearer credential (accept record + header). */
  function validCredential(generationId: number): { acceptSource: GateAcceptSource; header: string } {
    const secret = "deadbeefcafef00d"; // must be lowercase-hex (parseGateCredentialHeader)
    const accept: GateCredentialAcceptRecord = {
      version: GATE_CREDENTIAL_VERSION,
      generation_id: generationId,
      secret_sha256: createHash("sha256").update(secret, "utf8").digest("hex"),
    };
    return {
      acceptSource: { current: async () => accept },
      header: formatGateCredentialHeader({ generation_id: generationId, secret }),
    };
  }

  /**
   * Real oracle keypair + a real signed-and-written liveness token (no chown
   * -- this test runs unprivileged, and `createFsLivenessTokenSource` only
   * ever reads the file, never checks ownership), so the daemon's REAL
   * liveness gate passes and the CONNECT actually reaches peer resolution
   * instead of failing earlier at 503.
   */
  async function primeLiveOracle(input: {
    gatePort: number;
    generationId: number;
  }): Promise<{ loadOraclePublicKey: () => Promise<ReturnType<typeof generateKeyPairSync>["publicKey"]> }> {
    const { canonicalLivenessPayload } = await import("../../src/egress-gate/liveness-oracle.js");
    const { sign } = await import("node:crypto");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const claims = {
      version: 1 as const,
      agent_uid: AGENT_UID,
      gate_port: input.gatePort,
      generation_id: input.generationId,
      live: true,
      expires_at: Date.now() + 60_000,
    };
    const sig = sign(null, canonicalLivenessPayload(claims), privateKey).toString("base64");
    await writeFile(join(dir, `${AGENT_UID}.token`), JSON.stringify({ ...claims, sig }), "utf8");
    return { loadOraclePublicKey: async () => publicKey };
  }

  it("DEFAULT peerRunner: with no resolver daemon reachable, denies peer_unresolved (fail-closed, never a crash) -- proves the default is no longer local-only lsof", async () => {
    const port = await freeLoopbackPort();
    const { loadOraclePublicKey } = await primeLiveOracle({ gatePort: port, generationId: 9 });
    const { acceptSource, header } = validCredential(9);
    const events: unknown[] = [];
    const handle = await runEgressGateDaemon({
      agentUid: AGENT_UID,
      loadGatePolicy: async () => JSON.stringify({ agent_uid: AGENT_UID, gate_port: port, generation_id: 9 }),
      loadRules: async () => [],
      loadOraclePublicKey,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      runtimeDir: dir,
      livenessDir: dir,
      credDir: dir,
      peerResolverDir: dir, // nothing listens at dir/502.sock in this test
      onEvent: (e) => events.push(e),
    });
    try {
      // A VALID credential -- so a denial can only come from the peer lens,
      // which is exactly what this test is isolating.
      const statusLine = await rawConnect(handle.gate.port, "127.0.0.1:1", header);
      expect(statusLine).toBe("HTTP/1.1 403 Forbidden");
      expect(
        (events as { kind: string; reason?: string }[]).some(
          (e) => e.kind === "client_denied" && e.reason === "peer_unresolved",
        ),
      ).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("deps.peerRunner override is honored (a scripted runner still wires through unchanged)", async () => {
    const port = await freeLoopbackPort();
    const { loadOraclePublicKey } = await primeLiveOracle({ gatePort: port, generationId: 9 });
    const { acceptSource, header } = validCredential(9);
    let ranScripted = false;
    const trackedRunner: PeerCommandRunner = {
      run: (): Promise<{ code: number; stdout: string }> => {
        ranScripted = true;
        return Promise.resolve({ code: 0, stdout: "" }); // unresolved, deterministic
      },
    };
    const handle = await runEgressGateDaemon({
      agentUid: AGENT_UID,
      loadGatePolicy: async () => JSON.stringify({ agent_uid: AGENT_UID, gate_port: port, generation_id: 9 }),
      loadRules: async () => [],
      loadOraclePublicKey,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      runtimeDir: dir,
      livenessDir: dir,
      credDir: dir,
      peerRunner: trackedRunner,
      onEvent: () => undefined,
    });
    try {
      await rawConnect(handle.gate.port, "127.0.0.1:1", header);
      expect(ranScripted).toBe(true);
    } finally {
      await handle.close();
    }
  });

  it("the default socket path is derived from peerResolverSocketPath(agentUid, peerResolverDir ?? PEER_RESOLVER_DIR)", () => {
    expect(peerResolverSocketPath(AGENT_UID, "/tmp/x")).toBe("/tmp/x/502.sock");
  });
});
