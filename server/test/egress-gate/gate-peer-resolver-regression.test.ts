/**
 * REGRESSION TEST for the Mini1 2026-07-24 drill finding (HIGH): the
 * exclusive-egress gate denied 100% of a confined agent's requests --
 * including valid, on-manifest, correctly-credentialed ones -- because peer
 * resolution (`lsof`, run by the unprivileged gate uid) cannot see a
 * different uid's socket and returned `null` on every real connect.
 * `Review/Sanctuary/drill-evidence-2026-07-24/RESULTS.md`,
 * `Gate_Peer_Resolution_Fix_Build_Spec_2026-07-24.md` (Option 1).
 *
 * FAILS BEFORE THIS FIX, PASSES AFTER. Neither `peer-resolver-client.ts` nor
 * `peer-resolver-daemon.ts` existed on main before this change -- this whole
 * file could not even be authored, let alone pass, against the pre-fix tree
 * (the strongest form of "fails before": the exact plumbing under test did
 * not exist). Functionally, it reproduces the drill's exact causal chain:
 *
 *   1. a TCB gate (`gate-client-auth.ts`'s S5-3 fail-closed authorizer) wired
 *      to `createPrivilegedPeerRunner` instead of a mocked/fake
 *      `PeerCommandRunner` -- the REAL client this fix ships;
 *   2. talking to a REAL `runPeerResolverDaemon` server over a real
 *      loopback Unix domain socket in a temp dir (the REAL server this fix
 *      ships), whose OWN privileged lookup is injected to SIMULATE what
 *      root `lsof`/`proc_pidinfo` output looks like for the confined
 *      agent's port (the one piece that genuinely needs real root, which
 *      only the Erik-present Mini1 drill can prove; CI has no root and no
 *      second uid to reproduce the cross-uid failure itself);
 *   3. a real loopback CONNECT with a valid generation-bound bearer
 *      credential to an on-manifest destination.
 *
 * Pre-fix, the ONLY available `PeerCommandRunner` was `createExecFilePeerRunner`
 * (local execFile), which -- per the drill -- resolves NOTHING for a
 * cross-uid peer and denies every CONNECT `peer_unresolved`. This test
 * proves the NEW plumbing, once wired to an answer a privileged resolver
 * could actually produce, drives the gate to ALLOW instead -- and that the
 * previously-masked negatives (off-manifest destination, wrong peer uid) are
 * now denied for the RIGHT reason instead of the universal `peer_unresolved`,
 * exactly the drill's DoD language ("the masked negatives are now genuinely
 * proven").
 */

import { afterEach, describe, expect, it } from "vitest";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createExclusiveEgressGate,
  GATE_BIND_HOST,
  type EgressGateEvent,
  type GateLivenessProbe,
} from "../../src/egress-gate/gate-server.js";
import { createGateClientAuthenticator } from "../../src/egress-gate/gate-client-auth.js";
import {
  formatGateCredentialHeader,
  GATE_CREDENTIAL_VERSION,
  type GateAcceptSource,
  type GateCredentialAcceptRecord,
} from "../../src/egress-gate/gate-credential.js";
import { createPrivilegedPeerRunner } from "../../src/egress-gate/peer-resolver-client.js";
import { runPeerResolverDaemon } from "../../src/egress-gate/peer-resolver-daemon.js";
import type { PeerCommandRunner } from "../../src/egress-gate/peer-identity.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";

const AGENT_UID = 502;
const OPERATOR_UID = 501;
const GATE_UID = 511;
const GATE_PORT = 19998;
const GEN = 7;
const SECRET = "deadbeefcafef00d";

function sha256Hex(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

const liveProbe: GateLivenessProbe = {
  coalescing: "forbidden",
  binding: { agentUid: AGENT_UID, gatePort: GATE_PORT },
  check: () => Promise.resolve({ live: true, reasons: [] }),
};

const acceptRecord: GateCredentialAcceptRecord = {
  version: GATE_CREDENTIAL_VERSION,
  generation_id: GEN,
  secret_sha256: sha256Hex(SECRET),
};
const acceptSource: GateAcceptSource = { current: () => Promise.resolve(acceptRecord) };
const validHeader = formatGateCredentialHeader({ generation_id: GEN, secret: SECRET });

function allowRule(host: string, port: number): AllowlistRule {
  return {
    id: `regression-allow-${host}-${port}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-24T00:00:00Z",
    match: { host, port: [port], protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function startUpstream(): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => socket.end("upstream-hello"));
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

function rawConnect(
  gatePort: number,
  authority: string,
  proxyAuth?: string,
): Promise<{ statusLine: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(gatePort, "127.0.0.1", () => {
      const authLine = proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : "";
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authLine}\r\n`);
    });
    let data = "";
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("end", () => {
      const statusLine = data.split("\r\n")[0] ?? "";
      const body = data.split("\r\n\r\n").slice(1).join("\r\n\r\n");
      resolve({ statusLine, body });
    });
    socket.on("error", reject);
    setTimeout(() => socket.destroy(new Error("test connect timeout")), 5_000).unref();
  });
}

function fakeFsOps() {
  return {
    async mkdir(): Promise<void> {},
    async chmod(): Promise<void> {},
    async chown(): Promise<void> {},
    async rm(): Promise<void> {},
  };
}

/**
 * The privileged resolver's OWN "root lsof" is injected to simulate exactly
 * what the drill's hardware confirmation showed: `lsof -p <agent-pid>` as
 * root returns the real fds (8, in the drill); as the unprivileged gate uid
 * it returns 0. This is the one boundary CI cannot cross for real (no root,
 * no second uid) -- everything downstream of this injection point is the
 * REAL new code (the client, the wire protocol, the server, the gate's
 * unchanged decision logic).
 */
function simulatedRootLsof(peerUid: number): PeerCommandRunner {
  return {
    run: (_c, args) => {
      const port = Number(/:(\d+)$/.exec(args[2] ?? "")?.[1] ?? 0);
      return Promise.resolve({
        code: 0,
        stdout: [`p20439`, `u${peerUid}`, `n127.0.0.1:${port}->127.0.0.1:${GATE_PORT}`, ""].join("\n"),
      });
    },
  };
}

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups.pop()!();
  }
});

/**
 * Stand up a REAL peer-resolver daemon (root-simulated) + a REAL TCB gate
 * wired to the REAL privileged client -- the exact production S5-6 pairing,
 * minus only the LaunchDaemon/root process boundary CI cannot cross.
 */
async function startResolverAndGate(input: {
  peerUid: number;
  rules: AllowlistRule[];
}): Promise<{ gatePort: number; events: EgressGateEvent[] }> {
  const socketDir = await mkdtemp(join(tmpdir(), "peer-resolver-regression-"));
  cleanups.push(() => rm(socketDir, { recursive: true, force: true }));

  const resolverHandle = await runPeerResolverDaemon({
    agentUid: AGENT_UID,
    gateUid: GATE_UID,
    gatePort: GATE_PORT,
    socketDir,
    runner: simulatedRootLsof(input.peerUid),
    fsOps: fakeFsOps(),
    onEvent: () => undefined,
  });
  cleanups.push(() => resolverHandle.close());

  const events: EgressGateEvent[] = [];
  const server = createExclusiveEgressGate({
    policy: { agent_uid: AGENT_UID, gate_port: GATE_PORT },
    rules: input.rules,
    livenessProbe: liveProbe,
    clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
    // THE FIX: the real privileged client, talking to the real resolver
    // daemon above -- NOT a mocked PeerCommandRunner, NOT the old
    // createExecFilePeerRunner() that started this whole investigation.
    peerRunner: createPrivilegedPeerRunner({
      agentUid: AGENT_UID,
      gatePort: GATE_PORT,
      socketPath: resolverHandle.socketPath,
    }),
    onEvent: (e) => events.push(e),
    isRoutable: () => true,
  });
  await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { gatePort: (server.address() as AddressInfo).port, events };
}

describe("REGRESSION (Mini1 2026-07-24 drill): privileged-resolver-backed TCB gate", () => {
  it("P1 THE FIX: a valid credential from the AGENT's peer, resolved through the privileged resolver, is ALLOWED (this exact scenario denies 100% pre-fix)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { gatePort, events } = await startResolverAndGate({
      peerUid: AGENT_UID,
      rules: [allowRule("127.0.0.1", upstream.port)],
    });
    const result = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
    expect(result.body).toContain("upstream-hello");
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
    const decision = events.find((e) => e.kind === "decision");
    expect(decision && decision.kind === "decision" && decision.decision.disposition).toBe("allow");
  });

  it("N-WAY (N=3): repeats cleanly -- the privileged resolution is not a one-shot fluke", async () => {
    for (let i = 0; i < 3; i++) {
      const upstream = await startUpstream();
      const { gatePort } = await startResolverAndGate({
        peerUid: AGENT_UID,
        rules: [allowRule("127.0.0.1", upstream.port)],
      });
      const result = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, validHeader);
      expect(result.statusLine).toBe("HTTP/1.1 200 Connection Established");
      upstream.close();
    }
  });

  it("the MASKED NEGATIVE is now genuinely proven: off-manifest destination denies on DESTINATION, not peer_unresolved", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    // No allow rule for the upstream port: default-deny.
    const { gatePort, events } = await startResolverAndGate({ peerUid: AGENT_UID, rules: [] });
    const result = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    // Reached DESTINATION policy (peer auth passed) -- pre-fix this never got
    // past peer_unresolved, so this control was MASKED (RESULTS.md).
    expect(events.some((e) => e.kind === "client_denied")).toBe(false);
    const decision = events.find((e) => e.kind === "decision");
    expect(decision && decision.kind === "decision" && decision.decision.disposition).toBe("deny");
  });

  it("the OTHER masked negative is now genuinely proven: a valid credential from the OPERATOR uid denies peer_uid_mismatch, not peer_unresolved", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { gatePort, events } = await startResolverAndGate({
      peerUid: OPERATOR_UID, // resolution now SUCCEEDS, but mismatches the agent uid
      rules: [allowRule("127.0.0.1", upstream.port)],
    });
    const result = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_uid_mismatch");
    expect(denied && denied.kind === "client_denied" && denied.peerUid).toBe(OPERATOR_UID);
  });

  it("no-credential and stale-generation STILL deny (the fix never weakens the bearer lens)", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const { gatePort, events } = await startResolverAndGate({
      peerUid: AGENT_UID,
      rules: [allowRule("127.0.0.1", upstream.port)],
    });
    const anon = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`); // no header
    expect(anon.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const stale = formatGateCredentialHeader({ generation_id: GEN - 1, secret: SECRET });
    const staleResult = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, stale);
    expect(staleResult.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const reasons = events
      .filter((e): e is Extract<EgressGateEvent, { kind: "client_denied" }> => e.kind === "client_denied")
      .map((e) => e.reason);
    expect(reasons).toContain("no_credential");
    expect(reasons).toContain("stale_generation");
  });

  it("FAULT: the resolver process being DOWN (not started) still denies fail-closed, never a crash and never a silent allow", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const socketDir = await mkdtemp(join(tmpdir(), "peer-resolver-regression-down-"));
    cleanups.push(() => rm(socketDir, { recursive: true, force: true }));
    const events: EgressGateEvent[] = [];
    const server = createExclusiveEgressGate({
      policy: { agent_uid: AGENT_UID, gate_port: GATE_PORT },
      rules: [allowRule("127.0.0.1", upstream.port)],
      livenessProbe: liveProbe,
      clientAuth: createGateClientAuthenticator({ agentUid: AGENT_UID, acceptSource }),
      // Points at a socket path with NOTHING listening (resolver never started).
      peerRunner: createPrivilegedPeerRunner({
        agentUid: AGENT_UID,
        gatePort: GATE_PORT,
        socketPath: join(socketDir, "502.sock"),
      }),
      onEvent: (e) => events.push(e),
      isRoutable: () => true,
    });
    await new Promise<void>((resolve) => server.listen(0, GATE_BIND_HOST, resolve));
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
    const gatePort = (server.address() as AddressInfo).port;
    const result = await rawConnect(gatePort, `127.0.0.1:${upstream.port}`, validHeader);
    expect(result.statusLine).toBe("HTTP/1.1 403 Forbidden");
    const denied = events.find((e) => e.kind === "client_denied");
    expect(denied && denied.kind === "client_denied" && denied.reason).toBe("peer_unresolved");
  });
});
