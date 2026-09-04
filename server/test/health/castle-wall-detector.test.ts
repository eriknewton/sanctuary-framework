/**
 * The production Castle Wall evidence source, and the WIRED-CONSUMER proof.
 *
 * AGENTS rule 4: a capability with no production consumer is not shipped,
 * whatever its own tests say. `evaluateCastleWall`'s lifecycle/runtime branch
 * had unit tests and ZERO production call paths - every
 * `buildHealthEvidenceReport` call site omitted `castleWall`, so `monitor_health`,
 * `exec_attest` and the SHR publish payload reported `not_configured` on a host
 * whose wall was live, degraded, or faulted alike.
 *
 * Two kinds of test here, because one without the other proves nothing:
 *   - BEHAVIOR: the detector answers honestly across every reachable state, and
 *     never manufactures health from what it could not observe.
 *   - COMPOSITION: the production call sites actually reach it. A behavior test
 *     alone is exactly what the inert version already had.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";

import {
  detectCastleWallRuntimeSnapshot,
  castleWallSnapshotForHealthReport,
  CASTLE_WALL_DETECT_TIMEOUT_MS,
} from "../../src/health/castle-wall-detector.js";
import { buildHealthEvidenceReport, evaluateCastleWall } from "../../src/health/evidence.js";
import { frame, parseFrame } from "../../src/castle-wall/ipc/framing.js";
import type {
  CastleWallMessage,
  StatusResponse,
} from "../../src/castle-wall/ipc/messages.js";
import {
  CASTLE_WALL_IPC_CAPABILITIES,
  CASTLE_WALL_IPC_PROTOCOL_VERSION,
} from "../../src/castle-wall/ipc/messages.js";
import type { IpcTransport } from "../../src/castle-wall/runtime/ipc-client.js";
import { encrypt } from "../../src/core/encryption.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { SanctuaryConfig } from "../../src/config.js";

let tmp: string;
let masterKey: Uint8Array;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "cw-detector-"));
  masterKey = generateRandomKey();
  // The fortress's pinned Castle Wall key pair, in the exact on-disk shape
  // `buildLinuxIpcClientKeyMaterial` reads. Writing the REAL files (rather than
  // stubbing the loader) is what makes this a fortress-BOUND reading rather than
  // a socket-bound one.
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  await writeFile(join(tmp, "castle-pinned-pubkey.bin"), Buffer.from(pub));
  await writeFile(
    join(tmp, "castle-pinned-privkey.enc"),
    JSON.stringify(encrypt(seed, masterKey)),
    "utf8"
  );
});

afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

/**
 * A mock daemon that completes the handshake and answers exactly one
 * `status_request` with `statusFields`. `answerStatus: false` models a socket
 * that connects and then goes silent - the wedged case the deadline bounds.
 */
function mockDaemon(options: {
  statusFields?: Partial<StatusResponse>;
  answerStatus?: boolean;
  capabilities?: string[];
}): { transport: IpcTransport; sendChallenge: () => Promise<void> } {
  let listener: ((bytes: Uint8Array) => void) | null = null;
  let buffer = new Uint8Array(0);
  const emit = (msg: CastleWallMessage): void => {
    if (!listener) throw new Error("mock daemon: no listener");
    listener(
      frame(
        JSON.stringify({ jsonrpc: "2.0", method: `castle-wall.${msg.type}`, params: msg })
      )
    );
  };
  return {
    transport: {
      send: async (bytes: Uint8Array) => {
        const merged = new Uint8Array(buffer.length + bytes.length);
        merged.set(buffer, 0);
        merged.set(bytes, buffer.length);
        buffer = merged;
        for (;;) {
          const step = parseFrame(buffer);
          if (step.kind !== "complete") break;
          buffer = new Uint8Array(buffer.subarray(step.consumedBytes));
          const env = JSON.parse(step.body) as { params?: CastleWallMessage };
          const msg = env.params;
          if (msg?.type === "status_request" && options.answerStatus !== false) {
            emit({
              type: "status_response",
              request_id: msg.request_id,
              uptime_seconds: 12,
              loaded_manifest_signature_b64url: "sig",
              loaded_rule_count: 3,
              no_wall_engaged: false,
              manifest_state: "ready",
              lifecycle_state: "running",
              runtime_state: "kernel_runtime_ready",
              kernel_runtime_ready: true,
              enforcing: false,
              runtime_health: "ready",
              ...options.statusFields,
            });
          }
        }
      },
      onData: (l) => {
        listener = l;
        return () => {
          listener = null;
        };
      },
      close: async () => {
        listener = null;
      },
    },
    sendChallenge: async () => {
      for (let i = 0; i < 500 && !listener; i += 1) {
        await new Promise((r) => setTimeout(r, 1));
      }
      if (!listener) throw new Error("mock daemon: listener never attached");
      emit({
        type: "handshake_challenge",
        nonce_b64url: "AAEC",
        protocol_version: CASTLE_WALL_IPC_PROTOCOL_VERSION,
        capabilities: options.capabilities ?? [...CASTLE_WALL_IPC_CAPABILITIES],
      } as unknown as CastleWallMessage);
    },
  };
}

async function detect(options: {
  statusFields?: Partial<StatusResponse>;
  answerStatus?: boolean;
  socketExists?: boolean;
  timeoutMs?: number;
  drainState?: "healthy" | "retrying" | "faulted";
}) {
  const mock = mockDaemon({
    statusFields: options.statusFields,
    answerStatus: options.answerStatus,
  });
  const p = detectCastleWallRuntimeSnapshot({
    fortressStoragePath: tmp,
    fortressId: "fortress:test",
    masterKey,
    platform: "linux",
    socketPath: join(tmp, "castle.sock"),
    socketExists: async () => options.socketExists !== false,
    connectTransport: async () => mock.transport,
    timeoutMs: options.timeoutMs,
    drainState: options.drainState,
  });
  if (options.socketExists !== false) {
    void mock.sendChallenge().catch(() => {});
  }
  return await p;
}

describe("castle-wall detector: what it proves, and what it refuses to claim", () => {
  it("multiplexes 121 concurrent agent health reads onto one authenticated connection", async () => {
    const mock = mockDaemon({});
    let connects = 0;
    const socketExists = async (): Promise<boolean> => true;
    const connectTransport = async (): Promise<IpcTransport> => {
      connects += 1;
      return mock.transport;
    };
    const input = {
      fortressStoragePath: tmp,
      fortressId: "fortress:test",
      masterKey,
      platform: "linux" as const,
      socketPath: join(tmp, "castle.sock"),
      socketExists,
      connectTransport,
    };
    const reads = Array.from({ length: 121 }, () =>
      detectCastleWallRuntimeSnapshot(input)
    );
    void mock.sendChallenge();
    const snapshots = await Promise.all(reads);
    expect(connects).toBe(1);
    expect(snapshots.every((snapshot) => snapshot?.daemonUp === true)).toBe(true);
  });

  it("caps a HEALTHY cross-process reading at `unknown`, never `active`", async () => {
    const snapshot = await detect({});
    expect(snapshot).toBeDefined();
    expect(snapshot!.evidenceChannel).toBe("unobserved");
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.status).toBe("unknown");
    expect(verdict.status).not.toBe("active");
    expect(verdict.detector_evidence).toMatch(/not observable from here/i);
    expect(verdict.detector_evidence).toMatch(
      /absence of a fault is not evidence that evidence is flowing/i
    );
  });

  it("still reports a PROVEN-lost runtime as degraded (the ceiling is on positive claims only)", async () => {
    const snapshot = await detect({
      statusFields: { runtime_health: "lost", runtime_state: "degraded" },
    });
    expect(evaluateCastleWall(snapshot).status).toBe("degraded");
  });

  it("reports an INDETERMINATE probe as unknown, not as a failure", async () => {
    const snapshot = await detect({ statusFields: { runtime_health: "probe_unavailable" } });
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.status).toBe("unknown");
    expect(verdict.status).not.toBe("degraded");
  });

  it("does not read a CONTENDED manifest store as a proven failure", async () => {
    const snapshot = await detect({ statusFields: { manifest_state: "unavailable" } });
    expect(evaluateCastleWall(snapshot).status).toBe("unknown");
  });

  it("reports a POISONED manifest store as degraded", async () => {
    const snapshot = await detect({ statusFields: { manifest_state: "degraded" } });
    expect(evaluateCastleWall(snapshot).status).toBe("degraded");
  });

  it("reports not_configured when this host has no daemon socket for the fortress", async () => {
    const snapshot = await detect({ socketExists: false });
    expect(snapshot).toBeDefined();
    expect(snapshot!.configured).toBe(false);
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.status).toBe("not_configured");
    expect(verdict.detector_evidence).toMatch(/no Castle Wall daemon socket/i);
  });

  /**
   * The distinction the old code could not make: "nothing is installed" and
   * "something is installed and it will not answer" are different facts about a
   * host, and only the first is `not_configured`.
   */
  it("reports an installed-but-silent daemon as unknown WITH the cause, never not_configured", async () => {
    const snapshot = await detect({ answerStatus: false, timeoutMs: 150 });
    expect(snapshot).toBeDefined();
    // `"unknown"`, not `false`: a daemon that is alive but WEDGED produces this
    // same observation, so asserting it is down would overstate what we proved.
    expect(snapshot!.daemonUp).toBe("unknown");
    expect(snapshot!.configured).toBe(true);
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.status).toBe("unknown");
    expect(verdict.status).not.toBe("not_configured");
    expect(verdict.status).not.toBe("inactive");
    expect(verdict.detector_evidence).toMatch(/did not answer an authenticated status query/i);
  });

  /**
   * BOUNDED. A socket that connects and never answers must not hang the health
   * tool that called it; the whole point of the ceiling is that an unanswered
   * daemon is REPORTED, not waited out.
   */
  it("returns within its deadline against a wedged socket", async () => {
    const started = Date.now();
    const snapshot = await detect({ answerStatus: false, timeoutMs: 200 });
    const elapsed = Date.now() - started;
    expect(snapshot!.daemonUp).toBe("unknown");
    expect(elapsed).toBeLessThan(3_000);
    expect(CASTLE_WALL_DETECT_TIMEOUT_MS).toBeLessThan(15_000);
  });

  /**
   * REGRESSION for a leak in this file's own first cut: the transport is created
   * BEFORE the `IpcClient` that owns it, and the wall-clock deadline can fire in
   * that gap. Cleaning up only the client leaked one open socket per health call
   * whenever the race landed there, so a repeatedly-polled `monitor_health`
   * would exhaust the daemon's bounded connection limit and lock out the process
   * that actually arms the wall. A health check must never become an
   * availability attack on the thing it reports.
   */
  it("closes the transport even when the deadline fires before the client owns it", async () => {
    let closed = 0;
    const neverAnswering: IpcTransport = {
      send: async () => {},
      onData: () => () => {},
      close: async () => {
        closed += 1;
      },
    };
    const snapshot = await detectCastleWallRuntimeSnapshot({
      fortressStoragePath: tmp,
      fortressId: "fortress:test",
      masterKey,
      platform: "linux",
      socketPath: join(tmp, "castle.sock"),
      socketExists: async () => true,
      // Hand back the transport only after the deadline has already passed, so
      // the race resolves in exactly the window the leak lived in.
      connectTransport: async () => {
        await new Promise((r) => setTimeout(r, 120));
        return neverAnswering;
      },
      timeoutMs: 40,
    });
    expect(snapshot!.daemonUp).toBe("unknown");
    // Give the orphaned connect promise time to settle into the cleanup path.
    await new Promise((r) => setTimeout(r, 250));
    expect(closed, "the orphaned transport must be closed, not leaked").toBe(1);
  });

  it("is a no-op off Linux, where the channel-basis path owns this surface", async () => {
    const snapshot = await detectCastleWallRuntimeSnapshot({
      fortressStoragePath: tmp,
      fortressId: "fortress:test",
      masterKey,
      platform: "darwin",
      socketExists: async () => true,
    });
    expect(snapshot).toBeUndefined();
  });

  /**
   * The IN-PROCESS case: a caller that armed the wall genuinely knows the drain
   * state, so passing it lifts the `unobserved` ceiling. The verdict still is
   * not `active` - `nftablesApplied` / `cgroupAttached` remain unobserved, which
   * is the pre-existing honesty bound (ASSURANCE_MATRIX row 17) - but it is no
   * longer capped by the CROSS-PROCESS reason.
   */
  it("lifts the unobserved ceiling when the caller genuinely knows the drain state", async () => {
    const snapshot = await detect({ drainState: "healthy" });
    expect(snapshot!.evidenceChannel).toBe("confirmed");
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.detector_evidence).not.toMatch(/not observable from here/i);
  });

  it("reports a caller-known FAULTED drain state as degraded", async () => {
    const snapshot = await detect({ drainState: "faulted" });
    expect(snapshot!.evidenceChannel).toBe("faulted");
    expect(evaluateCastleWall(snapshot).status).toBe("degraded");
  });

  it("reports a caller-known RETRYING drain state as degraded, but says the link is not proven broken", async () => {
    const snapshot = await detect({ drainState: "retrying" });
    expect(snapshot!.evidenceChannel).toBe("drain_retrying");
    const verdict = evaluateCastleWall(snapshot);
    expect(verdict.status).toBe("degraded");
    expect(verdict.detector_evidence).toMatch(/not proven broken/i);
  });
});

describe("castle-wall detector: the evidence source never throws into a health tool", () => {
  it("returns undefined rather than throwing when the fortress has no pinned key", async () => {
    const empty = await mkdtemp(join(tmpdir(), "cw-empty-"));
    try {
      const snapshot = await castleWallSnapshotForHealthReport({
        config: { storage_path: empty },
        masterKey,
        overrides: {
          platform: "linux",
          socketExists: async () => true,
          connectTransport: async () => {
            throw new Error("connection refused");
          },
          timeoutMs: 200,
        },
      });
      // No pinned key on disk, so `buildLinuxIpcClientKeyMaterial` throws. The
      // health tool must still get an answer, and it must be the weakest one.
      expect(snapshot).toBeDefined();
      expect(evaluateCastleWall(snapshot).status).toBe("unknown");
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });

  it("feeds `buildHealthEvidenceReport`, and the verdict reaches castle_wall AND egress", async () => {
    const snapshot = await detect({ statusFields: { runtime_health: "lost", runtime_state: "degraded" } });
    const report = buildHealthEvidenceReport({
      config: {
        execution: { environment: "local", attestation: false },
        state: { encryption: "aes-256-gcm", integrity: "hmac-sha256" },
        disclosure: { proof_system: "commitment-only" },
        reputation: { export: true },
        storage_path: tmp,
      } as unknown as SanctuaryConfig,
      identityCount: 1,
      storageBackendName: "FilesystemStorage",
      castleWall: snapshot,
    });
    expect(report.castle_wall.status).toBe("degraded");
    // Same verdict, two surfaces: an inconsistency here would let one report
    // contradict the other about the same wall.
    expect(report.egress.enforcement).toBe("degraded");
  });
});

/**
 * COMPOSITION (AGENTS rule 4). The behavior tests above are exactly what the
 * INERT version already had: they prove the mapping works, not that anything
 * calls it. These assert the production object graph reaches it.
 *
 * Read from source rather than by invoking the MCP server, because the thing
 * being asserted IS the presence of the argument at those call sites: a runtime
 * assertion could pass against a report built by the test itself, which is the
 * mistake being guarded against.
 */
describe("castle-wall detector: production call sites are WIRED, not merely available", () => {
  const CALL_SITES = [
    { file: "src/index.ts", label: "exec_attest + monitor_health" },
    { file: "src/reputation/tools.ts", label: "SHR publish payload" },
  ];

  it("every buildHealthEvidenceReport call site passes a castleWall snapshot", async () => {
    for (const site of CALL_SITES) {
      const source = await readFile(join(process.cwd(), site.file), "utf8");
      const calls = source.split("buildHealthEvidenceReport({").slice(1);
      expect(
        calls.length,
        `${site.file} (${site.label}) has no buildHealthEvidenceReport call; if it moved, move this assertion with it`
      ).toBeGreaterThan(0);
      for (const call of calls) {
        // The argument object ends at the first `});`.
        const args = call.slice(0, call.indexOf("});"));
        expect(
          args,
          `a buildHealthEvidenceReport call in ${site.file} (${site.label}) omits ` +
            `\`castleWall\`, so it reports not_configured on every host and the ` +
            `lifecycle/runtime branch of evaluateCastleWall has no production ` +
            `call path from it (AGENTS rule 4)`
        ).toContain("castleWall:");
        expect(
          args,
          `${site.file} must source the snapshot from the SHARED evidence source; ` +
            `a second derivation would let the three reports disagree about one wall`
        ).toContain("castleWallSnapshotForHealthReport");
      }
    }
  });

  it("no production call site defaults the drain state it cannot observe", async () => {
    const source = await readFile(
      join(process.cwd(), "src/health/castle-wall-detector.ts"),
      "utf8"
    );
    // The detector must thread the caller's value through, never substitute one.
    expect(source).toContain("drainState: input.drainState");
    expect(source).not.toMatch(/drainState:\s*"healthy"/);
  });
});
