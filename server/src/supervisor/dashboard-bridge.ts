/**
 * Phase S1 — Dashboard → supervisor bridge.
 *
 * The dashboard process owns the one-time fortress unlock and holds the master
 * key in memory. When an operator clicks Protect, the dashboard must hand the
 * supervisor a TRANSIENT copy of that key over the authenticated local socket
 * so the supervisor can launch + supervise the wrapped agent. This bridge is
 * the seam: it knows the socket path + per-boot auth secret and how to resolve
 * the transient key, and it translates the supervisor's socket response into
 * the {@link ProtectLaunchOutcome} the v1/agents handler consumes.
 *
 * Custody note (Tier A): the bridge reuses the master ALREADY in the
 * dashboard's memory — no new credential is introduced and nothing extra is
 * written to disk. The transient key is base64url-encoded into a single
 * MAC-authenticated frame and sent over the local socket. If no master is
 * resolvable (fortress locked), the bridge fails closed with `forbidden` — it
 * never launches an agent it cannot unlock.
 *
 * HEAP-RESIDENCY HONESTY (codex S1 finding #3 — do NOT over-claim): this bridge
 * does NOT and cannot zero the key from the dashboard's heap. Two reasons, both
 * by design, not oversight:
 *   1. The `key` returned by `resolveTransientKey()` IS the dashboard's own
 *      resident master buffer (Tier A reuses it); the dashboard still needs it
 *      to read the audit log / identities, so the bridge must NOT zero it.
 *   2. The base64url encoding (`transientKeyB64`) is an immutable JS string and
 *      cannot be wiped; it lingers until GC. This is the unavoidable cost of
 *      marshalling a key through a string/JSON frame in a managed runtime.
 * The blast-radius win this bridge delivers is SPLIT-PROCESS (the agent SPAWNER
 * lives in a separate supervisor process — review H1), NOT "the dashboard heap
 * holds no key material." The dashboard already holds the resident master for
 * its read surface (dashboard-standalone.ts), exactly as the ratified spec
 * prescribes ("the dashboard keeps the one-time unlock... as today"). The
 * resident-master exposure window of the dashboard process is the H2 concern,
 * tracked separately (core-dump/swap/ptrace hardening), and is unchanged by
 * this bridge — it neither widens nor narrows it.
 */

import { toBase64url } from "../core/encoding.js";
import type { ProtectLaunchOutcome } from "../v1/agents.js";
import { sendSupervisorRequest, type SocketClientOptions } from "./socket-client.js";
import type { SupervisorResponse } from "./protocol.js";

export interface SupervisorBridgeDeps {
  socketPath: string;
  authSecret: Uint8Array;
  /**
   * Resolve the transient unlock key (the in-memory fortress master, or a
   * per-agent derived capability). Returns null when the fortress is locked /
   * no master is resident — the bridge then fails closed with `forbidden`
   * (Tier A reuses the dashboard's already-unlocked master; it never invents
   * one).
   */
  resolveTransientKey: () => Uint8Array | null;
  timeoutMs?: number;
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

export class SupervisorBridge {
  private readonly deps: SupervisorBridgeDeps;

  constructor(deps: SupervisorBridgeDeps) {
    this.deps = deps;
  }

  /**
   * Translate a v1/agents protect into a supervisor socket call. Never throws:
   * a socket/connect failure maps to `unavailable` (retryable 503), a locked
   * fortress to `forbidden` (collapsed into the generic 403 upstream). The
   * transient key is encoded once and never logged.
   */
  async launchProtect(spec: {
    agentId: string;
    harness: string;
    configPath: string;
  }): Promise<ProtectLaunchOutcome> {
    const key = this.deps.resolveTransientKey();
    if (!key) {
      this.deps.log?.("supervisor.protect.locked", { agent_id: spec.agentId });
      return { ok: false, reason: "forbidden" };
    }
    // Encode the transient key into the (single) authenticated frame.
    const transientKeyB64 = toBase64url(key);

    const opts: SocketClientOptions = {
      socketPath: this.deps.socketPath,
      authSecret: this.deps.authSecret,
      timeoutMs: this.deps.timeoutMs,
    };

    let resp: SupervisorResponse;
    try {
      resp = await sendSupervisorRequest(
        {
          kind: "protect",
          agent_id: spec.agentId,
          harness: spec.harness,
          config_path: spec.configPath,
          transient_key_b64: transientKeyB64,
        },
        opts,
      );
    } catch (err) {
      // Supervisor unreachable/timeout/frame-error ⇒ retryable, uncached.
      this.deps.log?.("supervisor.protect.unreachable", {
        agent_id: spec.agentId,
        error: err instanceof Error ? err.message : String(err),
      });
      return { ok: false, reason: "unavailable" };
    }

    return mapSupervisorResponse(resp);
  }
}

/** Translate a supervisor socket response into the handler's outcome shape. */
export function mapSupervisorResponse(
  resp: SupervisorResponse,
): ProtectLaunchOutcome {
  if (resp.ok) {
    switch (resp.kind) {
      case "protecting":
        return { ok: true, status: "protecting", agent_id: resp.agent_id, launch_id: resp.launch_id };
      case "already-protected":
        return { ok: true, status: "protected", agent_id: resp.agent_id };
      default:
        // A status/unprotecting response to a protect request is nonsensical.
        return { ok: false, reason: "unavailable" };
    }
  }
  switch (resp.reason) {
    case "rotation_in_progress":
      return { ok: false, reason: "rotation_in_progress" };
    case "bad_request":
      return { ok: false, reason: "bad_request" };
    case "not_found":
    case "unavailable":
      return { ok: false, reason: "unavailable" };
    default:
      return { ok: false, reason: "unavailable" };
  }
}
