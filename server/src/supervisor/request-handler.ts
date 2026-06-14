/**
 * Phase S1 — Supervisor request handler.
 *
 * Bridges the socket server's verified {@link SupervisorRequest}s to the
 * {@link Supervisor} lifecycle. This is where the transient key is decoded
 * from the protect frame into raw bytes and handed to the supervisor as a
 * {@link SupervisionSpec}. Residency (honest — codex S1): the supervisor zeroes
 * the key on a failed/refused launch, but RETAINS it for the agent lifetime on
 * a successful launch (Tier A crash-restart), zeroing it on unprotect/shutdown.
 *
 * The handler is fail-closed and never leaks the key: a malformed transient
 * key is a `bad_request`, an unknown agent is `not_found`, and any unexpected
 * error collapses to `unavailable` (the socket server also wraps a thrown
 * handler in `unavailable`). It performs the config-path root-confinement
 * check (review L2 / H1 blast-radius) before launching.
 */

import { fromBase64url, toBase64url } from "../core/encoding.js";
import type { SupervisorRequest, SupervisorResponse } from "./protocol.js";
import type { Supervisor, SupervisionSpec } from "./supervisor.js";

export interface RequestHandlerDeps {
  supervisor: Supervisor;
  /**
   * Confine a protect `config_path` to an allowed root before launch (H1/L2).
   * Returns true iff the path is safe to supervise. A false ⇒ `bad_request`
   * (never launch an API-pointed arbitrary path). Implementations should reuse
   * the wrap config root-confinement (`writeFileSafeUnderRoot`'s root logic).
   */
  isConfigPathAllowed: (configPath: string) => boolean;
  log?: (event: string, fields?: Record<string, unknown>) => void;
}

/** Build the socket-server `handle` callback. */
export function makeSupervisorHandler(
  deps: RequestHandlerDeps,
): (req: SupervisorRequest) => Promise<SupervisorResponse> {
  return async (req: SupervisorRequest): Promise<SupervisorResponse> => {
    switch (req.kind) {
      case "protect": {
        if (!deps.isConfigPathAllowed(req.config_path)) {
          deps.log?.("protect.rejected.path", { agent_id: req.agent_id });
          return { ok: false, kind: "error", reason: "bad_request" };
        }
        let transientKey: Uint8Array;
        try {
          transientKey = fromBase64url(req.transient_key_b64);
        } catch {
          return { ok: false, kind: "error", reason: "bad_request" };
        }
        // Buffer's base64 decode is lenient (it drops invalid chars rather
        // than throwing), so a garbage string can yield non-empty bytes — in
        // fact a VALID key plus a trailing junk char still decodes to the real
        // key bytes. Require a strict round-trip: the decoded bytes must
        // re-encode to the exact input, rejecting any malformed transient key.
        if (transientKey.length === 0 || toBase64url(transientKey) !== req.transient_key_b64) {
          // Codex S1 R8: a malformed-but-decodable key already materialized real
          // (possibly master-equivalent) bytes — zero them before rejecting so a
          // rejected protect leaves NO key bytes resident (honest custody #7).
          transientKey.fill(0);
          return { ok: false, kind: "error", reason: "bad_request" };
        }
        const spec: SupervisionSpec = {
          agent_id: req.agent_id,
          harness: req.harness,
          config_path: req.config_path,
          transientKey,
        };
        const result = await deps.supervisor.protect(spec);
        if (result.ok) {
          if (result.kind === "already-protected") {
            return { ok: true, kind: "already-protected", agent_id: result.agent_id };
          }
          return {
            ok: true,
            kind: "protecting",
            agent_id: result.agent_id,
            launch_id: result.launch_id,
          };
        }
        return { ok: false, kind: "error", reason: result.reason };
      }
      case "unprotect": {
        const result = await deps.supervisor.unprotect(req.agent_id);
        if (result.ok) {
          return { ok: true, kind: "unprotecting", agent_id: req.agent_id };
        }
        return { ok: false, kind: "error", reason: "not_found" };
      }
      case "status": {
        const agents = deps.supervisor.status(req.agent_id);
        return { ok: true, kind: "status", agents };
      }
    }
  };
}
