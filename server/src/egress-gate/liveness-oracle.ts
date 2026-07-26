/**
 * Root-owned liveness oracle: a short-TTL, generation-bound, SIGNED freshness
 * token the NON-ROOT gate verifies per-CONNECT (Unified Protect Slice 5 S5-3,
 * folds Codex H5-b; design 4b).
 *
 * THE PROBLEM. The gate must have FRESH pf-liveness before every CONNECT
 * (`checkPfAnchorLiveness` shells `pfctl`), but the dedicated `sanctuary-gate`
 * uid must NOT hold root or broad `/dev/pf` access (an unauthenticated loopback
 * proxy holding pf privilege is a far larger TCB member), and caching a root
 * supervisor's verdict in the gate would violate no-stale-positive after a
 * flush. So the gate needs liveness it can trust WITHOUT running pfctl itself
 * and WITHOUT trusting a cache.
 *
 * THE MECHANISM. The ROOT supervisor runs `checkPfAnchorLiveness` on its own
 * short cadence and PUBLISHES a freshness token
 * `{ agent_uid, gate_port, generation_id, live, expires_at }` signed with an
 * Ed25519 supervisor key. The gate holds ONLY the PUBLIC half. On every CONNECT
 * the gate reads the token file and verifies, fail-closed:
 *   - absent            -> not live (the supervisor invalidated it, or never ran);
 *   - bad signature     -> not live (a non-root process cannot forge liveness);
 *   - `live !== true`    -> not live (the supervisor's last check failed);
 *   - expired (now >= expires_at) -> not live (staleness is bounded by the TTL);
 *   - binding mismatch  -> not live (a token for a different agent/port/generation
 *     cannot be replayed onto this channel).
 * Only an unexpired, correctly-signed, live token whose binding matches THIS
 * `{ agent_uid, gate_port, generation_id }` yields live.
 *
 * THE GATE NEVER HOLDS pf PRIVILEGE. The gate runs no pfctl and reads no
 * `/dev/pf`; it verifies a signature. The pfctl cost stays on the root
 * supervisor, off the per-CONNECT hot path.
 *
 * HONEST RESIDUAL (design 4b, stated plainly, carried to the ledger). Liveness
 * is as fresh as the TTL: between a flush and the supervisor's invalidate, a
 * still-unexpired token could read live for at most the TTL. The TTL is picked
 * short enough (sub-second to low-single-digit seconds) that a same-TTL-window
 * flush cannot be exploited into meaningful egress; the exact value is a drilled
 * tuning, not a guess. On a drift-repair or flush the supervisor invalidates the
 * token immediately, so the common case denies without waiting for expiry.
 *
 * NO CACHED-GREEN SURVIVES A FLUSH. The gate re-reads and re-verifies the token
 * on every CONNECT (this probe is the gate's injected `livenessProbe`, which
 * `gate-server.ts` never caches a positive result of across requests). Once the
 * supervisor removes/invalidates the token, the very next CONNECT reads absent
 * and denies; a lingering unexpired token is bounded by the TTL above.
 *
 * HOST-FREE. The oracle (root) and the probe (gate) are pure over injected ops
 * (the signing key, the atomic write, the file read, the clock, the pf probe),
 * so the whole verify matrix is unit-testable with no root, no host, no pf. The
 * Ed25519 keys are real `node:crypto` KeyObjects; only the I/O is injected.
 */

import { sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

import type { PfLivenessResult } from "./pf-anchor.js";
import type { GateLivenessProbe } from "./gate-server.js";

/**
 * Root-owned parent directory for the gate liveness tokens. Mode 0711
 * (fix-round BLOCKER-2 class; asserted by `runtime-fs-plan.ts` at arming
 * time): root-only write + listing, execute/search for everyone, so the
 * NON-ROOT gate uid can traverse to its 0600 `<uid>.token` and the 0644
 * pinned supervisor PUBLIC key. The 0600 root-owned PRIVATE key in the same
 * dir stays unreadable by file mode. A 0700 parent (the pre-fix state)
 * blocked the gate's token read and made every CONNECT deny.
 */
export const GATE_LIVENESS_DIR = "/var/db/sanctuary/gate-liveness";

/**
 * The uid's signed freshness-token file path. The SINGLE source for this
 * path shape: the fs oracle ops read/write/remove through it, and the S5-7
 * unprotect teardown removes it directly (invalidation must work even when
 * the gate service account or oracle keys are already gone, so the teardown
 * never needs a constructed oracle).
 */
export function gateLivenessTokenPath(agentUid: number, dir: string = GATE_LIVENESS_DIR): string {
  return `${dir}/${agentUid}.token`;
}

/** On-disk schema version for the signed freshness token. */
export const GATE_LIVENESS_TOKEN_VERSION = 1 as const;

/** Default freshness-token TTL (ms). Kept short; the exact value is a drilled tuning. */
export const GATE_LIVENESS_DEFAULT_TTL_MS = 2_000;

/** The signed portion of a freshness token (canonically serialized before signing). */
export interface LivenessTokenClaims {
  version: typeof GATE_LIVENESS_TOKEN_VERSION;
  agent_uid: number;
  gate_port: number;
  generation_id: number;
  live: boolean;
  /** Epoch ms after which the token is stale. */
  expires_at: number;
}

/** A freshness token as written to disk: the claims + a detached Ed25519 signature. */
export interface SignedLivenessToken extends LivenessTokenClaims {
  /** base64 Ed25519 signature over {@link canonicalLivenessPayload}. */
  sig: string;
}

/** Injected side effects for the root-side oracle (host-free in tests). */
export interface LivenessOracleOps {
  /** Atomically write the gate-readable token file for `agentUid` (owner gate_uid, 0600). */
  writeToken(agentUid: number, payload: string): Promise<void>;
  /** Remove the token file for `agentUid` (ENOENT is not an error). */
  removeToken(agentUid: number): Promise<void>;
  /** The pf-anchor liveness check the supervisor runs (never on the gate). */
  probe(input: { agentUid: number; gatePort: number }): Promise<PfLivenessResult>;
  /** Wall clock (epoch ms). Injected for deterministic expiry tests. */
  now(): number;
}

/** Read-only token source the gate consults (reads the token file). */
export interface LivenessTokenSource {
  /** The raw token JSON for `agentUid`, or null if absent. */
  read(agentUid: number): Promise<string | null>;
}

/** What binding a gate probe expects a token to carry. */
export interface LivenessProbeBinding {
  agentUid: number;
  gatePort: number;
  generationId: number;
}

/**
 * Deterministic, injection-free serialization of the signed claims. A FIXED
 * field order (never `JSON.stringify` over an object whose key order a caller
 * could perturb) so the bytes the supervisor signs are exactly the bytes the
 * gate verifies. Any drift here would silently break every signature, which is
 * fail-closed (verify fails -> not live), but the fixed order makes it correct.
 */
export function canonicalLivenessPayload(claims: LivenessTokenClaims): Buffer {
  const ordered = [
    `v=${claims.version}`,
    `agent_uid=${claims.agent_uid}`,
    `gate_port=${claims.gate_port}`,
    `generation_id=${claims.generation_id}`,
    `live=${claims.live ? "1" : "0"}`,
    `expires_at=${claims.expires_at}`,
  ].join("&");
  return Buffer.from(ordered, "utf8");
}

/**
 * The root-side liveness oracle. Construct with the supervisor's PRIVATE
 * Ed25519 key + injected ops; {@link refresh} runs the pf probe and publishes a
 * freshly-signed token, {@link invalidate} removes it (flush / drift-repair).
 * Host-free.
 */
export class GateLivenessOracle {
  private readonly ttlMs: number;

  constructor(
    private readonly privateKey: KeyObject,
    private readonly ops: LivenessOracleOps,
    options?: { ttlMs?: number },
  ) {
    this.ttlMs = options?.ttlMs ?? GATE_LIVENESS_DEFAULT_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new Error(`gate liveness oracle: TTL must be a positive number of ms (got ${String(this.ttlMs)})`);
    }
  }

  /**
   * Run the pf probe for `{ agentUid, gatePort, generationId }` and publish a
   * signed LIVE token, or INVALIDATE on anything short of a confirmed-live
   * result. Returns the published token, or `null` when liveness could not be
   * confirmed (in which case the token has been removed). The supervisor calls
   * this on its own short cadence.
   *
   * FAIL-CLOSED ON EVERY NON-LIVE OUTCOME (Codex round-2 HIGH). The previous
   * shape published a `live:false` token on a not-live probe, which meant a
   * WRITE FAILURE on that not-live transition (or a probe THROW) left the prior
   * still-unexpired LIVE token readable until its TTL -- a stale positive after
   * a flush. Rev2:
   *   - probe THROWS  -> we cannot confirm liveness: remove any prior token
   *     (loudly if removal itself fails) and rethrow;
   *   - probe NOT-LIVE -> REMOVE the token (never publish `live:false`), so a
   *     flush invalidates immediately and no write-failure window can strand a
   *     stale live token; a removal failure THROWS (the supervisor must know the
   *     stale token persists);
   *   - probe LIVE -> sign + publish a fresh live token.
   */
  async refresh(binding: LivenessProbeBinding): Promise<SignedLivenessToken | null> {
    const { agentUid, gatePort, generationId } = binding;
    let result: PfLivenessResult;
    try {
      result = await this.ops.probe({ agentUid, gatePort });
    } catch (probeErr) {
      // Cannot confirm liveness -> invalidate fail-closed, then surface.
      try {
        await this.ops.removeToken(agentUid);
      } catch (rmErr) {
        throw new Error(
          `gate liveness oracle: probe failed AND token invalidation failed for uid ${agentUid} ` +
            `(a stale live token may persist until its TTL): probe=${probeErr instanceof Error ? probeErr.message : String(probeErr)}; ` +
            `remove=${rmErr instanceof Error ? rmErr.message : String(rmErr)}`,
          { cause: rmErr },
        );
      }
      throw probeErr;
    }
    if (result.live !== true) {
      // Not live -> remove the token (do NOT publish a live:false token that a
      // write failure could fail to overwrite). A removal failure is loud.
      await this.ops.removeToken(agentUid);
      return null;
    }
    const claims: LivenessTokenClaims = {
      version: GATE_LIVENESS_TOKEN_VERSION,
      agent_uid: agentUid,
      gate_port: gatePort,
      generation_id: generationId,
      live: true,
      expires_at: this.ops.now() + this.ttlMs,
    };
    const sig = edSign(null, canonicalLivenessPayload(claims), this.privateKey).toString("base64");
    const token: SignedLivenessToken = { ...claims, sig };
    await this.ops.writeToken(agentUid, JSON.stringify(token));
    return token;
  }

  /** Invalidate the token immediately (flush / drift-repair / unprotect). */
  async invalidate(agentUid: number): Promise<void> {
    await this.ops.removeToken(agentUid);
  }
}

/**
 * Verify a raw token string against the pinned public key + expected binding +
 * clock. Pure. Returns a {@link PfLivenessResult} so it drops straight into the
 * gate's `livenessProbe`. EVERY failure is not-live with a specific reason
 * (never a throw that could be swallowed into a default-live). `now` is epoch ms.
 */
export function verifyLivenessToken(input: {
  raw: string | null;
  publicKey: KeyObject;
  binding: LivenessProbeBinding;
  now: number;
}): PfLivenessResult {
  const { raw, publicKey, binding, now } = input;
  if (raw === null) {
    return { live: false, reasons: ["liveness token absent (supervisor invalidated or never published)"] };
  }
  let token: SignedLivenessToken;
  try {
    token = JSON.parse(raw) as SignedLivenessToken;
  } catch (err) {
    return { live: false, reasons: [`liveness token unparseable: ${err instanceof Error ? err.message : String(err)}`] };
  }
  if (
    token.version !== GATE_LIVENESS_TOKEN_VERSION ||
    !Number.isSafeInteger(token.agent_uid) ||
    !Number.isSafeInteger(token.gate_port) ||
    !Number.isSafeInteger(token.generation_id) ||
    typeof token.live !== "boolean" ||
    !Number.isSafeInteger(token.expires_at) ||
    typeof token.sig !== "string"
  ) {
    return { live: false, reasons: ["liveness token malformed"] };
  }
  const claims: LivenessTokenClaims = {
    version: token.version,
    agent_uid: token.agent_uid,
    gate_port: token.gate_port,
    generation_id: token.generation_id,
    live: token.live,
    expires_at: token.expires_at,
  };
  let signatureOk: boolean;
  try {
    signatureOk = edVerify(null, canonicalLivenessPayload(claims), publicKey, Buffer.from(token.sig, "base64"));
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return { live: false, reasons: ["liveness token signature invalid (not signed by the pinned supervisor key)"] };
  }
  const reasons: string[] = [];
  if (token.live !== true) {
    reasons.push("supervisor reported the pf anchor not live");
  }
  if (now >= token.expires_at) {
    reasons.push(`liveness token expired (now ${now} >= expires_at ${token.expires_at})`);
  }
  if (token.agent_uid !== binding.agentUid) {
    reasons.push(`liveness token agent_uid ${token.agent_uid} != expected ${binding.agentUid}`);
  }
  if (token.gate_port !== binding.gatePort) {
    reasons.push(`liveness token gate_port ${token.gate_port} != expected ${binding.gatePort}`);
  }
  if (token.generation_id !== binding.generationId) {
    reasons.push(`liveness token generation ${token.generation_id} != expected ${binding.generationId}`);
  }
  return reasons.length === 0 ? { live: true, reasons: [] } : { live: false, reasons };
}

/**
 * Build the gate's {@link GateLivenessProbe} from a token source + pinned public
 * key + expected binding + clock. This is what `gate-server.ts` consumes as its
 * mandatory `livenessProbe`: each CONNECT reads and re-verifies the current
 * token (no positive is cached across requests -- that contract lives in the
 * gate), so a flushed/invalidated token denies on the very next CONNECT.
 *
 * The probe SELF-DECLARES `coalescing: "forbidden"` (the explicit oracle
 * marker, second-family fix-round): its `check()` is a subprocess-free file
 * read + signature verify, so coalescing concurrent CONNECTs onto one
 * in-flight read buys no amplification protection and would let a post-flush
 * CONNECT join a pre-flush green. `createExclusiveEgressGate` keys its
 * single-flight construction guard off this marker: wire this probe in, OMIT
 * `singleFlightLiveness`, and single-flight is auto-disabled (the S5-6
 * contract; callers change nothing).
 */
export function createOracleLivenessProbe(input: {
  source: LivenessTokenSource;
  publicKey: KeyObject;
  binding: LivenessProbeBinding;
  now?: () => number;
}): GateLivenessProbe {
  const clock = input.now ?? ((): number => Date.now());
  // SNAPSHOT the binding into an internal immutable copy (Codex F3 round-2). The
  // gate cross-checks the ADVERTISED binding at construction; if `check()` read
  // the caller-owned `input.binding` object at runtime, a post-construction
  // mutation of that object would let the checked (advertised) binding and the
  // enforced (runtime) binding DIVERGE -- construction passes for A, runtime
  // then verifies against a mutated B. Both the advertised `binding` and the
  // runtime `verifyLivenessToken` call read this frozen internal copy, so they
  // can never diverge regardless of what the caller does to `input.binding`.
  const bound: LivenessProbeBinding = Object.freeze({
    agentUid: input.binding.agentUid,
    gatePort: input.binding.gatePort,
    generationId: input.binding.generationId,
  });
  // The ADVERTISED binding (what the gate cross-checks at construction) is a
  // FROZEN object derived from the same snapshot the runtime `check()` uses, and
  // the whole probe is frozen (Codex F3 round-3). So neither `probe.binding`
  // (reassigning the property) nor `probe.binding.agentUid` (mutating the object)
  // can be changed after construction to pass the guard against one policy while
  // `check()` still verifies against another -- the checked binding and the
  // enforced binding are provably the same immutable values.
  const advertised = Object.freeze({ agentUid: bound.agentUid, gatePort: bound.gatePort });
  const publicKey = input.publicKey;
  // BIND the token-source method once (Codex round-7): runtime must not re-read
  // `source.read` off the caller's object, or a post-construction swap of
  // `.read` could feed an old unexpired signed token back after invalidation.
  const readToken = input.source.read.bind(input.source);
  const probe: GateLivenessProbe = {
    // The EXPLICIT oracle marker (never inferred from `binding`): this probe's
    // verdict must be read per-CONNECT; the gate refuses to coalesce it.
    coalescing: "forbidden",
    binding: advertised,
    async check(): Promise<PfLivenessResult> {
      let raw: string | null;
      try {
        raw = await readToken(bound.agentUid);
      } catch (err) {
        // A read error is fail-closed: deny, never default-live.
        return {
          live: false,
          reasons: [`liveness token read failed: ${err instanceof Error ? err.message : String(err)}`],
        };
      }
      return verifyLivenessToken({ raw, publicKey, binding: bound, now: clock() });
    },
  };
  return Object.freeze(probe);
}

/**
 * Production FS-backed oracle ops: atomic gate-readable token writes + a pfctl
 * probe. Root-only; the `probe` is injected by the caller (the shipped
 * `checkPfAnchorLiveness` bound to a `PfCommandRunner`). Arms nothing by itself.
 */
export function createFsLivenessOracleOps(input: {
  gateUid: number;
  probe: (arg: { agentUid: number; gatePort: number }) => Promise<PfLivenessResult>;
  dir?: string;
  now?: () => number;
}): LivenessOracleOps {
  const dir = input.dir ?? GATE_LIVENESS_DIR;
  const tokenPath = (uid: number): string => gateLivenessTokenPath(uid, dir);
  return {
    async writeToken(agentUid, payload): Promise<void> {
      const { open, mkdir, chmod, rename, rm } = await import("node:fs/promises");
      await mkdir(dir, { recursive: true, mode: 0o711 }).catch(() => undefined);
      // EXPLICIT traversal mode (see GATE_LIVENESS_DIR): the gate uid must be
      // able to search this dir to read its own 0600 token; mkdir's mode is
      // umask-masked and does nothing for a pre-existing dir.
      await chmod(dir, 0o711);
      const path = tokenPath(agentUid);
      const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
      const handle = await open(tmp, "wx", 0o600);
      try {
        await handle.writeFile(payload, "utf8");
        await handle.chown(input.gateUid, -1);
        await handle.chmod(0o600);
      } finally {
        await handle.close();
      }
      try {
        await rename(tmp, path);
      } catch (err) {
        await rm(tmp, { force: true }).catch(() => undefined);
        throw err;
      }
    },
    async removeToken(agentUid): Promise<void> {
      const { rm } = await import("node:fs/promises");
      await rm(tokenPath(agentUid), { force: true });
    },
    probe: input.probe,
    now: input.now ?? ((): number => Date.now()),
  };
}

/** Production FS-backed token source the gate uses (reads the token file). */
export function createFsLivenessTokenSource(dir: string = GATE_LIVENESS_DIR): LivenessTokenSource {
  return {
    async read(agentUid: number): Promise<string | null> {
      const { readFile } = await import("node:fs/promises");
      try {
        return await readFile(`${dir}/${agentUid}.token`, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return null;
        }
        throw err;
      }
    },
  };
}
