/**
 * Generation-bound, current-only bearer credential for the exclusive-egress
 * gate (Unified Protect Slice 5 S5-3, folds Codex M5; design 4b).
 *
 * THE PROBLEM. Loopback-TCP peer resolution (lsof/libproc, `peer-identity.ts`)
 * has a documented TOCTOU window and can legitimately fail under load (the
 * PEER_LOOKUP_MAX_CONCURRENT skip path), so peer uid alone cannot be the gate's
 * client-authorization primary. The gate is the sole sanctioned egress route,
 * so an unidentified client must get NOTHING -- but the primary evidence has to
 * be something the confined agent can present reliably per CONNECT and that a
 * lingering stale process (or a different local uid) cannot forge.
 *
 * THE MECHANISM. Root writes a random secret ATOMICALLY BEFORE the agent is
 * unparked (the S5-5 barrier), bound to the COMMITTED generation id. Two files,
 * both root-authored, neither writable by the agent:
 *
 *   - the AGENT TOKEN file `<agent_uid>.token` (owner agent_uid, 0600): the
 *     JSON `{ version, generation_id, secret }` the agent reads and presents on
 *     every CONNECT either via the native `Proxy-Authorization:
 *     Sanctuary-Gate <gen>.<secret>` header or the standard HTTP Basic proxy
 *     form whose password is that same `<gen>.<secret>` payload;
 *   - the GATE ACCEPT file `<agent_uid>.accept` (owner gate_uid, 0600): the
 *     JSON `{ version, generation_id, secret_sha256 }` the NON-ROOT gate reads.
 *     The gate holds only the HASH + the generation id -- never the raw secret,
 *     so a gate-file disclosure cannot forge a token, and the gate never needs
 *     root or the agent's file.
 *
 * WHY TWO FILES (cross-process, least privilege). Root is the only writer; the
 * agent can read only its token; the gate can read only the hash. Rotation
 * (a new G5 generation) rewrites both -- accept FIRST, then the agent token --
 * so the gate's accept-state for the new generation is in place before the new
 * token is readable, and a stale process still holding the OLD token presents
 * an OLD generation id that the gate rejects as `stale_generation` regardless.
 * Unprotect removes both (the gate then has no accept-state -> denies all).
 *
 * CURRENT-ONLY. The presented credential carries the generation id it was
 * minted for. The gate compares that against the accept file's committed
 * generation FIRST (a stale generation is rejected before any secret compare)
 * and only then compares the secret hash in CONSTANT TIME. So an old token can
 * never replay after a new generation commits, and a secret compare never
 * short-circuits on a length/prefix timing side channel.
 *
 * HOST-FREE. The authority and the accept-source are pure over injected ops
 * (secret minting, the atomic file writes, the file reads), so every branch is
 * unit-testable with no root, no host, no real filesystem. The FS-backed
 * defaults ({@link createFsGateCredentialAuthority}, {@link createFsGateAcceptSource})
 * are the production wiring the arming slice (S5-6) uses; they arm nothing on
 * their own.
 *
 * HONESTY BOUND. This is the credential PRIMITIVE only. It does not itself
 * authorize a CONNECT (that is `gate-client-auth.ts`, which combines this with
 * the peer lens fail-closed) and does not provision the gate uid
 * (`gate-account.ts`). It is WIRED (S5-6): the install flow
 * (`arming-wiring.ts`) mints the generation-bound credential strictly before
 * unpark and revokes it on the coarse restore. It advances no capability
 * claim: the Erik-present S5-DRILL is still owed.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Root-owned parent directory for the gate credential files. Mode 0711
 * (fix-round BLOCKER-2; asserted by `runtime-fs-plan.ts` at arming time):
 * root-only write + listing, but EXECUTE/SEARCH for everyone so the two
 * non-root readers can traverse to the one file each is entitled to --
 * the GATE uid reads its 0600 `<uid>.accept`, the AGENT uid reads its 0600
 * `<uid>.token`. A 0700 parent (the pre-fix state) blocked both reads and
 * made every CONNECT deny; per-file 0600 + ownership still bind each file
 * to exactly its intended reader.
 */
export const GATE_CRED_DIR = "/var/db/sanctuary/gate-cred";

/** The `Proxy-Authorization` auth-scheme token the agent presents. */
export const GATE_AUTH_SCHEME = "Sanctuary-Gate";

/** Fixed Basic-auth username; identity is still only the uid + generation-bound secret. */
export const GATE_PROXY_BASIC_USERNAME = "sanctuary-gate";

/** On-disk schema version for both credential files. */
export const GATE_CREDENTIAL_VERSION = 1 as const;

/** Random secret length in bytes (256-bit). */
export const GATE_CREDENTIAL_SECRET_BYTES = 32;

/** The agent-readable token file contents. */
export interface GateCredentialToken {
  version: typeof GATE_CREDENTIAL_VERSION;
  generation_id: number;
  /** Hex-encoded random secret. */
  secret: string;
}

/** The gate-readable accept-state (the hash, never the raw secret). */
export interface GateCredentialAcceptRecord {
  version: typeof GATE_CREDENTIAL_VERSION;
  generation_id: number;
  /** Hex sha256 of the secret. */
  secret_sha256: string;
}

/** A parsed generation-bound credential from either accepted proxy-auth scheme. */
export interface PresentedGateCredential {
  generation_id: number;
  secret: string;
}

/** Why a presented credential failed the credential-only check. */
export type GateCredentialDenyReason =
  | "no_accept_state"
  | "no_credential"
  | "malformed_credential"
  | "stale_generation"
  | "bad_secret";

/** The credential-only verdict (peer lens is layered on in gate-client-auth.ts). */
export type GateCredentialVerdict =
  | { ok: true }
  | { ok: false; reason: GateCredentialDenyReason };

/** Injected side effects for the root-side authority (host-free in tests). */
export interface GateCredentialAuthorityOps {
  /** Mint a fresh random secret (hex). Default: 32 CSPRNG bytes. */
  mintSecret(): string;
  /**
   * Atomically write the gate-readable accept file for `agentUid`
   * (owner gate_uid, 0600). Production: tmp-write + fchown(gate_uid) + rename.
   */
  writeAccept(agentUid: number, payload: string): Promise<void>;
  /**
   * Atomically write the agent-readable token file for `agentUid`
   * (owner agent_uid, 0600). Production: tmp-write + fchown(agent_uid) + rename.
   */
  writeToken(agentUid: number, payload: string): Promise<void>;
  /** Remove BOTH credential files for `agentUid` (ENOENT is not an error). */
  remove(agentUid: number): Promise<void>;
}

/** Read-only accept-state source the gate consults (reads the `.accept` file). */
export interface GateAcceptSource {
  /** The committed accept-state for `agentUid`, or null if none exists. */
  current(agentUid: number): Promise<GateCredentialAcceptRecord | null>;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Format the header value the agent sends. Exported so the agent-side harness
 * (S5-6) and the tests format it identically to what {@link parseGateCredentialHeader}
 * accepts.
 */
export function formatGateCredentialHeader(token: {
  generation_id: number;
  secret: string;
}): string {
  return `${GATE_AUTH_SCHEME} ${token.generation_id}.${token.secret}`;
}

/**
 * Format the standard Basic proxy-auth header that unmodified HTTP clients
 * produce from `http://user:pass@host:port` proxy URLs. The password carries
 * the exact same payload {@link verifyGateCredential} verifies.
 */
export function formatGateCredentialBasicHeader(token: {
  generation_id: number;
  secret: string;
}): string {
  return `Basic ${Buffer.from(
    `${GATE_PROXY_BASIC_USERNAME}:${token.generation_id}.${token.secret}`,
    "utf8",
  ).toString("base64")}`;
}

function parseGateCredentialPayload(payload: string): PresentedGateCredential | null {
  const dot = payload.indexOf(".");
  if (dot <= 0 || dot === payload.length - 1) {
    return null;
  }
  const genPart = payload.slice(0, dot);
  const secret = payload.slice(dot + 1);
  if (!/^\d+$/.test(genPart)) {
    return null;
  }
  const generation_id = Number(genPart);
  if (!Number.isSafeInteger(generation_id) || generation_id < 0) {
    return null;
  }
  if (!/^[0-9a-f]+$/.test(secret)) {
    return null;
  }
  return { generation_id, secret };
}

function strictBase64Decode(value: string): string | null {
  if (value.length === 0 || /\s/.test(value)) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  if (value.includes("=") && value.length % 4 !== 0) {
    return null;
  }
  const remainder = value.length % 4;
  if (remainder === 1) {
    return null;
  }
  const normalized = `${value}${"=".repeat((4 - remainder) % 4)}`;
  const decoded = Buffer.from(normalized, "base64");
  const canonical = decoded.toString("base64").replace(/=+$/, "");
  if (canonical !== value.replace(/=+$/, "")) {
    return null;
  }
  return decoded.toString("utf8");
}

function parseBasicGateCredential(payload: string): PresentedGateCredential | null {
  const decoded = strictBase64Decode(payload);
  if (decoded === null) {
    return null;
  }
  const colon = decoded.indexOf(":");
  if (colon <= 0) {
    return null;
  }
  const username = decoded.slice(0, colon);
  if (username !== GATE_PROXY_BASIC_USERNAME) {
    return null;
  }
  return parseGateCredentialPayload(decoded.slice(colon + 1));
}

/**
 * Parse a `Proxy-Authorization` header value into a presented credential, or
 * null if it is absent/malformed. STRICT by construction (fail-closed): the
 * scheme must be either the native Sanctuary scheme or HTTP Basic with the
 * fixed username above, the generation id must be a non-negative integer, and
 * the secret must be a non-empty lowercase-hex string. A header array (Node
 * folds duplicate headers) is rejected -- the gate accepts exactly one.
 */
export function parseGateCredentialHeader(
  headerValue: string | string[] | undefined,
): PresentedGateCredential | null {
  if (typeof headerValue !== "string") {
    // undefined (absent) or string[] (duplicated header) -> no single credential.
    return null;
  }
  const trimmed = headerValue.trim();
  const separator = trimmed.indexOf(" ");
  if (separator <= 0) {
    return null;
  }
  const scheme = trimmed.slice(0, separator);
  const rest = trimmed.slice(separator + 1);
  if (scheme === GATE_AUTH_SCHEME) {
    return parseGateCredentialPayload(rest);
  }
  if (scheme.toLowerCase() === "basic") {
    return parseBasicGateCredential(rest);
  }
  return null;
}

/**
 * Constant-time verify of a presented credential against the committed
 * accept-state. Fail-closed at every branch:
 *   - no accept-state (unprotected / not yet minted) -> `no_accept_state`;
 *   - no/undefined presented credential -> `no_credential`;
 *   - generation mismatch -> `stale_generation` (checked BEFORE the secret, so a
 *     stale token never even reaches the secret compare);
 *   - secret hash mismatch -> `bad_secret`, compared with {@link timingSafeEqual}
 *     over the fixed-length sha256 digests (no early-out timing leak).
 * A presented credential of `null` is `no_credential` (not silently allowed).
 */
export function verifyGateCredential(
  accept: GateCredentialAcceptRecord | null,
  presented: PresentedGateCredential | null,
): GateCredentialVerdict {
  if (accept === null) {
    return { ok: false, reason: "no_accept_state" };
  }
  if (presented === null) {
    return { ok: false, reason: "no_credential" };
  }
  if (presented.generation_id !== accept.generation_id) {
    return { ok: false, reason: "stale_generation" };
  }
  const presentedHash = Buffer.from(sha256Hex(presented.secret), "utf8");
  const committedHash = Buffer.from(accept.secret_sha256, "utf8");
  // Digests are fixed-length (64 hex chars); a defensive length guard keeps
  // timingSafeEqual from throwing on a malformed stored hash.
  if (presentedHash.length !== committedHash.length) {
    return { ok: false, reason: "bad_secret" };
  }
  if (!timingSafeEqual(presentedHash, committedHash)) {
    return { ok: false, reason: "bad_secret" };
  }
  return { ok: true };
}

/**
 * The root-side credential authority: mints/rotates/revokes the
 * generation-bound bearer credential. Host-free (every side effect injected).
 */
export class GateCredentialAuthority {
  constructor(private readonly ops: GateCredentialAuthorityOps) {}

  /**
   * Mint (or rotate to) the credential for a committed generation. Writes the
   * gate ACCEPT file FIRST, then the agent TOKEN file, so the gate's
   * accept-state is in place before the token becomes readable (a same-uid
   * process that reads a half-written state can never present a secret the gate
   * would accept). Returns the accept record the gate will verify against.
   * Idempotent per (uid, generation) only in effect, not in bytes: each call
   * mints a FRESH secret, so re-minting the same generation rotates the secret
   * (the prior secret stops working immediately).
   */
  async mint(input: { agentUid: number; generationId: number }): Promise<GateCredentialAcceptRecord> {
    const { agentUid, generationId } = input;
    if (!Number.isInteger(agentUid) || agentUid <= 0) {
      throw new Error(`gate credential: refusing to mint for a non-positive/root agent uid ${String(agentUid)}`);
    }
    if (!Number.isSafeInteger(generationId) || generationId < 0) {
      throw new Error(`gate credential: refusing to mint for an invalid generation id ${String(generationId)}`);
    }
    const secret = this.ops.mintSecret();
    if (typeof secret !== "string" || !/^[0-9a-f]+$/.test(secret) || secret.length < 2) {
      throw new Error("gate credential: mintSecret produced a non-hex/empty secret (refusing to write a weak credential)");
    }
    const accept: GateCredentialAcceptRecord = {
      version: GATE_CREDENTIAL_VERSION,
      generation_id: generationId,
      secret_sha256: sha256Hex(secret),
    };
    const token: GateCredentialToken = {
      version: GATE_CREDENTIAL_VERSION,
      generation_id: generationId,
      secret,
    };
    await this.ops.writeAccept(agentUid, JSON.stringify(accept));
    await this.ops.writeToken(agentUid, JSON.stringify(token));
    return accept;
  }

  /** Remove both credential files (unprotect / abort). Fail-closed for the gate. */
  async revoke(agentUid: number): Promise<void> {
    await this.ops.remove(agentUid);
  }
}

/** Default CSPRNG secret mint: 32 hex-encoded random bytes. */
export function mintGateSecret(): string {
  return randomBytes(GATE_CREDENTIAL_SECRET_BYTES).toString("hex");
}

/**
 * The uid's gate-readable ACCEPT file path (the sha256 accept-state). The
 * SINGLE source for this path shape: the fs authority writes/removes through
 * it, and the S5-7 unprotect teardown removes it directly (revoke must work
 * even when the gate service account is already gone, so the teardown never
 * needs a `gateUid` to construct an authority).
 */
export function gateCredentialAcceptPath(agentUid: number, dir: string = GATE_CRED_DIR): string {
  return `${dir}/${agentUid}.accept`;
}

/** The uid's agent-readable bearer TOKEN file path (see {@link gateCredentialAcceptPath}). */
export function gateCredentialTokenPath(agentUid: number, dir: string = GATE_CRED_DIR): string {
  return `${dir}/${agentUid}.token`;
}

/**
 * The fs surface {@link createFsGateCredentialAuthority} writes through.
 * Injectable (tests pin the EXACT ownership/mode sequence with a recorder,
 * fix-round BLOCKER-2); production uses `node:fs/promises`.
 */
export interface GateCredentialFsOps {
  open(path: string, flags: string, mode: number): Promise<{
    writeFile(data: string, encoding: string): Promise<void>;
    chown(uid: number, gid: number): Promise<void>;
    chmod(mode: number): Promise<void>;
    close(): Promise<void>;
  }>;
  mkdir(path: string, options: { recursive: boolean; mode: number }): Promise<unknown>;
  chmod(path: string, mode: number): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  rm(path: string, options: { force: boolean }): Promise<void>;
}

async function defaultGateCredentialFsOps(): Promise<GateCredentialFsOps> {
  const { open, mkdir, chmod, rename, rm } = await import("node:fs/promises");
  return { open, mkdir, chmod, rename, rm } as GateCredentialFsOps;
}

/**
 * Production FS-backed authority. Atomic writes (tmp + rename); the caller-owned
 * `chown` binds each file to its reader (accept -> gate uid, token -> agent uid)
 * before the rename so the file is never briefly world-readable at its final
 * path. The parent dir is created/re-asserted 0711 with an EXPLICIT chmod
 * (mkdir's mode is umask-masked and does nothing for a pre-existing 0700 dir
 * from an older build) so both readers can traverse to their own file -- see
 * {@link GATE_CRED_DIR}. Root-only in practice; drill/wiring surface, arms
 * nothing by itself.
 */
export function createFsGateCredentialAuthority(input: {
  gateUid: number;
  dir?: string;
  mintSecret?: () => string;
  /** TEST SEAM: recorder fs ops (production always uses node:fs/promises). */
  fsOps?: GateCredentialFsOps;
}): GateCredentialAuthority {
  const dir = input.dir ?? GATE_CRED_DIR;
  const acceptPath = (uid: number): string => gateCredentialAcceptPath(uid, dir);
  const tokenPath = (uid: number): string => gateCredentialTokenPath(uid, dir);

  async function atomicWrite(path: string, payload: string, ownerUid: number): Promise<void> {
    const fs = input.fsOps ?? (await defaultGateCredentialFsOps());
    await fs.mkdir(dir, { recursive: true, mode: 0o711 }).catch(() => undefined);
    // EXPLICIT traversal mode (never umask/creation-order luck): both the
    // gate uid (.accept) and the agent uid (.token) must be able to search
    // this root-owned dir. Loud on failure: a credential the reader cannot
    // reach is a guaranteed all-deny, better surfaced at mint time.
    await fs.chmod(dir, 0o711);
    const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
    const handle = await fs.open(tmp, "wx", 0o600);
    try {
      await handle.writeFile(payload, "utf8");
      // Bind ownership BEFORE the rename so the file is never at its final,
      // reader-discoverable path while still owned by root-with-wrong-mode.
      await handle.chown(ownerUid, -1);
      await handle.chmod(0o600);
    } finally {
      await handle.close();
    }
    try {
      await fs.rename(tmp, path);
    } catch (err) {
      await fs.rm(tmp, { force: true }).catch(() => undefined);
      throw err;
    }
  }

  return new GateCredentialAuthority({
    mintSecret: input.mintSecret ?? mintGateSecret,
    async writeAccept(agentUid, payload): Promise<void> {
      await atomicWrite(acceptPath(agentUid), payload, input.gateUid);
    },
    async writeToken(agentUid, payload): Promise<void> {
      await atomicWrite(tokenPath(agentUid), payload, agentUid);
    },
    async remove(agentUid): Promise<void> {
      const fs = input.fsOps ?? (await defaultGateCredentialFsOps());
      await fs.rm(acceptPath(agentUid), { force: true });
      await fs.rm(tokenPath(agentUid), { force: true });
    },
  });
}

/**
 * Production FS-backed accept-source the NON-ROOT gate uses: reads the
 * `<agent_uid>.accept` file (gate-readable), returns null when absent
 * (fail-closed: the gate denies all). A malformed/partial file surfaces as a
 * throw the gate turns into a deny (never a silent allow).
 */
export function createFsGateAcceptSource(dir: string = GATE_CRED_DIR): GateAcceptSource {
  return {
    async current(agentUid: number): Promise<GateCredentialAcceptRecord | null> {
      const { readFile } = await import("node:fs/promises");
      let text: string;
      try {
        text = await readFile(`${dir}/${agentUid}.accept`, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return null;
        }
        throw err;
      }
      const parsed = JSON.parse(text) as GateCredentialAcceptRecord;
      if (
        parsed.version !== GATE_CREDENTIAL_VERSION ||
        !Number.isSafeInteger(parsed.generation_id) ||
        typeof parsed.secret_sha256 !== "string" ||
        !/^[0-9a-f]{64}$/.test(parsed.secret_sha256)
      ) {
        throw new Error(`gate accept file for uid ${agentUid} is malformed`);
      }
      return parsed;
    },
  };
}
