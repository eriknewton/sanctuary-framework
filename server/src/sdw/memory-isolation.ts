/**
 * One-owner-per-fortress isolation for the shared SDW memory scope.
 *
 * The SDW memory adapter wired in index.ts is bound to ONE `fleet-self` owner
 * scope reused for every caller. Production binds that scope to one wrapped
 * identity in an authenticated fortress record and refuses every distinct
 * correctly wrapped identity, including callers in another server process.
 *
 * It lives in its own file because EVERY tool family that reaches the shared
 * scope has to share ONE guard instance. Two guards over the same scope each
 * pin their own first caller, so a second agent refused by one family would
 * still be the first caller of the other and get through it. Read paths and
 * bulk plaintext export paths are the same custody question.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  createSdwOwnerPinIfAbsent,
  readSdwOwnerPin,
  replaceSdwOwnerPinIfEquals,
  SDW_OWNER_PIN_KEY,
  type SdwOwnerPinData,
} from "./write-gate.js";
import {
  SDW_CATALOG_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
} from "./records.js";
import { MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE } from "./memory-provenance-bad-signers.js";
import { LOCAL_HARNESS_KINDS } from "../contracts/v1.1/local-agent-records.js";

/**
 * The process-local test implementation below is strictly additive:
 * - No `ownerIdentity` resolver -> no second identity can ever be observed ->
 *   the guard is a strict NO-OP (existing single-agent behavior unchanged).
 * - A single coordinator resolves a stable value (or a stable `undefined`);
 *   the bound identity is pinned once and every call matches it -> NO-OP.
 * - Any call whose resolved identity differs from the pinned one is REFUSED.
 *   The pin is NOT advanced to the new identity, so the guard cannot be walked
 *   forward by alternating callers; the shared scope stays bound to whoever
 *   touched it first.
 *
 * `undefined` is treated as a concrete identity value (the "no wrapped-agent
 * id configured" caller). Mixing a concrete id with `undefined` is therefore
 * two distinct identities and is refused: a configured agent must not share
 * the unconfigured coordinator's scope.
 */
/**
 * The production identity resolver every guard instance in index.ts is built
 * over. It reads `SANCTUARY_AGENT_ID` from the SERVER's own process
 * environment, which `sanctuary wrap` writes into the harness's `sanctuary`
 * MCP entry at wrap time (must match `SANCTUARY_AGENT_ID` in
 * `wrap/cli.ts:buildSanctuaryEnv`; the value is `wrappedAgentId(...)`).
 *
 * INVARIANT: the guard keys on this wrap-time, operator-bound identity and
 * NEVER on a value the agent asserts in a tool argument or mints for itself.
 *
 * BOUND (stated, not softened): the value is plaintext in the harness-owned
 * config and accepted as the cooperative-mode identity. The durable guard
 * separates distinct correctly wrapped processes; it does not defend against
 * an agent that can rewrite and relaunch another harness's complete MCP entry.
 */
export function wrappedAgentIdentityFromEnv(): string | undefined {
  return process.env.SANCTUARY_AGENT_ID;
}

/**
 * The ONE place the wrapped harness id's SHAPE is pinned for the SDW owner
 * pin (register row `SDW-OWNER-PIN-AGENT-ID-SHAPE-01`). The rule binds
 * wherever a NEW pin could name an id: establishment of a fresh store
 * (`checkOrEstablishSdwOwnerPin`, and `precheckSdwOwnerPin` reporting a store
 * as establishable), `claimSdwOwnerForOperator`'s owner, and
 * `transferSdwOwnerForOperator`'s new owner. Each refuses a non-conforming id
 * before any write, so no caller (the MCP guard, the four memory-file CLI
 * verbs, `sdw-owner claim` and `transfer`) can pin the store to a principal
 * the wrapped server never presents.
 *
 * The form is what `sanctuary wrap` mints: must match `wrappedAgentId` in
 * `wrap/cli.ts` (which carries the reciprocal pin, and
 * `test/sdw/wrapped-agent-id-mint-parity.test.ts` builds ids through it and
 * asserts this rule accepts every one) (`${harnessKindForPlatform(platform)}:${fortressIdFromStoragePath(storagePath)}`),
 * whose two halves are `LOCAL_HARNESS_KINDS` in
 * `contracts/v1.1/local-agent-records.ts` (imported, never mirrored: AGENTS
 * rule 5) and `fortressIdFromStoragePath` in `dashboard/v1_1/wiring.ts`
 * (`fortress-` plus the first 16 hex characters of the storage path's sha256;
 * 16 = that function's `digest.slice(0, 16)`, half of the 32 hex characters a
 * 16-byte prefix would be and a quarter of the 64 a full sha256 hex is).
 *
 * INVARIANT: the shape check is a CONSISTENCY guard, not authentication. A
 * well-formed id is still only the cooperative-mode identity the wrap wrote
 * into the harness config (see `wrappedAgentIdentityFromEnv`); passing this
 * check proves the value could have been minted by `wrap`, never that it was.
 *
 * LEGACY PINS (written before this rule) are NOT refused on read. When a
 * store is already pinned, the caller is compared against the stored
 * `agent_id` exactly as before: the legacy owner presenting that same id is
 * ALLOWED, and the result carries `legacyPin: true` so the caller writes a
 * one-line legacy note to its audit trail (the MCP guard via `onLegacyPin`,
 * the CLI verbs via their own audit row) and the operator learns the pin
 * predates the form. Refusing here would lock every existing store out on
 * upgrade, which the register row never asked for. `transfer`'s
 * `expectedAgentId` is likewise exempt, so a legacy pin is recoverable
 * through the interactive transfer to a conforming id.
 */
export const WRAPPED_AGENT_ID_FORTRESS_HEX_LENGTH = 16;
export const WRAPPED_AGENT_ID_PATTERN: RegExp = new RegExp(
  `^(${LOCAL_HARNESS_KINDS.join("|")}):fortress-[0-9a-f]{${WRAPPED_AGENT_ID_FORTRESS_HEX_LENGTH}}$`,
);

/** True iff `value` has the wrapped harness id form `<harness-kind>:fortress-<16 hex>`. */
export function isWrappedAgentId(value: string): boolean {
  return WRAPPED_AGENT_ID_PATTERN.test(value);
}

export type IsolationRefusalReason =
  | "owner_identity_missing"
  | "owner_identity_malformed"
  | "owner_scope_conflict"
  | "owner_pin_invalid"
  | "owner_pin_missing_after_establishment"
  | "owner_pin_backend_unsupported"
  | "owner_pin_io_error";

export type MultiAgentIsolationGuard = (
  operation: string,
) => Promise<
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: IsolationRefusalReason }
>;

export function createMultiAgentIsolationGuard(
  ownerIdentity: (() => string | undefined) | undefined,
): MultiAgentIsolationGuard {
  // Sentinel so we can distinguish "never observed an identity" from "observed
  // `undefined`" without conflating the two.
  let bound: { value: string | undefined } | null = null;
  return async (_operation: string) => {
    if (ownerIdentity === undefined) {
      // No resolver wired: a second identity can never be observed. NO-OP.
      return { allowed: true };
    }
    const observed = ownerIdentity();
    if (bound === null) {
      bound = { value: observed };
      return { allowed: true };
    }
    return bound.value === observed
      ? { allowed: true }
      : { allowed: false, reason: "owner_scope_conflict" };
  };
}

export interface PersistentIsolationGuardOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly ownerIdentity: () => string | undefined;
  readonly now?: () => string;
  /**
   * Called at most ONCE per guard (per server process) the first time an
   * allowed call finds the store pinned to a legacy, pre-wrapped-form id, so
   * the composition root can write the one-line legacy note to the audit log.
   * A note, not a security dependency: the allow/refuse decision never
   * depends on it, so omitting it cannot weaken the guard (AGENTS rule 3).
   * Once-per-process bounds the audit writes a long-lived server makes
   * (AGENTS rule 8): one entry, not one per call.
   */
  readonly onLegacyPin?: (storedAgentId: string) => void | Promise<void>;
}

export { readSdwOwnerPin } from "./write-gate.js";

const SDW_ESTABLISHMENT_NAMESPACES = [
  SDW_CATALOG_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  MEMORY_PROVENANCE_BAD_SIGNER_NAMESPACE,
] as const;

async function sdwStoreEstablished(storage: StorageBackend): Promise<boolean> {
  for (const namespace of SDW_ESTABLISHMENT_NAMESPACES) {
    const entries = await storage.list(namespace);
    if (
      entries.some(
        (entry) =>
          namespace !== SDW_META_NAMESPACE || entry.key !== SDW_OWNER_PIN_KEY,
      )
    ) {
      return true;
    }
  }
  return false;
}

function pinData(
  fortressId: string,
  ownerRef: string,
  agentId: string,
  now: () => string,
): SdwOwnerPinData {
  return {
    version: 1,
    fortress_id: fortressId,
    owner_ref: ownerRef,
    agent_id: agentId,
    pinned_at: now(),
  };
}

function sameScope(
  data: Pick<SdwOwnerPinData, "fortress_id" | "owner_ref">,
  fortressId: string,
  ownerRef: string,
): boolean {
  return data.fortress_id === fortressId && data.owner_ref === ownerRef;
}

export interface SdwOwnerPinCheckOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly agentId: string;
  readonly now?: () => string;
}

export type SdwOwnerPinCheckResult =
  // `legacyPin` is present (true) only when the stored owner id predates the
  // wrapped form; see the LEGACY PINS note on WRAPPED_AGENT_ID_PATTERN.
  | { readonly allowed: true; readonly legacyPin?: true }
  | { readonly allowed: false; readonly reason: IsolationRefusalReason };

/**
 * Shared owner-pin check-or-establish rule. Every caller below MUST route
 * through this one function so a fresh store can only ever be established
 * once, by whichever caller writes first, under one shared rule:
 *   - `createPersistentMultiAgentIsolationGuard` (this file), the per-MCP-call
 *     guard, calls it with the wrap-time `SANCTUARY_AGENT_ID`.
 *   - `runMemoryIngestCommand`, `runMemoryEmitCommand`, `runMemoryTranscodeCommand`
 *     and `runMemoryTranscodeRestoreCommand` in `server/src/cli/memory-file.ts`
 *     (must match the import there) all call it with the CLI's resolved
 *     wrap-time agent id, so a CLI-first write on a fresh fortress, through
 *     ANY of the four verbs, establishes the SAME pin the MCP guard would
 *     have, instead of leaving the store established with no pin (STEP1-F1
 *     covered `memory_ingest`; STEP1-F2 extended the same rule to the other
 *     three so the drift could not recur through a sibling path: that drift
 *     left every later MCP read refused with
 *     `owner_pin_missing_after_establishment` until a manual `sdw-owner
 *     claim`).
 * An empty SDW scope is claimed through atomic create-if-absent; a used
 * legacy scope with no pin refuses until an operator explicitly claims it.
 */
export async function checkOrEstablishSdwOwnerPin(
  options: SdwOwnerPinCheckOptions,
): Promise<SdwOwnerPinCheckResult> {
  const now = options.now ?? (() => new Date().toISOString());
  const refuse = (reason: IsolationRefusalReason) => ({
    allowed: false as const,
    reason,
  });
  try {
    let pin = await readSdwOwnerPin(options.storage, options.masterKey);
    if (pin.status === "absent") {
      // ESTABLISHMENT shape check: a malformed id must never reach
      // `createSdwOwnerPinIfAbsent` below, or a fresh store would be pinned to
      // a principal no wrapped server presents (the register row's defect).
      if (!isWrappedAgentId(options.agentId)) return refuse("owner_identity_malformed");
      if (await sdwStoreEstablished(options.storage)) {
        return refuse("owner_pin_missing_after_establishment");
      }
      const created = await createSdwOwnerPinIfAbsent(
        options.storage,
        options.masterKey,
        pinData(options.fortressId, options.ownerRef, options.agentId, now),
      );
      if (created === "unsupported") {
        return refuse("owner_pin_backend_unsupported");
      }
      // The record on disk is authoritative. Two first callers may both
      // observe absence, but only one atomic create can win; the loser sees
      // the winner here and is refused on this same first call.
      pin = await readSdwOwnerPin(options.storage, options.masterKey);
    }
    if (
      pin.status !== "valid" ||
      !sameScope(pin.data, options.fortressId, options.ownerRef)
    ) {
      return refuse("owner_pin_invalid");
    }
    if (pin.data.agent_id !== options.agentId) return refuse("owner_scope_conflict");
    // READ of an existing pin: never refused for shape (see LEGACY PINS).
    return isWrappedAgentId(pin.data.agent_id)
      ? { allowed: true }
      : { allowed: true, legacyPin: true };
  } catch {
    return refuse("owner_pin_io_error");
  }
}

export type SdwOwnerPinPrecheckResult =
  | { readonly status: "pinned"; readonly legacyPin?: true }
  | { readonly status: "fresh" }
  | { readonly status: "refuse"; readonly reason: IsolationRefusalReason };

/**
 * READ-ONLY counterpart to `checkOrEstablishSdwOwnerPin`, for a caller whose
 * own authorization gate has not run yet (STEP1-F1 fix round 1: the pin must
 * never be created before Tier-1 approval, AGENTS.md #3 "no irreversible
 * operation without a confirmation gate"). NEVER calls
 * `createSdwOwnerPinIfAbsent` or otherwise writes. All four memory-file CLI
 * verbs in `server/src/cli/memory-file.ts` (`runMemoryIngestCommand`,
 * `runMemoryEmitCommand`, `runMemoryTranscodeCommand`,
 * `runMemoryTranscodeRestoreCommand`; STEP1-F1 wired the first, STEP1-F2 the
 * other three) call this BEFORE their own approval dialog, so an
 * already-decidable refusal (a different agent's pin, or a used-but-unpinned
 * legacy store) never bothers the operator; a genuinely fresh, untouched store
 * reports "fresh" and establishment is deferred to `checkOrEstablishSdwOwnerPin`,
 * run only from inside that caller's OWN approved branch.
 */
export async function precheckSdwOwnerPin(
  options: Omit<SdwOwnerPinCheckOptions, "now">,
): Promise<SdwOwnerPinPrecheckResult> {
  try {
    const pin = await readSdwOwnerPin(options.storage, options.masterKey);
    if (pin.status === "absent") {
      // Same ESTABLISHMENT shape rule as `checkOrEstablishSdwOwnerPin`, so a
      // CLI verb's pre-approval precheck refuses a malformed id before the
      // operator is asked, rather than reporting the store "fresh".
      if (!isWrappedAgentId(options.agentId)) {
        return { status: "refuse", reason: "owner_identity_malformed" };
      }
      if (await sdwStoreEstablished(options.storage)) {
        return { status: "refuse", reason: "owner_pin_missing_after_establishment" };
      }
      return { status: "fresh" };
    }
    if (
      pin.status !== "valid" ||
      !sameScope(pin.data, options.fortressId, options.ownerRef)
    ) {
      return { status: "refuse", reason: "owner_pin_invalid" };
    }
    if (pin.data.agent_id !== options.agentId) {
      return { status: "refuse", reason: "owner_scope_conflict" };
    }
    // READ of an existing pin: never refused for shape (see LEGACY PINS).
    return isWrappedAgentId(pin.data.agent_id)
      ? { status: "pinned" }
      : { status: "pinned", legacyPin: true };
  } catch {
    return { status: "refuse", reason: "owner_pin_io_error" };
  }
}

/**
 * Production guard. Every wrapped harness starts a separate server process,
 * so the owner lives in a MAC-authenticated fortress record and is checked on
 * every call. Missing wrap identity always refuses; the establish-or-check
 * rule itself is `checkOrEstablishSdwOwnerPin` above, shared with the CLI
 * ingest path.
 */
/**
 * One-line operator note for a store pinned to a legacy owner id. Written to
 * the audit trail by the MCP composition root (`onLegacyPin` in
 * `src/index.ts`) and by the memory-file CLI verbs; the store keeps working.
 */
export function sdwLegacyOwnerPinNote(storedAgentId: string): string {
  return (
    `LEGACY SDW owner pin: agent_id ${JSON.stringify(storedAgentId)} predates the wrapped form ` +
    `<harness-kind>:fortress-<${WRAPPED_AGENT_ID_FORTRESS_HEX_LENGTH} hex>; the store still works, ` +
    `and 'sanctuary sdw-owner transfer' can move it to a wrapped id`
  );
}

export function createPersistentMultiAgentIsolationGuard(
  options: PersistentIsolationGuardOptions,
): MultiAgentIsolationGuard {
  let legacyNoted = false;
  return async (_operation: string) => {
    const observed = options.ownerIdentity();
    if (observed === undefined || observed.length === 0) {
      return { allowed: false, reason: "owner_identity_missing" };
    }
    const result = await checkOrEstablishSdwOwnerPin({
      storage: options.storage,
      masterKey: options.masterKey,
      fortressId: options.fortressId,
      ownerRef: options.ownerRef,
      agentId: observed,
      ...(options.now !== undefined ? { now: options.now } : {}),
    });
    if (!result.allowed) return result;
    if (result.legacyPin === true && !legacyNoted) {
      legacyNoted = true;
      try {
        await options.onLegacyPin?.(observed);
      } catch {
        // The note is advisory; a failed audit append must not turn an
        // allowed read into a refusal or a crash.
      }
    }
    return { allowed: true };
  };
}

export type OwnerClaimResult =
  | { readonly status: "claimed" }
  | { readonly status: "agent_id_malformed" }
  | { readonly status: "already_claimed"; readonly agentId: string }
  | { readonly status: "invalid" }
  | { readonly status: "unsupported" }
  | { readonly status: "claim_lost" };

/** Explicit legacy-store migration. The production guard never calls this. */
export async function claimSdwOwnerForOperator(options: {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly agentId: string;
  readonly now?: () => string;
}): Promise<OwnerClaimResult> {
  // The operator-typed id is the free text the register row names; it is
  // refused here, before the atomic create, under the one shared shape rule.
  if (!isWrappedAgentId(options.agentId)) return { status: "agent_id_malformed" };
  const existing = await readSdwOwnerPin(options.storage, options.masterKey);
  if (existing.status === "invalid") return { status: "invalid" };
  if (existing.status === "valid") {
    return { status: "already_claimed", agentId: existing.data.agent_id };
  }
  const created = await createSdwOwnerPinIfAbsent(
    options.storage,
    options.masterKey,
    pinData(
      options.fortressId,
      options.ownerRef,
      options.agentId,
      options.now ?? (() => new Date().toISOString()),
    ),
  );
  if (created === "unsupported") return { status: "unsupported" };
  const after = await readSdwOwnerPin(options.storage, options.masterKey);
  if (
    after.status === "valid" &&
    sameScope(after.data, options.fortressId, options.ownerRef) &&
    after.data.agent_id === options.agentId
  ) {
    return { status: "claimed" };
  }
  return { status: "claim_lost" };
}

export type OwnerTransferResult =
  | { readonly status: "transferred" }
  | { readonly status: "agent_id_malformed" }
  | { readonly status: "absent" }
  | { readonly status: "invalid" }
  | { readonly status: "owner_mismatch"; readonly agentId: string }
  | { readonly status: "unsupported" }
  | { readonly status: "changed" };

/** Atomic operator-approved owner rotation; never a blind overwrite. */
export async function transferSdwOwnerForOperator(options: {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly expectedAgentId: string;
  readonly newAgentId: string;
  readonly now?: () => string;
}): Promise<OwnerTransferResult> {
  // Only the NEW owner is shape-checked: `expectedAgentId` must be allowed to
  // name a malformed legacy pin, or such a pin could never be transferred away.
  if (!isWrappedAgentId(options.newAgentId)) return { status: "agent_id_malformed" };
  const existing = await readSdwOwnerPin(options.storage, options.masterKey);
  if (existing.status === "absent") return { status: "absent" };
  if (
    existing.status !== "valid" ||
    !sameScope(existing.data, options.fortressId, options.ownerRef)
  ) {
    return { status: "invalid" };
  }
  if (existing.data.agent_id !== options.expectedAgentId) {
    return { status: "owner_mismatch", agentId: existing.data.agent_id };
  }
  const replaced = await replaceSdwOwnerPinIfEquals(
    options.storage,
    options.masterKey,
    existing.raw,
    pinData(
      options.fortressId,
      options.ownerRef,
      options.newAgentId,
      options.now ?? (() => new Date().toISOString()),
    ),
  );
  if (replaced === "unsupported") return { status: "unsupported" };
  if (replaced === "changed") return { status: "changed" };
  const after = await readSdwOwnerPin(options.storage, options.masterKey);
  return after.status === "valid" &&
    sameScope(after.data, options.fortressId, options.ownerRef) &&
    after.data.agent_id === options.newAgentId
    ? { status: "transferred" }
    : { status: "changed" };
}
