/**
 * Multi-agent isolation guard for the shared SDW memory owner scope.
 *
 * The SDW memory adapter wired in index.ts is bound to ONE `fleet-self` owner
 * scope reused for every caller, so SDW memory has no per-agent custody
 * isolation yet. This guard pins the single wrapped-agent identity the shared
 * scope is bound to and REFUSES any second, distinct identity, until real
 * per-agent isolation (deriving owner_ref from the caller) lands.
 *
 * It lives in its own file because EVERY tool family that reaches the shared
 * scope (memory read/write, memory-file transcode, provenance, vault
 * export/import/delete) has to share ONE guard instance. Two guards over the
 * same scope each pin their own first caller, so a second agent refused by one
 * family would still be the first caller of the other and get through it.
 *
 * TWO IMPLEMENTATIONS, ONE CONTRACT:
 * - `createMultiAgentIsolationGuard` pins in process memory. Each wrapped
 *   harness spawns its OWN stdio server, so an in-process pin can never see a
 *   second process; it is kept for single-graph tests and is NOT what
 *   production wires.
 * - `createPersistentMultiAgentIsolationGuard` pins in the FORTRESS: a MAC'd
 *   owner-pin record in `_sdw_meta`, written on first touch and checked on
 *   EVERY call, so a second process over the same fortress with a different
 *   identity is refused. This is the production guard (index.ts).
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  claimSdwOwnerPin,
  createSdwOwnerPinIfAbsent,
  readSdwOwnerPin,
  type SdwOwnerPinData,
} from "./write-gate.js";
import {
  SDW_CATALOG_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
} from "./records.js";

/**
 * Strictly additive and fail closed:
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
export type MultiAgentIsolationGuard = (
  operation: string,
) => Promise<{ allowed: true } | { allowed: false; reason: IsolationRefusalReason }>;

/** Audit-only refusal reasons (the agent sees the fixed denial). */
export type IsolationRefusalReason =
  | "owner_scope_conflict"
  | "owner_pin_invalid"
  | "owner_pin_missing_after_establishment"
  | "owner_pin_backend_unsupported"
  | "owner_pin_claim_lost";

/**
 * The production identity resolver every guard instance in index.ts is built
 * over. It reads `SANCTUARY_AGENT_ID` from the SERVER's own process
 * environment, which `sanctuary wrap` writes into the harness's `sanctuary`
 * MCP entry at wrap time (must match `SANCTUARY_AGENT_ID` in
 * `wrap/cli.ts:buildSanctuaryEnv`; the value is `wrappedAgentId(...)`).
 *
 * INVARIANT: the guard keys on this wrap-time, operator-bound identity and
 * NEVER on a value the agent asserts in a tool argument or mints for itself.
 * An agent can create identities at will, so any per-identity property it can
 * choose in a tool call is defeatable; the env var exists before the agent
 * process does and is set by whoever ran the wrap.
 *
 * BOUND (stated, not softened): the value is plaintext in the harness config
 * and is accepted unauthenticated. It is deterministic from the harness kind
 * and the fortress path, so an agent that can rewrite its own harness config
 * and relaunch can present the FIRST identity and pass. The guard therefore
 * separates DISTINCT wrapped identities (two harnesses, or one harness over
 * two fortresses); it does not defend against an agent that controls its own
 * harness config. That is the same trust basis as `SANCTUARY_PASSPHRASE` and
 * the fortress path, which travel in the same entry.
 */
export function wrappedAgentIdentityFromEnv(): string | undefined {
  return process.env.SANCTUARY_AGENT_ID;
}

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
}

export { readSdwOwnerPin } from "./write-gate.js";

/**
 * Namespaces whose non-emptiness proves the fortress's SDW store has been
 * used (must match the SDW store namespaces in sdw/records.ts). A missing pin
 * over a used store is "established and removed", never "fresh".
 */
const SDW_ESTABLISHMENT_NAMESPACES = [
  SDW_CATALOG_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_VECTOR_MEMORY_NAMESPACE,
] as const;

/**
 * Fortress-persisted pin. On EVERY call:
 *   - no record: if ANY SDW store namespace already holds a record, the pin
 *     was established and removed, and the call is REFUSED
 *     (`owner_pin_missing_after_establishment`); recovery is an operator verb
 *     that does not exist yet, never a repin. Otherwise the pin is created
 *     with an EXCLUSIVE create (`writeIfAbsent`: O_EXCL on the filesystem),
 *     re-read, and compared: of two processes first-touching at once exactly
 *     one creates, the other reads the winner's pin on its FIRST call and is
 *     refused. A backend without create-if-absent refuses
 *     (`owner_pin_backend_unsupported`) rather than overwriting.
 *   - record present: the MAC must verify under the master-derived key
 *     (`sdw-owner-pin-mac`) and the fortress/owner scope must match, or the
 *     call is REFUSED (a stripped, malformed or foreign-keyed pin is never
 *     read as "no pin yet"); then the pinned agent id must equal the observed
 *     one, with the UNCLAIMED exception below. A claimed pin is never
 *     advanced.
 *
 * UNCLAIMED pins. A pin whose `agent_id` is `null` was created by a server
 * that had no `SANCTUARY_AGENT_ID` (a harness wrapped before the variable
 * existed). `null` means UNCLAIMED, not "the unconfigured caller owns this":
 * a caller presenting a non-null id may claim a null pin exactly once, by a
 * compare-and-replace against the exact null record it read (never an
 * overwrite); a null caller over a null pin is allowed and leaves it
 * unclaimed; a null caller over a claimed pin, and any different non-null id
 * over a claimed pin, are refused. Without this the CHANGELOG-recommended
 * re-wrap would lock the upgraded harness out of its own memory.
 *
 * WRITE DISCIPLINE: the record is written only by an ALLOWED call (the
 * exclusive first create, or a claim); a refused call never writes, and an
 * invalid record is never overwritten. `_sdw_meta` therefore becomes
 * non-empty on the first allowed guarded call, read or write; master rotation
 * restamps it (`restampSdwOwnerPinForRotation`).
 */
export function createPersistentMultiAgentIsolationGuard(
  options: PersistentIsolationGuardOptions,
): MultiAgentIsolationGuard {
  const now = options.now ?? (() => new Date().toISOString());
  const readPin = () => readSdwOwnerPin(options.storage, options.masterKey);
  const pinData = (agentId: string | null): SdwOwnerPinData => ({
    version: 1,
    fortress_id: options.fortressId,
    owner_ref: options.ownerRef,
    agent_id: agentId,
    pinned_at: now(),
  });
  const sameScope = (data: { fortress_id: string; owner_ref: string }): boolean =>
    data.fortress_id === options.fortressId && data.owner_ref === options.ownerRef;
  const storeEstablished = async (): Promise<boolean> => {
    for (const namespace of SDW_ESTABLISHMENT_NAMESPACES) {
      if ((await options.storage.list(namespace)).length > 0) return true;
    }
    return false;
  };
  const refuse = (reason: IsolationRefusalReason) => ({ allowed: false as const, reason });

  return async (_operation: string) => {
    const observed = options.ownerIdentity() ?? null;
    let pin = await readPin();
    if (pin.status === "absent") {
      // INVARIANT (durable floor): a used store with no pin is a removed pin.
      // Missing must fail closed, never re-open the scope to the next caller.
      if (await storeEstablished()) return refuse("owner_pin_missing_after_establishment");
      const created = await createSdwOwnerPinIfAbsent(options.storage, options.masterKey, pinData(observed));
      if (created === "unsupported") return refuse("owner_pin_backend_unsupported");
      // Check-after-create: the record on disk, not the one we intended, is
      // the pin. The loser of a simultaneous first touch reads the winner's
      // record here and is refused on this, its first, call.
      pin = await readPin();
    }
    if (pin.status !== "valid" || !sameScope(pin.data)) return refuse("owner_pin_invalid");
    if (pin.data.agent_id === observed) return { allowed: true };
    // INVARIANT (UNCLAIMED pins): only a null pin may be claimed, only by a
    // non-null id, only by compare-and-replace against the exact record read
    // (never an overwrite), and only here, on an allowed call.
    if (pin.data.agent_id === null && observed !== null) {
      const claim = await claimSdwOwnerPin(options.storage, options.masterKey, pin.raw, pinData(observed));
      if (claim === "unsupported") return refuse("owner_pin_backend_unsupported");
      const after = await readPin();
      return after.status === "valid" && sameScope(after.data) && after.data.agent_id === observed
        ? { allowed: true }
        : refuse("owner_pin_claim_lost");
    }
    return refuse("owner_scope_conflict");
  };
}
