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

export type IsolationRefusalReason =
  | "owner_identity_missing"
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

/**
 * Production guard. Every wrapped harness starts a separate server process,
 * so the owner lives in a MAC-authenticated fortress record and is checked on
 * every call. An empty SDW scope is claimed through atomic create-if-absent;
 * a used legacy scope with no pin refuses until an operator explicitly claims
 * it. Missing wrap identity always refuses.
 */
export function createPersistentMultiAgentIsolationGuard(
  options: PersistentIsolationGuardOptions,
): MultiAgentIsolationGuard {
  const now = options.now ?? (() => new Date().toISOString());
  const refuse = (reason: IsolationRefusalReason) => ({
    allowed: false as const,
    reason,
  });

  return async (_operation: string) => {
    const observed = options.ownerIdentity();
    if (observed === undefined || observed.length === 0) {
      return refuse("owner_identity_missing");
    }
    try {
      let pin = await readSdwOwnerPin(options.storage, options.masterKey);
      if (pin.status === "absent") {
        if (await sdwStoreEstablished(options.storage)) {
          return refuse("owner_pin_missing_after_establishment");
        }
        const created = await createSdwOwnerPinIfAbsent(
          options.storage,
          options.masterKey,
          pinData(options.fortressId, options.ownerRef, observed, now),
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
      return pin.data.agent_id === observed
        ? { allowed: true }
        : refuse("owner_scope_conflict");
    } catch {
      return refuse("owner_pin_io_error");
    }
  };
}

export type OwnerClaimResult =
  | { readonly status: "claimed" }
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
