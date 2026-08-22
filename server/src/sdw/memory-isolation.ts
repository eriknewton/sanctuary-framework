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
import { SDW_META_NAMESPACE } from "./records.js";
import {
  SDW_OWNER_PIN_KEY,
  verifySdwOwnerPinEnvelope,
  writeSdwOwnerPin,
} from "./write-gate.js";

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
) => Promise<{ allowed: true } | { allowed: false }>;

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
    return bound.value === observed ? { allowed: true } : { allowed: false };
  };
}

export interface PersistentIsolationGuardOptions {
  readonly storage: Pick<StorageBackend, "read" | "write">;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  readonly ownerIdentity: () => string | undefined;
  readonly now?: () => string;
}

/**
 * Fortress-persisted pin. On EVERY call:
 *   - no record yet: write a pin for the observed identity, then re-read and
 *     verify it (two processes racing to first-touch both write; whichever
 *     record is on disk after the re-read wins, and the loser is refused);
 *   - record present: the MAC must verify under the master-derived key
 *     (`sdw-owner-pin-mac`) and the fortress/owner scope must match, or the
 *     call is REFUSED (a stripped, malformed or foreign-keyed pin is never
 *     read as "no pin yet"); then the pinned agent id must equal the observed
 *     one. The pin is never advanced.
 * `undefined` is persisted as `null` and is a concrete identity, as above.
 */
export function createPersistentMultiAgentIsolationGuard(
  options: PersistentIsolationGuardOptions,
): MultiAgentIsolationGuard {
  const now = options.now ?? (() => new Date().toISOString());
  const readPin = async () => {
    const raw = await options.storage.read(SDW_META_NAMESPACE, SDW_OWNER_PIN_KEY);
    if (raw === null) return null;
    return verifySdwOwnerPinEnvelope(options.masterKey, raw);
  };
  const matches = (
    pin: { readonly status: "valid"; readonly data: { fortress_id: string; owner_ref: string; agent_id: string | null } } | { readonly status: "invalid" },
    observed: string | null,
  ): boolean =>
    pin.status === "valid" &&
    pin.data.fortress_id === options.fortressId &&
    pin.data.owner_ref === options.ownerRef &&
    pin.data.agent_id === observed;

  return async (_operation: string) => {
    const observed = options.ownerIdentity() ?? null;
    let pin = await readPin();
    if (pin === null) {
      // Written through the SDW write gate (write-gate.ts is the only
      // SDW-namespace writer; this module never touches the bytes).
      await writeSdwOwnerPin(options.storage, options.masterKey, {
        version: 1,
        fortress_id: options.fortressId,
        owner_ref: options.ownerRef,
        agent_id: observed,
        pinned_at: now(),
      });
      // Check-after-write: the record on disk, not the one we intended, is
      // the pin. A concurrent first-touch by another identity loses here.
      pin = await readPin();
      if (pin === null) return { allowed: false };
    }
    return matches(pin, observed) ? { allowed: true } : { allowed: false };
  };
}
