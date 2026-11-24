import { lstat } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SessionBindingState, SessionBindingBootState } from "./session-binding-state.js";
export type { SessionBindingState } from "./session-binding-state.js";
import type { AuditLog } from "../operational/audit-log.js";
import { fingerprintIdentityId, UNBOUND_SESSION, type SessionBinding } from "./safety-base.js";
import { type IdentityLoadEvidence, IdentityManager } from "../cognitive/tools.js";
import type { StorageBackend } from "../storage/interface.js";
import { FORTRESS_CONFIG_LOCK } from "../config.js";

export interface SoleProofInputs {
  before: string[] | null;
  evidence: IdentityLoadEvidence;
  after: string[] | null;
}

export type SoleProof =
  | { proven: true; identity_id: string }
  | {
      proven: false;
      state: "state_UNBOUND_NO_IDENTITY" | "state_UNBOUND_SEVERAL_IDENTITIES" | "state_UNBOUND_UNPROVEN";
      reasons: string[];
    };

/** Decide sole identity from complete enumerations and validated load evidence. */
export function proveSoleIdentity({ before, evidence, after }: SoleProofInputs): SoleProof {
  // Sole is proven only when complete enumerations before and after load agree exactly with decrypted records; catches only return unproven.
  // The proof inputs must match createSanctuaryServer in index.ts and predictNextStartBinding in agent-native/session-binding.ts.
  // Counters must match IdentityLoadEvidence in cognitive/tools.ts.
  try {
    if (before === null || after === null) {
      return { proven: false, state: "state_UNBOUND_UNPROVEN", reasons: ["complete identity enumeration unavailable"] };
    }
    const reasons: string[] = [];
    if (evidence.total !== 1) reasons.push("listed record count is not one");
    if (evidence.loaded !== 1) reasons.push("loaded identity count is not one");
    if (evidence.failed !== 0) reasons.push("identity loading failed");
    if (evidence.skipped_null_reads !== 0) reasons.push("listed identity read was null");
    if (evidence.duplicate_ids !== 0) reasons.push("duplicate identity ids");
    if (evidence.key_mismatches !== 0) reasons.push("identity key mismatch");
    const sortedBefore = [...before].sort();
    const sortedAfter = [...after].sort();
    const stable = sortedBefore.length === sortedAfter.length && sortedBefore.every((key, i) => key === sortedAfter[i]);
    if (before.length !== 1 || !stable) reasons.push("identity enumeration is not a stable singleton");
    if (evidence.decrypted_keys.length !== before.length || evidence.decrypted_keys.some((key, i) => key !== before[i])) reasons.push("decrypted keys differ from enumeration");
    if (reasons.length === 0) return { proven: true, identity_id: before[0]! };
    // A relist that changed during load says nothing reliable about the count, so it is unproven, never empty or several.
    const state = !stable
      ? "state_UNBOUND_UNPROVEN"
      : before.length === 0 && evidence.total === 0
        ? "state_UNBOUND_NO_IDENTITY"
        : before.length > 1 || evidence.total > 1
          ? "state_UNBOUND_SEVERAL_IDENTITIES"
          : "state_UNBOUND_UNPROVEN";
    return { proven: false, state, reasons };
  } catch {
    return { proven: false, state: "state_UNBOUND_UNPROVEN", reasons: ["identity evidence comparison failed"] };
  }
}

/** Bracket loading with complete enumeration, preserving load failures for the caller. */
export async function collectSoleProofInputs(
  storage: Pick<StorageBackend, "listKeys">,
  identityManager: Pick<IdentityManager, "load">,
): Promise<SoleProofInputs> {
  const enumerate = async (): Promise<string[] | null> => {
    try {
      return storage.listKeys ? await storage.listKeys("_identities") : null;
    } catch {
      return null;
    }
  };
  const before = await enumerate();
  const evidence = await identityManager.load();
  const after = await enumerate();
  return { before, evidence, after };
}


type Decision = { state: SessionBindingState; binding?: SessionBinding };

/** A boot decision before it becomes a binding; the identity is carried only by the states that name one. */
export type BootDecision =
  | { state: "state_BOUND_NAMED" | "state_BOUND_SOLE_IDENTITY" | "state_NAMED_UNRESOLVED"; identity_id: string }
  | { state: Exclude<SessionBindingState, "state_BOUND_NAMED" | "state_BOUND_SOLE_IDENTITY" | "state_NAMED_UNRESOLVED"> };

/**
 * The boot precedence: the launch variable when it is set, else no default
 * when the flag is off, else the sole-identity proof. Pure; the proof is read
 * only when the precedence reaches it. Both callers must use this one
 * function: the boot decision in resolveSessionBinding and the next-start
 * prediction in predictNextStartBinding, both in this file. Per-call named
 * selection never calls it, so a sole boot stays frozen.
 */
export function decideBootBinding(input: {
  launch: string | undefined;
  flag: boolean;
  identityExists: (id: string) => boolean;
  proof: () => SoleProof;
}): BootDecision {
  if (input.launch !== undefined) {
    if (input.launch === "") return { state: "state_NAMED_EMPTY" };
    return input.identityExists(input.launch)
      ? { state: "state_BOUND_NAMED", identity_id: input.launch }
      : { state: "state_NAMED_UNRESOLVED", identity_id: input.launch };
  }
  if (!input.flag) return { state: "state_UNBOUND_FLAG_OFF" };
  const proof = input.proof();
  return proof.proven ? { state: "state_BOUND_SOLE_IDENTITY", identity_id: proof.identity_id } : { state: proof.state };
}
export interface SessionBindingResolver {
  readonly bootState: SessionBindingState;
  cooperative(): SessionBinding;
  primitive(): SessionBinding | undefined;
}

/** Both consumers require an installed boot decision before any authority is read. */
export function createSessionBindingAccessors() {
  let resolver: SessionBindingResolver | undefined;
  const installed = (): SessionBindingResolver => {
    if (!resolver) throw new Error("Session binding resolver is not installed");
    return resolver;
  };
  return {
    install(value: SessionBindingResolver): void {
      if (resolver) throw new Error("Session binding resolver is already installed");
      resolver = value;
    },
    cooperative: (): SessionBinding => installed().cooperative(),
    primitive: (): SessionBinding | undefined => installed().primitive(),
    // The read-only boot accessor must match SessionBindingBootState in session-binding-state.ts.
    bootState: (() => installed().bootState) as SessionBindingBootState,
  };
}

const STATE_MESSAGES: Record<SessionBindingState, string> = {
  state_BOUND_NAMED: "session bound to the identity named at launch",
  state_BOUND_SOLE_IDENTITY: "session bound by default to this fortress's only identity; every process started against this fortress shares it; sanctuary session-binding disable turns this off",
  state_UNBOUND_FLAG_OFF: "session not bound: default binding is off; use sanctuary session-binding enable or SANCTUARY_SESSION_IDENTITY_ID",
  state_UNBOUND_NO_IDENTITY: "session not bound: this fortress has no identity",
  state_UNBOUND_SEVERAL_IDENTITIES: "session not bound: this fortress has several identities; select one with SANCTUARY_SESSION_IDENTITY_ID",
  state_UNBOUND_UNPROVEN: "session not bound: identity set could not be proven",
  state_NAMED_EMPTY: "launch variable is empty; treated as not bound, never as the default",
  state_NAMED_UNRESOLVED: "session not bound: named identity not found",
};

/** The boot row's load counters; the field set must match IdentityLoadEvidence in cognitive/tools.ts. */
export function bootRowEvidence(evidence: IdentityLoadEvidence): Record<keyof IdentityLoadEvidence, number> {
  // The boot row records counts only, so its size is fixed and it never lists the fortress's identity keys.
  return {
    total: evidence.total,
    loaded: evidence.loaded,
    failed: evidence.failed,
    skipped_null_reads: evidence.skipped_null_reads,
    duplicate_ids: evidence.duplicate_ids,
    key_mismatches: evidence.key_mismatches,
    decrypted_keys: evidence.decrypted_keys.length,
  };
}

/** Install one boot decision and preserve per-call launch selection outside a sole boot. */
export async function resolveSessionBinding(options: {
  identityManager: Pick<IdentityManager, "get">;
  storage: StorageBackend;
  flag: boolean;
  auditLog: Pick<AuditLog, "appendCritical">;
  stderr: (line: string) => void;
  env: () => NodeJS.ProcessEnv;
  proofInputs: SoleProofInputs;
}): Promise<SessionBindingResolver> {
  const named = (id: string): Decision => {
    if (id === "") return { state: "state_NAMED_EMPTY" };
    if (!options.identityManager.get(id)) return { state: "state_NAMED_UNRESOLVED", binding: Object.freeze({ identity_id: id }) };
    return { state: "state_BOUND_NAMED", binding: Object.freeze({ identity_id: id,
      requester_identity_fingerprint: fingerprintIdentityId(id), binding_source: "launch_variable" }) };
  };
  const launch = options.env().SANCTUARY_SESSION_IDENTITY_ID;
  const chosen = decideBootBinding({ launch, flag: options.flag,
    identityExists: (id) => options.identityManager.get(id) !== undefined,
    // The proof contract must match proveSoleIdentity in agent-native/session-binding.ts and its boot caller in index.ts.
    proof: () => proveSoleIdentity(options.proofInputs) });
  let boot: Decision;
  switch (chosen.state) {
    case "state_BOUND_NAMED":
    case "state_NAMED_UNRESOLVED":
    case "state_NAMED_EMPTY":
      // The launch variable is set, so the boot decision is the same named selection each later call makes.
      boot = named(launch!);
      break;
    case "state_BOUND_SOLE_IDENTITY":
      boot = { state: chosen.state, binding: Object.freeze({ identity_id: chosen.identity_id,
        requester_identity_fingerprint: fingerprintIdentityId(chosen.identity_id), binding_source: "sole_identity" }) };
      break;
    default:
      boot = { state: chosen.state };
  }
  let auditFailed = false;
  try {
    await options.auditLog.appendCritical({ layer: "l1", operation: "session_binding_resolved", identity_id: "system",
      result: "success", details: { state: boot.state, binding_source: boot.binding?.binding_source,
        identity_id: boot.binding?.identity_id, flag: options.flag, evidence: bootRowEvidence(options.proofInputs.evidence) } });
  } catch {
    auditFailed = true;
    if (boot.state === "state_BOUND_SOLE_IDENTITY") boot = { state: "state_UNBOUND_UNPROVEN" };
  }
  options.stderr(STATE_MESSAGES[boot.state]);
  if (auditFailed) options.stderr("session binding boot row failed");
  // A sole binding is decided once at boot; the launch variable is not read again until exit.
  const frozenBoot = Object.freeze(boot);
  let previous = launch;
  let current = frozenBoot;
  const decision = (): Decision => {
    if (frozenBoot.state === "state_BOUND_SOLE_IDENTITY") return frozenBoot;
    const id = options.env().SANCTUARY_SESSION_IDENTITY_ID;
    // Named subjects are checked per call so a newly loaded named identity can resolve.
    if (id !== undefined) {
      const next = named(id);
      if (previous !== id || current.state !== next.state) current = next;
    } else current = frozenBoot.state === "state_BOUND_NAMED" || frozenBoot.state === "state_NAMED_UNRESOLVED" || frozenBoot.state === "state_NAMED_EMPTY"
      ? { state: "state_UNBOUND_FLAG_OFF" } : frozenBoot;
    previous = id;
    return current;
  };
  return Object.freeze({
    bootState: frozenBoot.state,
    cooperative(): SessionBinding {
      const selected = decision();
      return selected.state === "state_BOUND_NAMED" || selected.state === "state_BOUND_SOLE_IDENTITY"
        ? selected.binding! : UNBOUND_SESSION;
    },
    primitive(): SessionBinding | undefined {
      // The primitive view preserves pre-default-binding authority: non-bound sessions retain undefined, and unresolved names retain only their id.
      // DEBT(AGENT-SEAT-UNBOUND-PRIMITIVES): primitives retain their current unscoped authority until they share the binding flag's scope.
      return decision().binding;
    },
  });
}

/** Predict the next process from the same load evidence used at boot. */
export async function predictNextStartBinding(options: {
  flag: boolean;
  configFilePath: string;
  storage: StorageBackend;
  masterKey: Uint8Array | null;
  env: NodeJS.ProcessEnv;
}): Promise<string> {
  const prefix = "A server started now would be: ";
  // The lock name must match FORTRESS_CONFIG_LOCK in config.ts. Boot cannot take a lock that is present, so it refuses
  // to start; a lock whose absence cannot be shown is reported the same way.
  try {
    await lstat(join(dirname(options.configFilePath), FORTRESS_CONFIG_LOCK));
    return `${prefix}not bound: the config lock is held`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return `${prefix}not bound: the config lock is held`;
  }
  if (!options.masterKey) return "cannot predict: identities are encrypted and no key is available";
  const launch = options.env.SANCTUARY_SESSION_IDENTITY_ID;
  const manager = new IdentityManager(options.storage, options.masterKey);
  try {
    // Load only what the precedence will read: the identity set for a named launch, or the sole proof's inputs.
    let proof: SoleProof | undefined;
    if (launch !== undefined && launch !== "") await manager.load();
    else if (launch === undefined && options.flag) {
      // The prediction proof must match proveSoleIdentity in agent-native/session-binding.ts and the boot input collection in index.ts.
      proof = proveSoleIdentity(await collectSoleProofInputs(options.storage, manager));
    }
    const decision = decideBootBinding({ launch, flag: options.flag,
      identityExists: (id) => manager.get(id) !== undefined,
      proof: () => {
        if (!proof) throw new Error("sole proof was not collected");
        return proof;
      } });
    switch (decision.state) {
      case "state_BOUND_NAMED": return `${prefix}bound to ${decision.identity_id} by the launch variable`;
      case "state_BOUND_SOLE_IDENTITY": return `${prefix}bound by default to ${decision.identity_id}`;
      case "state_NAMED_UNRESOLVED": return `${prefix}not bound: named identity not found`;
      case "state_NAMED_EMPTY": return `${prefix}not bound: launch variable is empty`;
      case "state_UNBOUND_FLAG_OFF": return `${prefix}not bound: default binding is off`;
      case "state_UNBOUND_NO_IDENTITY": return `${prefix}not bound: this fortress has no identity`;
      case "state_UNBOUND_SEVERAL_IDENTITIES":
        return `${prefix}not bound: this fortress has several identities; select one with SANCTUARY_SESSION_IDENTITY_ID`;
      case "state_UNBOUND_UNPROVEN": return `${prefix}not bound: identity set could not be proven`;
    }
  } catch {
    return `${prefix}not bound: identity loading failed`;
  }
}
