/**
 * Sanctuary Agent Contract v0.1 — Tier B Adapter SDK (§5).
 *
 * Abstract base + common machinery for wrapping non-native harnesses (Cline,
 * Claude Code, Mastra) in the Agent Contract surface. Reference adapters
 * subclass `TierBAdapter` and implement the harness-specific parts:
 *
 *   - `translateLifecycle(cmd)` — how pause / checkpoint / retire map onto
 *     the harness's native command surface.
 *   - `wrapHarnessIn(msg)` / `wrapHarnessOut(msg)` — shape translation
 *     between Sanctuary envelopes and the harness's native message format.
 *   - `spawnChild()` — how to launch the harness as a managed child. The
 *     SDK provides HTTP_PROXY / HTTPS_PROXY env injection for free.
 *
 * Hard invariants enforced structurally by the SDK:
 *   1. The agent's private seed NEVER appears in the harness process env
 *      (the adapter holds an AgentKeyStore handle; signing goes through the
 *      SDK, not the harness).
 *   2. Harness sub-agents (e.g. Cline spawning a worker) are NOT promoted
 *      to first-class Sanctuary identities — the adapter tags them as
 *      "sub_of:<agent_id>" rather than minting new Agent Cards.
 *   3. Agent Card emitted for every Tier B adapter has `tier: "B"` literally.
 *
 * The SDK is transport-agnostic at v0.1 — subclasses pick stdio / websocket
 * / HTTP; the SDK only mediates signing, envelope wrap, capability check,
 * and lifecycle emission.
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../../core/encoding.js";
import { canonicalizeToBytes } from "../../mesh/canonical-json.js";
import type { SignedEvent } from "../../mesh/types.js";
import type {
  AgentCard,
  AgentCardCapability,
  AgentIdentityBinding,
  HarnessEnvelope,
  LifecycleEvent,
  UsageEvent,
} from "../types.js";
import {
  issueAgentCard,
  type IssueAgentCardParams,
} from "../card-issuer.js";
import { emitUsageEvent } from "../usage-event.js";
import {
  emitLifecycleEvent,
  type EmitLifecycleParams,
} from "../lifecycle.js";
import {
  sealLifecycleEmission,
  type LifecycleSealContext,
} from "../../workload-lifecycle/seal.js";
import {
  enforceCapability,
  InMemoryCapabilityCounter,
  type CapabilityCounter,
} from "../capability-enforcer.js";
import {
  wrapHarnessEnvelope,
  stampReceiverCheck,
} from "../envelope.js";
import {
  TierBInvariantError,
} from "../errors.js";
import type { AgentKeyStore } from "../identity-bind.js";
import {
  getAgentPublicKey,
  signWithAgentKey,
} from "../identity-bind.js";
import type {
  CapabilityKind,
  HarnessTier,
  LifecycleState,
  ModelProvider,
} from "../constants.js";
import type { LocalHarnessKind } from "../../contracts/v1.1/local-agent-records.js";
import type { AgentPlatform } from "../../wrap/config-reader.js";

// ═══════════════════════════════════════════════════════════════════════
// Shared types
// ═══════════════════════════════════════════════════════════════════════

export type LifecycleCommand =
  | "launch"
  | "pause"
  | "checkpoint"
  | "resume"
  | "retire"
  | "revoke";

/**
 * Parameters common to every Tier B adapter. Subclasses add harness-specific
 * params on top.
 */
export interface TierBAdapterParams {
  agent_id: string;
  fortress_id: string;
  harness_id: string;
  model_provider: ModelProvider;
  model_id: string;
  capabilities: AgentCardCapability[];
  policy_version: number;
  policy_blob_bytes: Uint8Array;
  attestation_endpoint: string;
  /** Shared agent key store — adapter unwraps agent seed through this. */
  key_store: AgentKeyStore;
  /** Binding record produced by bindAgentIdentity for this agent. */
  agent_identity_binding: AgentIdentityBinding;
  /** Fortress-master secret — needed to unwrap the agent seed transiently. */
  fortress_master_secret: Uint8Array;
  /** Node signing context for envelope emission. */
  emitter_node: string;
  emitter_principal: string;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
  /** Starting monotonic_seq — adapter increments per emission. */
  initial_monotonic_seq?: number;
  /** Optional capability counter (per-day caps). In-memory default. */
  counter?: CapabilityCounter;
  /** Optional HTTP proxy URL — injected into harness child env. Caller responsible for the proxy actually running. */
  http_proxy_url?: string;
  https_proxy_url?: string;
  /**
   * Optional workload-lifecycle audit seal. When present, every successful
   * lifecycle emission ALSO writes a critical, chain-bound workload-lifecycle
   * audit entry (binding the mesh SignedEvent to the audit chain by
   * `signed_event_hash`), closing the deferred audit-log seal named in
   * `agent-contract/lifecycle.ts`. Absent by default so existing callers and
   * unit tests are unaffected; a `checkpointed` transition writes no audit
   * entry (review M5 — the one deliberately-unmirrored transition).
   *
   * `workload_class` should be the HONEST declared classification (e.g.
   * "stateful-agent" for a wrapped harness session — the operator's workload,
   * never an unearned mind-class claim).
   */
  lifecycle_seal?: {
    context: LifecycleSealContext;
    /** Stable registry id; defaults to the agent_id when omitted. */
    workload_id?: string;
    /** Running instance id; defaults to the agent_id when omitted. */
    instance_id?: string;
  };
}

/**
 * Shared output of every adapter action. The adapter hands back both the
 * signed envelope AND the parsed body so the broker can index whichever it
 * needs.
 */
export interface AdapterEmission<T> {
  signed_event: SignedEvent<T>;
  body: T;
}

// ═══════════════════════════════════════════════════════════════════════
// Base class — all reference adapters inherit from this
// ═══════════════════════════════════════════════════════════════════════

/**
 * Common machinery for every Tier B adapter. Subclasses override:
 *   - `harnessEnv()` — additional env vars to inject (beyond HTTP_PROXY).
 *   - `translateLifecycle(cmd)` — harness-specific lifecycle mapping.
 *
 * This base class does NOT spawn a subprocess — that's the subclass's
 * responsibility (the test harness may stub it). The base only enforces
 * contract invariants and provides signing / emission primitives.
 */
export abstract class TierBAdapter {
  public readonly tier: HarnessTier = "B";
  protected seq: number;
  protected counter: CapabilityCounter;
  /** Agent Card for this session — set after calling `launch`. */
  protected card?: AgentCard;
  /** Per-instance ordinal of sealed (audit-recorded) lifecycle events, keyed by
   * agent_id. Drives `prev_lifecycle_seq` on the next sealed event. Only used
   * when `lifecycle_seal` is configured. See `emitLifecycle` for the honesty
   * note on why this is an adapter-local ordinal, not the chain sequence. */
  private readonly recordedLifecycleOrdinal = new Map<string, number>();

  constructor(protected params: TierBAdapterParams) {
    this.seq = params.initial_monotonic_seq ?? 0;
    this.counter = params.counter ?? new InMemoryCapabilityCounter();
  }

  /** Subclasses return the harness id (matches the reference adapter file name). */
  abstract readonly harnessId: string;

  /**
   * Harness-specific env vars. Keys like `SANCTUARY_AGENT_ID` are injected
   * by the base; subclasses add harness-specific knobs (e.g. `CLINE_FOO`).
   *
   * **MUST NOT** return the agent's private seed; the SDK enforces this
   * structurally by never exposing the seed to subclasses.
   */
  protected harnessEnv(): Record<string, string> {
    return {};
  }

  /**
   * Translate a canonical LifecycleCommand into the harness's native
   * command surface. Default returns an empty string (noop); subclasses
   * override with actual wire-format commands.
   */
  protected abstract translateLifecycle(cmd: LifecycleCommand): string;

  /**
   * Build the env the harness child should run with. The SDK injects
   * proxy URLs; subclasses add their own. The agent private seed is NEVER
   * in this map.
   */
  buildHarnessEnv(): Record<string, string> {
    const extra = this.harnessEnv();
    for (const key of Object.keys(extra)) {
      if (
        key === "SANCTUARY_AGENT_PRIVATE_KEY" ||
        key === "SANCTUARY_MASTER_SECRET" ||
        key.startsWith("SANCTUARY_KEY_")
      ) {
        throw new TierBInvariantError(
          `Tier B adapter ${this.harnessId} attempted to leak key material via env var ${key}`
        );
      }
    }
    const proxy: Record<string, string> = {};
    if (this.params.http_proxy_url) {
      proxy.HTTP_PROXY = this.params.http_proxy_url;
      proxy.http_proxy = this.params.http_proxy_url;
    }
    if (this.params.https_proxy_url) {
      proxy.HTTPS_PROXY = this.params.https_proxy_url;
      proxy.https_proxy = this.params.https_proxy_url;
    }
    return {
      SANCTUARY_AGENT_ID: this.params.agent_id,
      SANCTUARY_FORTRESS_ID: this.params.fortress_id,
      SANCTUARY_HARNESS_TIER: this.tier,
      SANCTUARY_HARNESS_ID: this.harnessId,
      ...proxy,
      ...extra,
    };
  }

  /**
   * Launch the Tier B agent: issue Agent Card, emit `launched` lifecycle
   * event, set up session state. Does not spawn the child process — the
   * subclass does that after calling `super.launch()`.
   */
  async launch(): Promise<{
    card_emission: AdapterEmission<AgentCard>;
    lifecycle_emission: AdapterEmission<LifecycleEvent>;
  }> {
    if (this.card) {
      throw new TierBInvariantError(
        `Tier B adapter ${this.harnessId} double-launched for agent ${this.params.agent_id}`
      );
    }
    const pub = await getAgentPublicKey({
      agent_id: this.params.agent_id,
      fortress_master_secret: this.params.fortress_master_secret,
      store: this.params.key_store,
    });
    const storePubkey = toBase64url(pub);
    if (this.params.agent_identity_binding.agent_id !== this.params.agent_id) {
      throw new TierBInvariantError(
        `Tier B adapter ${this.harnessId} identity binding is for agent ${this.params.agent_identity_binding.agent_id}, expected ${this.params.agent_id}`
      );
    }
    if (
      this.params.agent_identity_binding.fortress_id !== this.params.fortress_id
    ) {
      throw new TierBInvariantError(
        `Tier B adapter ${this.harnessId} identity binding fortress ${this.params.agent_identity_binding.fortress_id} does not match ${this.params.fortress_id}`
      );
    }
    if (this.params.agent_identity_binding.agent_pubkey !== storePubkey) {
      throw new TierBInvariantError(
        `Tier B adapter ${this.harnessId} identity binding public key does not match key store for agent ${this.params.agent_id}`
      );
    }
    const issue: IssueAgentCardParams = {
      agent_id: this.params.agent_id,
      fortress_id: this.params.fortress_id,
      tier: this.tier,
      harness_id: this.harnessId,
      model_provider: this.params.model_provider,
      model_id: this.params.model_id,
      agent_identity_binding: this.params.agent_identity_binding,
      capabilities: this.params.capabilities,
      policy_version: this.params.policy_version,
      policy_blob_bytes: this.params.policy_blob_bytes,
      attestation_endpoint: this.params.attestation_endpoint,
      emitter_node: this.params.emitter_node,
      emitter_principal: this.params.emitter_principal,
      node_private_key: this.params.node_private_key,
      principal_private_key: this.params.principal_private_key,
      monotonic_seq: this.seq++,
    };
    const cardOut = issueAgentCard(issue);
    this.card = cardOut.card;
    const lifecycleOut = await this.emitLifecycle({
      from_state: "uninstantiated",
      to_state: "launched",
      reason: `adapter=${this.harnessId} launched for agent=${this.params.agent_id}`,
    });
    return {
      card_emission: {
        signed_event: cardOut.signed_event,
        body: cardOut.card,
      },
      lifecycle_emission: lifecycleOut,
    };
  }

  /**
   * Emit a lifecycle event with the adapter's emitter context pre-filled.
   *
   * If a `lifecycle_seal` was configured, the mesh emission is ALSO sealed into
   * the audit chain (critical, durability-verified, bound by
   * `signed_event_hash`) before this resolves — closing the deferred
   * audit-log seal in `agent-contract/lifecycle.ts`. The mesh event is always
   * built first (pure, never fails on audit state); the seal write is awaited
   * so a completeness guarantee actually holds — a failed seal rejects here
   * rather than silently dropping the audit record. A `checkpointed`
   * transition is intentionally not mirrored to the chain (review M5).
   */
  async emitLifecycle(args: {
    from_state: LifecycleState | "uninstantiated";
    to_state: LifecycleState;
    reason: string;
    checkpoint_hash?: string;
    guardian_quorum?: EmitLifecycleParams["guardian_quorum"];
  }): Promise<AdapterEmission<LifecycleEvent>> {
    const out = emitLifecycleEvent({
      agent_id: this.params.agent_id,
      fortress_id: this.params.fortress_id,
      from_state: args.from_state,
      to_state: args.to_state,
      reason: args.reason,
      checkpoint_hash: args.checkpoint_hash,
      guardian_quorum: args.guardian_quorum,
      emitter_node: this.params.emitter_node,
      emitter_principal: this.params.emitter_principal,
      node_private_key: this.params.node_private_key,
      principal_private_key: this.params.principal_private_key,
      monotonic_seq: this.seq++,
    });
    const seal = this.params.lifecycle_seal;
    if (seal) {
      // Per-instance ordinal of this adapter's RECORDED lifecycle events.
      // NOTE on honesty (H2): this is the adapter's own count of events it has
      // sealed for this instance, NOT the global audit-chain sequence (the
      // `appendCritical` contract returns void, so the chain position is not
      // surfaced back here). It still gives an auditor a per-instance
      // linked-list ordinal that detects a dropped RECORD in this adapter's
      // emission stream; it does not detect an unrecorded real-world
      // transition, and it is not the chain sequence number. A later build
      // item that surfaces the chain sequence can populate the true value.
      const prevOrdinal = this.recordedLifecycleOrdinal.get(
        this.params.agent_id
      );
      const payload = await sealLifecycleEmission(seal.context, {
        event: out.event,
        signed_event: out.signed_event,
        workload_id: seal.workload_id ?? this.params.agent_id,
        instance_id: seal.instance_id ?? this.params.agent_id,
        ...(prevOrdinal !== undefined
          ? { prev_lifecycle_seq: prevOrdinal }
          : {}),
        ...(out.event.checkpoint_hash
          ? { state_commitment: out.event.checkpoint_hash }
          : {}),
      });
      // A `checkpointed` transition returns null (no audit op) and does not
      // advance the ordinal — honest: it was not recorded.
      if (payload !== null) {
        this.recordedLifecycleOrdinal.set(
          this.params.agent_id,
          (prevOrdinal ?? 0) + 1
        );
      }
    }
    return { signed_event: out.signed_event, body: out.event };
  }

  /**
   * Forward a harness-origin action: enforce capability, wrap as
   * `harness_out` envelope with allow-stamp, emit a usage event, return
   * both. This is the canonical entry point for broker-side observation of
   * harness activity.
   */
  observeHarnessAction<InBody, OutBody>(args: {
    capability_kind: CapabilityKind;
    capability_target: string;
    input: InBody;
    output: OutBody;
    attestation_state?: "present" | "degraded" | "unavailable";
  }): {
    envelope: HarnessEnvelope<OutBody>;
    usage: AdapterEmission<UsageEvent>;
  } {
    if (!this.card) {
      throw new TierBInvariantError(
        `observeHarnessAction called before launch on ${this.harnessId}/${this.params.agent_id}`
      );
    }
    const check = enforceCapability({
      card: this.card,
      attempted_kind: args.capability_kind,
      attempted_target: args.capability_target,
      counter: this.counter,
    });
    const env = wrapHarnessEnvelope<OutBody>({
      direction: "harness_out",
      agent_id: this.params.agent_id,
      fortress_id: this.params.fortress_id,
      capability_kind: args.capability_kind,
      capability_target: args.capability_target,
      body: args.output,
      policy_version: this.card.policy_version,
      claimant: this.params.agent_id,
    });
    const stamped = stampReceiverCheck(env, {
      decision: "allow",
      reason_code: `capability_declared:${check.capability_index}`,
    });
    const usageOut = emitUsageEvent({
      agent_id: this.params.agent_id,
      fortress_id: this.params.fortress_id,
      event_class: "tool_call",
      capability_kind: args.capability_kind,
      capability_target: args.capability_target,
      input: args.input,
      output: args.output,
      policy_version: this.card.policy_version,
      policy_version_hash: this.card.policy_version_hash,
      attestation_state: args.attestation_state ?? "present",
      emitter_node: this.params.emitter_node,
      emitter_principal: this.params.emitter_principal,
      node_private_key: this.params.node_private_key,
      principal_private_key: this.params.principal_private_key,
      monotonic_seq: this.seq++,
    });
    return {
      envelope: stamped,
      usage: { signed_event: usageOut.signed_event, body: usageOut.event },
    };
  }

  /**
   * Sign a payload with the per-agent key transiently — the SDK unwraps via
   * AgentKeyStore and zeroes the seed after signing. Subclasses call this
   * when the harness demands the agent's signature (e.g. Mastra's signed
   * outgoing HTTP request) without ever seeing the seed themselves.
   */
  async signWithAgentKey(payload: Uint8Array): Promise<Uint8Array> {
    return signWithAgentKey({
      agent_id: this.params.agent_id,
      fortress_master_secret: this.params.fortress_master_secret,
      store: this.params.key_store,
      payload,
    });
  }

  /**
   * Reject any attempt by the harness to promote a sub-agent to first-class
   * Sanctuary identity. Returns a stable `sub_of:<agent_id>:<label>` string
   * instead — auditors can see the hierarchy without the sub-agent
   * appearing in the fortress-wide identity roster.
   */
  labelSubAgent(label: string): string {
    if (!label || label.includes(":")) {
      throw new TierBInvariantError(
        `labelSubAgent rejected label "${label}" — must be non-empty and colon-free`
      );
    }
    return `sub_of:${this.params.agent_id}:${label}`;
  }

  /** Expose the adapter's emitted Agent Card (read-only). */
  getCard(): AgentCard | undefined {
    return this.card;
  }

  /** Hash the current card for downstream references. */
  getCardHash(): string {
    if (!this.card) {
      throw new TierBInvariantError(
        `getCardHash before launch on ${this.harnessId}`
      );
    }
    return toBase64url(sha256(canonicalizeToBytes(this.card)));
  }

  /** Exposed for tests — seq counter. */
  getSeq(): number {
    return this.seq;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Stub harness runtime — a minimal in-memory "harness" used by tests +
// reference adapters when a real child process is not appropriate.
// ═══════════════════════════════════════════════════════════════════════

export interface StubHarnessInvocation {
  capability_kind: CapabilityKind;
  capability_target: string;
  input: unknown;
  output: unknown;
}

/**
 * StubHarness — in-memory harness used by reference adapters in tests. Not
 * for production. Accepts a scripted list of invocations and yields them
 * one at a time.
 */
export class StubHarness {
  private i = 0;

  constructor(public readonly invocations: StubHarnessInvocation[]) {}

  next(): StubHarnessInvocation | undefined {
    return this.invocations[this.i++];
  }

  reset(): void {
    this.i = 0;
  }

  get remaining(): number {
    return Math.max(0, this.invocations.length - this.i);
  }
}

/**
 * The `sanctuary wrap --tier-b <id>` CLI extension looks up adapters
 * through this registry. Reference adapters register themselves on import.
 */
export interface TierBAdapterRegistration {
  id: TierBAdapterId;
  /** Short human-readable label shown in `sanctuary wrap --list`. */
  label: string;
  /** Factory used by the CLI. */
  factory: (params: TierBAdapterParams) => TierBAdapter;
}

export const TIER_B_ADAPTER_SUPERVISOR_HARNESSES = {
  "claude-code": "claude_code",
  cline: "cline",
  hermes: "hermes",
  mastra: "mastra",
} as const satisfies Record<string, LocalHarnessKind>;

export type TierBAdapterId = keyof typeof TIER_B_ADAPTER_SUPERVISOR_HARNESSES;

export const TIER_B_ADAPTER_WRAP_PLATFORMS = {
  "claude-code": "claude-code",
  cline: "cline",
  hermes: "hermes",
  mastra: "mastra",
} as const satisfies Record<TierBAdapterId, AgentPlatform>;

const REGISTRY = new Map<TierBAdapterId, TierBAdapterRegistration>();

export function supervisorHarnessForTierBAdapter(
  id: string,
): LocalHarnessKind | undefined {
  return TIER_B_ADAPTER_SUPERVISOR_HARNESSES[id as TierBAdapterId];
}

export function wrapPlatformForTierBAdapter(
  id: string,
): AgentPlatform | undefined {
  return TIER_B_ADAPTER_WRAP_PLATFORMS[id as TierBAdapterId];
}

export function registerTierBAdapter(r: TierBAdapterRegistration): void {
  if (!supervisorHarnessForTierBAdapter(r.id)) {
    throw new TierBInvariantError(
      `adapter id "${r.id}" has no supervisor harness mapping`
    );
  }
  if (!wrapPlatformForTierBAdapter(r.id)) {
    throw new TierBInvariantError(
      `adapter id "${r.id}" has no wrap platform mapping`
    );
  }
  if (REGISTRY.has(r.id)) {
    throw new TierBInvariantError(
      `adapter id "${r.id}" already registered`
    );
  }
  REGISTRY.set(r.id, r);
}

export function listTierBAdapters(): TierBAdapterRegistration[] {
  return Array.from(REGISTRY.values()).sort((a, b) =>
    a.id.localeCompare(b.id)
  );
}

export function getTierBAdapter(
  id: string
): TierBAdapterRegistration | undefined {
  return REGISTRY.get(id as TierBAdapterId);
}
