/**
 * The server's answer to a worker's authority request for one job: the
 * verified binding descriptor, the namespace keys for the job's refs, and the
 * authenticated writer-key table. It answers from memory only, after the
 * agent's response has gone, never calls the principal gate or its baseline
 * counters, and writes nothing to the shared audit log.
 */
import { deriveNamespaceKey } from "../core/key-derivation.js";
import type { StoredIdentity } from "../core/identity.js";
import { isReservedNamespace, resolveAuthenticatedIdentityWriterPublicKeys } from "../cognitive/state-store.js";
import type { PrincipalPolicy } from "../principal-policy/types.js";
import { LOCAL_TASK_SURFACE, type LocalBindingDescriptor, type LocalBindingSource } from "./binding.js";
import { AUTHORITY_PENDING_MAX, SOURCE_REFS_MAX } from "./limits.js";
import {
  IPC_MESSAGE_MAX_BYTES,
  ipcMessageBytes,
  type AuthorityRefusalCause,
  type AuthorityReply,
  type LocalTaskRef,
  type WriterKeyRow,
} from "./worker-protocol.js";

/**
 * HKDF info for every empty or uncovered ref slot. Decoy keys are derived so
 * that a reply costs the same derivations whatever the refs name, then zeroed
 * and discarded. Must match the decoy pin in test/local-recompile/authority.test.ts.
 */
export const LOCAL_TASK_DECOY_KEY_LABEL = "local-recompile-decoy";

/** The tool whose tier decides whether a ref's namespace is readable by the local task. */
export const COVERAGE_OPERATION = "state_read";

export interface AuthorityJob {
  request_id: string;
  refs: readonly LocalTaskRef[];
}

export interface LocalAuthorityDependencies {
  binding: LocalBindingSource;
  /** The frozen principal policy object; coverage reads nothing else. */
  policy: Readonly<PrincipalPolicy>;
  /** The live master key; never copied, never sent. */
  masterKey: Uint8Array;
  /** Loaded identities whose authenticated public keys verify record writers. */
  identities: () => readonly StoredIdentity[];
  /** Key derivation; production passes deriveNamespaceKey. */
  deriveKey?: (masterKey: Uint8Array, label: string) => Uint8Array;
}

/**
 * Whether a namespace is readable by the local task: not reserved, and the
 * frozen policy auto-allows state_read with no Tier 1 list naming it. Must
 * match the coverage rule pinned in test/local-recompile/authority.test.ts.
 */
export function coveredNamespace(policy: Readonly<PrincipalPolicy>, namespace: string): boolean {
  return (
    !isReservedNamespace(namespace) &&
    policy.tier3_always_allow.includes(COVERAGE_OPERATION) &&
    !policy.tier1_always_approve.includes(COVERAGE_OPERATION)
  );
}

function writerTable(identities: readonly StoredIdentity[]): WriterKeyRow[] {
  const rows: WriterKeyRow[] = [];
  for (const identity of identities) {
    const keys = resolveAuthenticatedIdentityWriterPublicKeys(identity).map((key) => Uint8Array.from(key.publicKey));
    if (keys.length > 0) rows.push({ kid: identity.identity_id, public_keys: keys });
  }
  return rows;
}

/** Remembers each submitted job's refs until the worker asks for its authority. */
export class LocalAuthority {
  private readonly pending = new Map<string, AuthorityJob>();
  private armedEpoch: number | undefined;
  private readonly deriveKey: (masterKey: Uint8Array, label: string) => Uint8Array;

  constructor(private readonly deps: LocalAuthorityDependencies) {
    this.deriveKey = deps.deriveKey ?? deriveNamespaceKey;
  }

  /** Record the binding epoch seen at arming; a later configuration change refuses every job. */
  arm(): void {
    const described = this.deps.binding.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE);
    this.armedEpoch = described.ok ? described.epoch : undefined;
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  /** Remember one job. Bounded: the oldest entry goes first, and a job evicted this way is refused when asked for. */
  register(job: AuthorityJob): void {
    this.pending.delete(job.request_id);
    this.pending.set(job.request_id, { request_id: job.request_id, refs: job.refs.map((ref) => ({ ...ref })) });
    while (this.pending.size > AUTHORITY_PENDING_MAX) {
      const oldest = this.pending.keys().next().value as string;
      this.pending.delete(oldest);
    }
  }

  /** Forget a job the worker will never ask about. */
  forget(requestId: string): void {
    this.pending.delete(requestId);
  }

  /**
   * Answer one authority request. Real key bytes leave only when the binding
   * is valid and every ref is covered; every other reply carries a cause and no key.
   */
  reply(requestId: string): AuthorityReply {
    const job = this.pending.get(requestId);
    this.pending.delete(requestId);
    const refs = job?.refs ?? [];
    const described = this.deps.binding.describeVerifiedLocalBinding(LOCAL_TASK_SURFACE, this.armedEpoch ?? -1);
    const covered = refs.map((ref) => coveredNamespace(this.deps.policy, ref.namespace));
    // Exactly SOURCE_REFS_MAX derivations every time, one per slot, with the decoy label for every
    // empty or uncovered slot, so the work done never depends on what the refs name or whether they pass.
    const derived: Uint8Array[] = [];
    try {
      for (let slot = 0; slot < SOURCE_REFS_MAX; slot += 1) {
        const ref = refs[slot];
        const label = ref !== undefined && covered[slot] === true ? ref.namespace : LOCAL_TASK_DECOY_KEY_LABEL;
        derived.push(this.deriveKey(this.deps.masterKey, label));
      }
      const cause = this.refusalCause(job, described.ok ? described.descriptor : undefined, described, covered);
      if (cause !== undefined) return { type: "authority_reply", request_id: requestId, outcome: "refused", cause };
      const descriptor = (described as { descriptor: LocalBindingDescriptor }).descriptor;
      const reply: AuthorityReply = {
        type: "authority_reply",
        request_id: requestId,
        outcome: "granted",
        descriptor: { runtime_tag: descriptor.runtime_tag, manifest_digest: descriptor.manifest_digest,
          endpoint: { address: descriptor.endpoint.address, port: descriptor.endpoint.port } },
        keys: refs.map((_, slot) => Uint8Array.from(derived[slot]!)),
        writers: writerTable(this.deps.identities()),
      };
      // A writer table that would not fit one IPC message refuses the job rather than splitting it.
      if (ipcMessageBytes(reply) > IPC_MESSAGE_MAX_BYTES) {
        zeroReply(reply);
        return { type: "authority_reply", request_id: requestId, outcome: "refused", cause: "writer_table_too_large" };
      }
      return reply;
    } finally {
      // Every derived slot, decoy or real, is zeroed here; a granted reply carries its own copies.
      for (const key of derived) key.fill(0);
    }
  }

  private refusalCause(
    job: AuthorityJob | undefined,
    descriptor: LocalBindingDescriptor | undefined,
    described: ReturnType<LocalBindingSource["describeVerifiedLocalBinding"]>,
    covered: boolean[],
  ): AuthorityRefusalCause | undefined {
    if (job === undefined || job.refs.length === 0) return "request_unknown";
    if (!described.ok) return described.refusal;
    if (descriptor === undefined) return "binding_absent";
    if (covered.some((value) => !value)) return "uncovered";
    return undefined;
  }
}

/** Zero every key byte a reply holds, after it has been sent or when it is refused. */
export function zeroReply(reply: AuthorityReply): void {
  if (reply.outcome !== "granted") return;
  for (const key of reply.keys) key.fill(0);
}
