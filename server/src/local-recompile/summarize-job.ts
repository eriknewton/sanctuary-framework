/**
 * One summary job in the worker, as named states: state_QUEUED,
 * state_AUTHORITY, state_DIGEST, state_READ, state_GENERATE, state_COMMIT,
 * then state_DONE or state_REFUSED. Each transition writes one operator-log
 * row carrying ids, counts, byte lengths, causes and durations, never record
 * or model text. The results object and its rows are the only output: nothing
 * returns to the server's agent path.
 */
import { createHash } from "node:crypto";
import { StateVerificationError, openStateEntry } from "../cognitive/state-entry-open.js";
import { resolveLoopbackConnectTarget, type LoopbackConnectTarget } from "../intelligence/loopback-endpoint.js";
import { inspectOllamaTagsDigest } from "../intelligence/runtime-light-verifier.js";
import {
  STREAM_TOTAL_MAX_BYTES,
  type SensitiveGenerateRequest,
  type SensitiveGenerationResult,
  type SensitiveTagsResult,
} from "../intelligence/sensitive-generation-client.js";
import { StorageReadBoundError } from "../storage/interface.js";
import { canonicalLocalJson } from "./canonical.js";
import type { QueuedJob } from "./job-queue.js";
import {
  CHUNK_SUMMARY_MAX_BYTES,
  COMBINE_OUTPUT_MAX_BYTES,
  NUM_PREDICT_CHUNK,
  NUM_PREDICT_COMBINE,
  PROMPT_TOKEN_BOUND,
  RECORD_PLAINTEXT_MAX_BYTES,
  TASK_INPUT_MAX_BYTES,
} from "./limits.js";
import type { JobCallOutcome, JobFailureCause, JobRefusalCause, OplogAppendKind, OplogBodies } from "./oplog.js";
import { chunkPrompt, combinePrompt, frameAndChunk, truncateUtf8 } from "./prompts.js";
import { CommitDeadlineError, CommitIndeterminateError, type LocalResultBody } from "./results-store.js";
import { LocalStoreError, SEAT_ID_HEX_LENGTH } from "./store-record.js";
import type { AuthorityReply, JobState, WriterKeyRow } from "./worker-protocol.js";

// AES-256-GCM appends a 16-byte authentication tag to the ciphertext.
const GCM_TAG_BYTES = 16;
/** Unpadded base64url length of n bytes: ceil(4n / 3). */
function base64urlLength(bytes: number): number {
  return Math.ceil((4 * bytes) / 3);
}
/**
 * Names, ids, the version and kid, two signatures, timestamps, the integrity
 * hash, a provenance stamp and a modest tag list, as JSON. A record whose
 * metadata is larger than this is refused as oversized rather than read.
 */
export const RECORD_ENVELOPE_ALLOWANCE_BYTES = 16 * 1_024;
/**
 * The stored size of a RECORD_PLAINTEXT_MAX_BYTES state entry: the
 * ciphertext appears twice as base64url (the payload's `ct` and the signed
 * envelope's `payload.ciphertext`), plus the envelope allowance. Must match the
 * StateEntry and SignedStateEnvelope shapes in cognitive/state-entry-open.ts.
 */
export const RECORD_STORED_MAX_BYTES =
  2 * base64urlLength(RECORD_PLAINTEXT_MAX_BYTES + GCM_TAG_BYTES) + RECORD_ENVELOPE_ALLOWANCE_BYTES;

/** The results store's seat id for a router seat; must match SEAT_ID_HEX_LENGTH in store-record.ts. */
export function resultSeatId(seat: string): string {
  return createHash("sha256").update(seat, "utf8").digest("hex").slice(0, SEAT_ID_HEX_LENGTH);
}

export interface GenerationClient {
  generate(input: SensitiveGenerateRequest): Promise<SensitiveGenerationResult>;
  fetchTags(): Promise<SensitiveTagsResult>;
}

export interface SummarizeJobDependencies {
  readRecord(namespace: string, key: string, maxBytes: number): Promise<Uint8Array | null>;
  log<K extends OplogAppendKind>(kind: K, body: OplogBodies[K]): Promise<unknown>;
  putPending(input: { request_id: string; seat: string; kind: "summarize"; deadline: number }): Promise<unknown>;
  /**
   * Commit the result; `committedRow` appends the job's job_committed row under the results lock,
   * after the object is durable (results-store.ts markCommitted states the rollback rule).
   */
  markCommitted(requestId: string, body: LocalResultBody, committedRow: () => Promise<unknown>): Promise<unknown>;
  /** Ask the server for this job's authority; null when no reply arrives in time. */
  requestAuthority(requestId: string): Promise<AuthorityReply | null>;
  reportState(requestId: string, state: JobState): void;
  /** The only way this job reaches a model: the loopback client bound to the descriptor's literal endpoint. */
  makeClient(target: LoopbackConnectTarget, timeoutMs: number): GenerationClient;
  callTimeoutMs: number;
  jobDeadlineMs: number;
  now(): number;
  setTimer(callback: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
}

class Refusal extends Error {
  constructor(readonly cause: JobRefusalCause, readonly slot: number | null = null) {
    super(cause);
  }
}
class Failure extends Error {
  constructor(readonly failure: JobFailureCause) {
    super(failure);
  }
}
/** The commit may have landed without its row; the job is logged indeterminate, never failed. */
class Indeterminate extends Error {}

function writerResolver(writers: readonly WriterKeyRow[]): (kid: string) => Promise<readonly Uint8Array[]> {
  const table = new Map(writers.map((row) => [row.kid, row.public_keys] as const));
  return async (kid) => (typeof kid === "string" ? table.get(kid) ?? [] : []);
}

function readFailureCause(error: unknown): JobRefusalCause {
  if (error instanceof StateVerificationError) {
    return error.classification === "integrity_hash_mismatch" ? "record_undecryptable" : "record_unverifiable";
  }
  // AES-GCM refuses a wrong key or altered ciphertext by throwing; nothing is returned.
  return "record_undecryptable";
}

/** Run one job to state_DONE or state_REFUSED. Never throws; every outcome is an operator-log row. */
export async function runSummarizeJob(entry: QueuedJob, deps: SummarizeJobDependencies): Promise<JobState> {
  const job = entry.job;
  const id = job.request_id;
  const started = deps.now();
  const deadlineAt = entry.queued_at + deps.jobDeadlineMs;
  let keys: Uint8Array[] = [];
  let generating = false;
  const state = (next: JobState) => deps.reportState(id, next);
  // No stage starts and no publication begins after the job's deadline: this runs at entry and before
  // every stage, and the results store checks it again under its lock, immediately before publication.
  const beforeDeadline = () => {
    if (deps.now() >= deadlineAt) throw new Failure("deadline");
  };
  try {
    beforeDeadline();
    await deps.log("job_started", { request_id: id, refs: job.refs.length });

    beforeDeadline();
    state("state_AUTHORITY");
    const reply = await deps.requestAuthority(id);
    if (reply === null) throw new Refusal("authority_timeout");
    if (reply.outcome === "refused") throw new Refusal(reply.cause);
    keys = reply.keys;
    if (keys.length !== job.refs.length) throw new Refusal("request_unknown");

    beforeDeadline();
    state("state_DIGEST");
    const { address, port } = reply.descriptor.endpoint;
    const host = address.includes(":") ? `[${address}]` : address;
    const resolved = resolveLoopbackConnectTarget(`http://${host}:${port}/`);
    if (!resolved.ok) throw new Refusal("not_loopback");
    const client = deps.makeClient(resolved.target, deps.callTimeoutMs);
    // Generation is bound to the signed model, checked at job time, not at boot: the runtime's
    // reported digest for the descriptor's tag must equal the digest the signed identity names.
    const tags = await client.fetchTags();
    if (!tags.ok) throw new Refusal("model_unavailable");
    const inspected = inspectOllamaTagsDigest(tags.payload, reply.descriptor.runtime_tag);
    if (!inspected.ok) throw new Refusal(inspected.state === "tags_model_absent" ? "model_unavailable" : "model_digest_mismatch");
    if (inspected.observedManifestDigest !== reply.descriptor.manifest_digest) throw new Refusal("model_digest_mismatch");

    beforeDeadline();
    state("state_READ");
    const resolveWriterKeys = writerResolver(reply.writers);
    const texts: string[] = [];
    let total = 0;
    for (const [slot, ref] of job.refs.entries()) {
      beforeDeadline();
      let raw: Uint8Array | null;
      try {
        raw = await deps.readRecord(ref.namespace, ref.key, RECORD_STORED_MAX_BYTES);
      } catch (error) {
        throw new Refusal(error instanceof StorageReadBoundError ? "record_oversized" : "record_missing", slot);
      }
      if (raw === null) throw new Refusal("record_missing", slot);
      try {
        // The worker checks each record's writer signature and decrypts it, but holds no copy of
        // the server's anti-rollback cache; DEBT(LOCAL-WORKER-ROLLBACK-ANCHOR).
        const opened = await openStateEntry(raw, {
          namespace: ref.namespace,
          key: ref.key,
          namespaceKey: keys[slot]!,
          resolveWriterKeys,
        });
        const bytes = Buffer.byteLength(opened.value, "utf8");
        if (bytes > RECORD_PLAINTEXT_MAX_BYTES) throw new Refusal("record_oversized", slot);
        total += bytes;
        if (total > TASK_INPUT_MAX_BYTES) throw new Refusal("input_too_large", slot);
        texts.push(opened.value);
      } catch (error) {
        if (error instanceof Refusal) throw error;
        throw new Refusal(readFailureCause(error), slot);
      } finally {
        raw.fill(0);
      }
    }
    // Each namespace key is used once, for its own record, and zeroed before generation begins.
    for (const key of keys) key.fill(0);
    const chunks = frameAndChunk(texts);
    texts.length = 0;
    if (chunks === null) throw new Refusal("input_too_large");

    beforeDeadline();
    state("state_GENERATE");
    generating = true;
    // A crash from here on leaves a pending object that the sweep marks indeterminate after the deadline.
    try {
      await deps.putPending({ request_id: id, seat: resultSeatId(job.seat), kind: "summarize", deadline: deadlineAt });
    } catch (error) {
      throw new Failure(error instanceof LocalStoreError && error.kind === "capacity" ? "results_full" : "commit_failed");
    }
    const abort = new AbortController();
    const timer = deps.setTimer(() => abort.abort(), Math.max(0, deadlineAt - deps.now()));
    try {
      const summaries: Array<{ text: string; cites: number[] }> = [];
      let truncated = false;
      let callNumber = 0;
      const call = async (phase: "chunk" | "combine", prompt: string, numPredict: number, capBytes: number) => {
        beforeDeadline();
        callNumber += 1;
        const callStarted = deps.now();
        // The transport refuses only a stream over its own total cap; the visible text is cut here at a
        // code-point boundary, so a long answer is kept and marked truncated rather than lost.
        const result = await client.generate({
          model: reply.descriptor.runtime_tag,
          prompt,
          numPredict,
          numCtx: PROMPT_TOKEN_BOUND,
          visibleTextMaxBytes: STREAM_TOTAL_MAX_BYTES,
          signal: abort.signal,
        });
        const outcome: JobCallOutcome = result.ok ? "ok" : result.reason;
        const cut = result.ok ? truncateUtf8(result.text, capBytes) : { text: "", truncated: false };
        await deps.log("job_call", {
          request_id: id,
          call: callNumber,
          phase,
          input_bytes: Buffer.byteLength(prompt, "utf8"),
          output_bytes: Buffer.byteLength(cut.text, "utf8"),
          truncated: cut.truncated,
          duration_ms: Math.max(0, deps.now() - callStarted),
          outcome,
        });
        // A reply that arrives after the deadline was aborted with its stream destroyed; the job ends here.
        if (abort.signal.aborted) throw new Failure("deadline");
        if (!result.ok) throw new Failure("call_failed");
        truncated ||= cut.truncated;
        return cut.text;
      };
      for (const chunk of chunks) {
        summaries.push({ text: await call("chunk", chunkPrompt(job.instruction, chunk), NUM_PREDICT_CHUNK, CHUNK_SUMMARY_MAX_BYTES), cites: chunk.cites });
      }
      const summary = summaries.length > 1
        ? await call("combine", combinePrompt(job.instruction, summaries), NUM_PREDICT_COMBINE, COMBINE_OUTPUT_MAX_BYTES)
        : summaries[0]!.text;

      state("state_COMMIT");
      // No publication begins after the deadline: checked here, and again by the store under its lock.
      if (abort.signal.aborted) throw new Failure("deadline");
      beforeDeadline();
      const body: LocalResultBody = {
        summary,
        refs: job.refs.map((ref, index) => canonicalLocalJson({ n: index + 1, namespace: ref.namespace, key: ref.key })),
        // Citations are the record numbers this code attached to each chunk, never parsed from model text.
        chunk_cites: summaries.map((part) => part.cites.join(",")),
        model_runtime_tag: reply.descriptor.runtime_tag,
        model_manifest_digest: reply.descriptor.manifest_digest,
        truncated: truncated ? "true" : "false",
      };
      // The object and its job_committed row are written under the results lock then the operator-log
      // lock. Invariant: a committed result never sits beside a job_failed row. Only a refusal before
      // the store's publication begins maps to job_failed; every failure after it has begun arrives as
      // CommitIndeterminateError and is logged job_indeterminate only.
      try {
        await deps.markCommitted(id, body, () =>
          deps.log("job_committed", {
            request_id: id,
            chunks: summaries.length,
            output_bytes: Buffer.byteLength(summary, "utf8"),
            truncated,
            duration_ms: Math.max(0, deps.now() - started),
          }));
      } catch (error) {
        if (error instanceof CommitDeadlineError) throw new Failure("deadline");
        if (error instanceof CommitIndeterminateError) throw new Indeterminate();
        if (error instanceof LocalStoreError && error.kind === "capacity") throw new Failure("results_full");
        throw new Failure("commit_failed");
      }
      state("state_DONE");
      return "state_DONE";
    } finally {
      deps.clearTimer(timer);
    }
  } catch (error) {
    state("state_REFUSED");
    try {
      if (error instanceof Refusal) {
        await deps.log("job_refused", { request_id: id, cause: error.cause, slot: error.slot });
      } else if (error instanceof Indeterminate) {
        await deps.log("job_indeterminate", { request_id: id });
      } else if (error instanceof Failure) {
        await deps.log("job_failed", { request_id: id, cause: error.failure });
      } else {
        const cause: JobFailureCause = error instanceof Failure ? error.failure : generating ? "commit_failed" : "call_failed";
        if (generating) await deps.log("job_failed", { request_id: id, cause });
        else await deps.log("job_refused", { request_id: id, cause: "internal", slot: null });
      }
    } catch {
      // The operator log is the only record; an append that fails leaves the job refused with no row.
    }
    return "state_REFUSED";
  } finally {
    for (const key of keys) key.fill(0);
  }
}
