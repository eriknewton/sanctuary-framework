/**
 * Bounds for the local summary task: the agent tool, the authority reply and
 * the worker job. Every value carries its derivation; none is tuned to pass a test.
 */
import { KIB, MINUTE_MS } from "./store-record.js";

/** The most record references one task names; also the fixed number of key derivations per authority reply. */
export const SOURCE_REFS_MAX = 32;
/** The instruction cap, counted in code points. */
export const INSTRUCTION_MAX_CHARS = 500;
/** One model call's input slice. */
export const CHUNK_BYTES = 16 * KIB;
/** At most this many chunk calls per job. */
export const CHUNK_MAX_CALLS = 8;
/** Four chunks of input per record. */
export const RECORD_PLAINTEXT_MAX_BYTES = 4 * CHUNK_BYTES;
/** The whole task input is what the chunk calls can carry. */
export const TASK_INPUT_MAX_BYTES = CHUNK_MAX_CALLS * CHUNK_BYTES;
/** Eight chunk calls plus one combine; combine runs only when there is more than one chunk. */
export const LOCAL_CALLS_MAX = CHUNK_MAX_CALLS + 1;
/** Generation bound sent on every chunk call. */
export const NUM_PREDICT_CHUNK = 256;
/** Generation bound sent on the combine call. */
export const NUM_PREDICT_COMBINE = 1_024;
/**
 * Sent as num_ctx. A token covers at least one input byte: 16,384 record
 * tokens, 1,024 of fixed system text, 2,000 of instruction (500 code points of
 * at most 4 bytes) and 1,024 of generation make 20,432, under 20 x 1,024.
 */
export const PROMPT_TOKEN_BOUND = 20 * 1_024;
/** Visible text kept from one chunk call. */
export const CHUNK_SUMMARY_MAX_BYTES = 2 * KIB;
/** Visible text kept from the combine call; its input is at most 8 x 2 KiB = 16 KiB, inside the same prompt bound. */
export const COMBINE_OUTPUT_MAX_BYTES = 8 * KIB;
/** Nine calls of 120 s each is 18 minutes, plus 2 for queueing and commit. */
export const JOB_DEADLINE_MS = 20 * MINUTE_MS;
/** Admitted submissions per seat in any trailing minute. */
export const SEAT_SUBMIT_PER_MINUTE = 4;
/** Admitted submissions per seat in any trailing hour; also the most timestamps kept per seat. */
export const SEAT_SUBMIT_PER_HOUR = 20;
/** A server process serves one launch seat; 16 bounds tests that vary it. The least recently used seat is evicted. */
export const RATE_SEATS_MAX = 16;
/** Queued jobs in the worker, across seats. */
export const WORKER_QUEUE_MAX = 32;
/** Queued jobs in the worker for one seat. */
export const WORKER_QUEUE_PER_SEAT_MAX = 8;
/** One job runs at a time, matching a model runtime that serves one request at a time. */
export const WORKER_RUNNING_MAX = 1;
/**
 * Jobs the server remembers for authority requests: every queued job plus the
 * running one, doubled so that jobs the worker dropped age out before live ones.
 */
export const AUTHORITY_PENDING_MAX = 2 * (WORKER_QUEUE_MAX + WORKER_RUNNING_MAX);
