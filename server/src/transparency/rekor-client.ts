/**
 * Minimal Sigstore Rekor client for transparency anchoring (PR-2).
 *
 * One operation: submit a hashedrekord proposal to the log and return the
 * created (or already-existing) entry reference. The HTTP transport is
 * injectable so the test suite NEVER touches the network (every live-path
 * behavior, including outages, malformed responses, and duplicate entries,
 * is covered by fixtures).
 *
 * Honesty discipline: a response that cannot be strictly parsed is a
 * FAILURE, never recorded as anchored. There is no retry loop here; retry
 * policy belongs to the operator-visible catch-up verb
 * (`sanctuary transparency anchor now`), not to a hidden loop.
 */

import type { HashedRekordProposal, RekorEntryRef } from "./anchor.js";

export const REKOR_ENTRIES_PATH = "/api/v1/log/entries";
export const REKOR_SUBMIT_TIMEOUT_MS = 30_000;

/** Narrow fetch surface so tests inject fixtures without network access. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  }
) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

export class RekorClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RekorClientError";
  }
}

/**
 * The log answered authoritatively that the entry does NOT exist (HTTP
 * 404). Distinct from transport failure: a receipt claiming an anchor the
 * log denies is verification-grade evidence, not an outage.
 */
export class RekorEntryNotFoundError extends RekorClientError {
  constructor(message: string) {
    super(message);
    this.name = "RekorEntryNotFoundError";
  }
}

export interface RekorSubmitResult {
  entry: RekorEntryRef;
  /** True when Rekor reported the entry already existed (HTTP 409). */
  duplicate: boolean;
}

export interface RekorClient {
  readonly baseUrl: string;
  submit(proposal: HashedRekordProposal): Promise<RekorSubmitResult>;
  /** GET one existing entry by UUID (fresh inclusion proof + body). */
  fetchEntry(uuid: string): Promise<RekorEntryRef>;
}

export interface HttpRekorClientOptions {
  baseUrl: string;
  fetchFn?: FetchLike;
  timeoutMs?: number;
}

export class HttpRekorClient implements RekorClient {
  readonly baseUrl: string;
  private readonly fetchFn: FetchLike;
  private readonly timeoutMs: number;

  constructor(options: HttpRekorClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchFn =
      options.fetchFn ?? (globalThis.fetch as unknown as FetchLike);
    if (typeof this.fetchFn !== "function") {
      throw new RekorClientError("no fetch implementation available");
    }
    this.timeoutMs = options.timeoutMs ?? REKOR_SUBMIT_TIMEOUT_MS;
  }

  async submit(proposal: HashedRekordProposal): Promise<RekorSubmitResult> {
    const url = `${this.baseUrl}${REKOR_ENTRIES_PATH}`;
    const controller = new AbortController();
    // ONE timeout budget covers the whole submission, including the
    // duplicate-entry lookup a 409 requires: the GET runs under the same
    // abort signal as the POST, so a stalling log cannot hold the caller
    // past timeoutMs.
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    try {
      let response: Awaited<ReturnType<FetchLike>>;
      try {
        response = await this.fetchFn(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify(proposal),
          signal: controller.signal,
        });
      } catch (err) {
        throw new RekorClientError(
          `Rekor unreachable (${url}): ${err instanceof Error ? err.message : String(err)}`
        );
      }

      if (response.status === 201) {
        return { entry: (await parseEntryBody(response)).entry, duplicate: false };
      }
      if (response.status === 409) {
        // The identical entry already exists. Rekor points at it via the
        // Location header; fetch it so the receipt carries real log
        // coordinates rather than a bare "duplicate" marker. The redirect
        // is followed ONLY same-origin: a Location pointing anywhere else
        // is a failure, never an outbound request (SSRF guard) and never
        // "anchored" on someone else's say-so.
        const location = response.headers.get("location");
        if (!location) {
          throw new RekorClientError(
            "Rekor reported a duplicate entry (409) without a Location header"
          );
        }
        const entryUrl = this.resolveSameOriginLocation(location);
        let existing: Awaited<ReturnType<FetchLike>>;
        try {
          existing = await this.fetchFn(entryUrl, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: controller.signal,
          });
        } catch (err) {
          throw new RekorClientError(
            `Rekor duplicate-entry lookup failed (${entryUrl}): ${err instanceof Error ? err.message : String(err)}`
          );
        }
        if (existing.status !== 200) {
          throw new RekorClientError(
            `Rekor duplicate-entry lookup returned HTTP ${existing.status}`
          );
        }
        const { entry, bodyB64 } = await parseEntryBody(existing);
        // "Duplicate" is only true if the fetched entry IS our proposal:
        // same digest, same signature, same public key. Anything else is
        // a failure, never recorded as anchored.
        assertDuplicateMatchesProposal(bodyB64, proposal);
        return { entry, duplicate: true };
      }
      const bodyText = await response.text().catch(() => "");
      throw new RekorClientError(
        `Rekor rejected the anchor (HTTP ${response.status})${bodyText ? `: ${bodyText.slice(0, 300)}` : ""}`
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Fetch one existing log entry by UUID. Used by the verifier's
   * --fetch-anchors mode to obtain a fresh inclusion proof (and the entry
   * body) directly from the log instead of trusting receipt-embedded
   * material. Strict parsing as everywhere: an off-shape response is a
   * failure, never silently usable evidence. A 404 raises the dedicated
   * RekorEntryNotFoundError because "the log denies this entry exists" is
   * itself a finding for the caller, not a retryable outage.
   */
  async fetchEntry(uuid: string): Promise<RekorEntryRef> {
    if (!/^[0-9a-f]{64,80}$/.test(uuid)) {
      throw new RekorClientError(
        `refusing to fetch a malformed Rekor entry UUID: ${uuid.slice(0, 96)}`
      );
    }
    const url = `${this.baseUrl}${REKOR_ENTRIES_PATH}/${uuid}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    try {
      let response: Awaited<ReturnType<FetchLike>>;
      try {
        response = await this.fetchFn(url, {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
      } catch (err) {
        throw new RekorClientError(
          `Rekor unreachable (${url}): ${err instanceof Error ? err.message : String(err)}`
        );
      }
      if (response.status === 404) {
        throw new RekorEntryNotFoundError(
          `Rekor reports no entry with UUID ${uuid} (HTTP 404)`
        );
      }
      if (response.status !== 200) {
        throw new RekorClientError(
          `Rekor entry lookup returned HTTP ${response.status}`
        );
      }
      const { entry } = await parseEntryBody(response);
      // The log must answer about the UUID we asked for. Sharded logs may
      // prepend a tree ID to the bare leaf-hash form, so suffix/prefix
      // relations are accepted; anything else is a wrong answer.
      if (
        entry.uuid !== uuid &&
        !entry.uuid.endsWith(uuid) &&
        !uuid.endsWith(entry.uuid)
      ) {
        throw new RekorClientError(
          `Rekor answered with entry ${entry.uuid} when asked for ${uuid}`
        );
      }
      return entry;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Resolve a 409 Location header against the configured Rekor base URL,
   * accepting it ONLY when the resolved origin exactly matches the
   * configured origin. Relative paths resolve same-origin by construction;
   * absolute URLs (and protocol-relative //host forms, which standard URL
   * resolution sends off-origin) must match exactly or are refused.
   */
  private resolveSameOriginLocation(location: string): string {
    let base: URL;
    try {
      base = new URL(this.baseUrl);
    } catch {
      throw new RekorClientError(
        `configured Rekor base URL is not a valid URL: ${this.baseUrl}`
      );
    }
    let resolved: URL;
    try {
      resolved = new URL(location, base);
    } catch {
      throw new RekorClientError(
        `Rekor duplicate (409) Location header is not a valid URL: ${location}`
      );
    }
    if (resolved.origin !== base.origin || resolved.origin === "null") {
      throw new RekorClientError(
        `Rekor duplicate (409) Location header points off-origin (${resolved.origin}, expected ${base.origin}); refusing to follow it`
      );
    }
    return resolved.toString();
  }
}

/**
 * Verify that a duplicate entry fetched via a 409 Location actually
 * contains the proposal we submitted. Rekor entries carry the canonical
 * entry document base64-encoded in `body`; the digest, signature, and
 * public key in it must match the submitted proposal byte-for-byte.
 * A missing, undecodable, or mismatched body is a FAILURE: the receipt
 * must never claim "anchored" pointing at someone else's entry.
 */
function assertDuplicateMatchesProposal(
  bodyB64: string | undefined,
  proposal: HashedRekordProposal
): void {
  if (!bodyB64) {
    throw new RekorClientError(
      "Rekor duplicate entry carried no body; cannot confirm it matches the submitted proposal"
    );
  }
  let entry: unknown;
  try {
    entry = JSON.parse(Buffer.from(bodyB64, "base64").toString("utf8"));
  } catch {
    throw new RekorClientError(
      "Rekor duplicate entry body did not decode to JSON; cannot confirm it matches the submitted proposal"
    );
  }
  const candidate = entry as {
    kind?: unknown;
    spec?: {
      data?: { hash?: { algorithm?: unknown; value?: unknown } };
      signature?: { content?: unknown; publicKey?: { content?: unknown } };
    };
  } | null;
  const matches =
    !!candidate &&
    typeof candidate === "object" &&
    candidate.kind === "hashedrekord" &&
    candidate.spec?.data?.hash?.algorithm === "sha256" &&
    candidate.spec?.data?.hash?.value === proposal.spec.data.hash.value &&
    candidate.spec?.signature?.content === proposal.spec.signature.content &&
    candidate.spec?.signature?.publicKey?.content ===
      proposal.spec.signature.publicKey.content;
  if (!matches) {
    throw new RekorClientError(
      "Rekor duplicate entry does not match the submitted proposal (digest, signature, or public key differ); refusing to record it as anchored"
    );
  }
}

/**
 * Parse Rekor's entry map `{ "<uuid>": { logIndex, logID, integratedTime,
 * verification, ... } }`. Strict: anything off-shape is an error, because a
 * receipt must never claim "anchored" on evidence that does not parse.
 * Also surfaces the raw base64 `body` field (when present) so the
 * duplicate path can verify the entry against the submitted proposal.
 */
async function parseEntryBody(
  response: Awaited<ReturnType<FetchLike>>
): Promise<{ entry: RekorEntryRef; bodyB64?: string }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await response.text());
  } catch {
    throw new RekorClientError("Rekor response was not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RekorClientError("Rekor response was not an entry object");
  }
  const keys = Object.keys(parsed as Record<string, unknown>);
  if (keys.length !== 1) {
    throw new RekorClientError(
      `Rekor response contained ${keys.length} entries (expected exactly 1)`
    );
  }
  const uuid = keys[0]!;
  const entry = (parsed as Record<string, unknown>)[uuid];
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new RekorClientError("Rekor entry body was not an object");
  }
  const candidate = entry as Record<string, unknown>;
  const logIndex = candidate.logIndex;
  const logId = candidate.logID;
  const integratedTime = candidate.integratedTime;
  if (
    typeof logIndex !== "number" ||
    !Number.isSafeInteger(logIndex) ||
    logIndex < 0 ||
    typeof logId !== "string" ||
    logId.length === 0 ||
    typeof integratedTime !== "number" ||
    !Number.isSafeInteger(integratedTime)
  ) {
    throw new RekorClientError(
      "Rekor entry was missing logIndex / logID / integratedTime"
    );
  }
  const verification = candidate.verification;
  return {
    entry: {
      uuid,
      log_index: logIndex,
      log_id: logId,
      integrated_time: integratedTime,
      // The body and verification blob are kept VERBATIM on the entry (and
      // therefore in the persisted receipt) so the PR-3 offline verifier
      // can rebind and Merkle-check the anchor with no network access.
      ...(typeof candidate.body === "string" ? { body_b64: candidate.body } : {}),
      ...(verification && typeof verification === "object" && !Array.isArray(verification)
        ? { verification: verification as Record<string, unknown> }
        : {}),
    },
    ...(typeof candidate.body === "string" ? { bodyB64: candidate.body } : {}),
  };
}
