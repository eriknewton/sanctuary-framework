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

export interface RekorSubmitResult {
  entry: RekorEntryRef;
  /** True when Rekor reported the entry already existed (HTTP 409). */
  duplicate: boolean;
}

export interface RekorClient {
  readonly baseUrl: string;
  submit(proposal: HashedRekordProposal): Promise<RekorSubmitResult>;
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
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
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
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 201) {
      return { entry: await parseEntryBody(response), duplicate: false };
    }
    if (response.status === 409) {
      // The identical entry already exists. Rekor points at it via the
      // Location header; fetch it so the receipt carries real log
      // coordinates rather than a bare "duplicate" marker.
      const location = response.headers.get("location");
      if (!location) {
        throw new RekorClientError(
          "Rekor reported a duplicate entry (409) without a Location header"
        );
      }
      const entryUrl = location.startsWith("http")
        ? location
        : `${this.baseUrl}${location}`;
      let existing: Awaited<ReturnType<FetchLike>>;
      try {
        existing = await this.fetchFn(entryUrl, {
          method: "GET",
          headers: { Accept: "application/json" },
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
      return { entry: await parseEntryBody(existing), duplicate: true };
    }
    const bodyText = await response.text().catch(() => "");
    throw new RekorClientError(
      `Rekor rejected the anchor (HTTP ${response.status})${bodyText ? `: ${bodyText.slice(0, 300)}` : ""}`
    );
  }
}

/**
 * Parse Rekor's entry map `{ "<uuid>": { logIndex, logID, integratedTime,
 * verification, ... } }`. Strict: anything off-shape is an error, because a
 * receipt must never claim "anchored" on evidence that does not parse.
 */
async function parseEntryBody(
  response: Awaited<ReturnType<FetchLike>>
): Promise<RekorEntryRef> {
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
    uuid,
    log_index: logIndex,
    log_id: logId,
    integrated_time: integratedTime,
    ...(verification && typeof verification === "object" && !Array.isArray(verification)
      ? { verification: verification as Record<string, unknown> }
      : {}),
  };
}
