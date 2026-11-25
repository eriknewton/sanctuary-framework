/**
 * The byte transport of `sanctuary verify-release`: four fixed resources,
 * fixed hosts, fixed redirect edges, byte caps, a stall timeout and the run
 * deadline. It is separate from the advisory update-check transport on purpose:
 * that one is best-effort and text-oriented, and this one supplies evidence.
 *
 * Every failure is a refusal. The network carries bytes only; authenticity
 * comes from the signatures checked later, so a fetch that fails, stalls,
 * redirects off policy or overruns a cap cannot be retried into a weaker
 * check, and the verb never reports anything but `refused` for it.
 */

import * as https from "node:https";
import type { IncomingHttpHeaders } from "node:http";
import {
  GITHUB_ASSET_HOSTS,
  MAX_ATTESTATIONS_BYTES,
  MAX_MANIFEST_BYTES,
  MAX_REDIRECT_HOPS,
  MAX_TARBALL_BYTES,
  MAX_VERSION_DOCUMENT_BYTES,
  STALL_TIMEOUT_MS,
  attestationsUrl,
  manifestUrl,
  tarballUrl,
  versionDocumentUrl,
} from "./constants.js";
import type { Deadline } from "./deadline.js";
import type { FetchResource, RefusalReason, StepOutcome } from "./reasons.js";

/** One response from the low-level requester. The body must be destroyed when it is not read to the end. */
export interface RawResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: AsyncIterable<Uint8Array> & { destroy(): void };
}

/** The injected seam: one GET of one absolute URL, no redirect handling, no ambient state. */
export type HttpRequester = (url: URL, signal: AbortSignal) => Promise<RawResponse>;

const HTTPS_PORT = "443";
const STATUS_OK = 200;
const REDIRECT_MIN = 300;
const REDIRECT_MAX = 399;

interface ResourcePolicy {
  resource: FetchResource;
  url: string;
  maxBytes: number;
  /** Hosts a redirect from the starting host may reach. Empty: any 3xx refuses. */
  redirectHosts: readonly string[];
}

export function resourcePolicies(version: string): Record<FetchResource, ResourcePolicy> {
  return {
    "version-document": { resource: "version-document", url: versionDocumentUrl(version), maxBytes: MAX_VERSION_DOCUMENT_BYTES, redirectHosts: [] },
    attestations: { resource: "attestations", url: attestationsUrl(version), maxBytes: MAX_ATTESTATIONS_BYTES, redirectHosts: [] },
    tarball: { resource: "tarball", url: tarballUrl(version), maxBytes: MAX_TARBALL_BYTES, redirectHosts: [] },
    // GitHub serves release assets from a separate asset host after one redirect.
    manifest: { resource: "manifest", url: manifestUrl(version), maxBytes: MAX_MANIFEST_BYTES, redirectHosts: GITHUB_ASSET_HOSTS },
  };
}

/** https, port 443, no userinfo, on every hop; the hostname is compared exactly after URL parsing. */
function hopAllowed(url: URL, hosts: readonly string[]): boolean {
  return url.protocol === "https:" && (url.port === "" || url.port === HTTPS_PORT)
    && url.username === "" && url.password === "" && hosts.includes(url.hostname);
}

function singleHeader(headers: IncomingHttpHeaders, name: string): string | undefined | null {
  const value = headers[name];
  if (value === undefined) return undefined;
  // Two values for one length or location header are ambiguous, so they are refused.
  return typeof value === "string" ? value : null;
}

/**
 * Fetch one resource. The policy's URL is the only starting point; a
 * redirect may move only to the policy's redirect hosts, never back to the
 * starting host or to the registry, at most MAX_REDIRECT_HOPS times.
 */
export async function fetchResource(
  policy: ResourcePolicy,
  requester: HttpRequester,
  deadline: Deadline,
): Promise<StepOutcome<Buffer>> {
  const { resource } = policy;
  const failed: RefusalReason = `fetch-failed:${resource}`;
  const redirectRefused: RefusalReason = `fetch-redirect-refused:${resource}`;
  const startHost = new URL(policy.url).hostname;
  let url = new URL(policy.url);
  let allowedHosts: readonly string[] = [startHost];
  const seen = new Set<string>();
  for (let hop = 0; ; hop++) {
    if (deadline.expired()) return { ok: false, reason: "deadline-exceeded" };
    if (!hopAllowed(url, allowedHosts) || seen.has(url.href)) return { ok: false, reason: hop === 0 ? failed : redirectRefused };
    seen.add(url.href);
    const outcome = await requestOnce(url, policy, requester, deadline);
    if (outcome.kind === "refused") return { ok: false, reason: outcome.reason };
    if (outcome.kind === "body") return { ok: true, evidence: outcome.body };
    // A redirect: only enumerated edges, bounded hops, each target revalidated in full at the loop top.
    if (policy.redirectHosts.length === 0 || hop + 1 > MAX_REDIRECT_HOPS) return { ok: false, reason: redirectRefused };
    let next: URL;
    try {
      next = new URL(outcome.location, url);
    } catch {
      return { ok: false, reason: redirectRefused };
    }
    url = next;
    allowedHosts = policy.redirectHosts;
  }
}

type HopOutcome =
  | { kind: "body"; body: Buffer }
  | { kind: "redirect"; location: string }
  | { kind: "refused"; reason: RefusalReason };

async function requestOnce(
  url: URL,
  policy: ResourcePolicy,
  requester: HttpRequester,
  deadline: Deadline,
): Promise<HopOutcome> {
  const { resource, maxBytes } = policy;
  const failed: RefusalReason = `fetch-failed:${resource}`;
  const oversize: RefusalReason = `fetch-oversize:${resource}`;
  const clock = deadline.clock;
  // One controller per hop: the run deadline and this hop's stall timer both abort it.
  const controller = new AbortController();
  let stalled = false;
  const onDeadline = (): void => controller.abort();
  deadline.signal.addEventListener("abort", onDeadline, { once: true });
  let stallTimer: unknown;
  const armStall = (): void => {
    clock.clearTimeout(stallTimer);
    stallTimer = clock.setTimeout(() => { stalled = true; controller.abort(); }, STALL_TIMEOUT_MS);
  };
  const lateOrFailed = (): RefusalReason => (deadline.expired() ? "deadline-exceeded" : failed);
  let response: RawResponse | undefined;
  try {
    armStall();
    try {
      response = await raceAbort(requester(url, controller.signal), controller.signal);
    } catch {
      return { kind: "refused", reason: stalled ? failed : lateOrFailed() };
    }
    if (response.status >= REDIRECT_MIN && response.status <= REDIRECT_MAX) {
      const location = singleHeader(response.headers, "location");
      response.body.destroy();
      if (typeof location !== "string" || location.length === 0) return { kind: "refused", reason: `fetch-redirect-refused:${resource}` };
      return { kind: "redirect", location };
    }
    if (response.status !== STATUS_OK) {
      response.body.destroy();
      return { kind: "refused", reason: failed };
    }
    const lengthHeader = singleHeader(response.headers, "content-length");
    let declared: number | undefined;
    if (lengthHeader !== undefined) {
      if (lengthHeader === null || !/^\d+$/.test(lengthHeader)) {
        response.body.destroy();
        return { kind: "refused", reason: failed };
      }
      declared = Number(lengthHeader);
      if (declared > maxBytes) {
        response.body.destroy();
        return { kind: "refused", reason: oversize };
      }
    }
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for await (const chunk of iterateWithAbort(response.body, controller.signal)) {
        total += chunk.byteLength;
        // The cap binds the bytes actually received, whatever Content-Length said.
        if (total > maxBytes) {
          response.body.destroy();
          return { kind: "refused", reason: oversize };
        }
        chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        armStall();
      }
    } catch {
      response.body.destroy();
      return { kind: "refused", reason: stalled ? failed : lateOrFailed() };
    }
    if (declared !== undefined && declared !== total) return { kind: "refused", reason: failed };
    // A body that completed after the deadline is discarded: it can never contribute evidence.
    if (deadline.expired()) return { kind: "refused", reason: "deadline-exceeded" };
    return { kind: "body", body: Buffer.concat(chunks, total) };
  } finally {
    clock.clearTimeout(stallTimer);
    deadline.signal.removeEventListener("abort", onDeadline);
    if (controller.signal.aborted) response?.body.destroy();
  }
}

/** Settle on abort even if the requester ignores its signal; a late resolution is destroyed, never read. */
function raceAbort(pending: Promise<RawResponse>, signal: AbortSignal): Promise<RawResponse> {
  if (signal.aborted) {
    pending.then(late => late.body.destroy(), () => undefined);
    return Promise.reject(new Error("aborted"));
  }
  return new Promise<RawResponse>((resolve, reject) => {
    const onAbort = (): void => {
      pending.then(late => late.body.destroy(), () => undefined);
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    pending.then(
      value => {
        signal.removeEventListener("abort", onAbort);
        if (signal.aborted) {
          value.body.destroy();
          reject(new Error("aborted"));
        } else {
          resolve(value);
        }
      },
      error => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/** Iterate a body, ending with an error as soon as the signal aborts, even between chunks. */
async function* iterateWithAbort(body: AsyncIterable<Uint8Array>, signal: AbortSignal): AsyncGenerator<Uint8Array> {
  const iterator = body[Symbol.asyncIterator]();
  let rejectAbort: ((error: Error) => void) | undefined;
  const aborted = new Promise<never>((_, reject) => { rejectAbort = reject; });
  aborted.catch(() => undefined);
  const onAbort = (): void => rejectAbort?.(new Error("aborted"));
  if (signal.aborted) onAbort();
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      const step = await Promise.race([iterator.next(), aborted]);
      if (step.done) return;
      yield step.value;
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    void iterator.return?.();
  }
}

/**
 * The production requester: one HTTPS GET with no agent pool, no cookies, no
 * credentials, no proxy and no ambient auth headers. Redirects are not
 * followed here; `fetchResource` decides every hop.
 */
export const httpsRequester: HttpRequester = (url, signal) =>
  new Promise<RawResponse>((resolve, reject) => {
    const request = https.request(url, {
      method: "GET",
      agent: false,
      headers: { accept: "*/*", "user-agent": "sanctuary-verify-release" },
      signal,
    }, response => {
      resolve({ status: response.statusCode ?? 0, headers: response.headers, body: response });
    });
    request.on("error", reject);
    request.end();
  });
