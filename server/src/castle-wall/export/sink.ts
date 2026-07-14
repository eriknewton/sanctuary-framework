/**
 * Delivery sinks for mapped enforcement events.
 *
 * TWO sinks, split by whether they touch the network:
 *   - `FileExportSink` (default): serializes each event as one NDJSON line and
 *     hands it to an injected writer (stdout by default, or an append-file
 *     writer). It NEVER opens a socket; `touchesNetwork` is false. This is the
 *     safe-by-default lane that needs no approval.
 *   - `HttpCollectorSink`: POSTs a JSON batch to the single PINNED collector URL.
 *     It FAILS LOUD on an unreachable destination or a non-2xx response (throws
 *     `EnforcementExportDeliveryError`); it never falls back to a file, never
 *     silently drops, and never follows a redirect off the pinned host
 *     (AGENTS.md must-never #5).
 *
 * NO SECRETS EVER (must-never #6): the payload is exactly the mapped
 * `EnforcementEvent[]` (metadata only), and no key material, bearer token, or
 * secret is attached to the body, headers, or any log line here.
 */

import type { EnforcementEventClass } from "./schema.js";
import type { EnforcementEvent } from "./schema.js";
import type { EnforcementExportSinkKind } from "./config.js";

/** Outcome of a single deliver() call. */
export interface DeliveryResult {
  /** Number of events handed to the sink. */
  delivered: number;
}

/** A destination mapped events are delivered to. */
export interface EnforcementExportSink {
  /** Which sink kind this is. */
  readonly kind: EnforcementExportSinkKind;
  /** Whether delivery opens a network connection. `false` for the file/stdout sink. */
  readonly touchesNetwork: boolean;
  /**
   * Deliver a batch. Resolves with the count delivered, or REJECTS (never
   * resolves-with-partial-silence) if delivery failed, so the caller can audit a
   * refusal and fail closed.
   */
  deliver(events: readonly EnforcementEvent[]): Promise<DeliveryResult>;
}

/** A line writer the file sink appends to. Injected so the sink stays hermetic. */
export type LineWriter = (line: string) => void | Promise<void>;

/** Serialize one enforcement event to a single canonical NDJSON line. */
function toNdjsonLine(event: EnforcementEvent): string {
  return JSON.stringify(event);
}

/**
 * The default, network-free sink. Writes one NDJSON line per event through the
 * injected writer. Opens no socket.
 */
export class FileExportSink implements EnforcementExportSink {
  readonly kind: EnforcementExportSinkKind = "file";
  readonly touchesNetwork = false;

  constructor(private readonly writeLine: LineWriter) {}

  async deliver(events: readonly EnforcementEvent[]): Promise<DeliveryResult> {
    for (const event of events) {
      await this.writeLine(toNdjsonLine(event));
    }
    return { delivered: events.length };
  }
}

/** A writer that appends NDJSON lines to `process.stdout`. Never a network sink. */
export function stdoutLineWriter(): LineWriter {
  return (line: string) => {
    process.stdout.write(`${line}\n`);
  };
}

export class EnforcementExportDeliveryError extends Error {
  constructor(message: string) {
    super(`enforcement-export delivery failed: ${message}`);
    this.name = "EnforcementExportDeliveryError";
  }
}

/** Options for {@link HttpCollectorSink}. */
export interface HttpCollectorSinkOptions {
  /** The single PINNED collector URL. Every batch goes here or nowhere. */
  destinationUrl: string;
  /** Injected fetch (mocked in tests; NEVER a real endpoint in a test). */
  fetchImpl?: typeof fetch;
  /** Abort a hung POST after this many ms. Default 10s. */
  timeoutMs?: number;
}

/**
 * Pushes a JSON batch to the pinned Cortex/XSIAM HTTP collector. Fails loud.
 */
export class HttpCollectorSink implements EnforcementExportSink {
  readonly kind: EnforcementExportSinkKind = "http";
  readonly touchesNetwork = true;

  private readonly destinationUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: HttpCollectorSinkOptions) {
    this.destinationUrl = options.destinationUrl;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async deliver(events: readonly EnforcementEvent[]): Promise<DeliveryResult> {
    // Body is metadata only: the mapped events plus a schema tag and a count.
    // No secret, no key, no token is attached anywhere.
    const body = JSON.stringify({
      schema: "sanctuary.enforcement-event.v1",
      count: events.length,
      events,
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(this.destinationUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: controller.signal,
        // The destination is EXACTLY the pinned URL. A redirect would re-route
        // the (metadata) batch to a host the operator never pinned; refuse
        // instead of following (mirrors the distress webhook posture).
        redirect: "error",
      });
    } catch (err) {
      // Unreachable / aborted / DNS failure. FAIL LOUD; never fall back.
      throw new EnforcementExportDeliveryError(
        err instanceof Error ? err.message : "collector unreachable",
      );
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      // A non-2xx is a failed delivery, not a success. FAIL LOUD.
      throw new EnforcementExportDeliveryError(
        `collector returned HTTP ${response.status}`,
      );
    }
    return { delivered: events.length };
  }
}

/** Count events per class (for the emitted-audit summary; metadata only). */
export function summarizeByClass(
  events: readonly EnforcementEvent[],
): Record<EnforcementEventClass, number> {
  const summary: Record<EnforcementEventClass, number> = {
    egress_decision: 0,
    policy_change: 0,
    distress: 0,
  };
  for (const event of events) summary[event.event_class] += 1;
  return summary;
}
