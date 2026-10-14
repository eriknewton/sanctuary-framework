import { randomBytes } from "node:crypto";

import { ABANDONED_PROBE_NONCE_CAP, NONCE_PATTERN, PROBE_NONCE_BYTES } from "./constants.js";
import type { RelayToNodeFrame } from "./envelopes.js";

export type HermesProbeWaiterState = "WAITING";
export type HermesProbeEntryRef = string;
export type HermesProbeNonceSource = () => string;

export type HermesProbeStartRefusal =
  | "stopped"
  | "probe_busy"
  | "abandoned_full"
  | "nonce_unusable";

export type HermesProbeTerminalReason =
  | "timed_out"
  | "connection_gone"
  | "stopped";

export type HermesProbeFatalReason = "unmatched_probe_reply";

export type HermesProbeWaiterAction =
  | { readonly kind: "send_probe"; readonly connectionId: string; readonly nonce: string }
  // A resolved probe means the relay delivered every earlier public event on that connection to Node.
  | { readonly kind: "resolved"; readonly entryRef: HermesProbeEntryRef }
  | { readonly kind: "refused"; readonly entryRef: HermesProbeEntryRef; readonly reason: HermesProbeTerminalReason };

export type HermesProbeWaiterResult = {
  readonly actions: readonly HermesProbeWaiterAction[];
  readonly refusal?: HermesProbeStartRefusal;
  readonly fatal?: HermesProbeFatalReason;
};

export type HermesProbeWaiterSnapshot = {
  readonly stopped: boolean;
  readonly live?: {
    readonly state: HermesProbeWaiterState;
    readonly entryRef: HermesProbeEntryRef;
    readonly connectionId: string;
    readonly nonce: string;
  };
  readonly abandoned: readonly { readonly connectionId: string; readonly nonce: string }[];
};

type LiveProbeWaiter = {
  readonly state: HermesProbeWaiterState;
  readonly entryRef: HermesProbeEntryRef;
  readonly connectionId: string;
  readonly nonce: string;
};

type ProbePair = {
  readonly connectionId: string;
  readonly nonce: string;
};

const EMPTY_RESULT: HermesProbeWaiterResult = Object.freeze({ actions: Object.freeze([]) });
const HEX_CHARACTERS_PER_BYTE = 2;

/**
 * Caller contract for later bridge composition: start only for an open busy row with this entry's
 * record current and in flight, the peer not shutting, and the lifecycle not stopped, because the
 * relay answers a probe for a closed connection at once. A resolved probe means the relay delivered
 * every earlier public event on that connection to Node; that is necessary for commit, never
 * sufficient, so the caller still applies queued control events and re-checks the row and record.
 * Closed and probe replies are fed synchronously in fd-3 order. Every send_probe action is written,
 * and a failed write goes through global stop rather than skipping that probe.
 */
export class HermesProbeWaiter {
  private live: LiveProbeWaiter | undefined;
  private readonly abandoned: ProbePair[] = [];
  private stopped = false;

  constructor(private readonly nonceSource: HermesProbeNonceSource) {
    if (typeof nonceSource !== "function") {
      throw new TypeError("HermesProbeWaiter requires a nonce source");
    }
  }

  start(entryRef: HermesProbeEntryRef, connectionId: string): HermesProbeWaiterResult {
    if (this.stopped) return { actions: [], refusal: "stopped" };

    if (this.live?.entryRef === entryRef) {
      this.abandonLiveWaiter();
    }

    if (this.live !== undefined) return { actions: [], refusal: "probe_busy" };

    // The live waiter counts against the abandoned cap before issue, so moving it to abandoned on
    // timeout, close, abandon, or stop cannot exceed the cap and no pair is ever evicted.
    if (this.abandoned.length + this.liveCount() >= ABANDONED_PROBE_NONCE_CAP) {
      return { actions: [], refusal: "abandoned_full" };
    }

    const nonce = this.drawUsableNonce();
    if (nonce === undefined) return { actions: [], refusal: "nonce_unusable" };

    // Uniqueness is checked only against live and abandoned nonces; pair-only state keeps no history
    // after a reply consumes a nonce, and 128 random bits make reuse of a consumed nonce negligible.
    this.live = Object.freeze({ state: "WAITING", entryRef, connectionId, nonce });
    return { actions: [Object.freeze({ kind: "send_probe", connectionId, nonce })] };
  }

  reply(frame: Extract<RelayToNodeFrame, { readonly kind: "probe_reply" }>): HermesProbeWaiterResult {
    if (this.live !== undefined && this.pairEquals(this.live, frame)) {
      const entryRef = this.live.entryRef;
      this.live = undefined;
      return { actions: [Object.freeze({ kind: "resolved", entryRef })] };
    }

    const abandonedIndex = this.abandoned.findIndex((pair) => this.pairEquals(pair, frame));
    if (abandonedIndex >= 0) {
      this.abandoned.splice(abandonedIndex, 1);
      return EMPTY_RESULT;
    }

    // The relay seam's late-discard wording applies only while the pair is still live or abandoned;
    // after a reply consumes the pair, pair-only state treats another reply as an unmatched frame.
    return { actions: [], fatal: "unmatched_probe_reply" };
  }

  timeout(entryRef: HermesProbeEntryRef, nonce: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.entryRef !== entryRef || this.live.nonce !== nonce) {
      return EMPTY_RESULT;
    }
    const refused = this.refuseWaiter(this.live, "timed_out");
    return { actions: [refused] };
  }

  connectionClosed(connectionId: string): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.connectionId !== connectionId) return EMPTY_RESULT;
    // Relay ids are never reused while a row is live, and the lifecycle slice deletes the row on the
    // single closed event, so a matching live waiter belongs to the current connection row.
    const refused = this.refuseWaiter(this.live, "connection_gone");
    return { actions: [refused] };
  }

  stop(): HermesProbeWaiterResult {
    this.stopped = true;
    if (this.live === undefined) return EMPTY_RESULT;
    const refused = this.refuseWaiter(this.live, "stopped");
    return { actions: [refused] };
  }

  abandon(entryRef: HermesProbeEntryRef): HermesProbeWaiterResult {
    if (this.live === undefined || this.live.entryRef !== entryRef) return EMPTY_RESULT;
    this.abandonLiveWaiter();
    return EMPTY_RESULT;
  }

  snapshot(): HermesProbeWaiterSnapshot {
    return Object.freeze({
      stopped: this.stopped,
      live: this.live === undefined ? undefined : { ...this.live },
      abandoned: this.abandoned.map((pair) => Object.freeze({ ...pair })),
    });
  }

  private drawUsableNonce(): string | undefined {
    let nonce: string;
    try {
      nonce = this.nonceSource();
    } catch {
      return undefined;
    }
    if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) return undefined;
    if (this.live?.nonce === nonce) return undefined;
    if (this.abandoned.some((pair) => pair.nonce === nonce)) return undefined;
    return nonce;
  }

  private refuseWaiter(
    live: LiveProbeWaiter,
    reason: HermesProbeTerminalReason,
  ): Extract<HermesProbeWaiterAction, { readonly kind: "refused" }> {
    this.abandonLiveWaiter();
    return Object.freeze({ kind: "refused", entryRef: live.entryRef, reason });
  }

  private abandonLiveWaiter(): void {
    if (this.live === undefined) return;
    this.abandoned.push(Object.freeze({ connectionId: this.live.connectionId, nonce: this.live.nonce }));
    this.live = undefined;
  }

  private liveCount(): number {
    return this.live === undefined ? 0 : 1;
  }

  private pairEquals(left: ProbePair, right: ProbePair): boolean {
    return left.connectionId === right.connectionId && left.nonce === right.nonce;
  }
}

export function createNodeCryptoHermesProbeNonceSource(): HermesProbeNonceSource {
  // PROBE_NONCE_BYTES is the relay-visible hex length, so the CSPRNG draw is half as many bytes.
  return () => randomBytes(PROBE_NONCE_BYTES / HEX_CHARACTERS_PER_BYTE).toString("hex");
}
