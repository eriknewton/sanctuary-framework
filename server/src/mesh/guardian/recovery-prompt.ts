/**
 * Post-recovery broker-credential rotation prompt builder.
 *
 * Spec §9.6 cascade hygiene + Architecture Walk Key 13: on first operator
 * login after a `master_rotation` event, surface a prompt asking the operator
 * to rotate externally-scoped broker credentials that third parties may still
 * associate with the pre-rotation key material.
 *
 * This module ships the PROMPT BUILDER + per-rotation tracking; the actual
 * broker rotation flow ships in v0.10.x (`Broker.rotateSecret`). The prompt
 * is dismissible, but re-surfaced on every master rotation.
 */

import { parseIsoInstantWithOffset } from "../../core/time.js";

export interface BrokerCredentialPromptItem {
  secret_name: string;
  rotation_cta: "rotate_now" | "skip_for_this_rotation";
}

export interface PostRecoveryPromptState {
  /**
   * Strict ISO-8601 timestamp (mandatory `Z`/numeric offset — TZ-SIB-02) of
   * the master rotation that triggered this prompt; the value the guardian
   * quorum signed over, already validated by the quorum parser (TZ-WINDOW-01).
   */
  rotated_at: string;
  /** Old master pubkey for operator identification. */
  old_master_pubkey: string;
  /** New master pubkey for operator identification. */
  new_master_pubkey: string;
  /** Credentials surfaced for rotation. */
  credentials: BrokerCredentialPromptItem[];
  /** ISO8601 of operator dismissal, if dismissed. */
  dismissed_at?: string;
  /** Per-credential rotation completion status. */
  rotated: Record<string, "pending" | "rotated" | "skipped">;
}

export interface BrokerCredentialLister {
  listSecretNames(): Promise<string[]>;
}

/**
 * Build the post-recovery prompt state from the broker's current secret list.
 *
 * Caller passes a broker handle (or any object satisfying
 * `BrokerCredentialLister`) and the rotation event. Returns a fresh state with
 * every secret marked `pending`.
 */
export async function buildPostRecoveryPrompt(params: {
  broker: BrokerCredentialLister;
  old_master_pubkey: string;
  new_master_pubkey: string;
  rotated_at: string;
}): Promise<PostRecoveryPromptState> {
  const names = await params.broker.listSecretNames();
  const credentials: BrokerCredentialPromptItem[] = names.map((n) => ({
    secret_name: n,
    rotation_cta: "rotate_now",
  }));
  const rotated: Record<string, "pending" | "rotated" | "skipped"> = {};
  for (const n of names) rotated[n] = "pending";
  return {
    rotated_at: params.rotated_at,
    old_master_pubkey: params.old_master_pubkey,
    new_master_pubkey: params.new_master_pubkey,
    credentials,
    rotated,
  };
}

/**
 * Track per-rotation prompt state so we re-surface on every new master
 * rotation and skip on already-handled ones for this rotation event.
 *
 * Indexed by `rotated_at` since each rotation is uniquely timestamped (the
 * value the guardian quorum signed over, not local clock).
 */
export class PostRecoveryPromptStore {
  private byRotation = new Map<string, PostRecoveryPromptState>();

  has(rotated_at: string): boolean {
    return this.byRotation.has(rotated_at);
  }

  get(rotated_at: string): PostRecoveryPromptState | undefined {
    return this.byRotation.get(rotated_at);
  }

  put(state: PostRecoveryPromptState): void {
    this.byRotation.set(state.rotated_at, state);
  }

  /** Mark a single credential rotated for the given rotation event. */
  markRotated(params: {
    rotated_at: string;
    secret_name: string;
    outcome: "rotated" | "skipped";
  }): void {
    const state = this.byRotation.get(params.rotated_at);
    if (!state) return;
    state.rotated[params.secret_name] = params.outcome;
  }

  /** Dismiss the prompt — operator chose to defer. */
  dismiss(rotated_at: string, at?: string): void {
    const state = this.byRotation.get(rotated_at);
    if (!state) return;
    state.dismissed_at = at ?? new Date().toISOString();
  }

  /** Most-recent rotation prompt, undefined if never rotated. */
  latest(): PostRecoveryPromptState | undefined {
    // TZ-SIB-02: the ordering reads each stamp through the strict
    // offset-requiring predicate so "most recent" names the same rotation on
    // every node; a stamp the predicate refuses sorts EARLIEST
    // (NEGATIVE_INFINITY), so an ambiguous stamp can never win "latest". In
    // practice every `rotated_at` here already passed the guardian quorum
    // parser's strict check (TZ-WINDOW-01) before a prompt was built.
    let latest: PostRecoveryPromptState | undefined;
    for (const state of this.byRotation.values()) {
      if (
        !latest ||
        (parseIsoInstantWithOffset(state.rotated_at) ??
          Number.NEGATIVE_INFINITY) >
          (parseIsoInstantWithOffset(latest.rotated_at) ??
            Number.NEGATIVE_INFINITY)
      ) {
        latest = state;
      }
    }
    return latest;
  }

  size(): number {
    return this.byRotation.size;
  }
}
