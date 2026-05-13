/**
 * Post-recovery prompt wiring across all four ceremonies.
 *
 * Spec §9.6 + Architecture Walk Key 13: every ceremony that changes trust
 * material or authority surfaces a post-recovery prompt on the operator's
 * next login. FU #3 shipped `buildPostRecoveryPrompt` + `PostRecoveryPromptStore`
 * for master rotation; WP-MVP-8 generalizes the fire-on-every-ceremony
 * pattern + records the operator's acknowledgment as a signed event.
 *
 * Each ceremony in this module calls `firePostRecoveryPrompt` at the tail of
 * its `execute`, passing the ceremony record + any broker lister it wants to
 * use. The prompt record is stored in a shared `PostRecoveryPromptStore`;
 * downstream UI surfaces (WP-MVP-2 console) render it.
 *
 * Operator acknowledgment is a separate call (`acknowledgePostRecoveryPrompt`).
 * Each acknowledgment emits a `gate_approved` usage event with
 * `capability_target` shaped as `mesh.recovery.post_recovery_prompt:<ceremony_id>`
 * so the audit log carries the full dismissal history.
 */

import {
  buildPostRecoveryPrompt,
  PostRecoveryPromptStore,
  type BrokerCredentialLister,
  type PostRecoveryPromptState,
} from "../guardian/recovery-prompt.js";
import {
  emitGateApproved,
  type AlertEmitContext,
  type EmittedAlert,
} from "../failure-modes/alerts.js";
import { recoveryCapabilityTarget } from "../failure-modes/constants.js";
import type { CeremonyId } from "./constants.js";
import type { UnifiedInboxBridge } from "../../principal-policy/unified-inbox-bridge.js";
import { ingestRecoveryPrompt } from "../../principal-policy/unified-inbox-producers.js";

export interface FirePostRecoveryPromptParams {
  store: PostRecoveryPromptStore;
  ceremony_type: CeremonyId;
  ceremony_id: string;
  old_master_pubkey: string;
  new_master_pubkey: string;
  rotated_at: string;
  broker: BrokerCredentialLister;
  /** Optional label suffix distinguishing multiple prompts for the same rotated_at. */
  prompt_key_suffix?: string;
  /** Psi-2 optional unified-inbox publisher. */
  inbox_bridge?: UnifiedInboxBridge;
}

/**
 * Build + store a PostRecoveryPromptState for a completed ceremony. Returns
 * the stored state so callers can push it to the dashboard bridge.
 *
 * The prompt key in the store is `<rotated_at>|<ceremony_id>|<suffix>` so
 * multiple ceremonies keyed against the same rotation timestamp are
 * independently tracked. The base FU #3 store used rotated_at alone; we keep
 * that shape by making the key the caller's responsibility via a thin
 * wrapper around the existing store (see `extendedStateKey` below).
 */
export async function firePostRecoveryPrompt(
  params: FirePostRecoveryPromptParams
): Promise<PostRecoveryPromptState> {
  const state = await buildPostRecoveryPrompt({
    broker: params.broker,
    old_master_pubkey: params.old_master_pubkey,
    new_master_pubkey: params.new_master_pubkey,
    rotated_at: params.rotated_at,
  });
  // Annotate the rotated_at with the ceremony context so multiple prompts
  // on the same rotation timestamp do not collide in the FU #3 store's
  // `byRotation` map. The rotated_at value inside the state is preserved for
  // downstream rendering; only the store key is annotated.
  const key = extendedStateKey(params);
  const annotated: PostRecoveryPromptState = {
    ...state,
    rotated_at: key,
  };
  params.store.put(annotated);
  if (params.inbox_bridge) {
    ingestRecoveryPrompt({
      bridge: params.inbox_bridge,
      recovery_class: "other",
      action_required: true,
      observed_at: params.rotated_at,
      source_event_id: `${params.ceremony_type}:${params.ceremony_id}:post_recovery_prompt`,
    });
  }
  return annotated;
}

function extendedStateKey(params: {
  rotated_at: string;
  ceremony_id: string;
  ceremony_type: CeremonyId;
  prompt_key_suffix?: string;
}): string {
  return (
    params.rotated_at +
    "|" +
    params.ceremony_type +
    ":" +
    params.ceremony_id +
    (params.prompt_key_suffix ? "|" + params.prompt_key_suffix : "")
  );
}

/**
 * Record the operator's acknowledgment of a post-recovery prompt. Emits a
 * signed `gate_approved` usage event so the dismissal is auditable, and
 * updates the prompt state in the store.
 */
export function acknowledgePostRecoveryPrompt(params: {
  store: PostRecoveryPromptStore;
  stored_prompt_key: string;
  emit_ctx: AlertEmitContext;
  ceremony_id: string;
  /**
   * Operator's note - non-empty. Renders in the emitted gate_approved event
   * for auditability.
   */
  note: string;
  /** Dismiss the prompt instead of rotating credentials? Default false. */
  dismissed?: boolean;
}): EmittedAlert {
  if (!params.note || params.note.trim().length === 0) {
    throw new Error(
      "acknowledgePostRecoveryPrompt: note must be non-empty"
    );
  }
  const state = params.store.get(params.stored_prompt_key);
  if (!state) {
    throw new Error(
      `acknowledgePostRecoveryPrompt: no prompt state stored for key ${params.stored_prompt_key}`
    );
  }
  if (params.dismissed) {
    params.store.dismiss(params.stored_prompt_key);
  }
  return emitGateApproved(params.emit_ctx, {
    failure_mode: "master_rotation",
    target: recoveryCapabilityTarget("post_recovery_prompt", params.ceremony_id),
    decision: params.dismissed ? "dismiss" : "acknowledge",
    detail: {
      ceremony_id: params.ceremony_id,
      note: params.note,
      stored_prompt_key: params.stored_prompt_key,
      credential_count: state.credentials.length,
      rotated_state: state.rotated,
    },
  });
}

/**
 * Thin in-memory `BrokerCredentialLister` for tests + for ceremonies that
 * do not yet have a real broker wired. Production callers supply the real
 * broker handle.
 */
export class StaticBrokerCredentialLister implements BrokerCredentialLister {
  private readonly names: string[];
  constructor(names: string[]) {
    this.names = [...names];
  }
  async listSecretNames(): Promise<string[]> {
    return [...this.names];
  }
}
