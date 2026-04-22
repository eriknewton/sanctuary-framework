/**
 * FailureModeDetector ↔ Sovereignty Dashboard SSE bridge.
 *
 * Spawn-prompt acceptance criterion 7: "Mesh Health dashboard panel renders
 * via existing SSE /events channel — no new transport. Every state transition
 * produces an observable SSE event."
 *
 * This bridge satisfies that criterion structurally: it subscribes to the
 * detector's `on_alert` and `on_health_snapshot` callbacks and forwards each
 * to the existing dashboard's `broadcastSSE` channel. It does NOT add a
 * second transport, does not open a new HTTP route, and does not require any
 * non-default port.
 *
 * The structural-typing interface (`MeshHealthBroadcastTarget`) means the
 * bridge can be unit-tested against a fake target without booting the full
 * dashboard.
 */

import type { FailureModeDetector } from "./detector.js";
import type {
  FailureModeAlert,
  MeshHealthSnapshot,
} from "./types.js";
import type { PostRecoveryPromptState } from "../guardian/recovery-prompt.js";

/**
 * Subset of the dashboard surface the bridge needs. The shipping
 * `SovereigntyDashboard` class satisfies this implicitly via its
 * `broadcastMeshHealth` / `broadcastMeshFailureModeAlert` /
 * `broadcastMeshPostRecoveryPrompt` methods.
 */
export interface MeshHealthBroadcastTarget {
  broadcastMeshHealth(snapshot: Record<string, unknown>): void;
  broadcastMeshFailureModeAlert(alert: Record<string, unknown>): void;
  broadcastMeshPostRecoveryPrompt(prompt: Record<string, unknown>): void;
}

export class FailureModeDashboardBridge {
  private readonly target: MeshHealthBroadcastTarget;
  private readonly detector: FailureModeDetector;

  constructor(params: {
    detector: FailureModeDetector;
    target: MeshHealthBroadcastTarget;
  }) {
    this.target = params.target;
    this.detector = params.detector;
    this.attach();
  }

  private attach(): void {
    // We can't *replace* on_alert / on_health_snapshot if the detector's
    // owner has already wired them; instead we wrap by composition.
    const original = (this.detector as unknown as {
      opts: {
        on_alert: (a: FailureModeAlert) => void;
        on_health_snapshot: (s: MeshHealthSnapshot) => void;
      };
    }).opts;
    const prevAlert = original.on_alert;
    const prevHealth = original.on_health_snapshot;
    original.on_alert = (alert: FailureModeAlert) => {
      try {
        prevAlert(alert);
      } finally {
        this.target.broadcastMeshFailureModeAlert(
          alert as unknown as Record<string, unknown>
        );
      }
    };
    original.on_health_snapshot = (snap: MeshHealthSnapshot) => {
      try {
        prevHealth(snap);
      } finally {
        this.target.broadcastMeshHealth(
          snap as unknown as Record<string, unknown>
        );
      }
    };
  }

  /**
   * Push a post-recovery rotation prompt to the dashboard. Called by the
   * cascade orchestrator after `installMasterRotation` succeeds and the
   * `buildPostRecoveryPrompt` returns a state.
   */
  pushPostRecoveryPrompt(prompt: PostRecoveryPromptState): void {
    this.target.broadcastMeshPostRecoveryPrompt(
      prompt as unknown as Record<string, unknown>
    );
  }
}
