/**
 * Mesh Health alert inbox — AC6.
 *
 * Tests the console's alert-inbox surface: inbound alerts populate the
 * inbox, each row carries a decision_options list matching the §8 failure
 * mode, acknowledgment transitions state from open to resolved, and the
 * acknowledgment broadcasts through the SSE event bus.
 *
 * No Concordia or Verascore imports. No new federation protocol wire
 * surface (spawn prompt escalation rule).
 */

import { afterEach, describe, expect, it } from "vitest";

import { bootThreeModeDrill, type ThreeModeDrillHandle } from "../acceptance/three-mode-drill/harness.js";
import {
  MeshConsoleClient,
  type ConsoleSSEEvent,
} from "../../src/console/index.js";
import type { FailureModeAlert } from "../../src/mesh/failure-modes/types.js";
import type { FailureMode } from "../../src/mesh/failure-modes/constants.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

function synthesizeAlert(mode: FailureMode, nodeId: string): FailureModeAlert {
  return {
    alert_id: `alert-${mode}-${Math.random().toString(36).slice(2, 8)}`,
    mode,
    target_node: nodeId,
    detected_at: Date.now(),
    message: `Synthetic ${mode} alert for test`,
    detail: {},
    resolution: { state: "open" },
  };
}

function consoleForNodeA(drill: ThreeModeDrillHandle): MeshConsoleClient {
  return new MeshConsoleClient({
    node: drill.nodeA,
    pinnedMaster: drill.master_public,
    rootPrincipalCert: drill.root_principal_cert,
    rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
    nodePrivateKey: drill.nodeKpA.privateKey,
  });
}

/**
 * Force-wire an alert into the client's internal store via the same path
 * the detector bridge uses. Calls into the private handler via a typed
 * surface — we don't export the internal, but the test file lives in the
 * same package and can use the public `acknowledgeAlert` as the verifier.
 */
function forceAlert(client: MeshConsoleClient, alert: FailureModeAlert): void {
  // Use the internal openAlerts map by invoking the private field through the
  // documented private-surface the detector uses — in tests we use the
  // `recordAttestationResult`-adjacent path: acknowledgeAlert throws if the
  // alert isn't present, so we must first seed it via the detector-style
  // surface. The detector's on_alert fires through the bridge set up in
  // wireFailureDetector. For this test we set up a synthetic detector-like
  // object that triggers the same code path.
  const fakeDetector = {
    opts: {
      on_alert: () => {},
      on_health_snapshot: () => {},
    },
  };
  // Install the bridge.
  (client as unknown as {
    wireFailureDetector: (d: unknown) => void;
  }).wireFailureDetector(fakeDetector);
  // Fire the alert through the installed hook.
  fakeDetector.opts.on_alert(alert);
}

describe("WP-MVP-2 console — Mesh Health alert inbox (AC6)", () => {
  it(
    "every FailureMode row surfaces plain-English decision options",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);

      const modes: FailureMode[] = [
        "offline",
        "compromised",
        "rollback",
        "split_brain",
        "canonical_audit_loss",
      ];

      for (const mode of modes) {
        const alert = synthesizeAlert(mode, active.nodeIdB);
        forceAlert(client, alert);
      }

      const inbox = client.alertInbox();
      expect(inbox.rows).toHaveLength(modes.length);
      for (const row of inbox.rows) {
        expect(row.decision_options.length).toBeGreaterThan(0);
        for (const opt of row.decision_options) {
          expect(opt.id).toBeTruthy();
          expect(opt.label).toBeTruthy();
        }
      }
    },
    40_000
  );

  it(
    "acknowledgeAlert transitions open → resolved and broadcasts via SSE",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);

      const sseEvents: ConsoleSSEEvent[] = [];
      client.onEvent((evt) => sseEvents.push(evt));

      const alert = synthesizeAlert("offline", active.nodeIdB);
      forceAlert(client, alert);

      const beforeAck = client.alertInbox().rows.find((r) => r.alert_id === alert.alert_id);
      expect(beforeAck?.state).toBe("open");

      const acked = client.acknowledgeAlert({
        alert_id: alert.alert_id,
        decision: "wait_for_reconnect",
        note: "operator test note",
      });
      expect(acked.state).toBe("resolved");

      // At least two alert events must have fired — the initial detection
      // broadcast and the acknowledgment broadcast.
      const alertBroadcasts = sseEvents.filter((e) => e.kind === "alert");
      expect(alertBroadcasts.length).toBeGreaterThanOrEqual(2);
    },
    40_000
  );

  it(
    "acknowledgeAlert throws on unknown alert_id (no silent drop)",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);
      expect(() =>
        client.acknowledgeAlert({
          alert_id: "does-not-exist",
          decision: "acknowledge",
        })
      ).toThrow(/no open alert/);
    },
    40_000
  );
});
