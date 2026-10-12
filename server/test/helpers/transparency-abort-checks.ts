import { channel } from "node:diagnostics_channel";

import type { TransparencySchedulerAbortState } from "../../src/transparency/scheduler.js";

export interface TransparencyAbortStateCheck {
  state: TransparencySchedulerAbortState;
  phase: string;
}

// Must match TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL in
// ../../src/transparency/scheduler.ts; this is an observation-only test hook,
// not the enforcement path.
const TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL =
  "sanctuary.transparency.abort-state-check";

export function recordTransparencyAbortStateChecks(): {
  calls: TransparencyAbortStateCheck[];
  stop(): void;
} {
  const calls: TransparencyAbortStateCheck[] = [];
  const checks = channel(TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL);
  const onCheck = (message: unknown): void => {
    if (
      typeof message === "object" &&
      message !== null &&
      "state" in message &&
      "phase" in message &&
      typeof message.phase === "string"
    ) {
      calls.push(message as TransparencyAbortStateCheck);
    }
  };
  checks.subscribe(onCheck);
  return {
    calls,
    stop() {
      checks.unsubscribe(onCheck);
    },
  };
}
