/**
 * Per-uid pf loopback anchor: generation, arm/disarm, and the MANDATORY
 * fail-closed runtime liveness check (Unified Protect Slice 3).
 *
 * The NEFilter content filter is proven BLIND to loopback traffic
 * (2026-06-30 drill), so the wall alone cannot pin the agent to the gate
 * port on loopback. This anchor closes that hole at the packet layer: it
 * drops ALL agent-uid loopback traffic except TCP to the gate port. The
 * exact per-uid pass/block shape was PROVEN on Tahoe (macOS 26.5.1) on
 * 2026-07-02, N=3, coordinator-verified (drill-evidence-2026-07-01/
 * unified-protect-keystone/RESULTS.md). Drill acceptance for THIS composed
 * build is PENDING, and the non-Tahoe macOS leg is still owed.
 *
 * The anchor text is generated from the SAME `ExclusiveEgressGatePolicy`
 * that derives the NEFilter manifest allow rule (single source, Slice 8);
 * `parity.ts` asserts the two artifacts agree.
 *
 * FAIL-CLOSED LIVENESS (the drill's one residual fail-open): a silently
 * unloaded anchor would reopen the loopback-relay hole while the posture
 * still reads "protected". `checkPfAnchorLiveness` therefore decides by
 * POSITIVE EVIDENCE ONLY: pf reports Status: Enabled AND the anchor prints
 * the expected pass + block rules. Any pfctl error, timeout, missing rule,
 * or unparseable output is NOT live. The gate server refuses to proxy when
 * this check fails, and posture surfaces MUST report not-protected.
 *
 * All privileged commands run through an injected {@link PfCommandRunner}
 * so the logic is unit-testable without root or a real pf.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createExecFileRunner } from "./exec-runner.js";

import {
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "../castle-wall/allowlist/gate-derivation.js";

/** The pf anchor name Sanctuary owns for the exclusive-egress confinement. */
export const PF_ANCHOR_NAME = "sanctuary.egress-gate";

/** Result of one command the runner executed. */
export interface PfCommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Abstraction over privileged command execution (pfctl). The production
 * runner shells out with a hard timeout; tests inject a mock. The runner
 * must REJECT (throw) only on spawn-level failure; a non-zero exit resolves
 * with its code so callers can decide.
 */
export interface PfCommandRunner {
  run(command: string, args: readonly string[]): Promise<PfCommandResult>;
}

/** Default hard timeout for a pfctl invocation. */
export const PF_COMMAND_TIMEOUT_MS = 10_000;

/**
 * Production runner: execFile with a hard timeout, never a shell (no
 * interpolation surface). Timeout or spawn failure resolves as a non-zero
 * synthetic result so every caller stays on the fail-closed path instead of
 * having to catch. Shared implementation: `exec-runner.ts`.
 */
export function createExecFilePfRunner(timeoutMs: number = PF_COMMAND_TIMEOUT_MS): PfCommandRunner {
  return createExecFileRunner(timeoutMs);
}

/**
 * Render the pf anchor rule text from the gate policy (single source with
 * the manifest rule, Slice 8).
 *
 * Shape (first-match-wins via `quick`):
 *   1. pass agent-uid TCP to 127.0.0.1:<gate-port> (the drill-proven pass)
 *   2. block drop EVERYTHING else on lo0 for the agent uid (tcp+udp, v4+v6)
 *
 * The pass rule uses the exact printed form the Tahoe keystone drill
 * captured from `pfctl -a <anchor> -sr`, so the liveness check can compare
 * against pfctl's canonical output. Throws on a malformed policy
 * (fail-closed at render time; never emit a permissive-by-accident anchor).
 */
export function renderPfAnchorRules(policy: ExclusiveEgressGatePolicy): string {
  if (validateExclusiveEgressGatePolicy(policy) === null) {
    throw new Error(
      "renderPfAnchorRules: refusing to render a pf anchor from a malformed exclusive-egress gate policy",
    );
  }
  const uid = policy.agent_uid;
  const port = policy.gate_port;
  return [
    `pass quick on lo0 inet proto tcp from any to 127.0.0.1 port = ${port} user = ${uid} flags S/SA keep state`,
    `block drop quick on lo0 inet proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet proto udp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto udp from any to any user = ${uid}`,
    "",
  ].join("\n");
}

/** Liveness verdict with the positive/negative evidence that produced it. */
export interface PfLivenessResult {
  /** True ONLY when every positive-evidence check passed. */
  live: boolean;
  /** Human-readable reasons when not live (empty when live). */
  reasons: string[];
}

/**
 * Check, by positive evidence, that the per-uid anchor is loaded AND pf is
 * enabled. Fail-closed: any error, non-zero exit, or missing expected rule
 * yields `live: false`.
 *
 * pfctl prints rules in its own canonical form; the pass rule matches the
 * drill-captured printed form exactly, and the block rules accept both the
 * `from any to any` and pfctl's collapsed `all` spellings.
 */
export async function checkPfAnchorLiveness(
  runner: PfCommandRunner,
  policy: ExclusiveEgressGatePolicy,
  anchorName: string = PF_ANCHOR_NAME,
): Promise<PfLivenessResult> {
  if (validateExclusiveEgressGatePolicy(policy) === null) {
    return { live: false, reasons: ["malformed exclusive-egress gate policy"] };
  }
  const reasons: string[] = [];

  let info: PfCommandResult;
  try {
    info = await runner.run("pfctl", ["-s", "info"]);
  } catch (err) {
    return {
      live: false,
      reasons: [`pfctl -s info failed to run: ${err instanceof Error ? err.message : String(err)}`],
    };
  }
  if (info.code !== 0) {
    reasons.push(`pfctl -s info exited ${info.code}`);
  } else if (!/^Status:\s+Enabled\b/m.test(info.stdout)) {
    reasons.push("pf is not enabled (pfctl -s info lacks 'Status: Enabled')");
  }

  let rules: PfCommandResult;
  try {
    rules = await runner.run("pfctl", ["-a", anchorName, "-sr"]);
  } catch (err) {
    reasons.push(
      `pfctl -a ${anchorName} -sr failed to run: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { live: false, reasons };
  }
  if (rules.code !== 0) {
    reasons.push(`pfctl -a ${anchorName} -sr exited ${rules.code}`);
    return { live: false, reasons };
  }

  const uid = policy.agent_uid;
  const port = policy.gate_port;
  const passRe = new RegExp(
    `^pass quick on lo0 inet proto tcp from any to 127\\.0\\.0\\.1 port = ${port} user = ${uid} flags S/SA keep state$`,
    "m",
  );
  if (!passRe.test(rules.stdout)) {
    reasons.push(`anchor ${anchorName} is missing the agent-to-gate pass rule (port ${port}, uid ${uid})`);
  }
  const blockShapes: Array<[string, RegExp]> = [
    ["inet tcp", blockRuleRe("inet", "tcp", uid)],
    ["inet udp", blockRuleRe("inet", "udp", uid)],
    ["inet6 tcp", blockRuleRe("inet6", "tcp", uid)],
    ["inet6 udp", blockRuleRe("inet6", "udp", uid)],
  ];
  for (const [label, re] of blockShapes) {
    if (!re.test(rules.stdout)) {
      reasons.push(`anchor ${anchorName} is missing the ${label} block-drop rule for uid ${uid}`);
    }
  }

  return { live: reasons.length === 0, reasons };
}

function blockRuleRe(family: "inet" | "inet6", proto: "tcp" | "udp", uid: number): RegExp {
  return new RegExp(
    `^block drop quick on lo0 ${family} proto ${proto} (?:all|from any to any) user = ${uid}$`,
    "m",
  );
}

/** Options for {@link armPfAnchor}. */
export interface ArmPfAnchorOptions {
  anchorName?: string;
  /**
   * Post-arm settle-probe tuning. The first-arm warmup race observed in the
   * design review let the first post-arm flow slip before rules were
   * effective, so arm is not "done" until the liveness check passes
   * `settleConsecutive` times in a row, `settleDelayMs` apart.
   */
  settleConsecutive?: number;
  settleDelayMs?: number;
  settleTimeoutMs?: number;
  /** Injected for tests. */
  sleep?: (ms: number) => Promise<void>;
}

/** Result of a successful arm. */
export interface ArmPfAnchorResult {
  /** Reference token from `pfctl -E`, needed for symmetric release (`-X`). */
  enableToken?: string;
  /** How many liveness probes ran during the settle phase. */
  settleProbes: number;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Arm the anchor: load the rendered rules into the Sanctuary anchor, enable
 * pf with reference counting (`pfctl -E`, token captured for symmetric
 * disarm), then run the post-arm settle-probe. If the settle-probe does not
 * confirm liveness in time, the anchor is DISARMED again and the call
 * throws: never report armed without positive evidence.
 *
 * Requires root (production callers run inside the privileged install/arm
 * ceremony). Drill acceptance for the composed arm path is PENDING.
 */
export async function armPfAnchor(
  runner: PfCommandRunner,
  policy: ExclusiveEgressGatePolicy,
  options: ArmPfAnchorOptions = {},
): Promise<ArmPfAnchorResult> {
  const anchorName = options.anchorName ?? PF_ANCHOR_NAME;
  const rulesText = renderPfAnchorRules(policy); // throws on malformed policy
  const sleep = options.sleep ?? defaultSleep;
  const settleConsecutive = options.settleConsecutive ?? 2;
  const settleDelayMs = options.settleDelayMs ?? 200;
  const settleTimeoutMs = options.settleTimeoutMs ?? 5_000;

  // CodeQL-clean temp handling: a fresh mkdtemp dir, file removed after load.
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-pf-"));
  const rulesFile = join(dir, "egress-gate.rules");
  let enableToken: string | undefined;
  try {
    await writeFile(rulesFile, rulesText, { mode: 0o600 });

    const load = await runner.run("pfctl", ["-a", anchorName, "-f", rulesFile]);
    if (load.code !== 0) {
      throw new Error(`pfctl -a ${anchorName} -f exited ${load.code}: ${load.stderr.trim()}`);
    }

    const enable = await runner.run("pfctl", ["-E"]);
    if (enable.code !== 0) {
      throw new Error(`pfctl -E exited ${enable.code}: ${enable.stderr.trim()}`);
    }
    const tokenMatch = /Token\s*:\s*(\d+)/.exec(`${enable.stdout}\n${enable.stderr}`);
    if (tokenMatch) {
      enableToken = tokenMatch[1];
    }

    // Settle-probe: require N consecutive live results before declaring armed.
    const deadline = Date.now() + settleTimeoutMs;
    let consecutive = 0;
    let probes = 0;
    let lastReasons: string[] = [];
    while (consecutive < settleConsecutive) {
      if (Date.now() > deadline) {
        throw new Error(
          `pf anchor settle-probe timed out after ${settleTimeoutMs}ms ` +
            `(last liveness failure: ${lastReasons.join("; ") || "none recorded"})`,
        );
      }
      const result = await checkPfAnchorLiveness(runner, policy, anchorName);
      probes += 1;
      if (result.live) {
        consecutive += 1;
      } else {
        consecutive = 0;
        lastReasons = result.reasons;
      }
      if (consecutive < settleConsecutive) {
        await sleep(settleDelayMs);
      }
    }
    const armResult: ArmPfAnchorResult = { settleProbes: probes };
    if (enableToken !== undefined) {
      armResult.enableToken = enableToken;
    }
    return armResult;
  } catch (err) {
    // Symmetric rollback: a half-armed anchor must not linger.
    await disarmPfAnchor(runner, { anchorName, ...(enableToken !== undefined ? { enableToken } : {}) }).catch(
      () => undefined,
    );
    throw err;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Options for {@link disarmPfAnchor}. */
export interface DisarmPfAnchorOptions {
  anchorName?: string;
  /** The `pfctl -E` token captured at arm time, released via `pfctl -X`. */
  enableToken?: string;
}

/**
 * Disarm symmetry: flush every rule out of the Sanctuary anchor, then
 * release the pf enable reference taken at arm time (when a token was
 * captured). Throws on failure: a disarm that silently did nothing would
 * leave state the operator believes is gone.
 */
export async function disarmPfAnchor(
  runner: PfCommandRunner,
  options: DisarmPfAnchorOptions = {},
): Promise<void> {
  const anchorName = options.anchorName ?? PF_ANCHOR_NAME;
  const flush = await runner.run("pfctl", ["-a", anchorName, "-F", "all"]);
  if (flush.code !== 0) {
    throw new Error(`pfctl -a ${anchorName} -F all exited ${flush.code}: ${flush.stderr.trim()}`);
  }
  if (options.enableToken !== undefined) {
    if (!/^\d+$/.test(options.enableToken)) {
      throw new Error("disarmPfAnchor: enableToken must be a numeric pfctl reference token");
    }
    const release = await runner.run("pfctl", ["-X", options.enableToken]);
    if (release.code !== 0) {
      throw new Error(`pfctl -X exited ${release.code}: ${release.stderr.trim()}`);
    }
  }
}
