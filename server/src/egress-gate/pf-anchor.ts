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
 * THE MAIN-RULESET HOOK IS PART OF ARMING. In pf, rules loaded into a named
 * anchor (`pfctl -a <name> -f <file>`) are INERT until the MAIN ruleset
 * contains an `anchor "<name>" on lo0` call rule that transfers packet
 * evaluation into the sub-anchor; the proven drill established confinement
 * with exactly that hook (a main.conf carrying the anchor call + load
 * anchor lines, preserving the stock com.apple anchors). `armPfAnchor`
 * therefore installs the hook when it is absent: it reloads the operator's
 * base pf config (`/etc/pf.conf` by default) PLUS the Sanctuary anchor call
 * as the running main ruleset. A loaded-but-unhooked anchor enforces
 * NOTHING and must never be reported as protection.
 *
 * FAIL-CLOSED LIVENESS (the drill's one residual fail-open): a silently
 * unloaded anchor would reopen the loopback-relay hole while the posture
 * still reads "protected". `checkPfAnchorLiveness` therefore decides by
 * POSITIVE EVIDENCE ONLY: pf reports Status: Enabled AND the anchor prints
 * the expected pass + block rules AND the MAIN ruleset prints the anchor
 * call rule (a loaded-but-unhooked anchor passes the first two probes while
 * enforcing nothing) AND nothing voids the call rule's evaluation: pf must
 * NOT be set to skip filtering on loopback (`set skip on lo0`/`lo`, a very
 * common operator pf.conf idiom, leaves all three earlier probes green
 * while pf never evaluates a single lo0 packet -- hooked-but-SKIPPED), and
 * no `pass ... quick` rule earlier in the main ruleset may match lo0
 * traffic (quick terminates evaluation before the anchor call is reached
 * -- hooked-but-PREEMPTED). Any pfctl error, timeout, missing rule, or
 * unparseable output is NOT live. The gate server refuses to proxy when
 * this check fails, and posture surfaces MUST report not-protected.
 *
 * All privileged commands run through an injected {@link PfCommandRunner}
 * so the logic is unit-testable without root or a real pf.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createExecFileRunner } from "./exec-runner.js";

import {
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "../castle-wall/allowlist/gate-derivation.js";

/** The pf anchor name Sanctuary owns for the exclusive-egress confinement. */
export const PF_ANCHOR_NAME = "sanctuary.egress-gate";

/**
 * The operator's base pf config. When arming must install the main-ruleset
 * hook, the running main ruleset is replaced with THIS file's contents plus
 * the Sanctuary anchor call, so the stock com.apple anchors (and any
 * operator customizations persisted here) are preserved, never clobbered.
 */
export const PF_BASE_CONF_PATH = "/etc/pf.conf";

/**
 * Anchor names we render into pf config text must stay in a conservative
 * charset: a quote or newline in the name would escape the quoted token in
 * the generated main.conf (config-injection surface, however unlikely the
 * caller). Fail closed on anything else.
 */
const SAFE_ANCHOR_NAME_RE = /^[A-Za-z0-9._-]+$/;

function assertSafeAnchorName(anchorName: string): void {
  if (!SAFE_ANCHOR_NAME_RE.test(anchorName)) {
    throw new Error(
      `pf-anchor: refusing anchor name ${JSON.stringify(anchorName)} (allowed charset: A-Za-z0-9._-)`,
    );
  }
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Render the two main-ruleset lines that make the sub-anchor ENFORCED: the
 * anchor call rule (transfers lo0 packet evaluation into the sub-anchor)
 * and the `load anchor` line (loads the sub-anchor's rules in the same
 * transaction). This is the exact hook shape the Tahoe keystone drill
 * proved; without the call rule the loaded rules are dormant.
 */
export function renderPfMainRulesetHook(anchorName: string, rulesFilePath: string): string {
  assertSafeAnchorName(anchorName);
  if (rulesFilePath.includes('"') || rulesFilePath.includes("\n")) {
    throw new Error("pf-anchor: refusing a rules-file path containing a quote or newline");
  }
  return [
    `anchor "${anchorName}" on lo0`,
    `load anchor "${anchorName}" from "${rulesFilePath}"`,
    "",
  ].join("\n");
}

/**
 * The printed form of the main-ruleset anchor call rule. pfctl canonically
 * appends `all` to a parameterless call rule; accept both spellings.
 */
function anchorCallRuleRe(anchorName: string): RegExp {
  return new RegExp(`^anchor "${escapeRegExp(anchorName)}" on lo0( all)?$`, "m");
}

/**
 * A skipped loopback interface in `pfctl -v -s Interfaces` output: pf
 * prints ` (skip)` after an interface (or interface-group) name whose
 * PFI_IFLAG_SKIP flag is set by `set skip on ...`. Both the `lo0`
 * interface and the `lo` group line are checked; skip on either means pf
 * never evaluates lo0 packets, voiding the anchor entirely.
 */
const LOOPBACK_SKIP_LINE_RE = /^lo0?\s*\(skip\)/m;

/**
 * Scan the printed MAIN ruleset for `pass ... quick` rules that appear
 * BEFORE the anchor call rule and could match lo0 traffic. pf evaluation
 * is last-match-wins EXCEPT `quick`, which terminates evaluation at that
 * rule: a matching earlier `pass quick` means the packet never reaches the
 * anchor call, so the anchor enforces nothing for that flow even though it
 * is loaded AND hooked (hooked-but-preempted). Deliberately conservative
 * (positive evidence only): any earlier quick pass rule not positively
 * bound to a non-loopback interface is treated as preempting; the rule's
 * own uid/port/af narrowing is NOT modeled.
 */
export function findPreemptingQuickPassRules(
  mainRulesetText: string,
  anchorName: string = PF_ANCHOR_NAME,
): string[] {
  const callRe = anchorCallRuleRe(anchorName);
  const preempting: string[] = [];
  for (const rawLine of mainRulesetText.split("\n")) {
    const line = rawLine.trim();
    if (callRe.test(line)) break;
    if (!/^pass\b/.test(line) || !/\bquick\b/.test(line)) continue;
    const onClause = /\bon\s+(!\s*)?([\w.:-]+)/.exec(line);
    if (onClause) {
      const negated = onClause[1] !== undefined;
      const iface = onClause[2] ?? "";
      const isLoopback = iface === "lo0" || iface === "lo";
      if (!negated && !isLoopback) continue; // positively bound off-loopback
      if (negated && isLoopback) continue; // explicitly excludes loopback
    }
    preempting.push(line);
  }
  return preempting;
}

/**
 * Detect `set skip on ...` lines in pf config TEXT that cover the loopback
 * interface (`lo0`) or its interface group (`lo`). Used by the arm path to
 * refuse hooking through a base config that would make pf skip all lo0
 * filtering (silently voiding the anchor it just hooked). Macro-valued
 * skip lists (`set skip on $ifs`) are not resolved here; the RUNTIME
 * probe in {@link checkPfAnchorLiveness} (`pfctl -v -s Interfaces`) is the
 * authoritative catch for those and for skip flags set outside this file.
 */
export function findLoopbackSkipLines(pfConfText: string): string[] {
  const hits: string[] = [];
  for (const rawLine of pfConfText.split("\n")) {
    const line = rawLine.replace(/#.*$/, "").trim();
    const m = /^set\s+skip\s+on\s+(.+)$/.exec(line);
    if (m === null) continue;
    const tokens = (m[1] ?? "").split(/[{},\s]+/).filter((t) => t.length > 0);
    if (tokens.some((t) => t === "lo0" || t === "lo")) {
      hits.push(rawLine.trim());
    }
  }
  return hits;
}

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
 * enabled AND the MAIN ruleset actually calls the anchor AND pf actually
 * evaluates lo0 packets through that call. Fail-closed: any error,
 * non-zero exit, or missing expected rule yields `live: false`.
 *
 * The third probe (`pfctl -sr`, the main ruleset) exists because the first
 * two are blind to the loaded-but-unhooked state: `pfctl -a <name> -sr`
 * prints a named anchor's rules whether or not any call rule transfers
 * evaluation into it, and `pfctl -s info` reports Enabled regardless. An
 * anchor in that state enforces NOTHING; reporting it live would be the
 * green-when-dead fail-open this check is mandated to prevent.
 *
 * The fourth probe (`pfctl -v -s Interfaces`) plus the main-ruleset
 * preemption scan exist because the first three are in turn blind to two
 * hooked-but-VOID states: `set skip on lo0` (or the `lo` group) makes pf
 * skip all filtering on loopback while every rule still prints, and an
 * earlier `pass ... quick` rule matching lo0 terminates evaluation before
 * the anchor call rule is reached (pf quick semantics). Either state is
 * the same fail-open through a different door; both are NOT live.
 *
 * pfctl prints rules in its own canonical form; the pass rule matches the
 * drill-captured printed form exactly, the block rules accept both the
 * `from any to any` and pfctl's collapsed `all` spellings, and the anchor
 * call rule accepts the trailing-`all` spelling.
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

  // Positive evidence that the anchor is HOOKED, not merely loaded: the
  // main ruleset must print the call rule that transfers lo0 evaluation
  // into the sub-anchor. Without it the rules above are dormant.
  let mainRules: PfCommandResult;
  try {
    mainRules = await runner.run("pfctl", ["-sr"]);
  } catch (err) {
    reasons.push(`pfctl -sr failed to run: ${err instanceof Error ? err.message : String(err)}`);
    return { live: false, reasons };
  }
  if (mainRules.code !== 0) {
    reasons.push(`pfctl -sr exited ${mainRules.code}`);
    return { live: false, reasons };
  }
  if (!anchorCallRuleRe(anchorName).test(mainRules.stdout)) {
    reasons.push(
      `main ruleset is missing the anchor call rule for ${anchorName} on lo0 ` +
        "(anchor is loaded but NOT hooked into packet evaluation)",
    );
  } else {
    const preempting = findPreemptingQuickPassRules(mainRules.stdout, anchorName);
    if (preempting.length > 0) {
      reasons.push(
        `main ruleset has ${preempting.length} 'pass ... quick' rule(s) before the ` +
          `${anchorName} anchor call that can match lo0 traffic and terminate evaluation ` +
          `first (anchor is hooked but PREEMPTED); first: ${preempting[0]}`,
      );
    }
  }

  // Positive evidence that pf EVALUATES lo0 at all: `set skip on lo0` (or
  // the `lo` group) leaves every probe above green while pf never runs a
  // single lo0 packet through the ruleset (anchor is hooked but SKIPPED).
  let ifaces: PfCommandResult;
  try {
    ifaces = await runner.run("pfctl", ["-v", "-s", "Interfaces"]);
  } catch (err) {
    reasons.push(
      `pfctl -v -s Interfaces failed to run: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { live: false, reasons };
  }
  if (ifaces.code !== 0) {
    reasons.push(`pfctl -v -s Interfaces exited ${ifaces.code}`);
    return { live: false, reasons };
  }
  if (LOOPBACK_SKIP_LINE_RE.test(ifaces.stdout)) {
    reasons.push(
      "pf is set to skip filtering on loopback ('set skip' covers lo0 or the lo group); " +
        "the anchor call rule prints but is never evaluated (anchor is hooked but SKIPPED)",
    );
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
   * The operator's base pf config used to compose the main ruleset when the
   * anchor call rule must be installed (default {@link PF_BASE_CONF_PATH}).
   * Tests point this at a fixture; production keeps the default.
   */
  mainConfPath?: string;
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
 * Arm the anchor: load the rendered rules into the Sanctuary anchor, HOOK
 * the anchor into the main ruleset when the call rule is absent, enable pf
 * with reference counting (`pfctl -E`, token captured for symmetric
 * disarm), then run the post-arm settle-probe. If the settle-probe does not
 * confirm liveness in time, the anchor is DISARMED again and the call
 * throws: never report armed without positive evidence.
 *
 * The hook step composes a main ruleset from the operator's base pf config
 * ({@link PF_BASE_CONF_PATH} unless overridden) plus the Sanctuary anchor
 * call + load lines, and loads it with `pfctl -f` -- the drill-proven shape,
 * preserving the stock com.apple anchors. It is skipped when `pfctl -sr`
 * already prints the call rule, so repeated arms do not reload the main
 * ruleset. HONESTY BOUND: when the hook IS installed, any rules a third
 * party added to the RUNNING main ruleset without persisting them to the
 * base config are replaced by base-config + hook; an unreadable base config
 * aborts the arm (never hook blind), and a base config that sets pf to
 * skip filtering on loopback (`set skip on lo0`/`lo`) also aborts: loading
 * it would hook an anchor pf never evaluates (silently unenforced). Void
 * states that arise anyway (skip set outside the base config, an earlier
 * preempting quick pass rule) are caught by the settle-probe, which runs
 * the full liveness check including the skip and preemption probes.
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
  assertSafeAnchorName(anchorName);
  const mainConfPath = options.mainConfPath ?? PF_BASE_CONF_PATH;
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

    // Hook the anchor into the MAIN ruleset (a loaded-but-unhooked anchor
    // enforces nothing). Skipped when the call rule is already present.
    const mainRules = await runner.run("pfctl", ["-sr"]);
    if (mainRules.code !== 0) {
      throw new Error(`pfctl -sr exited ${mainRules.code}: ${mainRules.stderr.trim()}`);
    }
    if (!anchorCallRuleRe(anchorName).test(mainRules.stdout)) {
      let baseConf: string;
      try {
        baseConf = await readFile(mainConfPath, "utf8");
      } catch (err) {
        throw new Error(
          `armPfAnchor: cannot read base pf config ${mainConfPath} ` +
            `(${err instanceof Error ? err.message : String(err)}); ` +
            "refusing to hook the anchor without preserving the operator's base ruleset",
          { cause: err },
        );
      }
      const skipLines = findLoopbackSkipLines(baseConf);
      if (skipLines.length > 0) {
        throw new Error(
          `armPfAnchor: base pf config ${mainConfPath} sets pf to skip filtering on ` +
            `loopback (${skipLines.join("; ")}); hooking the anchor through it would load ` +
            "a ruleset pf never evaluates on lo0 (silently unenforced). Remove lo0/lo from " +
            "'set skip' and re-arm; refusing to arm a void anchor",
        );
      }
      const mainFile = join(dir, "main.conf");
      const composed =
        (baseConf.endsWith("\n") || baseConf.length === 0 ? baseConf : `${baseConf}\n`) +
        renderPfMainRulesetHook(anchorName, rulesFile);
      await writeFile(mainFile, composed, { mode: 0o600 });
      const hook = await runner.run("pfctl", ["-f", mainFile]);
      if (hook.code !== 0) {
        throw new Error(
          `pfctl -f (main-ruleset anchor hook) exited ${hook.code}: ${hook.stderr.trim()}`,
        );
      }
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
 *
 * The MAIN-RULESET call rule installed at arm time is deliberately left in
 * place: with the sub-anchor flushed empty it evaluates nothing (inert),
 * and removing it would require reloading the operator's base config --
 * blast radius a teardown path must not take. It is visible via `pfctl -sr`
 * and makes the next arm's hook step a no-op.
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
