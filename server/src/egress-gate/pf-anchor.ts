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
 * unified-protect-keystone/RESULTS.md). The COMPOSED build (this module's
 * armPfAnchor / checkPfAnchorLiveness / disarmPfAnchor plus the gate) was
 * then drilled PASS N=3 on BOTH macOS families on 2026-07-03 (Tahoe 26.5.1
 * arm64 + Sonoma 14.6.1 x86_64); see
 * docs/audit/unified-protect-enforcement-status.md for the captured evidence
 * and the legs still owed (sysext-armed full-design console drills, Slice 4).
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
 * THE pf ENABLE REFERENCE IS NOT THIS MODULE'S TO REASON ABOUT. This module
 * owns the anchor's RULES; `pf-enable-state.ts` owns the `pfctl -E` reference
 * lifecycle end to end (acquire, resolve, release) and is the only place that
 * decides whether this fortress holds a live reference of its own. That split
 * exists because the same enable-state mistake was made at three call sites in
 * this file and cost a wrong-allow twice on hardware: once when a persisted
 * token outlived the reboot that zeroed it (F-PFBOOT), and once when a global
 * `Status: Enabled` read was mistaken for evidence that the reference holding
 * pf up was ours (F-PFTHIRDPARTY). Read that module's header before changing
 * anything here that touches `-E` or `-X`.
 *
 * All privileged commands run through an injected {@link PfCommandRunner}
 * so the logic is unit-testable without root or a real pf.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createExecFileRunner } from "./exec-runner.js";
import {
  ensurePfEnableReference,
  observePfEnabled,
  releasePfEnableReference,
  type BootSessionReader,
  type PfEnabledObservation,
  type PfEnableReference,
  type PfEnableReferenceDisposition,
  type PfEnableReferenceEnsured,
  type PfEnableReferenceRelease,
} from "./pf-enable-state.js";

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
  // Single-uid render delegates to the multi-uid union path (Slice 5 S5-1) so
  // the two can never drift: one confined uid is just a one-entry union.
  return renderPfAnchorRulesForUids([policy]);
}

/**
 * Render one confined uid's five anchor rules (the pass-to-gate rule + the
 * four block-drops). The pass rule uses the exact printed form the Tahoe
 * keystone drill captured from `pfctl -a <anchor> -sr`, so the liveness
 * check can compare against pfctl's canonical output.
 */
function renderUidAnchorLines(policy: ExclusiveEgressGatePolicy): string[] {
  const uid = policy.agent_uid;
  const port = policy.gate_port;
  return [
    `pass quick on lo0 inet proto tcp from any to 127.0.0.1 port = ${port} user = ${uid} flags S/SA keep state`,
    ...renderUidBlockOnlyLines(uid),
  ];
}

/**
 * Render one confined uid's FOUR block-drop rules WITHOUT the pass-to-gate
 * rule (Unified Protect Slice 5 S5-2, folds Codex M4 -- the block-only
 * tombstone). The generation state machine's crash recovery uses this when a
 * uid's gate generation was staged into the anchor (its pass rule loaded) but
 * never COMMITTED (G5), and must be torn back to a confined-but-gateless
 * state: the four block-drops keep non-gate loopback CLOSED for the uid while
 * the stale, uncommitted pass rule is removed, so recovery never reopens the
 * loopback-relay hole nor drops the whole uid (which would drop the
 * block-drops too). Posture reads amber/not-live for a tombstoned uid (no gate
 * pass) until a fresh generation commits or unprotect removes the uid.
 */
function renderUidBlockOnlyLines(uid: number): string[] {
  return [
    `block drop quick on lo0 inet proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet proto udp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto udp from any to any user = ${uid}`,
  ];
}

/**
 * A member of the shared anchor's confined-uid union (Unified Protect Slice 5).
 * A LIVE member ({@link ExclusiveEgressGatePolicy}: `agent_uid` + `gate_port`)
 * renders the pass-to-gate rule plus the four block-drops. A TOMBSTONE member
 * (`tombstone: true`, S5-2 M4) renders ONLY the four block-drops -- the uid
 * stays confined (non-gate loopback blocked) but has no gate pass, the
 * confined-but-gateless state a crash between G3 (pf load) and G5 (commit)
 * must leave. `gate_port` stays a valid port for schema validity even when
 * tombstoned; it is simply not rendered. This type is a backward-compatible
 * widening of the S5-1 union entry: an entry with no `tombstone` field renders
 * byte-identically to before.
 */
export interface PfAnchorUnionEntry extends ExclusiveEgressGatePolicy {
  /** Block-only tombstone: render the four block-drops, NOT the gate pass rule. */
  tombstone?: boolean;
}

/**
 * Render the pf anchor rule text for a UNION of confined uids (Unified
 * Protect Slice 5 S5-1). The shared `sanctuary.egress-gate` anchor holds one
 * confinement block per confined uid; this is the single artifact loaded into
 * the anchor whenever the set of confined uids changes, so a second uid never
 * overwrites a first's rules (the HIGH-4 destructive-full-replace flaw) and a
 * removal re-renders only the remaining union.
 *
 * DETERMINISTIC ORDER: entries are emitted sorted ascending by `agent_uid`,
 * so re-rendering the same SET produces byte-identical text (an idempotent
 * `pfctl -f` load; the liveness snapshot compare stays stable).
 *
 * FAIL-CLOSED at render time (never emit a permissive-by-accident anchor):
 *   - an EMPTY list throws (callers flush the anchor for the empty case, they
 *     do not load empty text);
 *   - a DUPLICATE `agent_uid` throws (the registry must never hold two
 *     entries for one uid; two blocks for one uid with different gate ports
 *     would render two conflicting pass rules);
 *   - any entry failing {@link validateExclusiveEgressGatePolicy} throws.
 */
export function renderPfAnchorRulesForUids(
  entries: readonly PfAnchorUnionEntry[],
): string {
  if (entries.length === 0) {
    throw new Error(
      "renderPfAnchorRulesForUids: refusing to render an EMPTY union (flush the anchor for the no-confined-uid case, never load empty rule text)",
    );
  }
  const seen = new Set<number>();
  for (const entry of entries) {
    if (validateExclusiveEgressGatePolicy(entry) === null) {
      throw new Error(
        "renderPfAnchorRulesForUids: refusing to render a pf anchor from a malformed exclusive-egress gate policy entry",
      );
    }
    if (seen.has(entry.agent_uid)) {
      throw new Error(
        `renderPfAnchorRulesForUids: duplicate agent_uid ${entry.agent_uid} in the union (each confined uid must appear at most once)`,
      );
    }
    seen.add(entry.agent_uid);
  }
  const sorted = [...entries].sort((a, b) => a.agent_uid - b.agent_uid);
  const lines: string[] = [];
  for (const entry of sorted) {
    lines.push(
      ...(entry.tombstone === true
        ? renderUidBlockOnlyLines(entry.agent_uid)
        : renderUidAnchorLines(entry)),
    );
  }
  lines.push("");
  return lines.join("\n");
}

/**
 * Render {@link observePfEnabled} into the liveness checks' not-live reason
 * strings. Empty when pf is observed enabled -- and, deliberately, NOT empty
 * when pf could not be read: an unreadable pf is never a passing probe.
 *
 * The disabled-pf string is kept byte-stable because it is the sentence the
 * boot supervisor surfaces to the operator and the one the drill logs quote.
 */
function pfEnabledLivenessReasons(observed: PfEnabledObservation): string[] {
  if (!observed.known) return [observed.reason];
  if (!observed.enabled) {
    return ["pf is not enabled (pfctl -s info lacks 'Status: Enabled')"];
  }
  return [];
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

  reasons.push(...pfEnabledLivenessReasons(await observePfEnabled(runner)));

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

/**
 * Per-line (anchored, no `m` flag) matchers for exactly one confined uid's
 * five anchor rules, used by the exact-union liveness comparison. Accepts
 * both pfctl block-rule spellings (`all` vs `from any to any`).
 */
function uidExpectedLineMatchers(
  entry: PfAnchorUnionEntry,
): Array<{ re: RegExp; label: string }> {
  const uid = entry.agent_uid;
  const port = entry.gate_port;
  const blockMatchers: Array<{ re: RegExp; label: string }> = [
    { re: new RegExp(`^block drop quick on lo0 inet proto tcp (?:all|from any to any) user = ${uid}$`), label: `inet tcp block-drop for uid ${uid}` },
    { re: new RegExp(`^block drop quick on lo0 inet proto udp (?:all|from any to any) user = ${uid}$`), label: `inet udp block-drop for uid ${uid}` },
    { re: new RegExp(`^block drop quick on lo0 inet6 proto tcp (?:all|from any to any) user = ${uid}$`), label: `inet6 tcp block-drop for uid ${uid}` },
    { re: new RegExp(`^block drop quick on lo0 inet6 proto udp (?:all|from any to any) user = ${uid}$`), label: `inet6 udp block-drop for uid ${uid}` },
  ];
  // A tombstoned uid must hold ONLY its four block-drops -- no pass rule. The
  // exactness pass (b) below then REJECTS any stray pass line for it, so a
  // stale/uncommitted gate pass on a tombstoned uid makes the union NOT live.
  if (entry.tombstone === true) {
    return blockMatchers;
  }
  return [
    {
      re: new RegExp(
        `^pass quick on lo0 inet proto tcp from any to 127\\.0\\.0\\.1 port = ${port} user = ${uid} flags S/SA keep state$`,
      ),
      label: `agent-to-gate pass rule (port ${port}, uid ${uid})`,
    },
    ...blockMatchers,
  ];
}

/**
 * Exact-union liveness (Unified Protect Slice 5 S5-1, folds Codex H4): prove
 * by POSITIVE EVIDENCE that the shared anchor holds EXACTLY the union of the
 * given confined uids' rules -- no more, no less -- and is enabled, hooked,
 * un-skipped, and un-preempted.
 *
 * Distinct from {@link checkPfAnchorLiveness} (single-uid presence check):
 * per-uid presence alone does not prove the anchor lacks an earlier or
 * broader PERMISSIVE rule (a stray `pass` from drift, a botched mutation, or
 * a third party). This check takes ONE anchor snapshot and asserts:
 *   (a) every expected rule for every confined uid is present, AND
 *   (b) EVERY printed anchor rule matches some expected union rule -- any
 *       unexpected line (especially a `pass`) makes the union NOT live.
 * Then it runs the shared hook / skip / preemption probes once for the whole
 * union. Fail-closed on any pfctl error, non-zero exit, or unparseable
 * output.
 */
export async function checkPfAnchorUnionLiveness(
  runner: PfCommandRunner,
  entries: readonly PfAnchorUnionEntry[],
  anchorName: string = PF_ANCHOR_NAME,
): Promise<PfLivenessResult> {
  if (entries.length === 0) {
    return { live: false, reasons: ["empty union (no confined uids to verify)"] };
  }
  const seen = new Set<number>();
  for (const entry of entries) {
    if (validateExclusiveEgressGatePolicy(entry) === null) {
      return { live: false, reasons: ["malformed exclusive-egress gate policy entry in union"] };
    }
    if (seen.has(entry.agent_uid)) {
      return { live: false, reasons: [`duplicate agent_uid ${entry.agent_uid} in union`] };
    }
    seen.add(entry.agent_uid);
  }
  const reasons: string[] = [];

  reasons.push(...pfEnabledLivenessReasons(await observePfEnabled(runner)));

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

  const printedLines = rules.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const sorted = [...entries].sort((a, b) => a.agent_uid - b.agent_uid);
  const expected: Array<{ re: RegExp; label: string }> = [];
  for (const entry of sorted) {
    expected.push(...uidExpectedLineMatchers(entry));
  }
  // (a) every expected union rule must be present.
  for (const { re, label } of expected) {
    if (!printedLines.some((line) => re.test(line))) {
      reasons.push(`anchor ${anchorName} is missing the ${label}`);
    }
  }
  // (b) EXACTNESS: every printed anchor rule must match some expected union
  // rule. An unexpected line (a stray permissive `pass`, a broader rule from
  // drift or a botched mutation) makes the union NOT live -- this is the H4
  // hardening over a bare per-uid presence check.
  //
  // Deliberately SET-based, not multiset/ordered (gate-round LOW): a duplicated
  // expected line or a reordering can only ever make the anchor MORE blocking
  // (all rules are `quick`; the only `pass` is the narrow per-uid gate rule and
  // everything else is `block drop`, so any reorder can at worst shadow a uid's
  // own gate pass behind its own block = that uid loses gate access, fail-closed,
  // never a widening). A strict count/order check would instead risk a
  // fail-CLOSED availability cliff on benign pfctl canonical-print drift, so the
  // presence + no-unexpected-line pair is the conservative, drill-safe choice.
  for (const line of printedLines) {
    if (!expected.some(({ re }) => re.test(line))) {
      reasons.push(
        `anchor ${anchorName} contains an unexpected rule not in the confined-uid union: ${line}`,
      );
    }
  }

  // Hooked, not merely loaded: the main ruleset must call the anchor.
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

  // pf must actually evaluate lo0 (not `set skip on lo0`/`lo`).
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
  /**
   * Reads `kern.bootsessionuuid`, used to bind a newly acquired pf enable
   * reference to the boot session that minted it. Injected for tests; defaults
   * to the real sysctl reader in `pf-enable-state.ts`.
   */
  bootSession?: BootSessionReader;
}

/** Result of a successful arm. */
export interface ArmPfAnchorResult {
  /**
   * The pf enable reference this fortress now holds -- token PLUS the boot
   * session that minted it. The caller persists the WHOLE record, never the
   * token alone: a bare token is indistinguishable from a token a reboot
   * invalidated, which is the F-PFBOOT defect in one sentence.
   *
   * Present whenever the arm established a reference (acquired OR verified as
   * still ours and live), so a caller that saves it always saves something
   * current.
   */
  enableReference?: PfEnableReference;
  /** True when THIS arm ran `pfctl -E` rather than reusing a verified reference. */
  acquiredEnableReference?: boolean;
  /**
   * What happened to the reference the acquire SUPERSEDED, when there was one.
   * Absent on a reuse and on a first arm.
   *
   * Carried out of the chokepoint verbatim -- `reason` included -- because a
   * superseded release that could not be accounted for leaves the kernel
   * holding an ORPHANED enable reference with no registry row naming it, and
   * dropping the reason here is what made that condition invisible. It
   * over-enforces (pf stays enabled) and can never be a wrong-allow, but an
   * operator who runs `--unprotect-egress-gate` and finds pf still enabled is
   * entitled to the sentence that explains why. Log it; do not act on it.
   */
  supersededEnableRelease?: PfEnableReferenceRelease;
  /** What the enable-reference chokepoint observed, for logs and diagnostics. */
  enableEvidence?: string[];
  /** How many liveness probes ran during the settle phase. */
  settleProbes: number;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Install the main-ruleset anchor call rule when it is absent, composing the
 * running main ruleset from the operator's base pf config plus the Sanctuary
 * hook lines (the drill-proven shape, preserving the stock com.apple
 * anchors). Skipped when `pfctl -sr` already prints the call rule, so
 * repeated arms do not reload the main ruleset. Refuses (throws) on an
 * unreadable base config or one that sets pf to skip filtering on loopback.
 * Shared by {@link armPfAnchor} and {@link armPfAnchorUnion} so the two can
 * never drift.
 */
async function installAnchorHookIfAbsent(
  runner: PfCommandRunner,
  anchorName: string,
  rulesFile: string,
  mainConfPath: string,
  dir: string,
): Promise<void> {
  const mainRules = await runner.run("pfctl", ["-sr"]);
  if (mainRules.code !== 0) {
    throw new Error(`pfctl -sr exited ${mainRules.code}: ${mainRules.stderr.trim()}`);
  }
  if (anchorCallRuleRe(anchorName).test(mainRules.stdout)) {
    return;
  }
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

/** Options for {@link armPfAnchorUnion}. */
export interface ArmPfAnchorUnionOptions extends ArmPfAnchorOptions {
  /**
   * The pf enable reference this fortress RECORDED at a prior arm (the
   * registry threads its committed record here): the `pfctl -E` token plus the
   * boot session that minted it.
   *
   * It is a RECORD, NEVER A GUARANTEE. Reference counting still matters -- each
   * `-E` bumps pf's count and returns a new token, so re-enabling on every
   * in-boot mutation would leak references -- but whether this record still
   * names a live reference OF OURS is a question only an observation can
   * answer, and `pf-enable-state.ts` answers it. Three verdicts, one
   * permission: reuse happens only when the reference is confirmed ours and
   * live in THIS boot; a stale record (post-reboot) or a pf held up by
   * somebody else's reference re-acquires, and the fresh record comes back in
   * {@link ArmPfAnchorResult.enableReference} for the caller to persist in
   * place of the old one.
   */
  existingEnableReference?: PfEnableReference;
}

/**
 * Arm the shared anchor to a UNION of confined uids (Unified Protect Slice 5
 * S5-1). This is the arm-equivalent primitive the locked registry uses in
 * place of a bare `pfctl -a <anchor> -f`: it reuses the SAME hook-install +
 * pf-enable + settle-probe semantics {@link armPfAnchor} owns (Codex H3 --
 * a bare load leaves rules loaded-but-unhooked/disabled, enforcing nothing),
 * with the settle-probe gated on {@link checkPfAnchorUnionLiveness} so "armed"
 * means the anchor holds EXACTLY the union and is hooked, enabled, un-skipped,
 * and un-preempted.
 *
 * Two deliberate differences from {@link armPfAnchor}:
 *   - It reuses a supplied enable reference instead of minting a new one, but
 *     ONLY when `pf-enable-state.ts` confirms that reference is ours and live
 *     in this boot session (reference counting -- see
 *     {@link ArmPfAnchorUnionOptions.existingEnableReference}).
 *   - ON FAILURE IT DOES NOT FLUSH THE ANCHOR (Codex B2). A flush would drop
 *     every other confined uid's rules; the anchor is a shared multi-uid
 *     surface now. The caller (the registry) owns rollback: it re-asserts the
 *     previous committed union, or -- if that too fails -- marks the registry
 *     dirty and forces posture red. This function just loads, hooks, enables,
 *     settles, and throws on any failure, leaving the anchor for the registry
 *     to reconcile.
 */
export async function armPfAnchorUnion(
  runner: PfCommandRunner,
  entries: readonly PfAnchorUnionEntry[],
  options: ArmPfAnchorUnionOptions = {},
): Promise<ArmPfAnchorResult> {
  const anchorName = options.anchorName ?? PF_ANCHOR_NAME;
  assertSafeAnchorName(anchorName);
  const mainConfPath = options.mainConfPath ?? PF_BASE_CONF_PATH;
  const rulesText = renderPfAnchorRulesForUids(entries); // throws on empty/dup/malformed
  const sleep = options.sleep ?? defaultSleep;
  const settleConsecutive = options.settleConsecutive ?? 2;
  const settleDelayMs = options.settleDelayMs ?? 200;
  const settleTimeoutMs = options.settleTimeoutMs ?? 5_000;

  const dir = await mkdtemp(join(tmpdir(), "sanctuary-pf-"));
  const rulesFile = join(dir, "egress-gate.rules");
  let ensured: PfEnableReferenceEnsured | undefined;
  // The `pfctl -E` reference THIS call acquired. Tracked so a post-enable
  // failure releases exactly the reference this call took, never one another
  // uid or an earlier arm depends on (folds gate-round finding: leaked -E
  // reference).
  let acquiredToken: string | undefined;
  try {
    await writeFile(rulesFile, rulesText, { mode: 0o600 });

    const load = await runner.run("pfctl", ["-a", anchorName, "-f", rulesFile]);
    if (load.code !== 0) {
      throw new Error(`pfctl -a ${anchorName} -f exited ${load.code}: ${load.stderr.trim()}`);
    }

    await installAnchorHookIfAbsent(runner, anchorName, rulesFile, mainConfPath, dir);

    // Establish that THIS fortress holds a live pf enable reference of its
    // own, minted in THIS boot session. The whole decision -- reuse or
    // re-acquire, and the release of anything superseded -- belongs to the
    // chokepoint; there is deliberately no enable-state branch left here.
    //
    // The two defects that made this a chokepoint instead of an inline `if`
    // (Mini1, 2026-07-26, merged main `ed7722ce`):
    //   F-PFBOOT     -- `if (existingEnableToken === undefined)` skipped
    //                   `pfctl -E` after every reboot because the persisted
    //                   token survived the kernel state it described. pf stayed
    //                   disabled, the anchor stayed loaded and inert, and the
    //                   confined uid regained loopback reach to sshd, Screen
    //                   Sharing, Ollama and PostgreSQL (CONNECTED 3/3 each,
    //                   against blocked 3/3 in the armed control).
    //   F-PFTHIRDPARTY -- a reference-count or `Status: Enabled` test alone
    //                   would have reused the record whenever ANY reference
    //                   held pf up. Measured: when that foreign reference was
    //                   released, confinement vanished in the same boot and the
    //                   same generation while the product reported health.
    // Holding our OWN reference is what makes the second case survivable.
    ensured = await ensurePfEnableReference(
      { runner, ...(options.bootSession !== undefined ? { bootSession: options.bootSession } : {}) },
      options.existingEnableReference,
    );
    if (ensured.acquired) {
      acquiredToken = ensured.reference.token;
    }

    // Settle-probe on the EXACT union: require N consecutive live results.
    const deadline = Date.now() + settleTimeoutMs;
    let consecutive = 0;
    let probes = 0;
    let lastReasons: string[] = [];
    while (consecutive < settleConsecutive) {
      if (Date.now() > deadline) {
        throw new Error(
          `pf anchor union settle-probe timed out after ${settleTimeoutMs}ms ` +
            `(last liveness failure: ${lastReasons.join("; ") || "none recorded"})`,
        );
      }
      const result = await checkPfAnchorUnionLiveness(runner, entries, anchorName);
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
    return {
      settleProbes: probes,
      enableReference: ensured.reference,
      acquiredEnableReference: ensured.acquired,
      ...(ensured.supersededRelease !== undefined
        ? { supersededEnableRelease: ensured.supersededRelease }
        : {}),
      enableEvidence: ensured.evidence,
    };
  } catch (err) {
    // Codex B2: NO catch-FLUSH -- the anchor is a shared multi-uid surface, so
    // `-F all` would drop every OTHER confined uid's rules; the registry owns
    // rollback of the anchor CONTENTS. BUT the `-E` reference THIS call took is
    // ours alone: release it so a post-enable failure never leaves pf enabled
    // with a dangling reference the registry believes it never acquired
    // (gate-round finding -- unbounded leak on retry + silent host-firewall
    // posture change). We only release what WE acquired this call (an existing
    // token belongs to a prior arm and stays live).
    //
    // ONE EXCEPTION, AND IT IS THE WHOLE POINT OF THIS MODULE (fix-round F1).
    // When the acquire SUPERSEDED a reference that was really released, the
    // reference this call took is no longer an ADDITION -- it is the only thing
    // holding pf up, for every confined uid on the host, including ones this
    // mutation never touched. Giving it back would take the count to zero under
    // a loaded anchor and unconfine a BYSTANDER uid until the registry
    // rollback's own `-E` (unbounded if that rollback also fails). Keeping it is
    // an orphaned reference: over-enforcing, releasable, and visible in
    // `pfctl -s References` -- which is the fail direction this module chose
    // everywhere else, so the failure path chooses it too.
    //
    // `already-gone` is NOT this case: it means the kernel held no such
    // reference, so nothing that was holding pf up was destroyed and the
    // reference we took really is ours alone to give back. `undefined` means no
    // supersession happened at all (a first arm). Both still release.
    const supersededWasReleased = ensured?.supersededRelease?.disposition === "released";
    if (acquiredToken !== undefined && !supersededWasReleased) {
      await releasePfEnableReference({ runner }, acquiredToken).catch(() => undefined);
    }
    throw err;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

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
  let ensured: PfEnableReferenceEnsured | undefined;
  try {
    await writeFile(rulesFile, rulesText, { mode: 0o600 });

    const load = await runner.run("pfctl", ["-a", anchorName, "-f", rulesFile]);
    if (load.code !== 0) {
      throw new Error(`pfctl -a ${anchorName} -f exited ${load.code}: ${load.stderr.trim()}`);
    }

    // Hook the anchor into the MAIN ruleset (a loaded-but-unhooked anchor
    // enforces nothing). Skipped when the call rule is already present.
    await installAnchorHookIfAbsent(runner, anchorName, rulesFile, mainConfPath, dir);

    // SAME chokepoint as the union path, deliberately. This single-uid arm has
    // no production caller today, and a second hand-written enable-state branch
    // here is exactly how it would drift back into the defect the union path
    // just had removed.
    ensured = await ensurePfEnableReference(
      { runner, ...(options.bootSession !== undefined ? { bootSession: options.bootSession } : {}) },
      undefined,
    );

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
    return {
      settleProbes: probes,
      enableReference: ensured.reference,
      acquiredEnableReference: ensured.acquired,
      enableEvidence: ensured.evidence,
    };
  } catch (err) {
    // Symmetric rollback: a half-armed anchor must not linger.
    await disarmPfAnchor(runner, {
      anchorName,
      ...(ensured !== undefined ? { enableToken: ensured.reference.token } : {}),
    }).catch(() => undefined);
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

/** What {@link disarmPfAnchor} did with the enable reference it was handed. */
export interface DisarmPfAnchorResult {
  /**
   * `none-supplied` when there was no token to release; otherwise the
   * chokepoint's disposition (`released`, or `already-gone` for a reference
   * the kernel does not have).
   */
  enableReference: PfEnableReferenceDisposition | "none-supplied";
  /** The evidence behind an `already-gone` call (absent otherwise). */
  staleReason?: string;
}

/**
 * Disarm symmetry: flush every rule out of the Sanctuary anchor, then
 * release the pf enable reference taken at arm time (when a token was
 * captured). Throws on failure: a disarm that silently did nothing would
 * leave state the operator believes is gone.
 *
 * ONE DELIBERATE EXCEPTION, and it is a recovery path rather than a leniency.
 * A `pfctl -X` that fails BECAUSE the kernel has no such reference is not a
 * teardown failure -- it is the truth about a token a reboot invalidated.
 * Before this, that failure made `--unprotect-egress-gate` throw
 * (`pfctl: pf: token invalid`, measured) and left a committed registry entry
 * NO product path could clear: the operator's last escape hatch was itself
 * deadlocked, and the only measured way out was an out-of-band `pfctl -E`,
 * which creates the F-PFTHIRDPARTY wrong-allow. `pf-enable-state.ts` decides
 * that question from BOTH captured pfctl failure messages plus an observation
 * of pf, and still throws on any failure it cannot account for. The fail
 * direction is safe in one direction only, which is the right one: an
 * unreleased reference leaves pf ENABLED (over-enforcing, visible in
 * `pfctl -s References`), never a confined uid with reach it should not have.
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
): Promise<DisarmPfAnchorResult> {
  const anchorName = options.anchorName ?? PF_ANCHOR_NAME;
  const flush = await runner.run("pfctl", ["-a", anchorName, "-F", "all"]);
  if (flush.code !== 0) {
    throw new Error(`pfctl -a ${anchorName} -F all exited ${flush.code}: ${flush.stderr.trim()}`);
  }
  if (options.enableToken === undefined) {
    return { enableReference: "none-supplied" };
  }
  if (!/^\d+$/.test(options.enableToken)) {
    throw new Error("disarmPfAnchor: enableToken must be a numeric pfctl reference token");
  }
  const release = await releasePfEnableReference({ runner }, options.enableToken);
  return {
    enableReference: release.disposition,
    ...(release.reason !== undefined ? { staleReason: release.reason } : {}),
  };
}
