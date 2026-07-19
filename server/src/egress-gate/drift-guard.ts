/**
 * Transient-pf-rule drift guard (Unified Protect Slice 5 S5-6, design MED-7).
 *
 * THE PROBLEM: `armPfAnchor`'s hook install composes `/etc/pf.conf` + the
 * Sanctuary hook and loads it as the RUNNING main ruleset -- which replaces
 * any transient rules a third party (Tailscale, Cloudflare WARP, a corporate
 * VPN) added to the running ruleset without persisting them. A drift REPAIR
 * doing this silently can break the operator's VPN/firewall while Sanctuary
 * reports itself green. The design's rule: before any hook install (repair
 * path), diff the running main ruleset against the base-config-derived
 * ruleset; if non-Sanctuary transient rules are present, automatic repair
 * REFUSES (posture stays amber, guidance names the foreign rules) and
 * proceeds only with the explicit interactive `--override-transient-pf-rules`
 * (audited).
 *
 * MECHANISM: the expected ruleset is derived by asking pf itself to
 * NORMALIZE the base config (`pfctl -n -v -f <composed>` -- parse-only, `-n`
 * never loads), because textual pf.conf lines and `pfctl -sr` output differ
 * syntactically (macros expanded, defaults printed). The diff is
 * line-set-based over normalized rules: any running rule (from `pfctl -sr`)
 * that is not in the normalized expected set and is not the Sanctuary anchor
 * call is FOREIGN. Fail-closed: any pfctl failure THROWS (the caller refuses
 * the repair -- never hook-install blind).
 *
 * HONESTY BOUND: this guard sees the MAIN ruleset only. Third-party rules
 * living inside their own anchors that ARE persisted/reloaded by their
 * owning daemon (the common Tailscale shape) survive an anchor-preserving
 * reload anyway; the guard exists for the transient main-ruleset class the
 * 2026-07 review named. The VPN-coexistence drill leg (S5-DRILL) is the
 * acceptance evidence; this module advances no claim.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PF_ANCHOR_NAME,
  PF_BASE_CONF_PATH,
  renderPfMainRulesetHook,
  type PfCommandRunner,
} from "./pf-anchor.js";

/** The result of one drift diff. */
export interface TransientPfRulesDiff {
  /** Running main-ruleset rules NOT derivable from the base config (foreign). */
  foreign: string[];
  /** The normalized expected rule count (observability). */
  expectedCount: number;
  /** The running rule count (observability). */
  runningCount: number;
}

/** Options for {@link diffTransientPfRules}. */
export interface DiffTransientPfRulesOptions {
  /** Base pf config path (default {@link PF_BASE_CONF_PATH}). */
  mainConfPath?: string;
  /** Sanctuary anchor name (default {@link PF_ANCHOR_NAME}). */
  anchorName?: string;
}

/** Normalize one printed pf rule line for set comparison. */
function normalizeRuleLine(line: string): string {
  return line.trim().replace(/\s+/g, " ");
}

function anchorNamesFromBaseConfig(baseConf: string): ReadonlyMap<string, readonly string[]> {
  const byDirective = new Map<string, Set<string>>();
  for (const rawLine of baseConf.split("\n")) {
    const line = normalizeRuleLine(rawLine);
    if (line.length === 0 || line.startsWith("#")) continue;
    const match = /^(scrub-anchor|anchor)\s+"([^"]+)"(?:\s|$)/.exec(line);
    if (match === null) continue;
    const directive = match[1]!;
    const name = match[2]!;
    const names = byDirective.get(directive) ?? new Set<string>();
    names.add(name);
    byDirective.set(directive, names);
  }
  return new Map([...byDirective.entries()].map(([directive, names]) => [directive, [...names].sort()]));
}

function normalizeRuleLineVariants(
  line: string,
  baseAnchorNames: ReadonlyMap<string, readonly string[]>,
): string[] {
  const normalized = normalizeRuleLine(line);
  const strippedAnchor = /^(scrub-anchor|anchor)\s+"\/\*"(.*)$/.exec(normalized);
  if (strippedAnchor === null) return [normalized];
  const directive = strippedAnchor[1]!;
  const suffix = strippedAnchor[2]!;
  const names = baseAnchorNames.get(directive) ?? [];
  if (names.length === 0) return [normalized];
  return names.map((name) => `${directive} "${name}"${suffix}`);
}

/**
 * Extract the RULE lines from pfctl output: `pfctl -sr` prints one rule per
 * line; `pfctl -n -v -f` echoes rules plus blank lines and `@n` prefixes in
 * some modes. Strip prefixes/blanks conservatively.
 */
function ruleLines(output: string, baseAnchorNames: ReadonlyMap<string, readonly string[]>): string[] {
  return output
    .split("\n")
    .flatMap((line) => normalizeRuleLineVariants(line.replace(/^@\d+\s+/, ""), baseAnchorNames))
    .filter((line) => line.length > 0);
}

/**
 * Diff the RUNNING pf main ruleset against the base-config-derived ruleset
 * (base config + the Sanctuary anchor hook lines, normalized by
 * `pfctl -n -v -f`). Returns the foreign (transient, third-party) rules.
 * THROWS on any pfctl or filesystem failure -- the repair caller must refuse,
 * never proceed blind (fail-closed, AGENTS.md invariant 5).
 */
export async function diffTransientPfRules(
  runner: PfCommandRunner,
  options: DiffTransientPfRulesOptions = {},
): Promise<TransientPfRulesDiff> {
  const mainConfPath = options.mainConfPath ?? PF_BASE_CONF_PATH;
  const anchorName = options.anchorName ?? PF_ANCHOR_NAME;

  const running = await runner.run("pfctl", ["-sr"]);
  if (running.code !== 0) {
    throw new Error(`pfctl -sr exited ${running.code}: ${running.stderr.trim()}`);
  }

  let baseConf: string;
  try {
    baseConf = await readFile(mainConfPath, "utf8");
  } catch (err) {
    throw new Error(
      `drift guard: cannot read base pf config ${mainConfPath} ` +
        `(${err instanceof Error ? err.message : String(err)}); refusing to diff blind`,
      { cause: err },
    );
  }

  // Compose base + the Sanctuary hook (the exact shape the arm path loads),
  // then ask pf to parse-and-print it WITHOUT loading (-n). The rules-file
  // path inside the hook's load line is a placeholder: `-n` never loads the
  // anchor contents, and the anchor CALL rule prints identically regardless.
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-pf-diff-"));
  let normalized: string;
  try {
    const composedPath = join(dir, "expected-main.conf");
    const composed =
      (baseConf.endsWith("\n") || baseConf.length === 0 ? baseConf : `${baseConf}\n`) +
      renderPfMainRulesetHook(anchorName, join(dir, "placeholder.rules"));
    // The load-anchor line references a rules file pfctl -n opens; give it an
    // empty real file so parse-only validation cannot fail on ENOENT.
    await writeFile(join(dir, "placeholder.rules"), "", { mode: 0o600 });
    await writeFile(composedPath, composed, { mode: 0o600 });
    const parse = await runner.run("pfctl", ["-n", "-v", "-f", composedPath]);
    if (parse.code !== 0) {
      throw new Error(
        `pfctl -n -v -f (expected-ruleset normalization) exited ${parse.code}: ${parse.stderr.trim()}`,
      );
    }
    // pfctl -n -v prints the parsed rules on stdout (some builds echo to
    // stderr as well); use both streams for the expected set.
    normalized = `${parse.stdout}\n${parse.stderr}`;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }

  const baseAnchorNames = anchorNamesFromBaseConfig(baseConf);
  const expected = new Set(ruleLines(normalized, baseAnchorNames));
  const runningRules = ruleLines(running.stdout, baseAnchorNames);
  const anchorCallPrefix = `anchor "${anchorName}"`;
  const foreign = runningRules.filter(
    (line) => !expected.has(line) && !line.startsWith(anchorCallPrefix),
  );
  return { foreign, expectedCount: expected.size, runningCount: runningRules.length };
}
