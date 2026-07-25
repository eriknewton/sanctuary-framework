/**
 * FIX F-HARNESSENV (HIGH, Mini1 confined-Hermes re-drill 2026-07-26): the
 * harness environment must be structurally inseparable from the harness argv.
 *
 * WHAT SHIPPED. The park install rendered the harness plist WITH the resolved
 * environment (`HOME`, `PYTHONPATH`, `HERMES_ACCEPT_HOOKS`). Every LATER
 * re-render rendered it WITHOUT: the release plist, the park re-render, the
 * degraded coarse restore, and the parked-form comparison. The drill captured
 * every distinct version of `/Library/LaunchDaemons/ai.sanctuaryprotocol.agent-harness.plist`
 * during one exclusive arm; version 1 (park install) carried all four env
 * entries, versions 2-4 carried only `SANCTUARY_STORAGE_PATH`. The plist the
 * agent was actually RELEASED under was version 3, so the gateway started with
 * no `PYTHONPATH`, fell through to Hermes' editable-install meta-path finder,
 * stat'd the operator's pre-re-home path, and died on `PermissionError`.
 * Reproduced 3/3 on direct arms and 1/1 on `--repair-egress-gate`.
 *
 * WHY A STRUCTURAL TEST AND NOT FOUR ASSERTIONS. Four writers each missing the
 * same field is not four bugs, it is one shape: an `environment` that a caller
 * had to remember. The fix makes the shape unrepresentable -- the carriers hold
 * a branded {@link HarnessLaunchSpec} that cannot be constructed without a
 * validated environment, and the two plist planners the arming/provisioning
 * paths may use derive BOTH halves from it. The type system pins most of that
 * (a bare `harnessArgv` no longer exists on any carrier). This file pins the
 * residual hole the type system cannot: a future writer reaching PAST the
 * launch-carrying planners to the low-level renderer, which still legitimately
 * accepts an optional environment for generic use.
 *
 * MUTATION-CHECKED: point any consumer at `planAgentHarnessDaemonInstall` /
 * `renderAgentHarnessDaemonPlist`, or drop `harnessLaunch` from a planner call,
 * and this file goes red.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

/**
 * The modules that CONSUME a resolved harness launch and cause a harness plist
 * to be written. Each is a writer the drill caught (or the call site that feeds
 * one). `egress-gate/harness-daemon.ts` and `egress-gate/release-barrier.ts`
 * are deliberately NOT here: they are where the launch spec is DERIVED into
 * argv + environment, which is the one place that split may legally happen.
 */
const LAUNCH_CONSUMER_FILES = [
  "server/src/egress-gate/arming-wiring.ts",
  "server/src/wrap/auto-provision.ts",
  "server/src/cli/castle-wall.ts",
] as const;

/** Planners that take a whole {@link HarnessLaunchSpec} and derive both halves. */
const LAUNCH_CARRYING_PLANNERS = ["planParkedHarnessInstall", "planCoarseHarnessDaemonInstall"] as const;

/**
 * Low-level plist entry points that accept argv and environment SEPARATELY.
 * Legitimate inside `harness-daemon.ts`/`release-barrier.ts`; reaching them
 * from a consumer is exactly how F-HARNESSENV happened.
 */
const SPLIT_ARGV_ENV_ENTRY_POINTS = ["planAgentHarnessDaemonInstall", "renderAgentHarnessDaemonPlist"] as const;

function parse(repoRelative: string): ts.SourceFile {
  return ts.createSourceFile(
    repoRelative,
    readFileSync(join(REPO_ROOT, repoRelative), "utf8"),
    ts.ScriptTarget.ES2022,
    true,
    ts.ScriptKind.TS,
  );
}

function calleeName(node: ts.CallExpression): string | undefined {
  if (ts.isIdentifier(node.expression)) return node.expression.text;
  if (ts.isPropertyAccessExpression(node.expression)) return node.expression.name.text;
  return undefined;
}

function forEachCall(source: ts.SourceFile, visit: (call: ts.CallExpression) => void): void {
  const walk = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) visit(node);
    ts.forEachChild(node, walk);
  };
  ts.forEachChild(source, walk);
}

function line(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

describe("F-HARNESSENV: the harness-plist writers cannot separate argv from environment", () => {
  it("no launch consumer reaches past the launch-carrying planners to a split argv/env entry point", () => {
    const offenders: string[] = [];
    for (const file of LAUNCH_CONSUMER_FILES) {
      const source = parse(file);
      forEachCall(source, (call) => {
        const name = calleeName(call);
        if (name !== undefined && (SPLIT_ARGV_ENV_ENTRY_POINTS as readonly string[]).includes(name)) {
          offenders.push(`${file}:${line(source, call)} calls ${name}`);
        }
      });
    }
    expect(
      offenders,
      "a harness-plist writer is rendering from a separate argv + environment again (F-HARNESSENV). " +
        `Use one of: ${LAUNCH_CARRYING_PLANNERS.join(", ")}, which derive both halves from the one HarnessLaunchSpec.`,
    ).toEqual([]);
  });

  it("every launch-carrying planner call passes harnessLaunch (never a bare argv)", () => {
    const offenders: string[] = [];
    let calls = 0;
    for (const file of LAUNCH_CONSUMER_FILES) {
      const source = parse(file);
      forEachCall(source, (call) => {
        const name = calleeName(call);
        if (name === undefined || !(LAUNCH_CARRYING_PLANNERS as readonly string[]).includes(name)) return;
        calls += 1;
        const arg = call.arguments[0];
        if (arg === undefined || !ts.isObjectLiteralExpression(arg)) {
          offenders.push(`${file}:${line(source, call)} ${name} was not called with an object literal`);
          return;
        }
        const names = arg.properties.map((p) => (p.name !== undefined && ts.isIdentifier(p.name) ? p.name.text : ""));
        if (!names.includes("harnessLaunch")) {
          offenders.push(`${file}:${line(source, call)} ${name} does not pass harnessLaunch`);
        }
        if (names.includes("harnessArgv") || names.includes("programArguments")) {
          offenders.push(
            `${file}:${line(source, call)} ${name} passes a bare argv field; the launch spec is the only carrier`,
          );
        }
      });
    }
    // Guard the guard: if the planners are ever renamed, this test must not
    // silently pass by scanning nothing.
    expect(calls, "the structural scan found no launch-carrying planner calls -- the guard has gone blind").toBeGreaterThan(0);
    expect(offenders).toEqual([]);
  });

  it("no carrier type in the arming/provisioning path still declares a bare harnessArgv field", () => {
    // The type system already rejects `harnessArgv` on the carriers, but only
    // for `server/src` (tests are transpiled, not typechecked). This keeps the
    // declaration side honest in one place a reader can point at.
    const offenders: string[] = [];
    for (const file of ["server/src/egress-gate/arming-wiring.ts", "server/src/castle-wall/provision/harness-argv.ts"]) {
      const source = parse(file);
      const walk = (node: ts.Node): void => {
        if (ts.isPropertySignature(node) && node.name !== undefined && ts.isIdentifier(node.name)) {
          if (node.name.text === "harnessArgv") {
            offenders.push(`${file}:${line(source, node)} declares a bare harnessArgv carrier field`);
          }
        }
        ts.forEachChild(node, walk);
      };
      ts.forEachChild(source, walk);
    }
    expect(offenders).toEqual([]);
  });
});
