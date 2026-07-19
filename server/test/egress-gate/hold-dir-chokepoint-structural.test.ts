/**
 * REGRESSION TRIPWIRE for the agent-harness hold-dir chokepoint (drill D1,
 * 2026-07-18).
 *
 * `/var/db/sanctuary/agent-harness` is root-owned and nothing in a first-ever
 * `sanctuary protect --hermes --exclusive-egress` creates it. Two writers lived
 * over it -- the parked install's exec wrapper and the release sequence's hold
 * file -- and disagreed about whose job the `mkdir` was, so every clean-host
 * arm died with `ENOENT ... release-exec-wrapper.sh`.
 *
 * WHAT THIS IS, HONESTLY (both gate lenses defeated the earlier, stronger
 * claim). This is a NAME-MATCHING SOURCE SCAN, not a structural guarantee. It
 * matches the destination expression text of a write against a list of known
 * hold-dir identifiers, so it reliably catches the ORIGINAL defect shape and
 * close variants -- and it is trivially evaded by ordinary code:
 *
 *     const dest = plan.wrapperPath;                       // passes
 *     await ops.writeFile(dest, content, 0o755);
 *     writeFile(path.join("/var/db", "sanctuary", "agent-harness", "x"), b);  // passes
 *
 * Keep it: a tripwire that catches the exact regression that already happened
 * once is worth its cost. But do NOT read a green run here as proof that no
 * module writes into the hold directory by another route. The property that
 * actually holds is enforced in `writeIntoHoldDir` itself, which takes a
 * DIRECTORY plus a bare file name and composes the path, so ensuring one
 * directory and writing into another is not expressible through the
 * chokepoint (see the "writes into EXACTLY the directory it ensured" tests in
 * release-barrier.test.ts).
 *
 * It scans the whole of `server/src`, not just `egress-gate/`, because the
 * next writer need not live in this module.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/**
 * A write whose destination expression names a hold-dir path. `writeIntoHoldDir`
 * is deliberately NOT in this list: its own internal `ops.writeFile(filePath,
 * ...)` writes an already-ensured path held in a neutral local, so the
 * chokepoint does not flag itself and needs no exemption.
 */
const HOLD_DIR_WRITE_RE =
  /\b(writeFile|writeFileSync|atomicRootWrite|appendFile|appendFileSync|copyFile|copyFileSync|open|createWriteStream)\s*\(\s*([^,)]*)/g;

/** Destination expressions that denote something inside the hold directory. */
const HOLD_DIR_TARGET_RE = /holdFilePath|holdPath|wrapperPath|AGENT_HARNESS_HOLD_DIR|releaseWrapperPath/;

/** Modules allowed to name the hold dir CONSTANT at all (layout statements). */
const HOLD_DIR_CONSTANT_OWNERS = new Set([
  // Defines the constant, the mode, and the chokepoint.
  "egress-gate/release-barrier.ts",
  // Re-exports it (a barrel re-export is not a use).
  "egress-gate/index.ts",
  // The one runtime-layout plan; imports the constant so the two statements of
  // "this directory is root 0755" cannot drift.
  "egress-gate/runtime-fs-plan.ts",
  // Holds the PRODUCTION ensure fed to the chokepoint and passes the directory
  // to it explicitly (the chokepoint no longer derives it from a file path).
  "egress-gate/arming-wiring.ts",
]);

function walkTsFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walkTsFiles(full, acc);
    else if (entry.endsWith(".ts")) acc.push(full);
  }
  return acc;
}

describe("agent-harness hold-dir chokepoint (drill D1 regression tripwire)", () => {
  const files = walkTsFiles(SERVER_SRC);

  it("finds a non-trivial source tree to scan (guards against a vacuous pass)", () => {
    expect(files.length).toBeGreaterThan(100);
  });

  it("no module names a hold-dir identifier as a write destination (the D1 defect shape)", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(SERVER_SRC, file).split(/[\\/]/).join("/");
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(HOLD_DIR_WRITE_RE)) {
        const destination = match[2] ?? "";
        if (HOLD_DIR_TARGET_RE.test(destination)) {
          offenders.push(`${rel}: ${match[1]}(${destination.trim()}) bypasses writeIntoHoldDir`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("no module mkdirs the hold directory outside the chokepoint's ensure op", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(SERVER_SRC, file).split(/[\\/]/).join("/");
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/\bmkdir(?:Sync)?\s*\(\s*([^,)]*)/g)) {
        const target = match[1] ?? "";
        if (HOLD_DIR_TARGET_RE.test(target)) {
          offenders.push(
            `${rel}: mkdir(${target.trim()}) -- the hold dir is ensured by the chokepoint's ensureHoldDir op, ` +
              "never by a writer's own mkdir",
          );
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("only the layout owners name the hold-dir constant", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(SERVER_SRC, file).split(/[\\/]/).join("/");
      if (HOLD_DIR_CONSTANT_OWNERS.has(rel)) continue;
      const text = readFileSync(file, "utf8");
      if (/AGENT_HARNESS_HOLD_DIR\b/.test(text) || text.includes("/var/db/sanctuary/agent-harness")) {
        offenders.push(`${rel}: names the hold directory outside the layout owners`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
