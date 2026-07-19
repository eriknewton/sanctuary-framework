/**
 * Structural guard for the agent-harness HOLD-DIR CHOKEPOINT (drill D1,
 * 2026-07-18).
 *
 * `/var/db/sanctuary/agent-harness` is root-owned and nothing in a first-ever
 * `sanctuary protect --hermes --exclusive-egress` creates it. Two writers lived
 * over it -- the parked install's exec wrapper and the release sequence's hold
 * file -- and disagreed about whose job the `mkdir` was, so every clean-host
 * arm died with `ENOENT ... release-exec-wrapper.sh`.
 *
 * The fix is a chokepoint (`writeIntoHoldDir`), not a second `mkdir`. This
 * test is what makes the chokepoint STRUCTURAL rather than a convention: a
 * future writer that reaches for a bare `writeFile(...holdPath...)` fails CI,
 * which is exactly how the third writer would otherwise reintroduce D1.
 *
 * It is deliberately a SOURCE scan -- the honest thing a unit test can assert
 * about "nobody else does this" -- over the whole of `server/src`, not just
 * `egress-gate/`, because the next writer need not live in this module.
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
]);

function walkTsFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walkTsFiles(full, acc);
    else if (entry.endsWith(".ts")) acc.push(full);
  }
  return acc;
}

describe("agent-harness hold-dir chokepoint (drill D1 structural guard)", () => {
  const files = walkTsFiles(SERVER_SRC);

  it("finds a non-trivial source tree to scan (guards against a vacuous pass)", () => {
    expect(files.length).toBeGreaterThan(100);
  });

  it("no module writes a hold-dir path except through writeIntoHoldDir", () => {
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
