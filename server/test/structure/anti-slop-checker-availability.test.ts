/**
 * F1 anti-slop checker availability guard.
 *
 * The coordinator rule tells product-repo workers to run
 * `scripts/check-ai-tells.sh <path>` before public artifacts ship. This repo
 * must therefore carry that relative script, not depend on a coordinator-only
 * checkout path.
 */

import { describe, expect, it } from "vitest";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const CHECKER = join(REPO_ROOT, "scripts", "check-ai-tells.sh");

describe("anti-slop checker availability", () => {
  it("keeps the documented scripts/check-ai-tells.sh command runnable", async () => {
    const mode = (await stat(CHECKER)).mode;
    expect(mode & 0o111).not.toBe(0);

    const dir = await mkdtemp(join(tmpdir(), "sanctuary-ai-tells-"));
    try {
      const clean = join(dir, "clean.md");
      const tell = join(dir, "tell.md");
      const tierOneTell = join(dir, "tier-one.md");
      await writeFile(clean, "A concrete sentence with a file path and a number: /tmp/x, 7.\n");
      await writeFile(tell, "This is load-bearing for the launch.\n");
      await writeFile(tierOneTell, "This sentence has an em dash — right here.\n");

      const cleanRun = spawnSync(CHECKER, ["--strict", clean], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      expect(cleanRun.status, cleanRun.stdout + cleanRun.stderr).toBe(0);

      const tellRun = spawnSync(CHECKER, ["--strict", tell], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      expect(tellRun.status, tellRun.stdout + tellRun.stderr).toBe(1);
      expect(tellRun.stdout).toContain("Claude lexical cluster");

      const tierOneRun = spawnSync(CHECKER, ["--strict", tierOneTell], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      expect(tierOneRun.status, tierOneRun.stdout + tierOneRun.stderr).toBe(1);
      expect(tierOneRun.stdout).toContain("em dash");

      const missingRun = spawnSync(CHECKER, ["--strict", join(dir, "missing.md")], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      expect(missingRun.status, missingRun.stdout + missingRun.stderr).toBe(2);
      expect(missingRun.stderr).toContain("path does not exist");
    } finally {
      await rm(dir, { force: true, recursive: true });
    }
  });
});
