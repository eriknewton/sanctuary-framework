import { spawnSync } from "node:child_process";
import { copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

describe("Castle Wall standalone boot-runtime bundle", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  it("starts without package metadata adjacent to the root-custodied daemon", async () => {
    const isolatedDir = await mkdtemp(join(tmpdir(), "castle-wall-bundle-"));
    tempDirs.push(isolatedDir);
    const daemonPath = join(isolatedDir, "castle-wall-boot-daemon.js");
    await copyFile(
      resolve("dist/boot-runtime/castle-wall-boot-daemon.js"),
      daemonPath,
    );
    const sealedBundle = await readFile(daemonPath, "utf8");

    // The boot daemon does not currently report the server version, so its
    // package metadata may be tree-shaken entirely. Either way, the sealed
    // artifact must never retain the external path that caused the release
    // candidate to fail outside a repository checkout.
    expect(sealedBundle).not.toContain("../package.json");

    const result = spawnSync(
      process.execPath,
      [
        daemonPath,
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
        "--fortress",
        join(isolatedDir, "fortress"),
      ],
      {
        encoding: "utf8",
        // Bundle smoke tests must fail before root-custodied credential access;
        // operator-owned boot-token state is never a test fixture.
        env: { ...process.env, SANCTUARY_CASTLE_LOCAL_SIGN: "1" },
      },
    );

    expect(result.status).toBe(1);
    expect(result.error).toBeUndefined();
    expect(result.stderr).not.toContain("MODULE_NOT_FOUND");
    expect(result.stderr).not.toContain("Cannot find module");
    expect(result.stderr).toContain(
      process.platform === "darwin" ? "fortress master key" : "macOS-only",
    );
  });
});
