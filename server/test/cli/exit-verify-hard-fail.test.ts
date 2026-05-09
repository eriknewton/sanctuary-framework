/**
 * v1.2.1 (Finding PPP): exit verify and exit import must hard-fail on
 * missing manifest.json instead of soft-failing with verified=false.
 */
import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { verifyExitBundle, InvalidExitBundleError } from "../../src/exit/verifier.js";

describe("exit verify/import hard-fail on missing manifest (Finding PPP)", () => {
  let tmpDir: string;

  it("verifyExitBundle throws InvalidExitBundleError on empty dir", async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "sanctuary-ppp-"));
    await expect(verifyExitBundle(tmpDir)).rejects.toThrow(InvalidExitBundleError);
    await expect(verifyExitBundle(tmpDir)).rejects.toThrow(/manifest\.json missing/);
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("verifyExitBundle throws InvalidExitBundleError on nonexistent dir", async () => {
    await expect(
      verifyExitBundle("/tmp/sanctuary-ppp-nonexistent-dir"),
    ).rejects.toThrow(InvalidExitBundleError);
  });
});
