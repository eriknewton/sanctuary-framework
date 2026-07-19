import { mkdtemp, mkdir, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { canonicalizeHomeDirectory } from "../../src/wrap/auto-provision.js";

describe("wrap/auto-provision canonicalizeHomeDirectory", () => {
  let dir: string;
  let realRoot: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-account-home-"));
    realRoot = await realpath(dir);
    await mkdir(join(dir, "private", "var"), { recursive: true });
    await symlink("private/var", join(dir, "var"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("treats symlinked /var and resolved /private/var forms as the same real filesystem path", async () => {
    await mkdir(join(dir, "private", "var", "sanctuary-agents", "sanctuary-hermes"), {
      recursive: true,
    });

    const viaVar = await canonicalizeHomeDirectory(
      join(dir, "var", "sanctuary-agents", "sanctuary-hermes"),
    );
    const viaPrivateVar = await canonicalizeHomeDirectory(
      join(dir, "private", "var", "sanctuary-agents", "sanctuary-hermes"),
    );

    expect(viaVar).toBe(viaPrivateVar);
    expect(viaVar).toBe(
      join(realRoot, "private", "var", "sanctuary-agents", "sanctuary-hermes"),
    );
  });

  it("resolves a nonexistent parent by anchoring at the longest existing prefix", async () => {
    const canonical = await canonicalizeHomeDirectory(
      join(dir, "var", "sanctuary-agents", "missing-parent", "sanctuary-hermes"),
    );

    expect(canonical).toBe(
      join(realRoot, "private", "var", "sanctuary-agents", "missing-parent", "sanctuary-hermes"),
    );
  });

  it("normalizes a '..' escape so callers can compare or reject the escaped target", async () => {
    const canonical = await canonicalizeHomeDirectory(
      join(dir, "var", "sanctuary-agents", "..", "outside"),
    );

    expect(canonical).toBe(join(realRoot, "private", "var", "outside"));
  });

  it("fails closed when realpath fails for a reason other than a missing prefix", async () => {
    const err = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
    err.code = "EACCES";

    await expect(
      canonicalizeHomeDirectory("/var/sanctuary-agents/sanctuary-hermes", async () => {
        throw err;
      }),
    ).rejects.toThrow(/EACCES/);
  });
});
