/**
 * Regression tests for loadPrincipalPolicy error handling.
 *
 * Verifies that the loader distinguishes between:
 * - ENOENT (generates default policy, writes to disk)
 * - Malformed YAML (throws MalformedPrincipalPolicyError)
 * - Validation error (throws MalformedPrincipalPolicyError)
 * - Permission denied (throws MalformedPrincipalPolicyError)
 * - Write failure on default generation (warns, returns default)
 *
 * Closes drill finding XXX (post-merge-drill-results-2026-05-11).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, writeFile, chmod, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadPrincipalPolicy,
  MalformedPrincipalPolicyError,
  DEFAULT_POLICY,
} from "../../src/principal-policy/loader.js";

describe("loadPrincipalPolicy error handling (XXX)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("ENOENT path generates default and writes the file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-test-xxx-"));
    const policyPath = join(dir, "principal-policy.yaml");

    const policy = await loadPrincipalPolicy(dir);

    // Returns frozen default
    expect(Object.isFrozen(policy)).toBe(true);
    expect(policy.tier1_always_approve).toEqual(
      DEFAULT_POLICY.tier1_always_approve
    );
    expect(policy.tier3_always_allow).toEqual(
      DEFAULT_POLICY.tier3_always_allow
    );

    // File was written
    expect(existsSync(policyPath)).toBe(true);
    const written = await readFile(policyPath, "utf-8");
    expect(written).toContain("tier1_always_approve");
  });

  it("malformed YAML throws MalformedPrincipalPolicyError", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-test-xxx-"));
    const policyPath = join(dir, "principal-policy.yaml");

    await writeFile(policyPath, "{ invalid: [unclosed", "utf-8");

    await expect(loadPrincipalPolicy(dir)).rejects.toThrow(
      MalformedPrincipalPolicyError
    );

    try {
      await loadPrincipalPolicy(dir);
    } catch (e) {
      expect(e).toBeInstanceOf(MalformedPrincipalPolicyError);
      const err = e as MalformedPrincipalPolicyError;
      expect(err.name).toBe("MalformedPrincipalPolicyError");
      expect(err.policyPath).toBe(policyPath);
      expect(err.message).toContain(policyPath);
    }
  });

  it("validation error throws MalformedPrincipalPolicyError with reason", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-test-xxx-"));
    const policyPath = join(dir, "principal-policy.yaml");

    // Valid YAML but missing required top-level fields (just a bare string)
    await writeFile(policyPath, "just_a_string", "utf-8");

    await expect(loadPrincipalPolicy(dir)).rejects.toThrow(
      MalformedPrincipalPolicyError
    );

    try {
      await loadPrincipalPolicy(dir);
    } catch (e) {
      const err = e as MalformedPrincipalPolicyError;
      expect(err.policyPath).toBe(policyPath);
      expect(err.reason.length).toBeGreaterThan(0);
    }
  });

  it("permission denied throws MalformedPrincipalPolicyError", async () => {
    if (process.platform === "win32") return; // skip on Windows

    const dir = await mkdtemp(join(tmpdir(), "sanctuary-test-xxx-"));
    const policyPath = join(dir, "principal-policy.yaml");

    await writeFile(policyPath, "version: 1\n", "utf-8");
    await chmod(policyPath, 0o000);

    try {
      await expect(loadPrincipalPolicy(dir)).rejects.toThrow(
        MalformedPrincipalPolicyError
      );

      try {
        await loadPrincipalPolicy(dir);
      } catch (e) {
        const err = e as MalformedPrincipalPolicyError;
        expect(err.reason).toContain("read failed");
      }
    } finally {
      // Restore permissions so tmpdir cleanup works
      await chmod(policyPath, 0o600);
    }
  });

  it("write failure on default generation logs warning and returns default", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-test-xxx-"));

    // Make the directory read-only so writeFile will fail
    if (process.platform === "win32") return; // skip on Windows
    await chmod(dir, 0o555);

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const policy = await loadPrincipalPolicy(dir);

      // Still returns the default
      expect(Object.isFrozen(policy)).toBe(true);
      expect(policy.tier1_always_approve).toEqual(
        DEFAULT_POLICY.tier1_always_approve
      );

      // Warning was logged
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const warnMsg = warnSpy.mock.calls[0][0] as string;
      expect(warnMsg).toContain("could not write default principal policy");
      expect(warnMsg).toContain(dir);
    } finally {
      await chmod(dir, 0o755);
    }
  });
});
