/**
 * Tests for `sanctuary check-updates` — the explicit-intent bypass of the
 * zero-outbound-by-default gate. Running this command IS the operator's
 * request, so it must always perform the check regardless of the
 * SANCTUARY_UPDATE_CHECK / SANCTUARY_NO_UPDATE_CHECK env defaults.
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { Writable } from "node:stream";
import { runCheckUpdatesCommand } from "../../src/cli/check-updates.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("sanctuary check-updates", () => {
  let savedNoUpdate: string | undefined;
  let savedUpdate: string | undefined;

  beforeEach(() => {
    savedNoUpdate = process.env.SANCTUARY_NO_UPDATE_CHECK;
    savedUpdate = process.env.SANCTUARY_UPDATE_CHECK;
  });

  afterEach(() => {
    if (savedNoUpdate !== undefined)
      process.env.SANCTUARY_NO_UPDATE_CHECK = savedNoUpdate;
    else delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    if (savedUpdate !== undefined)
      process.env.SANCTUARY_UPDATE_CHECK = savedUpdate;
    else delete process.env.SANCTUARY_UPDATE_CHECK;
  });

  it("--help prints usage and returns 0 without checking anything", async () => {
    const out = new Capture();
    let fetchCalled = false;
    const code = await runCheckUpdatesCommand({
      argv: ["--help"],
      out,
      fetchLatestVersionFn: async () => {
        fetchCalled = true;
        return null;
      },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("sanctuary check-updates");
    expect(fetchCalled).toBe(false);
  });

  it("runs the check even when neither env var is set (the zero-outbound default)", async () => {
    delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    delete process.env.SANCTUARY_UPDATE_CHECK;
    const out = new Capture();
    const code = await runCheckUpdatesCommand({
      argv: [],
      out,
      currentVersion: "1.0.0",
      fetchLatestVersionFn: async () => "2.0.0",
      fetchLatestSignedManifestFn: async () => null,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("Update available: 1.0.0 -> 2.0.0");
    expect(out.text()).toContain("npx @sanctuary-framework/mcp-server@2.0.0");
  });

  it("runs the check even when SANCTUARY_NO_UPDATE_CHECK=1 is set (explicit intent bypasses the alias)", async () => {
    process.env.SANCTUARY_NO_UPDATE_CHECK = "1";
    delete process.env.SANCTUARY_UPDATE_CHECK;
    const out = new Capture();
    const code = await runCheckUpdatesCommand({
      argv: [],
      out,
      currentVersion: "1.0.0",
      fetchLatestVersionFn: async () => null,
      fetchLatestSignedManifestFn: async () => null,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("up to date");
  });

  it("reports up to date when the registry has nothing newer", async () => {
    const out = new Capture();
    const code = await runCheckUpdatesCommand({
      argv: [],
      out,
      currentVersion: "1.0.0",
      fetchLatestVersionFn: async () => null,
      fetchLatestSignedManifestFn: async () => null,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("npm registry: up to date");
  });

  it("reports offline-or-unreachable when the fetch throws", async () => {
    const out = new Capture();
    const code = await runCheckUpdatesCommand({
      argv: [],
      out,
      currentVersion: "1.0.0",
      fetchLatestVersionFn: async () => {
        throw new Error("ECONNREFUSED");
      },
      fetchLatestSignedManifestFn: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("npm registry: offline or unreachable");
    expect(out.text()).toContain(
      "Signed release manifest: offline or unreachable",
    );
  });

  it("reports the signed-manifest result as not verifiable when the manifest fails verification", async () => {
    const out = new Capture();
    const code = await runCheckUpdatesCommand({
      argv: [],
      out,
      currentVersion: "1.0.0",
      fetchLatestVersionFn: async () => null,
      fetchLatestSignedManifestFn: async () => ({ not: "a valid manifest" }),
    });
    expect(code).toBe(0);
    expect(out.text()).toContain(
      "Signed release manifest: not verifiable against the pinned release-signing key",
    );
  });
});
