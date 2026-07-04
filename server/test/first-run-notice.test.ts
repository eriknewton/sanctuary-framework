/**
 * Tests for the zero-outbound-by-default first-run notice.
 *
 * Fail-open contract: any I/O error (missing directory, permission denied,
 * read-only filesystem) must never throw or block; the notice is
 * best-effort UX, never a gate.
 */

import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  printFirstRunNoticeOnce,
  ZERO_OUTBOUND_NOTICE,
} from "../src/first-run-notice.js";

class Capture {
  chunks: string[] = [];
  write(chunk: string): boolean {
    this.chunks.push(chunk);
    return true;
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("printFirstRunNoticeOnce", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      // Restore writable perms before cleanup in case a test locked the dir down.
      await chmod(dir, 0o700).catch(() => {});
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function makeFortress(): Promise<string> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-first-run-"));
    tempDirs.push(fortress);
    return fortress;
  }

  it("prints the notice once when the marker is absent", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    await printFirstRunNoticeOnce(fortress, out);
    expect(out.text()).toContain(ZERO_OUTBOUND_NOTICE);
    expect(out.text()).toContain("check-updates");
  });

  it("creates a marker file so it never prints again", async () => {
    const fortress = await makeFortress();
    await printFirstRunNoticeOnce(fortress, new Capture());
    const markerPath = join(fortress, "first-run-notice-shown");
    const s = await stat(markerPath);
    expect(s.isFile()).toBe(true);
  });

  it("is silent on the second call once the marker exists", async () => {
    const fortress = await makeFortress();
    await printFirstRunNoticeOnce(fortress, new Capture());

    const second = new Capture();
    await printFirstRunNoticeOnce(fortress, second);
    expect(second.text()).toBe("");
  });

  it("fails open (does not throw) when the storage path does not exist and cannot be created", async () => {
    // A path nested under a directory that itself does not exist: mkdir
    // with recursive:true would normally handle this, but simulate a
    // genuinely unwritable location by pointing at a path under a file
    // (not a directory), which no mkdir -p can ever create.
    const parent = await makeFortress();
    const blockerFile = join(parent, "blocker");
    await import("node:fs/promises").then(({ writeFile }) =>
      writeFile(blockerFile, "not a directory"),
    );
    const impossiblePath = join(blockerFile, "nested", "fortress");

    const out = new Capture();
    await expect(
      printFirstRunNoticeOnce(impossiblePath, out),
    ).resolves.toBeUndefined();
    // Best-effort: the notice may still have been written to the sink even
    // though the marker could not be persisted; the only hard requirement
    // is that startup (this call) never throws.
  });

  it("fails open when the marker directory is read-only", async () => {
    const fortress = await makeFortress();
    await chmod(fortress, 0o500); // read+execute, no write
    const out = new Capture();
    await expect(
      printFirstRunNoticeOnce(fortress, out),
    ).resolves.toBeUndefined();
    expect(out.text()).toContain(ZERO_OUTBOUND_NOTICE);
  });

  it("never throws even if the output sink's write throws", async () => {
    const fortress = await makeFortress();
    const throwingSink = {
      write(): boolean {
        throw new Error("broken stderr");
      },
    };
    await expect(
      printFirstRunNoticeOnce(fortress, throwingSink),
    ).resolves.toBeUndefined();
    // The marker should still be created despite the sink failing.
    const markerPath = join(fortress, "first-run-notice-shown");
    const s = await stat(markerPath);
    expect(s.isFile()).toBe(true);
  });
});
