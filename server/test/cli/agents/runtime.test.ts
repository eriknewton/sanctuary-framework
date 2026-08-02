/**
 * Unit tests for tenant runtime.json read/write/clear.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readTenantRuntime,
  writeTenantRuntime,
  clearTenantRuntime,
  RUNTIME_FILE_NAME,
} from "../../../src/cli/agents/runtime.js";

describe("cli/agents/runtime", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-runtime-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("readTenantRuntime returns null when no file exists", async () => {
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("writes then reads a full runtime record", async () => {
    await writeTenantRuntime(dir, {
      version: "0.10.0-x",
      pid: process.pid,
      started_at: "2026-04-17T00:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: 3505,
      webhook_callback_port: 3515,
      webhook_callback_host: "127.0.0.1",
      mode: "wrap",
    });
    const got = await readTenantRuntime(dir);
    expect(got).not.toBeNull();
    expect(got!.pid).toBe(process.pid);
    expect(got!.dashboard_port).toBe(3505);
    expect(got!.webhook_callback_port).toBe(3515);
    expect(got!.mode).toBe("wrap");
  });

  it("omits webhook fields when the writer did not supply them", async () => {
    await writeTenantRuntime(dir, {
      version: "0.10.0-x",
      pid: process.pid,
      started_at: "2026-04-17T00:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      mode: "standalone",
    });
    const got = await readTenantRuntime(dir);
    expect(got!.webhook_callback_port).toBeUndefined();
    expect(got!.webhook_callback_host).toBeUndefined();
  });

  it("clearTenantRuntime removes the file", async () => {
    await writeTenantRuntime(dir, {
      version: "x",
      pid: 2,
      started_at: "2026-04-17T00:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      mode: "wrap",
    });
    await clearTenantRuntime(dir);
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("clearTenantRuntime is idempotent for missing files", async () => {
    // No file present. Should not throw.
    await clearTenantRuntime(dir);
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("readTenantRuntime rejects malformed JSON", async () => {
    await writeFile(join(dir, RUNTIME_FILE_NAME), "{ not json }");
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("readTenantRuntime rejects JSON with missing required fields", async () => {
    await writeFile(
      join(dir, RUNTIME_FILE_NAME),
      JSON.stringify({ dashboard_port: "not-a-number" })
    );
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("readTenantRuntime ignores a dead writer pid instead of trusting stale runtime.json", async () => {
    await writeFile(
      join(dir, RUNTIME_FILE_NAME),
      JSON.stringify({
        version: "0.10.0-x",
        pid: 99_999_999,
        started_at: "2026-04-17T00:00:00.000Z",
        dashboard_host: "127.0.0.1",
        dashboard_port: 3501,
        mode: "wrap",
      }),
    );
    expect(await readTenantRuntime(dir)).toBeNull();
  });

  it("persists with 0600 permissions", async () => {
    if (process.platform === "win32") return;
    await writeTenantRuntime(dir, {
      version: "x",
      pid: 2,
      started_at: "2026-04-17T00:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      mode: "wrap",
    });
    const stat = await (await import("node:fs/promises")).stat(
      join(dir, RUNTIME_FILE_NAME)
    );
    const mode = stat.mode & 0o777;
    expect(mode & 0o077).toBe(0); // no group/other bits
  });

  it("writeTenantRuntime swallows I/O errors silently", async () => {
    // Target an unwritable path — write should not throw.
    const unwritable = "/this/path/does/not/exist/anywhere-xyz";
    await expect(
      writeTenantRuntime(unwritable, {
        version: "x",
        pid: 2,
        started_at: "2026-04-17T00:00:00.000Z",
        dashboard_host: "127.0.0.1",
        dashboard_port: 3501,
        mode: "wrap",
      })
    ).resolves.toBeUndefined();
  });

  it("sanity: written JSON contains the runtime filename", async () => {
    await writeTenantRuntime(dir, {
      version: "0.10.0-x",
      pid: 99,
      started_at: "2026-04-17T00:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      mode: "wrap",
    });
    const raw = await readFile(join(dir, RUNTIME_FILE_NAME), "utf-8");
    expect(raw).toContain("0.10.0-x");
    expect(raw).toContain("dashboard_port");
  });
});
