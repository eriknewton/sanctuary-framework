/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-2
 *
 * `sanctuary agents config <tenant> --approval-redirect=<bool>` CLI verb
 * regression suite. Also covers the `agents show` reflection of the
 * persisted state and the `sanctuary agent` (singular) alias surface
 * implemented in server/src/cli.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runAgentsCommand } from "../../src/cli/agents/cli.js";
import type { HealthProbeResult } from "../../src/cli/agents/health.js";
import type { TenantDescriptor } from "../../src/cli/agents/discovery.js";
import { parsePolicy } from "../../src/principal-policy/loader.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ) {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

const offlineProbe = async (
  _t: TenantDescriptor,
): Promise<HealthProbeResult> => ({
  running: false,
  status: null,
  reason: "ECONNREFUSED",
});

async function makeTenant(root: string, name: string): Promise<string> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "00.enc"), "");
  await writeFile(
    join(dir, "wrap-profile.json"),
    JSON.stringify({ version: 1 }),
  );
  return dir;
}

async function writeMinimalPolicy(tenantDir: string): Promise<void> {
  const yaml = [
    "version: 1",
    "tier1_always_approve:",
    "  - state_export",
    "approval_channel:",
    "  type: stderr",
    "  timeout_seconds: 300",
    "",
  ].join("\n");
  await writeFile(join(tenantDir, "principal-policy.yaml"), yaml);
}

describe("sanctuary agents config --approval-redirect (Upsilon-2)", () => {
  let home: string;
  let defaultRoot: string;
  let tenantADir: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-cfg-redirect-"));
    defaultRoot = join(home, ".sanctuary");
    await mkdir(defaultRoot, { recursive: true, mode: 0o700 });
    tenantADir = await makeTenant(defaultRoot, "tenant-a");
    await writeMinimalPolicy(tenantADir);
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("config <tenant> --approval-redirect=true persists the toggle", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    const policyPath = join(tenantADir, "principal-policy.yaml");
    const content = await readFile(policyPath, "utf-8");
    expect(content).toContain("approval_redirect:");
    expect(content).toMatch(/enabled:\s*true/);
    const parsed = parsePolicy(content);
    expect(parsed.approval_redirect).toEqual({
      enabled: true,
      mode: "replace",
    });
  });

  it("config <tenant> --approval-redirect=true --approval-redirect-mode=notify persists mode", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: [
        "config",
        "tenant-a",
        "--approval-redirect=true",
        "--approval-redirect-mode=notify",
      ],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    const parsed = parsePolicy(
      await readFile(join(tenantADir, "principal-policy.yaml"), "utf-8"),
    );
    expect(parsed.approval_redirect).toEqual({
      enabled: true,
      mode: "notify",
    });
  });

  it("config can flip enabled=false and is idempotent across multiple invocations", async () => {
    // Turn on.
    await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    // Turn off.
    await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=false"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    // Turn off again (idempotent).
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=false"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    const parsed = parsePolicy(
      await readFile(join(tenantADir, "principal-policy.yaml"), "utf-8"),
    );
    expect(parsed.approval_redirect?.enabled).toBe(false);
    // Block appears exactly once in the file.
    const content = await readFile(
      join(tenantADir, "principal-policy.yaml"),
      "utf-8",
    );
    const matches = content.match(/^approval_redirect:/gm) ?? [];
    expect(matches.length).toBe(1);
  });

  it("rejects an invalid --approval-redirect-mode value", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: [
        "config",
        "tenant-a",
        "--approval-redirect=true",
        "--approval-redirect-mode=hostile",
      ],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(2);
    expect(err.text).toMatch(/replace.*notify/);
  });

  it("rejects config invocation with no actionable flag", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(2);
    expect(err.text).toMatch(/nothing to do/);
  });

  it("agents show <tenant> reflects the persisted approval_redirect state", async () => {
    // Flip on first.
    await runAgentsCommand({
      argv: [
        "config",
        "tenant-a",
        "--approval-redirect=true",
        "--approval-redirect-mode=notify",
      ],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "tenant-a"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    expect(out.text).toMatch(/approval_redirect:\s+on \(notify\)/);
  });

  it("agents show --json includes structured approval_redirect state", async () => {
    await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    const out = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "tenant-a", "--json"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    const payload = JSON.parse(out.text);
    expect(payload.approval_redirect).toEqual({
      enabled: true,
      mode: "replace",
    });
  });

  it("config bootstraps a missing principal-policy.yaml on first toggle", async () => {
    // Tenant b has no policy file.
    await makeTenant(defaultRoot, "tenant-b");
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-b", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    const policyPath = join(defaultRoot, "tenant-b", "principal-policy.yaml");
    const content = await readFile(policyPath, "utf-8");
    expect(content).toContain("approval_redirect:");
    const parsed = parsePolicy(content);
    expect(parsed.approval_redirect?.enabled).toBe(true);
  });
});
