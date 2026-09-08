/**
 * Sanctuary v1.3 WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-2
 *
 * `sanctuary agents config <tenant> --approval-redirect=<bool>` CLI verb
 * regression suite. Also covers the `agents show` reflection of the
 * persisted state and the `sanctuary agent` (singular) alias surface
 * implemented in server/src/cli.ts.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, mkdir, symlink, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { runAgentsCommand } from "../../src/cli/agents/cli.js";
import type { HealthProbeResult } from "../../src/cli/agents/health.js";
import type { TenantDescriptor } from "../../src/cli/agents/discovery.js";
import { parsePolicy } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";

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

const configEnv = { SANCTUARY_PASSPHRASE: "test-passphrase" };

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
  let appendCriticalSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-cfg-redirect-"));
    defaultRoot = join(home, ".sanctuary");
    await mkdir(defaultRoot, { recursive: true, mode: 0o700 });
    tenantADir = await makeTenant(defaultRoot, "tenant-a");
    await writeMinimalPolicy(tenantADir);
    appendCriticalSpy = vi
      .spyOn(AuditLog.prototype, "appendCritical")
      .mockResolvedValue(undefined);
  });

  afterEach(async () => {
    appendCriticalSpy.mockRestore();
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
      env: configEnv,
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
    // Execution-time pin of the effect-timing guidance (not just source
    // text): the running CLI must state next-start semantics and must not
    // claim next-request effect. Must match the message in
    // src/cli/agents/cli.ts (structure pin: agents-config-restart-required-message.test.ts).
    expect(out.text).toContain(
      "Persisted. Takes effect the next time this tenant's Sanctuary server starts",
    );
    expect(out.text).not.toMatch(/next gate request/i);
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
      env: configEnv,
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

  it("config refuses to downgrade approval_redirect.enabled after it is enabled", async () => {
    // Turn on.
    await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
      env: configEnv,
    });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=false"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
      env: configEnv,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("principal policy update refused");
    const parsed = parsePolicy(
      await readFile(join(tenantADir, "principal-policy.yaml"), "utf-8"),
    );
    expect(parsed.approval_redirect?.enabled).toBe(true);
    // Block appears exactly once in the file.
    const content = await readFile(
      join(tenantADir, "principal-policy.yaml"),
      "utf-8",
    );
    const matches = content.match(/^approval_redirect:/gm) ?? [];
    expect(matches.length).toBe(1);
  });

  it("config is idempotent when keeping approval_redirect disabled", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=false"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
      env: configEnv,
    });

    expect(code).toBe(0);
    const parsed = parsePolicy(
      await readFile(join(tenantADir, "principal-policy.yaml"), "utf-8"),
    );
    expect(parsed.approval_redirect?.enabled).toBe(false);
  });

  it("config refuses to persist when the required audit append fails", async () => {
    appendCriticalSpy.mockRejectedValueOnce(new Error("audit unavailable"));
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-a", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
      env: configEnv,
    });

    expect(code).toBe(1);
    expect(err.text).toContain("principal policy update refused");
    const content = await readFile(join(tenantADir, "principal-policy.yaml"), "utf-8");
    expect(content).not.toContain("approval_redirect:");
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
      env: configEnv,
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
      env: configEnv,
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

  it("never reads the tenant policy through a symlink planted at its path", async () => {
    // `agents show` read the policy with a symlink-following readFile while
    // doctor, init and the runtime use the no-follow custody read, so this verb
    // rendered the approval-redirect state of a file the fortress does not own
    // (AGENTS.md MUST-NEVER #7: the runtime freezes whatever this path
    // resolves to). Failure mode from the outside: `agents show` reports the
    // planted policy's tiers and looks entirely healthy.
    const tenantDir = await makeTenant(defaultRoot, "tenant-planted");
    const outside = join(home, "attacker-policy.yaml");
    await writeFile(
      outside,
      [
        "version: 1",
        "tier1_always_approve:",
        "  - state_export",
        "approval_channel:",
        "  type: stderr",
        "  timeout_seconds: 300",
        "approval_redirect:",
        "  enabled: true",
        "  mode: notify",
        "",
      ].join("\n"),
    );
    await symlink(outside, join(tenantDir, "principal-policy.yaml"));

    const out = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "tenant-planted", "--json"],
      home,
      probe: offlineProbe,
      out: out as unknown as NodeJS.WritableStream,
      err: new StringWritable() as unknown as NodeJS.WritableStream,
    });
    expect(code).toBe(0);
    // The planted file says on/notify. The no-follow read never sees it.
    expect(JSON.parse(out.text).approval_redirect).toEqual({
      enabled: false,
      mode: "replace",
    });
  });

  it("refuses to rewrite a policy path occupied by a symlink", async () => {
    // The mutation path read its base text with the same following readFile, so
    // a planted link imported a foreign policy's tiers into the rewrite. The
    // bootstrap-default fallback must never cover this shape either.
    const tenantDir = await makeTenant(defaultRoot, "tenant-planted-write");
    const outside = join(home, "attacker-write-policy.yaml");
    await writeFile(
      outside,
      ["version: 1", "tier1_always_approve:", "  - state_export", ""].join("\n"),
    );
    await symlink(outside, join(tenantDir, "principal-policy.yaml"));

    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["config", "tenant-planted-write", "--approval-redirect=true"],
      home,
      probe: offlineProbe,
      out: new StringWritable() as unknown as NodeJS.WritableStream,
      err: err as unknown as NodeJS.WritableStream,
      env: configEnv,
    });
    expect(code).not.toBe(0);
    // The refusal has to name the READ, not the write: the write site already
    // refused the link, but only after the mutation had built its rewrite from
    // the planted file's text.
    expect(err.text).toContain("not a regular file");
    expect(await readFile(outside, "utf-8")).not.toContain("approval_redirect");
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
      env: configEnv,
    });
    expect(code).toBe(0);
    const policyPath = join(defaultRoot, "tenant-b", "principal-policy.yaml");
    const content = await readFile(policyPath, "utf-8");
    expect(content).toContain("approval_redirect:");
    const parsed = parsePolicy(content);
    expect(parsed.approval_redirect?.enabled).toBe(true);
  });
});
