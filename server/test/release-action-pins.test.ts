import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..");
const guard = join(repoRoot, "scripts", "check-release-action-pins.mjs");
const dirs: string[] = [];
const checkoutSha = "3d3c42e5aac5ba805825da76410c181273ba90b1";

function workflowDir(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "sanctuary-action-pins-"));
  dirs.push(root);
  const dir = join(root, "workflows");
  mkdirSync(dir);
  for (const [name, source] of Object.entries(files)) writeFileSync(join(dir, name), source);
  return dir;
}

function run(dir: string): string {
  return execFileSync(process.execPath, [guard, "--workflows-dir", dir], { encoding: "utf8", stdio: "pipe" });
}

function composite(dir: string, name: string, source: string): void {
  const actionDir = join(dir, "..", "actions", name);
  mkdirSync(actionDir, { recursive: true });
  writeFileSync(join(actionDir, "action.yml"), source);
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("release-sensitive action pin guard", () => {
  it("passes the repository's real release-sensitive workflows", () => {
    expect(execFileSync(process.execPath, [guard], { encoding: "utf8" })).toContain("Release action pin check passed");
  });

  it("refuses a mutable action ref on a tag-triggered workflow", () => {
    const dir = workflowDir({
      "release.yml": `on:\n  push:\n    tags: ["v*"]\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/release\.yml:7 actions\/checkout@v7/);
  });

  it("refuses mutable refs on manually privileged workflows while ignoring an ordinary read-only PR workflow", () => {
    const dir = workflowDir({
      "manual-write.yml": `on:\n  workflow_dispatch: {}\npermissions:\n  issues: write\njobs:\n  report:\n    steps:\n      - uses: actions/checkout@main\n`,
      "pr-read.yml": `on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7\n`,
      "tag-pinned.yml": `on:\n  push:\n    tags: ["v*"]\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@${checkoutSha}\n`,
    });
    expect(() => run(dir)).toThrow(/manual-write\.yml:8 actions\/checkout@main/);
  });

  it("refuses a mutable action ref on a scheduled privileged workflow", () => {
    const dir = workflowDir({
      "scheduled-write.yml": `on:\n  schedule:\n    - cron: "0 2 * * *"\npermissions:\n  contents: write\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/scheduled-write\.yml:9 actions\/checkout@v7/);
  });

  it("refuses a mutable action ref on pull_request_target even without explicit write permissions", () => {
    const dir = workflowDir({
      "target.yml": `on:\n  pull_request_target:\njobs:\n  inspect:\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/target\.yml:6 actions\/checkout@v7/);
  });

  it("refuses a mutable action ref on a callable privileged workflow", () => {
    const dir = workflowDir({
      "callable.yml": `on:\n  workflow_call:\npermissions:\n  id-token: write\njobs:\n  publish:\n    steps:\n      - uses: actions/setup-node@v7\n`,
    });
    expect(() => run(dir)).toThrow(/callable\.yml:8 actions\/setup-node@v7/);
  });

  it("refuses a mutable action ref for any explicitly privileged trigger", () => {
    const dir = workflowDir({
      "repository-dispatch.yml": `on:\n  repository_dispatch:\npermissions:\n  write-all\njobs:\n  mutate:\n    steps:\n      - uses: actions/checkout@main\n`,
    });
    expect(() => run(dir)).toThrow(/repository-dispatch\.yml:8 actions\/checkout@main/);
  });

  it("refuses inherited workflow permissions even when a job declares read-only permissions", () => {
    const dir = workflowDir({
      "manual-default.yml": `on:\n  workflow_dispatch: {}\njobs:\n  inspect:\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/manual-default\.yml:8 actions\/checkout@v7/);
  });

  it("refuses inherited permissions on a reusable workflow until they are explicit", () => {
    const dir = workflowDir({
      "callable-default.yml": `on:\n  workflow_call:\njobs:\n  inspect:\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/callable-default\.yml:6 actions\/checkout@v7/);
  });

  it("refuses write authority in permission scopes added by GitHub later", () => {
    const dir = workflowDir({
      "pages.yml": `on:\n  push:\npermissions:\n  pages: write\njobs:\n  deploy:\n    steps:\n      - uses: actions/checkout@v7\n`,
    });
    expect(() => run(dir)).toThrow(/pages\.yml:8 actions\/checkout@v7/);
  });

  it("refuses mutable external actions hidden behind a local composite", () => {
    const dir = workflowDir({
      "release.yml": `on:\n  workflow_dispatch: {}\npermissions:\n  contents: write\njobs:\n  publish:\n    steps:\n      - uses: ./.github/actions/release-helper\n`,
    });
    composite(dir, "release-helper", `name: Release helper\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v7\n`);
    expect(() => run(dir)).toThrow(/actions\/release-helper\/action\.yml:5 actions\/setup-node@v7/);
  });
});
