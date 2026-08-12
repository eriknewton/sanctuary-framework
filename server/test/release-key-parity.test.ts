import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..");
const guard = join(repoRoot, "scripts", "check-release-key-parity.mjs");
const workflowPath = join(repoRoot, ".github", "workflows", "publish-on-tag.yml");
const sourcePath = join(repoRoot, "server", "src", "release-manifest.ts");
const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function run(workflow: string, source: string): string {
  return execFileSync(process.execPath, [guard, "--workflow", workflow, "--source", source], { encoding: "utf8", stdio: "pipe" });
}

describe("release signing key parity", () => {
  it("passes the real workflow and shipped-client key", () => {
    expect(execFileSync(process.execPath, [guard], { encoding: "utf8" })).toContain("public keys match");
  });

  it("refuses a workflow/client key mismatch", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanctuary-key-parity-"));
    dirs.push(dir);
    const workflow = join(dir, "publish.yml");
    const source = join(dir, "release-manifest.ts");
    writeFileSync(workflow, readFileSync(workflowPath, "utf8").replace("61YBfiq_zlbTP5rl_r_msbPk40IXJL-_PuAxlpBVeF0", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"));
    writeFileSync(source, readFileSync(sourcePath, "utf8"));
    expect(() => run(workflow, source)).toThrow(/differs from the key pinned by shipped clients/);
  });

  it("refuses duplicate key declarations instead of accepting one", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanctuary-key-parity-"));
    dirs.push(dir);
    const workflow = join(dir, "publish.yml");
    const source = join(dir, "release-manifest.ts");
    const liveWorkflow = readFileSync(workflowPath, "utf8");
    writeFileSync(workflow, liveWorkflow.replace("  RELEASE_PUBLIC_KEY_B64URL:", "  RELEASE_PUBLIC_KEY_B64URL: 61YBfiq_zlbTP5rl_r_msbPk40IXJL-_PuAxlpBVeF0\n  RELEASE_PUBLIC_KEY_B64URL:"));
    writeFileSync(source, readFileSync(sourcePath, "utf8"));
    expect(() => run(workflow, source)).toThrow(/expected exactly one workflow release public key, found 2/);
  });
});
