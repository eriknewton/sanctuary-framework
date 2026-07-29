/**
 * v1.2.1 (Finding HHH): verify dist/templates/ ships in the npm artifact.
 * Runs `npm pack`, extracts, and confirms template directories exist.
 */
import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverDir = join(__dirname, "..", "..");

describe("template-list tarball (Finding HHH)", () => {
  let tmpDir: string;

  it("npm pack artifact contains dist/templates/research-assistant/", async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "sanctuary-hhh-"));

    // Pack the server package
    const tarballName = execSync("npm pack --pack-destination " + tmpDir, {
      cwd: serverDir,
      encoding: "utf-8",
      env: { ...process.env, npm_config_cache: join(tmpDir, ".npm-cache") },
    }).trim();

    // Extract
    execSync(`tar xzf "${tarballName}"`, { cwd: tmpDir });

    // Verify template directories exist
    const templateDir = join(tmpDir, "package", "dist", "templates");
    const entries = await readdir(templateDir);
    expect(entries).toContain("research-assistant");
    expect(entries).toContain("handoff-coordinator");
    expect(entries).toContain("planner");

    // Verify template files inside
    const raDir = join(templateDir, "research-assistant");
    const raFiles = await readdir(raDir);
    expect(raFiles).toContain("template.json");
    expect(raFiles).toContain("policy.md");
    expect(raFiles).toContain("defaults.json");

    await rm(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    // `npm pack` boots a fresh npm + tars dist/; under the full suite's parallel
    // load on a constrained machine that can exceed the old 30s budget. Use the
    // same generous timeout as the other CLI-subprocess tests.
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
