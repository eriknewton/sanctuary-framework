import { describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

function run(executable: string, args: string[]): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}> {
  return new Promise((settle, reject) => {
    const env = { ...process.env };
    delete env.SANCTUARY_PASSPHRASE;
    delete env.SANCTUARY_RECOVERY_KEY;
    const child = spawn(executable, args, {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.once("error", reject);
    child.once("close", (code, signal) => settle({ code, signal, stdout, stderr }));
  });
}

describe("production build custody lock runtime", () => {
  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "the shipped Node CLI acquires and releases the kernel-backed init lock",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "prod-cli-custody-lock-"));
      try {
        const cli = resolve(process.cwd(), "dist/cli.js");
        const firstLine = (await readFile(cli, "utf8")).split("\n", 1)[0];
        expect(firstLine).toBe("#!/usr/bin/env node");
        expect(process.release.name).toBe("node");
        const fortress = join(root, "fortress");
        const recoveryOut = join(root, "recovery-key.txt");
        const result = await run(process.execPath, [
          cli,
          "init",
          "--fortress",
          fortress,
          "--no-confirm",
          "--no-pin",
          "--no-identity",
          "--no-provision-local-intelligence",
          "--recovery-out",
          recoveryOut,
        ]);
        expect(result, result.stderr || result.stdout).toMatchObject({
          code: 0,
          signal: null,
        });
        await expect(stat(join(fortress, "state", "_meta", "custody-envelope.enc")))
          .resolves.toBeDefined();
        await expect(stat(recoveryOut)).resolves.toBeDefined();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
