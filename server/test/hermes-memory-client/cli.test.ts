// CLI failure paths keep the memory facade isolated from ordinary Sanctuary boot.
import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";
const run = promisify(execFile);
const cli = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));

describe("isolated memory CLI", () => {
  it("clientFailureNeverBootsOrdinarySanctuary", async () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("hermes-memory-client");
    const root = await mkdtemp("/tmp/hmc-");
    const guard = `${root}/guard.cjs`;
    await writeFile(guard, `const cp=require('node:child_process');for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync'])cp[key]=()=>{throw Error('forbidden subprocess');};require('node:module').syncBuiltinESMExports();`);
    try {
      for (const args of [["--bad"], ["--socket", "/tmp/no.sock"], ["--fortress", root], ["--help"]]) {
        const result = await run(process.execPath, ["--import", "tsx", "--require", guard, cli, "hermes-memory-client", ...args], {
          timeout: 10_000, env: { HOME: root, PATH: process.env.PATH, SANCTUARY_NO_UPDATE_CHECK: "1" },
        }).then(result => ({ ...result, code: 0 })).catch(error => error as { stdout: string; stderr: string; code: number });
        expect(result.code, "clientFailureNeverBootsOrdinarySanctuary").toBe(64);
        expect(result.stdout, "clientFailureNeverBootsOrdinarySanctuary").toBe("");
        expect(result.stderr, "clientFailureNeverBootsOrdinarySanctuary").toBe("");
      }
      expect(await readdir(root), "clientFailureNeverBootsOrdinarySanctuary").toEqual(["guard.cjs"]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it("bridgeDownIsClosedMcpFailure", async () => {
    const root = await mkdtemp("/tmp/hmc-");
    const guard = `${root}/guard.cjs`;
    await writeFile(guard, `const cp=require('node:child_process');for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync'])cp[key]=()=>{throw Error('forbidden subprocess');};require('node:module').syncBuiltinESMExports();const net=require('node:net');const connect=net.Socket.prototype.connect;net.Socket.prototype.connect=function(...args){if(typeof args[0]==='string')args[0]=${JSON.stringify(root + "/absent.sock")};return connect.apply(this,args);};`);
    try {
      const result = await run(process.execPath, ["--import", "tsx", "--require", guard, cli, "hermes-memory-client"], {
        timeout: 10_000, env: { HOME: root, PATH: process.env.PATH, SANCTUARY_NO_UPDATE_CHECK: "1" },
      }).then(result => ({ ...result, code: 0 })).catch(error => error as { stdout: string; stderr: string; code: number });
      expect(result.stdout, "bridgeDownIsClosedMcpFailure").toBe("");
      expect(result.stderr, "bridgeDownIsClosedMcpFailure").toBe("");
      expect(result.code).toBe(process.platform === "darwin" ? 0 : 64);
      expect(await readdir(root), "bridgeDownIsClosedMcpFailure").toEqual(["guard.cjs"]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
