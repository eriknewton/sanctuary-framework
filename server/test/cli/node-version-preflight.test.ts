import { describe, expect, it, vi } from "vitest";
import { createRequire } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import {
  assertSupportedNodeVersion,
  checkNodeVersion,
  MIN_NODE_MAJOR,
  MIN_NODE_VERSION,
} from "../../src/cli/node-version.js";
import { runDoctorChecks } from "../../src/cli/doctor.js";

const require = createRequire(import.meta.url);
const serverPackage = require("../../package.json") as {
  engines: { node: string };
};

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

describe("node version preflight", () => {
  it("fails closed on unsupported Node with an actionable stderr message", () => {
    const err = new Capture();
    const exit = vi.fn((code: number): never => {
      throw new Error(`process.exit:${code}`);
    });

    expect(() =>
      assertSupportedNodeVersion("20.11.0", { err, exit }),
    ).toThrow("process.exit:1");

    const message = err.text();
    expect(exit).toHaveBeenCalledWith(1);
    expect(message).toContain(`Sanctuary requires Node.js ${MIN_NODE_MAJOR}.x or later.`);
    expect(message).toContain("You are running Node.js 20.11.0.");
    expect(message).toContain("Please upgrade Node.js and run the command again.");
    expect(message).not.toContain("—");
    expect(message.toLowerCase()).not.toContain("sovereignty");
  });

  it("is a no-op on the minimum and higher supported versions", () => {
    const err = new Capture();
    const exit = vi.fn((code: number): never => {
      throw new Error(`process.exit:${code}`);
    });

    expect(() =>
      assertSupportedNodeVersion(`${MIN_NODE_MAJOR}.0.0`, { err, exit }),
    ).not.toThrow();
    expect(() =>
      assertSupportedNodeVersion(`${MIN_NODE_MAJOR + 1}.0.0`, { err, exit }),
    ).not.toThrow();
    expect(exit).not.toHaveBeenCalled();
    expect(err.text()).toBe("");
  });

  it("keeps the preflight minimum tied to server package engines.node", () => {
    const match = /^>=(\d+\.\d+\.\d+)$/.exec(serverPackage.engines.node);
    expect(match).not.toBeNull();
    expect(MIN_NODE_VERSION).toBe(match?.[1]);
    expect(MIN_NODE_MAJOR).toBe(Number(match?.[1].split(".")[0]));
  });

  it("reports a doctor FAIL for an injected unsupported Node version", async () => {
    const checks = await runDoctorChecks({
      storagePath: join(tmpdir(), "sanctuary-node-preflight-missing"),
      env: {},
      platform: "linux",
      nodeVersion: "20.11.0",
    });

    const nodeCheck = checks.find((check) => check.name === "node version");
    expect(nodeCheck).toBeDefined();
    expect(nodeCheck?.status).toBe("FAIL");
    expect(nodeCheck?.message).toBe(checkNodeVersion("20.11.0").message);
    expect(nodeCheck?.hint).toContain(`${MIN_NODE_MAJOR}.x or later`);
  });

  it("reports a doctor OK for an injected supported Node version", async () => {
    const checks = await runDoctorChecks({
      storagePath: join(tmpdir(), "sanctuary-node-preflight-missing"),
      env: {},
      platform: "linux",
      nodeVersion: `${MIN_NODE_MAJOR}.0.0`,
    });

    const nodeCheck = checks.find((check) => check.name === "node version");
    expect(nodeCheck).toBeDefined();
    expect(nodeCheck?.status).toBe("OK");
    expect(nodeCheck?.message).toContain(`Node.js ${MIN_NODE_MAJOR}.0.0`);
    expect(nodeCheck?.hint).toBe("none");
  });
});
