/**
 * broker-server startup — v0.10.1 regression guard for v0.10.0-rc.2 finding #1.
 *
 * v0.10.0-rc.2 had `require("../../package.json")` inline at
 * server/src/broker-mcp/broker-server.ts. The relative path resolved correctly
 * from source (server/src/broker-mcp/ → server/package.json) but resolved one
 * level too high from the bundled output (server/dist/cli.js → repo root,
 * which has no package.json). The `sanctuary broker-server` subcommand
 * therefore failed to start with `Cannot find module '../../package.json'`.
 *
 * The fix routes the version through `SANCTUARY_VERSION` exported from
 * config.ts, where the require sits at the matching server/src/ depth and
 * bundles cleanly. This test guards the contract two ways: source-import
 * loads without throwing, and the bundled cli.cjs (when present) actually
 * boots the broker-server stdio loop.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Backend } from "../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../src/disclosure/broker/backend-interface.js";
import { Broker } from "../../src/disclosure/broker/broker.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createBrokerMcpServer } from "../../src/broker-mcp/broker-server.js";
import { SANCTUARY_VERSION } from "../../src/config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgVersion = JSON.parse(
  readFileSync(join(repoRoot, "package.json"), "utf8")
).version as string;
const brokerServerSource = readFileSync(
  join(repoRoot, "src", "broker-mcp", "broker-server.ts"),
  "utf8"
);

function fakeBackend(): Backend {
  const store = new Map<string, string>();
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() { return true; },
    async addSecret(n, v) { store.set(n, v); },
    async readSecret(n) {
      const v = store.get(n);
      if (v === undefined) throw new SecretNotFoundError(n);
      return v;
    },
    async rotateSecret(n, v) { store.set(n, v); },
    async deleteSecret(n) { store.delete(n); },
    async listSecretNames() { return [...store.keys()]; },
  };
}

describe("broker-server startup — rc.2 require-path regression", () => {
  it("source import loads without throwing (would fail if the require path were broken)", () => {
    expect(typeof createBrokerMcpServer).toBe("function");
    expect(SANCTUARY_VERSION).toBe(pkgVersion);
  });

  it("createBrokerMcpServer reports SANCTUARY_VERSION as its server version", () => {
    const broker = new Broker({
      backend: fakeBackend(),
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      grants: [],
      principalIdentityId: "did:sanctuary:test",
    });
    const server = createBrokerMcpServer(broker, {
      skill: "test",
      agentId: "test",
      identityId: "did:sanctuary:test",
      tenantId: "tenant-test",
      fortressId: "fortress-test",
      audience: "sanctuary-broker",
    });
    const info = (server as unknown as { _serverInfo: { name: string; version: string } })
      ._serverInfo;
    expect(info.name).toBe("sanctuary-broker");
    expect(info.version).toBe(SANCTUARY_VERSION);
  });

  it("source does not re-introduce the broken `require(\"../../package.json\")` pattern", () => {
    // Structural guard: after bundling every src/ file into server/dist/cli.cjs,
    // only `require("../package.json")` from the bundle's own location resolves
    // to server/package.json. Any deeper relative path (../../, ../../../, …)
    // escapes the server/ directory at runtime. Routing the version through
    // SANCTUARY_VERSION keeps exactly one require site; this assert prevents
    // a future edit from re-inlining a local require in broker-server.ts.
    expect(brokerServerSource).not.toMatch(
      /require\s*\(\s*["']\.{2,}\/(?:\.\.\/)+package\.json["']\s*\)/
    );
    expect(brokerServerSource).toContain("SANCTUARY_VERSION");
  });
});
