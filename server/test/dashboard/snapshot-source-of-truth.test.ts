import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it, vi } from "vitest";
import { createIdentity } from "../../src/core/identity.js";
import { deriveMasterKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { IdentityManager } from "../../src/l1-cognitive/tools.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { handleRequest } from "../../src/dashboard/api.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import { runIdentityCommand } from "../../src/cli/identity.js";

class StringWritable extends Writable {
  chunks: string[] = [];

  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }

  get text(): string {
    return this.chunks.join("");
  }
}

function mockReq(): IncomingMessage {
  return {
    url: "/api/snapshot",
    method: "GET",
    headers: { host: "localhost" },
  } as unknown as IncomingMessage;
}

function mockRes(): ServerResponse & {
  _status: number;
  _body: string;
  _headers: Record<string, string>;
} {
  const res = {
    _status: 0,
    _body: "",
    _headers: {} as Record<string, string>,
    writeHead: vi.fn((status: number, headers?: Record<string, string>) => {
      res._status = status;
      if (headers) Object.assign(res._headers, headers);
    }),
    end: vi.fn((body?: string) => {
      res._body = body ?? "";
    }),
  };
  return res as unknown as ServerResponse & {
    _status: number;
    _body: string;
    _headers: Record<string, string>;
  };
}

describe("dashboard snapshot identity source-of-truth", () => {
  it("matches sanctuary identity show after wrap identity sources are attached", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-snapshot-sot-"));
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const passphrase = "snapshot-source-of-truth-passphrase";
    const derived = await deriveMasterKey(passphrase);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params))
    );

    const identityManager = new IdentityManager(storage, derived.key);
    await identityManager.load();
    const { storedIdentity, publicIdentity } = createIdentity(
      "default",
      derivePurposeKey(derived.key, "identity-encryption"),
      "passphrase"
    );
    await identityManager.save(storedIdentity);

    const auditLog = new AuditLog(storage, derived.key);
    await auditLog.append("l1", "identity_create", publicIdentity.identity_id, {
      label: "default",
      source: "test",
    });

    const out = new StringWritable();
    const err = new StringWritable();
    const savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    try {
      const code = await runIdentityCommand({
        argv: [
          "show",
          "--json",
          "--fortress",
          fortressPath,
          "--passphrase",
          passphrase,
        ],
        out,
        err,
        env: { SANCTUARY_PASSPHRASE: passphrase },
      });
      expect(code, err.text).toBe(0);
    } finally {
      if (savedStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
    }
    const cliIdentity = JSON.parse(out.text) as {
      identity_id: string;
      total_identities: number;
    };

    const sources: AggregatorSources = {
      mode: "co-located",
      server_version: "test",
    };
    Object.assign(sources, { identityManager, auditLog });

    const res = mockRes();
    const matched = await handleRequest({ sources }, mockReq(), res);
    expect(matched).toBe(true);
    expect(res._status).toBe(200);
    const snapshot = JSON.parse(res._body);

    expect(snapshot.agent.identity_count).toBe(cliIdentity.total_identities);
    expect(snapshot.agent.identity_count).toBeGreaterThanOrEqual(1);
    expect(snapshot.agent.primary_identity_id).toBe(cliIdentity.identity_id);
    expect(snapshot.audit).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          operation: "identity_create",
          identity_id: cliIdentity.identity_id,
        }),
      ])
    );
  });
});
