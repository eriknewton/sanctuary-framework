import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runAuditCommand, parseSearchOptions } from "../../src/cli/audit.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";

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

describe("sanctuary audit search", () => {
  const tempDirs: string[] = [];
  const passphrase = "audit-search-passphrase";

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress(): Promise<string> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-audit-search-"));
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(passphrase);
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      timestamp: "2026-06-09T10:00:00.000Z",
      layer: "l2",
      operation: "state_read",
      identity_id: "agent-a",
      result: "success",
      details: { path: "alpha" },
    });
    await auditLog.appendCritical({
      timestamp: "2026-06-09T11:00:00.000Z",
      layer: "l2",
      operation: "state_write",
      identity_id: "agent-b",
      result: "success",
      details: { path: "beta" },
    });
    await auditLog.appendCritical({
      timestamp: "2026-06-09T12:00:00.000Z",
      layer: "l1",
      operation: "identity_create",
      identity_id: "agent-a",
      result: "success",
    });
    await auditLog.flush();
    derived.key.fill(0);
    return fortress;
  }

  it("filters by type, actor, since, until, and limit", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: [
        "search",
        "--fortress",
        fortress,
        "--type",
        "state_read,state_write",
        "--since",
        "2026-06-09T09:30:00.000Z",
        "--until",
        "2026-06-09T11:30:00.000Z",
        "--actor",
        "agent-b",
        "--limit",
        "1",
      ],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("state_write");
    expect(out.text()).toContain("agent-b");
    expect(out.text()).not.toContain("state_read");
    expect(out.text()).not.toContain("identity_create");
  });

  it("emits JSON results", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: ["search", "--fortress", fortress, "--type", "identity_create", "--json"],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text());
    expect(parsed.total).toBe(1);
    expect(parsed.entries[0].operation).toBe("identity_create");
  });

  it("prints a clean empty result and exits 0", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: ["search", "--fortress", fortress, "--type", "missing_event"],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    expect(out.text()).toBe("(no audit entries)\n");
  });

  it("rejects invalid limit and missing key material", async () => {
    expect(() => parseSearchOptions(["--limit", "0"])).toThrow("--limit must be");

    const fortress = await makeFortress();
    const err = new Capture();
    const code = await runAuditCommand({
      argv: ["search", "--fortress", fortress],
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("requires SANCTUARY_PASSPHRASE");
  });

  it("accepts repeated type flags", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: [
        "search",
        "--fortress",
        fortress,
        "--type",
        "state_read",
        "--type",
        "identity_create",
        "--json",
      ],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text());
    expect(parsed.total).toBe(2);
    expect(parsed.entries.map((entry: { operation: string }) => entry.operation)).toEqual([
      "state_read",
      "identity_create",
    ]);
  });
});
