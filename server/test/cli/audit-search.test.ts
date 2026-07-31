import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runAuditCommand, parseSearchOptions } from "../../src/cli/audit.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";

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
    // Two denial entries that differ ONLY by request_id: this is the shape an
    // endpoint writes when it refuses to tell the caller which check failed and
    // hands back a correlation id instead. The lookup has to pick out exactly
    // one of them.
    await auditLog.appendCritical({
      timestamp: "2026-06-09T13:00:00.000Z",
      layer: "l2",
      operation: "v1_federation_reissue_node_cert",
      identity_id: "joiner-1",
      result: "failure",
      details: {
        reason: "no_recorded_rotation_lineage",
        request_id: "11111111-1111-4111-8111-111111111111",
        operator_next_step: "Restart the fortress endpoint, then re-enable.",
      },
    });
    await auditLog.appendCritical({
      timestamp: "2026-06-09T13:01:00.000Z",
      layer: "l2",
      operation: "v1_federation_reissue_node_cert",
      identity_id: "joiner-1",
      result: "failure",
      details: {
        reason: "federation_disabled",
        request_id: "22222222-2222-4222-8222-222222222222",
      },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return fortress;
  }

  // The redemption half of the correlation-id fix (F-FED-OPAQUEDENY): the id a
  // refused caller was handed has to be spendable in one command, or the
  // diagnosability gap is only half closed and the operator still greps JSON.
  it("looks a denial's request id up to exactly one entry, with the reason", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: [
        "search",
        "--fortress",
        fortress,
        "--request-id",
        "11111111-1111-4111-8111-111111111111",
      ],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    // The reason + remediation print WITHOUT --json: the operator asked the
    // question, so they get the answer, not a pointer to another flag.
    expect(out.text()).toContain("no_recorded_rotation_lineage");
    expect(out.text()).toContain("Restart the fortress endpoint");
    // The sibling denial (same operation, same actor, different id) is excluded.
    expect(out.text()).not.toContain("federation_disabled");
  });

  it("accepts --request-id=<id> and returns nothing for an unknown id", async () => {
    const fortress = await makeFortress();
    const out = new Capture();
    const code = await runAuditCommand({
      argv: [
        "search",
        "--fortress",
        fortress,
        "--request-id=22222222-2222-4222-8222-222222222222",
        "--json",
      ],
      out,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text());
    expect(parsed.total).toBe(1);
    expect(parsed.entries[0].details.reason).toBe("federation_disabled");

    const missing = new Capture();
    expect(
      await runAuditCommand({
        argv: ["search", "--fortress", fortress, "--request-id", "no-such-id"],
        out: missing,
        env: { SANCTUARY_PASSPHRASE: passphrase },
      }),
    ).toBe(0);
    expect(missing.text()).toBe("(no audit entries)\n");
  });

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

  it("reports audit integrity findings instead of silently returning search results", async () => {
    const fortress = await makeFortress();
    const storage = new FilesystemStorage(join(fortress, "state"));
    const [entryMeta] = await storage.list("_audit", "entry-");
    if (!entryMeta) throw new Error("missing audit fixture entry");
    const raw = await storage.read("_audit", entryMeta.key);
    if (!raw) throw new Error("missing audit fixture bytes");
    const envelope = JSON.parse(bytesToString(raw)) as { entry_hash: string };
    envelope.entry_hash = "0".repeat(64);
    await storage.write("_audit", entryMeta.key, stringToBytes(JSON.stringify(envelope)));

    const out = new Capture();
    const err = new Capture();
    const code = await runAuditCommand({
      argv: ["search", "--fortress", fortress, "--json"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: passphrase },
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("AUDIT INTEGRITY WARNING");
    const parsed = JSON.parse(out.text());
    expect(parsed.integrity_findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "entry_hash_mismatch" }),
      ])
    );
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
