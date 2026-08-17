/**
 * `sanctuary audit-chain repair-plan` — behavior and the no-mutation property.
 *
 * The load-bearing test here is not "does it print findings"; it is that the
 * fortress is BYTE-IDENTICAL before and after the command, proven by hashing
 * the whole directory tree (paths, modes, and contents) on both sides. That
 * property is what lets a read-only diagnostic ship ahead of any decision about
 * who may authorize a repair, so it is asserted on every path the verb can take
 * — clean, damaged, and privilege-limited — not only the happy one.
 *
 * The tree hash covers DIRECTORIES as well as files, because a mutation can be
 * a created empty directory (a namespace materialized as a side effect of being
 * read) and a contents-only hash would call that unchanged.
 */

import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import {
  AUDIT_DAEMON_NAMESPACE,
  createDaemonAuditLog,
  migrateFortressAuditStoreSplit,
} from "../../src/operational/audit-store-split.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { runProvisionPin } from "../../src/cli/castle-wall.js";
import {
  REPAIR_PLAN_EXIT_CLEAN,
  REPAIR_PLAN_EXIT_PLAN_PRODUCED,
  REPAIR_PLAN_EXIT_PRIVILEGE_LIMITED,
  REPAIR_PLAN_EXIT_STATE_UNREADABLE,
  REPAIR_PLAN_EXIT_USAGE,
  REPAIR_PLAN_SCHEMA_VERSION,
  computeRepairPlanEvidenceCommitment,
  runAuditChainRepairPlan,
  type AuditChainRepairPlan,
} from "../../src/cli/audit-chain-repair-plan.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _enc: BufferEncoding,
    cb: (e?: Error | null) => void
  ): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const PASSPHRASE = "test-audit-chain-repair-plan-passphrase";

/**
 * A hash over the fortress directory TREE: every path (relative, sorted), each
 * one's type and mode, and each file's content digest. Any write, delete,
 * truncation, mode change, or newly created directory changes this value.
 *
 * Failure mode to know: hashing contents alone would miss a created empty
 * directory, and hashing names alone would miss an in-place content edit of the
 * same length. Both are covered here on purpose.
 */
async function fortressTreeHash(root: string): Promise<string> {
  const parts: string[] = [];
  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = join(dir, entry.name);
      const rel = relative(root, full);
      const info = await stat(full);
      const mode = (info.mode & 0o7777).toString(8);
      if (entry.isDirectory()) {
        parts.push(`dir ${rel} ${mode}`);
        await walk(full);
      } else if (entry.isFile()) {
        const content = await readFile(full);
        parts.push(
          `file ${rel} ${mode} ${createHash("sha256").update(content).digest("hex")}`
        );
      } else {
        parts.push(`other ${rel} ${mode}`);
      }
    }
  }
  await walk(root);
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

describe("audit-chain repair-plan", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await chmod(join(dir, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(
        () => undefined
      );
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  const ENV = (fortressPath: string): NodeJS.ProcessEnv => ({
    SANCTUARY_STORAGE_PATH: fortressPath,
    SANCTUARY_PASSPHRASE: PASSPHRASE,
  });

  /** Provision a fortress and seed `entries` operator audit entries. */
  async function seededFortress(entries = 4): Promise<string> {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-repair-plan-"));
    tempDirs.push(fortressPath);
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: ENV(fortressPath),
    });
    expect(code).toBe(0);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, passphrase: PASSPHRASE });
    const log = new AuditLog(storage, masterKey);
    for (let i = 0; i < entries; i++) {
      await log.appendCritical({
        layer: "l1",
        operation: `seed-${i}`,
        identity_id: "operator",
        result: "success",
      });
    }
    await log.flush();
    masterKey.fill(0);
    return fortressPath;
  }

  /** Run the verb, returning its exit code, parsed plan, and streams. */
  async function runPlan(fortressPath: string): Promise<{
    code: number;
    out: CaptureStream;
    err: CaptureStream;
    plan?: AuditChainRepairPlan;
  }> {
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditChainRepairPlan([], {
      out,
      err,
      env: ENV(fortressPath),
    });
    const text = out.text().trim();
    return {
      code,
      out,
      err,
      plan: text ? (JSON.parse(text) as AuditChainRepairPlan) : undefined,
    };
  }

  /** In-place corruption of one audit entry's stored bytes: a CONTENT finding
   *  (the recomputed entry hash stops matching), not a read failure. */
  async function corruptOneEntry(fortressPath: string): Promise<void> {
    const auditDir = join(fortressPath, "state", "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.endsWith(".enc")).sort();
    expect(files.length).toBeGreaterThan(2);
    const target = join(auditDir, files[1]!);
    const raw = JSON.parse(await readFile(target, "utf8")) as Record<string, unknown>;
    const payload = String(raw.encrypted_payload_bytes);
    // Flip one character of the ciphertext while preserving length, so the
    // change cannot be detected from file size alone.
    raw.encrypted_payload_bytes =
      (payload[0] === "A" ? "B" : "A") + payload.slice(1);
    await writeFile(target, JSON.stringify(raw), "utf8");
  }

  it("reports a clean chain, exits 0, and leaves the fortress byte-identical", async () => {
    const fortressPath = await seededFortress();
    const before = await fortressTreeHash(fortressPath);

    const { code, plan } = await runPlan(fortressPath);

    expect(code).toBe(REPAIR_PLAN_EXIT_CLEAN);
    expect(plan?.schema_version).toBe(REPAIR_PLAN_SCHEMA_VERSION);
    expect(plan?.plan.state).toBe("PLAN_NO_ACTION_CHAIN_VERIFIES_CLEAN");
    expect(plan?.chain_state.verdict).toBe("verified");
    expect(plan?.chain_state.routine_finding_count).toBe(0);
    expect(plan?.chain_state.findings).toEqual([]);
    expect(plan?.plan.next_actions).toEqual(["no action"]);
    expect(plan?.export_manifest.complete).toBe(true);
    expect(plan?.evidence_commitment).toMatch(/^[0-9a-f]{64}$/);

    expect(await fortressTreeHash(fortressPath)).toBe(before);
  });

  it("reports injected findings, exits 3, and leaves the fortress byte-identical", async () => {
    const fortressPath = await seededFortress();
    await corruptOneEntry(fortressPath);
    const before = await fortressTreeHash(fortressPath);

    const { code, plan } = await runPlan(fortressPath);

    expect(code).toBe(REPAIR_PLAN_EXIT_PLAN_PRODUCED);
    expect(plan?.plan.state).toBe("PLAN_FORWARD_CUT_APPLICABLE");
    expect(plan?.chain_state.verdict).toBe("findings");
    expect(plan?.chain_state.routine_finding_count).toBeGreaterThan(0);
    expect(plan?.chain_state.findings.length).toBeGreaterThan(0);
    expect(plan?.chain_state.findings_truncated).toBe(false);
    // It describes what a repair WOULD do and points at an off-host export; it
    // never claims a repair is available in this build.
    expect(plan?.plan.next_actions.join(" ")).toContain("audit-chain export");
    expect(plan?.plan.next_actions.join(" ")).toContain("no repair verb exists");

    // THE no-mutation proof for the path that matters most: a fortress WITH
    // findings is the one a repair path would be tempted to touch.
    expect(await fortressTreeHash(fortressPath)).toBe(before);
  });

  it("refuses to offer a cut when part of the evidence is unreadable here", async () => {
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      // chmod cannot hide a directory from root, so the privilege-limited state
      // is unreachable in a root-run suite. Skipping is honest; asserting the
      // non-privilege-limited result here would assert the wrong thing.
      return;
    }
    const fortressPath = await seededFortress();
    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, passphrase: PASSPHRASE });
    await migrateFortressAuditStoreSplit({ storage, masterKey });
    const daemonLog = createDaemonAuditLog(storage, masterKey);
    await daemonLog.appendCritical({
      layer: "l1",
      operation: "daemon-seed",
      identity_id: "daemon",
      result: "success",
    });
    await daemonLog.flush();
    masterKey.fill(0);

    const daemonDir = join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE);
    // Hash with the daemon directory momentarily readable so the tree hash
    // covers its CONTENTS too, then re-hide it for the run. Hashing it while
    // hidden would leave the one region the verb is being asked to notice
    // outside the no-mutation proof.
    const hashWithDaemonReadable = async (): Promise<string> => {
      await chmod(daemonDir, 0o700);
      try {
        return await fortressTreeHash(fortressPath);
      } finally {
        await chmod(daemonDir, 0o000);
      }
    };

    await chmod(daemonDir, 0o000);
    const before = await hashWithDaemonReadable();

    const { code, plan } = await runPlan(fortressPath);

    expect(code).toBe(REPAIR_PLAN_EXIT_PRIVILEGE_LIMITED);
    expect(plan?.plan.state).toBe("PLAN_NO_ACTION_PRIVILEGE_LIMITED");
    expect(plan?.export_manifest.daemon_chain_access).toBe("present_unreadable");
    expect(plan?.plan.next_actions.join(" ")).toContain("re-run this command");
    // It must NOT recommend a cut on an incomplete read.
    expect(plan?.plan.next_actions.join(" ")).not.toContain("audit-chain export");

    expect(await hashWithDaemonReadable()).toBe(before);
  });

  it("runs offline: no server is constructed and no port is opened", async () => {
    // The verb is exercised end to end everywhere in this file without any
    // server ever being created; this case states the requirement explicitly
    // and pairs with the import-graph guard in
    // `test/structure/repair-plan-offline-import-graph.test.ts`, which is what
    // actually PROVES the server cannot be reached (a test that simply omits
    // starting a server proves nothing on its own).
    const fortressPath = await seededFortress();
    const { code, plan } = await runPlan(fortressPath);
    expect(code).toBe(REPAIR_PLAN_EXIT_CLEAN);
    expect(plan?.fortress_id).toMatch(/^fortress-[0-9a-f]{16}$/);
  });

  it("fails closed when the fortress state cannot be read, and never claims clean", async () => {
    const missing = join(tmpdir(), `sanctuary-repair-plan-absent-${Date.now()}`);
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditChainRepairPlan([], {
      out,
      err,
      // No passphrase supplied and no fortress at this path: the verb must
      // report that it could not read, never establish custody here.
      env: { SANCTUARY_STORAGE_PATH: missing },
    });
    expect(code).toBe(REPAIR_PLAN_EXIT_STATE_UNREADABLE);
    expect(out.text()).toBe("");
    expect(err.text()).toContain("NOT a report that the chain is clean");
    // MUST-NEVER #2 / the no-mutation contract: nothing was created at the path.
    await expect(stat(missing)).rejects.toThrow();
  });

  it("rejects an unparseable invocation with the usage code", async () => {
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runAuditChainRepairPlan(["--fortress"], {
      out,
      err,
      env: {},
      homeFallback: "",
    });
    expect(code).toBe(REPAIR_PLAN_EXIT_USAGE);
    expect(out.text()).toBe("");
  });

  it("produces the same evidence commitment for an unchanged fortress and a different one after a change", async () => {
    const fortressPath = await seededFortress();
    const first = await runPlan(fortressPath);
    const second = await runPlan(fortressPath);
    expect(first.plan?.evidence_commitment).toBe(second.plan?.evidence_commitment);

    await corruptOneEntry(fortressPath);
    const third = await runPlan(fortressPath);
    expect(third.plan?.evidence_commitment).not.toBe(
      first.plan?.evidence_commitment
    );
  });

  it("commits to every finding even when the printed list is truncated", () => {
    // The display cap must never weaken the digest, so the commitment is
    // computed from the FULL finding set. Two sets that differ only past the
    // cap must still commit differently.
    const base = {
      fortressId: "fortress-0123456789abcdef",
      verdict: "findings" as const,
      sealedRegion: { status: "not_present" } as const,
      tipSequence: 12,
      tipEntryHash: "a".repeat(64),
      exportManifest: {
        entries_listed: 12,
        entries_exported: 12,
        entries_skipped: 0,
        checkpoints_listed: 0,
        checkpoints_exported: 0,
        checkpoints_skipped: 0,
        complete: true,
        digest: "b".repeat(64),
        bytes: 100,
        daemon_chain_present: false,
        daemon_chain_access: "absent" as const,
      },
    };
    const many = Array.from({ length: 150 }, (_, i) => ({
      kind: "entry_hash_mismatch" as const,
      message: `finding ${i}`,
    }));
    const changedPastCap = many.map((f, i) =>
      i === 140 ? { ...f, message: "different" } : f
    );

    expect(
      computeRepairPlanEvidenceCommitment({ ...base, findings: many })
    ).not.toBe(
      computeRepairPlanEvidenceCommitment({ ...base, findings: changedPastCap })
    );
  });
});
