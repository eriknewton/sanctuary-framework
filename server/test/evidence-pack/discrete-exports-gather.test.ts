/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: discrete-export GATHER
 * (dry-bar R2-1 + C4 regression, over a REAL on-disk fortress).
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * `gatherDiscreteExports` reads the third-party verification exports from
 * persisted fortress state. Two honesty holes are pinned here:
 *   - R2-1: on a SPLIT (writer-migrated) fortress the raw audit-chain export
 *     covers the operator `_audit` chain only and silently omits the daemon
 *     enforcement chain; the gather must OMIT it (an honest read_failed), not
 *     ship an operator-only chain the signed pack calls "the recorded
 *     enforcement history".
 *   - C4: the anchor export must be read from ACTUAL anchoring state -- a
 *     genuinely-absent config with no receipts is a verified empty, but a
 *     config-absent-yet-receipts-present (inconsistent) state must be a
 *     read_failed, never a false "not enabled". Uses temp dirs, never host state.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import {
  AUDIT_DAEMON_NAMESPACE,
  migrateFortressAuditStoreSplit,
} from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { gatherDiscreteExports } from "../../src/evidence-pack/cli.js";

const dirs: string[] = [];
const GEN_AT = "2026-08-01T00:00:00.000Z";

afterEach(async () => {
  for (const d of dirs.splice(0)) {
    await rm(d, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function freshFortress() {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-ep-gather-"));
  dirs.push(root);
  const statePath = join(root, "state");
  const storage = new FilesystemStorage(statePath);
  const masterKey = generateRandomKey();
  return { root, statePath, storage, masterKey };
}

async function splitFortress() {
  const f = await freshFortress();
  const auditLog = new AuditLog(f.storage, f.masterKey);
  await auditLog.appendCritical({
    layer: "l1",
    operation: "pre-split-op",
    identity_id: "agent-a",
    result: "success",
  });
  await auditLog.flush();
  await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: f.masterKey });
  return f;
}

describe("R2-1: audit-chain export gather on a split fortress", () => {
  it("OMITS the operator-only audit-chain export (read_failed) on a migrated fortress", async () => {
    const f = await splitFortress();
    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("read_failed");
    if (out.audit_chain.status === "read_failed") {
      expect(out.audit_chain.reason).toMatch(/writer split|daemon/i);
      expect(out.audit_chain.reason).toMatch(/incomplete|complete/i);
    }
  });

  it("still gathers the audit-chain export on a NON-split fortress", async () => {
    const f = await freshFortress();
    const auditLog = new AuditLog(f.storage, f.masterKey);
    await auditLog.appendCritical({
      layer: "l1",
      operation: "op",
      identity_id: "agent-a",
      result: "success",
    });
    await auditLog.flush();
    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    // Not the split-omission read_failed: the operator-only chain IS the whole
    // enforcement history here, so it is exported (populated) honestly.
    expect(out.audit_chain.status).toBe("populated");
  });

  it("OMITS the export even when the daemon dir was deleted (marker survives)", async () => {
    const f = await splitFortress();
    await rm(join(f.statePath, AUDIT_DAEMON_NAMESPACE), { recursive: true, force: true });
    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    // The durable _meta split marker proves the export would be incomplete.
    expect(out.audit_chain.status).toBe("read_failed");
  });

  it("OMITS the export on a BOUNDARY-ONLY migrated fortress (daemon dir AND _meta marker deleted)", async () => {
    // Both gate families' HIGH: the export module's probe is boundary-blind (it
    // checks only the daemon namespace + the _meta marker). With BOTH deleted but
    // the MAC'd split boundary surviving, the boundary-aware daemonMigrationEstablished
    // is the only signal left -- and the gather must still omit the operator-only
    // chain rather than ship it as "the recorded enforcement history".
    const f = await splitFortress();
    await rm(join(f.statePath, AUDIT_DAEMON_NAMESPACE), { recursive: true, force: true });
    await f.storage.delete("_meta", "audit-store-split-established-v1");
    // Sanity: the boundary record still exists.
    const { readAuditStoreSplitBoundary, deriveAuditStoreSplitBoundaryMacKey } =
      await import("../../src/operational/audit-log.js");
    const b = await readAuditStoreSplitBoundary(
      f.statePath,
      deriveAuditStoreSplitBoundaryMacKey(f.masterKey)
    );
    expect(b.status).toBe("valid");

    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("read_failed");
  });
});

describe("C4: anchor export gather from real anchoring state", () => {
  it("verified-empty when anchoring was never configured (no config, no receipts)", async () => {
    const f = await freshFortress();
    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    expect(out.anchor.status).toBe("empty_verified");
  });

  it("read_failed (NOT a false 'not enabled') when config is absent but receipts exist", async () => {
    const f = await freshFortress();
    // Plant an anchor receipt via the storage API (so `list` finds the .enc
    // file) with NO anchoring config: an inconsistent state that must never
    // render as the definitive "anchoring is not enabled".
    await f.storage.write(
      "_transparency_anchors",
      "anchor-00000000000000000001",
      new TextEncoder().encode(JSON.stringify({ status: "anchored" }))
    );
    const out = await gatherDiscreteExports(f.storage, f.masterKey, "fortress-1", GEN_AT);
    expect(out.anchor.status).toBe("read_failed");
  });
});
