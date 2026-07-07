/**
 * Governed File-Grant v1 -- fail-closed + honest mint (DoD gate 5, Invariant
 * #5, plus the two-family gate fixes 1/2/3/5).
 *
 * Covers:
 *   - place() throws -> full rollback, NO active grant object AND NO tree
 *     entry survives (both the throws-before-recording and the
 *     records-then-throws partial-placement cases).
 *   - a broken POST-PLACE confirmation audit -> mint still reports SUCCESS with
 *     a live, recorded grant; it is never rolled back and reported as a failure
 *     (the fail-OPEN + false-rollback bug, Fix 1 + R2-3b).
 *   - a put() that DURABLY commits then throws -> the committed record is rolled
 *     back; no phantom `active` grant survives (R2-1).
 *   - a DURABLE pre-placement audit failure -> mint fails closed BEFORE place();
 *     access is never live without a preceding audit entry (R2-3a).
 *   - store.remove throwing during rollback -> no dangling `active` grant
 *     survives; a terminal `revoked` tombstone is persisted (Fix 2).
 *   - enforcement is HONEST: a same-owner box (incl. the sudo / source-owner
 *     case) reports "unmet", a real uid split reports "unverified", and a bare
 *     uid split is NEVER reported as "met" (Fix 3).
 *   - a path-traversing subject agent id is rejected before anything is
 *     persisted or placed (Fix 5).
 */

import { describe, expect, it } from "vitest";

import type { AuditLog } from "../../src/operational/audit-log.js";
import { mintFileGrant } from "../../src/file-grant/mint.js";
import type { FileGrantRecordStore } from "../../src/file-grant/mint.js";
import {
  FileGrantAgentIdRejectedError,
  FileGrantMintFailedError,
} from "../../src/file-grant/types.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

const NOW = new Date("2026-07-07T00:00:00.000Z");

function baseParams(overrides: Record<string, unknown> = {}) {
  return {
    subjectAgentId: "agent-1",
    scope: { kind: "file" as const, path: "/tmp/example.txt" },
    mode: "read",
    ttlSeconds: 3600,
    createdBy: "operator-1",
    ...overrides,
  };
}

describe("file-grant fail-closed mint: rollback leaves no object AND no tree entry", () => {
  it("place() throwing before recording rolls back the object and places nothing", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ placeThrows: new Error("EPERM: cannot chown to agent uid") });

    await expect(
      mintFileGrant(baseParams(), { fsOps, store: grantStore, now: NOW, auditLog }),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    // No phantom grant object.
    expect(await grantStore.list()).toHaveLength(0);
    // Nothing was placed at all.
    expect(fsOps.placed).toHaveLength(0);
    // The failure is still audited.
    const { entries } = await auditLog.query({ operation_type: "file_grant" });
    expect(entries.some((e) => e.result === "failure")).toBe(true);
  });

  it("place() recording a partial entry THEN throwing is scrubbed (no tree entry survives)", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      placeRecordsThenThrows: new Error("symlink ok then chown EPERM"),
    });

    await expect(
      mintFileGrant(baseParams(), { fsOps, store: grantStore, now: NOW, auditLog }),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    // No active grant object.
    expect(await grantStore.list()).toHaveLength(0);
    // The partial tree entry that place() recorded was scrubbed by the rollback.
    expect(fsOps.placed).toHaveLength(1);
    expect(fsOps.scrubbed).toContain(fsOps.placed[0]!.dest);
  });

  it("store.remove throwing during rollback leaves NO active grant (terminal tombstone persisted)", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    // A store whose delete fails, but whose write still works: mint must then
    // persist a terminal `revoked` record rather than leaving a dangling active.
    const removeFailingStore: FileGrantRecordStore = {
      put: (grant) => grantStore.put(grant),
      remove: async () => {
        throw new Error("store delete failed");
      },
    };
    const fsOps = new FakeFsOps({ placeThrows: new Error("placement failed") });

    await expect(
      mintFileGrant(baseParams(), { fsOps, store: removeFailingStore, now: NOW, auditLog }),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    const listed = await grantStore.list();
    // No grant is listable as active.
    expect(listed.some((g) => g.status === "active")).toBe(false);
    // A terminal tombstone was persisted so the mint is not silently lost.
    expect(listed.every((g) => g.status === "revoked")).toBe(true);
  });
});

describe("file-grant mint: a throw AFTER place() succeeds never becomes a false failure (Fix 1 + R2-3b)", () => {
  it("a broken POST-PLACE confirmation audit does NOT roll back a live grant; mint reports success", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });
    // Audit that throws ONLY on the post-placement CONFIRMATION append (phase
    // "placed"). The DURABLE pre-placement audit (phase "recorded") succeeds, so
    // the grant is audited BEFORE access is conferred (R2-3); a broken
    // confirmation must never roll back the already-live, already-audited grant
    // and report failure (the fail-OPEN + false-rollback bug, R2-3b).
    const throwingAudit = {
      appendCritical: async (entry: { result: string; details?: { phase?: string } }) => {
        if (entry.details?.phase === "placed") throw new Error("audit ENOSPC after place");
        return undefined as unknown as void;
      },
    } as unknown as AuditLog;

    const result = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
      auditLog: throwingAudit,
    });

    // Reported success (never both-survive-but-caller-sees-failure).
    expect(result.grant.status).toBe("active");
    // Access was conferred (placement happened) and the record is live.
    expect(fsOps.placed).toHaveLength(1);
    const persisted = await grantStore.get(result.grant.grant_id);
    expect(persisted).not.toBeNull();
    expect(persisted!.status).toBe("active");
  });
});

describe("file-grant mint: a put() that commits then throws leaves no phantom (R2-1)", () => {
  it("a persists-then-throws put() rolls the committed record back; no active grant survives", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    // A store whose put() DURABLY writes to the real grantStore and THEN throws,
    // modeling StateStore.write committing before a post-commit await
    // (rememberWriterPublicKey / observeVersion / rename->fsyncDir) throws. The
    // put()-catch must NOT assume nothing persisted: it must roll the committed
    // record back, exactly like the placement-failure path.
    const persistsThenThrows: FileGrantRecordStore = {
      put: async (grant) => {
        await grantStore.put(grant); // durable commit
        throw new Error("post-commit fsyncDir threw after write committed");
      },
      remove: (grantId) => grantStore.remove(grantId),
    };
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    await expect(
      mintFileGrant(baseParams(), { fsOps, store: persistsThenThrows, now: NOW, auditLog }),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    // The phantom committed record was rolled back: nothing listable as active.
    const listed = await grantStore.list();
    expect(listed.some((g) => g.status === "active")).toBe(false);
    // place() never ran (put threw before placement).
    expect(fsOps.placed).toHaveLength(0);
  });
});

describe("file-grant mint: audit precedes access (R2-3a)", () => {
  it("a pre-placement audit failure fails closed: no live access, no active grant", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });
    // Audit that throws on the DURABLE pre-placement append (phase "recorded").
    // Access must NEVER be conferred without a preceding audit entry, so mint
    // must fail BEFORE place() -- no symlink, no active grant, no
    // live-access-without-audit.
    const preAuditThrows = {
      appendCritical: async (entry: { result: string; details?: { phase?: string } }) => {
        if (entry.details?.phase === "recorded") throw new Error("audit ENOSPC before place");
        return undefined as unknown as void;
      },
    } as unknown as AuditLog;

    await expect(
      mintFileGrant(baseParams(), { fsOps, store: grantStore, now: NOW, auditLog: preAuditThrows }),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    // Access was NEVER conferred (place did not run): no live-access-without-audit.
    expect(fsOps.placed).toHaveLength(0);
    // And no active grant survives.
    expect((await grantStore.list()).some((g) => g.status === "active")).toBe(false);
  });
});

describe("file-grant mint: honest enforcement label (Fix 3, never overclaim)", () => {
  it("reports unmet when the agent uid equals the source-file owner (same-owner box)", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 501, sourceOwnerUid: 501 });

    const { grant, enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unmet");
    expect(await grantStore.get(grant.grant_id)).not.toBeNull();
  });

  it("reports unmet for the sudo/source-owner case (source owned BY the agent uid), never met", async () => {
    const { grantStore } = makeFileGrantTestStore();
    // Under sudo, process.getuid() would be 0; a naive uid check would see
    // 0 != 502 and print "met". The source is owned by the agent uid (502),
    // so there is NO boundary: the honest verdict is "unmet".
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 502 });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unmet");
    expect(enforcement).not.toBe("met");
  });

  it("reports unmet when no dedicated agent uid is configured at all", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: null, sourceOwnerUid: 501 });

    const { enforcement } = await mintFileGrant(baseParams({ ttlSeconds: null }), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unmet");
  });

  it("reports unverified (NOT met) for a real uid split with no on-hardware verification", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    // A uid split alone must never be reported as governed/met.
    expect(enforcement).toBe("unverified");
    expect(enforcement).not.toBe("met");
  });
});

describe("file-grant mint: agent-id containment (Fix 5)", () => {
  it("rejects a path-traversing subject agent id and persists/places nothing", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    await expect(
      mintFileGrant(baseParams({ subjectAgentId: "../../../../tmp/x" }), {
        fsOps,
        store: grantStore,
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(FileGrantAgentIdRejectedError);

    expect(await grantStore.list()).toHaveLength(0);
    expect(fsOps.placed).toHaveLength(0);
  });

  it("rejects a slashed or leading-dot agent id before any side effect", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps();

    for (const bad of ["a/b", ".hidden", "..", "", "x/../y"]) {
      await expect(
        mintFileGrant(baseParams({ subjectAgentId: bad }), {
          fsOps,
          store: grantStore,
          now: NOW,
        }),
      ).rejects.toBeInstanceOf(FileGrantAgentIdRejectedError);
    }
    expect(await grantStore.list()).toHaveLength(0);
    expect(fsOps.placed).toHaveLength(0);
  });
});
