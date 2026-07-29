/**
 * Governed File-Grant v1 -- list is audited (Fix 6).
 *
 * The build spec routes `file_grant_list` as Tier-3 auto-allow AND audit.
 * `recordFileGrantListAudit` must append a `file_grant_list` audit event
 * capturing who listed, the agent filter, and the count -- and must NOT record
 * the grant paths themselves (privacy).
 */

import { describe, expect, it } from "vitest";

import { recordFileGrantListAudit } from "../../src/file-grant/list.js";
import { makeFileGrantTestStore } from "./fixtures.js";

describe("file-grant list audit (Fix 6)", () => {
  it("appends a file_grant_list audit event with filter + count", async () => {
    const { auditLog } = makeFileGrantTestStore();

    await recordFileGrantListAudit(auditLog, "operator-1", { subjectAgentId: "agent-7" }, 3);

    const { entries } = await auditLog.query({ operation_type: "file_grant_list" });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.result).toBe("success");
    const details = entries[0]!.details as Record<string, unknown>;
    expect(details.agent_filter).toBe("agent-7");
    expect(details.count).toBe(3);
    // Privacy: the audit records the count/filter, never the granted paths.
    expect(JSON.stringify(details)).not.toContain("/");
  });

  it("records 'all' when no agent filter is applied", async () => {
    const { auditLog } = makeFileGrantTestStore();

    await recordFileGrantListAudit(auditLog, "operator-1", undefined, 0);

    const { entries } = await auditLog.query({ operation_type: "file_grant_list" });
    expect(entries).toHaveLength(1);
    expect((entries[0]!.details as Record<string, unknown>).agent_filter).toBe("all");
  });

  it("is best-effort: a broken audit log never throws out of the read-only list", async () => {
    const throwingAudit = {
      appendCritical: async () => {
        throw new Error("audit ENOSPC");
      },
    } as unknown as import("../../src/operational/audit-log.js").AuditLog;

    await expect(
      recordFileGrantListAudit(throwingAudit, "operator-1", undefined, 1),
    ).resolves.toBeUndefined();
  });
});
