import { describe, expect, it } from "vitest";
import {
  AuditIntegrityError,
  AuditLog,
  type AuditIntegrityAnomalyEvent,
} from "../../src/operational/audit-log.js";
import { bytesToString } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

describe("AuditLog integrity alerting", () => {
  it("emits a P1 anomaly event and writes audit-integrity-alert.log on detected findings", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey);
    for (const operation of ["one", "two", "three"]) {
      await writer.appendCritical({
        layer: "l2",
        operation,
        identity_id: "id-1",
        result: "success",
      });
    }

    const second = (await storage.list("_audit", "entry-")).find((meta) =>
      meta.key.startsWith("entry-00000000000000000002-")
    );
    if (!second) throw new Error("missing second audit entry");
    await storage.delete("_audit", second.key);

    const events: AuditIntegrityAnomalyEvent[] = [];
    const reader = new AuditLog(storage, masterKey, {
      integrityAnomalySubscribers: [(event) => events.push(event)],
    });

    await expect(
      reader.appendCritical({
        layer: "l2",
        operation: "after_corruption",
        identity_id: "id-1",
        result: "failure",
      })
    ).rejects.toMatchObject({
      name: "AuditIntegrityError",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
      ]),
    } satisfies Partial<AuditIntegrityError>);

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: "audit_integrity_finding",
      severity: "P1",
      findings: expect.arrayContaining([
        expect.objectContaining({ kind: "sequence_gap_or_reorder", sequence: 3 }),
      ]),
    });

    const alertRaw = await storage.read(
      "_audit_integrity_alert",
      "audit-integrity-alert.log"
    );
    expect(alertRaw).not.toBeNull();
    expect(bytesToString(alertRaw!)).toContain("sequence_gap_or_reorder");
    expect(bytesToString(alertRaw!)).toContain("\"severity\":\"P1\"");
  });
});
