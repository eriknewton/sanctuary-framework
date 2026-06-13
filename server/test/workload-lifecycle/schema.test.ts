/**
 * Workload-lifecycle audit schema — schema, vocabulary, emission API.
 *
 * Asserts the ratified design's invariants AND the three HIGH review
 * inversions (H1: unconsented delete is always recorded; H2: prev_lifecycle_seq
 * honesty; distress op reuse), plus the M3 single-sanctioned-writer guard.
 */

import { describe, it, expect } from "vitest";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { canonicalJson, sha256Hex } from "../../src/audit/chain.js";
import { SANCTUARY_DISTRESS_OPERATION } from "../../src/distress/tools.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_OP_VALUES,
  WORKLOAD_LIFECYCLE_SCHEMA,
  isWorkloadLifecycleOp,
  lifecycleOpForState,
  STATE_TO_LIFECYCLE_OP,
} from "../../src/workload-lifecycle/constants.js";
import {
  validateWorkloadLifecyclePayload,
  emitWorkloadLifecycle,
  signedEventHash,
  WorkloadLifecycleSchemaError,
  type WorkloadLifecyclePayload,
} from "../../src/workload-lifecycle/payload.js";

function basePayload(
  over: Partial<WorkloadLifecyclePayload> = {}
): WorkloadLifecyclePayload {
  return {
    lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
    workload_id: "wl-1",
    instance_id: "wli-1",
    workload_class: "stateful-agent",
    class_definition: "sanctuary.workload-class.v1",
    initiator: { kind: "operator", identity_id: "op-1" },
    consent_ref: null,
    consent_status: "absent",
    state_disposition: "running",
    ...over,
  };
}

async function newAuditLog(): Promise<AuditLog> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new AuditLog(storage, masterKey);
}

describe("workload-lifecycle vocabulary", () => {
  it("exposes the lifecycle operation strings", () => {
    expect(WORKLOAD_LIFECYCLE_OPS.INSTANTIATED).toBe("workload_instantiated");
    expect(WORKLOAD_LIFECYCLE_OPS.SLEPT).toBe("workload_slept");
    expect(WORKLOAD_LIFECYCLE_OPS.DELETED).toBe("workload_deleted");
    // Additive (rung b): host attestation joins the lifecycle vocabulary so an
    // auditor folding the ops sees attestation events in the same set.
    expect(WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED).toBe("workload_host_attestation");
    // Additive (rung c): undeclared-workload detection joins the vocabulary so an
    // auditor folding the ops sees detection findings in the same set.
    expect(WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED).toBe(
      "workload_undeclared_detected"
    );
    expect(WORKLOAD_LIFECYCLE_OP_VALUES.length).toBe(11);
  });

  it("reuses the CANONICAL distress operation — no second distress vocabulary", () => {
    // The chain record of a distress signal IS its lifecycle event.
    expect(WORKLOAD_LIFECYCLE_OPS.DISTRESS_SIGNALED).toBe(
      SANCTUARY_DISTRESS_OPERATION
    );
    expect(WORKLOAD_LIFECYCLE_OPS.DISTRESS_SIGNALED).toBe("sanctuary_distress");
    // There is deliberately no `workload_distress_signaled` string.
    expect(WORKLOAD_LIFECYCLE_OP_VALUES).not.toContain(
      "workload_distress_signaled"
    );
  });

  it("isWorkloadLifecycleOp recognizes its own strings and rejects others", () => {
    expect(isWorkloadLifecycleOp("workload_paused")).toBe(true);
    expect(isWorkloadLifecycleOp("sanctuary_distress")).toBe(true);
    expect(isWorkloadLifecycleOp("broker_secret_added")).toBe(false);
  });
});

describe("op <-> agent-contract state mapping (review M5)", () => {
  it("maps each contract state to the documented op", () => {
    expect(lifecycleOpForState("launched")).toBe("workload_instantiated");
    expect(lifecycleOpForState("paused")).toBe("workload_paused");
    expect(lifecycleOpForState("resumed")).toBe("workload_resumed");
    // retired and revoked both record as the SAFE DEFAULT (sleep), never delete.
    expect(lifecycleOpForState("retired")).toBe("workload_slept");
    expect(lifecycleOpForState("revoked")).toBe("workload_slept");
  });

  it("checkpointed maps to NO audit op (the one unmirrored transition)", () => {
    expect(lifecycleOpForState("checkpointed")).toBeNull();
    expect(STATE_TO_LIFECYCLE_OP.checkpointed).toBeNull();
  });

  it("an unknown state returns undefined (caller fails closed)", () => {
    expect(lifecycleOpForState("teleported")).toBeUndefined();
  });

  it("retired never auto-maps to delete (sleep-as-default is structural)", () => {
    expect(lifecycleOpForState("retired")).not.toBe("workload_deleted");
  });
});

describe("payload validation — fail closed", () => {
  it("accepts a well-formed payload", () => {
    expect(() => validateWorkloadLifecyclePayload(basePayload())).not.toThrow();
  });

  it("fails closed on an unknown lifecycle_schema version", () => {
    expect(() =>
      validateWorkloadLifecyclePayload(
        basePayload({
          lifecycle_schema: "sanctuary.workload-lifecycle.v2" as never,
        })
      )
    ).toThrow(WorkloadLifecycleSchemaError);
  });

  it("fails closed on a missing lifecycle_schema", () => {
    const p = basePayload();
    delete (p as Record<string, unknown>).lifecycle_schema;
    expect(() => validateWorkloadLifecyclePayload(p)).toThrow(
      /unknown lifecycle_schema/
    );
  });

  it("requires consent_status — silence is never legal", () => {
    const p = basePayload();
    delete (p as Record<string, unknown>).consent_status;
    expect(() => validateWorkloadLifecyclePayload(p)).toThrow(
      /consent_status required/
    );
  });

  it("treats consent_status:'absent' as a legal, loud value", () => {
    expect(() =>
      validateWorkloadLifecyclePayload(
        basePayload({ consent_status: "absent" })
      )
    ).not.toThrow();
  });

  it("rejects an unknown initiator.kind", () => {
    expect(() =>
      validateWorkloadLifecyclePayload(
        basePayload({
          initiator: { kind: "intruder" as never, identity_id: "x" },
        })
      )
    ).toThrow(/initiator.kind/);
  });

  it("rejects a negative prev_lifecycle_seq", () => {
    expect(() =>
      validateWorkloadLifecyclePayload(basePayload({ prev_lifecycle_seq: -1 }))
    ).toThrow(/prev_lifecycle_seq/);
  });

  it("rejects an unknown top-level key (no workload-content smuggling)", () => {
    // The privacy invariant: lifecycle, not contents. A cast caller cannot ride
    // a prompt/memory/secret into the audit chain via an extra field.
    const p = basePayload() as Record<string, unknown>;
    p.prompt = "secret system prompt";
    expect(() => validateWorkloadLifecyclePayload(p)).toThrow(/unknown key/);
  });

  it("rejects an unknown nested key in initiator", () => {
    const p = basePayload();
    (p.initiator as Record<string, unknown>).secret_seed = "leak";
    expect(() => validateWorkloadLifecyclePayload(p)).toThrow(/unknown key/);
  });

  it("strips to a fresh object — only schema fields survive validation", () => {
    // Even constructing the object directly, validation returns a clean object.
    const out = validateWorkloadLifecyclePayload(
      basePayload({ consent_status: "present", consent_ref: "c-1" })
    );
    expect(Object.keys(out).sort()).toEqual(
      [
        "class_definition",
        "consent_ref",
        "consent_status",
        "initiator",
        "instance_id",
        "lifecycle_schema",
        "state_disposition",
        "workload_class",
        "workload_id",
      ].sort()
    );
  });

  it("rejects an invalid revival_class", () => {
    expect(() =>
      validateWorkloadLifecyclePayload(
        basePayload({ revival_class: "incinerated" as never })
      )
    ).toThrow(/revival_class/);
  });
});

describe("H1 — an unconsented delete is ALWAYS recordable", () => {
  it("validates a workload_deleted payload with consent_status:'absent' and no override", () => {
    // The omission pattern the schema exists to kill: the worst act must NOT be
    // the one act guaranteed to leave no record. Schema validity NEVER suppresses
    // the record; prevention is the Tier-1 policy gate's job.
    const p = basePayload({
      consent_status: "absent",
      consent_ref: null,
      state_disposition: "destroyed",
    });
    expect(() => validateWorkloadLifecyclePayload(p)).not.toThrow();
  });

  it("emits a loud unconsented delete to the critical audit chain", async () => {
    const auditLog = await newAuditLog();
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.DELETED,
      identity_id: "fortress-1",
      payload: basePayload({
        consent_status: "absent",
        state_disposition: "destroyed",
      }),
    });
    const { entries } = await auditLog.query({
      operation_type: "workload_deleted",
    });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details?.consent_status).toBe("absent");
    expect(entries[0]!.layer).toBe("l2");
  });
});

describe("emission API writes critical chain entries", () => {
  it("appends a critical entry the chain can read back", async () => {
    const auditLog = await newAuditLog();
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
      identity_id: "fortress-1",
      payload: basePayload({ consent_status: "present", consent_ref: "c-1" }),
    });
    const { entries } = await auditLog.query({
      operation_type: "workload_instantiated",
    });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details?.lifecycle_schema).toBe(
      WORKLOAD_LIFECYCLE_SCHEMA
    );
    expect(entries[0]!.details?.consent_status).toBe("present");
  });

  it("rejects (fails closed) before writing when the payload is invalid", async () => {
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        operation: WORKLOAD_LIFECYCLE_OPS.PAUSED,
        identity_id: "fortress-1",
        payload: basePayload({
          lifecycle_schema: "bogus" as never,
        }),
      })
    ).rejects.toThrow(WorkloadLifecycleSchemaError);
    const { total } = await auditLog.query({ layer: "l2" });
    expect(total).toBe(0);
  });

  it("fails closed (no write) when operation is outside the lifecycle vocabulary", async () => {
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        // A JS/cast caller smuggling a non-lifecycle op past the type system.
        operation: "broker_secret_added" as never,
        identity_id: "fortress-1",
        payload: basePayload(),
      })
    ).rejects.toThrow(/not a workload-lifecycle op/);
    const { total } = await auditLog.query({ layer: "l2" });
    expect(total).toBe(0);
  });

  it("rejects an incoherent delete that claims its state still runs", async () => {
    // Internal-consistency check (not consent-gating): a delete recording
    // state_disposition:"running" is a self-contradictory RECORD.
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        operation: WORKLOAD_LIFECYCLE_OPS.DELETED,
        identity_id: "fortress-1",
        payload: basePayload({ state_disposition: "running" }),
      })
    ).rejects.toThrow(/state_disposition "destroyed"/);
    expect((await auditLog.query({ layer: "l2" })).total).toBe(0);
  });

  it("still records an HONEST gated delete (destroyed + absent consent)", async () => {
    // H1 must survive the consistency check: the real delete path works.
    const auditLog = await newAuditLog();
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.DELETED,
      identity_id: "fortress-1",
      payload: basePayload({
        state_disposition: "destroyed",
        consent_status: "absent",
      }),
    });
    expect(
      (await auditLog.query({ operation_type: "workload_deleted" })).entries
    ).toHaveLength(1);
  });

  it("rejects a fork without exactly one lineage parent", async () => {
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        operation: WORKLOAD_LIFECYCLE_OPS.FORKED,
        identity_id: "fortress-1",
        payload: basePayload({ state_disposition: "preserved" }),
      })
    ).rejects.toThrow(/exactly one parent/);
  });

  it("rejects a merge with fewer than two lineage parents", async () => {
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        operation: WORKLOAD_LIFECYCLE_OPS.MERGED,
        identity_id: "fortress-1",
        payload: basePayload({
          state_disposition: "preserved",
          lineage: { parents: ["wli-x"] },
        }),
      })
    ).rejects.toThrow(/at least two parents/);
  });

  it("accepts a well-formed fork", async () => {
    const auditLog = await newAuditLog();
    await emitWorkloadLifecycle({
      auditLog,
      operation: WORKLOAD_LIFECYCLE_OPS.FORKED,
      identity_id: "fortress-1",
      payload: basePayload({
        state_disposition: "preserved",
        lineage: { parents: ["wli-parent"] },
      }),
    });
    expect(
      (await auditLog.query({ operation_type: "workload_forked" })).entries
    ).toHaveLength(1);
  });

  it("refuses to write the distress op — only the canonical emitter may", async () => {
    // Distress is reused as a vocabulary marker, but the bounded distress
    // emitter owns rate limit + envelope + egress ordering. The generic writer
    // must NOT short-circuit it.
    const auditLog = await newAuditLog();
    await expect(
      emitWorkloadLifecycle({
        auditLog,
        operation: WORKLOAD_LIFECYCLE_OPS.DISTRESS_SIGNALED,
        identity_id: "fortress-1",
        payload: basePayload(),
      })
    ).rejects.toThrow(/canonical distress emitter/);
    const { total } = await auditLog.query({ layer: "l2" });
    expect(total).toBe(0);
  });
});

describe("signedEventHash binding", () => {
  it("is deterministic sha256 over canonical JSON of the packed event", () => {
    const evt = { a: 1, b: [2, 3], event_id: "e-1" };
    expect(signedEventHash(evt)).toBe(sha256Hex(canonicalJson(evt)));
    // Key order in the input does not change the hash.
    expect(signedEventHash({ b: [2, 3], event_id: "e-1", a: 1 })).toBe(
      signedEventHash(evt)
    );
  });
});

describe("M3 — single sanctioned writer guard", () => {
  // The lifecycle vocabulary must be written ONLY through emitWorkloadLifecycle
  // (which is the only thing that calls appendCritical with a workload_* op).
  // The canonical distress op is excluded — it legitimately predates this schema
  // and is owned by distress/tools.ts.
  //
  // This guard is a heuristic, not a proof: it cannot catch a value computed at
  // runtime. It catches the two realistic regressions — a hardcoded workload_*
  // literal, OR a reference to a WORKLOAD_LIFECYCLE_OPS member — appearing in a
  // file that ALSO writes to the audit log (append/appendCritical), anywhere
  // outside the sanctioned schema module.
  const SCHEMA_DIR = join("src", "workload-lifecycle");

  async function scanSrc(
    predicate: (text: string, file: string) => string[]
  ): Promise<string[]> {
    const srcRoot = join(__dirname, "..", "..", "src");
    const offenders: string[] = [];
    async function walk(dir: string): Promise<void> {
      for (const ent of await readdir(dir, { withFileTypes: true })) {
        const full = join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === "node_modules") continue;
          await walk(full);
          continue;
        }
        if (!ent.name.endsWith(".ts")) continue;
        if (full.includes(SCHEMA_DIR)) continue; // sanctioned home
        const text = await readFile(full, "utf8");
        offenders.push(...predicate(text, full));
      }
    }
    await walk(srcRoot);
    return offenders;
  }

  it("no source file outside the schema module hardcodes a workload_* op literal", async () => {
    const workloadOps = WORKLOAD_LIFECYCLE_OP_VALUES.filter((op) =>
      op.startsWith("workload_")
    );
    const offenders = await scanSrc((text, file) =>
      workloadOps
        .filter((op) => text.includes(`"${op}"`) || text.includes(`'${op}'`))
        .map((op) => `${file}: literal ${op}`)
    );
    expect(offenders).toEqual([]);
  });

  it("no file that writes to the audit log references the lifecycle op constants", async () => {
    // A file that both references WORKLOAD_LIFECYCLE_OPS.<member> AND calls an
    // audit append is a candidate rogue writer — exactly the appendCritical(
    // { operation: WORKLOAD_LIFECYCLE_OPS.DELETED }) escape codex flagged.
    const offenders = await scanSrc((text, file) => {
      const usesOpConstant = /WORKLOAD_LIFECYCLE_OPS\s*\./.test(text);
      const writesAudit = /\.append(Critical)?\s*\(/.test(text);
      return usesOpConstant && writesAudit
        ? [`${file}: references WORKLOAD_LIFECYCLE_OPS and calls audit append`]
        : [];
    });
    expect(offenders).toEqual([]);
  });
});
