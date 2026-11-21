// What each outside signal does to a recall in flight, as wired: a public cancel and a vanished peer leave the recall
// running to its own bounded end and its audit row; a process stop and a relay shutdown abort it. None writes to the
// memory corpus or quarantines, and after repeated waves no read is left in flight and every admission record is free.
import { describe, expect, it } from "vitest";
import { quiesce, recallBridge, turnsUntil } from "./recall-read-ahead-harness.js";

const passages = Array.from({ length: 6 }, (_, n) => ({ id: `p${String(n).padStart(2, "0")}`, text: `board meeting ${n}` }));
const ALL = passages.map(passage => passage.id);
const parkAt = (id: string) => (key: string) => key === `doc.mem.agent.${id}` ? "park" as const : undefined;

describe("one recall in flight, with a parked read, under each signal", () => {
  it("public cancel: the recall is not aborted; it finishes, answers and appends its audit row", async () => {
    const h = await recallBridge(passages);
    try {
      h.storage.rule = parkAt("p01");
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 1);
      h.cancel("c1", "r1");
      await quiesce();
      h.storage.release();
      await turnsUntil(() => h.recordCount() === 0);
      // The property: cancel reaches only an insert's approval entry, so the recall ran to a complete answer.
      expect(h.recallAudits()).toEqual([expect.objectContaining({ truncated: false })]);
      expect(h.body("r1")).toMatchObject({ outcome: "recalled", truncated: false });
      expect((h.body("r1").passages as unknown[]).length).toBe(3);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });

  it("peer disconnect: the recall is not aborted; it finishes and appends its audit row, and no frame is written", async () => {
    const h = await recallBridge(passages);
    try {
      h.storage.rule = parkAt("p01");
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 1);
      h.close("c1");
      await quiesce();
      // The detached record still counts against admission until the recall settles.
      expect(h.recordCount()).toBe(1);
      h.storage.release();
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.recallAudits()).toEqual([expect.objectContaining({ truncated: false })]);
      expect(h.recallAudits()[0]!.passage_ids).toHaveLength(3);
      expect(h.responses("r1")).toEqual([]);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });

  it("process stop (the shell's signal path, relay EOF): the recall is aborted, appends a truncated audit row and writes no frame", async () => {
    const h = await recallBridge(passages);
    try {
      h.storage.rule = parkAt("p01");
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 1);
      h.core.relayEof();
      await quiesce();
      h.storage.release();
      await turnsUntil(() => h.recallAudits().length === 1);
      // The property: the process abort signal stops the scan and the verification phase.
      expect(h.recallAudits()[0]).toMatchObject({ truncated: true, passage_ids: [] });
      expect(h.responses("r1")).toEqual([]);
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); }
  });

  it("relay shutdown: the recall is aborted, appends a truncated audit row and writes no frame", async () => {
    const h = await recallBridge(passages);
    try {
      h.storage.rule = parkAt("p01");
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 1);
      h.core.relayFrame({ kind: "relay_shutdown" });
      await quiesce();
      h.storage.release();
      await turnsUntil(() => h.recallAudits().length === 1);
      expect(h.recallAudits()[0]).toMatchObject({ truncated: true, passage_ids: [] });
      expect(h.responses("r1")).toEqual([]);
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); }
  });
});

describe("repeated waves", () => {
  const WAVES = 12; // Twelve calls: more than HERMES_MAX_CALL_RECORDS, so a record left held would refuse a later call.
  it("cancel waves leave no read in flight and every admission record free", async () => {
    const h = await recallBridge(passages);
    try {
      h.accept("c1");
      for (let n = 0; n < WAVES; n++) {
        h.storage.rule = parkAt(ALL[1 + (n % (ALL.length - 1))]!);
        h.call("c1", `cancel-${n}`);
        await turnsUntil(() => h.storage.parked.length === 1);
        h.cancel("c1", `cancel-${n}`);
        await quiesce(5);
        h.storage.release();
        await turnsUntil(() => h.recordCount() === 0);
        expect(h.storage.inFlight).toBe(0);
        expect(h.body(`cancel-${n}`)).toMatchObject({ outcome: "recalled" });
      }
      expect(h.recallAudits()).toHaveLength(WAVES);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });

  it("disconnect and reconnect waves leave no read in flight and every admission record free", async () => {
    const h = await recallBridge(passages);
    try {
      for (let n = 0; n < WAVES; n++) {
        h.storage.rule = parkAt(ALL[1 + (n % (ALL.length - 1))]!);
        h.accept(`c${n}`); h.call(`c${n}`, `gone-${n}`);
        await turnsUntil(() => h.storage.parked.length === 1);
        h.close(`c${n}`);
        await quiesce(5);
        h.storage.release();
        await turnsUntil(() => h.recordCount() === 0);
        expect(h.storage.inFlight).toBe(0);
      }
      // Every vanished caller's recall still appended its audit row; none wrote a response frame.
      expect(h.recallAudits()).toHaveLength(WAVES);
      expect(h.writes.filter(row => row.type === "response")).toEqual([]);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});
