/**
 * Broker daemon liveness heartbeat PRODUCER — interval beat + stand-down.
 *
 * Mirrors the Castle Wall producer integration test: an injected in-memory
 * AuditLog + fake timers, no MCP server. Asserts the producer emits a MARKED
 * beat immediately and on the interval, and that a clean stand-down appends the
 * stand-down marker exactly once (the load-bearing #657 false-RED parity).
 *
 * The end-to-end PROCESS-LIFECYCLE drill (kill the real broker-server, watch the
 * row flip to dead_no_heartbeat; clean-stop it, watch intentionally_stopped) is
 * DRILL-PENDING and not provable from CI - see the PR body. This test proves the
 * producer's emission behavior in isolation.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { startBrokerLivenessHeartbeat } from "../../src/broker-mcp/liveness-heartbeat.js";
import {
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
} from "../../src/broker-mcp/liveness-constants.js";
import {
  BROKER_PRODUCER_SIG_DETAIL_KEY,
  BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY,
  BROKER_PRODUCER_SIGNATURE_SCHEME_V1,
  BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  loadBrokerProducerKey,
  loadOrCreateBrokerProducerSigner,
} from "../../src/broker-mcp/producer-signature.js";

const FORTRESS = "fortress:broker-producer-test";

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

async function newSigner() {
  const dir = await mkdtemp(join(tmpdir(), "broker-liveness-signer-"));
  const signer = await loadOrCreateBrokerProducerSigner(dir);
  return { dir, signer };
}

async function countOp(log: AuditLog, operation: string): Promise<number> {
  const { entries } = await log.query({ limit: 10_000 });
  return entries.filter((e) => e.operation === operation).length;
}

async function waitForOpCount(
  log: AuditLog,
  operation: string,
  count: number,
): Promise<void> {
  await vi.waitFor(async () => {
    expect(await countOp(log, operation)).toBe(count);
  });
}

async function markedEntriesFor(log: AuditLog, operation: string) {
  const { entries } = await log.query({ limit: 10_000 });
  return entries.filter(
    (e) =>
      e.operation === operation &&
      e.layer === "l3" &&
      (e.details as Record<string, unknown> | undefined)?.[
        BROKER_DAEMON_AUDIT_PROVENANCE_KEY
      ] === BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  );
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("broker daemon liveness producer — emits a marked beat", () => {
  it("emits one MARKED beat immediately on start", async () => {
    const log = newLog();
    const { dir, signer } = await newSigner();
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 1);
    const beats = await markedEntriesFor(log, BROKER_DAEMON_HEARTBEAT_OPERATION);
    expect(beats.length).toBe(1);
    // Process-liveness layer is l3 (the broker layer).
    expect(beats[0]?.layer).toBe("l3");
    expect(beats[0]?.details?.[BROKER_PRODUCER_SIG_DETAIL_KEY]).toEqual(
      expect.any(String),
    );
    expect(
      beats[0]?.details?.[BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY],
    ).toBe(BROKER_PRODUCER_SIGNATURE_SCHEME_V1);
    expect(
      beats[0]?.details?.[BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY],
    ).toEqual(expect.any(String));
    expect(
      beats[0]?.details?.[BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY],
    ).toEqual(expect.any(Number));
    expect(beats[0]?.details?.seq).toBe(1);
    expect(await loadBrokerProducerKey(dir)).toMatchObject({
      status: "present",
    });
    handle.stop();
    await rm(dir, { recursive: true, force: true });
  });

  it("emits additional beats on the ~45s interval", async () => {
    vi.useFakeTimers();
    const log = newLog();
    const { dir, signer } = await newSigner();
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    // Immediate beat.
    await vi.advanceTimersByTimeAsync(0);
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 1);
    // Two interval ticks → two more beats.
    await vi.advanceTimersByTimeAsync(45_000);
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 2);
    await vi.advanceTimersByTimeAsync(45_000);
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 3);
    const beats = await markedEntriesFor(log, BROKER_DAEMON_HEARTBEAT_OPERATION);
    expect(beats.map((b) => b.details?.seq)).toEqual([1, 2, 3]);
    handle.stop();
    await rm(dir, { recursive: true, force: true });
  });

  it("stop() halts the interval — no further beats after stop", async () => {
    vi.useFakeTimers();
    const log = newLog();
    const { dir, signer } = await newSigner();
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    await vi.advanceTimersByTimeAsync(0);
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 1);
    handle.stop();
    await vi.advanceTimersByTimeAsync(45_000 * 3);
    await log.flush();
    // Only the immediate beat survives; the interval was cleared.
    expect(await countOp(log, BROKER_DAEMON_HEARTBEAT_OPERATION)).toBe(1);
    await rm(dir, { recursive: true, force: true });
  });
});

describe("broker daemon liveness producer — SIGTERM-style stand-down (#657 parity)", () => {
  it("standDown() appends exactly one MARKED stand-down and clears the interval", async () => {
    vi.useFakeTimers();
    const log = newLog();
    const { dir, signer } = await newSigner();
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    await vi.advanceTimersByTimeAsync(0);
    await waitForOpCount(log, BROKER_DAEMON_HEARTBEAT_OPERATION, 1);

    await handle.standDown();
    await log.flush();

    const standDowns = await markedEntriesFor(
      log,
      BROKER_DAEMON_STAND_DOWN_OPERATION,
    );
    expect(standDowns.length).toBe(1);
    expect(standDowns[0]?.layer).toBe("l3");
    expect(standDowns[0]?.details?.[BROKER_PRODUCER_SIG_DETAIL_KEY]).toEqual(
      expect.any(String),
    );
    expect(standDowns[0]?.details?.seq).toBe(2);

    // The interval was cleared by stand-down: no further beats.
    await vi.advanceTimersByTimeAsync(45_000 * 3);
    await log.flush();
    expect(await countOp(log, BROKER_DAEMON_HEARTBEAT_OPERATION)).toBe(1);
    await rm(dir, { recursive: true, force: true });
  });

  it("standDown() is idempotent — a second call (SIGTERM then SIGINT) does NOT double-emit", async () => {
    const log = newLog();
    const { dir, signer } = await newSigner();
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    await log.flush();
    await handle.standDown();
    await handle.standDown();
    await log.flush();
    expect(await countOp(log, BROKER_DAEMON_STAND_DOWN_OPERATION)).toBe(1);
    await rm(dir, { recursive: true, force: true });
  });

  it("a heartbeat write failure never throws out of the producer (fail toward the alarm)", async () => {
    const log = newLog();
    const { dir, signer } = await newSigner();
    // Force append to reject; the producer must swallow it.
    vi.spyOn(log, "appendCritical").mockRejectedValue(new Error("storage down"));
    const handle = startBrokerLivenessHeartbeat({
      auditLog: log,
      fortressId: FORTRESS,
      producerSigner: signer,
      intervalSeconds: 45,
    });
    // standDown also tries to append; it must resolve, not reject.
    await expect(handle.standDown()).resolves.toBeUndefined();
    handle.stop();
    await rm(dir, { recursive: true, force: true });
  });
});
