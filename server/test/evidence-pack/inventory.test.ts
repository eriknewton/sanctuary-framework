// fail-before-exempt: authenticated StateStore fixture wiring only; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Sanctuary MCP Server - Evidence Pack inventory-collector tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, hermetic tests for the inventory collector: the mapping from the three
 * shipped enumeration sources into a per-source {@link ReadOutcome}, including
 * the ok+empty vs failed+reason distinction that the typed chokepoint enforces.
 */

import { describe, it, expect } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createIdentity, type StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { ObserveStore } from "../../src/castle-wall/observe/store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { CandidateObservation } from "../../src/castle-wall/observe/types.js";
import {
  buildEvidencePack,
  REPORT_FILENAME,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import {
  buildInventorySnapshot,
  emptyInventorySnapshot,
  notCollectedInventorySnapshot,
  type ProxyServerView,
} from "../../src/evidence-pack/inventory.js";
import { readObservedDestinationCandidatesStrict } from "../../src/evidence-pack/observe-candidates.js";
import type {
  EvidencePack,
  EvidencePackInput,
  InventoryAgentRow,
  InventoryMcpServerRow,
  InventoryObservedDestinationRow,
  InventorySnapshot,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";
import { populated, type ReadOutcome } from "../../src/evidence-pack/read-outcome.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

function rowsOf<T>(o: ReadOutcome<T[]>): T[] {
  return o.status === "populated" ? o.value : [];
}

function agentRecord(over: Partial<LocalAgentRecord>): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-x",
    identity_id: "id-1",
    harness: "claude_code",
    model_provider: { vendor: "anthropic", model_id: "claude-opus-4", runs_locally: false },
    policy_id: "pol-1",
    status: "active",
    budget_summary: { last_refreshed_at: "2026-08-01T00:00:00.000Z" },
    last_activity_at: "2026-08-10T00:00:00.000Z",
    wrapped_at: "2026-07-15T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
    ...over,
  };
}

function candidate(over: Partial<CandidateObservation>): CandidateObservation {
  return {
    agent_id: "agent-x",
    agent_template: "coding-assistant",
    host: "api.openai.com",
    ip: "1.2.3.4",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 3,
    first_seen: "2026-08-01T00:00:00.000Z",
    last_seen: "2026-08-10T00:00:00.000Z",
    would_be_disposition: "denied",
    exfil_risk: false,
    ...over,
  };
}

function retention(): RetentionFacts {
  return {
    max_entries: 100_000,
    retained_total: 0,
    max_total_size_bytes: 100 * 1024 * 1024,
    retained_total_size_bytes: 0,
    ever_pruned: false,
    earliest_retained_at: null,
    daemon_store: { status: "absent", included_entry_count: 0 },
  };
}

function packInput(inventory: InventorySnapshot): EvidencePackInput {
  return {
    firm_name: "Evidence R1 Law LLP",
    quarter: { year: 2026, quarter: 3 },
    generated_at_override: "2026-10-02T00:00:00.000Z",
    custody: populated({
      custody_mode: "passphrase",
      outbound_denied_by_default: populated(true),
    }),
    inventory,
  };
}

function deps(signer: StoredIdentity, masterKey: Uint8Array): BuildEvidencePackDeps {
  const audit: ReadOutcome<AuditReadData> = populated({
    entries: [],
    retention: retention(),
  });
  return { audit, signer, masterKey };
}

function reportText(pack: EvidencePack): string {
  const report = pack.files.find((file) => file.filename === REPORT_FILENAME);
  if (!report) throw new Error("expected report file");
  return report.content;
}

async function makeObservedStore(): Promise<{
  store: ObserveStore;
  stateStore: StateStore;
  signer: StoredIdentity;
  masterKey: Uint8Array;
}> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("evidence-r1", identityEncryptionKey, "passphrase");
  await persistStoredIdentity(storage, masterKey, storedIdentity);
  const store = new ObserveStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey,
  });
  return { store, stateStore, signer: storedIdentity, masterKey };
}

describe("buildInventorySnapshot", () => {
  it("maps agent records to a populated outcome and sorts the rows", () => {
    const snap = buildInventorySnapshot({
      agents: {
        ok: true,
        records: [
          agentRecord({ agent_id: "zeta", harness: "cursor" }),
          agentRecord({ agent_id: "alpha", harness: "hermes" }),
        ],
      },
    });
    expect(snap.agents.status).toBe("populated");
    const rows = rowsOf<InventoryAgentRow>(snap.agents);
    expect(rows.map((a) => a.agent_id)).toEqual(["alpha", "zeta"]);
    const alpha = rows[0]!;
    expect(alpha.harness).toBe("hermes");
    expect(alpha.model_vendor).toBe("anthropic");
    expect(alpha.model_id).toBe("claude-opus-4");
    expect(alpha.wrapped_at).toBe("2026-07-15T00:00:00.000Z");
  });

  it("maps proxy servers to a populated outcome and sorts them", () => {
    const servers: ProxyServerView[] = [
      { name: "weather", transport: "stdio", enabled: true },
      { name: "email", transport: "http", enabled: false },
    ];
    const snap = buildInventorySnapshot({ proxyServers: { ok: true, records: servers } });
    expect(rowsOf<InventoryMcpServerRow>(snap.mcp_servers).map((s) => s.name)).toEqual([
      "email",
      "weather",
    ]);
  });

  it("maps observed destinations, falling back to the IP when no hostname was seen", () => {
    const snap = buildInventorySnapshot({
      observedDestinations: {
        ok: true,
        records: [
          candidate({ host: "api.telegram.org", port: 443, exfil_risk: true }),
          candidate({ host: null, ip: "9.9.9.9", port: 8080 }),
        ],
      },
    });
    const rows = rowsOf<InventoryObservedDestinationRow>(snap.observed_destinations);
    expect(rows.map((d) => d.host)).toEqual(["9.9.9.9", "api.telegram.org"]);
    const telegram = rows.find((d) => d.host === "api.telegram.org")!;
    expect(telegram.exfil_risk).toBe(true);
  });

  it("rejects malformed observed-destination candidates as read_failed, never populated", () => {
    const snap = buildInventorySnapshot({
      observedDestinations: {
        ok: true,
        records: [
          candidate({
            host: "api.telegram.org",
            would_be_disposition: "allowed",
            times_seen: -7,
            first_seen: "not-a-timestamp",
            exfil_risk: false,
          }),
        ],
      },
    });
    expect(snap.observed_destinations.status).toBe("read_failed");
    if (snap.observed_destinations.status === "read_failed") {
      expect(snap.observed_destinations.reason).toContain("malformed candidate evidence");
      expect(snap.observed_destinations.reason).not.toContain("allowed");
      expect(snap.observed_destinations.reason).not.toContain("-7");
      expect(snap.observed_destinations.reason).not.toContain("not-a-timestamp");
      expect(snap.observed_destinations.reason).not.toContain("api.telegram.org");
    }
  });

  it("rejects a zero-count observed destination before it can sign denied-flow prose", async () => {
    const snap = buildInventorySnapshot({
      observedDestinations: {
        ok: true,
        records: [candidate({ times_seen: 0 })],
      },
    });

    expect(snap.observed_destinations.status).toBe("read_failed");
    const fixture = await makeObservedStore();
    const pack = buildEvidencePack(packInput(snap), deps(fixture.signer, fixture.masterKey));
    const text = reportText(pack);
    expect(text).toContain("malformed candidate evidence");
    expect(text).not.toContain("| api.openai.com |");
    expect(text).not.toContain("Each row is a destination the wall DENIED");
  });

  it("a failed source is read_failed with a reason and NO rows (never a partial list)", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: false, records: [], reason: "profile could not be read" },
    });
    expect(snap.agents.status).toBe("read_failed");
    if (snap.agents.status === "read_failed") {
      expect(snap.agents.reason).toBe("profile could not be read");
    }
    expect(rowsOf(snap.agents)).toEqual([]);
  });

  it("a successful empty read is empty_verified (a genuine 'none', the only definitive-negative source)", () => {
    const snap = buildInventorySnapshot({ agents: { ok: true, records: [] } });
    expect(snap.agents.status).toBe("empty_verified");
  });

  it("R3-5: an undefined (not-collected) source is a FAILED read, never a minted EmptyVerified witness", () => {
    const snap = buildInventorySnapshot({});
    for (const source of [snap.agents, snap.mcp_servers, snap.observed_destinations]) {
      expect(source.status).toBe("read_failed");
      if (source.status === "read_failed") {
        expect(source.reason).toContain("not collected");
      }
    }
  });

  it("emptyInventorySnapshot stays all empty_verified (an EXPLICIT verified-empty constructor, never a not-collected default)", () => {
    const empty = emptyInventorySnapshot();
    expect(empty.agents.status).toBe("empty_verified");
    expect(empty.mcp_servers.status).toBe("empty_verified");
    expect(empty.observed_destinations.status).toBe("empty_verified");
  });

  it("R3-5: notCollectedInventorySnapshot is all read_failed with the not-collected reason", () => {
    const snap = notCollectedInventorySnapshot();
    for (const source of [snap.agents, snap.mcp_servers, snap.observed_destinations]) {
      expect(source.status).toBe("read_failed");
      if (source.status === "read_failed") {
        expect(source.reason).toContain("not collected");
      }
    }
  });

  it("a populated section carries only { status, value } - no completeness/total flag", () => {
    const snap = buildInventorySnapshot({
      agents: { ok: true, records: [agentRecord({ agent_id: "a" })] },
    });
    expect(Object.keys(snap.agents).sort()).toEqual(["status", "value"]);
  });

  describe("R4-2 pre-idempotency (un-healed legacy observe store) signal", () => {
    it("sets observed_destinations_pre_idempotency when a populated store had no fold watermark", () => {
      const snap = buildInventorySnapshot({
        observedDestinations: {
          ok: true,
          records: [candidate({ host: "api.telegram.org", exfil_risk: true })],
        },
        observedStorePreIdempotency: true,
      });
      expect(snap.observed_destinations.status).toBe("populated");
      expect(snap.observed_destinations_pre_idempotency).toBe(true);
    });

    it("is false on a post-#931 (watermarked) store even when populated", () => {
      const snap = buildInventorySnapshot({
        observedDestinations: {
          ok: true,
          records: [candidate({ host: "api.telegram.org", exfil_risk: true })],
        },
        observedStorePreIdempotency: false,
      });
      expect(snap.observed_destinations_pre_idempotency).toBe(false);
    });

    it("is dropped (false) when the observe read is NOT populated - no rows means no Seen caveat to orphan", () => {
      // Empty read + the legacy signal: nothing renders, so the caveat is suppressed.
      const emptyRead = buildInventorySnapshot({
        observedDestinations: { ok: true, records: [] },
        observedStorePreIdempotency: true,
      });
      expect(emptyRead.observed_destinations.status).toBe("empty_verified");
      expect(emptyRead.observed_destinations_pre_idempotency).toBe(false);

      // Failed read + the legacy signal: same suppression.
      const failedRead = buildInventorySnapshot({
        observedDestinations: { ok: false, records: [], reason: "store unreadable" },
        observedStorePreIdempotency: true,
      });
      expect(failedRead.observed_destinations.status).toBe("read_failed");
      expect(failedRead.observed_destinations_pre_idempotency).toBe(false);
    });

    it("defaults to false when the signal is omitted", () => {
      const snap = buildInventorySnapshot({
        observedDestinations: {
          ok: true,
          records: [candidate({ host: "api.telegram.org", exfil_risk: true })],
        },
      });
      expect(snap.observed_destinations_pre_idempotency).toBe(false);
    });
  });

  describe("R1: strict persisted observe-candidate boundary", () => {
    it("real persisted garbage renders as read_failed with no raw row contents", async () => {
      const fixture = await makeObservedStore();
      await fixture.store.putCandidate(
        candidate({
          host: "leaky-r1.example",
          would_be_disposition: "allowed",
          times_seen: -7,
          first_seen: "not-a-timestamp",
          exfil_risk: true,
        })
      );

      const observedDestinations = await readObservedDestinationCandidatesStrict(
        fixture.stateStore
      );
      const snapshot = buildInventorySnapshot({
        agents: { ok: true, records: [] },
        proxyServers: { ok: true, records: [] },
        observedDestinations,
      });

      expect(snapshot.observed_destinations.status).toBe("read_failed");
      const report = reportText(
        buildEvidencePack(packInput(snapshot), deps(fixture.signer, fixture.masterKey))
      );
      expect(report).toContain("observed egress destination inventory could not be read");
      expect(report).toContain("malformed candidate evidence");
      expect(report).not.toContain("leaky-r1.example");
      expect(report).not.toContain("-7");
      expect(report).not.toContain("not-a-timestamp");
    });

    it("real persisted valid observe candidate still renders through the pack", async () => {
      const fixture = await makeObservedStore();
      await fixture.store.putCandidate(
        candidate({
          host: "api.telegram.org",
          times_seen: 4,
          exfil_risk: true,
        })
      );

      const observedDestinations = await readObservedDestinationCandidatesStrict(
        fixture.stateStore
      );
      const snapshot = buildInventorySnapshot({
        agents: { ok: true, records: [] },
        proxyServers: { ok: true, records: [] },
        observedDestinations,
      });

      expect(snapshot.observed_destinations.status).toBe("populated");
      const report = reportText(
        buildEvidencePack(packInput(snapshot), deps(fixture.signer, fixture.masterKey))
      );
      expect(report).toContain("api.telegram.org");
      expect(report).toContain("elevated (review)");
      expect(report).toContain("| 4 |");
    });
  });
});
