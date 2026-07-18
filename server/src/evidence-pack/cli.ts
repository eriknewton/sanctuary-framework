/**
 * Sanctuary MCP Server - Law-firm Evidence Pack CLI
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage:
 *   sanctuary evidence-pack generate --quarter 2026-Q3 --firm "Acme Law"
 *
 * Spins up a Sanctuary server instance, pulls the retained audit history,
 * aggregates the requested calendar quarter, and writes a signed evidence
 * pack (a human-readable PDF + a signed Markdown report + a signed manifest)
 * to the output directory.
 *
 * NOT LEGAL ADVICE. The generated pack is a technical artifact.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { createSanctuaryServer } from "../index.js";
import type { SanctuaryConfig } from "../config.js";
import type { StoredIdentity } from "../core/identity.js";
import { AuditIntegrityError, type AuditEntry } from "../operational/audit-log.js";
import {
  createDaemonAuditLog,
  daemonMigrationEstablished,
  errnoAccessReason,
  resolveDaemonStorePresence,
} from "../operational/audit-store-split.js";
import { fortressRanAuditStoreSplitMigration } from "../cli/audit-chain-export.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  anchorReceiptsPresentOnDisk,
  buildAnchorsExport,
  readAnchorConfig,
} from "../transparency/anchoring.js";
import type { StorageBackend } from "../storage/interface.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { StateStore } from "../cognitive/state-store.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { ObserveStore } from "../castle-wall/observe/index.js";
import type { CandidateObservation } from "../castle-wall/observe/types.js";
import { readPersistedLocalAgents } from "../hub/agent-registry-persistence.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import { SovereigntyProfileStore } from "../sovereignty-profile.js";
import { readPersistedCheckpoints } from "../transparency/emitter.js";
import {
  TRANSPARENCY_BUNDLE_FORMAT,
  type TransparencyBundle,
} from "../transparency/checkpoint.js";
import { exportAuditChain, totalRecordsSkipped } from "../cli/audit-chain-export.js";
import type {
  CustodyFacts,
  DaemonStoreDisclosure,
  EvidencePackDiscreteExports,
  EvidencePackInput,
  InventorySnapshot,
  PerStoreRetention,
  RetentionFacts,
} from "./types.js";
import {
  buildInventorySnapshot,
  type InventorySourceRead,
  type ProxyServerView,
} from "./inventory.js";
import {
  emptyVerified,
  populated,
  readFailed,
  type ReadOutcome,
} from "./read-outcome.js";
import {
  buildEvidencePack,
  MANIFEST_FILENAME,
  PDF_FILENAME,
  PRODUCT_NAME,
  REPORT_FILENAME,
  type AuditReadData,
} from "./generate.js";
import { currentQuarter, parseQuarterLabel, quarterLabel } from "./quarter.js";

/**
 * Enumerate the AI-tool inventory from the fortress's persisted state,
 * READ-ONLY and with NO live upstream connections or network: wrapped-harness
 * records from the plaintext hub registry file, configured MCP tool servers
 * from the sovereignty profile, and observed egress destinations from the
 * encrypted observe store. Each source captures its READ OUTCOME (ok + records,
 * or failed + reason) so the renderer distinguishes a genuine empty ("none
 * recorded") from a read failure ("could not be read; incomplete") and NEVER
 * renders a failed read as an affirmative census claim (slice-2 MED-2 / HIGH-1).
 * Never establishes a live connection during pack generation.
 */
async function gatherInventory(
  config: SanctuaryConfig,
  storage: StorageBackend,
  masterKey: Uint8Array,
  signer: StoredIdentity
): Promise<InventorySnapshot> {
  const agents: InventorySourceRead<LocalAgentRecord> = (() => {
    try {
      return { ok: true, records: readPersistedLocalAgents(config.storage_path) };
    } catch (e) {
      return {
        ok: false,
        records: [],
        reason: `the hub agent registry could not be read: ${(e as Error).message}`,
      };
    }
  })();

  const proxyServers: InventorySourceRead<ProxyServerView> = await (async () => {
    try {
      const profileStore = new SovereigntyProfileStore(storage, masterKey);
      await profileStore.load();
      return {
        ok: true,
        records: (profileStore.get().upstream_servers ?? []).map((u) => ({
          name: u.name,
          transport: u.transport.type,
          enabled: u.enabled,
        })),
      };
    } catch (e) {
      return {
        ok: false,
        records: [],
        reason: `the sovereignty profile could not be read: ${(e as Error).message}`,
      };
    }
  })();

  // R4-2 (round-4 sweep 2026-07-15; gate-hardened): alongside the candidate
  // rows, capture whether the store has NOT completed a reconciling refresh
  // (candidate rows present but no fold watermark). The pack renders the
  // persisted store WITHOUT folding (staying non-mutating + offline +
  // allowlist-independent), so it cannot reconcile the store; instead it
  // detects the condition here and the renderer discloses that the rows may
  // not reflect a reconciled state. A missing watermark alongside rows is a
  // legacy PRE-#931 additive store OR the narrow window of a post-#931
  // recompute-heal that crashed after writing rows but before advancing the
  // watermark (refresh.ts, non-atomic by design); the caveat wording covers
  // both without attributing a specific cause. The signal is sound in the
  // dangerous direction -- a store that HAS completed a reconciling refresh
  // always carries a watermark, so a genuinely un-reconciled store is never
  // missed.
  let observedStorePreIdempotency = false;
  const observedDestinations: InventorySourceRead<CandidateObservation> =
    await (async () => {
      try {
        const stateStore = new StateStore(storage, masterKey);
        const observeStore = new ObserveStore(stateStore, {
          identityId: signer.identity_id,
          encryptedPrivateKey: signer.encrypted_private_key,
          identityEncryptionKey: derivePurposeKey(masterKey, "identity-encryption"),
        });
        const records = [...(await observeStore.listCandidates()).values()];
        if (records.length > 0) {
          const watermark = await observeStore.getFoldWatermark();
          observedStorePreIdempotency = watermark === null;
        }
        return { ok: true, records };
      } catch (e) {
        return {
          ok: false,
          records: [],
          reason: `the observe store could not be read: ${(e as Error).message}`,
        };
      }
    })();

  return buildInventorySnapshot({
    agents,
    proxyServers,
    observedDestinations,
    observedStorePreIdempotency,
  });
}

/**
 * Gather the discrete third-party verification exports from persisted state,
 * offline: the signed transparency-checkpoint bundle (assembled from the
 * shipped `readPersistedCheckpoints`; requires a single signing key across the
 * checkpoints), the audit-chain JSONL export (from the shipped
 * `exportAuditChain`), and the public-anchor evidence (from the shipped
 * `buildAnchorsExport`). Each absent export carries an honest reason string.
 * Never contacts the network.
 *
 * R2-1 (dry-bar): the raw `exportAuditChain` dumps the OPERATOR `_audit` chain
 * only. On a fortress that ran the writer-split migration, a daemon enforcement
 * chain (`_audit-daemon`) also exists, so an operator-only export would present
 * an INCOMPLETE enforcement history as "the recorded enforcement history" (the
 * census hole G-1 closed on the counts, on the export surface). The gather omits
 * the audit-chain export (an honest `read_failed`) whenever EITHER the export
 * module's daemon-dir/marker probe (`fortressRanAuditStoreSplitMigration`, what
 * `runExport` fails closed on) OR the boundary-aware `daemonMigrationEstablished`
 * (which the census path uses and which catches a boundary-only migrated
 * fortress whose daemon dir + `_meta` marker were deleted) fires -- so the
 * export surface omits on the SAME evidence-destruction cases the census path
 * flags `missing`, not a weaker subset.
 *
 * C4 (dry-bar): the anchor export is read from actual anchoring state via
 * `readAnchorConfig` + `buildAnchorsExport`, NEVER minted as a bare
 * `empty_verified` (which would render a DEFINITIVE "anchoring is not enabled on
 * this install" even when it is enabled with receipts). A genuinely-absent
 * (authenticated) config is the only path to `empty_verified`.
 */
export async function gatherDiscreteExports(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  fortressId: string,
  generatedAt: string
): Promise<EvidencePackDiscreteExports> {
  const transparency: ReadOutcome<string> = await (async () => {
    try {
      const checkpoints = await readPersistedCheckpoints(storage);
      if (checkpoints.length === 0) {
        return emptyVerified();
      }
      const keys = new Set(checkpoints.map((c) => c.public_key));
      if (keys.size !== 1) {
        return readFailed(
          "the checkpoints carry more than one signing key; a single-key bundle could not be assembled. Investigate the key history before publishing."
        );
      }
      const bundle: TransparencyBundle = {
        format: TRANSPARENCY_BUNDLE_FORMAT,
        exported_at: generatedAt,
        public_key: [...keys][0]!,
        checkpoints,
      };
      return populated(JSON.stringify(bundle, null, 2));
    } catch (e) {
      return readFailed(`the transparency bundle could not be gathered: ${(e as Error).message}`);
    }
  })();

  const audit_chain: ReadOutcome<string> = await (async () => {
    try {
      // R2-1: refuse an operator-only chain on a split (migrated) fortress. The
      // raw exporter dumps `_audit` only; the daemon enforcement chain would be
      // silently omitted. This is the SAME fail-closed guard `runExport`
      // enforces (marker-aware: it also fires when the daemon directory was
      // deleted but the migration marker survives). Omitting it as a
      // `read_failed` is honest: §10 then states the export is not included and
      // why, instead of calling an incomplete chain "the recorded enforcement
      // history".
      // Consult BOTH the export module's own daemon-dir/marker probe AND the
      // marker+boundary-aware `daemonMigrationEstablished` (which the pack can
      // run because it holds the master key): the former misses a boundary-only
      // migrated fortress whose daemon dir was deleted and whose _meta marker is
      // absent, the latter closes that hole. Either firing means an operator-
      // only export would omit the daemon chain.
      if (
        (await fortressRanAuditStoreSplitMigration(storage)) ||
        (await daemonMigrationEstablished(storage, masterKey))
      ) {
        return readFailed(
          "a single-file audit-chain export could NOT be shown to be complete for " +
            "this fortress: it appears to have run the audit-store writer split (a " +
            "daemon enforcement chain _audit-daemon, or a durable split marker, is " +
            "present, or the check could not rule it out), so an operator-`_audit`-" +
            "only export would omit the root-owned daemon enforcement chain. It was " +
            "NOT included rather than risk presenting an incomplete enforcement " +
            "history as complete. Export the operator chain with 'sanctuary " +
            "audit-chain export --operator-only' and the daemon chain separately as " +
            "root."
        );
      }
      const chunks: Buffer[] = [];
      const sink = new Writable({
        write(chunk, _enc, cb) {
          chunks.push(Buffer.from(chunk));
          cb();
        },
      });
      const summary = await exportAuditChain(storage, sink);
      const jsonl = Buffer.concat(chunks).toString("utf8");
      // P1-A (dry-bar round 6): one or more LISTED records were unreadable /
      // invalid JSON / not a V2 envelope and were SKIPPED, so this export is
      // INCOMPLETE. Distinguish "listed N, exported < N" (a corrupt / partial
      // chain) from "listed 0" (a genuinely empty chain): never render a corrupt
      // all-skipped chain as a definitive §10 `emptyVerified` "empty" (a false
      // clean bill, the opposite of the tamper-evidence the export exists to
      // provide), and never sign a silently-partial chain as complete. Disclose
      // it as a read failure carrying the listed/exported/skipped counts.
      const skipped = totalRecordsSkipped(summary);
      if (skipped > 0) {
        return readFailed(
          "the audit-chain export could NOT be shown to be complete for this " +
            `fortress: ${skipped} listed record(s) were unreadable, invalid, or ` +
            "not a recognized audit record and were skipped (entries: listed " +
            `${summary.entriesListed}, exported ${summary.entriesExported}, ` +
            `skipped ${summary.entriesSkipped}; checkpoints: listed ` +
            `${summary.checkpointsListed}, exported ${summary.checkpointsExported}, ` +
            `skipped ${summary.checkpointsSkipped}). It was NOT included rather ` +
            "than present a corrupt or incomplete chain as a complete or empty one."
        );
      }
      return jsonl.length > 0 ? populated(jsonl) : emptyVerified();
    } catch (e) {
      return readFailed(`the audit-chain export could not be gathered: ${(e as Error).message}`);
    }
  })();

  // C4: read ACTUAL anchoring state rather than minting a bare verified-empty
  // (which renders a DEFINITIVE "anchoring is not enabled" even when it is
  // enabled with receipts). Public anchoring is opt-in / default-off. Honest
  // mapping, each arm backed by a real read:
  //   - config absent (MAC-authenticated) AND no receipts on disk -> verified
  //     empty (no anchor evidence: not enabled, or enabled-and-nothing-anchored;
  //     the §10 wording covers both);
  //   - config present (enabled/disabled) with >=1 receipt -> the real anchors
  //     export (historical anchors stay auditable even when currently disabled);
  //   - config present but ZERO receipts -> verified empty (configured, nothing
  //     anchored yet) -- NEVER populated, so §10 never says a receipt-less export
  //     lets an auditor "confirm the checkpoints were publicly anchored";
  //   - config absent but receipts PRESENT on disk (inconsistent), a tampered
  //     config, or any other read error -> read_failed, never a false "not
  //     enabled". `anchorReceiptsPresentOnDisk` fails toward "present", so an
  //     unlistable receipt store becomes read_failed here, not a false empty.
  const anchor: ReadOutcome<string> = await (async () => {
    try {
      const state = await readAnchorConfig({ storage, masterKey });
      const receiptsPresent = await anchorReceiptsPresentOnDisk(storage);
      if (state.status === "absent") {
        return receiptsPresent
          ? readFailed(
              "the anchoring config is absent but anchor receipts are present on " +
                "disk (an inconsistent anchoring state), so the anchor evidence " +
                "could not be gathered and this install's anchoring status could " +
                "not be determined."
            )
          : emptyVerified();
      }
      const anchorsDoc = await buildAnchorsExport({
        storage,
        masterKey,
        fortressId,
        now: () => new Date(generatedAt),
      });
      // Only a receipt with status "anchored" is public-anchor evidence. A
      // receipt-less export -- or one carrying ONLY failed anchor attempts (a
      // Rekor outage persists `status:"failed"` receipts) -- proves NOTHING was
      // publicly anchored, so it must not render as a definitive "publicly
      // anchored" claim. Verified empty instead ("enabled, nothing anchored yet").
      const hasAnchored = anchorsDoc.receipts.some(
        (r) => r.status === "anchored"
      );
      return hasAnchored
        ? populated(JSON.stringify(anchorsDoc, null, 2))
        : emptyVerified();
    } catch (e) {
      return readFailed(`the anchor evidence could not be gathered: ${(e as Error).message}`);
    }
  })();

  return { transparency, audit_chain, anchor };
}

/**
 * D5-2 (dry-bar round 5): merge two stores' `ever_pruned` facts WITHOUT
 * laundering an UNKNOWN (`null`) into a definitive `false`. `null` means a
 * store's `getRetentionUsage()` threw, so its pruned-status is genuinely
 * unknown; it is ABSORBING unless the other store DEFINITELY pruned:
 *
 *   - `true || anything    -> true`   (some store definitely pruned)
 *   - `null || (false|null) -> null`  (an unknown can NEVER become never-pruned)
 *   - `false || false      -> false`  (both stores definitely never pruned)
 *
 * The old `Boolean(a) || Boolean(b)` collapsed `null || false` to a definitive
 * `false`, re-enabling the flattering "the log has never pruned ... no recorded
 * activity before X" reassurance from a census that was not fully read. Exported
 * for direct unit coverage of the three-state truth table.
 */
export function mergeEverPruned(
  a: boolean | null,
  b: boolean | null
): boolean | null {
  if (a === true || b === true) return true;
  if (a === null || b === null) return null;
  return false;
}

/**
 * D8-1 Leg A (Dry-8 sweep): one store's retention-usage read as the pack
 * consumes it. `entryCount: null` is the SINGLE "usage unavailable" signal:
 * the underlying `AuditLog.getRetentionUsage()` returns a plain `number`
 * entryCount and can NEVER produce `null` itself, so a `null` here means the
 * whole usage read THREW and NOTHING about the store's on-disk usage was
 * read. `totalSizeBytes` is therefore `null` ("unread") in that state --
 * never the old `0` placeholder, which was a FILLER masquerading as a read
 * figure: it passed the chokepoint's finiteness checks and let the SIGNED
 * manifest serialize a definitive `retention_at_cap: false` (plus "below
 * both caps" prose) from a size nobody read, while the same pack's prose
 * hedged. `everPruned` may independently be `null` (its sub-read inside a
 * successful usage read is best-effort).
 */
export interface RetentionUsageRead {
  entryCount: number | null;
  totalSizeBytes: number | null;
  everPruned: boolean | null;
}

/**
 * D8-1 Leg A: the ONE catch for a failed `getRetentionUsage()` read (both the
 * operator and daemon call sites route through it). On a throw -- e.g. a
 * transient storage fault between `query()` succeeding and the usage
 * `storage.list()` -- it returns the all-`null` "usage unavailable" signal,
 * never placeholder figures. `deriveAuditReadOutcome` then records the
 * store's size position as UNREAD (`retained_total_size_bytes: null`), which
 * the `retentionDeterminability` chokepoint classifies NOT-DETERMINABLE: the
 * prose hedges AND the signed manifest carries the explicit
 * `retention_at_cap_determinable: false` marker instead of a definitive
 * boolean -- the two surfaces converge instead of contradicting each other.
 * Exported so tests can drive the REAL failure path with an injected throw.
 */
export async function readRetentionUsage(log: {
  getRetentionUsage(): Promise<{
    entryCount: number;
    totalSizeBytes: number;
    everPruned: boolean | null;
  }>;
}): Promise<RetentionUsageRead> {
  try {
    return await log.getRetentionUsage();
  } catch {
    return { entryCount: null, totalSizeBytes: null, everPruned: null };
  }
}

/**
 * Derive the pack's audit read outcome from the windowed `query()` result plus
 * the authoritative on-disk census. Pure; exported so tests can pin the
 * truncation and fallback semantics without a live server.
 *
 * Honesty invariants (each is a reviewed finding, not a style choice):
 *
 * - WATCH-2 (confirmatory review 2026-07-14): `retained_total` comes from the
 *   on-disk census (`getRetentionUsage().entryCount`), NOT from `query()`'s
 *   windowed total. The in-memory window (`maxInMemoryEntries`) today equals
 *   the on-disk cap, but it is an anticipated tuning knob; a windowed total
 *   would understate the retained log and defeat the shortfall detector's
 *   at-cap check. The windowed total is used only when the census itself was
 *   unreadable (`entryCount: null`).
 * - F3 (round-2 sweep 2026-07-14): if the read is provably INCOMPLETE - the
 *   on-disk census exceeds the windowed total (a RAM window smaller than the
 *   disk cap), or `query()` returned fewer entries than its own total (its
 *   `limit` truncated the result) - the whole audit read FAILS CLOSED to
 *   `read_failed`. Otherwise a truncated window would feed the aggregation and
 *   `earliest_retained_at`, and the shortfall reassurance arm ("the log has
 *   never pruned ... no recorded activity before <earliest>") would assert a
 *   false cause while older entries sit on disk outside the window. Neither
 *   truncation is constructible with today's defaults; the guard makes the
 *   anticipated configurations structurally safe.
 * - D8-1 Leg A note on F3 when usage is UNAVAILABLE (`entryCount: null`): the
 *   window-vs-census comparison has no census to compare against, so the
 *   `windowTruncated` half of the guard is INERT in that state. That is
 *   accepted, precisely because every claim the guard protects is disarmed
 *   elsewhere in the same state: (a) the `queryTruncated` half still fails
 *   closed on `query()`'s own internal truncation; (b) a RAM window smaller
 *   than the disk cap is not constructible with today's defaults
 *   (`maxInMemoryEntries` defaults to `maxEntries` -- the same reason F3 is
 *   an anticipatory guard at all); and (c) with usage unavailable this
 *   derivation records the store's size position as UNREAD (`null`), so the
 *   `retentionDeterminability` chokepoint classifies at-cap NOT-DETERMINABLE
 *   and the reassurance arm F3 exists to protect ("never pruned ... below
 *   both caps ... no recorded activity before X") structurally cannot fire
 *   (`ever_pruned` is also `null`, which `mergeEverPruned` keeps absorbing).
 *   The residual exposure -- a future window-smaller-than-disk configuration
 *   AND a usage fault in the same run -- yields hedged prose plus the signed
 *   not-determinable marker, never a definitive claim.
 * - R3-3 (round-3 sweep 2026-07-14): `earliest_retained_at` is the MINIMUM
 *   entry timestamp, not the positionally-first entry. Audit entries sort by
 *   append sequence, so under backward clock skew a later-appended entry can
 *   carry an earlier timestamp; taking `entries[0]` would then let the
 *   never-pruned reassurance arm assert "no recorded activity before X" while
 *   a retained entry is timestamped before X. An entry whose timestamp does
 *   not parse is skipped by the scan (with a positional fallback only if NO
 *   timestamp parses, preserving a non-null earliest for a non-empty read).
 */
export function deriveAuditReadOutcome(params: {
  entries: readonly AuditEntry[];
  windowedTotal: number;
  retentionConfig: { maxEntries: number; maxTotalSizeBytes: number };
  /** See {@link RetentionUsageRead}: `entryCount: null` = usage unavailable. */
  usage: RetentionUsageRead;
  /**
   * WATCH-1: the F2 daemon enforcement store (`_audit-daemon`) read, when the
   * operator store has been split. Omit (or `absent`) on a non-split fortress.
   * `included` merges the daemon entries + retention into the census;
   * `present_unreadable` discloses the daemon store exists but was not readable
   * at this privilege (the counts then EXCLUDE it, disclosed, never silent).
   * `missing` (C1): audit-store split evidence is present but the daemon store
   * is absent (deleted/renamed, or the split evidence is present-but-unverifiable
   * -- fail-closed) (excluded + disclosed, never conflated with `absent`).
   */
  daemon?:
    | { status: "absent" }
    | { status: "missing" }
    | { status: "present_unreadable"; unreadable_reason?: "privilege" | "io" }
    | { status: "present_tampered" }
    | {
        status: "included";
        entries: readonly AuditEntry[];
        windowedTotal: number;
        /** See {@link RetentionUsageRead}: `entryCount: null` = usage unavailable. */
        usage: RetentionUsageRead;
        /**
         * D5-1: the daemon store's OWN retention caps. Its own `AuditLog`
         * instance prunes on independent 100k-entry / 100 MB caps, so at-cap
         * must be evaluated against THESE, not the operator caps applied to the
         * merged two-store total.
         */
        retentionConfig: { maxEntries: number; maxTotalSizeBytes: number };
      };
  /**
   * D9C-1: the instant the audit census was taken (captured by the CLI BEFORE
   * `auditLog.query()`), threaded onto the returned {@link AuditReadData} so the
   * generator can bound the attested coverage window at the census cut rather
   * than the later generation instant. Omit for callers that do not track it.
   */
  censusTakenAt?: string;
}): ReadOutcome<AuditReadData> {
  const { entries, windowedTotal, retentionConfig, usage } = params;
  const daemon = params.daemon ?? { status: "absent" as const };
  // `entryCount: null` (usage unavailable) disarms this half of the F3 guard;
  // see the "D8-1 Leg A note on F3" in the doc comment for why that is inert
  // (queryTruncated still guards, the window==disk-cap default, and the unread
  // size position makes every protected claim not-determinable downstream).
  const windowTruncated =
    usage.entryCount !== null && usage.entryCount > windowedTotal;
  const queryTruncated = entries.length < windowedTotal;
  if (windowTruncated || queryTruncated) {
    const retainedCount = Math.max(usage.entryCount ?? 0, windowedTotal);
    return readFailed(
      `the audit log retains ${retainedCount} entries but only ` +
        `${entries.length} could be read by this run, so the retained ` +
        "history was not read to completion and the quarter's decision " +
        "counts and coverage are not determinable from this read"
    );
  }

  // D8-1 Leg A: a store whose usage read THREW (`entryCount: null`) had
  // NOTHING about its on-disk usage read, so its size position is UNREAD
  // (`null`) -- even if a stale caller still passes the old `totalSizeBytes: 0`
  // placeholder alongside `entryCount: null`, that figure is a filler by
  // construction, never a read, and must not reach the chokepoint as one. The
  // `null` size makes `retentionDeterminability` classify at-cap
  // NOT-DETERMINABLE (hedged prose + the signed manifest marker), which is the
  // honest rendering of "the retention position was not read this run".
  const readSize = (u: RetentionUsageRead): number | null =>
    u.entryCount === null ? null : u.totalSizeBytes;
  // Merged DISPLAY size: a sum over an unread contributor is itself unread.
  const addSizes = (a: number | null, b: number | null): number | null =>
    a === null || b === null ? null : a + b;

  // WATCH-1: fold the daemon store in. A truncated daemon read is the same
  // honesty failure as a truncated operator read: fail closed rather than
  // present a partial daemon census as complete.
  let mergedEntries: readonly AuditEntry[] = entries;
  let retainedTotal = usage.entryCount ?? windowedTotal;
  let retainedSizeBytes = readSize(usage);
  let everPruned = usage.everPruned;
  let includedDaemonCount = 0;
  // D5-1: the per-store retention breakdown that drives the at-cap decision.
  // The operator store is always a contributor; the daemon store is added only
  // when merged (`included`). `detectShortfall` ORs at-cap PER STORE against
  // each store's OWN cap, so a healthy split fortress whose MERGED total exceeds
  // one store's cap (while neither store is near its own) never renders "at cap".
  const perStoreRetention: PerStoreRetention[] = [
    {
      store: "operator",
      max_entries: retentionConfig.maxEntries,
      retained_total: usage.entryCount ?? windowedTotal,
      max_total_size_bytes: retentionConfig.maxTotalSizeBytes,
      retained_total_size_bytes: readSize(usage),
    },
  ];
  if (daemon.status === "included") {
    const daemonWindowTruncated =
      daemon.usage.entryCount !== null &&
      daemon.usage.entryCount > daemon.windowedTotal;
    const daemonQueryTruncated = daemon.entries.length < daemon.windowedTotal;
    if (daemonWindowTruncated || daemonQueryTruncated) {
      const retained = Math.max(daemon.usage.entryCount ?? 0, daemon.windowedTotal);
      return readFailed(
        `the daemon enforcement store (_audit-daemon) retains ${retained} ` +
          `entries but only ${daemon.entries.length} could be read by this ` +
          "run, so the daemon enforcement history was not read to completion " +
          "and the quarter's decision counts and coverage are not determinable"
      );
    }
    mergedEntries = [...entries, ...daemon.entries];
    includedDaemonCount = daemon.entries.length;
    retainedTotal += daemon.usage.entryCount ?? daemon.windowedTotal;
    retainedSizeBytes = addSizes(retainedSizeBytes, readSize(daemon.usage));
    // D5-2: merge the pruned-status WITHOUT laundering an UNKNOWN into `false`.
    // `null` (a store whose `getRetentionUsage()` threw) is ABSORBING unless the
    // other store definitely pruned: `true || anything -> true`,
    // `false || null -> null`, `null || null -> null`. The old `Boolean(a)||
    // Boolean(b)` collapsed `null || false` to a definitive `false`, re-enabling
    // the flattering "never pruned / no activity before X" reassurance from an
    // unreadable census. An unknown must never become a definitive never-pruned.
    everPruned = mergeEverPruned(usage.everPruned, daemon.usage.everPruned);
    perStoreRetention.push({
      store: "daemon",
      max_entries: daemon.retentionConfig.maxEntries,
      retained_total: daemon.usage.entryCount ?? daemon.windowedTotal,
      max_total_size_bytes: daemon.retentionConfig.maxTotalSizeBytes,
      retained_total_size_bytes: readSize(daemon.usage),
    });
  }

  // R3-3: min-scan, never positional (entries are append-ordered, and clock
  // skew can put an earlier timestamp on a later-appended entry). Scan the
  // MERGED set so a daemon entry can legitimately be the earliest.
  let earliest: string | null = null;
  let earliestMs = Number.POSITIVE_INFINITY;
  for (const entry of mergedEntries) {
    const t = new Date(entry.timestamp).getTime();
    if (Number.isFinite(t) && t < earliestMs) {
      earliestMs = t;
      earliest = entry.timestamp;
    }
  }
  if (earliest === null && mergedEntries.length > 0) {
    earliest = mergedEntries[0]!.timestamp;
  }
  const retention: RetentionFacts = {
    max_entries: retentionConfig.maxEntries,
    retained_total: retainedTotal,
    max_total_size_bytes: retentionConfig.maxTotalSizeBytes,
    retained_total_size_bytes: retainedSizeBytes,
    ever_pruned: everPruned,
    earliest_retained_at: earliest,
    daemon_store: {
      status: daemon.status,
      included_entry_count: includedDaemonCount,
      // G-3: carry WHY the daemon store was unreadable (privilege vs I/O) so the
      // §7 disclosure only advises "re-run as root" for a privilege limitation.
      ...(daemon.status === "present_unreadable" && daemon.unreadable_reason
        ? { unreadable_reason: daemon.unreadable_reason }
        : {}),
    },
    // D5-1: judge at-cap per store against each store's own cap (see above).
    per_store_retention: perStoreRetention,
  };
  // G-2: hand the generator the daemon entries separately (in addition to the
  // merged census) so it can compute how many fall INSIDE the reporting quarter
  // window -- the figure the §7 "N merged into the counts above" note renders,
  // rather than the all-time total. Only present when the daemon store was
  // merged (`included`); the window itself is not known at this pre-window layer.
  // D9C-1: carry the census cut (when the caller captured one) so the generator
  // never signs a coverage window that post-dates the operations counted here.
  const censusFields =
    params.censusTakenAt !== undefined
      ? { census_taken_at: params.censusTakenAt }
      : {};
  return populated(
    daemon.status === "included"
      ? { entries: mergedEntries, retention, daemon_entries: daemon.entries, ...censusFields }
      : { entries: mergedEntries, retention, ...censusFields }
  );
}

/**
 * WATCH-1: read the F2 daemon enforcement store (`_audit-daemon`) for the
 * census. Returns:
 *   - `absent` on a genuinely fresh / never-armed fortress (nothing to add);
 *   - `missing` (C1) when audit-store split evidence is present but the daemon
 *     store is absent (deleted/renamed, or present-but-unverifiable split
 *     evidence -- fail-closed), distinguished from `absent` via the marker-aware
 *     {@link resolveDaemonStorePresence}, and EXCLUDED from the census with a
 *     hedged split-evidence disclosure;
 *   - `present_unreadable` when a daemon store exists but this privilege cannot
 *     read it (the pack then DISCLOSES the omission), with the reason
 *     (`privilege` vs `io`) classified from the actual filesystem errno (C3) so
 *     the disclosure only advises "re-run as root" for a privilege limitation;
 *   - `present_tampered` when the store WAS readable but failed integrity
 *     verification (round-5 gate: tamper evidence must never be mislabeled as a
 *     privilege limitation, and "re-run as root" is futile advice when root
 *     already hit the integrity failure);
 *   - `included` with the daemon entries + retention to merge.
 * A non-integrity read failure after the directory was listable is
 * `present_unreadable` so a pack always generates and discloses rather than
 * crashing.
 *
 * Exported for the integration regression test only; the CLI is the caller.
 */
export async function readDaemonStore(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<
  | { status: "absent" }
  | { status: "missing" }
  | { status: "present_unreadable"; unreadable_reason: "privilege" | "io" }
  | { status: "present_tampered" }
  | {
      status: "included";
      entries: readonly AuditEntry[];
      windowedTotal: number;
      /** See {@link RetentionUsageRead}: `entryCount: null` = usage unavailable. */
      usage: RetentionUsageRead;
      // D5-1: the daemon store's OWN retention caps, so at-cap is judged against
      // this store's independent limits, never the merged total vs a single cap.
      retentionConfig: { maxEntries: number; maxTotalSizeBytes: number };
    }
> {
  // C1 + C3: the marker-aware presence chokepoint distinguishes a fresh
  // fortress (`absent`) from a deleted daemon store on a migrated one
  // (`missing`), and classifies an unreadable store's reason from the actual
  // stat/readdir errno instead of assuming `privilege`.
  const presence = await resolveDaemonStorePresence(storage, masterKey);
  if (presence.kind === "absent") return { status: "absent" };
  if (presence.kind === "missing") return { status: "missing" };
  if (presence.kind === "present_unreadable") {
    return {
      status: "present_unreadable",
      unreadable_reason: presence.reason,
    };
  }
  try {
    const daemonLog = createDaemonAuditLog(storage, masterKey);
    // Default strict integrity mode: a daemon-store tamper makes query() throw
    // AuditIntegrityError, distinguished below from an access failure.
    const { entries, total } = await daemonLog.query({ limit: 1_000_000 });
    // D8-1 Leg A: a usage-read throw yields the all-null "usage unavailable"
    // signal (never placeholder figures), so the daemon store's retention
    // position renders not-determinable instead of a signed below-cap claim.
    const usage = await readRetentionUsage(daemonLog);
    return {
      status: "included",
      entries: entries as readonly AuditEntry[],
      windowedTotal: total,
      usage,
      // D5-1: capture the daemon store's OWN retention caps for the per-store
      // at-cap comparison (a distinct AuditLog instance with independent caps).
      retentionConfig: daemonLog.getRetentionConfig(),
    };
  } catch (e) {
    // A strict-mode integrity failure over a READABLE store is tamper evidence,
    // not a privilege limitation. Disclose it as such (two-family round-5 gate:
    // Codex HIGH / Opus-family MED, convergent) -- BUT only when the findings are
    // genuine tamper. A strict-mode throw whose findings are purely ACCESS
    // failures (a per-file EACCES the directory listed) is a privilege limit, not
    // tamper: never cry "tamper" for a permission problem (G-3 follow-up gate).
    if (e instanceof AuditIntegrityError) {
      return classifyDaemonIntegrityError(e);
    }
    // G-3: the directory listed, but the read/decrypt failed for another reason.
    // Distinguish a PRIVILEGE limitation (a per-file EACCES/EPERM under a
    // root-owned store -- re-running as root fixes it) from a genuine I/O or
    // corruption error (root will hit the SAME failure), so the §7 disclosure
    // does not advise the futile "re-run as root" for the latter. Disclose the
    // omission either way rather than dropping the store or failing the pack.
    return {
      status: "present_unreadable",
      unreadable_reason: daemonUnreadableReason(e),
    };
  }
}

/**
 * G-3: classify a non-integrity daemon-store read failure as a `privilege`
 * limitation (a filesystem permission error -- `EACCES`/`EPERM`, possibly nested
 * on the error's `cause` chain) or a generic `io` error. The distinction drives
 * whether the disclosure advises "re-run as root": a privilege limitation clears
 * under root, a genuine I/O/corruption error does not. Exported for direct unit
 * coverage (a real non-privilege, non-integrity read error is fragile to stage
 * on disk).
 */
export function daemonUnreadableReason(e: unknown): "privilege" | "io" {
  // Delegates to the single canonical classifier in `operational` (the lowest
  // layer that owns the daemon store) so the privilege-vs-io walk can never
  // drift between the presence resolver and this post-read path.
  return errnoAccessReason(e);
}

/**
 * G-3 follow-up (two-family gate): a strict-mode daemon `query()` raises
 * `AuditIntegrityError` for BOTH genuine tamper (hash / prev-hash / anchor /
 * decrypt / malformed / sequence findings) AND a pure ACCESS failure
 * (`entry_unreadable` / `storage_unavailable` -- a file the directory listed but
 * this uid could not read, e.g. a per-file EACCES under a root-owned store).
 * Only the former is tamper evidence. Classify a purely-access-failure error as
 * `present_unreadable` (re-run as root may read it), never `present_tampered` --
 * crying "tamper" for a permission problem is the round-5 mislabel in the other
 * direction. Any genuine tamper finding (even mixed with access findings) is
 * `present_tampered`. Exported for direct unit coverage.
 *
 * C3 (dry-bar): within the access-only case, distinguish the reason from the
 * REAL errno rather than the finding KIND. Both `entry_unreadable` (a per-file
 * read failure) and `storage_unavailable` (a namespace listing / anchor read
 * failure) can be EITHER a permission limit (a root-owned file the operator uid
 * cannot read -- root clears it, "re-run as root" is correct) OR a genuine I/O /
 * corruption / disappearance error (root will NOT clear it). audit-log.ts stamps
 * the underlying error's message onto the finding, so classify `privilege` iff
 * any access-only finding's message reveals a permission errno (`EACCES`/
 * `EPERM`), else the claim-less `io` (honest "investigate", no futile root
 * advice). This closes the mislabel in BOTH directions and for BOTH access
 * kinds (a pure `entry_unreadable`/EIO no longer advises a futile root re-run).
 */
export function classifyDaemonIntegrityError(
  e: AuditIntegrityError
):
  | { status: "present_tampered" }
  | { status: "present_unreadable"; unreadable_reason: "privilege" | "io" } {
  const ACCESS_ONLY_KINDS: ReadonlySet<string> = new Set([
    "entry_unreadable",
    "storage_unavailable",
  ]);
  const allAccessFailures =
    e.findings.length > 0 &&
    e.findings.every((f) => ACCESS_ONLY_KINDS.has(f.kind));
  if (!allAccessFailures) {
    return { status: "present_tampered" };
  }
  // Privilege ONLY when a permission errno is actually present in a finding
  // message; otherwise the claim-less `io` (covers EIO, a null/disappeared
  // read, and any non-permission storage failure), so no access kind ever
  // advises a futile "re-run as root" for a non-permission error.
  const anyPermissionErrno = e.findings.some((f) =>
    /\bE(ACCES|PERM)\b/.test(f.message)
  );
  return {
    status: "present_unreadable",
    unreadable_reason: anyPermissionErrno ? "privilege" : "io",
  };
}

/**
 * G-1 follow-up (two-family gate): the operator-facing CLI summary echoes the
 * quarter's recorded-operation count, which is the OPERATOR store only when the
 * daemon store is excluded (`present_unreadable` / `present_tampered`). Return a
 * warning so that terminal echo is never a silent single-store count either.
 * Empty for `absent` / `included` (the count is the whole census / already
 * merged). The signed report + PDF carry the full disclosure; this keeps the
 * ephemeral stderr summary consistent with them.
 */
export function daemonStoreCliWarning(
  daemon: DaemonStoreDisclosure | undefined
): string[] {
  if (!daemon) return [];
  if (daemon.status === "present_unreadable") {
    return [
      "  NOTE: the recorded-operation count AND the covered-window / shortfall",
      "  assessment above are from the OPERATOR audit store only. A root-owned",
      "  daemon enforcement store (_audit-daemon) is present but was not readable",
      "  here, so daemon-recorded enforcement is NOT reflected in them; treat these",
      "  as an operator-store view, not a complete enforcement census. See the",
      "  report's access-log and enforcement summary section.",
      "",
    ];
  }
  if (daemon.status === "present_tampered") {
    return [
      "  WARNING: a root-owned daemon enforcement store (_audit-daemon) is present",
      "  but FAILED integrity verification, so the recorded-operation count AND the",
      "  covered-window / shortfall assessment above are the OPERATOR store only and",
      "  the daemon store shows tamper evidence; investigate. See the report's",
      "  access-log and enforcement summary section.",
      "",
    ];
  }
  if (daemon.status === "missing") {
    return [
      "  WARNING: audit-store writer-split evidence is present but the root-owned",
      "  daemon enforcement store (_audit-daemon) is ABSENT (deleted or renamed, or",
      "  the split evidence is present but unverifiable), so the recorded-operation",
      "  count AND the covered-window / shortfall assessment above are the OPERATOR",
      "  store only. This is NOT a clean fresh fortress; investigate. See the",
      "  report's access-log and enforcement summary section.",
      "",
    ];
  }
  return [];
}

interface EvidencePackCliOptions {
  subcommand: "generate" | "help";
  firmName: string;
  quarterLabel?: string;
  output?: string;
  passphrase?: string;
}

function parseArgs(args: string[]): EvidencePackCliOptions {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return { subcommand: "help", firmName: "" };
  }
  if (args[0] !== "generate") {
    throw new Error(
      `Unknown evidence-pack subcommand: "${args[0]}". Supported: "generate".`
    );
  }

  const opts: EvidencePackCliOptions = { subcommand: "generate", firmName: "" };
  const flags = args.slice(1);
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const next = flags[i + 1];
    switch (flag) {
      case "--quarter":
        opts.quarterLabel = next;
        i++;
        break;
      case "--firm":
        opts.firmName = next ?? "";
        i++;
        break;
      case "--output":
        opts.output = next;
        i++;
        break;
      case "--passphrase":
        opts.passphrase = next;
        i++;
        break;
      default:
        throw new Error(`Unknown flag: "${flag}"`);
    }
  }

  if (opts.firmName.trim().length === 0) {
    throw new Error(
      'Missing required --firm "<name>". ' +
        'Usage: sanctuary evidence-pack generate --quarter 2026-Q3 --firm "Acme Law"'
    );
  }
  return opts;
}

function printHelp(): void {
  const help = `
Sanctuary - Law-firm Evidence Pack (walking skeleton, slice 1)

USAGE
  sanctuary evidence-pack generate --firm "<name>" [flags]

FLAGS
  --firm <name>       Firm name printed on the cover (required)
  --quarter <YYYY-Qn> Reporting quarter, e.g. 2026-Q3 (default: current quarter)
  --output <dir>      Output directory (default: ./evidence-pack-<quarter>-<ts>)
  --passphrase <pass> Master key passphrase (or SANCTUARY_PASSPHRASE env)
  --help              Print this help text

OUTPUT
  ${MANIFEST_FILENAME}  - signed manifest (per-file SHA-256 + Ed25519)
  ${REPORT_FILENAME}    - signed human-readable Markdown report
  ${PDF_FILENAME}       - rendered PDF (a copy of the report; NOT signed)

  The Markdown report is SHA-256 hashed and Ed25519-signed with the fortress
  primary identity; the manifest signs over those hashes. The PDF is a
  human-readable render and is intentionally not signed - verify integrity
  against the Markdown report and the manifest.

NOT LEGAL ADVICE
  This tool produces a technical evidence artifact. It is not legal advice.
`.trim();
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(help);
}

function defaultOutputDir(label: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  return `./evidence-pack-${label}-${ts}`;
}

/**
 * Run the evidence-pack CLI subcommand. Called from the main CLI dispatcher
 * in `src/cli.ts` when `args[0] === "evidence-pack"`.
 */
export async function runEvidencePack(args: string[]): Promise<void> {
  let opts: EvidencePackCliOptions;
  try {
    opts = parseArgs(args);
  } catch (e) {
    // SAFETY: stderr is the operator-facing CLI error channel for this subcommand; no logger module is in scope yet.
    console.error(`Error: ${(e as Error).message}\n`);
    printHelp();
    process.exit(2);
  }

  if (opts.subcommand === "help") {
    printHelp();
    process.exit(0);
  }

  const quarter = opts.quarterLabel
    ? parseQuarterLabel(opts.quarterLabel)
    : currentQuarter();
  const label = quarterLabel(quarter);
  const outputDir = opts.output ?? defaultOutputDir(label);

  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("[sanctuary evidence-pack] Starting Sanctuary server instance...");
  const { config, identityManager, masterKey, auditLog } =
    await createSanctuaryServer({
      passphrase: opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE,
    });

  const signer = identityManager.getDefault();
  if (!signer) {
    throw new Error(
      "No primary identity configured. Run identity_create and " +
        "identity_set_primary before generating an evidence pack."
    );
  }

  // Read-only storage handle onto the same fortress state dir, for the
  // inventory + discrete-export enumeration (no live connections, no network).
  // Typed as the concrete FilesystemStorage so the WATCH-1 daemon-store probe /
  // read (which need `namespacePath`) can reuse it; it still satisfies every
  // `StorageBackend` consumer below.
  const storage: FilesystemStorage = new FilesystemStorage(
    `${config.storage_path}/state`
  );

  // Pull the full retained audit history (oldest first) as a typed read
  // outcome: a query failure becomes `read_failed` so the decision-count and
  // coverage sections render incomplete-with-reason instead of a false "no
  // denials" / "full quarter covered".
  const audit: ReadOutcome<AuditReadData> = await (async () => {
    try {
      // D9C-1: stamp the census cut BEFORE the query. Every entry the census
      // counts has a timestamp at or before the query's storage snapshot, which
      // is at or after this instant; bounding the attested coverage window at
      // `censusTakenAt` therefore guarantees the signed span never claims
      // coverage of an operation appended after the census (and never counted).
      // The generation time is stamped LATER (after inventory + discrete-export
      // gathering), so attesting through it would over-claim the intervening gap.
      const censusTakenAt = new Date().toISOString();
      const { entries, total } = await auditLog.query({ limit: 1_000_000 });
      const retentionConfig = auditLog.getRetentionConfig();
      // Read the on-disk usage + ever-pruned so the shortfall detector can tell
      // size-cap pruning from genuine inactivity (sweep HIGH-5). Best-effort:
      // D8-1 Leg A -- a throw here (a transient fault between query()'s
      // storage.list() and this one) yields the all-null "usage unavailable"
      // signal, never placeholder figures, so the pack's retention position
      // renders not-determinable (hedged prose + signed manifest marker)
      // instead of a definitive below-cap claim built on a filler size of 0.
      const usage = await readRetentionUsage(auditLog);
      // WATCH-1: after the F2 audit-store split, daemon-produced enforcement
      // records live in the separate root-owned `_audit-daemon` store, which the
      // operator `auditLog.query()` above does NOT see. Probe it and, when
      // readable, MERGE it into the census; when present-but-unreadable, disclose
      // the omission (never a silent single-store false count).
      const daemon = await readDaemonStore(storage, masterKey);
      return deriveAuditReadOutcome({
        entries: entries as readonly AuditEntry[],
        windowedTotal: total,
        retentionConfig,
        usage,
        daemon,
        censusTakenAt,
      });
    } catch (e) {
      return readFailed(`the audit log could not be read: ${(e as Error).message}`);
    }
  })();

  // Custody facts. Master-key custody mode is not yet surfaced by the server
  // API, so it is reported as unknown rather than guessed. The per-install
  // outbound-enforcement posture is NOT probed by this build (it would require
  // reading the wall/pf/system-extension state), so it is a `read_failed`
  // outcome that renders "not determinable for this install" - NEVER a hardcoded
  // "yes", which would be a false security fact on an un-walled host (HIGH-2).
  const custody: ReadOutcome<CustodyFacts> = populated({
    custody_mode: "unknown",
    outbound_denied_by_default: readFailed(
      "this pack does not probe machine-level egress/wall enforcement, so the " +
        "outbound-enforcement posture was not determined for this install."
    ),
  });

  // Enumerate the real AI-tool inventory and gather the discrete
  // third-party verification exports, both READ-ONLY from persisted state.
  const generatedAt = new Date().toISOString();
  const inventory = await gatherInventory(config, storage, masterKey, signer);
  const discreteExports = await gatherDiscreteExports(
    storage,
    masterKey,
    // Stamp the anchor export with the SAME fortress id the transparency
    // checkpoints carry (derived from the storage path), NOT the signer identity
    // id: the auditor's `verify-transparency --check-anchors` cross-checks the
    // anchors export's `fortress_id` against the checkpoints, and a mismatch
    // makes it emit "not evidence about this bundle" (Codex/Family-B MED).
    fortressIdFromStoragePath(config.storage_path),
    generatedAt
  );

  const input: EvidencePackInput = {
    firm_name: opts.firmName,
    quarter,
    generated_at_override: generatedAt,
    custody,
    inventory,
    discrete_exports: discreteExports,
  };

  const pack = buildEvidencePack(input, { audit, signer, masterKey });

  await mkdir(outputDir, { recursive: true });
  await writeFile(
    join(outputDir, MANIFEST_FILENAME),
    JSON.stringify(pack.manifest, null, 2),
    "utf-8"
  );
  for (const file of pack.files) {
    await writeFile(join(outputDir, file.filename), file.content, "utf-8");
  }
  await writeFile(join(outputDir, PDF_FILENAME), pack.pdf);

  const summaryLines = [
    "",
    `[sanctuary evidence-pack] ${PRODUCT_NAME} generation complete.`,
    "",
  ];
  const sf = pack.shortfall;
  if (sf.status === "read_failed") {
    summaryLines.push(
      `  WARNING: the audit log could not be read, so coverage and decision`,
      `  counts could NOT be computed and are NOT asserted in the report.`,
      `  Reason: ${sf.reason}`,
      ""
    );
  } else if (sf.status === "populated" && sf.value.in_progress_quarter) {
    // P3 (Dry-9): name the actual attestable-end bound. When D9C-1 clamps the
    // window to the audit-census cut, say so -- never the stale "the generation
    // time" (the census was read BEFORE the generation instant).
    const boundLabel = sf.value.covered_to_is_census_cut
      ? "the audit-census cut point"
      : "the generation time";
    summaryLines.push(
      `  WARNING: ${label} is still IN PROGRESS. This pack covers only through`,
      `  ${sf.value.covered_to_exclusive} (${boundLabel}), NOT the full`,
      "  quarter. Do not present it to an insurer or client as a complete-quarter",
      "  report; regenerate after the quarter closes. The report is stamped PARTIAL.",
      ""
    );
  }
  const coverageLine =
    sf.status === "populated"
      ? `${sf.value.covered_from} to ${sf.value.covered_to_exclusive} (exclusive)`
      : "could not be determined (audit log unreadable)";
  const shortfallLine =
    sf.status === "populated"
      ? sf.value.shortfall
        ? "YES - disclosed in the report"
        : "no"
      : "indeterminate (audit log unreadable)";
  // R3-4: mirror the report's honest split (sections.ts "Total recorded audit
  // operations"): total_in_window includes non-control-point "other"
  // operations, so labeling the raw total "control-point decisions" restates
  // the mislabel the report already fixed (round-1 LOW-1).
  const decisionsLine =
    pack.aggregation.status === "populated"
      ? `${pack.aggregation.value.total_in_window} ` +
        `(${pack.aggregation.value.total_in_window - pack.aggregation.value.by_category.other} ` +
        `control-point decisions + ${pack.aggregation.value.by_category.other} other recorded operations)`
      : "not computed (audit log unreadable)";
  const partialTag =
    sf.status === "populated" && sf.value.in_progress_quarter
      ? " (PARTIAL - in progress)"
      : "";
  summaryLines.push(
    `  Output directory: ${outputDir}`,
    `  Firm:             ${opts.firmName}`,
    `  Quarter:          ${label}${partialTag}`,
    `  Covered window:   ${coverageLine}`,
    `  Covered-window shortfall: ${shortfallLine}`,
    `  Recorded audit operations in quarter: ${decisionsLine}`,
    // G-1 follow-up: keep the terminal count from reading as a complete census
    // when a root-owned daemon store is present but excluded (the operator-uid
    // armed-box case) -- disclose it adjacent to the count, as the report does.
    ...daemonStoreCliWarning(
      sf.status === "populated" ? sf.value.daemon_store : undefined
    ),
    `  Signer:           ${pack.manifest.signer.did}`,
    "",
    "  NOT LEGAL ADVICE. Have the policy/attestation content reviewed by a",
    "  licensed attorney before first use.",
    ""
  );
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(summaryLines.join("\n"));

  // Stdout: just the output directory path (for scripting).
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(outputDir);
}
