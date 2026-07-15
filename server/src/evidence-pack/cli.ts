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
  probeDaemonChainAccess,
} from "../operational/audit-store-split.js";
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
import { exportAuditChain } from "../cli/audit-chain-export.js";
import type {
  CustodyFacts,
  DaemonStoreDisclosure,
  EvidencePackDiscreteExports,
  EvidencePackInput,
  InventorySnapshot,
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
 * checkpoints), and the audit-chain JSONL export (from the shipped
 * `exportAuditChain`). Public-anchor evidence is opt-in / default-off and is
 * reported absent unless a later slice wires it. Each absent export carries an
 * honest reason string. Never contacts the network.
 */
async function gatherDiscreteExports(
  storage: StorageBackend,
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
      const chunks: Buffer[] = [];
      const sink = new Writable({
        write(chunk, _enc, cb) {
          chunks.push(Buffer.from(chunk));
          cb();
        },
      });
      await exportAuditChain(storage, sink);
      const jsonl = Buffer.concat(chunks).toString("utf8");
      return jsonl.length > 0 ? populated(jsonl) : emptyVerified();
    } catch (e) {
      return readFailed(`the audit-chain export could not be gathered: ${(e as Error).message}`);
    }
  })();

  // Public anchoring is opt-in / default-off; a not-enabled install is a
  // verified empty, not a read failure.
  const anchor: ReadOutcome<string> = emptyVerified();

  return { transparency, audit_chain, anchor };
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
  usage: {
    entryCount: number | null;
    totalSizeBytes: number;
    everPruned: boolean | null;
  };
  /**
   * WATCH-1: the F2 daemon enforcement store (`_audit-daemon`) read, when the
   * operator store has been split. Omit (or `absent`) on a non-split fortress.
   * `included` merges the daemon entries + retention into the census;
   * `present_unreadable` discloses the daemon store exists but was not readable
   * at this privilege (the counts then EXCLUDE it, disclosed, never silent).
   */
  daemon?:
    | { status: "absent" }
    | { status: "present_unreadable"; unreadable_reason?: "privilege" | "io" }
    | { status: "present_tampered" }
    | {
        status: "included";
        entries: readonly AuditEntry[];
        windowedTotal: number;
        usage: {
          entryCount: number | null;
          totalSizeBytes: number;
          everPruned: boolean | null;
        };
      };
}): ReadOutcome<AuditReadData> {
  const { entries, windowedTotal, retentionConfig, usage } = params;
  const daemon = params.daemon ?? { status: "absent" as const };
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

  // WATCH-1: fold the daemon store in. A truncated daemon read is the same
  // honesty failure as a truncated operator read: fail closed rather than
  // present a partial daemon census as complete.
  let mergedEntries: readonly AuditEntry[] = entries;
  let retainedTotal = usage.entryCount ?? windowedTotal;
  let retainedSizeBytes = usage.totalSizeBytes;
  let everPruned = usage.everPruned;
  let includedDaemonCount = 0;
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
    retainedSizeBytes += daemon.usage.totalSizeBytes;
    // Either store having pruned means early-quarter entries may be missing.
    everPruned =
      usage.everPruned === null && daemon.usage.everPruned === null
        ? null
        : Boolean(usage.everPruned) || Boolean(daemon.usage.everPruned);
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
  };
  // G-2: hand the generator the daemon entries separately (in addition to the
  // merged census) so it can compute how many fall INSIDE the reporting quarter
  // window -- the figure the §7 "N merged into the counts above" note renders,
  // rather than the all-time total. Only present when the daemon store was
  // merged (`included`); the window itself is not known at this pre-window layer.
  return populated(
    daemon.status === "included"
      ? { entries: mergedEntries, retention, daemon_entries: daemon.entries }
      : { entries: mergedEntries, retention }
  );
}

/**
 * WATCH-1: read the F2 daemon enforcement store (`_audit-daemon`) for the
 * census. Returns `absent` on a non-split fortress (nothing to add),
 * `present_unreadable` when a daemon store exists but this privilege cannot read
 * it (the pack then DISCLOSES the omission), `present_tampered` when the store
 * WAS readable but failed integrity verification (round-5 gate: tamper evidence
 * must never be mislabeled as a privilege limitation, and "re-run as root" is
 * futile advice when root already hit the integrity failure), or `included`
 * with the daemon entries + retention to merge. A non-integrity read failure
 * after the directory was listable is `present_unreadable` so a pack always
 * generates and discloses rather than crashing.
 *
 * Exported for the integration regression test only; the CLI is the caller.
 */
export async function readDaemonStore(
  storage: FilesystemStorage,
  masterKey: Uint8Array
): Promise<
  | { status: "absent" }
  | { status: "present_unreadable"; unreadable_reason: "privilege" | "io" }
  | { status: "present_tampered" }
  | {
      status: "included";
      entries: readonly AuditEntry[];
      windowedTotal: number;
      usage: {
        entryCount: number | null;
        totalSizeBytes: number;
        everPruned: boolean | null;
      };
    }
> {
  const access = await probeDaemonChainAccess(storage);
  if (access === "absent") return { status: "absent" };
  // A directory that exists but is not listable at this uid is a PRIVILEGE
  // limitation (the expected operator-uid case on an armed box, where re-running
  // as root reads it), never an I/O error.
  if (access === "present_unreadable") {
    return { status: "present_unreadable", unreadable_reason: "privilege" };
  }
  try {
    const daemonLog = createDaemonAuditLog(storage, masterKey);
    // Default strict integrity mode: a daemon-store tamper makes query() throw
    // AuditIntegrityError, distinguished below from an access failure.
    const { entries, total } = await daemonLog.query({ limit: 1_000_000 });
    let usage: {
      entryCount: number | null;
      totalSizeBytes: number;
      everPruned: boolean | null;
    };
    try {
      usage = await daemonLog.getRetentionUsage();
    } catch {
      usage = { entryCount: null, totalSizeBytes: 0, everPruned: null };
    }
    return {
      status: "included",
      entries: entries as readonly AuditEntry[],
      windowedTotal: total,
      usage,
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
  for (let cur: unknown = e, depth = 0; cur != null && depth < 8; depth++) {
    const code = (cur as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM") return "privilege";
    const next = (cur as { cause?: unknown }).cause;
    if (next === cur) break;
    cur = next;
  }
  return "io";
}

/**
 * G-3 follow-up (two-family gate): a strict-mode daemon `query()` raises
 * `AuditIntegrityError` for BOTH genuine tamper (hash / prev-hash / anchor /
 * decrypt / malformed / sequence findings) AND a pure ACCESS failure
 * (`entry_unreadable` / `storage_unavailable` -- a file the directory listed but
 * this uid could not read, e.g. a per-file EACCES under a root-owned store).
 * Only the former is tamper evidence. Classify a purely-access-failure error as
 * a PRIVILEGE limitation (`present_unreadable`; re-run as root reads it), never
 * `present_tampered` -- crying "tamper" for a permission problem is the round-5
 * mislabel in the other direction. Any genuine tamper finding (even mixed with
 * access findings) is `present_tampered`. Exported for direct unit coverage.
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
  if (allAccessFailures) {
    return { status: "present_unreadable", unreadable_reason: "privilege" };
  }
  return { status: "present_tampered" };
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
      "  NOTE: the recorded-operation count above is from the OPERATOR audit",
      "  store only. A root-owned daemon enforcement store (_audit-daemon) is",
      "  present but was not readable here, so daemon-recorded enforcement is NOT",
      "  in that count (not a complete enforcement census). See the report's",
      "  access-log and enforcement summary section.",
      "",
    ];
  }
  if (daemon.status === "present_tampered") {
    return [
      "  WARNING: a root-owned daemon enforcement store (_audit-daemon) is present",
      "  but FAILED integrity verification, so the recorded-operation count above",
      "  is the OPERATOR store only and the daemon store shows tamper evidence;",
      "  investigate. See the report's access-log and enforcement summary section.",
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
      const { entries, total } = await auditLog.query({ limit: 1_000_000 });
      const retentionConfig = auditLog.getRetentionConfig();
      // Read the on-disk usage + ever-pruned so the shortfall detector can tell
      // size-cap pruning from genuine inactivity (sweep HIGH-5). Best-effort.
      let usage: {
        entryCount: number | null;
        totalSizeBytes: number;
        everPruned: boolean | null;
      };
      try {
        usage = await auditLog.getRetentionUsage();
      } catch {
        usage = { entryCount: null, totalSizeBytes: 0, everPruned: null };
      }
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
  const discreteExports = await gatherDiscreteExports(storage, generatedAt);

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
    summaryLines.push(
      `  WARNING: ${label} is still IN PROGRESS. This pack covers only through`,
      `  ${sf.value.covered_to_exclusive} (the generation time), NOT the full`,
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
