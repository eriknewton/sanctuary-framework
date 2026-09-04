/** Shared `protect` / `init` adapter for the Q5D provisioning ceremony. */

import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  InMemoryModelProvenanceStore,
  type ModelProvenance,
  type ModelProvenanceStore,
} from "../operational/model-provenance.js";
import {
  OllamaClient,
  OllamaRuntimeEvidenceClient,
  Q5_PROVISIONING_LOCK_FILE,
  LocalModelsRootResolutionError,
  SubstrateSelector,
  TIER2_PINNED_SURFACE,
  createNodeImmuneFileSystemAdapter,
  createOnDiskImmuneVerifier,
  isTier2PinViolation,
  loadPackagedModelManifestV2,
  localProvisioningPreflight,
  runLocalIntelligenceProvisioning,
  verifyModelManifestV2WithKey,
  type ImmuneDiskVerifier,
  type HardwareCapabilityReport,
  type LocalModelsRootResolution,
  type OllamaPullProgress,
  type LocalProvisioningAuditEvent,
  type LocalProvisioningResult,
  type PackagedModelManifestRefusalReason,
  type ProvenanceProjectionOutcome,
  type RuntimeLightVerifier,
  type SubstrateChoice,
  type SubstrateConfig,
  type Surface,
} from "../intelligence/index.js";
import { INTELLIGENCE_NAMESPACE } from "../intelligence/policy-store.js";
import { withCrossProcessLock, type CrossProcessLockOptions } from "../storage/cross-process-lock.js";

export interface RunLocalIntelligenceSetupInput {
  storage: StorageBackend;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  identityId: string;
  preAnswered?: boolean;
  isTty?: boolean;
  /**
   * `--model-manifest <path>`: an operator-supplied signed manifest verified
   * by the same loader, parser, byte cap, and pinned key as the packaged one.
   * This is the only way to use a manifest newer than the shipped asset;
   * network discovery is deferred.
   */
  modelManifestPath?: string;
  print?: (line: string) => void;
  input?: Readable;
  output?: Writable;
}

/** What the manifest loader hands the ceremony: verified text or a typed refusal. */
export type LocalIntelligenceManifestLoad =
  | { ok: true; manifestText: string }
  | { ok: false; reason: PackagedModelManifestRefusalReason };

export interface RunLocalIntelligenceSetupDeps {
  /**
   * Test seam over the manifest source. Production takes the default below,
   * the packaged-asset loader (`loadPackagedModelManifestV2`), which reads the
   * signed envelope shipped in the package (or the operator path) and returns
   * verified text or a typed, audited refusal. A seam returning a bare string
   * is treated as text for the ceremony's own verifier to judge; there is no
   * null default any more, so an absent manifest is a named refusal.
   */
  loadManifest?: () => Promise<string | null | LocalIntelligenceManifestLoad>;
  /** Host installer adapter; the production default performs no mutation. */
  installRuntime?: () => Promise<boolean>;
  modelStore?: ModelProvenanceStore;
  client?: OllamaClient;
  confirm?: (prompt: string) => Promise<boolean>;
  platform?: NodeJS.Platform;
  modelManifestV2PublicKey?: Uint8Array;
  runtimeVerifier?: RuntimeLightVerifier;
  immuneVerifier?: ImmuneDiskVerifier;
  resolveModelsRoot?: () => Promise<LocalModelsRootResolution>;
  probeHardware?: () => Promise<HardwareCapabilityReport>;
  lockOptions?: CrossProcessLockOptions;
}

/**
 * Resolve and validate the one root that Q5 persists, reporting the one state
 * that is not yet a verdict: a DEFAULT root that does not exist because Ollama
 * has never pulled. Must match `LocalModelsRootResolution` in
 * `../intelligence/provisioning.ts`, whose ceremony re-calls this strictly
 * after the pull. This is called only after a V2 catalog verifies.
 */
export async function resolveOllamaModelsRootState(
  platform: NodeJS.Platform,
  environment: Readonly<Record<string, string | undefined>> = process.env,
  homeDirectory = homedir(),
): Promise<LocalModelsRootResolution> {
  if (platform === "win32") {
    throw new LocalModelsRootResolutionError("immune_platform_unsupported");
  }
  const configured = environment.OLLAMA_MODELS;
  const explicitlyConfigured = configured !== undefined && configured.length > 0;
  const rawCandidate = explicitlyConfigured
    ? configured
    : join(homeDirectory, ".ollama", "models");
  if (!isAbsolute(rawCandidate) || rawCandidate.includes("\0")) {
    throw new LocalModelsRootResolutionError("model_root_invalid");
  }
  const candidate = resolve(rawCandidate);
  let lexical: Awaited<ReturnType<typeof lstat>>;
  try {
    lexical = await lstat(candidate);
  } catch (error) {
    const code = errorCode(error);
    // Ollama creates ~/.ollama/models on its first pull, so an absent DEFAULT
    // root means "runtime present, no models yet", not a misconfigured host. An
    // operator who set OLLAMA_MODELS asserted that exact path, so its absence
    // stays a refusal; so does any other error, including ENOTDIR, where a path
    // component exists but is not a directory.
    if (code === "ENOENT" && !explicitlyConfigured) {
      return { kind: "default_root_absent" };
    }
    throw new LocalModelsRootResolutionError(
      code === "ENOENT" || code === "ENOTDIR"
        ? "model_root_invalid"
        : "integrity_io_unavailable",
    );
  }
  if (lexical.isSymbolicLink() || !lexical.isDirectory()) {
    throw new LocalModelsRootResolutionError(
      lexical.isSymbolicLink() ? "symlink_refused" : "model_root_invalid",
    );
  }
  let resolved: string;
  try {
    resolved = await realpath(candidate);
  } catch (error) {
    const code = errorCode(error);
    throw new LocalModelsRootResolutionError(
      code === "ENOENT" || code === "ENOTDIR"
        ? "model_root_invalid"
        : "integrity_io_unavailable",
    );
  }
  // A persisted alias would let later process/environment changes redirect
  // verification, so the accepted spelling must already be its real path.
  if (resolved !== candidate) {
    throw new LocalModelsRootResolutionError("model_root_invalid");
  }
  return { kind: "resolved", rootReal: resolved };
}

/**
 * Strict resolution for callers that need a root string. Every state other than
 * a real, non-aliased, non-symlink directory is a refusal here, including the
 * absent default root: a caller asking for a path has nowhere to put "not yet".
 */
export async function resolveOllamaModelsRoot(
  platform: NodeJS.Platform,
  environment: Readonly<Record<string, string | undefined>> = process.env,
  homeDirectory = homedir(),
): Promise<string> {
  const resolution = await resolveOllamaModelsRootState(
    platform,
    environment,
    homeDirectory,
  );
  if (resolution.kind !== "resolved") {
    throw new LocalModelsRootResolutionError("model_root_invalid");
  }
  return resolution.rootReal;
}

// 5_000 ms = 5 s x 1000 ms/s. Ollama emits progress lines several times a
// second, so an unthrottled reporter would flood the operator channel; one line
// per five seconds still proves within a glance that the download is moving.
const PULL_PROGRESS_PRINT_INTERVAL_MS = 5_000;

// The status forms Ollama emits during a pull. The renderer below prints one of
// these exact strings or a fixed token, never the runtime's own bytes.
const KNOWN_PULL_STATUSES: ReadonlySet<string> = new Set([
  "pulling manifest",
  "verifying sha256 digest",
  "writing manifest",
  "removing any unused layers",
  "success",
]);
// 64 = the hex length of a SHA-256 digest; Ollama abbreviates the layer digest
// in `pulling <digest>`, so the shortest form worth rendering is a 6-character
// prefix and the longest is the full digest.
const PULL_STATUS_DIGEST_MAX_HEX_CHARS = 64;
const PULL_STATUS_DIGEST_MIN_HEX_CHARS = 6;
const PULL_DIGEST_STATUS = new RegExp(
  `^pulling (?:sha256:)?([0-9a-f]{${PULL_STATUS_DIGEST_MIN_HEX_CHARS},${PULL_STATUS_DIGEST_MAX_HEX_CHARS}})$`,
);
const UNRECOGNIZED_PULL_STATUS = "runtime status";

/**
 * Project the runtime's `status` onto a closed set of forms this renderer
 * writes itself. The string arrives from the Ollama process and lands on the
 * operator's terminal, where a newline could forge a fresh log line, an ANSI
 * escape could rewrite what is already on screen, and an unbounded length could
 * bury the surrounding output; an allowlist that reconstructs its output means
 * no untrusted byte is ever echoed, rather than a denylist of the escapes
 * someone remembered.
 */
function renderPullStatus(status: string): string {
  if (KNOWN_PULL_STATUSES.has(status)) return status;
  const digest = PULL_DIGEST_STATUS.exec(status);
  return digest === null ? UNRECOGNIZED_PULL_STATUS : `pulling ${digest[1]}`;
}

/**
 * One operator-facing line per reported pull progress event. `runtimeTag` is
 * derived from the signed catalog entry (schema-validated identity components),
 * not from the runtime, so only the status needs projecting.
 */
export function formatPullProgress(
  runtimeTag: string,
  progress: OllamaPullProgress,
): string {
  const { total, completed } = progress;
  const share = total !== undefined && total > 0 && completed !== undefined &&
      completed >= 0 && completed <= total
    // Rendered as a whole-number percentage of bytes Ollama reports for the
    // layer in flight, omitted entirely when it does not report both counters.
    ? ` ${Math.floor((completed / total) * 100)}%`
    : "";
  return `Pulling ${runtimeTag}: ${renderPullStatus(progress.status)}${share}`;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function provisioningChoices(
  config: SubstrateConfig,
): Readonly<Record<Surface, SubstrateChoice>> {
  const configuredChoices = { ...config.perSurface };
  // Invoke-time posture already pins this surface local. Provisioning uses
  // the same effective choice without rewriting a tampered persisted choice.
  if (isTier2PinViolation(
    TIER2_PINNED_SURFACE,
    configuredChoices[TIER2_PINNED_SURFACE],
  )) {
    configuredChoices[TIER2_PINNED_SURFACE] = "local";
  }
  return configuredChoices;
}

function timestampStableProvenance(provenance: ModelProvenance): unknown {
  const {
    declared_at: _declaredAt,
    load_integrity_verified_at: _verifiedAt,
    ...stable
  } = provenance;
  return stable;
}

function provenanceMatchesStableContent(
  left: ModelProvenance,
  right: ModelProvenance,
): boolean {
  return JSON.stringify(timestampStableProvenance(left)) ===
    JSON.stringify(timestampStableProvenance(right));
}

/**
 * Shared composition root for the ceremony. The manifest source defaults to
 * the packaged signed asset (see `loadManifest` above), so production is live
 * and fail-closed: a refusal from the loader is a typed, audited refusal of
 * the whole ceremony. The host installer remains inert (no mutation). Tests
 * inject side effects through `deps` and exercise the complete path.
 */
export async function runLocalIntelligenceSetup(
  input: RunLocalIntelligenceSetupInput,
  deps: RunLocalIntelligenceSetupDeps = {},
): Promise<LocalProvisioningResult> {
  const isTty = input.isTty ?? process.stdin.isTTY === true;
  // The ONE consent decision for this run; the sequencer re-runs the same
  // predicate rather than either side re-deriving the table from isTty and
  // preAnswered. Must match `localProvisioningPreflight` in
  // `intelligence/provisioning-consent.ts`.
  const preflight = localProvisioningPreflight(isTty, input.preAnswered);
  // INVARIANT: a headless run that never asked for local intelligence returns
  // before the selector is constructed, so it reads no durable config, writes
  // no refusal audit row, and persists no provisioning failure. The early
  // return is what keeps the untouched-fortress promise true for the config
  // read as well, not only for the mutation.
  if (preflight.kind === "not-requested") return { kind: "not-requested" };
  const selector = new SubstrateSelector({
    storage: input.storage,
    masterKey: input.masterKey,
    auditLog: input.auditLog,
    identityId: input.identityId,
    ...(deps.modelManifestV2PublicKey === undefined
      ? {}
      : { modelManifestV2PublicKey: deps.modelManifestV2PublicKey }),
  });
  await selector.load();
  const config = selector.getConfig();
  let authorityConfig = config;
  const initialConfiguredChoices = provisioningChoices(config);
  const client = deps.client ?? new OllamaClient({
    endpoint: config.ollamaEndpoint ?? "http://localhost:11434",
  });
  const modelStore = deps.modelStore ?? new InMemoryModelProvenanceStore();
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
  const print = input.print ?? ((line: string) => console.error(`  ${line}`));
  const confirm = deps.confirm ?? (async (prompt: string) => {
    const rl = createInterface({
      input: input.input ?? process.stdin,
      output: input.output ?? process.stderr,
    });
    try {
      const answer = (await rl.question(prompt)).trim().toLowerCase();
      return answer === "y" || answer === "yes";
    } finally {
      rl.close();
    }
  });

  const audit = async (event: {
    operation: LocalProvisioningAuditEvent["operation"];
    outcome: LocalProvisioningAuditEvent["outcome"];
    details: LocalProvisioningAuditEvent["details"];
  }) => {
    await input.auditLog.append(
      "l2",
      event.operation,
      input.identityId,
      event.details,
      event.outcome,
    );
  };
  // The production manifest source is the packaged signed asset (or the
  // operator-supplied path), read and verified by the bounded loader; the
  // loader performs no network fetch. Must match the loader's refusal
  // taxonomy in packaged-model-manifest.ts: a refusal here becomes the
  // ceremony's typed refusal, never a bare absence.
  const loadManifest = deps.loadManifest ?? (async (): Promise<LocalIntelligenceManifestLoad> => {
    const loaded = await loadPackagedModelManifestV2({
      ...(input.modelManifestPath === undefined ? {} : { assetPath: input.modelManifestPath }),
      ...(deps.modelManifestV2PublicKey === undefined
        ? {}
        : { publicKey: deps.modelManifestV2PublicKey }),
      audit,
    });
    return loaded.ok
      ? { ok: true, manifestText: loaded.manifestText }
      : { ok: false, reason: loaded.reason };
  });
  // A headless run or explicit decline skips even reading the manifest;
  // neither path may touch the asset or the host while refusing mutation.
  // Only `proceed` reads it, so the manifest source is gated by the same
  // predicate as the mutation, never by a second copy of the truth table.
  const loaded = preflight.kind === "proceed" ? await loadManifest() : null;
  const manifestText = loaded === null
    ? null
    : typeof loaded === "string"
    ? loaded
    : loaded.ok
    ? loaded.manifestText
    : null;
  const manifestLoadRefusal = loaded !== null && typeof loaded === "object" && !loaded.ok
    ? loaded.reason
    : undefined;
  const runtimeVerifier = deps.runtimeVerifier ?? new OllamaRuntimeEvidenceClient({
    endpoint: config.ollamaEndpoint ?? "http://localhost:11434",
  });
  const immuneVerifier = deps.immuneVerifier ?? createOnDiskImmuneVerifier({
    fs: createNodeImmuneFileSystemAdapter(),
  });
  return runLocalIntelligenceProvisioning({
    isTty,
    platform: deps.platform ?? process.platform,
    preAnswered: input.preAnswered,
    manifestText,
    ...(manifestLoadRefusal === undefined ? {} : { manifestLoadRefusal }),
    initialConfiguredChoices,
    // Must match `reloadLocalProvisioningAuthority` in selector.ts; this
    // callback is invoked only from inside the provisioning lock.
    reloadAuthority: async () => {
      authorityConfig = await selector.reloadLocalProvisioningAuthority();
      return {
        configuredChoices: provisioningChoices(authorityConfig),
        ...(authorityConfig.version === 2
          ? { existingIntegrityState: authorityConfig.localIntegrityState }
          : {}),
      };
    },
    ...(deps.modelManifestV2PublicKey === undefined
      ? {}
      : {
        verifyManifest: (text, manifestVersionFloor) =>
          verifyModelManifestV2WithKey(
            text,
            deps.modelManifestV2PublicKey!,
            manifestVersionFloor === undefined ? {} : { manifestVersionFloor },
          ),
      }),
    probeHardware: deps.probeHardware ?? (() => selector.probeHardware()),
    resolveModelsRoot: deps.resolveModelsRoot ?? (() =>
      resolveOllamaModelsRootState(deps.platform ?? process.platform)),
    runtimeVerifier,
    immuneVerifier,
    withProvisioningLock: (operation) => withCrossProcessLock(
      input.storage,
      INTELLIGENCE_NAMESPACE,
      Q5_PROVISIONING_LOCK_FILE,
      // Lock order is provisioning then config-save; routine writers take only
      // config-save, so reload-through-commit cannot interleave or deadlock.
      () => selector.withLocalIntegrityConfigSaveLock(operation),
      {
        ...deps.lockOptions,
        metadata: { purpose: "q5-local-integrity-provisioning" },
      },
    ),
    installRuntime: deps.installRuntime ?? (async () => false),
    // A multi-gigabyte pull runs for minutes to hours; its progress goes to the
    // ceremony's own operator channel (the same `print` that renders the plan),
    // so a working download reads as movement instead of a hang.
    pull: (runtimeTag) => {
      let lastPrintedAt = 0;
      return client.pull(runtimeTag, {
        onProgress: (progress) => {
          const now = Date.now();
          // The terminal line is the one that says the download finished, so it
          // is never dropped by the rate limit.
          if (
            progress.status !== "success" &&
            now - lastPrintedAt < PULL_PROGRESS_PRINT_INTERVAL_MS
          ) {
            return;
          }
          lastPrintedAt = now;
          print(formatPullProgress(runtimeTag, progress));
        },
      });
    },
    confirm,
    print,
    commitVerified: (commit) => selector.commitLocalIntegrityProvisioning(
      commit.integrityState,
      commit.runtimeTags,
    ),
    projectProvenance: async (projection) => {
      let outcome: ProvenanceProjectionOutcome = authorityConfig.version === 2
        ? "unchanged"
        : "projected";
      if (
        authorityConfig.version === 2 && projection.some((entry) => {
          const prior = modelStore.get(entry.model.model_id);
          return prior === undefined ||
            !provenanceMatchesStableContent(prior, entry.provenance);
        })
      ) {
        outcome = "repaired";
      }
      for (const entry of projection) modelStore.declare(entry.provenance);
      return outcome;
    },
    recordFailure: (surfaces, failureClass, snippet) =>
      selector.recordLocalProvisioningFailure(surfaces, failureClass, snippet),
    audit,
  });
}
