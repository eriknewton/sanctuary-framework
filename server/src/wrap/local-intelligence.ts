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
  resolveModelsRoot?: () => Promise<string>;
  probeHardware?: () => Promise<HardwareCapabilityReport>;
  lockOptions?: CrossProcessLockOptions;
}

/**
 * Resolve and validate the one root that Q5 persists. This is called only
 * after an injected V2 catalog verifies; the null-default production path
 * never reads `OLLAMA_MODELS` or the host model store.
 */
export async function resolveOllamaModelsRoot(
  platform: NodeJS.Platform,
  environment: Readonly<Record<string, string | undefined>> = process.env,
  homeDirectory = homedir(),
): Promise<string> {
  if (platform === "win32") {
    throw new LocalModelsRootResolutionError("immune_platform_unsupported");
  }
  const configured = environment.OLLAMA_MODELS;
  const rawCandidate = configured !== undefined && configured.length > 0
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
  return resolved;
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
      resolveOllamaModelsRoot(deps.platform ?? process.platform)),
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
    pull: (runtimeTag) => client.pull(runtimeTag),
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
