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
  runLocalIntelligenceProvisioning,
  verifyModelManifestV2WithKey,
  type ImmuneDiskVerifier,
  type HardwareCapabilityReport,
  type LocalProvisioningResult,
  type ProvenanceProjectionOutcome,
  type RuntimeLightVerifier,
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
  print?: (line: string) => void;
  input?: Readable;
  output?: Writable;
}

export interface RunLocalIntelligenceSetupDeps {
  /** Future bounded fetch path; deliberately null until a signed asset ships. */
  loadManifest?: () => Promise<string | null>;
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

/**
 * Production remains honestly inert while the signed asset/fetch path is
 * absent. Tests inject every side effect and exercise the complete ceremony.
 */
export async function runLocalIntelligenceSetup(
  input: RunLocalIntelligenceSetupInput,
  deps: RunLocalIntelligenceSetupDeps = {},
): Promise<LocalProvisioningResult> {
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
  const configuredChoices = { ...config.perSurface };
  // Invoke-time posture already pins this surface local. Provisioning uses
  // the same effective choice without rewriting a tampered persisted choice.
  if (isTier2PinViolation(
    TIER2_PINNED_SURFACE,
    configuredChoices[TIER2_PINNED_SURFACE],
  )) {
    configuredChoices[TIER2_PINNED_SURFACE] = "local";
  }
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

  const isTty = input.isTty ?? process.stdin.isTTY === true;
  // A headless run or explicit decline skips even the future manifest fetch;
  // neither path may cause network activity while refusing host mutation.
  const manifestText = input.preAnswered === false || !isTty
    ? null
    : await (deps.loadManifest ?? (async () => null))();
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
    configuredChoices,
    ...(config.version === 2
      ? { existingIntegrityState: config.localIntegrityState }
      : {}),
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
      operation,
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
      let outcome: ProvenanceProjectionOutcome = config.version === 2
        ? "unchanged"
        : "projected";
      if (
        config.version === 2 && projection.some((entry) => {
          const prior = modelStore.get(entry.model.model_id);
          return prior === undefined || JSON.stringify(prior) !== JSON.stringify(entry.provenance);
        })
      ) {
        outcome = "repaired";
      }
      for (const entry of projection) modelStore.declare(entry.provenance);
      return outcome;
    },
    recordFailure: (surfaces, failureClass, snippet) =>
      selector.recordLocalProvisioningFailure(surfaces, failureClass, snippet),
    audit: async (event) => {
      await input.auditLog.append(
        "l2",
        event.operation,
        input.identityId,
        event.details,
        event.outcome,
      );
    },
  });
}
