/**
 * Q5D atomic local-intelligence provisioning.
 *
 * Host, registry, lock, persistence, provenance, and audit effects are all
 * injected. Production still supplies no manifest asset, so this complete
 * path cannot arm a fortress without the separately gated loader.
 */

import { isAbsolute } from "node:path";
import { INTEL_OPS } from "./audit-events.js";
import {
  IMMUNE_MODEL_LOAD_SURFACES,
  MODEL_MANIFEST_V2_SCHEMA_VERSION,
  computeModelManifestV2BodyDigest,
  deriveOllamaRuntimeTag,
  verifyModelManifestV2WithKey,
  type LocalIntegrityStateV2,
  type ModelLoadIntegrityAssurance,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
  type ModelManifestV2VerificationResult,
  type VerifiedLocalBindingV2,
} from "./model-manifest-v2.js";
import { loadPinnedModelManifestKey, type ModelManifestTier } from "./model-manifest.js";
import type { PackagedModelManifestRefusalReason } from "./packaged-model-manifest.js";
import type { RuntimeLightVerifier } from "./runtime-light-verifier.js";
import type {
  ImmuneDiskVerifier,
  ImmuneVerificationResult,
} from "./immune-disk-verifier.js";
import type {
  HardwareCapabilityReport,
  SubstrateChoice,
  SubstrateFailureClass,
  Surface,
} from "./types.js";
import { SURFACES } from "./types.js";
import type { ModelProvenance } from "../operational/model-provenance.js";
import type { OllamaMutationResult } from "./substrates/local.js";
import { localProvisioningPreflight } from "./provisioning-consent.js";
import { LocalIntegrityStateLoadError } from "./policy-store.js";
import { CrossProcessLockError } from "../storage/cross-process-lock.js";

export const MODEL_REGISTRY_PROVIDER_CATEGORY = "model-registry" as const;
export const Q5_PROVISIONING_LOCK_FILE = ".q5-provisioning.lock";

export class LocalModelsRootResolutionError extends Error {
  constructor(
    readonly reason:
      | "model_root_invalid"
      | "symlink_refused"
      | "integrity_io_unavailable"
      | "immune_platform_unsupported",
  ) {
    super(reason);
    this.name = "LocalModelsRootResolutionError";
  }
}

/**
 * What the model-root resolver reports. `default_root_absent` is the one state
 * that is not yet a verdict: the DEFAULT root does not exist because the runtime
 * has never pulled, and Ollama creates it on its first pull. It deliberately
 * carries no path, so an unvalidated root cannot enter the ceremony; the caller
 * re-resolves strictly once the pull has created the directory. Must match
 * `resolveOllamaModelsRootState` in `../wrap/local-intelligence.ts`.
 */
export type LocalModelsRootResolution =
  | { kind: "resolved"; rootReal: string }
  | { kind: "default_root_absent" };

/**
 * The ceremony's own root protocol state. `ROOT_PENDING_PULL` carries no path
 * at all, so the plan, the consent step, verification, and the commit cannot
 * receive "not resolved yet" as a value; the commit consumes a root only from
 * `ROOT_RESOLVED`, which is only ever entered from a strict resolution or from
 * the durable armed record.
 */
type ProvisioningRootState =
  | { state: "ROOT_RESOLVED"; rootReal: string }
  | { state: "ROOT_PENDING_PULL" };

export type LocalProvisioningRefusalReason =
  | "declined"
  | "non_tty"
  // Asset-stage refusals from the packaged manifest loader
  // (packaged-model-manifest.ts); each names why no manifest text arrived, so
  // the ceremony never collapses a typed loader refusal into a bare "absent".
  | PackagedModelManifestRefusalReason
  | "integrity_state_absent"
  | "integrity_state_invalid"
  | "manifest_signature_invalid"
  | "manifest_rollback"
  | "binding_mismatch"
  | "below_baseline"
  | "manual_install_required"
  | "install_failed"
  | "pull_failed"
  | "runtime_model_absent"
  | "runtime_manifest_digest_invalid"
  | "runtime_manifest_digest_mismatch"
  | "model_root_invalid"
  | "path_escape"
  | "symlink_refused"
  | "disk_manifest_invalid"
  | "disk_manifest_digest_mismatch"
  | "descriptor_bounds_exceeded"
  | "layer_missing"
  | "layer_size_mismatch"
  | "layer_digest_mismatch"
  | "unstable_file"
  | "integrity_io_unavailable"
  | "immune_platform_unsupported";

export interface VerifiedProvisioningProjection {
  model: ModelManifestModelV2;
  provenance: ModelProvenance;
  surfaces: readonly Surface[];
}

export interface AtomicLocalProvisioningCommit {
  integrityState: LocalIntegrityStateV2;
  runtimeTags: Readonly<Partial<Record<Surface, string>>>;
  provenance: readonly VerifiedProvisioningProjection[];
}

export type ProvenanceProjectionOutcome = "projected" | "repaired" | "unchanged";

export interface LocalProvisioningAuditEvent {
  operation:
    | typeof INTEL_OPS.MODEL_PULL
    | typeof INTEL_OPS.MODEL_PROVISION_REFUSED
    | typeof INTEL_OPS.LOAD_INTEGRITY;
  outcome: "success" | "failure";
  details: Readonly<Record<string, string | number | boolean | readonly string[]>>;
}

export interface LocalProvisioningOps {
  isTty: boolean;
  platform: NodeJS.Platform;
  /** false is an explicit decline; true still cannot bypass the TTY confirm. */
  preAnswered?: boolean;
  manifestText: string | null;
  /**
   * Why `manifestText` is null when the packaged loader ran and refused. The
   * ceremony refuses with this exact reason instead of the generic
   * `integrity_state_absent`, so an operator can tell a missing package asset
   * from a bad signature from a byte-pin mismatch. Undefined when no loader
   * ran (headless or declined) or when text arrived.
   */
  manifestLoadRefusal?: PackagedModelManifestRefusalReason;
  /** Pre-lock snapshot used only to describe an early consent refusal. */
  initialConfiguredChoices: Readonly<Record<Surface, SubstrateChoice>>;
  /**
   * Must execute inside `withProvisioningLock` and return the durable config
   * view that verification, root selection, and commit construction consume.
   */
  reloadAuthority: () => Promise<{
    configuredChoices: Readonly<Record<Surface, SubstrateChoice>>;
    existingIntegrityState?: LocalIntegrityStateV2;
  }>;
  verifyManifest?: (
    text: string | null,
    manifestVersionFloor?: number,
  ) => ModelManifestV2VerificationResult;
  probeHardware: () => Promise<HardwareCapabilityReport>;
  /**
   * Resolve the one root Q5 persists. A `default_root_absent` result means the
   * host has a runtime but has never pulled; the ceremony defers to after the
   * pull and calls this again, so only a strictly resolved root is ever
   * verified against or committed.
   */
  resolveModelsRoot: () => Promise<LocalModelsRootResolution>;
  runtimeVerifier: RuntimeLightVerifier;
  immuneVerifier: ImmuneDiskVerifier;
  withProvisioningLock: <T>(operation: () => Promise<T>) => Promise<T>;
  installRuntime: () => Promise<boolean>;
  pull: (runtimeTag: string) => Promise<OllamaMutationResult>;
  confirm: (prompt: string) => Promise<boolean>;
  print: (line: string) => void;
  commitVerified: (commit: AtomicLocalProvisioningCommit) => Promise<void>;
  projectProvenance: (
    projection: readonly VerifiedProvisioningProjection[],
  ) => Promise<ProvenanceProjectionOutcome | void> | ProvenanceProjectionOutcome | void;
  recordFailure: (
    surfaces: readonly Surface[],
    failureClass: SubstrateFailureClass,
    snippet: string,
  ) => Promise<void>;
  audit: (event: LocalProvisioningAuditEvent) => Promise<void> | void;
  now?: () => Date;
}

export type LocalProvisioningResult =
  | {
    kind: "provisioned" | "already-provisioned";
    surfaces: readonly Surface[];
    models: readonly string[];
    provenanceProjection: "projected" | "degraded";
  }
  /**
   * The run never asked for local intelligence (no flag, no terminal to ask).
   * Distinct from `refused`: nothing was read, recorded, audited, or degraded,
   * so a caller renders it as information, never as a failure.
   */
  | { kind: "not-requested" }
  | { kind: "refused"; reason: LocalProvisioningRefusalReason };

const FAILURE_COPY: Record<LocalProvisioningRefusalReason, string> = {
  declined: "Local intelligence setup was declined; configured local surfaces remain local and degraded.",
  non_tty: "Local intelligence setup requires an interactive TTY; no runtime or model mutation occurred.",
  integrity_asset_absent: "The packaged signed model manifest is missing; no model pull was attempted.",
  integrity_asset_oversize: "The signed model manifest exceeds the reviewed byte cap; no model pull was attempted.",
  integrity_asset_unparseable: "The signed model manifest is not a valid V2 envelope; no model pull was attempted.",
  integrity_asset_signature_invalid: "The signed model manifest does not verify under the pinned catalog root; no model pull was attempted.",
  integrity_asset_pin_mismatch: "The packaged model manifest does not match the build-time byte pin; no model pull was attempted.",
  integrity_asset_module_location_unavailable: "The packaged model manifest cannot be located from a CommonJS entry point; run the ESM CLI (sanctuary) to provision. No model pull was attempted.",
  integrity_state_absent: "The signed V2 model catalog is unavailable; no model pull was attempted.",
  integrity_state_invalid: "The signed V2 model catalog or armed record is invalid; no model pull was attempted.",
  manifest_signature_invalid: "The V2 model catalog signature is invalid; no model pull was attempted.",
  manifest_rollback: "The V2 model catalog is below the persisted integrity floor; old state was retained.",
  binding_mismatch: "A local surface could not be rederived from the signed catalog; old state was retained.",
  below_baseline: "This host is below the signed local-model baseline; no model pull was attempted.",
  manual_install_required: "Automatic Ollama installation is unavailable on Windows; install Ollama manually, then re-run local intelligence setup.",
  install_failed: "Ollama installation did not complete; no surface was marked provisioned.",
  pull_failed: "A signed-catalog model pull failed; no Q5 state was committed.",
  runtime_model_absent: "A required exact runtime model is absent; no Q5 state was committed.",
  runtime_manifest_digest_invalid: "Runtime manifest evidence is invalid; no Q5 state was committed.",
  runtime_manifest_digest_mismatch: "Runtime manifest evidence mismatched the signed root; no Q5 state was committed.",
  model_root_invalid: "The Ollama model root is invalid; no Q5 state was committed.",
  path_escape: "A derived model path escaped the persisted root; no Q5 state was committed.",
  symlink_refused: "A model-store symlink was refused; no Q5 state was committed.",
  disk_manifest_invalid: "The on-disk model manifest is invalid; no Q5 state was committed.",
  disk_manifest_digest_mismatch: "The on-disk model manifest mismatched the signed root; no Q5 state was committed.",
  descriptor_bounds_exceeded: "Authenticated model descriptors exceed reviewed bounds; no Q5 state was committed.",
  layer_missing: "An authenticated model artifact is missing; no Q5 state was committed.",
  layer_size_mismatch: "An authenticated model artifact size mismatched; no Q5 state was committed.",
  layer_digest_mismatch: "An authenticated model artifact digest mismatched; no Q5 state was committed.",
  unstable_file: "A model artifact changed while being verified; no Q5 state was committed.",
  integrity_io_unavailable: "Integrity I/O or authoritative state save is unavailable; durable state may have advanced, so inspect it before retrying.",
  immune_platform_unsupported: "This platform cannot provide reviewed immune verification; no Q5 state was committed.",
};

interface RequiredModel {
  model: ModelManifestModelV2;
  surfaces: Surface[];
  assurance: ModelLoadIntegrityAssurance;
}

interface VerificationEvidence {
  runtimeManifestDigest: string;
  immune?: Extract<ImmuneVerificationResult, { ok: true }>;
}

type VerificationSweep =
  | { ok: true; evidence: ReadonlyMap<string, VerificationEvidence> }
  | { ok: false; reason: LocalProvisioningRefusalReason };

function defaultVerifyManifest(
  text: string | null,
  manifestVersionFloor?: number,
): ModelManifestV2VerificationResult {
  const key = loadPinnedModelManifestKey();
  if (key === null) return { ok: false, reason: "bad_pinned_key_length" };
  return verifyModelManifestV2WithKey(
    text,
    key,
    manifestVersionFloor === undefined ? {} : { manifestVersionFloor },
  );
}

function manifestRefusal(
  result: Exclude<ModelManifestV2VerificationResult, { ok: true }>,
): LocalProvisioningRefusalReason {
  if (result.reason === "absent") return "integrity_state_absent";
  if (result.reason === "rollback" || result.reason === "downgrade") {
    return "manifest_rollback";
  }
  if (
    result.reason === "bad_signature" ||
    result.reason === "bad_signature_encoding" ||
    result.reason === "bad_signature_length" ||
    result.reason === "zero_signature" ||
    result.reason === "bad_pinned_key_length" ||
    result.reason === "zero_pinned_key"
  ) {
    return "manifest_signature_invalid";
  }
  return "integrity_state_invalid";
}

function assuranceForSurface(surface: Surface): ModelLoadIntegrityAssurance {
  return IMMUNE_MODEL_LOAD_SURFACES.includes(
      surface as (typeof IMMUNE_MODEL_LOAD_SURFACES)[number],
    )
    ? "immune"
    : "light";
}

function bindingFor(
  model: ModelManifestModelV2,
  surface: Surface,
  manifestVersion: number,
): VerifiedLocalBindingV2 {
  return {
    model_id: model.model_id,
    runtime_tag: deriveOllamaRuntimeTag(model.ollama_identity),
    ollama_identity: model.ollama_identity,
    assurance: assuranceForSurface(surface),
    manifest_version: manifestVersion,
  };
}

function requiredModels(
  body: ModelManifestBodyV2,
  tier: ModelManifestTier,
  localSurfaces: readonly Surface[],
): Map<string, RequiredModel> | null {
  const models = new Map<string, RequiredModel>();
  for (const surface of localSurfaces) {
    const modelId = body.surface_defaults[tier][surface];
    const model = modelId === null ? undefined : body.models[modelId];
    if (model === undefined) return null;
    const assurance = assuranceForSurface(surface);
    const existing = models.get(model.model_id);
    if (existing !== undefined) {
      existing.surfaces.push(surface);
      if (assurance === "immune") existing.assurance = "immune";
    } else {
      models.set(model.model_id, { model, surfaces: [surface], assurance });
    }
  }
  return models;
}

async function verifyEveryModel(
  ops: LocalProvisioningOps,
  models: ReadonlyMap<string, RequiredModel>,
  rootReal: string,
  manifestVersion: number,
): Promise<VerificationSweep> {
  const evidence = new Map<string, VerificationEvidence>();
  for (const [modelId, required] of models) {
    const representativeSurface = required.surfaces.find(
      (surface) => assuranceForSurface(surface) === required.assurance,
    )!;
    const binding = bindingFor(required.model, representativeSurface, manifestVersion);
    const runtime = await ops.runtimeVerifier.verify({ rootReal, binding });
    if (!runtime.ok) return { ok: false, reason: runtime.reason };
    let immune: Extract<ImmuneVerificationResult, { ok: true }> | undefined;
    if (required.assurance === "immune") {
      const immuneBinding: VerifiedLocalBindingV2 = { ...binding, assurance: "immune" };
      const disk = await ops.immuneVerifier.verify({
        rootReal,
        binding: immuneBinding,
        checkpoint: "provisioning",
      });
      if (!disk.ok) return { ok: false, reason: disk.reason };
      immune = disk;
    }
    evidence.set(modelId, {
      runtimeManifestDigest: runtime.observedManifestDigest,
      ...(immune === undefined ? {} : { immune }),
    });
  }
  return { ok: true, evidence };
}

function repairableByPull(reason: LocalProvisioningRefusalReason): boolean {
  return [
    "runtime_model_absent",
    "runtime_manifest_digest_mismatch",
    "disk_manifest_invalid",
    "disk_manifest_digest_mismatch",
    "layer_missing",
    "layer_size_mismatch",
    "layer_digest_mismatch",
  ].includes(reason);
}

function buildAtomicCommit(
  verified: Extract<ModelManifestV2VerificationResult, { ok: true }>,
  models: ReadonlyMap<string, RequiredModel>,
  evidence: ReadonlyMap<string, VerificationEvidence>,
  rootReal: string,
  committedAt: string,
): AtomicLocalProvisioningCommit {
  const bindings = Object.create(null) as Partial<Record<Surface, VerifiedLocalBindingV2>>;
  const runtimeTags: Partial<Record<Surface, string>> = {};
  for (const required of models.values()) {
    for (const surface of required.surfaces) {
      const binding = bindingFor(required.model, surface, verified.body.manifest_version);
      bindings[surface] = binding;
      runtimeTags[surface] = binding.runtime_tag;
    }
  }
  const integrityState: LocalIntegrityStateV2 = {
    state: "armed",
    schema_version: MODEL_MANIFEST_V2_SCHEMA_VERSION,
    manifest_version_floor: verified.body.manifest_version,
    signed_manifest: verified.manifest,
    signed_body_sha256: computeModelManifestV2BodyDigest(verified.body),
    ollama_models_root: rootReal,
    bindings,
    committed_at: committedAt,
  };
  const provenance = [...models.entries()].map(([modelId, required]) => {
    const modelEvidence = evidence.get(modelId)!;
    const immune = modelEvidence.immune;
    const projection: ModelProvenance = {
      model_id: required.model.model_id,
      model_name: required.model.model_name,
      model_version: required.model.model_version,
      provider: required.model.provider,
      runtime_manifest_hash: `sha256:${modelEvidence.runtimeManifestDigest}`,
      ...(immune === undefined
        ? { load_integrity_assurance: "runtime-manifest" as const }
        : {
          verified_artifact_hashes: immune.verifiedArtifactDigests.map(
            (digest) => `sha256:${digest}`,
          ),
          load_integrity_assurance: "on-disk-all-layers" as const,
        }),
      load_integrity_verified_at: committedAt,
      model_manifest_version: verified.body.manifest_version,
      license: required.model.license.identifier,
      open_weights: required.model.open_weights,
      open_source: required.model.open_source,
      local_inference: true,
      serving_surfaces: required.surfaces,
      declared_at: committedAt,
    };
    return { model: required.model, provenance: projection, surfaces: required.surfaces };
  });
  // The complete record and config tag projection are handed to one save;
  // provenance remains derived evidence and is deliberately not in this write.
  return { integrityState, runtimeTags, provenance };
}

/** Run one serialized verify/pull/verify/atomic-save/projection ceremony. */
export async function runLocalIntelligenceProvisioning(
  ops: LocalProvisioningOps,
): Promise<LocalProvisioningResult> {
  let affectedSurfaces = SURFACES.filter(
    (surface) => ops.initialConfiguredChoices[surface] === "local",
  );
  const preflight = localProvisioningPreflight(ops.isTty, ops.preAnswered);
  // INVARIANT: an unrequested run returns BEFORE `refuse`, so it writes no
  // refusal audit row and no persisted provisioning failure. Reaching `refuse`
  // here is what made a plain headless `protect` mark five surfaces degraded.
  if (preflight.kind === "not-requested") return { kind: "not-requested" };
  if (preflight.kind === "refused") {
    return refuse(
      ops,
      affectedSurfaces,
      preflight.reason,
      preflight.reason === "non_tty" ? "substrate_unavailable" : "substrate_misconfigured",
    );
  }

  try {
    return await ops.withProvisioningLock(async () => {
      // Must match `reloadLocalProvisioningAuthority` in selector.ts: the
      // authority read and every verification/mutation stay under one lock.
      const authority = await ops.reloadAuthority();
      const localSurfaces = SURFACES.filter(
        (surface) => authority.configuredChoices[surface] === "local",
      );
      affectedSurfaces = localSurfaces;
      const floor = authority.existingIntegrityState?.manifest_version_floor;
      // A typed loader refusal is the verdict; it is never re-read as the
      // generic absence the verifier would otherwise report for null text.
      if (ops.manifestText === null && ops.manifestLoadRefusal !== undefined) {
        return refuse(ops, localSurfaces, ops.manifestLoadRefusal, "substrate_misconfigured");
      }
      const verifyManifest = ops.verifyManifest ?? defaultVerifyManifest;
      const verified = verifyManifest(ops.manifestText, floor);
      if (!verified.ok) {
        const reason = manifestRefusal(verified);
        return refuse(ops, localSurfaces, reason, "substrate_misconfigured", {
          recordFailure: reason !== "manifest_rollback",
        });
      }

      const hardware = await ops.probeHardware();
      if (hardware.tier === "below-baseline") {
        return refuse(ops, localSurfaces, "below_baseline", "substrate_unavailable");
      }
      const models = requiredModels(verified.body, hardware.tier, localSurfaces);
      if (models === null || models.size === 0) {
        return refuse(ops, localSurfaces, "binding_mismatch", "substrate_misconfigured");
      }

      // The root is a two-state protocol, never a nullable string: only
      // ROOT_RESOLVED carries a path, so no consumer can read "not resolved
      // yet" as a value. ROOT_PENDING_PULL means the default root does not
      // exist because the reachable runtime has never pulled; nothing is on
      // disk to verify and nothing may be persisted from it, so the strict
      // resolution is deferred until the pull below has created the directory.
      let rootState: ProvisioningRootState = { state: "ROOT_PENDING_PULL" };
      const persistedRoot = authority.existingIntegrityState?.ollama_models_root;
      if (persistedRoot !== undefined) {
        // Once armed, the just-reloaded durable root remains authoritative even
        // if the process environment changed before this lock was acquired.
        rootState = { state: "ROOT_RESOLVED", rootReal: persistedRoot };
      } else {
        let resolution: LocalModelsRootResolution;
        try {
          resolution = await ops.resolveModelsRoot();
        } catch (error) {
          return refuse(
            ops,
            localSurfaces,
            rootResolutionRefusal(error),
            "substrate_misconfigured",
          );
        }
        if (resolution.kind === "resolved") {
          rootState = { state: "ROOT_RESOLVED", rootReal: resolution.rootReal };
        } else if (!hardware.ollamaReachable) {
          // Without a reachable runtime nothing in this run can create the root,
          // so an absent default root stays a refusal instead of becoming a wait
          // for a pull that cannot happen.
          return refuse(ops, localSurfaces, "model_root_invalid", "substrate_misconfigured");
        }
      }
      if (rootState.state === "ROOT_RESOLVED" && !isAbsolute(rootState.rootReal)) {
        return refuse(ops, localSurfaces, "model_root_invalid", "substrate_misconfigured");
      }

      let sweep: VerificationSweep | null = rootState.state === "ROOT_RESOLVED"
        ? await verifyEveryModel(
          ops,
          models,
          rootState.rootReal,
          verified.body.manifest_version,
        )
        : null;
      const alreadyPresent = sweep !== null && sweep.ok;
      if (sweep === null || !sweep.ok) {
        if (sweep !== null && !repairableByPull(sweep.reason)) {
          return refuse(ops, localSurfaces, sweep.reason, "substrate_misconfigured");
        }
        for (const line of renderLocalProvisioningPlan({
          installRuntime: !hardware.ollamaReachable,
          platform: ops.platform,
          models: [...models.values()].map(({ model }) => model),
        })) {
          ops.print(line);
        }
        if (!hardware.ollamaReachable && ops.platform === "win32") {
          return refuse(
            ops,
            localSurfaces,
            "manual_install_required",
            "substrate_unavailable",
          );
        }
        const estimatedParamsB = [...models.values()].reduce(
          (sum, { model }) => sum + model.params_b,
          0,
        );
        const confirmed = await ops.confirm(
          `Set up local intelligence now? This installs/uses Ollama and downloads models totaling ${estimatedParamsB.toFixed(2)}B signed parameters, verified against a signed V2 catalog. [y/N] `,
        );
        if (!confirmed) {
          return refuse(ops, localSurfaces, "declined", "substrate_misconfigured");
        }
        if (!hardware.ollamaReachable && !(await ops.installRuntime())) {
          return refuse(ops, localSurfaces, "install_failed", "substrate_unavailable");
        }
        for (const { model } of models.values()) {
          const runtimeTag = deriveOllamaRuntimeTag(model.ollama_identity);
          const pulled = await ops.pull(runtimeTag);
          await safeAudit(ops, {
            operation: INTEL_OPS.MODEL_PULL,
            outcome: pulled.ok ? "success" : "failure",
            details: {
              model_id: model.model_id,
              provider_category: MODEL_REGISTRY_PROVIDER_CATEGORY,
              manifest_version: verified.body.manifest_version,
            },
          });
          if (!pulled.ok) {
            return refuse(
              ops,
              localSurfaces,
              "pull_failed",
              pulled.failureClass ?? "substrate_unavailable",
            );
          }
        }
        if (rootState.state === "ROOT_PENDING_PULL") {
          // The pull has run, so the root must exist now and must clear exactly
          // the same strict resolution a persisted root clears; a root that is
          // still absent, aliased, or a symlink is refused here, never committed.
          let resolution: LocalModelsRootResolution;
          try {
            resolution = await ops.resolveModelsRoot();
          } catch (error) {
            return refuse(
              ops,
              localSurfaces,
              rootResolutionRefusal(error),
              "substrate_misconfigured",
            );
          }
          if (resolution.kind !== "resolved" || !isAbsolute(resolution.rootReal)) {
            return refuse(ops, localSurfaces, "model_root_invalid", "substrate_misconfigured");
          }
          rootState = { state: "ROOT_RESOLVED", rootReal: resolution.rootReal };
        }
        sweep = await verifyEveryModel(
          ops,
          models,
          rootState.rootReal,
          verified.body.manifest_version,
        );
        if (!sweep.ok) {
          return refuse(ops, localSurfaces, sweep.reason, "substrate_misconfigured");
        }
      }
      // The commit consumes a root ONLY from the ROOT_RESOLVED state. Both
      // conditions hold on every path above; refusing rather than asserting
      // keeps a future edit that breaks one of them from persisting a root that
      // was never strictly resolved or a sweep that never passed.
      if (rootState.state !== "ROOT_RESOLVED" || !sweep.ok) {
        return refuse(ops, localSurfaces, "model_root_invalid", "substrate_misconfigured");
      }

      const committedAt = (ops.now ?? (() => new Date()))().toISOString();
      const commit = buildAtomicCommit(
        verified,
        models,
        sweep.evidence,
        rootState.rootReal,
        committedAt,
      );
      try {
        await ops.commitVerified(commit);
      } catch (error) {
        // A second config mutation here would destroy save-failure preservation.
        return refuse(
          ops,
          localSurfaces,
          commitRefusalReason(error),
          "substrate_misconfigured",
          { recordFailure: false },
        );
      }

      // The ceremony's only success output. Without it an armed fortress looks
      // exactly like one that silently did nothing, which is why the armed
      // state had to be inferred from an encrypted record.
      ops.print(
        `Verified signed model manifest v${verified.body.manifest_version} against the pinned catalog key.`,
      );
      ops.print(`Local intelligence armed: ${renderArmedBindings(commit)}`);

      let provenanceProjection: "projected" | "degraded" = "projected";
      try {
        const projectionOutcome = await ops.projectProvenance(commit.provenance);
        await safeAudit(ops, {
          operation: INTEL_OPS.LOAD_INTEGRITY,
          outcome: "success",
          details: {
            stage: projectionOutcome === "repaired"
              ? "provenance_projection_recovery"
              : "provenance_projection",
            manifest_version: verified.body.manifest_version,
            model_count: commit.provenance.length,
            generation_refused: false,
          },
        });
      } catch {
        provenanceProjection = "degraded";
        await safeAudit(ops, {
          operation: INTEL_OPS.LOAD_INTEGRITY,
          outcome: "failure",
          details: {
            stage: "provenance_projection",
            reason: "integrity_io_unavailable",
            manifest_version: verified.body.manifest_version,
            generation_refused: false,
          },
        });
      }
      for (const surface of localSurfaces) {
        const binding = commit.integrityState.bindings[surface]!;
        await safeAudit(ops, {
          operation: INTEL_OPS.LOAD_INTEGRITY,
          outcome: "success",
          details: {
            surface,
            model_id: binding.model_id,
            manifest_version: binding.manifest_version,
            assurance: binding.assurance,
            stage: "provisioning_commit",
            expected_manifest_digest: binding.ollama_identity.ollama_manifest_sha256,
            generation_refused: false,
          },
        });
      }
      return {
        kind: alreadyPresent ? "already-provisioned" : "provisioned",
        surfaces: localSurfaces,
        models: [...models.keys()],
        provenanceProjection,
      };
    });
  } catch (error) {
    if (error instanceof CrossProcessLockError) {
      // The operator channel may name the lockfile and its manual-removal path;
      // audit fields remain on the closed reason taxonomy below.
      ops.print(error.message);
      return refuse(
        ops,
        affectedSurfaces,
        "integrity_io_unavailable",
        "substrate_unavailable",
        { recordFailure: false },
      );
    }
    if (error instanceof LocalIntegrityStateLoadError) {
      return refuse(
        ops,
        affectedSurfaces,
        commitRefusalReason(error),
        "substrate_misconfigured",
        { recordFailure: false },
      );
    }
    // The critical section may already have pulled or even committed before an
    // unexpected crash; persist a bounded failure instead of claiming no change.
    return refuse(
      ops,
      affectedSurfaces,
      "integrity_io_unavailable",
      "substrate_unavailable",
    );
  }
}

function rootResolutionRefusal(error: unknown): LocalProvisioningRefusalReason {
  return error instanceof LocalModelsRootResolutionError
    ? error.reason
    : "integrity_io_unavailable";
}

function commitRefusalReason(error: unknown): LocalProvisioningRefusalReason {
  if (!(error instanceof LocalIntegrityStateLoadError)) {
    return "integrity_io_unavailable";
  }
  return error.reason;
}

/**
 * Hex characters of a sha256 digest shown on an operator line. 12 hex chars =
 * 48 bits, long enough for an operator to match the line against the manifest
 * by eye and short enough that nobody mistakes it for the digest itself; the
 * full digest is what `sanctuary intelligence diagnose` prints.
 *
 * SOLE DECLARATION: the badge label in `intelligence/selector.ts` IMPORTS this
 * constant rather than re-typing 12, so the ceremony line and the concierge
 * label can never truncate one binding's digest to two different widths.
 */
export const ARMED_DIGEST_PREFIX_CHARS = 12;

/**
 * One line naming what this fortress is now bound to: each distinct runtime
 * tag with the prefix of the signed Ollama manifest digest it was verified
 * against. Never prints key material; the digest is public manifest content.
 */
function renderArmedBindings(commit: AtomicLocalProvisioningCommit): string {
  const byTag = new Map<string, string>();
  for (const binding of Object.values(commit.integrityState.bindings)) {
    if (binding === undefined) continue;
    byTag.set(
      binding.runtime_tag,
      binding.ollama_identity.ollama_manifest_sha256.slice(
        0,
        ARMED_DIGEST_PREFIX_CHARS,
      ),
    );
  }
  return [...byTag.entries()]
    .map(([tag, digestPrefix]) => `${tag} (manifest sha256 ${digestPrefix})`)
    .join(", ");
}

export function renderLocalProvisioningPlan(input: {
  installRuntime: boolean;
  platform: NodeJS.Platform;
  models: readonly ModelManifestModelV2[];
}): string[] {
  const lines = ["Local intelligence setup plan (no changes have been made):"];
  lines.push(
    input.installRuntime && input.platform === "win32"
      ? "- Install Ollama manually on Windows, then re-run this setup; automatic Windows installation is not available."
      : input.installRuntime
      ? "- Install Ollama using the platform adapter after confirmation."
      : "- Use the reachable Ollama runtime; no runtime install is planned.",
  );
  for (const model of input.models) {
    lines.push(
      `- Pull ${deriveOllamaRuntimeTag(model.ollama_identity)} from ${model.ollama_identity.registry} (${model.params_b}B parameters; license ${model.license.identifier}).`,
    );
    lines.push("- Verify its signed Ollama manifest root and required on-disk artifacts before binding.");
  }
  return lines;
}

async function safeAudit(
  ops: LocalProvisioningOps,
  event: LocalProvisioningAuditEvent,
): Promise<void> {
  try {
    await ops.audit(event);
  } catch {
    // Audit failure cannot roll back or replace the authoritative Q5 record.
  }
}

async function refuse(
  ops: LocalProvisioningOps,
  surfaces: readonly Surface[],
  reason: LocalProvisioningRefusalReason,
  failureClass: SubstrateFailureClass,
  options: { recordFailure?: boolean } = {},
): Promise<LocalProvisioningResult> {
  if (options.recordFailure !== false) {
    try {
      await ops.recordFailure(surfaces, failureClass, FAILURE_COPY[reason]);
    } catch {
      // Refusal remains fail-closed when its derived status projection cannot save.
    }
  }
  await safeAudit(ops, {
    operation: INTEL_OPS.MODEL_PROVISION_REFUSED,
    outcome: "failure",
    details: { reason, affected_surfaces: surfaces },
  });
  return { kind: "refused", reason };
}
