/**
 * Consent-gated local-intelligence provisioning.
 *
 * This module owns sequencing only. Every host/network mutation is injected,
 * so tests never install Ollama, reach a registry, or pull real weights. The
 * sole trust input is the typed body returned by the merged P2 verifier.
 */

import { timingSafeEqual } from "node:crypto";
import { INTEL_OPS } from "./audit-events.js";
import {
  provenanceFromVerifiedModelManifest,
  resolveModelForSurface,
  verifyModelManifest,
  type ModelManifestModel,
  type ModelManifestVerificationResult,
} from "./model-manifest.js";
import type {
  HardwareCapabilityReport,
  SubstrateChoice,
  SubstrateFailureClass,
  Surface,
} from "./types.js";
import { SURFACES } from "./types.js";
import type { ModelProvenance } from "../operational/model-provenance.js";
import type {
  OllamaMutationResult,
  OllamaShowResult,
} from "./substrates/local.js";
import { localProvisioningPreflightRefusal } from "./provisioning-consent.js";

export const MODEL_REGISTRY_PROVIDER_CATEGORY = "model-registry" as const;

export type LocalProvisioningRefusalReason =
  | "declined"
  | "non_tty"
  | "manifest_unavailable"
  | "manifest_invalid"
  | "below_baseline"
  | "manual_install_required"
  | "install_failed"
  | "pull_failed"
  | "show_failed"
  | "digest_mismatch"
  | "commit_failed";

export interface VerifiedProvisioningCommit {
  model: ModelManifestModel;
  provenance: ModelProvenance;
  surfaces: readonly Surface[];
}

export interface LocalProvisioningAuditEvent {
  operation:
    | typeof INTEL_OPS.MODEL_PULL
    | typeof INTEL_OPS.MODEL_PROVISION_REFUSED;
  outcome: "success" | "failure";
  details: Readonly<Record<string, string | number | boolean | readonly string[]>>;
}

export interface LocalProvisioningOps {
  isTty: boolean;
  platform: NodeJS.Platform;
  /** false is an explicit decline; true still cannot bypass the TTY confirm. */
  preAnswered?: boolean;
  manifestText: string | null;
  configuredChoices: Readonly<Record<Surface, SubstrateChoice>>;
  verifyManifest?: (text: string | null) => ModelManifestVerificationResult;
  probeHardware: () => Promise<HardwareCapabilityReport>;
  installRuntime: () => Promise<boolean>;
  pull: (runtimeTag: string) => Promise<OllamaMutationResult>;
  show: (runtimeTag: string) => Promise<OllamaShowResult>;
  confirm: (prompt: string) => Promise<boolean>;
  print: (line: string) => void;
  commitVerified: (commits: readonly VerifiedProvisioningCommit[]) => Promise<void>;
  recordFailure: (
    surfaces: readonly Surface[],
    failureClass: SubstrateFailureClass,
    snippet: string,
  ) => Promise<void>;
  audit: (event: LocalProvisioningAuditEvent) => Promise<void> | void;
}

export type LocalProvisioningResult =
  | { kind: "provisioned"; surfaces: readonly Surface[]; models: readonly string[] }
  | { kind: "already-provisioned"; surfaces: readonly Surface[]; models: readonly string[] }
  | { kind: "refused"; reason: LocalProvisioningRefusalReason };

const FAILURE_COPY: Record<LocalProvisioningRefusalReason, string> = {
  declined: "Local intelligence setup was declined; configured local surfaces remain local and degraded.",
  non_tty: "Local intelligence setup requires an interactive TTY; no runtime or model mutation occurred.",
  manifest_unavailable: "The signed local-model manifest is unavailable; no model pull was attempted.",
  manifest_invalid: "The signed local-model manifest failed verification; no model pull was attempted.",
  below_baseline: "This host is below the signed local-model baseline; no model pull was attempted.",
  manual_install_required: "Automatic Ollama installation is unavailable on Windows; install Ollama manually, then re-run local intelligence setup.",
  install_failed: "Ollama installation did not complete; no surface was marked provisioned.",
  pull_failed: "A manifest-approved model pull failed; no surface was marked provisioned.",
  show_failed: "The installed model digest could not be observed; no surface was marked provisioned.",
  digest_mismatch: "The installed model digest did not match the signed manifest; no surface was marked provisioned.",
  commit_failed: "Verified model state could not be committed; no surface was marked provisioned.",
};

/**
 * Run one plan-print-confirm-pull-verify-commit ceremony. The digest gate is
 * all-or-nothing: no provenance or surface binding is committed until every
 * distinct model required by the local surfaces matches its signed digest.
 */
export async function runLocalIntelligenceProvisioning(
  ops: LocalProvisioningOps,
): Promise<LocalProvisioningResult> {
  const localSurfaces = SURFACES.filter(
    (surface) => ops.configuredChoices[surface] === "local",
  );

  const preflightRefusal = localProvisioningPreflightRefusal(
    ops.isTty,
    ops.preAnswered,
  );
  if (preflightRefusal !== null) {
    return refuse(
      ops,
      localSurfaces,
      preflightRefusal,
      preflightRefusal === "non_tty"
        ? "substrate_unavailable"
        : "substrate_misconfigured",
    );
  }

  const verifyManifest = ops.verifyManifest ?? verifyModelManifest;
  const verified = verifyManifest(ops.manifestText);
  if (!verified.ok) {
    const reason = verified.reason === "absent"
      ? "manifest_unavailable"
      : "manifest_invalid";
    return refuse(ops, localSurfaces, reason, "substrate_misconfigured");
  }

  const hardware = await ops.probeHardware();
  if (hardware.tier === "below-baseline") {
    return refuse(ops, localSurfaces, "below_baseline", "substrate_unavailable");
  }

  const models = new Map<string, { model: ModelManifestModel; surfaces: Surface[] }>();
  for (const surface of localSurfaces) {
    const model = resolveModelForSurface(verified.body, hardware.tier, surface);
    // The P2 parser closes references; null here is an explicit no-model tier
    // and cannot be reinterpreted as permission to use a hardcoded default.
    if (model === null) {
      return refuse(ops, localSurfaces, "manifest_invalid", "substrate_misconfigured");
    }
    const existing = models.get(model.model_id);
    if (existing) existing.surfaces.push(surface);
    else models.set(model.model_id, { model, surfaces: [surface] });
  }

  const alreadyPresent = await allDigestsMatch(models, ops.show);
  if (alreadyPresent) {
    return {
      kind: "already-provisioned",
      surfaces: localSurfaces,
      models: [...models.keys()],
    };
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
    `Set up local intelligence now? This installs/uses Ollama and downloads models totaling ${estimatedParamsB.toFixed(2)}B signed parameters, verified against a signed manifest. [y/N] `,
  );
  if (!confirmed) {
    return refuse(ops, localSurfaces, "declined", "substrate_misconfigured");
  }

  if (!hardware.ollamaReachable && !(await ops.installRuntime())) {
    return refuse(ops, localSurfaces, "install_failed", "substrate_unavailable");
  }

  for (const { model } of models.values()) {
    const pulled = await ops.pull(model.runtime_tag);
    if (!pulled.ok) {
      await ops.audit({
        operation: INTEL_OPS.MODEL_PULL,
        outcome: "failure",
        details: {
          model_id: model.model_id,
          registry_source: model.registry_source,
          provider_category: MODEL_REGISTRY_PROVIDER_CATEGORY,
          manifest_version: verified.body.manifest_version,
        },
      });
      return refuse(ops, localSurfaces, "pull_failed", pulled.failureClass ?? "substrate_unavailable");
    }
    await ops.audit({
      operation: INTEL_OPS.MODEL_PULL,
      outcome: "success",
      details: {
        model_id: model.model_id,
        registry_source: model.registry_source,
        provider_category: MODEL_REGISTRY_PROVIDER_CATEGORY,
        manifest_version: verified.body.manifest_version,
      },
    });
    const observed = await ops.show(model.runtime_tag);
    if (!observed.ok || observed.digest === null) {
      return refuse(ops, localSurfaces, "show_failed", observed.failureClass ?? "substrate_unavailable");
    }
    if (!digestsEqual(observed.digest, model.weights_sha256)) {
      return refuse(ops, localSurfaces, "digest_mismatch", "substrate_misconfigured");
    }
  }

  const declaredAt = new Date().toISOString();
  const commits: VerifiedProvisioningCommit[] = [...models.values()].map(
    ({ model, surfaces }) => ({
      model,
      provenance: {
        ...provenanceFromVerifiedModelManifest(model, declaredAt),
        serving_surfaces: surfaces,
      },
      surfaces,
    }),
  );
  try {
    await ops.commitVerified(commits);
  } catch {
    return refuse(ops, localSurfaces, "commit_failed", "substrate_misconfigured");
  }
  return {
    kind: "provisioned",
    surfaces: localSurfaces,
    models: commits.map((entry) => entry.model.model_id),
  };
}

export function renderLocalProvisioningPlan(input: {
  installRuntime: boolean;
  platform: NodeJS.Platform;
  models: readonly ModelManifestModel[];
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
      `- Pull ${model.runtime_tag} from ${model.registry_source} (${model.params_b}B parameters; license ${model.license.identifier}).`,
    );
    lines.push("- Verify its observed SHA-256 against the signed model manifest before use.");
  }
  return lines;
}

async function allDigestsMatch(
  models: ReadonlyMap<string, { model: ModelManifestModel }>,
  show: LocalProvisioningOps["show"],
): Promise<boolean> {
  if (models.size === 0) return true;
  for (const { model } of models.values()) {
    const observed = await show(model.runtime_tag);
    if (
      !observed.ok ||
      observed.digest === null ||
      !digestsEqual(observed.digest, model.weights_sha256)
    ) {
      return false;
    }
  }
  return true;
}

function digestsEqual(observed: string, expected: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(observed) || !/^[0-9a-f]{64}$/.test(expected)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(observed, "hex"), Buffer.from(expected, "hex"));
}

async function refuse(
  ops: LocalProvisioningOps,
  surfaces: readonly Surface[],
  reason: LocalProvisioningRefusalReason,
  failureClass: SubstrateFailureClass,
): Promise<LocalProvisioningResult> {
  await ops.recordFailure(surfaces, failureClass, FAILURE_COPY[reason]);
  await ops.audit({
    operation: INTEL_OPS.MODEL_PROVISION_REFUSED,
    outcome: "failure",
    details: { reason, affected_surfaces: surfaces },
  });
  return { kind: "refused", reason };
}
