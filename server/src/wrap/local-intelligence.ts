/** Shared `protect` / `init` adapter for the P1 provisioning ceremony. */

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
  SubstrateSelector,
  TIER2_PINNED_SURFACE,
  runLocalIntelligenceProvisioning,
  type LocalProvisioningResult,
  type Surface,
} from "../intelligence/index.js";

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
  /** Host installer adapter; no installer mutation is implemented in P1. */
  installRuntime?: () => Promise<boolean>;
  modelStore?: ModelProvenanceStore;
  client?: OllamaClient;
  confirm?: (prompt: string) => Promise<boolean>;
  platform?: NodeJS.Platform;
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
  });
  await selector.load();
  const config = selector.getConfig();
  const configuredChoices = { ...config.perSurface };
  // Invoke-time posture already pins this surface local. Provisioning uses
  // the same effective choice without rewriting a tampered persisted choice.
  configuredChoices[TIER2_PINNED_SURFACE] = "local";
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
  return runLocalIntelligenceProvisioning({
    isTty,
    platform: deps.platform ?? process.platform,
    preAnswered: input.preAnswered,
    manifestText,
    configuredChoices,
    probeHardware: () => selector.probeHardware(),
    installRuntime: deps.installRuntime ?? (async () => false),
    pull: (runtimeTag) => client.pull(runtimeTag),
    show: (runtimeTag) => client.show(runtimeTag),
    confirm,
    print,
    commitVerified: async (commits) => {
      const runtimeTags: Partial<Record<Surface, string>> = {};
      for (const commit of commits) {
        modelStore.declare(commit.provenance);
        for (const surface of commit.surfaces) {
          runtimeTags[surface] = commit.model.runtime_tag;
        }
      }
      await selector.markLocalModelsProvisioned(runtimeTags);
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
