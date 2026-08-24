import type { AuditLog } from "../operational/audit-log.js";
import { InjectionDetector } from "../security/injection-detector.js";
import { SentinelDispatcher } from "../sentinel/sentinel-dispatcher.js";
import { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import { SentinelRegistry } from "../sentinel/sentinel-registry.js";
import {
  ActionDispatcher,
  AutoTriggerActionRegistry,
} from "../auto-trigger/action-dispatcher.js";
import { ThresholdConfigStore } from "../auto-trigger/threshold-config-store.js";
import type { StorageBackend } from "../storage/interface.js";
import { COMPILED_CONTEXT_SENTINEL_ID } from "./types.js";
import { CompiledContextScanner } from "./scanner.js";

export const COMPILED_CONTEXT_DETECTOR_POLICY_FINGERPRINT =
  "injection-detector:v1:enabled:medium:escalate:decoded-rescans-64";

/** Bind screening findings to the existing production dispatcher graph. */
export function createDispatcherWiredCompiledContextScanner(options: {
  detector: Pick<InjectionDetector, "scan">;
  detectorEnabled: boolean;
  dispatcher: Pick<SentinelDispatcher, "reportFinding">;
  policyFingerprint?: string;
}): CompiledContextScanner {
  return new CompiledContextScanner({
    detector: options.detector,
    detectorEnabled: options.detectorEnabled,
    policyFingerprint:
      options.policyFingerprint ?? COMPILED_CONTEXT_DETECTOR_POLICY_FINGERPRINT,
    reporter: {
      async report(finding): Promise<void> {
        await options.dispatcher.reportFinding(
          COMPILED_CONTEXT_SENTINEL_ID,
          finding,
        );
      },
    },
  });
}

/**
 * Build the same durable finding/audit/auto-trigger graph for production
 * entrypoints that do not run the main MCP sentinel boot sequence (standalone
 * dashboard and local legacy concierge CLI).
 */
export function createCompiledContextRuntime(options: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  fortressId: string;
  identityId: string;
}): {
  scanner: CompiledContextScanner;
  findingStore: SentinelFindingStore;
  sentinelDispatcher: SentinelDispatcher;
  autoTriggerDispatcher: ActionDispatcher;
} {
  const findingStore = new SentinelFindingStore({
    storage: options.storage,
    masterKey: options.masterKey,
    fortressId: options.fortressId,
    auditLog: options.auditLog,
  });
  const sentinelDispatcher = new SentinelDispatcher({
    registry: new SentinelRegistry(),
    findingStore,
    auditLog: options.auditLog,
    fortressId: options.fortressId,
    identityId: options.identityId,
    tickIntervalMs: 0,
  });
  const thresholdStore = new ThresholdConfigStore({
    storage: options.storage,
    masterKey: options.masterKey,
    fortressId: options.fortressId,
  });
  const autoTriggerDispatcher = new ActionDispatcher({
    store: thresholdStore,
    action: AutoTriggerActionRegistry.withDefaults(
      options.auditLog,
      options.identityId,
      options.fortressId,
    ),
    auditLog: options.auditLog,
    fortressId: options.fortressId,
    identityId: options.identityId,
  });
  sentinelDispatcher.onEvent((event) => {
    if (event.type !== "finding") return;
    void autoTriggerDispatcher.handleFinding(event.finding, "sentinel");
  });
  const detector = new InjectionDetector({
    enabled: true,
    sensitivity: "medium",
    on_detection: "escalate",
  });
  return {
    scanner: createDispatcherWiredCompiledContextScanner({
      detector,
      detectorEnabled: true,
      dispatcher: sentinelDispatcher,
    }),
    findingStore,
    sentinelDispatcher,
    autoTriggerDispatcher,
  };
}
