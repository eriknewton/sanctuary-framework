import type { InjectionSignal } from "../security/injection-detector.js";

export const COMPILED_CONTEXT_CONTRACT_VERSION =
  "sanctuary.compiled-context-screen.v1";
export const COMPILED_CONTEXT_SENTINEL_ID = "compiled-context-injection";

export const COMPILED_CONTEXT_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxContributors: 64,
  maxMetadataBytes: 16 * 1024,
  maxSignals: 32,
  maxCacheEntries: 128,
});

export type CompiledContextOutcome =
  | "clean"
  | "flagged_escalate"
  | "flagged_block"
  | "detector_disabled_by_policy"
  | "scan_failed"
  | "over_limit";

export type CompiledContextAssemblerId = "substrate-selector";

export type CompiledContextContributorKind =
  | "request_context"
  | "request_query"
  | "request_item"
  | "request_category"
  | "redaction_text";

// More specific source labels are accepted by the shared contract when an
// upstream assembler can prove them. The selector's generic typed adapter
// intentionally does not invent these labels.
export type CompiledContextKnownSourceKind =
  | CompiledContextContributorKind
  | "typed_history"
  | "recalled_memory"
  | "fetched_tool_result"
  | "federation_content";

export interface CompiledContextContributor {
  kind: CompiledContextKnownSourceKind;
}

/**
 * C4 will supply this adapter. It is optional today: callers must not invent
 * clustering values, and neither a low score nor a high trust tier changes
 * whether the artifact is scanned.
 */
export interface CompiledContextProvenanceClustering {
  version: string;
  primaryGrouping: "admission_lineage";
  clusterCount: number;
  largestClusterSize: number;
  distinctOriginCount: number;
  quarantinedVectorCount: number;
}

export interface CompiledContextMetadata {
  assemblerId: CompiledContextAssemblerId;
  surface: string;
  contributors: readonly CompiledContextContributor[];
  provenanceClustering?: CompiledContextProvenanceClustering;
}

export interface CompiledContextScanRequest {
  artifact: string;
  metadata: CompiledContextMetadata;
  /** Compiler-side bounded preflight; no detector/cache work may override it. */
  preflightOverLimit?: boolean;
  observedByteLength?: number;
}

export interface CompiledContextScanResult {
  outcome: CompiledContextOutcome;
  contentHash: string | null;
  byteLength: number;
  contributorCount: number;
  confidence: number;
  signals: readonly Pick<InjectionSignal, "type" | "severity">[];
  cacheHit: boolean;
}

export interface CompiledContextFindingReporter {
  report(finding: CompiledContextFinding): Promise<void>;
}

/** Structural subset accepted by SentinelDispatcher.reportFinding. */
export interface CompiledContextFinding {
  finding_id: string;
  sentinel_id: string;
  severity: "info" | "warn" | "alert";
  summary: string;
  details: Record<string, unknown>;
  observed_at: string;
  evidence_audit_ids: string[];
  fortress_id: string;
}
