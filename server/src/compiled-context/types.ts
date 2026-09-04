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

/**
 * Trust class of one contributor's bytes.
 *
 * `first_party_runtime` means the runtime itself assembled those bytes from
 * its own template and its own local records, so their SIZE is a design
 * choice of this fortress rather than an adversary's. `untrusted` means the
 * bytes came from, or can be steered by, someone other than the runtime:
 * the operator's question, agent-supplied text, a raw state-store payload.
 *
 * The class changes ONLY the prompt-stuffing size heuristic (see
 * {@link CompiledContextScanRequest.parts} and the scanner's first-party
 * field). No trust class exempts any contributor from role-override,
 * security-bypass, Unicode/homoglyph, decoded-payload, exfiltration or
 * over-limit screening, and no trust class makes a flagged artifact clean.
 */
export type CompiledContextTrustClass = "untrusted" | "first_party_runtime";

export interface CompiledContextContributor {
  kind: CompiledContextKnownSourceKind;
  /**
   * INVARIANT: an absent `trust` reads as `untrusted`. Provenance is proven
   * by the assembler that can prove it, never assumed by the scanner, so a
   * caller that says nothing keeps the strictest sizing.
   */
  trust?: CompiledContextTrustClass;
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
  /**
   * The contributor texts the assembler joined into `artifact`, index-aligned
   * with `metadata.contributors`. Supplied only so the scanner can size each
   * contributor by its trust class instead of sizing the joined total; the
   * artifact itself stays the hashed, cached, screened unit.
   *
   * INVARIANT: a `parts` array whose length does not equal the contributor
   * count is unusable provenance, so the scanner ignores it and screens the
   * whole artifact as untrusted. A mismatch can only lose an exemption, never
   * grant one.
   */
  parts?: readonly string[];
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
