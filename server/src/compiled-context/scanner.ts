import { createHash } from "node:crypto";
import { InjectionDetector } from "../security/injection-detector.js";
import {
  COMPILED_CONTEXT_CONTRACT_VERSION,
  COMPILED_CONTEXT_LIMITS,
  type CompiledContextFindingReporter,
  type CompiledContextFinding,
  type CompiledContextOutcome,
  type CompiledContextScanRequest,
  type CompiledContextScanResult,
} from "./types.js";

export interface CompiledContextScannerOptions {
  detector: Pick<InjectionDetector, "scan">;
  detectorEnabled: boolean;
  policyFingerprint: string;
  reporter: CompiledContextFindingReporter;
  limits?: Partial<Record<keyof typeof COMPILED_CONTEXT_LIMITS, number>>;
}

type CompiledContextLimits = Record<keyof typeof COMPILED_CONTEXT_LIMITS, number>;

/**
 * Safe construction default for tests and non-runtime embedders. Input is
 * still inspected and suspicious input is still refused; production
 * construction sites are structurally required to replace the no-op reporter
 * with the real dispatcher wiring.
 */
export function createUnwiredCompiledContextScanner(): CompiledContextScanner {
  return new CompiledContextScanner({
    detector: new InjectionDetector({
      enabled: true,
      sensitivity: "medium",
      on_detection: "escalate",
    }),
    detectorEnabled: true,
    policyFingerprint: "default:enabled:medium:escalate",
    reporter: {
      async report(): Promise<void> {},
    },
  });
}

export class CompiledContextScanner {
  private readonly detector: Pick<InjectionDetector, "scan">;
  private readonly detectorEnabled: boolean;
  private readonly policyFingerprint: string;
  private readonly reporter: CompiledContextFindingReporter;
  private readonly limits: CompiledContextLimits;
  private readonly cache = new Map<string, CompiledContextScanResult>();

  constructor(options: CompiledContextScannerOptions) {
    this.detector = options.detector;
    this.detectorEnabled = options.detectorEnabled;
    this.policyFingerprint = options.policyFingerprint;
    this.reporter = options.reporter;
    this.limits = Object.freeze({
      ...COMPILED_CONTEXT_LIMITS,
      ...(options.limits ?? {}),
    });
  }

  async screen(request: CompiledContextScanRequest): Promise<CompiledContextScanResult> {
    const byteLength =
      request.observedByteLength ?? Buffer.byteLength(request.artifact, "utf8");
    const contributorCount = request.metadata.contributors.length;
    if (
      request.preflightOverLimit === true ||
      byteLength > this.limits.maxBytes ||
      contributorCount > this.limits.maxContributors
    ) {
      return this.reportNonTerminal("over_limit", request, byteLength);
    }

    let metadataJson: string;
    try {
      metadataJson = JSON.stringify(request.metadata);
    } catch {
      return this.reportNonTerminal("scan_failed", request, byteLength);
    }
    if (Buffer.byteLength(metadataJson, "utf8") > this.limits.maxMetadataBytes) {
      return this.reportNonTerminal("over_limit", request, byteLength);
    }

    const contentHash = sha256Hex(request.artifact);
    const cacheKey = sha256Hex(
      [
        COMPILED_CONTEXT_CONTRACT_VERSION,
        this.policyFingerprint,
        this.detectorEnabled ? "enabled" : "disabled",
        metadataJson,
        contentHash,
        String(byteLength),
      ].join("\u0000"),
    );
    const cached = this.cache.get(cacheKey);
    if (cached) {
      this.cache.delete(cacheKey);
      this.cache.set(cacheKey, cached);
      return { ...cached, cacheHit: true };
    }

    if (!this.detectorEnabled) {
      const disabled = this.makeResult(
        "detector_disabled_by_policy",
        contentHash,
        byteLength,
        contributorCount,
        0,
        [],
      );
      try {
        await this.report(disabled, request);
      } catch {
        return this.reportNonTerminal("scan_failed", request, byteLength);
      }
      this.retain(cacheKey, disabled);
      return disabled;
    }

    try {
      const detection = this.detector.scan("compiled_context", {
        // `payload` tells the shared detector that JSON/XML structure is
        // expected here; it does not skip role/bypass/Unicode/decoded scans.
        compiled_payload: request.artifact,
      });
      // The shared detector also reports generic inbound URLs/emails as
      // `data_exfiltration`. Those are not TM-SHARD injection evidence and,
      // for frontier-with-filter, must reach the existing PII redactor. Keep
      // every injection/evasion/stuffing signal and exclude only that separate
      // context-gate concern from this verdict.
      const verdictSignals = detection.signals.filter(
        (signal) => signal.type !== "data_exfiltration",
      );
      const outcome: CompiledContextOutcome = verdictSignals.length === 0
        ? "clean"
        : verdictSignals.some((signal) => signal.severity === "high")
          ? "flagged_block"
          : "flagged_escalate";
      const result = this.makeResult(
        outcome,
        contentHash,
        byteLength,
        contributorCount,
        detection.confidence,
        verdictSignals
          .slice(0, this.limits.maxSignals)
          .map(({ type, severity }) => ({ type, severity })),
      );
      if (outcome !== "clean") await this.report(result, request);
      this.retain(cacheKey, result);
      return result;
    } catch {
      return this.reportNonTerminal("scan_failed", request, byteLength);
    }
  }

  getRetainedCacheEntriesForTest(): number {
    return this.cache.size;
  }

  private async reportNonTerminal(
    outcome: "scan_failed" | "over_limit",
    request: CompiledContextScanRequest,
    byteLength: number,
  ): Promise<CompiledContextScanResult> {
    const result = this.makeResult(
      outcome,
      null,
      byteLength,
      request.metadata.contributors.length,
      1,
      [],
    );
    try {
      await this.report(result, request);
    } catch {
      // The original fail-closed outcome is retained even when its operator
      // reporting dependency is also unavailable. Callers never treat it clean.
    }
    return result;
  }

  private makeResult(
    outcome: CompiledContextOutcome,
    contentHash: string | null,
    byteLength: number,
    contributorCount: number,
    confidence: number,
    signals: CompiledContextScanResult["signals"],
  ): CompiledContextScanResult {
    return {
      outcome,
      contentHash,
      byteLength,
      contributorCount,
      confidence,
      signals,
      cacheHit: false,
    };
  }

  private async report(
    result: CompiledContextScanResult,
    request: CompiledContextScanRequest,
  ): Promise<void> {
    const severity =
      result.outcome === "flagged_escalate" ||
      result.outcome === "detector_disabled_by_policy"
        ? "warn"
        : "alert";
    const signalTypes = result.signals.map((signal) => signal.type).join(",").slice(0, 512);
    const finding: CompiledContextFinding = {
      finding_id: "",
      sentinel_id: "",
      severity,
      summary: `Compiled-context screening outcome: ${result.outcome}`,
      details: {
        outcome: result.outcome,
        assembler_id: request.metadata.assemblerId,
        surface: request.metadata.surface.slice(0, 96),
        content_sha256: result.contentHash ?? "unavailable",
        byte_length: result.byteLength,
        contributor_count: result.contributorCount,
        signal_count: result.signals.length,
        signal_types: signalTypes,
        contract_version: COMPILED_CONTEXT_CONTRACT_VERSION,
        provenance_clustering_supplied:
          request.metadata.provenanceClustering !== undefined,
      },
      observed_at: "",
      evidence_audit_ids: [],
      fortress_id: "",
    };
    await this.reporter.report(finding);
  }

  private retain(key: string, result: CompiledContextScanResult): void {
    this.cache.set(key, result);
    while (this.cache.size > this.limits.maxCacheEntries) {
      const oldest = this.cache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
  }
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
