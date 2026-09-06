import { createHash } from "node:crypto";
import {
  COMPILED_CONTEXT_SCAN_NAME,
  FIRST_PARTY_RUNTIME_FIELD,
  InjectionDetector,
} from "../security/injection-detector.js";
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
 * The field name carrying the bytes this runtime assembled itself, and the
 * scan name that field is only meaningful under, are IMPORTED from
 * `../security/injection-detector.ts` rather than re-typed here: that module
 * is the side that grants the prompt-stuffing exemption, so it declares the
 * contract and this module consumes it. The exemption covers the size and
 * repetition heuristic and nothing else. Only this scanner ever writes the
 * field, and it writes it only from contributors an assembler labelled
 * `first_party_runtime`, so untrusted bytes have no path to the exemption.
 */

/** Detector field name carrying every contributor that is not first-party. */
const UNTRUSTED_FIELD = "compiled_payload";

/**
 * Term appended to every screening-cache policy fingerprint once the detector
 * sizes a first-party contributor differently from an untrusted one.
 *
 * Declared here, once, and imported by `./runtime.ts`: the fingerprint is a
 * CACHE KEY, so if the two fingerprints in this module and that one stop
 * agreeing about the detector's policy, a result decided under the old policy
 * can be replayed under the new one. A hand-typed suffix in two files is the
 * shape that drifts, and it drifts silently, because a wrong cache key never
 * fails to compile and never fails a test that does not exercise the cache.
 */
export const FIRST_PARTY_STUFFING_EXEMPT_FINGERPRINT_TERM =
  "first-party-stuffing-exempt";

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
    // Moves with the shared detector policy, same reason as
    // COMPILED_CONTEXT_DETECTOR_POLICY_FINGERPRINT in ./runtime.ts.
    policyFingerprint:
      `default:enabled:medium:escalate:${FIRST_PARTY_STUFFING_EXEMPT_FINGERPRINT_TERM}`,
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
      // `payload` tells the shared detector that JSON/XML structure is
      // expected here; it does not skip role/bypass/Unicode/decoded scans.
      const detection = this.detector.scan(
        COMPILED_CONTEXT_SCAN_NAME,
        detectorPayload(request),
      );
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

/**
 * Split the compiled artifact into the fields the shared detector scans.
 *
 * Default and fallback shape is the single `compiled_payload` field holding
 * the whole artifact, exactly as before trust classes existed. The two-field
 * shape is used ONLY when the assembler supplied per-contributor `parts` that
 * align with its contributor list, CONCATENATE BACK to the artifact character
 * for character, and include at least one contributor labelled
 * `first_party_runtime`. Every character is still scanned in both shapes; the
 * split exists so the size of the runtime's own template is not counted
 * against the untrusted budget.
 *
 * INVARIANT: the artifact is the unit that is hashed, cached, and released, so
 * `parts` are only a description of it and must be PROVEN to describe it. A
 * count check alone is a container-level check: it passes parts that agree in
 * number while differing in content, which would let the scanned text and the
 * released text diverge. The concatenation comparison below is the whole
 * agreement, and it pins the compiler's `PART_SEPARATOR` handling by
 * construction rather than by a mirrored constant.
 *
 * INVARIANT: unusable provenance (missing `parts`, a count mismatch, or parts
 * that do not reconstruct the artifact) falls back to the single untrusted
 * field, so a malformed request can only tighten screening, never loosen it.
 *
 * Residual, stated rather than hidden: grouping splits one scanned string into
 * two, so a pattern that straddles the boundary between the first-party
 * segment and the untrusted one is no longer adjacent to the pattern matcher.
 * Every character still reaches the detector in one group or the other, and
 * order within each group is preserved, so no pattern that fits inside a
 * single group is lost. The residual is exactly that lost adjacency, for a
 * pattern whose halves are each individually benign.
 *
 * The two groups are NOT scanned identically, and no comment here should imply
 * they are: the first-party field is exempt from the prompt-stuffing size and
 * repetition heuristic, which is the entire purpose of the split. Every other
 * heuristic (role override, security bypass, Unicode and homoglyph, encoded
 * payload, exfiltration) runs on both groups, and the hard artifact-size
 * refusal counts both.
 *
 * What the exemption rests on is AUTHORSHIP, not assembly. The assembler
 * verifies that the claimed prefix really is a prefix of the context it was
 * handed, and the single production minting site names only its own fixed
 * template text. Bytes this fortress merely assembled out of local records,
 * which quote agent-authored strings such as audit detail lines, identity
 * labels and task titles, fall outside that prefix and are screened as
 * untrusted like any other input.
 */
function detectorPayload(
  request: CompiledContextScanRequest,
): Record<string, unknown> {
  const contributors = request.metadata.contributors;
  const parts = request.parts;
  if (parts === undefined || parts.length !== contributors.length) {
    return { [UNTRUSTED_FIELD]: request.artifact };
  }
  // The parts must BE the artifact, not merely be counted like it.
  if (parts.join("") !== request.artifact) {
    return { [UNTRUSTED_FIELD]: request.artifact };
  }
  const firstParty: string[] = [];
  const untrusted: string[] = [];
  for (let index = 0; index < parts.length; index++) {
    // Absent trust reads as untrusted; see CompiledContextContributor.trust.
    const group = contributors[index]!.trust === "first_party_runtime"
      ? firstParty
      : untrusted;
    group.push(parts[index]!);
  }
  if (firstParty.length === 0) {
    return { [UNTRUSTED_FIELD]: request.artifact };
  }
  // Concatenated, not joined with a separator: the parts already carry the
  // separators the artifact was built with (proven by the equality above), so
  // inserting another would scan text the artifact does not contain.
  return {
    [UNTRUSTED_FIELD]: untrusted.join(""),
    [FIRST_PARTY_RUNTIME_FIELD]: firstParty.join(""),
  };
}
