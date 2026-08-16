/**
 * C12-REPLAY — revoke-denial audit-write governor (rule 8, §2.5 + F-8a + NH-4).
 *
 * Once freshness enforcement exists, every replay is a guaranteed denial, so an
 * attacker can convert harvested-but-expired signatures into an audit-write
 * amplifier. This governor caps the writes with a per-authentic-emitter token
 * bucket AND a global per-node ceiling above it (a sync response relays events
 * from MANY authentic emitters, so per-emitter keying alone totals M*perEmitter
 * with M outside the defender's control).
 *
 * Two invariants the callers rely on:
 *   1. Suppression is FORENSIC-ONLY, never decisional. The accept/deny decision
 *      for a revoke is computed BEFORE and INDEPENDENTLY of whether its audit
 *      entry is written. A suppressed denial is still a denial.
 *   2. Saturation never blinds forensics. When suppressions occur, exactly one
 *      sealed SUMMARY entry per interval carries {suppressed_count,
 *      distinct_emitter_count} accumulated over the interval — an attacker who
 *      floods to saturate the ceiling degrades per-attempt attribution
 *      granularity but can never erase HOW MANY denials occurred or from HOW
 *      MANY distinct authentic emitters while saturated.
 *
 * Placement note (design Q6): the design leaned toward the shared
 * `sealAuditEntry` boundary. Concrete obstacle taken here: `sealAuditEntry`
 * (`mesh/audit-batch.ts`) is a STATELESS pure crypto primitive shared by every
 * audit path, and a per-node denial ceiling needs per-node mutable window
 * state; threading that state through every seal call site would be a larger,
 * riskier change than a scoped governor owned by MeshNode. The governor is
 * still a single shared object so other denial paths can adopt it.
 */

/** A sealed-summary payload the caller writes once per saturated interval. */
export interface DenialSaturationSummary {
  suppressed_count: number;
  distinct_emitter_count: number;
}

export interface DenialAuditDecision {
  /** Whether to write THIS denial's individual sealed audit entry. */
  writeIndividual: boolean;
  /**
   * Present when a prior interval's suppressions must now be summarized (the
   * window just rolled over). The caller writes one sealed summary entry.
   */
  saturationSummary?: DenialSaturationSummary;
}

export class DenialAuditGovernor {
  private windowStartMs: number | null = null;
  private readonly perEmitter = new Map<string, number>();
  private globalWritten = 0;
  private suppressed = 0;
  private readonly distinctSuppressed = new Set<string>();

  constructor(
    private readonly perEmitterMax: number,
    private readonly globalMax: number,
    private readonly windowMs: number
  ) {}

  /**
   * Decide whether this denial's individual audit entry is written. The
   * accept/deny of the revoke itself has ALREADY happened; this is audit-write
   * accounting only.
   */
  consider(emitterNode: string, nowMs: number): DenialAuditDecision {
    const rolledSummary = this.rollIfElapsed(nowMs);
    if (this.windowStartMs === null) this.windowStartMs = nowMs;

    const per = this.perEmitter.get(emitterNode) ?? 0;
    let writeIndividual: boolean;
    if (this.globalWritten < this.globalMax && per < this.perEmitterMax) {
      this.perEmitter.set(emitterNode, per + 1);
      this.globalWritten += 1;
      writeIndividual = true;
    } else {
      this.suppressed += 1;
      this.distinctSuppressed.add(emitterNode);
      writeIndividual = false;
    }
    return { writeIndividual, saturationSummary: rolledSummary };
  }

  /**
   * Emit any pending saturation summary for the CURRENT interval's suppressions
   * without waiting for the window to roll (production wires this to the same
   * periodic timer as the audit-buffer flush). Returns undefined when there is
   * nothing to summarize. Clears the suppression accumulators so a summary is
   * emitted at most once per pending set.
   */
  flushSaturationSummary(): DenialSaturationSummary | undefined {
    if (this.suppressed === 0) return undefined;
    const summary: DenialSaturationSummary = {
      suppressed_count: this.suppressed,
      distinct_emitter_count: this.distinctSuppressed.size,
    };
    this.suppressed = 0;
    this.distinctSuppressed.clear();
    return summary;
  }

  private rollIfElapsed(nowMs: number): DenialSaturationSummary | undefined {
    if (
      this.windowStartMs !== null &&
      nowMs - this.windowStartMs >= this.windowMs
    ) {
      const summary =
        this.suppressed > 0
          ? {
              suppressed_count: this.suppressed,
              distinct_emitter_count: this.distinctSuppressed.size,
            }
          : undefined;
      this.reset(nowMs);
      return summary;
    }
    return undefined;
  }

  private reset(nowMs: number): void {
    this.windowStartMs = nowMs;
    this.perEmitter.clear();
    this.globalWritten = 0;
    this.suppressed = 0;
    this.distinctSuppressed.clear();
  }
}
