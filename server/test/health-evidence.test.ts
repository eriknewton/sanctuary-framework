import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import {
  buildHealthEvidenceReport,
  evaluateCastleWall,
} from "../src/health/evidence.js";

describe("health evidence", () => {
  it("reports Castle Wall active when daemon and enforcement evidence are present", () => {
    const status = evaluateCastleWall({
      platform: "linux",
      configured: true,
      daemonUp: true,
      nftablesApplied: true,
      cgroupAttached: true,
      detectorName: "test detector",
      lastEventAt: "2026-05-16T01:02:03.000Z",
      statusResponse: {
        uptime_seconds: 42,
        loaded_rule_count: 7,
        no_wall_engaged: false,
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "enforcing",
        kernel_runtime_ready: true,
        enforcing: true,
        loaded_manifest_signature_b64url: "sig",
      },
    });

    expect(status.status).toBe("active");
    expect(status.last_event_at).toBe("2026-05-16T01:02:03.000Z");
    expect(status.detector_evidence).toContain("test detector reports daemon up");
    expect(status.detector_evidence).toContain("loaded rules 7");
    expect(status.detector_evidence).toContain("nftables true");
    expect(status.detector_evidence).toContain("cgroup true");
  });

  it("does not report Castle Wall active when it is missing or disabled", () => {
    const notConfigured = evaluateCastleWall({
      platform: "linux",
      configured: false,
      reason: "Castle Wall disabled in test config",
    });
    const inactive = evaluateCastleWall({
      platform: "linux",
      configured: true,
      daemonUp: false,
    });

    expect(notConfigured.status).toBe("not_configured");
    expect(notConfigured.status).not.toBe("active");
    expect(notConfigured.detector_evidence).toContain("disabled");
    expect(inactive.status).toBe("inactive");
    expect(inactive.status).not.toBe("active");
  });

  it("reports degraded when the daemon is up but nftables is not applied", () => {
    const status = evaluateCastleWall({
      platform: "linux",
      configured: true,
      daemonUp: true,
      nftablesApplied: false,
      cgroupAttached: true,
      statusResponse: {
        uptime_seconds: 12,
        loaded_rule_count: 3,
        no_wall_engaged: false,
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "enforcing",
        kernel_runtime_ready: true,
        enforcing: true,
        loaded_manifest_signature_b64url: "sig",
      },
    });

    expect(status.status).toBe("degraded");
    expect(status.detector_evidence).toContain("nftables rules not applied");
  });

  it("does not promote a running control-plane-only daemon to active", () => {
    const status = evaluateCastleWall({
      platform: "linux",
      configured: true,
      daemonUp: true,
      nftablesApplied: true,
      cgroupAttached: true,
      statusResponse: {
        uptime_seconds: 12,
        loaded_rule_count: 3,
        no_wall_engaged: false,
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "control_plane_only",
        kernel_runtime_ready: false,
        enforcing: false,
        loaded_manifest_signature_b64url: "sig",
      },
    });
    expect(status.status).toBe("degraded");
    expect(status.detector_evidence).toContain("control_plane_only");
  });

  it("reports unknown when no runtime detector evidence is available", () => {
    const status = evaluateCastleWall();

    expect(status.status).toBe("unknown");
    expect(status.status).not.toBe("active");
    expect(status.detector_evidence).toContain("No Castle Wall runtime detector");
  });

  it("builds health reports with unknown subsystems instead of optimistic defaults", () => {
    const report = buildHealthEvidenceReport({
      config: defaultConfig(),
      identityCount: 0,
      storageBackendName: "MemoryStorage",
    });

    expect(report.castle_wall.status).toBe("unknown");
    expect(report.egress.enforcement).toBe("unknown");
    expect(report.audit.writes_persistent).toBe(false);
    expect(report.audit.chain_verified).toBe("unknown");
    expect(report.layers.l1.status).toBe("unknown");
    expect(report.layers.l4.interaction_count).toBe("unknown");
  });

  // Honesty (audit seam #4): L3/L4 must NOT report "active" on config
  // presence. "active" means observed enforcement; no detector observes a
  // disclosure proof emitted or a reputation interaction in this process.
  it("does not claim L3/L4 active on config presence (configured-not-verified)", () => {
    const report = buildHealthEvidenceReport({
      config: defaultConfig(),
      identityCount: 0,
      storageBackendName: "MemoryStorage",
    });

    // Default config has a ZK proof system (schnorr-pedersen) configured, but
    // no proof was emitted, so L3 is "unknown" (configured, unverified).
    expect(report.layers.l3.status).not.toBe("active");
    expect(report.layers.l3.status).toBe("unknown");
    expect(report.layers.l3.proof_emitted_in_window).toBe(false);
    expect(report.layers.l3.evidence).toContain("no proof emitted");

    // Reputation telemetry is unavailable, so L4 is "unknown", never "active".
    expect(report.layers.l4.status).not.toBe("active");
    expect(report.layers.l4.status).toBe("unknown");
    expect(report.layers.l4.evidence).toContain("configured, unverified");
  });

  // Honesty (audit seam #4): commitment-only disclosure has no ZK proof
  // system at all — L3 is "not_configured", never "active".
  it("reports L3 not_configured when only commitment-only disclosure is set", () => {
    const config = defaultConfig();
    config.disclosure.proof_system = "commitment-only";
    const report = buildHealthEvidenceReport({
      config,
      identityCount: 0,
      storageBackendName: "MemoryStorage",
    });

    expect(report.layers.l3.status).toBe("not_configured");
    expect(report.layers.l3.evidence).toContain("no zero-knowledge proof system");
  });
});

describe("health/evidence : the four-state runtime model", () => {
  const base = {
    platform: "linux" as const,
    configured: true as const,
    daemonUp: true as const,
    nftablesApplied: true as const,
    cgroupAttached: true as const,
  };
  const status = (over: Record<string, unknown>) => ({
    uptime_seconds: 12,
    loaded_rule_count: 3,
    no_wall_engaged: false,
    loaded_manifest_signature_b64url: "sig",
    ...over,
  });

  /**
   * FAIL-BEFORE for the compatibility outage: a pre-v2 daemon reports NONE of
   * the runtime fields. The previous branch compared them directly, so
   * `undefined !== "running"` produced a `degraded` verdict about a daemon that
   * simply does not report the field. Absence must read as not-proven, never as
   * proof of failure.
   */
  it("reads a pre-v2 daemon's ABSENT runtime block as unknown, not degraded", () => {
    const result = evaluateCastleWall({
      ...base,
      statusResponse: status({}) as never,
    });
    expect(result.status).toBe("unknown");
    expect(result.status).not.toBe("degraded");
    expect(result.status).not.toBe("active");
    expect(result.detector_evidence).toContain("not currently proven");
  });

  it("reads an INDETERMINATE health probe as unknown, not degraded and not active", () => {
    const result = evaluateCastleWall({
      ...base,
      statusResponse: status({
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "kernel_runtime_ready",
        kernel_runtime_ready: false,
        enforcing: false,
        runtime_health: "probe_unavailable",
      }) as never,
    });
    expect(result.status).toBe("unknown");
    expect(result.detector_evidence).toContain("probe_unavailable");
  });

  it("reads a PROVEN-lost runtime as degraded", () => {
    const result = evaluateCastleWall({
      ...base,
      statusResponse: status({
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "kernel_runtime_ready",
        kernel_runtime_ready: true,
        enforcing: false,
        runtime_health: "lost",
      }) as never,
    });
    expect(result.status).toBe("degraded");
  });

  /**
   * The state model must be SATISFIABLE. `runtime_state: "enforcing"` is
   * documented in `castle-wall-daemon/src/daemon.rs` as never produced in this
   * slice, so requiring it made every healthy privileged host read degraded
   * forever. A live kernel runtime with the detector details confirmed is the
   * honest top of the reachable model.
   */
  it("accepts a live kernel runtime with no agent wrapped", () => {
    const result = evaluateCastleWall({
      ...base,
      statusResponse: status({
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "kernel_runtime_ready",
        kernel_runtime_ready: true,
        enforcing: false,
        runtime_health: "ready",
      }) as never,
    });
    expect(result.status).toBe("active");
  });

  it("still refuses to call a wall active while the operator bypass is engaged", () => {
    const result = evaluateCastleWall({
      ...base,
      statusResponse: status({
        no_wall_engaged: true,
        manifest_state: "ready" as const,
        lifecycle_state: "running",
        runtime_state: "enforcing",
        kernel_runtime_ready: true,
        enforcing: true,
        runtime_health: "ready",
      }) as never,
    });
    expect(result.status).toBe("degraded");
  });
});

describe("health/evidence : the mandatory audit-ACK confirmation gate", () => {
  const live = {
    platform: "linux" as const,
    configured: true as const,
    daemonUp: true as const,
    nftablesApplied: true as const,
    cgroupAttached: true as const,
    statusResponse: {
      uptime_seconds: 12,
      loaded_rule_count: 3,
      no_wall_engaged: false,
      loaded_manifest_signature_b64url: "sig",
      manifest_state: "ready" as const,
      lifecycle_state: "running",
      runtime_state: "kernel_runtime_ready",
      kernel_runtime_ready: true,
      enforcing: false,
      runtime_health: "ready",
    } as never,
  };

  /**
   * OWNER RULING (2026-09-02). This is the exact input that must NOT pass: a
   * perfectly live kernel runtime whose evidence channel cannot confirm that
   * reclaimed WAL ranges were actually truncated. Without the gate this reads
   * `active`, which is a complete-enforcement claim on unproven evidence.
   */
  it("degrades a LIVE runtime whose ACKs are unconfirmed", () => {
    expect(evaluateCastleWall({ ...live, evidenceChannel: "confirmed" }).status).toBe(
      "active"
    );
    const unconfirmed = evaluateCastleWall({ ...live, evidenceChannel: "unconfirmed_ack" });
    expect(unconfirmed.status).toBe("degraded");
    expect(unconfirmed.status).not.toBe("active");
    expect(unconfirmed.detector_evidence).toContain("audit_drain_ack_response");
  });

  it("degrades a LIVE runtime whose drain link has faulted", () => {
    const faulted = evaluateCastleWall({ ...live, evidenceChannel: "faulted" });
    expect(faulted.status).toBe("degraded");
    expect(faulted.detector_evidence).toContain("not reaching the consumer");
  });

  /**
   * The channel gate outranks the runtime block. An unconfirmed channel is a
   * POSITIVE fact (the peer did not advertise the capability), so reporting
   * `unknown` here would understate what we actually observed.
   */
  it("reports an unconfirmed channel as degraded even when the runtime is indeterminate", () => {
    const both = evaluateCastleWall({
      platform: "linux",
      configured: true,
      daemonUp: true,
      nftablesApplied: true,
      cgroupAttached: true,
      evidenceChannel: "unconfirmed_ack",
      statusResponse: {
        uptime_seconds: 1,
        loaded_rule_count: 0,
        no_wall_engaged: false,
        loaded_manifest_signature_b64url: null,
      } as never,
    });
    expect(both.status).toBe("degraded");
  });

  /**
   * Absence is NOT confirmation, but it is also not this field's business: the
   * macOS detector has no consumer-side drain channel at all, so an omitted
   * `evidenceChannel` must leave the existing verdict untouched rather than
   * degrading every non-Linux runtime.
   */
  it("leaves the verdict untouched when no drain channel is reported", () => {
    expect(evaluateCastleWall(live).status).toBe("active");
  });

  it("carries the degradation into the full health report", () => {
    const report = buildHealthEvidenceReport({
      config: defaultConfig(),
      identityCount: 0,
      storageBackendName: "FilesystemStorage",
      castleWall: { ...live, evidenceChannel: "unconfirmed_ack" },
    });
    expect(report.castle_wall.status).toBe("degraded");
    expect(report.egress.enforcement).toBe("degraded");
    expect(report.layers.l1.status).toBe("degraded");
    expect(
      report.degradations.some((d) => d.layer === "l1" && d.severity === "critical")
    ).toBe(true);
  });
});
