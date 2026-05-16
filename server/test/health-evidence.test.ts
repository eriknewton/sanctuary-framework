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
        loaded_manifest_signature_b64url: "sig",
      },
    });

    expect(status.status).toBe("degraded");
    expect(status.detector_evidence).toContain("nftables rules not applied");
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
});
