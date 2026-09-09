import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { buildHealthEvidenceReport } from "../src/health/evidence.js";
import {
  getMcpSdkVersion,
  getSanctuaryVersion,
  packageVersion,
} from "../src/version.js";

describe("attestation evidence", () => {
  it("reports the Sanctuary version from server package.json", () => {
    const pkg = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8")
    ) as { version: string };

    expect(getSanctuaryVersion()).toBe(pkg.version);
    expect(packageVersion({ version: "9.9.9-test" }, "fixture")).toBe("9.9.9-test");
  });

  it("reports the installed MCP SDK version from its package.json", () => {
    const pkg = JSON.parse(
      readFileSync(
        join(process.cwd(), "node_modules", "@modelcontextprotocol", "sdk", "package.json"),
        "utf8"
      )
    ) as { version: string };

    expect(getMcpSdkVersion()).toBe(pkg.version);
    expect(getMcpSdkVersion()).not.toBe("1.26.0");
  });

  it("uses dynamic versions in the attestation evidence report", () => {
    const serverPkg = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8")
    ) as { version: string };
    const sdkPkg = JSON.parse(
      readFileSync(
        join(process.cwd(), "node_modules", "@modelcontextprotocol", "sdk", "package.json"),
        "utf8"
      )
    ) as { version: string };

    const report = buildHealthEvidenceReport({
      config: defaultConfig(),
      identityCount: 1,
      storageBackendName: "FilesystemStorage",
      castleWall: {
        platform: "linux",
        configured: true,
        daemonUp: true,
        nftablesApplied: true,
        cgroupAttached: true,
        statusResponse: {
          uptime_seconds: 10,
          loaded_rule_count: 2,
          no_wall_engaged: false,
          manifest_state: "ready" as const,
          lifecycle_state: "running",
          runtime_state: "enforcing",
          kernel_runtime_ready: true,
          enforcing: true,
          loaded_manifest_signature_b64url: "sig",
        },
      },
    });

    expect(report.sanctuary_version).toBe(serverPkg.version);
    expect(report.mcp_sdk_version).toBe(sdkPkg.version);
    expect(report.castle_wall.status).toBe("active");
    expect(report.egress.enforcement).toBe("active");
  });
});
