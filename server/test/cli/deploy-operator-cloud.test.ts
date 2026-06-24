import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";

import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli.js";
import {
  renderOperatorCloudPlan,
  runDeployCommand,
} from "../../src/cli/deploy.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const FORBIDDEN_MATERIAL_PATTERNS = [
  /master_secret/i,
  /master_private_key/i,
  /issuing_principal_private_key/i,
  /private_key/i,
  /SANCTUARY_PASSPHRASE/,
  /SANCTUARY_RECOVERY_KEY/,
  /recovery_key/i,
  /passphrase/i,
];

describe("sanctuary deploy operator-cloud plan", () => {
  it("is a top-level CLI surface", () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("deploy");
  });

  it("renders disclosure plus cloud-init and systemd skeletons without custody material", () => {
    const plan = renderOperatorCloudPlan({
      provider: "generic-ssh",
      label: "cloud-1",
      region: "us-test-1",
      serviceUser: "svc-sanctuary",
      stateDir: "/srv/sanctuary",
      installDir: "/opt/sanctuary",
      binary: "/usr/local/bin/sanctuary",
    });

    expect(plan).toContain("schema_version: operator-cloud-deploy-plan-v1");
    expect(plan).toContain("node_mode: operator_cloud");
    expect(plan).toContain("trust_boundary: provider in trust boundary, not TEE");
    expect(plan).toContain("tee_attested: false");
    expect(plan).toContain("drill_status: unproven");
    expect(plan).toContain("cloud_init:");
    expect(plan).toContain("systemd_unit:");
    expect(plan).toContain("Environment=SANCTUARY_STORAGE_PATH=/srv/sanctuary");
    expect(plan).toContain("ExecStart=/usr/local/bin/sanctuary dashboard --host 0.0.0.0 --no-confirm");
    for (const pattern of FORBIDDEN_MATERIAL_PATTERNS) {
      expect(plan).not.toMatch(pattern);
    }
  });

  it("supports CLI flags", async () => {
    const out = new Capture();
    const code = await runDeployCommand({
      argv: [
        "operator-cloud",
        "plan",
        "--provider",
        "generic-ssh",
        "--label",
        "cloud-2",
        "--region",
        "region-a",
        "--user",
        "svc",
        "--state-dir",
        "/var/lib/sanctuary-cloud",
        "--install-dir",
        "/opt/sanctuary-cloud",
        "--binary",
        "/opt/bin/sanctuary",
      ],
      out,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("label: cloud-2");
    expect(out.text()).toContain("region: region-a");
    expect(out.text()).toContain("User=svc");
    expect(out.text()).toContain("WorkingDirectory=/opt/sanctuary-cloud");
    expect(out.text()).toContain("SANCTUARY_STORAGE_PATH=/var/lib/sanctuary-cloud");
  });

  it("prints operator-cloud plan help without rendering a unit", async () => {
    const out = new Capture();
    const code = await runDeployCommand({
      argv: ["operator-cloud", "plan", "--help"],
      out,
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary deploy operator-cloud plan");
    expect(out.text()).not.toContain("[Service]");
  });
});
