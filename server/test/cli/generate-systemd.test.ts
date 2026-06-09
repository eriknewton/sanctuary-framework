import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import {
  renderSystemdUnit,
  runGenerateCommand,
} from "../../src/cli/generate.js";

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

describe("sanctuary generate systemd", () => {
  it("renders deterministic unit content", () => {
    const unit = renderSystemdUnit({
      user: "svc-sanctuary",
      stateDir: "/var/lib/sanctuary",
      binary: "/usr/local/bin/sanctuary",
      platform: "linux",
    });
    expect(unit).toContain("sudo systemctl enable --now sanctuary.service");
    expect(unit).toContain("User=svc-sanctuary");
    expect(unit).toContain("Environment=SANCTUARY_STORAGE_PATH=/var/lib/sanctuary");
    expect(unit).toContain("ExecStart=/usr/local/bin/sanctuary dashboard --no-confirm");
  });

  it("notes macOS context but still emits Linux unit", () => {
    const unit = renderSystemdUnit({
      user: "erik",
      stateDir: "~/.sanctuary",
      binary: "/usr/local/bin/sanctuary",
      platform: "darwin",
    });
    expect(unit).toContain("this host is macOS");
    expect(unit).toContain("[Unit]");
  });

  it("supports CLI flags", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({
      argv: [
        "systemd",
        "--user",
        "svc",
        "--state-dir",
        "/srv/sanctuary",
        "--binary",
        "/opt/bin/sanctuary",
      ],
      out,
      platform: "linux",
      currentUser: "ignored",
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("User=svc");
    expect(out.text()).toContain("SANCTUARY_STORAGE_PATH=/srv/sanctuary");
    expect(out.text()).toContain("ExecStart=/opt/bin/sanctuary dashboard --no-confirm");
  });

  it("rejects unknown generate subcommands", async () => {
    const err = new Capture();
    const code = await runGenerateCommand({ argv: ["launchd"], err });
    expect(code).toBe(2);
    expect(err.text()).toContain("Unknown generate command: launchd");
  });

  it("prints systemd help without templating", async () => {
    const out = new Capture();
    const code = await runGenerateCommand({ argv: ["systemd", "--help"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("Usage: sanctuary generate systemd");
    expect(out.text()).not.toContain("[Service]");
  });
});
