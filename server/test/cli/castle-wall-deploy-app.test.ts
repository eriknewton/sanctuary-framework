import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runDeployApp,
  type CastleWallCommandContext,
} from "../../src/cli/castle-wall.js";

// Deploy-time tripwire for the redeploy-without-re-activation skew (graph row
// defect.sysext-deactivation-extension-not-found): replacing the installed
// app at a different embedded-extension version than the OS activated record
// must be an explicit choice, never the silent default. The tripwire is
// advisory-strict: only a POSITIVELY OBSERVED skew refuses; unreadable
// probes warn and proceed, because deploy is not a security boundary.

function sink(): { stream: Writable; text: () => string } {
  let buffer = "";
  const stream = new Writable({
    write(chunk, _enc, cb) {
      buffer += String(chunk);
      cb();
    },
  });
  return { stream, text: () => buffer };
}

// Real-shaped `systemextensionsctl list` rows (tab-separated columns; must
// stay in the shape parseActivatedCastleWallBundleVersions parses).
const LIST_HEADER = "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]";
function activatedRow(version: string): string {
  return `*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/${version})\tCastle Wall\t[activated enabled]`;
}

interface DeployHarness {
  ctx: CastleWallCommandContext;
  outText: () => string;
  errText: () => string;
  copyCalls: Array<{ sourceApp: string; destApp: string }>;
}

function makeHarness(opts: {
  embedded: string | null;
  rawList: string | null;
  copyCode?: number;
  copyStderr?: string;
}): DeployHarness {
  const out = sink();
  const err = sink();
  const copyCalls: Array<{ sourceApp: string; destApp: string }> = [];
  return {
    ctx: {
      out: out.stream,
      err: err.stream,
      platform: "darwin",
      embeddedSysextVersionProbe: async () => opts.embedded,
      sysextListRawProbe: async () => opts.rawList,
      deployAppCopyRunner: async (sourceApp, destApp) => {
        copyCalls.push({ sourceApp, destApp });
        return { code: opts.copyCode ?? 0, stderr: opts.copyStderr ?? "" };
      },
    },
    outText: out.text,
    errText: err.text,
    copyCalls,
  };
}

describe("castle-wall deploy-app extension-version tripwire", () => {
  let workDir: string | undefined;
  let sourceApp: string;
  let destApp: string;

  async function makeBundles(): Promise<void> {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-app-"));
    sourceApp = join(workDir, "incoming", "Sanctuary-CastleWall.app");
    destApp = join(workDir, "Applications", "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
  }

  afterEach(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
    workDir = undefined;
  });

  it("refuses to overwrite when the incoming embedded version skews from the activated record", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    // Refusing means refusing: the copy step must never have been reached.
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("Refusing to replace");
    expect(h.errText()).toContain("1472");
    expect(h.errText()).toContain("1421");
    // The refusal names both supported orders and the explicit override.
    expect(h.errText()).toContain("--allow-extension-skew");
    expect(h.errText()).toContain("sanctuary uninstall");
  });

  it("deploys when the incoming embedded version matches an activated record", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    expect(h.errText()).not.toContain("Refusing");
    expect(h.errText()).not.toContain("Warning");
  });

  it("deploys when the OS holds no activated Castle Wall record", async () => {
    await makeBundles();
    // Parseable list output with no Castle Wall row (foreign team): a fresh
    // machine, not an unreadable probe, so no warning is emitted.
    const h = makeHarness({
      embedded: "1472",
      rawList: [
        LIST_HEADER,
        "*\t*\tOTHERTEAM99\tcom.example.other (1.0/7)\tOther\t[activated enabled]",
      ].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    expect(h.errText()).toBe("");
  });

  it("--allow-extension-skew deploys through a skew and prints what it overrode", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp, "--allow-extension-skew"],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    // The override must disclose the skew it is overriding, both versions
    // included, so the transcript stays truthful even under a scripted run.
    expect(h.errText()).toContain("Overriding");
    expect(h.errText()).toContain("1472");
    expect(h.errText()).toContain("1421");
  });

  it("warns and proceeds when the activated-extension list is unreadable", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: null });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    expect(h.errText()).toContain("Warning: could not read");
    expect(h.errText()).toContain("activated-extension list");
  });

  it("warns and proceeds when the incoming bundle's embedded version is unreadable", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: null,
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    expect(h.errText()).toContain("Warning: could not read");
    expect(h.errText()).toContain(sourceApp);
  });

  it("surfaces a copy failure as a non-zero exit", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
      copyCode: 1,
      copyStderr: "disk full",
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    expect(h.errText()).toContain("deploy copy failed");
    expect(h.errText()).toContain("disk full");
  });

  it("requires --app and never copies on a usage error", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    const code = await runDeployApp(["--dest", destApp], h.ctx);
    expect(code).toBe(2);
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("Usage:");
  });

  it("refuses a --dest that does not name a .app bundle", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", join(workDir!, "Applications")],
      h.ctx,
    );
    expect(code).toBe(2);
    // The default copy runner removes the destination before copying, so a
    // non-.app destination must be rejected before any copy runner runs.
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain(".app");
  });

  it("is macOS-only", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      { ...h.ctx, platform: "linux" },
    );
    expect(code).toBe(2);
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("macOS-only");
  });
});
