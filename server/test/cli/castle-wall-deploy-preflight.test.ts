import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runDeployPreflight,
  SYSEXT_REREGISTRATION_GUIDANCE,
  type CastleWallCommandContext,
} from "../../src/cli/castle-wall.js";

// Check-only preflight for the redeploy-without-re-activation skew (graph row
// defect.sysext-deactivation-extension-not-found): replacing the installed
// app at a different embedded-extension version than the OS activated record
// must be an explicit choice, never the silent default. The verb performs NO
// filesystem mutation (copying the bundle stays with the operator's own
// deploy tooling), and it is advisory-strict: only a POSITIVELY OBSERVED
// skew exits non-zero; an unreadable probe warns and exits 0, because
// deploying the app is not a security boundary.

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

interface PreflightHarness {
  ctx: CastleWallCommandContext;
  outText: () => string;
  errText: () => string;
}

function makeHarness(opts: {
  embedded: string | null;
  rawList: string | null;
}): PreflightHarness {
  const out = sink();
  const err = sink();
  return {
    ctx: {
      out: out.stream,
      err: err.stream,
      platform: "darwin",
      embeddedSysextVersionProbe: async () => opts.embedded,
      sysextListRawProbe: async () => opts.rawList,
    },
    outText: out.text,
    errText: err.text,
  };
}

describe("castle-wall deploy-preflight extension-version check", () => {
  let workDir: string | undefined;
  let sourceApp: string;
  let destApp: string;

  async function makeBundles(): Promise<void> {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-preflight-"));
    sourceApp = join(workDir, "incoming", "Sanctuary-CastleWall.app");
    // Never created: the verb must not require, read, or touch the
    // destination path; it only names it in the report.
    destApp = join(workDir, "Applications", "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
  }

  afterEach(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
    workDir = undefined;
  });

  it("exits 2 when the incoming embedded version skews from the activated record", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(2);
    expect(h.errText()).toContain("Extension-version skew");
    expect(h.errText()).toContain("1472");
    expect(h.errText()).toContain("1421");
    // The refusal names both supported orders and the explicit override.
    expect(h.errText()).toContain("--allow-extension-skew");
    expect(h.errText()).toContain("sanctuary uninstall");
  });

  it("exits 0 and reports the match when the incoming version matches the activated record", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.outText()).toContain("Preflight OK");
    expect(h.outText()).toContain("1472");
    expect(h.errText()).toBe("");
    // Check-only means check-only: the verb created nothing anywhere in the
    // work tree (in particular, no destination directory and no staging).
    expect(await readdir(workDir!)).toEqual(["incoming"]);
  });

  it("exits 0 and says so when the OS holds no activated Castle Wall record", async () => {
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
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.outText()).toContain("no activated Castle Wall system-extension record");
    expect(h.errText()).toBe("");
  });

  it("--allow-extension-skew exits 0 through a skew and prints what it overrode", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp, "--allow-extension-skew"],
      h.ctx,
    );
    expect(code).toBe(0);
    // The override must disclose the skew it is overriding, both versions
    // included, so the transcript stays truthful even under a scripted run.
    expect(h.errText()).toContain("Overriding");
    expect(h.errText()).toContain("1472");
    expect(h.errText()).toContain("1421");
  });

  it("warns and exits 0 when the activated-extension list is unreadable", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: null });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    // The warning names WHICH probe was unreadable.
    expect(h.errText()).toContain("Warning: could not read");
    expect(h.errText()).toContain("activated-extension list");
  });

  it("warns and exits 0 when the incoming bundle's embedded version is unreadable", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: null,
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.errText()).toContain("Warning: could not read");
    expect(h.errText()).toContain(sourceApp);
  });

  it("exits 2 on the inverse skew too: an activated record newer than the incoming app", async () => {
    await makeBundles();
    // Skew is skew in both directions: an OLDER incoming app under a NEWER
    // activated record strands the record just the same.
    const h = makeHarness({
      embedded: "1421",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(2);
    expect(h.errText()).toContain("Extension-version skew");
    expect(h.errText()).toContain("1421");
    expect(h.errText()).toContain("1472");
  });

  it("exits 0 when the incoming version matches ANY of several activated records", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421"), activatedRow("1472")].join(
        "\n",
      ),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.outText()).toContain("Preflight OK");
    expect(h.errText()).toBe("");
  });

  it("exits 2 and names every activated record when several exist and none matches", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1500",
      rawList: [LIST_HEADER, activatedRow("1421"), activatedRow("1430")].join(
        "\n",
      ),
    });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(2);
    expect(h.errText()).toContain("1421");
    expect(h.errText()).toContain("1430");
  });

  it("re-registration orders are the imported #1323 guidance constant, verbatim", async () => {
    // The guidance is asserted through the IMPORTED constant only (never
    // restated here), so this test pins surface-to-constant wiring while the
    // constant's own doc pins the cross-language Swift twin.
    await makeBundles();
    const refusal = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    expect(
      await runDeployPreflight(["--app", sourceApp, "--dest", destApp], refusal.ctx),
    ).toBe(2);
    expect(refusal.errText()).toContain(SYSEXT_REREGISTRATION_GUIDANCE);
    const override = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421")].join("\n"),
    });
    expect(
      await runDeployPreflight(
        ["--app", sourceApp, "--dest", destApp, "--allow-extension-skew"],
        override.ctx,
      ),
    ).toBe(0);
    expect(override.errText()).toContain(SYSEXT_REREGISTRATION_GUIDANCE);
  });

  it("requires --app and refuses a value-less --dest as usage errors", async () => {
    await makeBundles();
    const missingApp = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    expect(await runDeployPreflight(["--dest", destApp], missingApp.ctx)).toBe(2);
    expect(missingApp.errText()).toContain("Usage:");
    // --dest with no value rides the shared consumeFlagValue chokepoint: it
    // must refuse loudly, never silently check against the default path.
    const danglingDest = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    expect(
      await runDeployPreflight(["--app", sourceApp, "--dest"], danglingDest.ctx),
    ).toBe(2);
  });

  it("exits 2 when --app names no bundle on disk (never a mere warning)", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    const code = await runDeployPreflight(
      ["--app", join(workDir!, "missing.app"), "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(2);
    expect(h.errText()).toContain("no app bundle at");
  });

  it("is macOS-only", async () => {
    await makeBundles();
    const h = makeHarness({ embedded: "1472", rawList: LIST_HEADER });
    const code = await runDeployPreflight(
      ["--app", sourceApp, "--dest", destApp],
      { ...h.ctx, platform: "linux" },
    );
    expect(code).toBe(2);
    expect(h.errText()).toContain("macOS-only");
  });
});
