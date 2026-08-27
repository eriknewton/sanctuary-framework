import { afterEach, describe, expect, it } from "vitest";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runDeployApp,
  stageAndSwapDeployAppCopy,
  type CastleWallCommandContext,
  type DeployAppCopyResult,
} from "../../src/cli/castle-wall.js";

// Attended re-registration guidance (merged #1323). Pinned verbatim here so a
// drift in ANY of the three deploy-app surfaces (refusal, override, success)
// or the deactivation notice fails a test, not a drill: must match
// SYSEXT_REREGISTRATION_GUIDANCE in src/cli/castle-wall.ts, which itself pins
// HeadlessFilterCLI.swift and src/cli/uninstall.ts.
const REREGISTRATION_GUIDANCE =
  "launch Sanctuary-CastleWall.app at the console so its activation flow " +
  "re-registers the extension, approve or re-enable the Sanctuary " +
  "background helper if macOS prompts for it, wait for re-registration to " +
  "complete";

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
  copyPreviousInstall?: DeployAppCopyResult["previousInstall"];
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
        return {
          code: opts.copyCode ?? 0,
          stderr: opts.copyStderr ?? "",
          ...(opts.copyPreviousInstall !== undefined
            ? { previousInstall: opts.copyPreviousInstall }
            : {}),
        };
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
    // The re-registration order must be the #1323 guidance verbatim, never a
    // paraphrase that omits the helper approval and the wait.
    expect(h.errText()).toContain(REREGISTRATION_GUIDANCE);
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
    // The success text's follow-up order is the #1323 guidance verbatim.
    expect(h.outText()).toContain(REREGISTRATION_GUIDANCE);
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
    // The override's re-registration order is the #1323 guidance verbatim.
    expect(h.errText()).toContain(REREGISTRATION_GUIDANCE);
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

  it("surfaces a copy failure as a non-zero exit and discloses the previous install's state", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
      copyCode: 1,
      copyStderr: "disk full",
      copyPreviousInstall: "intact",
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    expect(h.errText()).toContain("deploy copy failed");
    expect(h.errText()).toContain("disk full");
    expect(h.errText()).toContain(`bundle at ${destApp} is intact`);
  });

  it("a failure that lost the previous install says so in the error", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
      copyCode: 1,
      copyStderr: "rename failed",
      copyPreviousInstall: "gone",
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    // The worst outcome must be the loudest: the operator learns from the
    // error itself that no app is installed at the destination now.
    expect(h.errText()).toContain("could NOT be restored");
    expect(h.errText()).toContain("no app is installed there now");
  });

  it("a successful swap with a leftover surfaces the runner's note as a warning", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
      copyCode: 0,
      copyStderr: "deployed, but could not remove the superseded bundle",
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.errText()).toContain("Warning:");
    expect(h.errText()).toContain("superseded bundle");
    expect(h.outText()).toContain("Deployed");
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

  it("refuses the inverse skew too: an activated record newer than the incoming app", async () => {
    await makeBundles();
    // Skew is skew in both directions: deploying an OLDER app under a NEWER
    // activated record strands the record just the same.
    const h = makeHarness({
      embedded: "1421",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("Refusing to replace");
    expect(h.errText()).toContain("1421");
    expect(h.errText()).toContain("1472");
  });

  it("deploys when the incoming version matches ANY of several activated records", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1421"), activatedRow("1472")].join(
        "\n",
      ),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
    expect(h.errText()).not.toContain("Refusing");
  });

  it("refuses and names every activated record when several exist and none matches", async () => {
    await makeBundles();
    const h = makeHarness({
      embedded: "1500",
      rawList: [LIST_HEADER, activatedRow("1421"), activatedRow("1430")].join(
        "\n",
      ),
    });
    const code = await runDeployApp(
      ["--app", sourceApp, "--dest", destApp],
      h.ctx,
    );
    expect(code).toBe(1);
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("1421");
    expect(h.errText()).toContain("1430");
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

describe("castle-wall deploy-app destination aliasing refusal", () => {
  // The copy runner renames the destination aside and deletes it, so a
  // destination that IS the source (or contains it, or is contained by it,
  // through any symlink spelling) would destroy the source before it could
  // be copied. Every case here must be refused BEFORE any copy runner runs.
  let workDir: string | undefined;

  afterEach(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
    workDir = undefined;
  });

  function aliasHarness(): DeployHarness {
    // Probes report a clean match so only the alias check can refuse.
    return makeHarness({
      embedded: "1472",
      rawList: [LIST_HEADER, activatedRow("1472")].join("\n"),
    });
  }

  async function expectAliasRefusal(
    h: DeployHarness,
    argv: string[],
  ): Promise<void> {
    const code = await runDeployApp(argv, h.ctx);
    expect(code).toBe(2);
    expect(h.copyCalls).toEqual([]);
    expect(h.errText()).toContain("not disjoint with the source bundle");
  }

  it("refuses --dest equal to --app", async () => {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-alias-"));
    const sourceApp = join(workDir, "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    await expectAliasRefusal(aliasHarness(), [
      "--app",
      sourceApp,
      "--dest",
      sourceApp,
    ]);
  });

  it("refuses a --dest inside the source bundle", async () => {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-alias-"));
    const sourceApp = join(workDir, "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    await expectAliasRefusal(aliasHarness(), [
      "--app",
      sourceApp,
      "--dest",
      join(sourceApp, "Contents", "Nested.app"),
    ]);
  });

  it("refuses a --dest that contains the source bundle", async () => {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-alias-"));
    const outerApp = join(workDir, "Outer.app");
    const sourceApp = join(outerApp, "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    await expectAliasRefusal(aliasHarness(), [
      "--app",
      sourceApp,
      "--dest",
      outerApp,
    ]);
  });

  it("refuses a --dest that aliases the source through a symlinked parent", async () => {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-alias-"));
    const incoming = join(workDir, "incoming");
    const sourceApp = join(incoming, "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    // The alias hides in an EXISTING component: link/... resolves back into
    // incoming/..., so the literal strings differ while the bundles are one.
    const link = join(workDir, "link");
    await symlink(incoming, link);
    await expectAliasRefusal(aliasHarness(), [
      "--app",
      sourceApp,
      "--dest",
      join(link, "Sanctuary-CastleWall.app"),
    ]);
  });

  it("allows a disjoint sibling destination through the same checks", async () => {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-alias-"));
    const sourceApp = join(workDir, "incoming", "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    const h = aliasHarness();
    const destApp = join(workDir, "Applications", "Sanctuary-CastleWall.app");
    const code = await runDeployApp(["--app", sourceApp, "--dest", destApp], h.ctx);
    expect(code).toBe(0);
    expect(h.copyCalls).toEqual([{ sourceApp, destApp }]);
  });
});

// ---------------------------------------------------------------------------
// The REAL runner: stat, staging, swap, rollback, and cleanup sequencing,
// with only the subprocess seam faked. The fake EXECUTES rm/mv/ditto against
// the real temp filesystem (with injectable per-call failures), so what
// these tests prove is the runner's ordering and its truthful
// previousInstall reporting, not a mock's echo.
// ---------------------------------------------------------------------------

type SubprocessCall = { command: string; args: string[] };

function makeFakeSubprocess(
  failWhen?: (call: SubprocessCall, index: number) => boolean,
) {
  const calls: SubprocessCall[] = [];
  const run = async (
    command: string,
    args: string[],
    _timeoutMs: number,
  ): Promise<{ code: number; stderr: string }> => {
    const call = { command, args };
    calls.push(call);
    if (failWhen?.(call, calls.length - 1)) {
      return { code: 1, stderr: `injected failure: ${command} ${args.join(" ")}` };
    }
    if (command === "/bin/rm") {
      await rm(args[args.length - 1]!, { recursive: true, force: true });
      return { code: 0, stderr: "" };
    }
    if (command === "/bin/mv") {
      await rename(args[0]!, args[1]!);
      return { code: 0, stderr: "" };
    }
    if (command === "/usr/bin/ditto") {
      await cp(args[0]!, args[1]!, { recursive: true });
      return { code: 0, stderr: "" };
    }
    throw new Error(`fake subprocess: unexpected command ${command}`);
  };
  return { run, calls };
}

const isMv = (c: SubprocessCall) => c.command === "/bin/mv";
const mvTo = (dest: string) => (c: SubprocessCall) =>
  isMv(c) && c.args[1] === dest;

describe("stageAndSwapDeployAppCopy staging, swap, and rollback", () => {
  let workDir: string | undefined;
  let sourceApp: string;
  let destDir: string;
  let destApp: string;

  async function makeInstall(opts: { destExists: boolean }): Promise<void> {
    workDir = await mkdtemp(join(tmpdir(), "cw-deploy-swap-"));
    sourceApp = join(workDir, "incoming", "Sanctuary-CastleWall.app");
    destDir = join(workDir, "Applications");
    destApp = join(destDir, "Sanctuary-CastleWall.app");
    await mkdir(sourceApp, { recursive: true });
    await writeFile(join(sourceApp, "marker.txt"), "new-version");
    await mkdir(destDir, { recursive: true });
    if (opts.destExists) {
      await mkdir(destApp, { recursive: true });
      await writeFile(join(destApp, "marker.txt"), "old-version");
    }
  }

  afterEach(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
    workDir = undefined;
  });

  async function marker(appPath: string): Promise<string> {
    return readFile(join(appPath, "marker.txt"), "utf8");
  }

  async function residue(): Promise<string[]> {
    // Any .sanctuary-deploy-* entry left in the destination parent is a
    // strand; success and every failure path must leave zero.
    return (await readdir(destDir)).filter((name) =>
      name.startsWith(".sanctuary-deploy-"),
    );
  }

  it("replaces an existing install and leaves no staging or aside residue", async () => {
    await makeInstall({ destExists: true });
    const fake = makeFakeSubprocess();
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(await marker(destApp)).toBe("new-version");
    expect(await residue()).toEqual([]);
    // The source itself must be untouched by a deploy.
    expect(await marker(sourceApp)).toBe("new-version");
  });

  it("installs fresh when no previous bundle exists", async () => {
    await makeInstall({ destExists: false });
    const fake = makeFakeSubprocess();
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).toBe(0);
    expect(await marker(destApp)).toBe("new-version");
    expect(await residue()).toEqual([]);
  });

  it("a copy (staging) failure leaves the previous install intact and cleans staging", async () => {
    await makeInstall({ destExists: true });
    const fake = makeFakeSubprocess((c) => c.command === "/usr/bin/ditto");
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).not.toBe(0);
    expect(result.previousInstall).toBe("intact");
    // The previous install was never touched: same bundle, same content.
    expect(await marker(destApp)).toBe("old-version");
    expect(await residue()).toEqual([]);
  });

  it("a swap-in failure restores the old bundle by renaming it back", async () => {
    await makeInstall({ destExists: true });
    // Fail only the swap-in mv (its SOURCE is the staging bundle); the
    // move-aside and the restore (aside -> dest) run for real.
    const fake = makeFakeSubprocess(
      (c) => isMv(c) && (c.args[0] ?? "").includes("-staging-"),
    );
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).not.toBe(0);
    expect(result.previousInstall).toBe("restored");
    expect(await marker(destApp)).toBe("old-version");
    expect(await residue()).toEqual([]);
  });

  it("a swap-in failure whose restore also fails reports the install gone", async () => {
    await makeInstall({ destExists: true });
    let mvCount = 0;
    const fake = makeFakeSubprocess((c) => {
      if (!isMv(c)) return false;
      mvCount += 1;
      // First mv (dest -> aside) succeeds; the swap-in AND the restore fail.
      return mvCount >= 2;
    });
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).not.toBe(0);
    expect(result.previousInstall).toBe("gone");
    expect(result.stderr).toContain("also failed");
  });

  it("a move-aside failure leaves the previous install intact and cleans staging", async () => {
    await makeInstall({ destExists: true });
    const fake = makeFakeSubprocess((c) => isMv(c) && c.args[0] === destApp);
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).not.toBe(0);
    expect(result.previousInstall).toBe("intact");
    expect(await marker(destApp)).toBe("old-version");
    expect(await residue()).toEqual([]);
  });

  it("a fresh-install swap failure reports that no previous install existed", async () => {
    await makeInstall({ destExists: false });
    const fake = makeFakeSubprocess(mvTo(destApp));
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    expect(result.code).not.toBe(0);
    expect(result.previousInstall).toBe("none");
    expect(await residue()).toEqual([]);
  });

  it("a failed aside cleanup after a successful swap is a success with a loud leftover", async () => {
    await makeInstall({ destExists: true });
    const fake = makeFakeSubprocess(
      (c) => c.command === "/bin/rm" && (c.args[1] ?? "").includes("-old-"),
    );
    const result = await stageAndSwapDeployAppCopy(sourceApp, destApp, fake.run);
    // The new bundle IS in place; the leftover is disclosed, not escalated
    // into a failure of a completed deploy.
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("remove it manually");
    expect(await marker(destApp)).toBe("new-version");
  });
});
