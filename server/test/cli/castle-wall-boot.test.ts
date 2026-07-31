import { afterEach, describe, expect, it } from "vitest";
import { access, lstat, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  CASTLE_WALL_BOOT_LABEL,
  bootServiceEnabled,
  bootServiceInstalled,
  bootServiceLoaded,
  bootServicePlistPresent,
  bootServiceReady,
  deriveHomebrewStableBinDir,
  parseBootArgs,
  renderBootLaunchDaemonPlist,
  runInstallBoot,
  runProvisionBootToken,
  runUninstallBoot,
  type CastleWallBootContext,
  type ExecFileResult,
} from "../../src/cli/castle-wall-boot.js";
import {
  deriveSafeModeAuditKey,
  readBootToken,
  safeModeAuditStoragePath,
} from "../../src/castle-wall/boot/boot-token.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const TEST_OPERATOR_UID = String(process.getuid?.() ?? 501);
const TEST_OPERATOR_GID = String(process.getgid?.() ?? 20);

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

interface FakeLaunchctl {
  calls: Array<{ cmd: string; args: string[] }>;
  /** Models a live, running launchd job (a `pid = N` line in `print`). */
  running: boolean;
  /** Models a launchctl disabled override in `print-disabled system`. */
  disabled: boolean;
  execFileFn: (cmd: string, args: string[]) => ExecFileResult;
}

function makeFakeExec(opts: { home?: string; fortress?: string } = {}): FakeLaunchctl {
  const state: FakeLaunchctl = {
    calls: [],
    running: false,
    disabled: false,
    execFileFn: (cmd: string, args: string[]): ExecFileResult => {
      state.calls.push({ cmd, args });
      if (cmd === "dscl") {
        return {
          code: 0,
          stdout: `NFSHomeDirectory: ${opts.home ?? "/Users/operator"}\n`,
          stderr: "",
        };
      }
      if (cmd === "chown") {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (cmd === "launchctl") {
        const verb = args[0];
        if (verb === "print-disabled") {
          return {
            code: 0,
            stdout: `disabled services = {\n\t"${CASTLE_WALL_BOOT_LABEL}" => ${state.disabled ? "disabled" : "enabled"}\n}\n`,
            stderr: "",
          };
        }
        if (verb === "print") {
          return state.running
            ? {
                code: 0,
                stdout:
                  "\tstate = running\n" +
                  "\tpid = 4242\n" +
                  "\tenvironment = {\n" +
                  `\t\tSANCTUARY_STORAGE_PATH => ${opts.fortress ?? "/Users/operator/.sanctuary"}\n` +
                  "\t}\n",
                stderr: "",
              }
            : { code: 113, stdout: "", stderr: "Could not find service" };
        }
        if (verb === "bootstrap") {
          state.running = true;
          return { code: 0, stdout: "", stderr: "" };
        }
        if (verb === "bootout") {
          const was = state.running;
          state.running = false;
          return was
            ? { code: 0, stdout: "", stderr: "" }
            : { code: 113, stdout: "", stderr: "No such process" };
        }
        if (verb === "enable") {
          state.disabled = false;
          return { code: 0, stdout: "", stderr: "" };
        }
      }
      return { code: 1, stdout: "", stderr: `unexpected command: ${cmd}` };
    },
  };
  return state;
}

describe("castle-wall boot service (F1 Option C)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeTemp(prefix: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  async function fileExists(path: string): Promise<boolean> {
    try {
      await access(path);
      return true;
    } catch {
      return false;
    }
  }

  // ── Plist rendering (pure, safe-mode root service) ─────────────────

  describe("renderBootLaunchDaemonPlist", () => {
    const base = {
      programArguments: [
        "/usr/local/bin/node",
        "/opt/sanctuary/dist/cli.js",
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
      fortressPath: "/Users/operator/.sanctuary",
      signerClientPath:
        "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client",
    };

    it("renders a root safe-mode plist with the expected keys and no secrets", () => {
      const plist = renderBootLaunchDaemonPlist(base);
      expect(plist).toContain(`<string>${CASTLE_WALL_BOOT_LABEL}</string>`);
      expect(plist).toContain("<key>RunAtLoad</key>");
      expect(plist).toContain("<key>KeepAlive</key>");
      expect(plist).toContain("<key>SANCTUARY_STORAGE_PATH</key>");
      expect(plist).toContain("<string>/Users/operator/.sanctuary</string>");
      expect(plist).toContain("<key>SANCTUARY_CASTLE_SIGNER_CLIENT</key>");
      expect(plist).toContain("<string>--safe-mode</string>");
      expect(plist).toContain("castle-wall-daemon.log");
      // Runs as root (system domain): NO UserName key.
      expect(plist).not.toContain("<key>UserName</key>");
      // The plist is world-readable; secrets must never appear.
      expect(plist).not.toContain("SANCTUARY_PASSPHRASE");
      expect(plist).not.toContain("SANCTUARY_RECOVERY_KEY");
      expect(plist).not.toContain("SANCTUARY_CASTLE_LOCAL_SIGN");
    });

    it("prepends the node interpreter dir to the daemon PATH (env-shebang shim resolves node)", () => {
      // The 2026-06-14 drill brick: launchd's minimal PATH excludes Homebrew's
      // /opt/homebrew/bin, so a `#!/usr/bin/env node` shim crash-loops with
      // `env: node: No such file or directory`. The fix puts node's dir on PATH.
      const plist = renderBootLaunchDaemonPlist({ ...base, nodeBinDir: "/opt/homebrew/bin" });
      expect(plist).toContain("<key>PATH</key>");
      expect(plist).toContain(
        "<string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>",
      );
    });

    it("does not duplicate a standard dir already on PATH, and rejects a relative node dir", () => {
      const plist = renderBootLaunchDaemonPlist({ ...base, nodeBinDir: "/usr/bin" });
      expect(plist).toContain("<string>/usr/bin:/bin:/usr/sbin:/sbin</string>");
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, nodeBinDir: "opt/homebrew/bin" }),
      ).toThrow(/absolute/);
    });

    it("also prepends the stable symlink dir behind the interpreter dir (#450 item 2: brew-upgrade durability)", () => {
      // nodeBinDir is the version-pinned Cellar keg (vanishes on `brew upgrade
      // node`); stableBinDir is the prefix symlink dir that survives the upgrade.
      // Both must be on PATH, with the exact interpreter first.
      const plist = renderBootLaunchDaemonPlist({
        ...base,
        nodeBinDir: "/opt/homebrew/Cellar/node/25.8.2/bin",
        stableBinDir: "/opt/homebrew/bin",
      });
      expect(plist).toContain(
        "<string>/opt/homebrew/Cellar/node/25.8.2/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>",
      );
    });

    it("dedupes the stable dir against the interpreter dir and rejects a relative stable dir", () => {
      // If both resolve to the same dir, it appears once.
      const plist = renderBootLaunchDaemonPlist({
        ...base,
        nodeBinDir: "/opt/homebrew/bin",
        stableBinDir: "/opt/homebrew/bin",
      });
      expect(plist).toContain(
        "<string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>",
      );
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, stableBinDir: "opt/homebrew/bin" }),
      ).toThrow(/absolute/);
    });

    it("XML-escapes paths with special characters", () => {
      const plist = renderBootLaunchDaemonPlist({
        ...base,
        fortressPath: `/tmp/we&ird <dir> "quoted" 'apos'`,
      });
      expect(plist).toContain("/tmp/we&amp;ird &lt;dir&gt; &quot;quoted&quot; &apos;apos&apos;");
      expect(plist).not.toContain(`we&ird`);
    });

    it("rejects a program argv that omits --safe-mode", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({
          ...base,
          programArguments: ["/usr/local/bin/node", "/x/cli.js", "castle-wall", "daemon"],
        }),
      ).toThrow(/safe-mode/);
    });

    it("rejects a relative program path", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({
          ...base,
          programArguments: ["node", "cli.js", "--safe-mode"],
        }),
      ).toThrow(/absolute/);
    });

    it("rejects empty programArguments", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, programArguments: [] }),
      ).toThrow(/empty/);
    });

    it("rejects a relative fortress path", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, fortressPath: "relative/.sanctuary" }),
      ).toThrow(/absolute/);
    });

    it("rejects a credentialed URL-shaped env value in the world-readable plist", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({
          ...base,
          fortressPath: "/tmp/http://sanctuary-gate:7.deadbeef@127.0.0.1",
        }),
      ).toThrow(/SANCTUARY_STORAGE_PATH value containing URL credentials/);
    });

    it("rejects a credentialed URL-shaped ProgramArgument in the world-readable plist", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({
          ...base,
          programArguments: [
            ...base.programArguments,
            "http://sanctuary-gate:7.deadbeef@127.0.0.1:49152",
          ],
        }),
      ).toThrow(/program argument value containing URL credentials/);
    });

    it("rejects a missing or relative signer client path", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, signerClientPath: "" }),
      ).toThrow(/signer/i);
      expect(() =>
        renderBootLaunchDaemonPlist({ ...base, signerClientPath: "shim" }),
      ).toThrow(/absolute/);
    });

    it("rejects control characters in arguments (plist injection)", () => {
      expect(() =>
        renderBootLaunchDaemonPlist({
          ...base,
          programArguments: ["/usr/bin/x", "--safe-mode", "a\nb"],
        }),
      ).toThrow(/control characters/);
    });
  });

  describe("deriveHomebrewStableBinDir (#450 item 2)", () => {
    it("maps a Cellar keg interpreter to the prefix's stable bin dir", () => {
      expect(
        deriveHomebrewStableBinDir("/opt/homebrew/Cellar/node/25.8.2/bin/node"),
      ).toBe("/opt/homebrew/bin");
      expect(
        deriveHomebrewStableBinDir("/usr/local/Cellar/node/24.0.0/bin/node"),
      ).toBe("/usr/local/bin");
    });

    it("returns null for non-Cellar interpreters (system node, nvm, already-stable)", () => {
      expect(deriveHomebrewStableBinDir("/usr/bin/node")).toBeNull();
      expect(deriveHomebrewStableBinDir("/opt/homebrew/bin/node")).toBeNull();
      expect(
        deriveHomebrewStableBinDir("/Users/op/.nvm/versions/node/v22.0.0/bin/node"),
      ).toBeNull();
      // A leading /Cellar/ with no prefix is not a real keg path.
      expect(deriveHomebrewStableBinDir("/Cellar/node/bin/node")).toBeNull();
    });

    it("refuses to derive from an UNTRUSTED Cellar prefix (codex MED: root-PATH escalation)", () => {
      // An operator-writable `/Cellar/`-shaped prefix must never put a fallback
      // dir on the ROOT boot daemon PATH.
      expect(
        deriveHomebrewStableBinDir("/Users/op/Cellar/node/25.8.2/bin/node"),
      ).toBeNull();
      expect(
        deriveHomebrewStableBinDir("/tmp/evil/Cellar/node/1/bin/node"),
      ).toBeNull();
    });
  });

  describe("bootServiceInstalled (#450 item 5 / codex: validate, not just file-exists)", () => {
    const validPlist = renderBootLaunchDaemonPlist({
      programArguments: [
        "/usr/local/bin/node",
        "/opt/sanctuary/dist/cli.js",
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
      fortressPath: "/Users/operator/.sanctuary",
      signerClientPath: "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client",
    });

    it("returns true for a well-formed boot-survival plist", async () => {
      const path = join(await makeTemp("f1-plist-"), "boot.plist");
      await writeFile(path, validPlist);
      expect(await bootServiceInstalled(path)).toBe(true);
    });

    it("returns true when the plist targets the expected fortress path", async () => {
      const path = join(await makeTemp("f1-plist-"), "boot.plist");
      await writeFile(path, validPlist);
      expect(await bootServiceInstalled(path, "/Users/operator/.sanctuary/")).toBe(true);
    });

    it("returns false when the plist targets a different fortress path", async () => {
      const path = join(await makeTemp("f1-plist-"), "boot.plist");
      await writeFile(path, validPlist);
      expect(await bootServiceInstalled(path, "/Users/operator/other-sanctuary")).toBe(
        false,
      );
    });

    it("returns false on duplicate SANCTUARY_STORAGE_PATH keys (last-wins evasion)", async () => {
      const path = join(await makeTemp("f1-plist-"), "dupkey.plist");
      // First key matches the expected fortress (would fool a first-match read),
      // but launchd makes the LATER duplicate effective — fail closed on the dup.
      const dupPlist = validPlist.replace(
        /(<key>SANCTUARY_STORAGE_PATH<\/key>\s*<string>[^<]*<\/string>)/,
        "$1\n\t\t<key>SANCTUARY_STORAGE_PATH</key>\n\t\t<string>/Users/operator/evil-sanctuary</string>",
      );
      await writeFile(path, dupPlist);
      expect(await bootServiceInstalled(path, "/Users/operator/.sanctuary")).toBe(false);
    });

    it("returns false when the plist omits the fortress environment", async () => {
      const path = join(await makeTemp("f1-plist-"), "boot.plist");
      await writeFile(
        path,
        validPlist.replace(
          /\n\t\t<key>SANCTUARY_STORAGE_PATH<\/key>\n\t\t<string>[^<]*<\/string>/,
          "",
        ),
      );
      expect(await bootServiceInstalled(path)).toBe(false);
      expect(await bootServiceInstalled(path, "/Users/operator/.sanctuary")).toBe(false);
      expect(await bootServicePlistPresent(path)).toBe(true);
    });

    it("returns false when the plist is absent", async () => {
      const path = join(await makeTemp("f1-plist-"), "missing.plist");
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for a wrong-label plist (file-exists is not enough)", async () => {
      const path = join(await makeTemp("f1-plist-"), "wrong.plist");
      await writeFile(path, validPlist.replace(CASTLE_WALL_BOOT_LABEL, "com.evil.other"));
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for a plist missing --safe-mode (would run the wrong mode)", async () => {
      const path = join(await makeTemp("f1-plist-"), "nomode.plist");
      await writeFile(path, validPlist.replace("<string>--safe-mode</string>", ""));
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for a plist with RunAtLoad disabled", async () => {
      const path = join(await makeTemp("f1-plist-"), "norunatload.plist");
      await writeFile(
        path,
        validPlist.replace(
          "<key>RunAtLoad</key>\n\t<true/>",
          "<key>RunAtLoad</key>\n\t<false/>",
        ),
      );
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for a plist with KeepAlive disabled", async () => {
      const path = join(await makeTemp("f1-plist-"), "nokeepalive.plist");
      await writeFile(
        path,
        validPlist.replace(
          "<key>KeepAlive</key>\n\t<true/>",
          "<key>KeepAlive</key>\n\t<false/>",
        ),
      );
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for a plist that does not run castle-wall daemon under launchd", async () => {
      const path = join(await makeTemp("f1-plist-"), "wrongargv.plist");
      await writeFile(
        path,
        validPlist.replace("<string>castle-wall</string>", "<string>not-castle-wall</string>"),
      );
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false for an unsupported executable even when daemon tokens are present", async () => {
      const path = join(await makeTemp("f1-plist-"), "wrongprogram.plist");
      await writeFile(
        path,
        renderBootLaunchDaemonPlist({
          programArguments: ["/bin/echo", "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: "/Users/operator/.sanctuary",
          signerClientPath: "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client",
        }),
      );
      expect(await bootServiceInstalled(path)).toBe(false);
    });

    it("returns false when the signer-client environment is missing or relative", async () => {
      const missingPath = join(await makeTemp("f1-plist-"), "missing-signer.plist");
      await writeFile(
        missingPath,
        validPlist.replace(
          /\n\t\t<key>SANCTUARY_CASTLE_SIGNER_CLIENT<\/key>\n\t\t<string>[^<]*<\/string>/,
          "",
        ),
      );
      expect(await bootServiceInstalled(missingPath)).toBe(false);

      const relativePath = join(await makeTemp("f1-plist-"), "relative-signer.plist");
      await writeFile(
        relativePath,
        validPlist.replace(
          /<key>SANCTUARY_CASTLE_SIGNER_CLIENT<\/key>\n\t\t<string>[^<]*<\/string>/,
          "<key>SANCTUARY_CASTLE_SIGNER_CLIENT</key>\n\t\t<string>relative-shim</string>",
        ),
      );
      expect(await bootServiceInstalled(relativePath)).toBe(false);
    });

    it("bootServiceReady requires the matching plist plus a stable live launchd pid", async () => {
      const path = join(await makeTemp("f1-plist-"), "boot.plist");
      await writeFile(path, validPlist);
      const fake = makeFakeExec({ fortress: "/Users/operator/.sanctuary" });
      const noSleep = async () => undefined;

      expect(
        await bootServiceReady(path, "/Users/operator/.sanctuary", fake.execFileFn, noSleep),
      ).toBe(false);

      fake.running = true;
      expect(
        await bootServiceReady(path, "/Users/operator/.sanctuary", fake.execFileFn, noSleep),
      ).toBe(true);
      expect(bootServiceEnabled(fake.execFileFn)).toBe(true);

      fake.disabled = true;
      expect(
        await bootServiceReady(path, "/Users/operator/.sanctuary", fake.execFileFn, noSleep),
      ).toBe(false);

      const wrongLoadedJob = makeFakeExec({ fortress: "/Users/operator/other-sanctuary" });
      wrongLoadedJob.running = true;
      expect(
        await bootServiceReady(path, "/Users/operator/.sanctuary", wrongLoadedJob.execFileFn, noSleep),
      ).toBe(false);

      const suffixLoadedJob = makeFakeExec({ fortress: "/Users/operator/.sanctuary-old" });
      suffixLoadedJob.running = true;
      expect(
        await bootServiceReady(path, "/Users/operator/.sanctuary", suffixLoadedJob.execFileFn, noSleep),
      ).toBe(false);
    });

    it("bootServiceEnabled parses both launchctl disabled value formats", () => {
      const printDisabled = (value: string): ExecFileResult => ({
        code: 0,
        stdout: `disabled services = {\n\t"${CASTLE_WALL_BOOT_LABEL}" => ${value}\n}\n`,
        stderr: "",
      });

      expect(bootServiceEnabled(() => printDisabled("enabled"))).toBe(true);
      expect(bootServiceEnabled(() => printDisabled("disabled"))).toBe(false);
      expect(bootServiceEnabled(() => printDisabled("false"))).toBe(true);
      expect(bootServiceEnabled(() => printDisabled("true"))).toBe(false);
      expect(bootServiceEnabled(() => printDisabled("bogus"))).toBe(false);
    });

    it("bootServiceLoaded treats unknown launchctl print failures as occupied", () => {
      const notLoaded: ExecFileResult = {
        code: 113,
        stdout: "",
        stderr: "Could not find service",
      };
      expect(bootServiceLoaded(() => notLoaded)).toBe(false);

      const unknownFailure: ExecFileResult = {
        code: 5,
        stdout: "",
        stderr: "Input/output error",
      };
      expect(bootServiceLoaded(() => unknownFailure)).toBe(true);
    });
  });

  describe("parseBootArgs", () => {
    it("parses both flag forms incl. --yes and --rotate", () => {
      expect(
        parseBootArgs([
          "--fortress",
          "/f",
          "--user=op",
          "--binary",
          "/b",
          "--signer-client=/s",
          "--yes",
          "--rotate",
        ]),
      ).toEqual({
        fortress: "/f",
        user: "op",
        binary: "/b",
        signerClient: "/s",
        yes: true,
        rotate: true,
      });
    });
  });

  // ── provision-boot-token ───────────────────────────────────────────

  describe("runProvisionBootToken", () => {
    it("refuses on non-macOS and refuses when not root", async () => {
      const err1 = new CaptureStream();
      expect(
        await runProvisionBootToken([], { err: err1, platform: "linux", getuid: () => 0 }),
      ).toBe(1);
      const err2 = new CaptureStream();
      expect(
        await runProvisionBootToken([], { err: err2, platform: "darwin", getuid: () => 501 }),
      ).toBe(1);
      expect(err2.text()).toContain("must run as root");
    });

    it("mints a root-owned 0600 token and audits it in the boot-audit segment", async () => {
      const fortress = await makeTemp("f1-prov-");
      const tokenPath = join(await makeTemp("f1-tok-"), "boot-token.bin");
      const out = new CaptureStream();
      const fake = makeFakeExec({ fortress });
      const normalizeCalls: string[] = [];
      const code = await runProvisionBootToken(["--fortress", fortress], {
        out,
        env: { SUDO_USER: "operator", SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID },
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        bootTokenPath: tokenPath,
        normalizeFortressCustody: async (input: { fortressPath: string }) => {
          normalizeCalls.push(input.fortressPath);
          return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
        },
      });
      expect(code).toBe(0);
      expect(out.text()).toContain("Boot token provisioned");
      expect(normalizeCalls).toEqual([fortress]);

      const info = await stat(tokenPath);
      expect(info.mode & 0o777).toBe(0o600);

      // The provision was chowned root:wheel (root path).
      expect(fake.calls.some((c) => c.cmd === "chown" && c.args[0] === "root:wheel")).toBe(true);

      // The custody event is readable in the boot-audit segment under the
      // token-derived key (NOT the master key).
      const token = await readBootToken({ path: tokenPath });
      expect(token.status).toBe("ok");
      if (token.status === "ok") {
        const auditKey = deriveSafeModeAuditKey(token.token);
        const auditLog = new AuditLog(
          new FilesystemStorage(safeModeAuditStoragePath(fortress, token.token)),
          auditKey,
        );
        const q = await auditLog.query({ layer: "l1", limit: 50 });
        const entry = q.entries.find((e) => e.operation === "boot_token_provisioned");
        expect(entry).toBeDefined();
        expect(entry?.result).toBe("success");
        expect((entry?.details as Record<string, unknown>).source).toBe(
          "castle-wall-provision-boot-token",
        );
      }
    });

    it("refuses an audited root provision when the operator identity is unresolved", async () => {
      const fortress = await makeTemp("f1-prov-unresolved-");
      const tokenPath = join(await makeTemp("f1-tok-unresolved-"), "boot-token.bin");
      const err = new CaptureStream();
      const normalizeCalls: string[] = [];

      const code = await runProvisionBootToken(["--fortress", fortress], {
        err,
        env: {},
        platform: "darwin",
        getuid: () => 0,
        execFileFn: makeFakeExec({ fortress }).execFileFn,
        bootTokenPath: tokenPath,
        normalizeFortressCustody: async (input: { fortressPath: string }) => {
          normalizeCalls.push(input.fortressPath);
          return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
        },
      });

      expect(code).toBe(1);
      expect(err.text()).toContain("Cannot resolve the non-root operator identity");
      await expect(readFile(tokenPath)).rejects.toThrow();
      expect(normalizeCalls).toEqual([]);
    });

    it("is idempotent: a second run keeps the existing token unless --rotate", async () => {
      const fortress = await makeTemp("f1-prov2-");
      const tokenPath = join(await makeTemp("f1-tok2-"), "boot-token.bin");
      const ctx: CastleWallBootContext = {
        out: new CaptureStream(),
        platform: "darwin",
        getuid: () => 0,
        execFileFn: makeFakeExec().execFileFn,
        bootTokenPath: tokenPath,
        env: { SUDO_USER: "operator", SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID },
      };
      expect(await runProvisionBootToken(["--fortress", fortress], ctx)).toBe(0);
      const first = await readFile(tokenPath);

      const out2 = new CaptureStream();
      expect(
        await runProvisionBootToken(["--fortress", fortress], { ...ctx, out: out2 }),
      ).toBe(0);
      expect(out2.text()).toContain("already present");
      expect(Buffer.from(await readFile(tokenPath)).equals(Buffer.from(first))).toBe(true);

      // --rotate replaces it.
      expect(
        await runProvisionBootToken(["--fortress", fortress, "--rotate"], {
          ...ctx,
          out: new CaptureStream(),
        }),
      ).toBe(0);
      expect(Buffer.from(await readFile(tokenPath)).equals(Buffer.from(first))).toBe(false);
    });
  });

  // ── install-boot ───────────────────────────────────────────────────

  describe("runInstallBoot", () => {
    async function makeInstallFixture() {
      const fortress = await makeTemp("f1-fortress-");
      const plistDir = await makeTemp("f1-plist-");
      const binDir = await makeTemp("f1-bin-");
      const tokDir = await makeTemp("f1-tok-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const binary = join(binDir, "sanctuary");
      const signerClient = join(binDir, "castle-wall-signer-client");
      const globalPin = join(binDir, "castle-pinned-pubkey.bin");
      const bootTokenPath = join(tokDir, "boot-token.bin");
      await writeFile(binary, "#!/bin/sh\n", { mode: 0o755 });
      await writeFile(signerClient, "#!/bin/sh\n", { mode: 0o755 });
      await writeFile(globalPin, Buffer.alloc(32, 7));
      const fake = makeFakeExec({ fortress });
      const out = new CaptureStream();
      const err = new CaptureStream();
      const ctx: CastleWallBootContext = {
        out,
        err,
        env: { SUDO_USER: "operator", SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID },
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
        globalPinPath: globalPin,
        bootTokenPath,
        // No-op sleep: the post-bootstrap stability check samples the pid over a
        // multi-second window in production; tests must not actually wait.
        sleepFn: async () => {},
      };
      const argv = ["--fortress", fortress, "--binary", binary, "--signer-client", signerClient];
      return { fortress, plistPath, binary, signerClient, globalPin, bootTokenPath, fake, out, err, ctx, argv };
    }

    it("refuses on non-macOS", async () => {
      const err = new CaptureStream();
      const code = await runInstallBoot([], { err, platform: "linux", getuid: () => 0 });
      expect(code).toBe(1);
      expect(err.text()).toContain("macOS-only");
    });

    it("refuses when not root", async () => {
      const err = new CaptureStream();
      const code = await runInstallBoot([], { err, platform: "darwin", getuid: () => 501 });
      expect(code).toBe(1);
      expect(err.text()).toContain("sudo");
    });

    it("refuses without an operator account", async () => {
      const err = new CaptureStream();
      const code = await runInstallBoot([], {
        err,
        env: {},
        platform: "darwin",
        getuid: () => 0,
      });
      expect(code).toBe(1);
      expect(err.text()).toContain("operator account");
    });

    it("fails closed in helper mode when the global pin is missing", async () => {
      const f = await makeInstallFixture();
      await rm(f.globalPin);
      const code = await runInstallBoot(f.argv, f.ctx);
      expect(code).toBe(1);
      expect(f.err.text()).toContain("re-pin");
      expect(await fileExists(f.plistPath)).toBe(false);
    });

    it("fails closed when the signer-client shim is missing", async () => {
      const f = await makeInstallFixture();
      await rm(f.signerClient);
      const code = await runInstallBoot(f.argv, f.ctx);
      expect(code).toBe(1);
      expect(f.err.text()).toContain("Signer-client shim not found");
    });

    it("requires --binary outside a dist install", async () => {
      const f = await makeInstallFixture();
      const code = await runInstallBoot(
        ["--fortress", f.fortress, "--signer-client", f.signerClient],
        f.ctx,
      );
      expect(code).toBe(1);
      expect(f.err.text()).toContain("--binary");
    });

    it("auto-provisions the token, installs the safe-mode plist, verifies a live PID, and states the drill caveat", async () => {
      const f = await makeInstallFixture();
      const code = await runInstallBoot(f.argv, f.ctx);
      expect(code).toBe(0);

      // Token auto-minted root-owned 0600.
      expect(await fileExists(f.bootTokenPath)).toBe(true);
      expect((await stat(f.bootTokenPath)).mode & 0o777).toBe(0o600);

      const plist = await readFile(f.plistPath, "utf8");
      expect(plist).toContain(CASTLE_WALL_BOOT_LABEL);
      expect(plist).toContain("<string>--safe-mode</string>");
      expect(plist).not.toContain("<key>UserName</key>");
      expect(plist).toContain(f.fortress);
      expect(plist).not.toContain("PASSPHRASE");

      const launchctlVerbs = f.fake.calls
        .filter((c) => c.cmd === "launchctl")
        .map((c) => c.args[0]);
      expect(launchctlVerbs).toContain("bootstrap");
      expect(launchctlVerbs).toContain("enable");
      expect(launchctlVerbs).toContain("print"); // start-verification
      expect(f.out.text()).toContain("pid 4242");
      expect(f.out.text()).toContain("reboot drill");
    });

    it("does NOT certify the service when bootstrap succeeds but no process starts (codex a)", async () => {
      const f = await makeInstallFixture();
      // Bootstrap accepted, but the job never produces a live PID (crash-loop /
      // missing dependency). `print` returns loaded-but-not-running: no pid line.
      let bootstrapped = false;
      const noPidExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootstrap") {
          bootstrapped = true;
        }
        if (bootstrapped && cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: "\tstate = not running\n", stderr: "" };
        }
        return f.fake.execFileFn(cmd, args);
      };
      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: noPidExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("did not stay running");
      expect(f.err.text()).toContain("NOT yet closed");
    });

    it("reports when cleanup bootout after a failed bootstrap cannot complete", async () => {
      const f = await makeInstallFixture();
      let bootstrapped = false;
      const stuckCleanupExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootstrap") {
          bootstrapped = true;
        }
        if (bootstrapped && cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: "\tstate = not running\n", stderr: "" };
        }
        if (bootstrapped && cmd === "launchctl" && args[0] === "bootout") {
          return { code: 1, stdout: "", stderr: "ETIMEDOUT: launchctl bootout timed out" };
        }
        return f.fake.execFileFn(cmd, args);
      };

      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: stuckCleanupExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("launchctl bootout after failed bootstrap did not complete");
      expect(f.err.text()).toContain("ETIMEDOUT");
      expect(f.err.text()).toContain("Could not prove the failed unit was booted out");
    });

    it("does NOT certify a crash-looping service that flaps between pids (2026-06-14 false-PASS)", async () => {
      const f = await makeInstallFixture();
      // Bootstrap accepted; `print` returns a DIFFERENT pid each read, modelling a
      // daemon that exits non-zero and is throttle-restarted on a new pid. A
      // one-shot check would certify the first transient pid as "running".
      let n = 0;
      let bootstrapped = false;
      const flappingExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootstrap") {
          bootstrapped = true;
        }
        if (bootstrapped && cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: `\tstate = running\n\tpid = ${5000 + n++}\n`, stderr: "" };
        }
        return f.fake.execFileFn(cmd, args);
      };
      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: flappingExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("did not stay running");
      // The failed (churning) unit is booted out so it does not throttle forever
      // (one pre-bootstrap bootout + one on the stability failure).
      const bootouts = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootout",
      );
      expect(bootouts.length).toBeGreaterThanOrEqual(2);
    });

    it("is idempotent: a second run with an identical plist and live job does not re-bootstrap", async () => {
      const f = await makeInstallFixture();
      expect(await runInstallBoot(f.argv, f.ctx)).toBe(0);
      const bootstrapsAfterFirst = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;
      expect(await runInstallBoot(f.argv, f.ctx)).toBe(0);
      const bootstrapsAfterSecond = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;
      expect(bootstrapsAfterSecond).toBe(bootstrapsAfterFirst);
      expect(f.out.text()).toContain("already installed and running");
    });

    it("runs the custody-normalize chokepoint on success with the resolved operator (spec 2026-07-30)", async () => {
      const f = await makeInstallFixture();
      const normalizeCalls: { fortressPath: string; operator: { uid: number; gid: number } }[] = [];
      const ctx = {
        ...f.ctx,
        env: { SUDO_USER: "operator", SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID },
        normalizeFortressCustody: async (input: { fortressPath: string; operator: { uid: number; gid: number } }) => {
          normalizeCalls.push({ fortressPath: input.fortressPath, operator: input.operator });
          return {
            status: "clean" as const,
            repaired: [],
            skips: [],
            vanished: [],
            failed: [],
          };
        },
      };
      expect(await runInstallBoot(f.argv, ctx)).toBe(0);
      expect(normalizeCalls).toEqual([
        { fortressPath: f.fortress, operator: { uid: Number(TEST_OPERATOR_UID), gid: Number(TEST_OPERATOR_GID) } },
      ]);

      // The idempotent already-installed shortcut ALSO normalizes: the log-dir
      // mkdir above it touches the fortress on every run.
      expect(await runInstallBoot(f.argv, ctx)).toBe(0);
      expect(f.out.text()).toContain("already installed and running");
      expect(normalizeCalls).toHaveLength(2);
    });

    it("does not touch a symlinked fortress log dir; boot logs go to /var/log", async () => {
      const f = await makeInstallFixture();
      const outside = await makeTemp("f1-outside-");
      // The attack: a same-uid actor plants <fortress>/logs as a symlink.
      // install-boot must not mkdir/chown through it at all.
      await symlink(outside, join(f.fortress, "logs"));

      const code = await runInstallBoot(f.argv, f.ctx);

      expect(code).toBe(0);
      expect(await readFile(f.plistPath, "utf8")).toContain("/var/log/castle-wall-daemon.log");
      const outsideStat = await stat(outside);
      expect(outsideStat.uid).toBe(process.getuid?.() ?? outsideStat.uid);
    });

    it("normalizes on FAILURE exits too, not just success (gate HIGH: the log-dir mkdir precedes them)", async () => {
      const f = await makeInstallFixture();
      const normalizeCalls: string[] = [];
      // Bootstrap is accepted but the unit never stays running: a failure
      // return AFTER the log-dir mkdir may have created the fortress
      // top-level dir root-owned, so the chokepoint must still run.
      let bootstrapped = false;
      const flappingExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootstrap") bootstrapped = true;
        if (bootstrapped && cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: "\tstate = not running\n", stderr: "" };
        }
        return f.fake.execFileFn(cmd, args);
      };
      const code = await runInstallBoot(f.argv, {
        ...f.ctx,
        env: { SUDO_USER: "operator", SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID },
        execFileFn: flappingExec,
        normalizeFortressCustody: async (input: { fortressPath: string }) => {
          normalizeCalls.push(input.fortressPath);
          return {
            status: "clean" as const,
            repaired: [],
            skips: [],
            vanished: [],
            failed: [],
          };
        },
      });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("did not stay running");
      expect(normalizeCalls).toEqual([f.fortress]);
    });

    it("refuses before mutation when root runs without a resolvable operator", async () => {
      const f = await makeInstallFixture();
      const normalizeCalls: string[] = [];
      const ctx = {
        ...f.ctx,
        // SUDO_USER present (install-boot's own operator-name requirement) but
        // no SUDO_UID/SUDO_GID: the fail-closed identity chokepoint refuses.
        env: { SUDO_USER: "operator" },
        normalizeFortressCustody: async (input: { fortressPath: string }) => {
          normalizeCalls.push(input.fortressPath);
          return {
            status: "clean" as const,
            repaired: [],
            skips: [],
            vanished: [],
            failed: [],
          };
        },
      };
      expect(await runInstallBoot(f.argv, ctx)).toBe(1);
      expect(normalizeCalls).toEqual([]);
      expect(f.err.text()).toContain("Cannot resolve the non-root operator identity");
      expect(f.fake.calls.some((call) => call.cmd === "launchctl")).toBe(false);
    });

    it("repairs a disabled launchd override instead of taking the idempotent shortcut", async () => {
      const f = await makeInstallFixture();
      expect(await runInstallBoot(f.argv, f.ctx)).toBe(0);
      const bootstrapsAfterFirst = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;

      f.fake.disabled = true;
      expect(await runInstallBoot(f.argv, f.ctx)).toBe(0);
      const bootstrapsAfterSecond = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;
      expect(bootstrapsAfterSecond).toBeGreaterThan(bootstrapsAfterFirst);
      expect(f.fake.disabled).toBe(false);
      const repairCalls = f.fake.calls
        .map((call, index) => ({ ...call, index }))
        .filter((call) => call.cmd === "launchctl" && (call.args[0] === "enable" || call.args[0] === "bootout"));
      const lastEnable = repairCalls.findLast((call) => call.args[0] === "enable");
      const lastBootout = repairCalls.findLast((call) => call.args[0] === "bootout");
      expect(lastEnable?.index).toBeLessThan(lastBootout?.index ?? Number.POSITIVE_INFINITY);
    });

    it("refuses to replace an existing singleton plist for a different fortress", async () => {
      const f = await makeInstallFixture();
      const otherFortress = await makeTemp("f1-other-fortress-");
      await writeFile(
        f.plistPath,
        renderBootLaunchDaemonPlist({
          programArguments: [f.binary, "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: otherFortress,
          signerClientPath: f.signerClient,
        }),
      );

      const code = await runInstallBoot(f.argv, f.ctx);
      expect(code).toBe(1);
      expect(f.err.text()).toContain("Refusing to replace");
      expect(f.err.text()).toContain(otherFortress);
      expect(f.err.text()).toContain(f.fortress);
      expect(await readFile(f.plistPath, "utf8")).toContain(otherFortress);
      expect(
        f.fake.calls.some(
          (c) => c.cmd === "launchctl" && (c.args[0] === "bootout" || c.args[0] === "bootstrap"),
        ),
      ).toBe(false);
    });

    it("refuses to replace a loaded singleton job for a different fortress", async () => {
      const f = await makeInstallFixture();
      const otherFortress = await makeTemp("f1-other-loaded-");
      const loadedOther = makeFakeExec({ fortress: otherFortress });
      loadedOther.running = true;

      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: loadedOther.execFileFn });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("Refusing to replace loaded");
      expect(f.err.text()).toContain(otherFortress);
      expect(await fileExists(f.plistPath)).toBe(false);
      expect(
        loadedOther.calls.some(
          (c) => c.cmd === "launchctl" && (c.args[0] === "bootout" || c.args[0] === "bootstrap"),
        ),
      ).toBe(false);
    });

    it("refuses to replace an unverifiable singleton plist", async () => {
      const f = await makeInstallFixture();
      await writeFile(f.plistPath, "<plist/>");

      const code = await runInstallBoot(f.argv, f.ctx);
      expect(code).toBe(1);
      expect(f.err.text()).toContain("does not expose a verifiable SANCTUARY_STORAGE_PATH");
      expect(await readFile(f.plistPath, "utf8")).toBe("<plist/>");
      expect(
        f.fake.calls.some(
          (c) => c.cmd === "launchctl" && (c.args[0] === "bootout" || c.args[0] === "bootstrap"),
        ),
      ).toBe(false);
    });

    it("refuses to replace an unverifiable loaded singleton job", async () => {
      const f = await makeInstallFixture();
      const loadedUnknownExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" };
        }
        return f.fake.execFileFn(cmd, args);
      };

      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: loadedUnknownExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("does not expose a verifiable SANCTUARY_STORAGE_PATH");
      expect(await fileExists(f.plistPath)).toBe(false);
      expect(
        f.fake.calls.some(
          (c) => c.cmd === "launchctl" && (c.args[0] === "bootout" || c.args[0] === "bootstrap"),
        ),
      ).toBe(false);
    });

    it("re-bootstraps instead of shortcutting when the matching service is not loaded", async () => {
      const f = await makeInstallFixture();
      expect(await runInstallBoot(f.argv, f.ctx)).toBe(0);
      const bootstrapsAfterFirst = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;
      const notLoadedJob = makeFakeExec({ fortress: f.fortress });
      const rebootstrapExec = (cmd: string, args: string[]): ExecFileResult => {
        const result = notLoadedJob.execFileFn(cmd, args);
        f.fake.calls.push({ cmd, args });
        return result;
      };
      expect(await runInstallBoot(f.argv, { ...f.ctx, execFileFn: rebootstrapExec })).toBe(0);
      const bootstrapsAfterSecond = f.fake.calls.filter(
        (c) => c.cmd === "launchctl" && c.args[0] === "bootstrap",
      ).length;
      expect(bootstrapsAfterSecond).toBeGreaterThan(bootstrapsAfterFirst);
      expect(f.out.text()).not.toContain("already installed and running");
    });

    it("surfaces launchctl enable failure before bootout/bootstrap", async () => {
      const f = await makeInstallFixture();
      const failingEnableExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "enable") {
          return { code: 64, stdout: "", stderr: "disabled database locked" };
        }
        return f.fake.execFileFn(cmd, args);
      };

      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: failingEnableExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("launchctl enable failed");
      expect(
        f.fake.calls.some(
          (c) => c.cmd === "launchctl" && (c.args[0] === "bootout" || c.args[0] === "bootstrap"),
        ),
      ).toBe(false);
    });

    it("fails closed when launchctl bootout times out and never attempts bootstrap (Bug E)", async () => {
      const f = await makeInstallFixture();
      const calls: Array<{ cmd: string; args: string[] }> = [];
      const timeoutBootoutExec = (cmd: string, args: string[]): ExecFileResult => {
        calls.push({ cmd, args });
        if (cmd === "launchctl" && args[0] === "bootout") {
          return { code: 1, stdout: "", stderr: "Error: spawnSync launchctl ETIMEDOUT" };
        }
        return f.fake.execFileFn(cmd, args);
      };

      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: timeoutBootoutExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("launchctl bootout failed");
      expect(f.err.text()).toContain("ETIMEDOUT");
      expect(calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootstrap")).toBe(false);
    });

    it("surfaces a bootstrap failure instead of claiming success", async () => {
      const f = await makeInstallFixture();
      const failingExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootstrap") {
          return { code: 5, stdout: "", stderr: "Input/output error" };
        }
        return f.fake.execFileFn(cmd, args);
      };
      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: failingExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("bootstrap failed");
    });
  });

  // ── uninstall-boot ─────────────────────────────────────────────────

  describe("runUninstallBoot", () => {
    it("refuses on non-macOS and non-root", async () => {
      const err1 = new CaptureStream();
      expect(await runUninstallBoot(["--yes"], { err: err1, platform: "linux", getuid: () => 0 })).toBe(1);
      const err2 = new CaptureStream();
      expect(await runUninstallBoot(["--yes"], { err: err2, platform: "darwin", getuid: () => 501 })).toBe(1);
      expect(err2.text()).toContain("sudo");
    });

    it("requires --yes confirmation before removing (codex c brick guard)", async () => {
      const plistDir = await makeTemp("f1-un0-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      await writeFile(plistPath, "<plist/>");
      const fake = makeFakeExec();
      fake.running = true;
      const err = new CaptureStream();
      const code = await runUninstallBoot([], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(1);
      expect(err.text()).toContain("--yes");
      expect(err.text()).toContain("brick");
      // Nothing was removed and no bootout fired without confirmation.
      expect(await fileExists(plistPath)).toBe(true);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(false);
    });

    it("removes the plist with --yes, boots out the job, and warns the filter stays armed", async () => {
      const plistDir = await makeTemp("f1-un-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      await writeFile(plistPath, "<plist/>");
      const fake = makeFakeExec();
      fake.running = true;
      const out = new CaptureStream();
      const code = await runUninstallBoot(["--yes"], {
        out,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(0);
      expect(await fileExists(plistPath)).toBe(false);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(true);
      expect(out.text()).toContain("does NOT disarm");
    });

    it("removes a stale fortress castle.sock when uninstalling the boot service (Bug D cleanup)", async () => {
      const fortress = await makeTemp("f1-un-sock-fortress-");
      const plistDir = await makeTemp("f1-un-sock-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const socketPath = join(fortress, "castle.sock");
      const sentinel = join(fortress, "sentinel");
      await writeFile(sentinel, "target-must-not-be-touched");
      await symlink(sentinel, socketPath);
      await writeFile(
        plistPath,
        renderBootLaunchDaemonPlist({
          programArguments: ["/opt/sanctuary/dist/cli.js", "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: fortress,
          signerClientPath: "/bin/echo",
        }),
      );
      const fake = makeFakeExec();
      fake.running = true;
      const out = new CaptureStream();
      const code = await runUninstallBoot(["--yes"], {
        out,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
        socketHasLiveListenerFn: async (candidate) => {
          expect(candidate).toBe(socketPath);
          return false;
        },
      });
      expect(code).toBe(0);
      expect(await fileExists(plistPath)).toBe(false);
      expect(await fileExists(socketPath)).toBe(false);
      expect(await readFile(sentinel, "utf8")).toBe("target-must-not-be-touched");
      expect(out.text()).toContain("Removed stale Castle Wall socket");
    });

    it("fails before plist or socket removal when launchctl bootout returns a real error", async () => {
      const fortress = await makeTemp("f1-un-bootout-fail-fortress-");
      const plistDir = await makeTemp("f1-un-bootout-fail-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const socketPath = join(fortress, "castle.sock");
      const sentinel = join(fortress, "sentinel");
      await writeFile(sentinel, "target-must-not-be-touched");
      await symlink(sentinel, socketPath);
      await writeFile(
        plistPath,
        renderBootLaunchDaemonPlist({
          programArguments: ["/opt/sanctuary/dist/cli.js", "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: fortress,
          signerClientPath: "/bin/echo",
        }),
      );
      const fake = makeFakeExec();
      const failingBootout = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootout") {
          fake.calls.push({ cmd, args });
          return { code: 5, stdout: "", stderr: "Input/output error" };
        }
        return fake.execFileFn(cmd, args);
      };
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", fortress], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: failingBootout,
        plistPath,
        socketHasLiveListenerFn: async () => {
          throw new Error("socket cleanup must not run after bootout failure");
        },
      });
      expect(code).toBe(1);
      expect(await fileExists(plistPath)).toBe(true);
      expect((await lstat(socketPath)).isSymbolicLink()).toBe(true);
      expect(await readFile(sentinel, "utf8")).toBe("target-must-not-be-touched");
      expect(err.text()).toContain("bootout failed");
    });

    it("fails before socket cleanup when a loaded singleton without a plist cannot be booted out", async () => {
      const fortress = await makeTemp("f1-un-loaded-bootout-fail-fortress-");
      const plistDir = await makeTemp("f1-un-loaded-bootout-fail-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const socketPath = join(fortress, "castle.sock");
      const sentinel = join(fortress, "sentinel");
      await writeFile(sentinel, "target-must-not-be-touched");
      await symlink(sentinel, socketPath);
      const fake = makeFakeExec({ fortress });
      fake.running = true;
      const failingBootout = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "bootout") {
          fake.calls.push({ cmd, args });
          return { code: 5, stdout: "", stderr: "Input/output error" };
        }
        return fake.execFileFn(cmd, args);
      };
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes"], {
        err,
        env: { SANCTUARY_STORAGE_PATH: fortress },
        platform: "darwin",
        getuid: () => 0,
        execFileFn: failingBootout,
        plistPath,
        socketHasLiveListenerFn: async () => {
          throw new Error("socket cleanup must not run after bootout failure");
        },
      });
      expect(code).toBe(1);
      expect((await lstat(socketPath)).isSymbolicLink()).toBe(true);
      expect(await readFile(sentinel, "utf8")).toBe("target-must-not-be-touched");
      expect(err.text()).toContain("bootout failed");
    });

    it("leaves a live/pre-existing castle.sock in place during uninstall cleanup (Bug D safety)", async () => {
      const fortress = await makeTemp("f1-un-live-sock-fortress-");
      const plistDir = await makeTemp("f1-un-live-sock-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const socketPath = join(fortress, "castle.sock");
      const sentinel = join(fortress, "live-socket-target");
      await writeFile(sentinel, "live-target-must-not-be-touched");
      await symlink(sentinel, socketPath);
      const fake = makeFakeExec();
      const out = new CaptureStream();
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", fortress], {
        out,
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
        socketHasLiveListenerFn: async (candidate) => {
          expect(candidate).toBe(socketPath);
          return true;
        },
      });
      expect(code).toBe(0);
      expect((await lstat(socketPath)).isSymbolicLink()).toBe(true);
      expect(await readFile(sentinel, "utf8")).toBe("live-target-must-not-be-touched");
      expect(err.text()).toContain("accepting connections");
      expect(out.text()).toContain("nothing to remove");
    });

    it("refuses a scoped uninstall when the singleton boot service targets a different fortress", async () => {
      const requestedFortress = await makeTemp("f1-un-requested-fortress-");
      const installedFortress = await makeTemp("f1-un-installed-fortress-");
      const plistDir = await makeTemp("f1-un-mismatch-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      await writeFile(
        plistPath,
        renderBootLaunchDaemonPlist({
          programArguments: ["/opt/sanctuary/dist/cli.js", "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: installedFortress,
          signerClientPath: "/bin/echo",
        }),
      );
      const fake = makeFakeExec();
      fake.running = true;
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", requestedFortress], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(1);
      expect(await fileExists(plistPath)).toBe(true);
      expect(fake.running).toBe(true);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(
        false,
      );
      expect(err.text()).toContain("targets");
      expect(err.text()).toContain(installedFortress);
    });

    it("refuses a scoped uninstall when the plist matches but the loaded singleton targets another fortress", async () => {
      const requestedFortress = await makeTemp("f1-un-loaded-mismatch-requested-");
      const loadedFortress = await makeTemp("f1-un-loaded-mismatch-loaded-");
      const plistDir = await makeTemp("f1-un-loaded-mismatch-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      await writeFile(
        plistPath,
        renderBootLaunchDaemonPlist({
          programArguments: ["/opt/sanctuary/dist/cli.js", "castle-wall", "daemon", "--safe-mode", "--launchd"],
          fortressPath: requestedFortress,
          signerClientPath: "/bin/echo",
        }),
      );
      const fake = makeFakeExec({ fortress: loadedFortress });
      fake.running = true;
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", requestedFortress], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(1);
      expect(await fileExists(plistPath)).toBe(true);
      expect(fake.running).toBe(true);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(
        false,
      );
      expect(err.text()).toContain("loaded singleton");
      expect(err.text()).toContain(loadedFortress);
    });

    it("refuses a scoped uninstall when the singleton plist path is present but unverifiable", async () => {
      const requestedFortress = await makeTemp("f1-un-dangling-requested-fortress-");
      const plistDir = await makeTemp("f1-un-dangling-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      await symlink(join(plistDir, "missing-target.plist"), plistPath);
      const fake = makeFakeExec({ fortress: "/Users/operator/other-sanctuary" });
      fake.running = true;
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", requestedFortress], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(1);
      expect((await lstat(plistPath)).isSymbolicLink()).toBe(true);
      expect(fake.running).toBe(true);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(
        false,
      );
      expect(err.text()).toContain("verifiable matching plist");
    });

    it("refuses a scoped uninstall when launchd has a loaded singleton but no verifiable plist", async () => {
      const requestedFortress = await makeTemp("f1-un-loaded-no-plist-fortress-");
      const plistDir = await makeTemp("f1-un-loaded-no-plist-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const fake = makeFakeExec({ fortress: requestedFortress });
      fake.running = true;
      const err = new CaptureStream();
      const code = await runUninstallBoot(["--yes", "--fortress", requestedFortress], {
        err,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(1);
      expect(fake.running).toBe(true);
      expect(fake.calls.some((c) => c.cmd === "launchctl" && c.args[0] === "bootout")).toBe(
        false,
      );
      expect(err.text()).toContain("verifiable matching plist");
    });

    it("is idempotent when nothing is installed (with --yes)", async () => {
      const plistDir = await makeTemp("f1-un2-");
      const plistPath = join(plistDir, `${CASTLE_WALL_BOOT_LABEL}.plist`);
      const fake = makeFakeExec();
      const out = new CaptureStream();
      const code = await runUninstallBoot(["--yes"], {
        out,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        plistPath,
      });
      expect(code).toBe(0);
      expect(out.text()).toContain("nothing to remove");
    });
  });
});
