import { afterEach, describe, expect, it } from "vitest";
import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  CASTLE_WALL_BOOT_LABEL,
  bootServiceInstalled,
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
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

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
  execFileFn: (cmd: string, args: string[]) => ExecFileResult;
}

function makeFakeExec(opts: { home?: string } = {}): FakeLaunchctl {
  const state: FakeLaunchctl = {
    calls: [],
    running: false,
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
        if (verb === "print") {
          return state.running
            ? { code: 0, stdout: "\tstate = running\n\tpid = 4242\n", stderr: "" }
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
      const fake = makeFakeExec();
      const code = await runProvisionBootToken(["--fortress", fortress], {
        out,
        platform: "darwin",
        getuid: () => 0,
        execFileFn: fake.execFileFn,
        bootTokenPath: tokenPath,
      });
      expect(code).toBe(0);
      expect(out.text()).toContain("Boot token provisioned");

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

    it("is idempotent: a second run keeps the existing token unless --rotate", async () => {
      const fortress = await makeTemp("f1-prov2-");
      const tokenPath = join(await makeTemp("f1-tok2-"), "boot-token.bin");
      const ctx: CastleWallBootContext = {
        out: new CaptureStream(),
        platform: "darwin",
        getuid: () => 0,
        execFileFn: makeFakeExec().execFileFn,
        bootTokenPath: tokenPath,
        env: {},
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
      const fake = makeFakeExec();
      const out = new CaptureStream();
      const err = new CaptureStream();
      const ctx: CastleWallBootContext = {
        out,
        err,
        env: { SUDO_USER: "operator" },
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
      const noPidExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "print") {
          return { code: 0, stdout: "\tstate = not running\n", stderr: "" };
        }
        return f.fake.execFileFn(cmd, args);
      };
      const code = await runInstallBoot(f.argv, { ...f.ctx, execFileFn: noPidExec });
      expect(code).toBe(1);
      expect(f.err.text()).toContain("did not stay running");
      expect(f.err.text()).toContain("NOT yet closed");
    });

    it("does NOT certify a crash-looping service that flaps between pids (2026-06-14 false-PASS)", async () => {
      const f = await makeInstallFixture();
      // Bootstrap accepted; `print` returns a DIFFERENT pid each read, modelling a
      // daemon that exits non-zero and is throttle-restarted on a new pid. A
      // one-shot check would certify the first transient pid as "running".
      let n = 0;
      const flappingExec = (cmd: string, args: string[]): ExecFileResult => {
        if (cmd === "launchctl" && args[0] === "print") {
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
