import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  runCastleWallLinuxUpgradeTransaction,
  type FixedUpgradePaths,
  type LinuxUpgradeTransactionDependencies,
} from "../../src/cli/castle-wall-linux-upgrade.js";

const fortressId = "a1b2c3d4e5f60718";
const serviceUid = "1001";
const metadata = "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=exited ; status=0/SUCCESS";
const firstPre = "/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/\${SANCTUARY_FORTRESS_ID}";
const secondPre = "/usr/bin/install -d -o root -g sanctuary -m 0700 /run/sanctuary/locks";

function unitShow(paths: FixedUpgradePaths): string {
  return [
    "LoadState=loaded", `FragmentPath=${paths.fragment}`, "DropInPaths=", "NeedDaemonReload=no",
    `EnvironmentFiles=${paths.environment} (ignore_errors=no)`, "Environment=",
    `ExecStart={ path=${paths.binary} ; argv[]=${paths.binary} --fortress-id \${SANCTUARY_FORTRESS_ID} --trusted-service-uid \${SANCTUARY_TRUSTED_SERVICE_UID} ; ignore_errors=no ; ${metadata} }`,
    `ExecStartPre={ path=/usr/bin/install ; argv[]=${firstPre} ; ignore_errors=no ; ${metadata} } { path=/usr/bin/install ; argv[]=${secondPre} ; ignore_errors=no ; ${metadata} }`,
    `ExecStartPreEx={ path=/usr/bin/install ; argv[]=${firstPre} ; flags= ; ${metadata} } { path=/usr/bin/install ; argv[]=${secondPre} ; flags=privileged ; ${metadata} }`,
    "ExecCondition=", "ExecConditionEx=", "ExecStartPost=", "ExecStartPostEx=",
    "ExecStop=", "ExecStopEx=", "ExecStopPost=", "ExecStopPostEx=",
  ].join("\n") + "\n";
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "castle-wall-upgrade-"));
  const paths: FixedUpgradePaths = {
    cli: join(root, "cli.js"), systemctl: join(root, "systemctl"),
    fragment: join(root, "unit.service"), environment: join(root, "unit.env"),
    binary: join(root, "bin", "castle-wall-daemon"),
  };
  const candidate = join(root, "new-daemon");
  await mkdir(join(root, "bin"), { mode: 0o700 });
  await writeFile(paths.cli, "trusted installed CLI", { mode: 0o644 });
  await writeFile(paths.systemctl, "systemctl", { mode: 0o755 });
  await writeFile(paths.fragment, "shipped unit", { mode: 0o644 });
  await writeFile(paths.environment,
    `SANCTUARY_FORTRESS_ID=${fortressId}\nSANCTUARY_TRUSTED_SERVICE_UID=${serviceUid}\n`,
    { mode: 0o600 });
  await writeFile(paths.binary, "old binary", { mode: 0o755 });
  await writeFile(candidate, "new binary", { mode: 0o755 });
  const calls: string[] = [];
  const runner = {
    run: vi.fn(async (command: string, args: readonly string[]) => {
      calls.push(`${command} ${args.join(" ")}`);
      if (command === paths.systemctl && args[0] === "show") {
        return { code: 0, stdout: unitShow(paths), stderr: "" };
      }
      return { code: 0, stdout: "", stderr: "" };
    }),
  };
  const deps: LinuxUpgradeTransactionDependencies = {
    paths, custodyBase: root, custodyUid: process.getuid!(), runner,
  };
  const argv = (route: "disarm" | "reboot") => ["--route", route, "--candidate", candidate];
  const stageNames = async () => (await readdir(join(root, "bin"))).filter((name) => name.startsWith(".castle-wall-upgrade-"));
  return { root, paths, candidate, calls, runner, deps, argv, stageNames,
    cleanup: () => rm(root, { recursive: true, force: true }) };
}

describe("privileged Linux upgrade caller with controlled custody", () => {
  it("stages the admitted bytes, preflights the staged inode, and completes disarm before start", async () => {
    const f = await fixture();
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      f.runner.run.mockImplementation(async (command, args) => {
        f.calls.push(`${command} ${args.join(" ")}`);
        if (command === f.paths.systemctl && args[0] === "show") return { code: 0, stdout: unitShow(f.paths), stderr: "" };
        if (args[0] === "--preflight-manifest") {
          expect(command).toMatch(/\.castle-wall-upgrade-/);
          expect(await readFile(command, "utf8")).toBe("new binary");
          expect((await lstat(command)).mode & 0o777).toBe(0o755);
          expect((await lstat(command)).uid).toBe(process.getuid!());
          expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
          expect(args).toEqual(["--preflight-manifest", "--fortress-id", fortressId]);
        }
        return { code: 0, stdout: "", stderr: "" };
      });
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(0);
      expect(f.calls.map((call) => call.split(" ")[1])).toEqual([
        "show", "--preflight-manifest", "show", "stop", "--disarm", "start",
      ]);
      expect(await readFile(f.paths.binary, "utf8")).toBe("new binary");
      expect(await f.stageNames()).toEqual([]);
    } finally { log.mockRestore(); await f.cleanup(); }
  });

  it("uses reboot as route B's boundary without a same-boot start", async () => {
    const f = await fixture();
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("reboot"), f.deps)).toBe(0);
      expect(f.calls.some((call) => call === `${f.paths.systemctl} start sanctuary-castle-wall.service`)).toBe(false);
      expect(f.calls.at(-1)).toBe(`${f.paths.systemctl} reboot`);
      expect(await readFile(f.paths.binary, "utf8")).toBe("new binary");
    } finally { log.mockRestore(); await f.cleanup(); }
  });

  it("rejects a candidate pathname swap after FD verification before stage or stop", async () => {
    const f = await fixture();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      f.deps.onDescriptorVerified = async (path) => {
        if (path !== f.candidate) return;
        await rename(f.candidate, `${f.candidate}.held`);
        await symlink(`${f.candidate}.held`, f.candidate);
      };
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(1);
      expect(error.mock.calls.join(" ")).toMatch(/path identity changed/);
      expect(f.calls).toHaveLength(1); // only the initial read-only show
      expect(await f.stageNames()).toEqual([]);
      expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
    } finally { error.mockRestore(); await f.cleanup(); }
  });

  it("rejects unsafe candidate custody before stage or mutation", async () => {
    const f = await fixture();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await chmod(f.candidate, 0o777);
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(1);
      expect(error.mock.calls.join(" ")).toMatch(/mode is not permitted/);
      expect(f.calls).toHaveLength(1);
      expect(await f.stageNames()).toEqual([]);
      expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
    } finally { error.mockRestore(); await f.cleanup(); }
  });

  it("rejects a replaced stage inode before stop and leaves the installed binary intact", async () => {
    const f = await fixture();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      f.runner.run.mockImplementation(async (command, args) => {
        f.calls.push(`${command} ${args.join(" ")}`);
        if (args[0] === "show") return { code: 0, stdout: unitShow(f.paths), stderr: "" };
        if (args[0] === "--preflight-manifest") {
          await rename(command, `${command}.held`);
          await writeFile(command, "hostile stage", { mode: 0o755 });
        }
        return { code: 0, stdout: "", stderr: "" };
      });
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(1);
      expect(error.mock.calls.join(" ")).toMatch(/staged or installed binary changed/);
      expect(f.calls.some((call) => call.includes(" stop "))).toBe(false);
      expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
    } finally { error.mockRestore(); await f.cleanup(); }
  });

  it("rejects an effective-unit mismatch before stop and reports a stopped route without replacement", async () => {
    const f = await fixture();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      let shows = 0;
      f.runner.run.mockImplementation(async (command, args) => {
        f.calls.push(`${command} ${args.join(" ")}`);
        if (args[0] === "show") {
          shows += 1;
          return { code: 0, stdout: shows === 1 ? unitShow(f.paths) :
            unitShow(f.paths).replace("NeedDaemonReload=no", "NeedDaemonReload=yes"), stderr: "" };
        }
        return { code: 0, stdout: "", stderr: "" };
      });
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(1);
      expect(f.calls.some((call) => call.includes(" stop "))).toBe(false);
      expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
      expect(await f.stageNames()).toEqual([]);
    } finally { error.mockRestore(); await f.cleanup(); }
  });

  it("propagates a stop-step abort and does not disarm, replace, or start", async () => {
    const f = await fixture();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      f.runner.run.mockImplementation(async (command, args) => {
        f.calls.push(`${command} ${args.join(" ")}`);
        if (args[0] === "show") return { code: 0, stdout: unitShow(f.paths), stderr: "" };
        if (args[0] === "stop") return { code: 7, stdout: "", stderr: "stop refused" };
        return { code: 0, stdout: "", stderr: "" };
      });
      expect(await runCastleWallLinuxUpgradeTransaction(f.argv("disarm"), f.deps)).toBe(1);
      expect(error.mock.calls.join(" ")).toMatch(/aborted at stop_unit \(exit 7\): stop refused/);
      expect(f.calls.some((call) => call.includes(" --disarm") || call.includes(" start "))).toBe(false);
      expect(await readFile(f.paths.binary, "utf8")).toBe("old binary");
      expect(await f.stageNames()).toEqual([]);
    } finally { error.mockRestore(); await f.cleanup(); }
  });
});
