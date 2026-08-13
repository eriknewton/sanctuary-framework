import { cpSync } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  installBootRuntimeSnapshot,
  isContentAddressedBootRuntimePath,
  removeBootRuntimeSnapshot,
  type BootRuntimeExecResult,
} from "../../src/cli/castle-wall-boot-runtime.js";

describe("Castle Wall root boot-runtime custody", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function fixture() {
    const trustedAncestorDir = await mkdtemp(join(tmpdir(), "castle-boot-runtime-"));
    tempDirs.push(trustedAncestorDir);
    const protectedDir = join(trustedAncestorDir, "Sanctuary");
    const runtimeDir = join(protectedDir, "boot-runtime");
    const nodeSourcePath = join(trustedAncestorDir, "source-node");
    const cliSourcePath = join(trustedAncestorDir, "source-cli.js");
    const signerClientSourcePath = join(trustedAncestorDir, "source-signer");
    await writeFile(nodeSourcePath, "node bytes", { mode: 0o755 });
    await writeFile(cliSourcePath, "cli bytes", { mode: 0o644 });
    await writeFile(signerClientSourcePath, "signer bytes", { mode: 0o755 });
    const calls: Array<{ cmd: string; args: string[] }> = [];
    const execFileFn = (cmd: string, args: string[]): BootRuntimeExecResult => {
      calls.push({ cmd, args });
      if (cmd === "/usr/bin/otool") {
        return {
          code: 0,
          stdout: `${args[1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n`,
          stderr: "",
        };
      }
      if (cmd === "/usr/bin/codesign") return { code: 0, stdout: "", stderr: "" };
      return { code: 1, stdout: "", stderr: `unexpected command ${cmd}` };
    };
    return {
      trustedAncestorDir,
      protectedDir,
      runtimeDir,
      nodeSourcePath,
      cliSourcePath,
      signerClientSourcePath,
      execFileFn,
      calls,
      expectedOwnerUid: process.getuid?.() ?? 0,
    };
  }

  it("installs content-addressed, non-writable executable inputs and pins launchd to them", async () => {
    const f = await fixture();
    const snapshot = await installBootRuntimeSnapshot(f);

    expect(isContentAddressedBootRuntimePath(snapshot.nodePath, "node", f.runtimeDir)).toBe(true);
    expect(isContentAddressedBootRuntimePath(snapshot.cliPath, "cli", f.runtimeDir)).toBe(true);
    expect(
      isContentAddressedBootRuntimePath(snapshot.signerClientPath, "signer-client", f.runtimeDir),
    ).toBe(true);
    expect(snapshot.programArguments).toEqual([
      snapshot.nodePath,
      snapshot.cliPath,
      "castle-wall",
      "daemon",
      "--safe-mode",
      "--launchd",
    ]);
    expect((await lstat(snapshot.nodePath)).mode & 0o777).toBe(0o555);
    expect((await lstat(snapshot.cliPath)).mode & 0o777).toBe(0o444);
    expect((await lstat(snapshot.signerClientPath)).mode & 0o777).toBe(0o555);
    expect(await readFile(snapshot.cliPath, "utf8")).toBe("cli bytes");
    expect(f.calls.filter((call) => call.cmd === "/usr/bin/otool")).toHaveLength(2);
    expect(f.calls.find((call) => call.cmd === "/usr/bin/codesign")?.args.join(" ")).toContain(
      "YFQSWQ9BJN",
    );
  });

  it("rejects an executable with a non-system dynamic-library dependency", async () => {
    const f = await fixture();
    const code = await installBootRuntimeSnapshot({
      ...f,
      execFileFn: (cmd, args) =>
        cmd === "/usr/bin/otool"
          ? {
              code: 0,
              stdout: `${args[1]}:\n\t/opt/homebrew/lib/libssl.dylib (compatibility version 1.0.0, current version 1.0.0)\n`,
              stderr: "",
            }
          : { code: 0, stdout: "", stderr: "" },
    }).catch((error: Error) => error.message);

    expect(code).toContain("non-system dynamic library");
  });

  it("rejects a signer client that fails the exact code-signing requirement", async () => {
    const f = await fixture();
    await expect(
      installBootRuntimeSnapshot({
        ...f,
        execFileFn: (cmd, args) => {
          if (cmd === "/usr/bin/otool") {
            return {
              code: 0,
              stdout: `${args[1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n`,
              stderr: "",
            };
          }
          return { code: 1, stdout: "", stderr: "requirement failed" };
        },
      }),
    ).rejects.toThrow(/code-signing verification failed/);
  });

  it("copies the exact app inputs into root custody before verifying and capturing them", async () => {
    const f = await fixture();
    const signedAppPath = join(f.trustedAncestorDir, "Source.app");
    const nodeSourcePath = join(signedAppPath, "Contents", "Resources", "boot-runtime", "node");
    const cliSourcePath = join(
      signedAppPath,
      "Contents",
      "Resources",
      "boot-runtime",
      "castle-wall-boot-daemon.js",
    );
    const signerClientSourcePath = join(
      signedAppPath,
      "Contents",
      "MacOS",
      "castle-wall-signer-client",
    );
    await mkdir(join(signedAppPath, "Contents", "Resources", "boot-runtime"), {
      recursive: true,
    });
    await mkdir(join(signedAppPath, "Contents", "MacOS"), { recursive: true });
    await writeFile(nodeSourcePath, "signed node", { mode: 0o755 });
    await writeFile(cliSourcePath, "signed daemon", { mode: 0o644 });
    await writeFile(signerClientSourcePath, "signed signer", { mode: 0o755 });
    await writeFile(join(signedAppPath, "Contents", "Info.plist"), "plist");
    let deepVerifications = 0;
    let copiedIntoCustody = false;
    const verifiedAppPaths: string[] = [];
    const snapshot = await installBootRuntimeSnapshot({
      ...f,
      signedAppPath,
      nodeSourcePath,
      cliSourcePath,
      signerClientSourcePath,
      execFileFn: (cmd, args) => {
        if (cmd === "/usr/bin/ditto") {
          cpSync(args[0]!, args[1]!, { recursive: true });
          copiedIntoCustody = true;
          return { code: 0, stdout: "", stderr: "" };
        }
        if (cmd === "/usr/bin/otool") {
          return {
            code: 0,
            stdout: `${args[1]}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n`,
            stderr: "",
          };
        }
        if (cmd === "/usr/sbin/spctl") return { code: 0, stdout: "", stderr: "" };
        if (cmd === "/usr/bin/plutil") {
          return {
            code: 0,
            stdout: args.includes("SanctuaryCastleWallHeadlessContractVersion")
              ? "3\n"
              : "a61a7322ca80\n",
            stderr: "",
          };
        }
        if (args[0] === "-dv") {
          return {
            code: 0,
            stdout: "",
            stderr: "Identifier=ai.sanctuaryprotocol.macos\nTeamIdentifier=YFQSWQ9BJN\n",
          };
        }
        if (args.includes("--deep")) {
          deepVerifications += 1;
          verifiedAppPaths.push(args[args.length - 1]!);
        }
        return { code: 0, stdout: "", stderr: "" };
      },
    });

    expect(snapshot.programArguments[0]).toBe(snapshot.nodePath);
    expect(await readFile(snapshot.cliPath, "utf8")).toBe("signed daemon");
    expect(copiedIntoCustody).toBe(true);
    expect(deepVerifications).toBe(1);
    expect(verifiedAppPaths[0]).not.toBe(signedAppPath);
    expect(verifiedAppPaths[0]).toContain(".boot-runtime-source-");
  });

  it("refuses a signed-app install whose executable inputs are redirected outside the app", async () => {
    const f = await fixture();
    await expect(
      installBootRuntimeSnapshot({
        ...f,
        signedAppPath: join(f.trustedAncestorDir, "Source.app"),
      }),
    ).rejects.toThrow(/must come from the verified Castle Wall app/);
  });

  it("rejects codesign identity prefixes rather than accepting substring matches", async () => {
    const f = await fixture();
    const signedAppPath = join(f.trustedAncestorDir, "Source.app");
    const nodeSourcePath = join(signedAppPath, "Contents", "Resources", "boot-runtime", "node");
    const cliSourcePath = join(
      signedAppPath,
      "Contents",
      "Resources",
      "boot-runtime",
      "castle-wall-boot-daemon.js",
    );
    const signerClientSourcePath = join(
      signedAppPath,
      "Contents",
      "MacOS",
      "castle-wall-signer-client",
    );
    await mkdir(join(signedAppPath, "Contents", "Resources", "boot-runtime"), {
      recursive: true,
    });
    await mkdir(join(signedAppPath, "Contents", "MacOS"), { recursive: true });
    await writeFile(nodeSourcePath, "signed node", { mode: 0o755 });
    await writeFile(cliSourcePath, "signed daemon");
    await writeFile(signerClientSourcePath, "signed signer", { mode: 0o755 });
    await writeFile(join(signedAppPath, "Contents", "Info.plist"), "plist");

    await expect(
      installBootRuntimeSnapshot({
        ...f,
        signedAppPath,
        nodeSourcePath,
        cliSourcePath,
        signerClientSourcePath,
        execFileFn: (cmd, args) => {
          if (cmd === "/usr/bin/ditto") {
            cpSync(args[0]!, args[1]!, { recursive: true });
            return { code: 0, stdout: "", stderr: "" };
          }
          if (cmd === "/usr/bin/codesign" && args[0] === "-dv") {
            return {
              code: 0,
              stdout: "",
              stderr:
                "Identifier=ai.sanctuaryprotocol.macos.attacker\n" +
                "TeamIdentifier=YFQSWQ9BJNEVIL\n",
            };
          }
          return { code: 0, stdout: "", stderr: "" };
        },
      }),
    ).rejects.toThrow(/required bundle and team identity/);
  });

  it("refuses a group-writable custody ancestor before creating the protected directory", async () => {
    const f = await fixture();
    await chmod(f.trustedAncestorDir, 0o770);
    await expect(installBootRuntimeSnapshot(f)).rejects.toThrow(/writable by group or other/);
    await expect(lstat(f.protectedDir)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses a symlinked protected directory", async () => {
    const f = await fixture();
    const outside = await mkdtemp(join(tmpdir(), "castle-boot-runtime-outside-"));
    tempDirs.push(outside);
    await symlink(outside, f.protectedDir);
    await expect(installBootRuntimeSnapshot(f)).rejects.toThrow(/real directory/);
  });

  it("removes the runtime only after revalidating its custody chain", async () => {
    const f = await fixture();
    await installBootRuntimeSnapshot(f);
    expect(await removeBootRuntimeSnapshot(f)).toBe(true);
    await expect(lstat(f.runtimeDir)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await removeBootRuntimeSnapshot(f)).toBe(false);
  });
});
