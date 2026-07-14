/**
 * Command construction tests for the file-grant ACL primitive.
 *
 * These are pure argv-shape tests. They do not execute setfacl, chmod, sudo,
 * or any other host command.
 */

import { constants as fsConstants } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import {
  AGENT_READ_PROBE_SCRIPT,
  buildAgentReadProbeCommand,
  buildLinuxFortressTraverseGrantCommand,
  buildLinuxFortressTraverseRevokeCommand,
  buildLinuxGrantAgentReadCommands,
  buildLinuxRevokeAgentReadCommands,
  buildMacFortressTraverseGrantCommand,
  buildMacFortressTraverseRevokeCommand,
  buildMacGrantAgentReadCommands,
  buildMacRevokeAgentReadCommands,
  type FileGrantMacAclLinkOps,
  type FileGrantOpenedFile,
  PosixFileGrantFsOps,
  type FileGrantExecCommand,
  type FileGrantExecRunner,
} from "../../src/file-grant/fs-ops.js";
import type {
  FileGrantPinnedSource,
  FileGrantSourceIdentity,
} from "../../src/file-grant/types.js";
import { withPathLock } from "../../src/storage/cross-process-lock.js";
import { makeFileGrantTestStore } from "./fixtures.js";

function pinnedSource(overrides: Partial<FileGrantPinnedSource> = {}): FileGrantPinnedSource {
  return {
    source_realpath: "/operator/source.txt",
    source_owner_uid: 501,
    source_dev: "11",
    source_ino: "22",
    source_fd_path: "/proc/test/fd/9",
    close: async () => {},
    ...overrides,
  };
}

function errnoError(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

function makeRecordingExecRunner(): {
  commands: FileGrantExecCommand[];
  runner: FileGrantExecRunner;
} {
  const commands: FileGrantExecCommand[] = [];
  return {
    commands,
    runner: {
      execFile: async (command) => {
        commands.push(command);
        if (command.file === "id") return { stdout: "agentuser\n", stderr: "" };
        return { stdout: "", stderr: "" };
      },
    },
  };
}

function makeMacAclLinkOps(params: {
  identity: FileGrantSourceIdentity;
  linkError?: NodeJS.ErrnoException;
  missingOnOpen?: boolean;
  isFile?: boolean;
  mode?: number;
}): {
  links: Array<{ existingPath: string; newPath: string }>;
  opens: Array<{ path: string; flags: number }>;
  rms: Array<{ path: string; options: { force?: boolean } }>;
  ops: FileGrantMacAclLinkOps;
} {
  const links: Array<{ existingPath: string; newPath: string }> = [];
  const opens: Array<{ path: string; flags: number }> = [];
  const rms: Array<{ path: string; options: { force?: boolean } }> = [];
  const ops: FileGrantMacAclLinkOps = {
    link: async (existingPath, newPath) => {
      links.push({ existingPath, newPath });
      if (params.linkError) throw params.linkError;
    },
    open: async (path, flags): Promise<FileGrantOpenedFile> => {
      opens.push({ path, flags });
      if (params.missingOnOpen) throw errnoError("ENOENT", "missing trusted link");
      return {
        stat: async () => ({
          dev: BigInt(params.identity.source_dev),
          ino: BigInt(params.identity.source_ino),
          uid: 501n,
          mode: params.mode ?? 0o100000,
          isFile: () => params.isFile ?? true,
          isDirectory: () => false,
        }),
        close: async () => {},
      };
    },
    rm: async (path, options) => {
      rms.push({ path, options });
    },
  };
  return { links, opens, rms, ops };
}

class MacMintHarnessFsOps extends PosixFileGrantFsOps {
  placed: Array<{ src: string; dest: string }> = [];
  probeCalls: Array<{
    entry: string;
    uid: number;
    identity: FileGrantSourceIdentity;
  }> = [];

  constructor(
    fortressPath: string,
    options: ConstructorParameters<typeof PosixFileGrantFsOps>[1],
    private readonly source: FileGrantPinnedSource,
    private readonly probeResult: boolean
  ) {
    super(fortressPath, options);
  }

  override async realpath(path: string): Promise<string> {
    return path;
  }

  override async pinSource(_canonicalPath: string): Promise<FileGrantPinnedSource> {
    return this.source;
  }

  override async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    this.placed.push({ src: canonicalSrc, dest: relativeTreeEntry });
  }

  override async probeAgentRead(
    relativeTreeEntry: string,
    agentUid: number,
    pinned: FileGrantSourceIdentity
  ): Promise<boolean> {
    this.probeCalls.push({
      entry: relativeTreeEntry,
      uid: agentUid,
      identity: { source_dev: pinned.source_dev, source_ino: pinned.source_ino },
    });
    return this.probeResult;
  }

  override async agentUid(_subjectAgentId: string): Promise<number | null> {
    return 502;
  }
}

describe("file-grant ACL command argv construction", () => {
  it("builds Linux setfacl grant commands with execute-only ancestors and source leaf read", () => {
    expect(
      buildLinuxGrantAgentReadCommands(
        "/fortress/grants",
        "agent-1/nested/fg_abc",
        502,
        "/operator/source.txt"
      )
    ).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1/nested"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/operator/source.txt"] },
    ]);
  });

  it("builds Linux setfacl revoke commands that remove only the persisted source leaf ACE", () => {
    expect(buildLinuxRevokeAgentReadCommands(502, "/operator/source.txt")).toEqual([
      { file: "setfacl", args: ["-x", "u:502", "/operator/source.txt"] },
    ]);
  });

  it("keeps execute-only ancestor ACLs out of per-grant Linux revoke commands", () => {
    const grantCommands = buildLinuxGrantAgentReadCommands(
      "/fortress/grants",
      "agent-1/nested/fg_abc",
      502,
      "/operator/source.txt"
    );
    const revokeCommands = buildLinuxRevokeAgentReadCommands(502, "/operator/source.txt");

    expect(grantCommands.slice(0, 3)).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1/nested"] },
    ]);
    expect(revokeCommands).toEqual([
      { file: "setfacl", args: ["-x", "u:502", "/operator/source.txt"] },
    ]);
  });

  it("builds macOS chmod grant commands with execute-only ancestors and a trusted ACL target", () => {
    expect(
      buildMacGrantAgentReadCommands(
        "/fortress/grants",
        "agent-1/nested/fg_abc",
        "agentuser",
        "/fortress/grants/agent-1/nested/fg_abc"
      )
    ).toEqual([
      { file: "chmod", args: ["+a", "user:agentuser allow execute", "/fortress/grants"] },
      { file: "chmod", args: ["+a", "user:agentuser allow execute", "/fortress/grants/agent-1"] },
      {
        file: "chmod",
        args: ["+a", "user:agentuser allow execute", "/fortress/grants/agent-1/nested"],
      },
      {
        file: "chmod",
        args: [
          "+a",
          "user:agentuser allow read,execute",
          "/fortress/grants/agent-1/nested/fg_abc",
        ],
      },
    ]);
  });

  it("builds macOS chmod revoke commands against the trusted ACL target", () => {
    expect(
      buildMacRevokeAgentReadCommands("agentuser", "/fortress/grants/agent-1/fg_abc")
    ).toEqual([
      {
        file: "chmod",
        args: ["-a", "user:agentuser allow read,execute", "/fortress/grants/agent-1/fg_abc"],
      },
    ]);
  });

  it("builds the fortress-dir traverse grant/revoke commands as single execute-only ACEs (F1 fix)", () => {
    expect(buildLinuxFortressTraverseGrantCommand("/fortress", 502)).toEqual({
      file: "setfacl",
      args: ["-m", "u:502:--x", "/fortress"],
    });
    expect(buildLinuxFortressTraverseRevokeCommand("/fortress", 502)).toEqual({
      file: "setfacl",
      args: ["-x", "u:502", "/fortress"],
    });
    expect(buildMacFortressTraverseGrantCommand("/fortress", "agentuser")).toEqual({
      file: "chmod",
      args: ["+a", "user:agentuser allow execute", "/fortress"],
    });
    expect(buildMacFortressTraverseRevokeCommand("/fortress", "agentuser")).toEqual({
      file: "chmod",
      args: ["-a", "user:agentuser allow execute", "/fortress"],
    });
    // Never a read ACE: the fortress dir gets traverse-only, same as every
    // other ancestor in the grant-tree walk.
    expect(
      JSON.stringify(buildMacFortressTraverseGrantCommand("/fortress", "agentuser"))
    ).not.toContain("read");
    expect(buildLinuxFortressTraverseGrantCommand("/fortress", 502).args).not.toContain("u:502:rX");
  });

  it("builds the agent-uid read probe as sudo argv, not a shell command", () => {
    expect(
      buildAgentReadProbeCommand(
        "/fortress/grants",
        "agent-1/fg_abc",
        502,
        { source_dev: "11", source_ino: "22" },
        "/node"
      )
    ).toEqual({
      file: "sudo",
      args: [
        "-n",
        "-u",
        "#502",
        "/node",
        "-e",
        AGENT_READ_PROBE_SCRIPT,
        "/fortress/grants/agent-1/fg_abc",
        "11",
        "22",
      ],
    });
  });

  it("macOS grant verifies a hard-link ACL target before chmod and can reach met", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({ identity: { source_dev: "11", source_ino: "22" } });
    const source = pinnedSource({ source_fd_path: undefined });
    const fsOps = new MacMintHarnessFsOps(
      fortress,
      {
        platform: "darwin",
        execRunner: exec.runner,
        macAclLinkOps: macLinks.ops,
      },
      source,
      true
    );

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/operator/source.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-13T00:00:00.000Z") }
    );

    const trustedPath = join(fortress, "grants", grant.tree_entry);
    expect(enforcement).toBe("met");
    expect(grant.granted_read_ace).toEqual({
      agent_uid: 502,
      platform: "darwin",
      source_realpath: "/operator/source.txt",
      source_dev: "11",
      source_ino: "22",
      mac_principal: "agentuser",
      mac_acl_hardlink_path: trustedPath,
    });
    expect(macLinks.links).toEqual([
      { existingPath: "/operator/source.txt", newPath: trustedPath },
    ]);
    expect(macLinks.opens).toEqual([
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
    ]);
    expect(exec.commands).toEqual([
      { file: "id", args: ["-nu", "502"] },
      { file: "chmod", args: ["+a", "user:agentuser allow execute", fortress] },
      { file: "chmod", args: ["+a", "user:agentuser allow execute", join(fortress, "grants")] },
      {
        file: "chmod",
        args: ["+a", "user:agentuser allow execute", join(fortress, "grants", "agent-1")],
      },
      {
        file: "chmod",
        args: ["+a", "user:agentuser allow read,execute", trustedPath],
      },
    ]);
    expect(exec.commands).not.toContainEqual({
      file: "chmod",
      args: ["+a", "user:agentuser allow read,execute", "/operator/source.txt"],
    });
    expect(fsOps.probeCalls).toEqual([
      {
        entry: grant.tree_entry,
        uid: 502,
        identity: { source_dev: "11", source_ino: "22" },
      },
    ]);
  });

  it("macOS grant fails closed when the hard-link inode differs from the pinned source", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({ identity: { source_dev: "11", source_ino: "23" } });
    const fsOps = new MacMintHarnessFsOps(
      fortress,
      {
        platform: "darwin",
        execRunner: exec.runner,
        macAclLinkOps: macLinks.ops,
      },
      pinnedSource({ source_fd_path: undefined }),
      true
    );

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/operator/source.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-13T00:00:00.000Z") }
    );

    const trustedPath = join(fortress, "grants", grant.tree_entry);
    expect(enforcement).toBe("unverified");
    expect(grant.granted_read_ace).toBeNull();
    expect(macLinks.links).toEqual([
      { existingPath: "/operator/source.txt", newPath: trustedPath },
    ]);
    expect(macLinks.rms).toEqual([
      { path: trustedPath, options: { force: true } },
      { path: trustedPath, options: { force: true } },
    ]);
    expect(exec.commands).toEqual([{ file: "id", args: ["-nu", "502"] }]);
    expect(fsOps.probeCalls).toHaveLength(0);
  });

  it("macOS grant fails closed on EXDEV without applying an ACE", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({
      identity: { source_dev: "11", source_ino: "22" },
      linkError: errnoError("EXDEV", "cross-device link"),
    });
    const fsOps = new MacMintHarnessFsOps(
      fortress,
      {
        platform: "darwin",
        execRunner: exec.runner,
        macAclLinkOps: macLinks.ops,
      },
      pinnedSource({ source_fd_path: undefined }),
      true
    );

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/operator/source.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-13T00:00:00.000Z") }
    );

    const trustedPath = join(fortress, "grants", grant.tree_entry);
    expect(enforcement).toBe("unverified");
    expect(grant.granted_read_ace).toBeNull();
    expect(macLinks.links).toEqual([
      { existingPath: "/operator/source.txt", newPath: trustedPath },
    ]);
    expect(macLinks.opens).toHaveLength(0);
    expect(macLinks.rms).toEqual([
      { path: trustedPath, options: { force: true } },
      { path: trustedPath, options: { force: true } },
    ]);
    expect(exec.commands).toEqual([{ file: "id", args: ["-nu", "502"] }]);
    expect(fsOps.probeCalls).toHaveLength(0);
  });

  it("macOS revoke removes the ACE through the trusted hard link before unlinking it", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const treeEntry = "agent-1/fg_revoke";
    const trustedPath = join(fortress, "grants", treeEntry);
    await mkdir(join(fortress, "grants", "agent-1"), { recursive: true });
    await writeFile(trustedPath, "operator data");
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({ identity: { source_dev: "11", source_ino: "22" } });
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "darwin",
      execRunner: exec.runner,
      macAclLinkOps: macLinks.ops,
    });

    const result = await fsOps.removeEntry(treeEntry, {
      grantedReadAce: {
        agent_uid: 502,
        platform: "darwin",
        source_realpath: "/operator/source.txt",
        source_dev: "11",
        source_ino: "22",
        mac_principal: "agentuser",
        mac_acl_hardlink_path: trustedPath,
      },
    });

    expect(result).toEqual({
      treeEntryRemoved: true,
      aclRemoval: {
        status: "removed",
        agent_uid: 502,
        platform: "darwin",
        source_realpath: "/operator/source.txt",
      },
      scrubbed: true,
    });
    expect(exec.commands).toEqual([
      { file: "chmod", args: ["-a", "user:agentuser allow read,execute", trustedPath] },
    ]);
    expect(macLinks.opens).toEqual([
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
    ]);
    await expect(readFile(trustedPath, "utf-8")).rejects.toThrow();
  });

  it("macOS revoke fails closed when the trusted hard-link inode differs", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const treeEntry = "agent-1/fg_revoke_mismatch";
    const trustedPath = join(fortress, "grants", treeEntry);
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({ identity: { source_dev: "11", source_ino: "23" } });
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "darwin",
      execRunner: exec.runner,
      macAclLinkOps: macLinks.ops,
    });

    const result = await fsOps.removeEntry(treeEntry, {
      grantedReadAce: {
        agent_uid: 502,
        platform: "darwin",
        source_realpath: "/operator/source.txt",
        source_dev: "11",
        source_ino: "22",
        mac_principal: "agentuser",
        mac_acl_hardlink_path: trustedPath,
      },
    });

    expect(result.scrubbed).toBe(false);
    expect(result.treeEntryRemoved).toBe(false);
    expect(result.aclRemoval.status).toBe("failed");
    expect(result.aclRemoval.reason).toContain("source inode mismatch");
    expect(exec.commands).toHaveLength(0);
    expect(macLinks.opens).toEqual([
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
    ]);
  });

  it("macOS revoke fails closed when the trusted ACL target is not regular", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-"));
    const treeEntry = "agent-1/fg_revoke_fifo";
    const trustedPath = join(fortress, "grants", treeEntry);
    const exec = makeRecordingExecRunner();
    const macLinks = makeMacAclLinkOps({
      identity: { source_dev: "11", source_ino: "22" },
      isFile: false,
      mode: 0o010000,
    });
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "darwin",
      execRunner: exec.runner,
      macAclLinkOps: macLinks.ops,
    });

    const result = await fsOps.removeEntry(treeEntry, {
      grantedReadAce: {
        agent_uid: 502,
        platform: "darwin",
        source_realpath: "/operator/source.txt",
        source_dev: "11",
        source_ino: "22",
        mac_principal: "agentuser",
        mac_acl_hardlink_path: trustedPath,
      },
    });

    expect(result.scrubbed).toBe(false);
    expect(result.treeEntryRemoved).toBe(false);
    expect(result.aclRemoval.status).toBe("failed");
    expect(result.aclRemoval.reason).toContain("not a regular file");
    expect(exec.commands).toHaveLength(0);
    expect(macLinks.opens).toEqual([
      {
        path: trustedPath,
        flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      },
    ]);
  });

  it("best-effort removes partial Linux ACLs when grant application fails", async () => {
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          if (command.args[1] === "u:502:rX") {
            throw new Error("setfacl leaf failed");
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, pinnedSource());

    expect(result.status).toBe("failed");
    expect(seen).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/proc/test/fd/9"] },
      { file: "setfacl", args: ["-x", "u:502", "/proc/test/fd/9"] },
      // The just-applied fortress traverse ACE is cleaned up too: a partial
      // apply must never orphan the uid-level traverse ACE.
      { file: "setfacl", args: ["-x", "u:502", "/fortress"] },
    ]);
  });

  it("cleans up the fortress traverse ACE when an ancestor command fails BEFORE the source leaf is attempted", async () => {
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          if (command.args[2] === "/fortress/grants") {
            throw new Error("setfacl ancestor failed");
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, pinnedSource());

    // The fortress ACE succeeded, the FIRST grant-tree ancestor failed, and
    // the source leaf was never attempted -- yet the fortress ACE is still
    // removed. This is the pre-leaf failure path that previously skipped ALL
    // cleanup (sourceLeafCommandAttempted was never set).
    expect(result.status).toBe("failed");
    expect(seen).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress"] },
    ]);
  });

  it("fails closed (never applied) when the fortress-dir traverse ACE itself fails to apply", async () => {
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          if (command.args[2] === "/fortress") {
            throw new Error("setfacl fortress ACE failed: EPERM");
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, pinnedSource());

    // The whole apply fails closed: no ancestor or leaf ACE command ever ran,
    // because the agent could not even reach the grant tree without the
    // fortress-dir ACE (F1 fix: this is the exact gap the fix closes).
    expect(result.status).toBe("not_privileged");
    expect(seen).toEqual([{ file: "setfacl", args: ["-m", "u:502:--x", "/fortress"] }]);
  });

  it("grantAgentRead applies the leaf ACL to the pinned source fd path", async () => {
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, pinnedSource());

    expect(result.status).toBe("applied");
    expect(result.grantedReadAce).toEqual({
      agent_uid: 502,
      platform: "linux",
      source_realpath: "/operator/source.txt",
      source_dev: "11",
      source_ino: "22",
    });
    expect(seen).toContainEqual({
      file: "setfacl",
      args: ["-m", "u:502:rX", "/proc/test/fd/9"],
    });
    expect(seen).not.toContainEqual({
      file: "setfacl",
      args: ["-m", "u:502:rX", "/operator/source.txt"],
    });
    expect(seen).not.toContainEqual({
      file: "setfacl",
      args: ["-m", "u:502:rX", "/fortress/grants/agent-1/fg_abc"],
    });
  });

  it("removeEntry removes the persisted uid source ACE even when no descriptor exists", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-acl-"));
    const source = join(dir, "source.txt");
    await writeFile(source, "ok");
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          return { stdout: "", stderr: "" };
        },
      },
    });
    const pinned = await fsOps.pinSource(source);
    const ace = {
      agent_uid: 502,
      platform: "linux" as const,
      source_realpath: source,
      source_dev: pinned.source_dev,
      source_ino: pinned.source_ino,
    };
    await pinned.close();

    const result = await fsOps.removeEntry("agent-1/fg_abc", {
      grantedReadAce: ace,
    });

    expect(result).toEqual({
      treeEntryRemoved: false,
      aclRemoval: {
        status: "removed",
        agent_uid: 502,
        platform: "linux",
        source_realpath: source,
      },
      scrubbed: true,
    });
    expect(seen).toEqual([
      {
        file: "setfacl",
        args: ["-x", "u:502", expect.stringMatching(`^/proc/${process.pid}/fd/`)],
      },
    ]);
  });

  it("removeEntry does not run setfacl remove when the persisted source inode changed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-acl-"));
    const source = join(dir, "source.txt");
    await writeFile(source, "ok");
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.removeEntry("agent-1/fg_abc", {
      grantedReadAce: {
        agent_uid: 502,
        platform: "linux",
        source_realpath: source,
        source_dev: "999",
        source_ino: "888",
      },
    });

    expect(result.scrubbed).toBe(false);
    expect(result.aclRemoval.status).toBe("failed");
    expect(result.aclRemoval.reason).toContain("source inode mismatch");
    expect(seen).toHaveLength(0);
  });

  it("Linux: draining ONE subject agent id never strips the shared-uid fortress ACE while ANOTHER agent id still holds a grant (F1 fix, cross-agent)", async () => {
    // The fortress traverse ACE is keyed on the box's single OS uid; two
    // DISTINCT logical agent ids resolve to that same uid. Draining agent-1's
    // subtree while agent-2 still holds an active grant must NOT remove the
    // shared ACE (it would break agent-2's still-live reach path). Only when
    // the WHOLE grant tree is drained may the ACE go.
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-fortress-lifecycle-"));
    const sourceDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-source-lifecycle-"));
    const sourceA = join(sourceDir, "a.txt");
    const sourceB = join(sourceDir, "b.txt");
    await writeFile(sourceA, "a");
    await writeFile(sourceB, "b");

    const originDir = join(fortress, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 })
    );

    const exec = makeRecordingExecRunner();
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "linux",
      execRunner: exec.runner,
    });

    const pinnedA = await fsOps.pinSource(sourceA);
    await fsOps.place(sourceA, "agent-1/fg_a");
    const resultA = await fsOps.grantAgentRead("agent-1/fg_a", 502, pinnedA);
    await pinnedA.close();

    const pinnedB = await fsOps.pinSource(sourceB);
    await fsOps.place(sourceB, "agent-2/fg_b");
    const resultB = await fsOps.grantAgentRead("agent-2/fg_b", 502, pinnedB);
    await pinnedB.close();

    expect(resultA.status).toBe("applied");
    expect(resultB.status).toBe("applied");
    // Both grants applied the (idempotent) fortress-dir traverse ACE.
    expect(exec.commands.filter((c) => c.args.includes(fortress))).toHaveLength(2);

    exec.commands.length = 0;

    // Draining agent-1 ENTIRELY (its last grant) while agent-2's grant is
    // still live: the shared uid's fortress ACE must stay.
    const first = await fsOps.removeEntry("agent-1/fg_a", {
      grantedReadAce: resultA.grantedReadAce,
    });
    expect(first.treeEntryRemoved).toBe(true);
    expect(exec.commands).not.toContainEqual({ file: "setfacl", args: ["-x", "u:502", fortress] });

    // Draining agent-2 as well empties the WHOLE tree: now (and only now)
    // the fortress ACE is removed, not left as a standing orphan.
    const second = await fsOps.removeEntry("agent-2/fg_b", {
      grantedReadAce: resultB.grantedReadAce,
    });
    expect(second.treeEntryRemoved).toBe(true);
    expect(exec.commands).toContainEqual({ file: "setfacl", args: ["-x", "u:502", fortress] });
    // ...and exactly once, with no compensating re-apply (the tree really is empty).
    expect(exec.commands.filter((c) => c.args.includes(fortress))).toEqual([
      { file: "setfacl", args: ["-x", "u:502", fortress] },
    ]);
  });

  it("Linux: a concurrent mint placing an entry between drain-check and ACE removal triggers an immediate re-apply (revoke-vs-mint race close)", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-fortress-race-"));
    const sourceDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-source-race-"));
    const source = join(sourceDir, "a.txt");
    await writeFile(source, "a");

    const originDir = join(fortress, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 })
    );

    // Exec runner that simulates a concurrent mint: the moment the revoke
    // path issues the fortress ACE removal, a new grant entry appears in the
    // tree (as a real mint's place() would have done).
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          if (command.args[0] === "-x" && command.args[2] === fortress) {
            await mkdir(join(fortress, "grants", "agent-9"), { recursive: true });
            await writeFile(join(fortress, "grants", "agent-9", "fg_new"), "placed");
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const pinned = await fsOps.pinSource(source);
    await fsOps.place(source, "agent-1/fg_a");
    const result = await fsOps.grantAgentRead("agent-1/fg_a", 502, pinned);
    await pinned.close();
    expect(result.status).toBe("applied");
    seen.length = 0;

    await fsOps.removeEntry("agent-1/fg_a", { grantedReadAce: result.grantedReadAce });

    // The drain check passed (tree looked empty), the removal ran, the
    // re-check saw the concurrently placed entry, and the ACE was re-applied.
    expect(seen.filter((c) => c.args.includes(fortress))).toEqual([
      { file: "setfacl", args: ["-x", "u:502", fortress] },
      { file: "setfacl", args: ["-m", "u:502:--x", fortress] },
    ]);
  });

  it("Linux: a FAILED re-apply after a concurrent placement THROWS loudly, never a silent unreachable grant (fail-closed; bug-inject vs the swallow)", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-fortress-race-fail-"));
    const sourceDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-source-race-fail-"));
    const source = join(sourceDir, "a.txt");
    await writeFile(source, "a");

    const originDir = join(fortress, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 })
    );

    // The `-x` removal triggers a concurrent placement (as a mint's place()
    // would), AND the subsequent `-m` re-apply FAILS. The old code swallowed
    // that failure, leaving the shared ACE removed while an active grant needs
    // it (a silent unreachable-active-grant). The fix makes it a hard throw.
    const seen: FileGrantExecCommand[] = [];
    let armed = false;
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          if (armed && command.args[0] === "-x" && command.args[2] === fortress) {
            await mkdir(join(fortress, "grants", "agent-9"), { recursive: true });
            await writeFile(join(fortress, "grants", "agent-9", "fg_new"), "placed");
          }
          if (armed && command.args[0] === "-m" && command.args[2] === fortress) {
            throw new Error("setfacl re-apply failed: EPERM");
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const pinned = await fsOps.pinSource(source);
    await fsOps.place(source, "agent-1/fg_a");
    const result = await fsOps.grantAgentRead("agent-1/fg_a", 502, pinned);
    await pinned.close();
    expect(result.status).toBe("applied");
    seen.length = 0;
    armed = true;

    // Fail-closed: the removal path THROWS rather than swallowing the failed
    // re-apply. (Against the pre-fix swallow this resolves without throwing.)
    await expect(
      fsOps.removeEntry("agent-1/fg_a", { grantedReadAce: result.grantedReadAce })
    ).rejects.toThrow(/re-apply the fortress traverse ACE/);

    expect(seen.filter((c) => c.args.includes(fortress))).toEqual([
      { file: "setfacl", args: ["-x", "u:502", fortress] },
      { file: "setfacl", args: ["-m", "u:502:--x", fortress] },
    ]);

    // opus LOW-2: access for THIS grant was removed BEFORE the throw. The
    // grant-tree entry is gone, and the source-inode ACE removal ran before
    // any fortress-dir command.
    await expect(stat(join(fortress, "grants", "agent-1", "fg_a"))).rejects.toThrow();
    const firstFortressIdx = seen.findIndex((c) => c.args.includes(fortress));
    const sourceAceRemoved = seen
      .slice(0, firstFortressIdx)
      .some((c) => c.args[0] === "-x" && c.args[2]?.includes("/fd/"));
    expect(sourceAceRemoved).toBe(true);
  });

  it("serializes concurrent fortress-ACE removals across two FsOps over the same fortress (cross-process lock engaged)", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-lock-"));
    await mkdir(join(fortress, "grants"), { recursive: true, mode: 0o711 });

    // A first holder that parks inside the locked critical section long enough
    // for a second acquire to be forced to wait, proving mutual exclusion.
    let firstInside = false;
    let secondEnteredWhileFirstInside = false;
    let releaseFirst: () => void = () => {};
    const firstDone = new Promise<void>((r) => (releaseFirst = r));

    const lockDir = join(fortress, "grants");
    const first = withPathLock(lockDir, ".fortress-ace.lock", async () => {
      firstInside = true;
      await firstDone;
      firstInside = false;
    });
    // Give `first` a tick to acquire.
    await new Promise((r) => setTimeout(r, 20));

    const second = withPathLock(
      lockDir,
      ".fortress-ace.lock",
      async () => {
        // If the lock is real, we only get here after `first` released.
        secondEnteredWhileFirstInside = firstInside;
      },
      { retryMs: 5, timeoutMs: 2000 }
    );

    // Second must still be blocked while first holds the lock.
    await new Promise((r) => setTimeout(r, 30));
    expect(firstInside).toBe(true);
    releaseFirst();
    await first;
    await second;
    expect(secondEnteredWhileFirstInside).toBe(false);
  });

  it("holds the fortress-ACE lock THROUGH the mint probe (a concurrent acquire times out during the probe; round-4 bug-inject)", async () => {
    if (process.getuid === undefined) return; // POSIX-only
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-probe-lock-"));
    const sourceDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-probe-src-"));
    const source = join(sourceDir, "s.txt");
    await writeFile(source, "secret");

    const originDir = join(fortress, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    // The agent uid MUST differ from the source-file owner (this process) so
    // the probe actually runs.
    const agentUid = process.getuid() + 4242;
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: agentUid, system_uid_allow_ceiling: 500 })
    );

    let releaseProbe: () => void = () => {};
    const probeGate = new Promise<void>((r) => (releaseProbe = r));
    let markProbeEntered: () => void = () => {};
    const probeEntered = new Promise<void>((r) => (markProbeEntered = r));

    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          if (command.file === "sudo") {
            // Inside the read probe: signal, then BLOCK. In round 4 the mint
            // still holds the fortress-ACE lock here (apply+probe are one hold).
            markProbeEntered();
            await probeGate;
          }
          return { stdout: "", stderr: "" };
        },
      },
    });

    const mintPromise = mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: source },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-14T00:00:00.000Z") }
    );

    await probeEntered; // the mint is now blocked inside its read probe

    // Round-4 guarantee: the fortress-ACE lock is held THROUGH the probe, so a
    // concurrent acquire on the same grants-root lockfile must TIME OUT.
    // Bug-inject: pre-round-4 the probe ran OUTSIDE the lock, so this acquire
    // would SUCCEED (acquired === true) and the test would fail.
    let acquired = false;
    await withPathLock(
      join(fortress, "grants"),
      ".fortress-ace.lock",
      async () => {
        acquired = true;
      },
      { timeoutMs: 300, retryMs: 20 }
    ).catch(() => {
      /* expected: CrossProcessLockError (held through the probe) */
    });
    expect(acquired).toBe(false);

    releaseProbe();
    const { enforcement } = await mintPromise;
    expect(enforcement).toBe("met");
  });

  it("fails CLOSED (never runs unlocked) when a permission anomaly blocks BOTH mkdir AND stat on a REAL fortress (round-5 close; bug-inject)", async () => {
    if (process.getuid?.() === 0) return; // root bypasses mode bits; anomaly not reproducible
    // A real, EXISTING fortress whose PARENT is unsearchable: mkdir(grants)
    // and stat(fortress) BOTH EACCES, yet the fortress path exists. The lock
    // must NOT mistake "cannot observe" for "absent" and run the critical
    // section unlocked (a fail-OPEN of serialization).
    const parent = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-perm-"));
    const fortress = join(parent, "fortress");
    await mkdir(fortress);
    await chmod(parent, 0o000); // remove search/traverse on the parent
    try {
      const seen: FileGrantExecCommand[] = [];
      const fsOps = new PosixFileGrantFsOps(fortress, {
        platform: "linux",
        execRunner: {
          execFile: async (command) => {
            seen.push(command);
            return { stdout: "", stderr: "" };
          },
        },
      });

      const result = await fsOps.grantAgentRead("agent-1/fg_x", 502, pinnedSource());

      // Fail-closed: the apply reports a non-applied status and the critical
      // section never entered (zero exec commands ran). On dc73884d the EACCES
      // stat collapsed to "absent" -> degraded UNLOCKED -> status "applied" and
      // commands recorded, so this bug-injects.
      expect(result.status).not.toBe("applied");
      expect(seen).toHaveLength(0);
    } finally {
      await chmod(parent, 0o700);
      await rm(parent, { recursive: true, force: true });
    }
  });

  it("still takes the unit-rig UNLOCKED path when the fortress is genuinely absent (ENOENT); does not over-tighten", async () => {
    // A synthetic, non-existent fortress: mkdir(grants) fails and stat(fortress)
    // -> ENOENT (provably absent) -> the intended unit-rig unlocked fallback
    // still runs the operation (commands recorded), so the rigs are not broken.
    const seen: FileGrantExecCommand[] = [];
    const fsOps = new PosixFileGrantFsOps("/fortress-does-not-exist-xyz", {
      platform: "linux",
      execRunner: {
        execFile: async (command) => {
          seen.push(command);
          return { stdout: "", stderr: "" };
        },
      },
    });

    const result = await fsOps.grantAgentRead("agent-1/fg_x", 502, pinnedSource());

    expect(result.status).toBe("applied");
    expect(seen.length).toBeGreaterThan(0);
    expect(seen[0]).toEqual({
      file: "setfacl",
      args: ["-m", "u:502:--x", "/fortress-does-not-exist-xyz"],
    });
  });

  it("macOS: keeps the fortress-dir traverse ACE while the agent has another active grant, and removes it once drained (F1 fix)", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-mac-lifecycle-"));
    const originDir = join(fortress, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 })
    );

    const treeEntryA = "agent-1/fg_a";
    const treeEntryB = "agent-1/fg_b";
    const trustedPathA = join(fortress, "grants", treeEntryA);
    const trustedPathB = join(fortress, "grants", treeEntryB);
    await mkdir(join(fortress, "grants", "agent-1"), { recursive: true });
    await writeFile(trustedPathA, "a");
    await writeFile(trustedPathB, "b");

    const identityA: FileGrantSourceIdentity = { source_dev: "11", source_ino: "22" };
    const identityB: FileGrantSourceIdentity = { source_dev: "11", source_ino: "33" };
    const exec = makeRecordingExecRunner();
    const macAclLinkOps: FileGrantMacAclLinkOps = {
      link: async () => {},
      open: async (path): Promise<FileGrantOpenedFile> => {
        const identity = path === trustedPathA ? identityA : identityB;
        return {
          stat: async () => ({
            dev: BigInt(identity.source_dev),
            ino: BigInt(identity.source_ino),
            uid: 501n,
            isFile: () => true,
          }),
          close: async () => {},
        };
      },
      rm: async () => {},
    };
    const fsOps = new PosixFileGrantFsOps(fortress, {
      platform: "darwin",
      execRunner: exec.runner,
      macAclLinkOps,
    });

    const aceA = {
      agent_uid: 502,
      platform: "darwin" as const,
      source_realpath: "/operator/a.txt",
      source_dev: identityA.source_dev,
      source_ino: identityA.source_ino,
      mac_principal: "agentuser",
      mac_acl_hardlink_path: trustedPathA,
    };
    const aceB = {
      agent_uid: 502,
      platform: "darwin" as const,
      source_realpath: "/operator/b.txt",
      source_dev: identityB.source_dev,
      source_ino: identityB.source_ino,
      mac_principal: "agentuser",
      mac_acl_hardlink_path: trustedPathB,
    };

    // Revoking the FIRST grant leaves the agent's SECOND grant active, so the
    // fortress-dir ACE must stay in place.
    const first = await fsOps.removeEntry(treeEntryA, { grantedReadAce: aceA });
    expect(first.treeEntryRemoved).toBe(true);
    expect(first.aclRemoval.status).toBe("removed");
    expect(exec.commands).not.toContainEqual({
      file: "chmod",
      args: ["-a", "user:agentuser allow execute", fortress],
    });

    // Revoking the LAST (second) grant drains the whole tree: the fortress
    // ACE is removed too, not left as a standing orphan.
    const second = await fsOps.removeEntry(treeEntryB, { grantedReadAce: aceB });
    expect(second.treeEntryRemoved).toBe(true);
    expect(second.aclRemoval.status).toBe("removed");
    expect(exec.commands).toContainEqual({
      file: "chmod",
      args: ["-a", "user:agentuser allow execute", fortress],
    });
  });
});
