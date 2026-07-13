/**
 * Command construction tests for the file-grant ACL primitive.
 *
 * These are pure argv-shape tests. They do not execute setfacl, chmod, sudo,
 * or any other host command.
 */

import { constants as fsConstants } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import {
  AGENT_READ_PROBE_SCRIPT,
  buildAgentReadProbeCommand,
  buildLinuxGrantAgentReadCommands,
  buildLinuxRevokeAgentReadCommands,
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
      { path: trustedPath, flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW },
      { path: trustedPath, flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW },
    ]);
    expect(exec.commands).toEqual([
      { file: "id", args: ["-nu", "502"] },
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
      { path: trustedPath, flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW },
      { path: trustedPath, flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW },
    ]);
    await expect(readFile(trustedPath, "utf-8")).rejects.toThrow();
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
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/proc/test/fd/9"] },
      { file: "setfacl", args: ["-x", "u:502", "/proc/test/fd/9"] },
    ]);
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
});
