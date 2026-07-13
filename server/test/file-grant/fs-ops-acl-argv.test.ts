/**
 * Command construction tests for the file-grant ACL primitive.
 *
 * These are pure argv-shape tests. They do not execute setfacl, chmod, sudo,
 * or any other host command.
 */

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  AGENT_READ_PROBE_SCRIPT,
  buildAgentReadProbeCommand,
  buildLinuxGrantAgentReadCommands,
  buildLinuxRevokeAgentReadCommands,
  buildMacGrantAgentReadCommands,
  buildMacRevokeAgentReadCommands,
  PosixFileGrantFsOps,
  type FileGrantExecCommand,
} from "../../src/file-grant/fs-ops.js";
import type { FileGrantPinnedSource } from "../../src/file-grant/types.js";

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

  it("builds macOS chmod grant commands with execute-only ancestors and read/execute leaf", () => {
    expect(
      buildMacGrantAgentReadCommands(
        "/fortress/grants",
        "agent-1/nested/fg_abc",
        "agentuser",
        "/operator/source.txt"
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
        args: ["+a", "user:agentuser allow read,execute", "/operator/source.txt"],
      },
    ]);
  });

  it("builds macOS chmod revoke commands that remove only the persisted source leaf ACE", () => {
    expect(buildMacRevokeAgentReadCommands("agentuser", "/operator/source.txt")).toEqual([
      {
        file: "chmod",
        args: ["-a", "user:agentuser allow read,execute", "/operator/source.txt"],
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
