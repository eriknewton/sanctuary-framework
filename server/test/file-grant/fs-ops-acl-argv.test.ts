/**
 * Command construction tests for the file-grant ACL primitive.
 *
 * These are pure argv-shape tests. They do not execute setfacl, chmod, sudo,
 * or any other host command.
 */

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
    expect(buildAgentReadProbeCommand("/fortress/grants", "agent-1/fg_abc", 502, "/node")).toEqual({
      file: "sudo",
      args: [
        "-n",
        "-u",
        "#502",
        "/node",
        "-e",
        AGENT_READ_PROBE_SCRIPT,
        "/fortress/grants/agent-1/fg_abc",
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

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, "/operator/source.txt");

    expect(result.status).toBe("failed");
    expect(seen).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/operator/source.txt"] },
      { file: "setfacl", args: ["-x", "u:502", "/operator/source.txt"] },
    ]);
  });

  it("grantAgentRead applies the leaf ACL to source realpath, not the grant-tree symlink", async () => {
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

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502, "/operator/source.txt");

    expect(result.status).toBe("applied");
    expect(result.grantedReadAce).toEqual({
      agent_uid: 502,
      platform: "linux",
      source_realpath: "/operator/source.txt",
    });
    expect(seen).toContainEqual({
      file: "setfacl",
      args: ["-m", "u:502:rX", "/operator/source.txt"],
    });
    expect(seen).not.toContainEqual({
      file: "setfacl",
      args: ["-m", "u:502:rX", "/fortress/grants/agent-1/fg_abc"],
    });
  });

  it("removeEntry removes the persisted uid source ACE even when no descriptor exists", async () => {
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
        source_realpath: "/operator/source.txt",
      },
    });

    expect(result).toEqual({
      treeEntryRemoved: false,
      aclRemoval: {
        status: "removed",
        agent_uid: 502,
        platform: "linux",
        source_realpath: "/operator/source.txt",
      },
      scrubbed: true,
    });
    expect(seen).toEqual([
      { file: "setfacl", args: ["-x", "u:502", "/operator/source.txt"] },
    ]);
  });
});
