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
  it("builds Linux setfacl grant commands with execute-only ancestors and read/traverse leaf", () => {
    expect(buildLinuxGrantAgentReadCommands("/fortress/grants", "agent-1/nested/fg_abc", 502)).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1/nested"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/fortress/grants/agent-1/nested/fg_abc"] },
    ]);
  });

  it("builds Linux setfacl revoke commands that remove the uid entry from leaf and ancestors", () => {
    expect(buildLinuxRevokeAgentReadCommands("/fortress/grants", "agent-1/fg_abc", 502)).toEqual([
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants/agent-1/fg_abc"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants"] },
    ]);
  });

  it("builds macOS chmod grant commands with execute-only ancestors and read/execute leaf", () => {
    expect(buildMacGrantAgentReadCommands("/fortress/grants", "agent-1/nested/fg_abc", "agentuser")).toEqual([
      { file: "chmod", args: ["+a", "user:agentuser allow execute", "/fortress/grants"] },
      { file: "chmod", args: ["+a", "user:agentuser allow execute", "/fortress/grants/agent-1"] },
      {
        file: "chmod",
        args: ["+a", "user:agentuser allow execute", "/fortress/grants/agent-1/nested"],
      },
      {
        file: "chmod",
        args: ["+a", "user:agentuser allow read,execute", "/fortress/grants/agent-1/nested/fg_abc"],
      },
    ]);
  });

  it("builds macOS chmod revoke commands that remove the exact ACEs", () => {
    expect(buildMacRevokeAgentReadCommands("/fortress/grants", "agent-1/fg_abc", "agentuser")).toEqual([
      {
        file: "chmod",
        args: ["-a", "user:agentuser allow read,execute", "/fortress/grants/agent-1/fg_abc"],
      },
      { file: "chmod", args: ["-a", "user:agentuser allow execute", "/fortress/grants/agent-1"] },
      { file: "chmod", args: ["-a", "user:agentuser allow execute", "/fortress/grants"] },
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

    const result = await fsOps.grantAgentRead("agent-1/fg_abc", 502);

    expect(result.status).toBe("failed");
    expect(seen).toEqual([
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants"] },
      { file: "setfacl", args: ["-m", "u:502:--x", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-m", "u:502:rX", "/fortress/grants/agent-1/fg_abc"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants/agent-1/fg_abc"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants/agent-1"] },
      { file: "setfacl", args: ["-x", "u:502", "/fortress/grants"] },
    ]);
  });
});
