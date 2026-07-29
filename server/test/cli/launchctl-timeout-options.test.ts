import { afterEach, describe, expect, it, vi } from "vitest";

describe("launchctl wrappers pass bounded subprocess options", () => {
  afterEach(() => {
    vi.doUnmock("node:child_process");
    vi.resetModules();
  });

  it("castle-wall boot default launchctl wrapper passes timeout and SIGKILL to spawnSync", async () => {
    vi.resetModules();
    const spawnSync = vi.fn(() => ({
      status: null,
      stdout: "",
      stderr: "",
      error: Object.assign(new Error("spawnSync launchctl ETIMEDOUT"), { name: "Error" }),
    }));
    vi.doMock("node:child_process", () => ({ spawnSync }));

    const {
      bootServiceLoaded,
      CASTLE_WALL_BOOT_LABEL,
      LAUNCHCTL_TIMEOUT_MS,
      LAUNCHCTL_KILL_SIGNAL,
    } = await import("../../src/cli/castle-wall-boot.js");

    bootServiceLoaded();

    expect(spawnSync).toHaveBeenCalledWith(
      "launchctl",
      ["print", `system/${CASTLE_WALL_BOOT_LABEL}`],
      expect.objectContaining({
        encoding: "utf8",
        timeout: LAUNCHCTL_TIMEOUT_MS,
        killSignal: LAUNCHCTL_KILL_SIGNAL,
      }),
    );
  });
});
