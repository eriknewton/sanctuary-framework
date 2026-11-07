import { afterEach, describe, expect, it, vi } from "vitest";

const dispatch = vi.hoisted(() => ({ run: vi.fn(), boot: vi.fn(), dashboard: vi.fn() }));
vi.mock("../../src/dashboard-standalone.js", () => ({ startStandaloneDashboard: dispatch.dashboard }));
vi.mock("../../src/index.js", () => ({ createSanctuaryServer: dispatch.boot }));
vi.mock("../../src/mcp-child-fortress-refusal.js", () => ({ refuseMissingMcpChildFortressOrExit: async () => undefined }));
vi.mock("../../src/cli/memory-archive.js", () => ({ runMemoryArchiveExportCommand: dispatch.run }));

const argv = process.argv;
afterEach(() => {
  process.argv = argv;
  vi.restoreAllMocks();
  dispatch.run.mockReset();
  dispatch.boot.mockReset();
  dispatch.dashboard.mockReset();
});

// The rejection is built after the module reset, so its class is the one the freshly imported entry handler checks.
async function runEntry(
  args: string[],
  target: typeof dispatch.run,
  makeError: () => Promise<unknown>,
): Promise<{ printed: ReturnType<typeof vi.spyOn>; exit: ReturnType<typeof vi.spyOn>; error: unknown }> {
  vi.resetModules();
  const error = await makeError();
  target.mockRejectedValue(error);
  process.argv = [argv[0], "sanctuary", ...args];
  const printed = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const exited = new Error("fixture exit");
  const exit = vi.spyOn(process, "exit").mockImplementation(() => { throw exited; });
  const { cliEntryInvocation } = await import("../../src/cli.js");
  await expect(cliEntryInvocation).rejects.toBe(exited);
  return { printed, exit, error };
}

// Compared by identity only: a deep matcher would read the hostile fixture's getter itself.
function expectPrintedOnce(printed: ReturnType<typeof vi.spyOn>, message: string, error: unknown): void {
  expect(printed.mock.calls).toHaveLength(1);
  expect(printed.mock.calls[0][0]).toBe(message);
  expect(printed.mock.calls[0][1]).toBe(error);
}

describe("top-level cleanup failure reporting", () => {
  it.each([
    "establishment release", "CLI finalization", "lease close", "lease deadline", "nested archive cleanup",
    "ordinary error", "ordinary aggregate", "lock contention", "untyped release wording", "flush-only finalization",
  ])("reports %s through the real entry handler", async kind => {
    vi.resetModules();
    const { MasterEstablishmentReleaseError, CLI_FINALIZATION_ERROR_MESSAGE } = await import("../../src/core/master-custody.js");
    const { CrossProcessLockError } = await import("../../src/storage/cross-process-lock.js");
    const operation = new Error("fixture operation");
    const release = new CrossProcessLockError("custody lock listener close failed", "io");
    const cleanup = ["establishment release", "CLI finalization", "lease close", "lease deadline", "nested archive cleanup"].includes(kind);
    const error = kind === "establishment release"
      ? new MasterEstablishmentReleaseError([operation, new Error("fixture release")], "fixture establishment")
      : kind === "CLI finalization"
        ? new AggregateError([operation, release], CLI_FINALIZATION_ERROR_MESSAGE)
        : kind === "lease close" ? release
          : kind === "lease deadline"
            // One millisecond is a diagnostic fixture value; no timer runs in this test.
            ? new CrossProcessLockError("process-owned custody lock listener did not close within 1ms", "holder-lost")
            : kind === "nested archive cleanup"
              ? new AggregateError([operation, new AggregateError([release], "fixture lease grouping")], "Memory archive cleanup encountered errors")
              : kind === "ordinary aggregate" ? new AggregateError([operation], "fixture ordinary aggregate")
                : kind === "lock contention" ? new CrossProcessLockError("fixture busy", "contention")
                  : kind === "untyped release wording" ? new Error(release.message)
                    // The release succeeded and only the final flush failed, so custody was released.
                    : kind === "flush-only finalization" ? new AggregateError([operation, new Error("fixture flush")], CLI_FINALIZATION_ERROR_MESSAGE)
                      : operation;
    dispatch.run.mockRejectedValue(error);
    process.argv = [argv[0], "sanctuary", "memory_archive_export"];
    const printed = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const exited = new Error("fixture exit");
    const exit = vi.spyOn(process, "exit").mockImplementation(() => { throw exited; });
    const { cliEntryInvocation } = await import("../../src/cli.js");
    await expect(cliEntryInvocation).rejects.toBe(exited);
    expect(dispatch.run).toHaveBeenCalled();
    expect(printed).toHaveBeenCalledExactlyOnceWith(cleanup
      ? "Fortress custody could not be released cleanly; any work the command already reported as complete was committed."
      : "Sanctuary MCP Server failed to start:", error);
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("keeps the start-failure message when server boot fails to release custody", async () => {
    const { printed, exit, error } = await runEntry([], dispatch.boot, async () => {
      const { MasterEstablishmentReleaseError } = await import("../../src/core/master-custody.js");
      return new MasterEstablishmentReleaseError([new Error("fixture boot"), new Error("fixture release")], "fixture establishment");
    });
    expect(dispatch.boot).toHaveBeenCalled();
    expectPrintedOnce(printed, "Sanctuary MCP Server failed to start:", error);
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("keeps the start-failure message when the standalone dashboard fails to release custody", async () => {
    const { printed, exit, error } = await runEntry(["dashboard"], dispatch.dashboard, async () => {
      const { MasterEstablishmentReleaseError } = await import("../../src/core/master-custody.js");
      return new MasterEstablishmentReleaseError([new Error("fixture dashboard"), new Error("fixture release")], "fixture establishment");
    });
    expect(dispatch.dashboard).toHaveBeenCalled();
    expectPrintedOnce(printed, "Sanctuary MCP Server failed to start:", error);
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("keeps the original diagnostic and exit when classification itself throws", async () => {
    const { printed, exit, error } = await runEntry(["memory_archive_export"], dispatch.run, async () => {
      const hostile = new AggregateError([], "fixture hostile aggregate");
      Object.defineProperty(hostile, "errors", { get() { throw new Error("fixture hostile getter"); } });
      return hostile;
    });
    expect(dispatch.run).toHaveBeenCalled();
    expectPrintedOnce(printed, "Sanctuary MCP Server failed to start:", error);
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
});
