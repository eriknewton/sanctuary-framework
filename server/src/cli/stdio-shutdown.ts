/** CLI-owned idle shutdown. Embedding createSanctuaryServer owns no signals. */
export function installStdioShutdown(
  server: { onclose?: () => void },
  cleanup: () => Promise<void>,
  watchdogMs = 10_000,
): () => Promise<void> {
  let shutdownPromise: Promise<void> | undefined;
  const shutdown = (): Promise<void> => {
    // Cache before cleanup can synchronously reenter through server.onclose.
    shutdownPromise ??= Promise.resolve().then(async () => {
      const watchdog = setTimeout(() => {
        // SAFETY: stderr is the operator-facing CLI channel.
        console.error(`Sanctuary MCP Server: shutdown did not complete in ${String(watchdogMs)}ms; forcing exit.`);
        process.exit(1);
      }, watchdogMs);
      try {
        await cleanup();
      } catch (error) {
        // SAFETY: stderr is the operator-facing CLI channel.
        console.error("Sanctuary MCP Server: shutdown error:", error);
        process.exitCode = 1;
      } finally {
        // Remain armed for leaked refed handles, without delaying natural exit.
        watchdog.unref();
      }
    });
    return shutdownPromise;
  };
  const trigger = (): void => { void shutdown(); };
  // The SDK transport does not translate stdin EOF into onclose.
  process.stdin.on("end", trigger);
  server.onclose = trigger;
  process.on("SIGTERM", trigger);
  process.on("SIGINT", trigger);
  if (process.stdin.readableEnded) trigger();
  return shutdown;
}
