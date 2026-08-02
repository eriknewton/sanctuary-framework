export const DEFAULT_HTTP_SHUTDOWN_GRACE_MS = 5_000;

const DEFAULT_FORCE_CLOSE_SETTLE_MS = 1_000;

export interface HttpServerLifecycleTarget {
  close(callback?: (err?: Error) => void): unknown;
  closeAllConnections?: () => void;
  closeIdleConnections?: () => void;
  on(event: "error", listener: (err: unknown) => void): unknown;
}

export interface CloseHttpServerOptions {
  label: string;
  graceMs?: number;
  forceCloseSettleMs?: number;
}

function normalizedDelayMs(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.max(0, value);
}

export function forceCloseHttpServer(
  server: HttpServerLifecycleTarget,
): void {
  try {
    server.closeIdleConnections?.();
  } catch {
    // Best-effort shutdown path; closeAllConnections is attempted next.
  }
  try {
    server.closeAllConnections?.();
  } catch {
    // Best-effort shutdown path; the caller still waits on server.close().
  }
}

export async function cleanupFailedHttpServer(
  server: HttpServerLifecycleTarget,
): Promise<void> {
  forceCloseHttpServer(server);
  await new Promise<void>((resolve) => {
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

export function attachPostListenHttpServerErrorLogger(
  server: HttpServerLifecycleTarget,
  label: string,
): void {
  server.on("error", (err) => {
    const detail = err instanceof Error ? err.message : String(err);
    // SAFETY: stderr is the operator-facing lifecycle fault channel for these
    // dashboard servers; this does not include request bodies or secret state.
    process.stderr.write(
      `\n  SAFETY: ${label} emitted a post-listen server error; ` +
        `the process is staying alive. ${detail}\n`,
    );
  });
}

export async function closeHttpServer(
  server: HttpServerLifecycleTarget,
  options: CloseHttpServerOptions,
): Promise<void> {
  const graceMs = normalizedDelayMs(
    options.graceMs,
    DEFAULT_HTTP_SHUTDOWN_GRACE_MS,
  );
  const forceCloseSettleMs = normalizedDelayMs(
    options.forceCloseSettleMs,
    DEFAULT_FORCE_CLOSE_SETTLE_MS,
  );

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let forceTimer: ReturnType<typeof setTimeout> | null = null;
    let settleTimer: ReturnType<typeof setTimeout> | null = null;

    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      if (forceTimer) clearTimeout(forceTimer);
      if (settleTimer) clearTimeout(settleTimer);
      if (err) reject(err);
      else resolve();
    };

    forceTimer = setTimeout(() => {
      forceCloseHttpServer(server);
      settleTimer = setTimeout(() => finish(), forceCloseSettleMs);
    }, graceMs);

    try {
      server.close((err?: Error) => finish(err));
    } catch (err) {
      finish(err instanceof Error ? err : new Error(String(err)));
    }
  });
}
