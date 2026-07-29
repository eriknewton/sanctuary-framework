/**
 * Test infrastructure: retry-on-EADDRINUSE helper for tests that bind HTTP
 * listeners to randomly chosen ports.
 *
 * Background. Several integration tests boot a Node http server on a port
 * picked uniformly at random in a wide range. Under parallel CI workers two
 * test files occasionally pick the same port in the same window and one
 * worker hits EADDRINUSE. The flakes are rare per run but accumulate over
 * weeks. The structurally correct alternative (bind to port 0 and read the
 * OS-assigned port back from server.address()) does not work cleanly here
 * because the systems-under-test bake the supplied port into URLs they
 * construct at boot (e.g. WebhookApprovalChannel embeds callback_port in
 * outbound payloads, DashboardApprovalChannel embeds it in selfOrigin and
 * one-click session URLs). Refactoring those code paths to support port-0
 * readback rippled wider than this housekeeping PR; bounded retries on
 * EADDRINUSE in test-side setup gives the same race-resistance with zero
 * production-code change.
 *
 * Usage. Wrap the listener-bind in bindWithRetry and have the inner setup
 * acquire its port(s) via randomTestPort() each attempt. On EADDRINUSE the
 * helper sleeps a short jittered interval and re-runs setup with fresh
 * ports. Any partial state from a failed attempt should be torn down inside
 * the inner setup (try/catch around the second listener) before re-throwing
 * so the next attempt starts clean.
 */

export interface BindWithRetryOptions {
  /** Maximum retries after the first attempt. Defaults to 3. */
  maxRetries?: number;
  /** Upper bound on the jittered sleep between attempts, in ms. Defaults to 100. */
  jitterMs?: number;
}

/**
 * Pick a port uniformly at random in the 10000-59999 range. Exclude ports
 * Node's Fetch rejects as unsafe before the request reaches the local test
 * server; in this range the practical offender is 10080.
 */
export function randomTestPort(): number {
  let port = 10000 + Math.floor(Math.random() * 50000);
  while (port === 10080) {
    port = 10000 + Math.floor(Math.random() * 50000);
  }
  return port;
}

/**
 * Run setup() and retry on EADDRINUSE up to maxRetries times. Other errors
 * propagate immediately. The setup function must perform its own teardown
 * of any partial listener state before throwing so retries do not leak file
 * descriptors.
 */
export async function bindWithRetry<T>(
  setup: () => Promise<T>,
  options: BindWithRetryOptions = {},
): Promise<T> {
  const { maxRetries = 3, jitterMs = 100 } = options;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await setup();
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EADDRINUSE") {
        throw err;
      }
      lastErr = err;
      if (attempt < maxRetries) {
        await new Promise((resolve) =>
          setTimeout(resolve, Math.random() * jitterMs),
        );
      }
    }
  }
  throw lastErr;
}
