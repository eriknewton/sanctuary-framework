# Test port discipline (Sigma-6)

This document describes the rule of thumb every Sanctuary test file
must follow when binding a TCP listener (HTTP server, websocket, raw
TCP). It is enforced structurally by a regression test that scans the
test tree on every `npm test` run; it is documented here so that a
contributor reading a failure understands why and how to fix.

## The rule

Every `.listen()` call in `server/test/` must satisfy one of:

1. **Ephemeral.** `.listen(0, ...)` lets the OS pick an available
   port. Read the assigned port back via `server.address().port` and
   feed it into any URL the test constructs. This is the
   structurally correct pattern when the systems-under-test do not
   bake the port into outbound payloads or self-origin URLs.

2. **Retry-wrapped.** Wrap the bind in `bindWithRetry` from
   `server/test/util/port-collision-retry.ts`. The helper picks a
   random port (`randomTestPort()`), runs the supplied setup, and
   retries on `EADDRINUSE` with a fresh port. Use this when the SUT
   embeds the port in its config (e.g. `DashboardApprovalChannel`
   embeds `port` in self-origin URLs and one-click session URLs;
   `WebhookApprovalChannel` embeds it in outbound payloads).

3. **Explicit whitelist.** Annotate the line with
   `// port-discipline: ignore — <reason>`. The annotation may be on
   the same line or on the immediately preceding line. Only use this
   when a fixed port is genuinely required (e.g. asserting a
   default-config string contains a known port number) and the
   listener never actually binds.

## Why this exists

The `dashboard.test.ts:rate-limiting` suite hit 9-10
`EADDRINUSE`-driven CI flake incidents across the v1.2.x / v1.3.x
build cascades (iterations 2-6). Each one cost a `gh run rerun
--failed` and a coordinator-side retry decision. The root cause was
the same in every incident: the test picked a random port in
`10000-59999`, and another worker in the vitest pool (or a stale
process from a prior run) had already bound that port.

The fix landed in this PR rewires `dashboard.test.ts` to use
`bindWithRetry` (already established for `webhook.test.ts`) and adds
this regression gate so the pattern can't silently regress.

## Cross-references

- `server/test/util/port-collision-retry.ts` — the `bindWithRetry`
  helper itself.
- `server/scripts/test-port-discipline.ts` — the scanner that
  enforces this rule on every `npm test` run.
- `server/test/scripts/test-port-discipline.test.ts` — the
  vitest regression suite that drives the scanner.
- `server/docs/test-concurrency-discipline.md` — sibling
  discipline for perf-bound tests that flake under vitest worker
  concurrency.
- `server/docs/perf-calibration.md` — Sigma-4 perf-calibration
  notes (D5 production-pipeline p99 bound origin).

## Adding a new test that binds a port

If you can use ephemeral allocation, do that:

```ts
import { createServer } from "node:http";

const server = createServer(handler);
await new Promise<void>((resolve) =>
  server.listen(0, "127.0.0.1", () => resolve()),
);
const addr = server.address();
if (!addr || typeof addr !== "object") throw new Error("no address");
const url = `http://127.0.0.1:${addr.port}`;
```

If your SUT embeds the port in its config, use `bindWithRetry`:

```ts
import { bindWithRetry, randomTestPort } from "../util/port-collision-retry.js";
import { MyService } from "../../src/my-service.js";

let port: number;
let service: MyService;

beforeEach(async () => {
  await bindWithRetry(async () => {
    port = randomTestPort();
    service = new MyService({ port, host: "127.0.0.1" });
    await service.start();
  });
});
```

If you genuinely need a fixed port (rare — usually a fixture string
asserting default config), whitelist it explicitly:

```ts
// port-discipline: ignore — asserting the default-config dashboard port string
expect(config.dashboard.port).toBe(3501);
```
