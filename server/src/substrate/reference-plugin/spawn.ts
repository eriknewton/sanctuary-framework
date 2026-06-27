/**
 * Spawn the reference blocklist plugin and wrap its stdin/stdout in the host's
 * framed-JSON client (slice S5).
 *
 * IMPORTANT — confinement boundary: this helper spawns the plugin process DIRECTLY
 * (plain `node bin/blocklist.mjs`). It is the dev/CLI/test path that exercises the
 * WIRE CONTRACT (framing, verdict algebra, attribution). It does NOT apply the
 * seccomp/namespace jail — that is the Rust `sanctuary-plugin-launcher`'s job, and
 * the confinement guarantee is proven by the Linux hostile-probe drill
 * (test/substrate/reference-plugin/hostile-plugin.drill.test.ts), not by this path.
 * Production wiring routes the same plugin through the launcher; this helper is for
 * `sanctuary plugin test`, the e2e attribution test, and local liveness checks.
 */

import { spawn, type ChildProcess } from "node:child_process";

import { FramedJsonPluginClient, type PluginRuntimeClient } from "../supervisor.js";

export interface SpawnedPlugin {
  client: PluginRuntimeClient;
  child: ChildProcess;
  /** Terminate the plugin process and close the client. */
  close(): void;
}

/**
 * Spawn the reference plugin entry binary with a hardened, minimal environment.
 *
 * - no shell (argv array, never a command string)
 * - empty env (the plugin needs none; this matches the launcher's env-scrub posture)
 * - stdio: piped stdin/stdout for framing, inherited stderr for diagnostics
 */
export function spawnReferencePlugin(entryPath: string, nodeBin = process.execPath): SpawnedPlugin {
  const child = spawn(nodeBin, [entryPath], {
    stdio: ["pipe", "pipe", "ignore"],
    env: {},
  });
  if (!child.stdin || !child.stdout) {
    child.kill();
    throw new Error("reference plugin stdio pipes were not created");
  }
  const client = new FramedJsonPluginClient(child.stdin, child.stdout);
  return {
    client,
    child,
    close(): void {
      try {
        client.close?.();
      } finally {
        child.kill();
      }
    },
  };
}
