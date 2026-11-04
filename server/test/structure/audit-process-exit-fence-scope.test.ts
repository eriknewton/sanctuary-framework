/** Daemon-only fence opt-in and unchanged ordinary audit composition. Job 996. */
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
const source = new URL("../../src/", import.meta.url).pathname;
function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(dir, entry.name)) : entry.name.endsWith(".ts") ? [join(dir, entry.name)] : []);
}
describe("audit exit fence scope", () => {
  it("has a wired daemon consumer and no unapproved source consumer", () => {
    const daemon = readFileSync(join(source, "cli/castle-wall.ts"), "utf8");
    const start = daemon.indexOf("export async function runDaemon(");
    const body = daemon.slice(start, daemon.indexOf("\n}\n", start) + 2);
    expect(body).toContain("processExitFence: WALL_DAEMON_AUDIT_EXIT_FENCE");
    expect(body).toContain("auditLog.processExitFence !== WALL_DAEMON_AUDIT_EXIT_FENCE");
    const allowed = new Set(["operational/audit-log.ts", "cli/castle-wall.ts", "cli/castle-wall-full-agent-state.ts", "cli/castle-wall-full-agent.ts"]);
    const consumers = files(source).filter(path => /\bprocessExitFence\b/.test(readFileSync(path, "utf8"))).map(path => relative(source, path));
    expect(consumers.filter(path => !allowed.has(path))).toEqual([]);
    for (const path of ["index.ts", "hermes-memory-bridge/process-shell.ts"]) {
      expect(readFileSync(join(source, path), "utf8")).not.toContain("processExitFence");
    }
  });
});
