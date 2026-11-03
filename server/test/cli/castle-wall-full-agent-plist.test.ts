/** Fixed user-session supervision contract. Job 996. */
import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it } from "vitest";
const modulePath = "../../src/cli/castle-wall-full-agent.js";
const statePath = "../../src/cli/castle-wall-full-agent-state.js";
const api = await import(modulePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent.js") | null;
const state = await import(statePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
beforeEach(() => { expect(api, "LaunchAgent renderer is shipped").not.toBeNull(); expect(state).not.toBeNull(); });
const args = ["/usr/local/bin/node", "/opt/sanctuary/cli.js", "castle-wall", "daemon", "--fortress", "/Users/operator/Fortress", "--launch-agent"];
describe("full agent plist", () => {
  it("matches the golden bytes and the restart budget", () => {
    const plist = api!.generateFullAgentPlist(args);
    expect(plist).toBe(readFileSync(new URL("./fixtures/castle-wall-full-agent.golden.plist", import.meta.url), "utf8"));
    expect(api!.fullAgentLaunchAgentWellFormed(plist)).toBe(true);
    expect(api!.FULL_AGENT_THROTTLE_INTERVAL_S + state!.FULL_AGENT_START_TO_ARMED_BUDGET_S).toBe(state!.FULL_AGENT_RESTART_BUDGET_S);
  });
  it.each([
    ["KeepAlive true", (s: string) => s.replace("\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>", "\t<true/>")],
    ["missing SuccessfulExit", (s: string) => s.replace("<key>SuccessfulExit</key>", "<key>NetworkState</key>")],
    ["missing launch flag", (s: string) => s.replace("--launch-agent", "--launchd")],
    ["forbidden environment", (s: string) => s.replace("<key>PATH</key>", "<key>SANCTUARY_PASSPHRASE</key>")],
    ["relative interpreter", (s: string) => s.replace("/usr/local/bin/node", "node")],
    ["relative CLI", (s: string) => s.replace("/opt/sanctuary/cli.js", "cli.js")],
    ["relative fortress", (s: string) => s.replaceAll("/Users/operator/Fortress", "Fortress")],
    ["wrong throttle", (s: string) => s.replace("<integer>5</integer>", "<integer>6</integer>")],
  ] as const)("rejects %s", (_name, change) => {
    expect(api!.fullAgentLaunchAgentWellFormed(change(api!.generateFullAgentPlist(args)))).toBe(false);
  });
  it("renders escaped paths and refuses relative paths at construction", () => {
    const escaped = [...args]; escaped[5] = "/Users/operator/A&B";
    expect(api!.fullAgentLaunchAgentWellFormed(api!.generateFullAgentPlist(escaped))).toBe(true);
    const relative = [...args]; relative[5] = "Fortress";
    expect(() => api!.generateFullAgentPlist(relative)).toThrow();
  });
});
