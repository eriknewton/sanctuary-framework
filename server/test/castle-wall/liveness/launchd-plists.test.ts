/** Canary and observer property lists, their well-formed checks, and the system-domain print parser. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ACCOUNT_NAME_MAX,
  CANARY_CURL_DEADLINE_S,
  CANARY_IP,
  CANARY_LABEL,
  CANARY_PORT,
  CANARY_START_INTERVAL_S,
  OBSERVER_LABEL,
  WATCH_THROTTLE_INTERVAL_S,
} from "../../../src/castle-wall/liveness/constants.js";
import {
  CANARY_PLIST_BYTES,
  CANARY_PROGRAM_ARGUMENTS,
  generateCanaryPlist,
  generateWatchAgentPlist,
  parseSystemJobPrint,
  systemJobNotFound,
  watchAgentLaunchAgentWellFormed,
} from "../../../src/castle-wall/liveness/launchd-plists.js";
import { CANARY_FIXTURE_ACCOUNT, renderCanaryGolden } from "../../../scripts/generate-canary-plist.js";

const FIXTURES = join(__dirname, "fixtures");
const GOLDEN = readFileSync(join(FIXTURES, "canary.golden.plist"), "utf8");
const GOLDEN_SHA = readFileSync(join(FIXTURES, "canary.golden.sha256"), "utf8").trim();
const OBSERVER_GOLDEN = readFileSync(join(FIXTURES, "observer.golden.plist"), "utf8");
const PRINTS = JSON.parse(readFileSync(join(FIXTURES, "launchctl-print.json"), "utf8")) as {
  entries: Record<string, { kind: string; code: number; stdout: string; stderr: string }>;
};
const keysOf = (plist: string): string[] => {
  // Top-level keys are the tab-indented ones directly under the outer dict.
  return [...plist.matchAll(/^\t<key>([^<]+)<\/key>$/gm)].map(m => m[1]!);
};
const FIXTURE_NODE = "/opt/homebrew/opt/node/bin/node";
const FIXTURE_CLI = "/opt/homebrew/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js";
const FIXTURE_FORTRESS = "/Users/operator-fixture/.sanctuary";
const watchArgs = (node = FIXTURE_NODE) => [node, FIXTURE_CLI, "castle-wall", "run-watch", "--fortress", FIXTURE_FORTRESS, "--launch-agent"];

describe("canary plist golden", () => {
  it("regenerates the golden fixture byte for byte with its SHA-256", () => {
    const plist = generateCanaryPlist(CANARY_FIXTURE_ACCOUNT);
    expect(plist).toBe(GOLDEN);
    expect(createHash("sha256").update(plist).digest("hex")).toBe(GOLDEN_SHA);
    const rendered = renderCanaryGolden();
    expect(rendered.plist).toBe(GOLDEN);
    expect(rendered.sha256).toBe(`${GOLDEN_SHA}\n`);
  });

  it("carries exactly the allowed keys in order and none of the refused keys", () => {
    expect(keysOf(GOLDEN)).toEqual(["Label", "UserName", "ProgramArguments", "StartInterval", "RunAtLoad", "ProcessType", "EnvironmentVariables"]);
    for (const refused of ["Program", "WorkingDirectory", "StandardOutPath", "StandardErrorPath", "KeepAlive"]) expect(GOLDEN).not.toContain(`<key>${refused}</key>`);
    expect(GOLDEN).toContain(`<string>${CANARY_LABEL}</string>`);
    expect(GOLDEN).toContain(`<integer>${CANARY_START_INTERVAL_S}</integer>`);
    expect(GOLDEN).toContain("\t<key>EnvironmentVariables</key>\n\t<dict/>\n");
  });

  it("names the fixed curl command with the constants substituted", () => {
    const deadline = String(CANARY_CURL_DEADLINE_S);
    expect([...CANARY_PROGRAM_ARGUMENTS]).toEqual([
      "/usr/bin/curl", "-q", "--noproxy", "*", "--retry", "0", "--output", "/dev/null", "--silent",
      "--connect-timeout", deadline, "--max-time", deadline, `http://${CANARY_IP}:${CANARY_PORT}/`,
    ]);
    const array = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(GOLDEN)![1]!;
    expect([...array.matchAll(/<string>([^<]*)<\/string>/g)].map(m => m[1])).toEqual([...CANARY_PROGRAM_ARGUMENTS]);
  });

  it("computes CANARY_PLIST_BYTES from the longest valid account name", () => {
    expect(CANARY_PLIST_BYTES).toBe(Buffer.byteLength(generateCanaryPlist("a".repeat(ACCOUNT_NAME_MAX))));
    expect(Buffer.byteLength(GOLDEN)).toBeLessThanOrEqual(CANARY_PLIST_BYTES);
  });
});

describe("canary account name", () => {
  it.each([
    ["ampersand", "agent&x"], ["less-than", "agent<x"], ["quote", 'agent"x'], ["space", "agent x"], ["tab", "agent\tx"],
    ["leading dash", "-agent"], ["empty", ""], ["too long", "a".repeat(ACCOUNT_NAME_MAX + 1)], ["slash", "agent/x"],
  ])("refuses a name with %s by throwing, never escaping", (_case, name) => {
    expect(() => generateCanaryPlist(name)).toThrow();
  });

  it("accepts the portable name forms", () => {
    for (const name of ["_agent", "sanctuary-agent.2", "A", "a".repeat(ACCOUNT_NAME_MAX)]) expect(generateCanaryPlist(name)).toContain(`<string>${name}</string>`);
  });
});

describe("observer LaunchAgent", () => {
  it("regenerates the golden with PATH as the only environment entry and no log paths", () => {
    const plist = generateWatchAgentPlist(watchArgs());
    expect(plist).toBe(OBSERVER_GOLDEN);
    expect(plist).not.toContain("StandardOutPath");
    expect(plist).not.toContain("StandardErrorPath");
    expect(keysOf(plist)).toEqual(["Label", "ProgramArguments", "RunAtLoad", "KeepAlive", "ThrottleInterval", "LimitLoadToSessionType", "EnvironmentVariables", "WorkingDirectory"]);
    expect(plist).toContain(`<string>${OBSERVER_LABEL}</string>`);
    expect(plist).toContain("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
    expect(plist).toContain(`<integer>${WATCH_THROTTLE_INTERVAL_S}</integer>`);
    expect(plist).toContain("\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n");
    const env = /<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(plist)![1]!;
    expect([...env.matchAll(/<key>([^<]+)<\/key>/g)].map(m => m[1])).toEqual(["PATH"]);
  });

  it("accepts the golden and refuses each forbidden key and a versioned or Cellar node", () => {
    expect(watchAgentLaunchAgentWellFormed(OBSERVER_GOLDEN)).toBe(true);
    const insert = (key: string, value: string) => OBSERVER_GOLDEN.replace("\t<key>WorkingDirectory</key>", `\t<key>${key}</key>\n\t${value}\n\t<key>WorkingDirectory</key>`);
    for (const [key, value] of [["StandardOutPath", "<string>/tmp/x</string>"], ["StandardErrorPath", "<string>/tmp/x</string>"], ["Program", "<string>/bin/sh</string>"], ["UserName", "<string>root</string>"]] as const) {
      expect(watchAgentLaunchAgentWellFormed(insert(key, value)), key).toBe(false);
    }
    for (const node of ["/opt/homebrew/Cellar/node/25.1.0/bin/node", "/Users/operator-fixture/.nvm/versions/node/v24/bin/node", "/opt/homebrew/node@24/bin/node"]) {
      expect(() => generateWatchAgentPlist(watchArgs(node)), node).toThrow();
      expect(watchAgentLaunchAgentWellFormed(OBSERVER_GOLDEN.split(FIXTURE_NODE).join(node)), node).toBe(false);
    }
    expect(watchAgentLaunchAgentWellFormed(generateWatchAgentPlist(watchArgs("/opt/homebrew/opt/node@24/bin/node")))).toBe(true);
  });

  it("refuses any argument list other than the run-watch shape", () => {
    expect(() => generateWatchAgentPlist([FIXTURE_NODE, FIXTURE_CLI, "castle-wall", "daemon", "--fortress", FIXTURE_FORTRESS, "--launch-agent"])).toThrow();
    expect(() => generateWatchAgentPlist(watchArgs().slice(0, 6))).toThrow();
    expect(() => generateWatchAgentPlist(["node", FIXTURE_CLI, "castle-wall", "run-watch", "--fortress", FIXTURE_FORTRESS, "--launch-agent"])).toThrow();
  });
});

describe("system-domain print parser", () => {
  it("reads pid, program, arguments and username from the captured shape", () => {
    const parsed = parseSystemJobPrint(PRINTS.entries.captured_system_running!.stdout);
    expect(parsed).toEqual({
      valid: true, pid: 75399, program: "/opt/agent-fixture/venv/bin/python",
      arguments: ["/opt/agent-fixture/venv/bin/python", "-m", "agent_fixture.main", "gateway", "run", "--accept-hooks"],
      username: "sanctuary-agent-fixture",
    });
  });

  it("reads the modelled wrapped canary print and ignores nested dictionaries", () => {
    const parsed = parseSystemJobPrint(PRINTS.entries.canary_system!.stdout);
    expect(parsed.valid).toBe(true);
    expect(parsed.program).toBe("/usr/bin/curl");
    expect(parsed.arguments).toEqual([...CANARY_PROGRAM_ARGUMENTS]);
    expect(parsed.username).toBe("sanctuary-agent-fixture");
    expect(parsed.pid).toBeNull();
    expect(parseSystemJobPrint(PRINTS.entries.harness_system!.stdout).pid).toBe(75400);
  });

  it("reads a duplicated field as unknown and refuses unbalanced text", () => {
    const text = PRINTS.entries.captured_system_running!.stdout;
    expect(parseSystemJobPrint(`${text}\tpid = 1\n`).pid).toBeNull();
    expect(parseSystemJobPrint(`${text}\tusername = root\n`).username).toBeNull();
    expect(parseSystemJobPrint("system/x = {\n\tpid = 5\n").valid).toBe(false);
    expect(parseSystemJobPrint("").valid).toBe(false);
    expect(parseSystemJobPrint("garbage\n").valid).toBe(false);
    expect(parseSystemJobPrint("system/x = {\n}\n").valid).toBe(false);
  });

  it("treats only the captured not-found outcome as not found", () => {
    const nf = PRINTS.entries.captured_system_not_found!;
    expect(systemJobNotFound(nf, CANARY_LABEL)).toBe(true);
    expect(systemJobNotFound({ ...nf, stdout: nf.stderr, stderr: "" }, CANARY_LABEL)).toBe(true);
    expect(systemJobNotFound({ ...nf, code: 1 }, CANARY_LABEL)).toBe(false);
    expect(systemJobNotFound({ ...nf, stderr: "Bad request.\n" }, CANARY_LABEL)).toBe(false);
    expect(systemJobNotFound({ code: 113, stdout: PRINTS.entries.canary_system!.stdout, stderr: nf.stderr }, CANARY_LABEL)).toBe(false);
    expect(systemJobNotFound({ ...nf, stderr: nf.stderr.replace(CANARY_LABEL, "other.label") }, CANARY_LABEL)).toBe(false);
  });
});
