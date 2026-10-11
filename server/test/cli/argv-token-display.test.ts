/**
 * CLI refusals name the flag, never its value.
 *
 * Every operator-facing refusal for an unrecognized flag, option, argument,
 * or subcommand renders the offending argv token through the one shared
 * formatter in src/cli/argv.ts (`argvTokenForDisplay` /
 * `subcommandTokenForDisplay`). A refusal may print a flag name (the text
 * before `=`) or a verb-shaped subcommand word; it never prints the value
 * bound with `=`, a dash-leading token that is not shaped like a flag name,
 * or a positional value.
 *
 * Three layers, each over the full set:
 *   1. the formatter's own contract;
 *   2. a source census over every CLI module: each refusal template that
 *      interpolates must route the token through the formatter, or appear on
 *      an explicit allowlist with a reason (and every allowlist entry must
 *      still exist, so the list cannot rot);
 *   3. a behavioral table that drives every reachable refusal path with a
 *      `--flag=VALUE` token and a dash-leading value token, and asserts the
 *      value appears nowhere in what the operator sees (stdout, stderr,
 *      injected streams, console, and any thrown message the top-level
 *      printer would render).
 */

import { mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { Writable } from "node:stream";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  ARGV_TOKEN_NOT_SHOWN,
  argvTokenForDisplay,
  subcommandTokenForDisplay,
} from "../../src/cli/argv.js";
import { CLI_SUBPROCESS_TEST_TIMEOUT_MS, runCli } from "./helpers/run-cli";

// Must match ARGV_TOKEN_NOT_SHOWN in src/cli/argv.ts.
const EXPECTED_NOT_SHOWN = "<argument not shown>";

// The marker carries an uppercase run and digits so no token built from it
// has a flag-name or verb-word shape; a display rule that printed it would be
// printing operator data.
const MARK = "Zq9VALUEmark";
const FLAG_WITH_VALUE = `--zz-not-a-flag=${MARK}`;
const DASH_VALUE = `-${MARK}`;
const POSITIONAL_VALUE = MARK;
const DOUBLE_DASH_VALUE = `--${MARK}`;
const FORTRESS_FLAG_WITH_VALUE = `--fortress-zz=${MARK}`;
const FORTRESS_DASH_VALUE = `--fortress${MARK}`;

describe("argv token display formatter", () => {
  it("pins the placeholder text", () => {
    expect(ARGV_TOKEN_NOT_SHOWN).toBe(EXPECTED_NOT_SHOWN);
  });

  it("names a long flag and drops the value bound with =", () => {
    expect(argvTokenForDisplay("--name")).toBe("--name");
    expect(argvTokenForDisplay(`--output-file=${MARK}`)).toBe("--output-file");
    expect(argvTokenForDisplay("--a1-b2=x=y")).toBe("--a1-b2");
    expect(argvTokenForDisplay("-h")).toBe("-h");
  });

  it("does not print a dash-leading token that is not flag-shaped", () => {
    for (const token of [
      DASH_VALUE,
      `--${MARK}`,
      `--${MARK}=x`,
      "-abc",
      "--",
      "-",
      "--a b",
      "--a_b",
      "--a--b",
      "--a-",
      "---a",
    ]) {
      expect(argvTokenForDisplay(token), token).toBe(EXPECTED_NOT_SHOWN);
    }
  });

  it("never prints a positional value", () => {
    expect(argvTokenForDisplay(POSITIONAL_VALUE)).toBe(EXPECTED_NOT_SHOWN);
    expect(argvTokenForDisplay("claude-code")).toBe(EXPECTED_NOT_SHOWN);
    expect(argvTokenForDisplay("")).toBe(EXPECTED_NOT_SHOWN);
  });

  it("subcommand form prints verb-shaped words and follows the flag rule otherwise", () => {
    expect(subcommandTokenForDisplay("frobnicate")).toBe("frobnicate");
    expect(subcommandTokenForDisplay("operator-cloud")).toBe("operator-cloud");
    expect(subcommandTokenForDisplay("v2")).toBe("v2");
    expect(subcommandTokenForDisplay(undefined)).toBe(EXPECTED_NOT_SHOWN);
    expect(subcommandTokenForDisplay(POSITIONAL_VALUE)).toBe(EXPECTED_NOT_SHOWN);
    expect(subcommandTokenForDisplay("has space")).toBe(EXPECTED_NOT_SHOWN);
    expect(subcommandTokenForDisplay(FLAG_WITH_VALUE)).toBe("--zz-not-a-flag");
    expect(subcommandTokenForDisplay(DASH_VALUE)).toBe(EXPECTED_NOT_SHOWN);
  });
});

// ── Source census ────────────────────────────────────────────────────

const SERVER_ROOT = join(import.meta.dirname, "..", "..");
const SRC = join(SERVER_ROOT, "src");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

/** Every CLI module: src/cli/**, src/cli.ts, any src/**\/cli.ts, the offline verifier. */
function cliSourceFiles(): string[] {
  const all = walk(SRC);
  return all
    .filter((p) => {
      const rel = relative(SRC, p);
      return (
        rel.startsWith(`cli/`) ||
        rel === "cli.ts" ||
        rel.endsWith("/cli.ts") ||
        rel === "transparency/offline-cli.ts"
      );
    })
    .sort();
}

const REFUSAL_KEYWORD = /\b(unknown|unrecognized|unexpected)\b/i;
const FORMATTER_CALL = /^(argvTokenForDisplay|subcommandTokenForDisplay)\(/;
const FORMATTER_MAP = 'unknown.map(argvTokenForDisplay).join(" ")';

/**
 * Interpolations in a refusal-shaped template that are not an argv token, or
 * are a value the operator supplied as a named lookup key for that verb.
 * Keyed `<path relative to src>|<expression>`. Full-set: every entry must be
 * matched by the census, so a removed site removes its entry.
 */
const ALLOWLIST: Record<string, string> = {
  "cli/agents/cli.ts|positional": "tenant lookup key named for `agents show`",
  "cli/anomaly.ts|detectorId": "detector lookup key named for this verb",
  "cli/anomaly.ts|classifierId": "classifier lookup key named for this verb",
  "cli/castle-wall.ts|reason": "probe outcome reason, not argv",
  "cli/castle-wall.ts|report.state": "host app report field, not argv",
  "cli/federation.ts|String(cause)": "caught error text, not argv",
  "cli/federation.ts|verb": "fixed verb string chosen by the code",
  "cli/federation.ts|FEDERATION_HELP": "fixed help text",
  "cli/fleet.ts|ATTEST_USAGE": "fixed usage text",
  "cli/fleet.ts|USAGE": "fixed usage text",
  "cli/license.ts|flags.plan": "value of --plan, checked against a fixed plan list",
  'cli/license.ts|PLAN_NAMES.join(", ")': "fixed plan list",
  "cli/license.ts|f": "feature name checked against a fixed feature list",
  'cli/license.ts|ALL_ENTITLEMENT_FEATURE_FLAGS.join(", ")': "fixed feature list",
  "cli/license.ts|USAGE": "fixed usage text",
  "cli/nodes.ts|HELP": "fixed help text",
  "cli/nodes.ts|String(cause)": "caught error text, not argv",
  "cli/plugin.ts|PLUGIN_HELP": "fixed help text",
  "cli/secrets.ts|f.secret": "binding name from the stored surrogate policy",
  "cli/sentinel.ts|sentinelId": "sentinel lookup key named for this verb",
  'evidence-pack/cli.ts|unexpected.sort().join(", ")': "file names found on disk, not argv",
  "honeypot/cli.ts|trapId": "trap lookup key named for this verb",
  "templates/cli.ts|templateName": "template lookup key named for this verb",
  "wrap/cli.ts|String(i + 1)": "argv position, not the token",
  "wrap/cli.ts|hint": "fixed known-flag suggestion",
};

describe("source census: refusal templates route argv tokens through the formatter", () => {
  it("every interpolation is the formatter or an allowlisted non-token", () => {
    const template = /`((?:[^`\\]|\\.)*)`/g;
    const violations: string[] = [];
    const seen = new Set<string>();
    let formatterSites = 0;
    for (const file of cliSourceFiles()) {
      const rel = relative(SRC, file);
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
        for (const m of line.matchAll(template)) {
          const body = m[1]!;
          if (!body.includes("${")) continue;
          const staticText = body.replace(/\$\{[^}]*\}/g, "");
          if (!REFUSAL_KEYWORD.test(staticText)) continue;
          for (const e of body.matchAll(/\$\{([^}]*)\}/g)) {
            const expr = e[1]!;
            if (FORMATTER_CALL.test(expr) || expr === FORMATTER_MAP) {
              formatterSites += 1;
              continue;
            }
            const key = `${rel}|${expr}`;
            if (key in ALLOWLIST) {
              seen.add(key);
              continue;
            }
            violations.push(`${rel}:${String(idx + 1)} interpolates \${${expr}}`);
          }
        }
      });
    }
    expect(violations).toEqual([]);
    expect([...seen].sort()).toEqual(Object.keys(ALLOWLIST).sort());
    // 67 = refusal-template interpolations routed through the formatter when
    // this census was written (44 subcommand-position sites, 23 flag or
    // argument sites); a drop means a site stopped using it.
    expect(formatterSites).toBeGreaterThanOrEqual(67);
  });
});

// ── Behavioral table ─────────────────────────────────────────────────

class ExitSignal extends Error {}

function sink(): { stream: Writable; text: () => string } {
  let buf = "";
  const stream = new Writable({
    write(chunk, _enc, cb) {
      buf += String(chunk);
      cb();
    },
  });
  return { stream, text: () => buf };
}

interface Io {
  out: Writable;
  err: Writable;
  env: NodeJS.ProcessEnv;
}

let tempHome = "";

/**
 * Runs one refusal path and returns everything an operator would see:
 * injected streams, console, raw process stdout/stderr, and the message of
 * any thrown error (the top-level printer renders it).
 */
async function seen(run: (io: Io) => Promise<unknown> | unknown): Promise<string> {
  const out = sink();
  const err = sink();
  let captured = "";
  const collect = (...args: unknown[]): void => {
    captured += args.map(String).join(" ") + "\n";
  };
  const spies = [
    vi.spyOn(console, "error").mockImplementation(collect),
    vi.spyOn(console, "log").mockImplementation(collect),
    vi.spyOn(console, "warn").mockImplementation(collect),
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      captured += String(chunk);
      return true;
    }) as never),
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => {
      captured += String(chunk);
      return true;
    }) as never),
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new ExitSignal(`exit ${String(code)}`);
    }) as never),
  ];
  const env: NodeJS.ProcessEnv = {
    HOME: tempHome,
    SANCTUARY_STORAGE_PATH: join(tempHome, ".sanctuary"),
    PATH: process.env.PATH,
  };
  try {
    await run({ out: out.stream, err: err.stream, env });
  } catch (e) {
    if (!(e instanceof ExitSignal)) captured += `${(e as Error).message}\n`;
  } finally {
    for (const s of spies) s.mockRestore();
  }
  return `${out.text()}${err.text()}${captured}`;
}

type Runner = (argv: string[], io: Io) => Promise<unknown> | unknown;

const io3 = (argv: string[], io: Io) => ({ argv, out: io.out, err: io.err, env: io.env });

async function load<T>(path: string): Promise<T> {
  return (await import(path)) as T;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
const runners: Record<string, Runner> = {
  sentinel: async (a, io) => (await load<any>("../../src/cli/sentinel.js")).runSentinelCommand(io3(a, io)),
  anomaly: async (a, io) => (await load<any>("../../src/cli/anomaly.js")).runAnomalyCommand(io3(a, io)),
  secrets: async (a, io) => (await load<any>("../../src/cli/secrets.js")).runSecretsCommand(io3(a, io)),
  autoTrigger: async (a, io) => (await load<any>("../../src/cli/auto-trigger.js")).runAutoTriggerCommand(io3(a, io)),
  policy: async (a, io) => (await load<any>("../../src/cli/policy.js")).runPolicyCommand(io3(a, io)),
  inbox: async (a, io) => (await load<any>("../../src/cli/inbox.js")).runInboxCommand(io3(a, io)),
  task: async (a, io) => (await load<any>("../../src/cli/task.js")).runTaskCommand(io3(a, io)),
  concierge: async (a, io) => (await load<any>("../../src/cli/concierge.js")).runConciergeCommand(io3(a, io)),
  agents: async (a, io) => (await load<any>("../../src/cli/agents/cli.js")).runAgentsCommand(io3(a, io)),
  erc8004: async (a, io) => (await load<any>("../../src/cli/erc8004.js")).runErc8004Command(io3(a, io)),
  transparency: async (a, io) => (await load<any>("../../src/cli/transparency.js")).runTransparencyCommand(io3(a, io)),
  verifyTransparency: async (a, io) =>
    (await load<any>("../../src/cli/transparency.js")).runVerifyTransparencyCommand(io3(a, io)),
  identity: async (a, io) => (await load<any>("../../src/cli/identity.js")).runIdentityCommand(io3(a, io)),
  distress: async (a, io) => (await load<any>("../../src/cli/distress.js")).runDistressCommand(io3(a, io)),
  license: async (a, io) => (await load<any>("../../src/cli/license.js")).runLicenseCommand(io3(a, io)),
  didWeb: async (a, io) => (await load<any>("../../src/cli/did-web.js")).runDidWebCommand(io3(a, io)),
  federation: async (a, io) => (await load<any>("../../src/cli/federation.js")).runFederationCommand(io3(a, io)),
  plugin: async (a, io) => (await load<any>("../../src/cli/plugin.js")).runPluginCommand(io3(a, io)),
  cortexExport: async (a, io) =>
    (await load<any>("../../src/cli/cortex-export.js")).runCortexExportCommand(io3(a, io)),
  nodes: async (a, io) => (await load<any>("../../src/cli/nodes.js")).runNodesCommand(io3(a, io)),
  fileGrant: async (a, io) => (await load<any>("../../src/cli/file-grant.js")).runFileGrantCommand(io3(a, io)),
  deploy: async (a, io) => (await load<any>("../../src/cli/deploy.js")).runDeployCommand(io3(a, io)),
  intelligence: async (a) =>
    (await load<any>("../../src/cli/intelligence.js")).runIntelligenceCommand({ argv: a }),
  intelligenceConfigReset: async (a, io) =>
    (await load<any>("../../src/cli/intelligence.js")).runIntelligenceConfigReset(a, {
      print: (line: string) => io.err.write(`${line}\n`),
      env: io.env,
    }),
  fleet: async (a, io) => (await load<any>("../../src/cli/fleet.js")).runFleetCommand(io3(a, io)),
  audit: async (a, io) => (await load<any>("../../src/cli/audit.js")).runAuditCommand(io3(a, io)),
  observe: async (a, io) =>
    (await load<any>("../../src/cli/castle-wall-observe.js")).runObserveCommand(io3(a, io)),
  checkpoint: async (a, io) => (await load<any>("../../src/cli/checkpoint.js")).runCheckpointCommand(io3(a, io)),
  generate: async (a, io) => (await load<any>("../../src/cli/generate.js")).runGenerateCommand(io3(a, io)),
  completion: async (a, io) => (await load<any>("../../src/cli/completion.js")).runCompletionCommand(io3(a, io)),
  status: async (a, io) => (await load<any>("../../src/cli/status.js")).runStatusCommand(io3(a, io)),
  rotateMaster: async (a, io) =>
    (await load<any>("../../src/cli/rotate-master.js")).runRotateMasterCommand(io3(a, io)),
  resetPassphrase: async (a, io) =>
    (await load<any>("../../src/cli/reset-passphrase.js")).runResetPassphraseCommand(io3(a, io)),
  restoreAttest: async (a, io) =>
    (await load<any>("../../src/cli/restore-attest.js")).runRestoreAttestCommand(io3(a, io)),
  livenessProbe: async (a, io) =>
    (await load<any>("../../src/cli/liveness-probe.js")).runLivenessProbeCommand(io3(a, io)),
  install: async (a, io) => (await load<any>("../../src/cli/install.js")).runInstallCommand(io3(a, io)),
  uninstall: async (a, io) => (await load<any>("../../src/cli/uninstall.js")).runUninstallCommand(io3(a, io)),
  sdwOwner: async (a, io) => (await load<any>("../../src/cli/sdw-owner.js")).runSdwOwnerCommand(io3(a, io)),
  repairCustody: async (a, io) =>
    (await load<any>("../../src/cli/castle-wall-custody.js")).runRepairCustody(a, {
      out: io.out,
      err: io.err,
      env: io.env,
    }),
  wrap: async (a) => (await load<any>("../../src/wrap/cli.js")).parseWrapArgs(a),
  offlineVerifier: async (a, io) =>
    (await load<any>("../../src/transparency/offline-cli.js")).runStandaloneTransparencyVerifier(io3(a, io)),
  compliance: async (a) => (await load<any>("../../src/compliance/eu_ai_act/cli.js")).runCompliance(a),
  nistAiRmf: async (a) => (await load<any>("../../src/compliance/nist_ai_rmf/cli.js")).runNistAiRmf(a),
  evidencePack: async (a) => (await load<any>("../../src/evidence-pack/cli.js")).runEvidencePack(a),
  exit: async (a, io) => (await load<any>("../../src/exit/cli.js")).runExitCommand(io3(a, io)),
  templates: async (a, io) => (await load<any>("../../src/templates/cli.js")).runTemplateCommand(io3(a, io)),
  honeypot: async (a, io) => (await load<any>("../../src/honeypot/cli.js")).runHoneypotCli({}, io3(a, io)),
};
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Every module the runner table loads; imported once up front (see beforeAll). */
const RUNNER_MODULES = [
  "../../src/cli/agents/cli.js",
  "../../src/cli/anomaly.js",
  "../../src/cli/audit.js",
  "../../src/cli/auto-trigger.js",
  "../../src/cli/castle-wall-custody.js",
  "../../src/cli/castle-wall-observe.js",
  "../../src/cli/checkpoint.js",
  "../../src/cli/completion.js",
  "../../src/cli/concierge.js",
  "../../src/cli/cortex-export.js",
  "../../src/cli/deploy.js",
  "../../src/cli/did-web.js",
  "../../src/cli/distress.js",
  "../../src/cli/erc8004.js",
  "../../src/cli/federation.js",
  "../../src/cli/file-grant.js",
  "../../src/cli/fleet.js",
  "../../src/cli/generate.js",
  "../../src/cli/identity.js",
  "../../src/cli/inbox.js",
  "../../src/cli/install.js",
  "../../src/cli/intelligence.js",
  "../../src/cli/license.js",
  "../../src/cli/liveness-probe.js",
  "../../src/cli/nodes.js",
  "../../src/cli/plugin.js",
  "../../src/cli/policy.js",
  "../../src/cli/reset-passphrase.js",
  "../../src/cli/restore-attest.js",
  "../../src/cli/rotate-master.js",
  "../../src/cli/sdw-owner.js",
  "../../src/cli/secrets.js",
  "../../src/cli/sentinel.js",
  "../../src/cli/status.js",
  "../../src/cli/task.js",
  "../../src/cli/transparency.js",
  "../../src/cli/uninstall.js",
  "../../src/compliance/eu_ai_act/cli.js",
  "../../src/compliance/nist_ai_rmf/cli.js",
  "../../src/evidence-pack/cli.js",
  "../../src/exit/cli.js",
  "../../src/honeypot/cli.js",
  "../../src/templates/cli.js",
  "../../src/transparency/offline-cli.js",
  "../../src/wrap/cli.js",
];

/**
 * [case name, runner, argv prefix placed before the token, dash-leading value
 * token]. Parsers that refuse only `--`-prefixed tokens (and run on past a
 * single-dash token) get the `--`-prefixed value form, so the case reaches
 * the refusal instead of the command body.
 */
const CASES: Array<[string, keyof typeof runners, string[], string?]> = [
  ["sentinel subcommand", "sentinel", []],
  ["anomaly subcommand", "anomaly", []],
  ["anomaly detectors subcommand", "anomaly", ["detectors"]],
  ["secrets subcommand", "secrets", []],
  ["secrets surrogate subcommand", "secrets", ["surrogate"]],
  ["auto-trigger subcommand", "autoTrigger", []],
  // `auto-trigger recommendations` opens the fortress before it dispatches,
  // so its refusal is covered by the source census, not driven here.
  ["auto-trigger rules subcommand", "autoTrigger", ["rules"]],
  ["policy subcommand", "policy", []],
  ["policy drafts subcommand", "policy", ["drafts"]],
  ["inbox subcommand", "inbox", []],
  ["inbox approvals subcommand", "inbox", ["approvals"]],
  ["task subcommand", "task", []],
  ["concierge subcommand", "concierge", []],
  ["agents subcommand", "agents", []],
  ["erc8004 subcommand", "erc8004", []],
  ["transparency subcommand", "transparency", []],
  ["transparency anchor subcommand", "transparency", ["anchor"]],
  ["identity subcommand", "identity", []],
  ["distress subcommand", "distress", []],
  ["license verb", "license", []],
  ["did-web subcommand", "didWeb", []],
  ["federation subcommand", "federation", []],
  ["plugin subcommand", "plugin", []],
  ["cortex-export subcommand", "cortexExport", []],
  ["nodes subcommand", "nodes", []],
  ["file-grant subcommand", "fileGrant", []],
  ["deploy target", "deploy", []],
  ["deploy operator-cloud action", "deploy", ["operator-cloud"]],
  ["intelligence subcommand", "intelligence", []],
  ["fleet verb", "fleet", []],
  ["fleet attest verb", "fleet", ["attest"]],
  ["audit subcommand", "audit", []],
  ["observe subcommand", "observe", []],
  ["checkpoint subcommand", "checkpoint", []],
  ["generate subcommand", "generate", []],
  ["completion shell", "completion", []],
  ["exit subcommand", "exit", []],
  ["template subcommand", "templates", []],
  ["honeypot subcommand", "honeypot", []],
  ["compliance subcommand", "compliance", []],
  ["evidence-pack subcommand", "evidencePack", []],
  ["status option", "status", []],
  ["verify-transparency option", "verifyTransparency", []],
  ["rotate-master flag", "rotateMaster", [], DOUBLE_DASH_VALUE],
  ["reset-passphrase flag", "resetPassphrase", [], DOUBLE_DASH_VALUE],
  ["restore-attest flag", "restoreAttest", [], DOUBLE_DASH_VALUE],
  ["audit search option", "audit", ["search"]],
  ["liveness-probe option", "livenessProbe", []],
  ["install option", "install", []],
  ["uninstall option", "uninstall", []],
  ["intelligence config-reset option", "intelligenceConfigReset", []],
  ["sdw-owner argument", "sdwOwner", ["status"]],
  ["castle-wall repair-custody argument", "repairCustody", []],
  ["wrap flag", "wrap", []],
  ["offline transparency verifier option", "offlineVerifier", []],
  ["compliance eu-ai-act flag", "compliance", ["eu-ai-act", "did:key:z6MkArgvTokenDisplay"]],
  ["compliance nist-ai-rmf flag", "nistAiRmf", []],
  ["evidence-pack generate flag", "evidencePack", ["generate"]],
];

/** Cases whose token sits where a subcommand, verb, target, or shell name belongs. */
const SUBCOMMAND_POSITION = / (subcommand|verb|target|action|shell)$/;

/** Fortress-family refusals fire only for a `--fortress`-prefixed token. */
const FORTRESS_CASES: Array<[string, keyof typeof runners]> = [
  ["inbox fortress flag", "inbox"],
  ["task fortress flag", "task"],
  ["concierge fortress flag", "concierge"],
  ["agents fortress flag", "agents"],
  ["federation fortress flag", "federation"],
];

/** Positional-value refusals in argument parsers. */
const POSITIONAL_CASES: Array<[string, keyof typeof runners, string[]]> = [
  ["uninstall argument", "uninstall", []],
  ["sdw-owner argument", "sdwOwner", ["status"]],
  ["castle-wall repair-custody argument", "repairCustody", []],
  ["wrap argument", "wrap", []],
  ["evidence-pack generate argument", "evidencePack", ["generate"]],
];

describe("behavioral table: no refusal path prints an argv value", () => {
  let savedHome: string | undefined;
  // Cold-importing these CLI modules transforms a large share of the server
  // tree; doing it once here keeps that cost out of each case's own timeout
  // on a loaded machine. 300_000 ms = 5 minutes, a ceiling for that one-time
  // transform, not an expected duration.
  beforeAll(async () => {
    for (const path of RUNNER_MODULES) await import(path);
  }, 300_000);

  beforeAll(() => {
    tempHome = mkdtempSync(join(tmpdir(), "argv-token-display-"));
    savedHome = process.env.HOME;
    process.env.HOME = tempHome;
  });
  afterAll(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
  });

  for (const [name, runner, prefix, dashValue] of CASES) {
    for (const token of [FLAG_WITH_VALUE, dashValue ?? DASH_VALUE]) {
      it(`${name}: ${token === FLAG_WITH_VALUE ? "--flag=value" : "dash-leading value"}`, async () => {
        const text = await seen((io) => runners[runner]!([...prefix, token], io));
        expect(text).not.toContain(MARK);
      });
    }
  }

  // A non-verb-shaped token in a subcommand position is a value, not a typo.
  for (const [name, runner, prefix] of CASES.filter(([n]) => SUBCOMMAND_POSITION.test(n))) {
    it(`${name}: positional value`, async () => {
      const text = await seen((io) => runners[runner]!([...prefix, POSITIONAL_VALUE], io));
      expect(text).not.toContain(MARK);
    });
  }

  for (const [name, runner] of FORTRESS_CASES) {
    for (const token of [FORTRESS_FLAG_WITH_VALUE, FORTRESS_DASH_VALUE]) {
      it(`${name}: ${token === FORTRESS_FLAG_WITH_VALUE ? "--flag=value" : "dash-leading value"}`, async () => {
        const text = await seen((io) => runners[runner]!([token], io));
        expect(text).not.toContain(MARK);
      });
    }
  }

  for (const [name, runner, prefix] of POSITIONAL_CASES) {
    it(`${name}: positional value`, async () => {
      const text = await seen((io) => runners[runner]!([...prefix, POSITIONAL_VALUE], io));
      expect(text).not.toContain(MARK);
    });
  }

  it("a refusal still names the flag the operator typed", async () => {
    const text = await seen((io) => runners.rotateMaster!([FLAG_WITH_VALUE], io));
    expect(text).toContain("--zz-not-a-flag");
    const wrap = await seen((io) => runners.wrap!([FLAG_WITH_VALUE], io));
    expect(wrap).toContain("Unrecognized flag '--zz-not-a-flag'");
  });
});

/**
 * The castle-wall dispatchers live in src/cli.ts, which runs `main()` on
 * import, so they are driven through the built CLI.
 */
describe("behavioral table: castle-wall dispatchers in the built CLI", () => {
  for (const prefix of [["castle-wall"], ["castle-wall", "signer-helper"]]) {
    for (const token of [FLAG_WITH_VALUE, DASH_VALUE, POSITIONAL_VALUE]) {
      it(
        `${prefix.join(" ")}: ${token}`.replace(MARK, "<value>"),
        async () => {
          const { output } = await runCli(...prefix, token);
          expect(output).not.toContain(MARK);
        },
        CLI_SUBPROCESS_TEST_TIMEOUT_MS,
      );
    }
  }
});
