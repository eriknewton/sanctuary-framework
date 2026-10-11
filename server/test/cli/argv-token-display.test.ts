/**
 * CLI refusals never reproduce an unrecognized argv token.
 *
 * Every operator-facing refusal for an unrecognized flag, option, argument,
 * or subcommand renders the offending token through the one shared
 * formatter in src/cli/argv.ts (`argvTokenForDisplay`), and every
 * "unexpected error" refusal renders a caught value through
 * `caughtErrorForDisplay`. An unrecognized token prints as
 * `<argument not shown>` whatever its shape, because a value typed in the
 * wrong slot can look exactly like a long flag or a verb. The only token
 * printed is a single lowercase short flag.
 *
 * Scope. Covered: every refusal of an unrecognized or unexpected token in the
 * CLI modules (src/cli/**, src/cli.ts, every src/**\/cli.ts, and the offline
 * transparency verifier); every interpolation of a credential-named
 * identifier in any string form in those modules (template, `+`
 * concatenation with at least one literal operand, `format(...)` with a
 * literal format string); and the "unexpected error" lines in
 * cli/federation.ts and cli/nodes.ts. NOT covered: a generic catch block that
 * prints whatever message a callee threw (for example the exit verbs'
 * top-level catch, recorded in OUT_OF_SCOPE below), and string building the
 * census does not parse (`+=`, `.concat(...)`, `[...].join(...)`, a `+`
 * chain with no literal operand, or `format(...)` whose format string is not a
 * literal).
 *
 * Three layers, each over the full set:
 *   1. the formatter's own contract;
 *   2. a source census over every CLI module, parsed with the TypeScript
 *      compiler: every refusal-shaped template literal, `+` concatenation,
 *      and `format(...)` call must interpolate only a whole formatter call or
 *      an allowlisted non-token (every allowlist entry must still exist, and
 *      the formatter-site count is exact, so neither list can rot);
 *   3. a behavioral table that drives every reachable refusal path with a
 *      `--flag=VALUE` token, a dash-leading value, a value shaped like a long
 *      flag, and (in positional slots) a value shaped like a verb, asserts
 *      that a refusal was produced, and asserts no value appears in what the
 *      operator sees (stdout, stderr, injected streams, console, and every
 *      thrown message, string throw, and `cause` the top-level printer could
 *      render).
 */

import { mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { Writable } from "node:stream";
import ts from "typescript";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  ARGV_TOKEN_NOT_SHOWN,
  argvTokenForDisplay,
  caughtErrorForDisplay,
  consumeFlagValue,
  consumeFlagValues,
} from "../../src/cli/argv.js";
import { CLI_SUBPROCESS_TEST_TIMEOUT_MS, runCli } from "./helpers/run-cli";

// Must match ARGV_TOKEN_NOT_SHOWN in src/cli/argv.ts.
const EXPECTED_NOT_SHOWN = "<argument not shown>";

// Value markers. MARK has no flag or verb shape; the other two are the shapes
// a real value can take: a hyphenated multi-word value typed after `--`, and a
// lowercase hex string (24 = 12 bytes, hex-encoded) in a verb slot.
const MARK = "Zq9VALUEmark";
const FLAG_SHAPED_MARK = "correct-horse-battery-staple";
const HEX_MARK = "deadbeef0123456789abcdef";
const MARKERS = [MARK, FLAG_SHAPED_MARK, HEX_MARK];

const FLAG_WITH_VALUE = `--zz-not-a-flag=${MARK}`;
const DASH_VALUE = `-${MARK}`;
const DOUBLE_DASH_VALUE = `--${MARK}`;
const FLAG_SHAPED_VALUE = `--${FLAG_SHAPED_MARK}`;
const POSITIONAL_VALUE = MARK;
const VERB_SHAPED_VALUE = HEX_MARK;
const FORTRESS_FLAG_WITH_VALUE = `--fortress-zz=${MARK}`;
const FORTRESS_DASH_VALUE = `--fortress${MARK}`;
const FORTRESS_FLAG_SHAPED_VALUE = `--fortress-${FLAG_SHAPED_MARK}`;

describe("argv token display formatter", () => {
  it("pins the placeholder text", () => {
    expect(ARGV_TOKEN_NOT_SHOWN).toBe(EXPECTED_NOT_SHOWN);
  });

  it("prints only a single lowercase short flag", () => {
    expect(argvTokenForDisplay("-h")).toBe("-h");
    expect(argvTokenForDisplay("-x")).toBe("-x");
  });

  it("never prints any other token, whatever its shape", () => {
    for (const token of [
      undefined,
      "",
      "-",
      "--",
      "-A",
      "-ab",
      "--name",
      `--output-file=${MARK}`,
      FLAG_WITH_VALUE,
      DASH_VALUE,
      DOUBLE_DASH_VALUE,
      FLAG_SHAPED_VALUE,
      `${FLAG_SHAPED_VALUE}=x`,
      POSITIONAL_VALUE,
      VERB_SHAPED_VALUE,
      FLAG_SHAPED_MARK,
      "frobnicate",
      "operator-cloud",
      "claude-code",
      "has space",
    ]) {
      expect(argvTokenForDisplay(token), String(token)).toBe(EXPECTED_NOT_SHOWN);
    }
  });

  it("renders a caught value as its error class name only", () => {
    expect(caughtErrorForDisplay(new TypeError(`bad ${MARK}`))).toBe("TypeError");
    expect(caughtErrorForDisplay(new Error(MARK))).toBe("Error");
    const renamed = new Error("x");
    renamed.name = FLAG_SHAPED_MARK;
    expect(caughtErrorForDisplay(renamed)).toBe("error");
    expect(caughtErrorForDisplay(MARK)).toBe("error");
    expect(caughtErrorForDisplay(undefined)).toBe("error");
  });

  it("consumeFlagValue and consumeFlagValues refusals name the flag, never the next token", () => {
    const cases: string[][] = [
      ["--fortress", DASH_VALUE],
      ["--fortress", FLAG_SHAPED_VALUE],
      ["--fortress", "a", "--fortress", MARK],
      ["--fortress="],
    ];
    for (const argv of cases) {
      const single = consumeFlagValue(argv, "--fortress");
      expect(single.error, argv.join(" ")).toBeDefined();
      const multi = consumeFlagValues(argv, "--fortress");
      for (const text of [single.error ?? "", multi.error ?? ""]) {
        for (const m of MARKERS) expect(text).not.toContain(m);
      }
    }
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
  return walk(SRC)
    .filter((p) => {
      const rel = relative(SRC, p);
      return (
        rel.startsWith("cli/") ||
        rel === "cli.ts" ||
        rel.endsWith("/cli.ts") ||
        rel === "transparency/offline-cli.ts"
      );
    })
    .sort();
}

const REFUSAL_KEYWORD = /\b(unknown|unrecognized|unexpected)\b/i;
/**
 * Interpolations named like credential or key material are checked in every
 * string form (template, `+` concatenation, `format(...)`), refusal keyword or
 * not: a value a credential-named variable holds must never reach a message
 * without a formatter or an allowlist reason.
 */
const CREDENTIAL_NAMED =
  /passphrase|password|passwd|recovery_?key|private_?key|secret|token|mnemonic|seed_?phrase|api_?key|bearer|key_?material/i;
const FORMATTERS = new Set(["argvTokenForDisplay", "caughtErrorForDisplay"]);
const FORMATTER_MAP = "unknown.map(argvTokenForDisplay).join(\" \")";

interface AllowEntry {
  reason: string;
  /** When set, the census must find exactly this many uses, so one entry cannot silently cover a second site. */
  count?: number;
}

/**
 * Interpolations the census accepts without a formatter: not an argv token,
 * or a lookup key the verb resolves against its own known set. Keyed
 * `<path relative to src>|<expression>`. Full-set: every entry must be
 * matched by the census, so a removed site removes its entry.
 */
const ALLOWLIST: Record<string, AllowEntry> = {
  "cli/agents/cli.ts|positional": { reason: "tenant lookup key named for `agents show`" },
  "cli/anomaly.ts|detectorId": { reason: "detector lookup key named for this verb" },
  "cli/anomaly.ts|classifierId": { reason: "classifier lookup key named for this verb" },
  "cli/castle-wall.ts|reason": { reason: "probe outcome reason, not argv" },
  "cli/castle-wall.ts|report.state": { reason: "host app report field, not argv" },
  "cli/federation.ts|verb": { reason: "fixed verb string chosen by the code" },
  "cli/federation.ts|FEDERATION_HELP": { reason: "fixed help text" },
  "cli/fleet.ts|ATTEST_USAGE": { reason: "fixed usage text" },
  "cli/fleet.ts|USAGE": { reason: "fixed usage text" },
  "cli/license.ts|flags.plan": { reason: "value of --plan, checked against a fixed plan list" },
  'cli/license.ts|PLAN_NAMES.join(", ")': { reason: "fixed plan list" },
  "cli/license.ts|f": { reason: "feature name checked against a fixed feature list" },
  'cli/license.ts|ALL_ENTITLEMENT_FEATURE_FLAGS.join(", ")': { reason: "fixed feature list" },
  "cli/license.ts|USAGE": { reason: "fixed usage text" },
  "cli/nodes.ts|HELP": { reason: "fixed help text" },
  "cli/plugin.ts|PLUGIN_HELP": { reason: "fixed help text" },
  "cli/secrets.ts|f.secret": {
    reason:
      "binding name already matched against the helper's served-name set before this line; values never enter this record",
  },
  "cli/sentinel.ts|sentinelId": { reason: "sentinel lookup key named for this verb" },
  'evidence-pack/cli.ts|unexpected.sort().join(", ")': { reason: "file names found on disk, not argv" },
  "honeypot/cli.ts|trapId": { reason: "trap lookup key named for this verb" },
  "templates/cli.ts|templateName": { reason: "template lookup key named for this verb" },
  "cli/agents/cli.ts|passphraseLabel(tenant)": {
    reason: "fixed status label for where a tenant's credential lives",
  },
  "cli/castle-wall.ts|error instanceof Error ? error.message : String(error)": {
    reason:
      "content-filter status line for a host-app probe the CLI spawns itself with no operator arguments; a status read, not a refusal of argv",
    count: 1,
  },
  "cli/reset-passphrase.ts|availability.recoveryKey.reason": { reason: "fixed availability reason text" },
  "cli/rotate-master.ts|opts.recoveryKey": {
    reason:
      "the newly minted recovery key, shown once to the operator on this terminal by design; not argv. Exactly one use: a second use of this expression is a new decision",
    count: 1,
  },
  "cli/secrets.ts|SURROGATE_BOUND_PORT": { reason: "numeric constant" },
  "cli/secrets.ts|f.reason": { reason: "fixed failure reason class" },
  "cli/secrets.ts|describeUnlockSettleCommands(f.agentUid)": {
    reason: "fixed command text built from a numeric uid",
  },
  "wrap/cli.ts|passphraseLocation": { reason: "where the credential is stored, never the value" },
  // Credential-named interpolations that are not refusal text. Each is pinned
  // to its current use count so a new use is a new decision.
  "cli/auto-trigger.ts|token": { reason: "Authorization request header, never printed", count: 1 },
  "cli/concierge.ts|token": { reason: "Authorization request header, never printed", count: 1 },
  "cli/dashboard-request.ts|token": { reason: "Authorization request header, never printed", count: 1 },
  "cli/policy.ts|token": { reason: "Authorization request header, never printed", count: 2 },
  "cli/castle-wall-boot.ts|bootTokenPath": { reason: "file path of the boot token, not its bytes", count: 4 },
  "cli/castle-wall-observe.ts|tokenRead.length": { reason: "byte length, not content", count: 1 },
  "cli/castle-wall-observe.ts|tokenRead.mode.toString(8)": { reason: "file mode, not content", count: 1 },
  "cli/castle-wall.ts|tokenRead.length": { reason: "byte length, not content", count: 1 },
  "cli/castle-wall.ts|tokenRead.mode.toString(8)": { reason: "file mode, not content", count: 1 },
  "cli/castle-wall.ts|BOOT_TOKEN_LENGTH": { reason: "numeric constant", count: 1 },
  "cli/castle-wall.ts|ED25519_PRIVATE_KEY_BYTES": { reason: "numeric constant", count: 1 },
  "cli/federation.ts|JSON.stringify( { joined: true, persisted, node_id: bootstrapToken.intended_node_id, node_pubkey: toBase64url(assembled.nodePublicKey), certificate: response.certificate, issuing_principal_cert: response.issuing_principal_cert ?? null, }, null, 2, )":
    { reason: "join result: node id from the bootstrap record, public key, certificates", count: 1 },
  "cli/federation.ts|JSON.stringify({ bootstrap_token: response.bootstrap_token }, null, 2)": {
    reason: "the bootstrap token is the intended output of `federation authorize`, handed to the joiner",
    count: 1,
  },
  "cli/federation.ts|secretB64": {
    reason: "the intended output of `federation reveal-master-secret`, printed only after the disclosure is audited",
    count: 1,
  },
  "cli/secrets.ts|secret": {
    reason: "secret binding NAME (the operator's label for a stored value); values are never held in this variable",
    count: 22,
  },
  "cli/secrets.ts|b.secret": { reason: "binding NAME from the policy file", count: 2 },
  "exit/cli.ts|report.declared_rekey_material": {
    reason: "inspection state enum describing what the bundle declares, not key bytes",
    count: 1,
  },
  "wrap/cli.ts|String(i + 1)": { reason: "argv position, not the token" },
  "wrap/cli.ts|hint": { reason: "fixed known-flag suggestion" },
};

/**
 * Message sites this guard deliberately does NOT cover, recorded so the
 * scope stays truthful: a generic catch block that prints a callee's error
 * message is callee error text, not a refusal of an unrecognized token.
 * Keyed `<path relative to src>|<exact source text>`; each must still exist.
 */
const OUT_OF_SCOPE: Record<string, string> = {
  "exit/cli.ts|write(err, error instanceof Error ? `${error.message}\\n` : `${String(error)}\\n`);":
    "the exit verbs' top-level catch prints whatever message a callee threw; tracked separately",
};

interface CensusResult {
  violations: string[];
  allowlisted: Map<string, number>;
  formatterSites: string[];
}

/** Census over one parsed module; `rel` is its path relative to src. */
function censusModule(rel: string, source: string, result: CensusResult): void {
  const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true);
  const checked = new Set<ts.Node>();
  const where = (n: ts.Node): string =>
    `${rel}:${String(sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1)}`;

  const checkExpr = (expr: ts.Expression): void => {
    if (checked.has(expr)) return;
    checked.add(expr);
    // Whitespace-collapsed so a multi-line expression has a one-line allowlist key.
    const text = expr.getText(sf).replace(/\s+/g, " ");
    // The WHOLE interpolation must be the formatter call; a formatter call
    // inside a larger expression (`f(x) + x`) does not count.
    const isFormatterCall =
      ts.isCallExpression(expr) && ts.isIdentifier(expr.expression) && FORMATTERS.has(expr.expression.text);
    if (isFormatterCall || text === FORMATTER_MAP) {
      result.formatterSites.push(`${where(expr)} ${text}`);
      return;
    }
    if (ts.isStringLiteralLike(expr) || ts.isNumericLiteral(expr)) return;
    const key = `${rel}|${text}`;
    if (key in ALLOWLIST) {
      result.allowlisted.set(key, (result.allowlisted.get(key) ?? 0) + 1);
      return;
    }
    result.violations.push(`${where(expr)} interpolates ${text}`);
  };

  const staticText = (n: ts.Node): string | undefined => {
    if (ts.isStringLiteralLike(n)) return n.text;
    if (ts.isTemplateExpression(n)) {
      return n.head.text + n.templateSpans.map((sp) => sp.literal.text).join("");
    }
    return undefined;
  };

  const flattenPlus = (n: ts.Expression): ts.Expression[] => {
    const e = ts.isParenthesizedExpression(n) ? n.expression : n;
    if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return [...flattenPlus(e.left), ...flattenPlus(e.right)];
    }
    return [e];
  };

  /** True when an identifier inside the expression (not a string literal in it) is credential-named. */
  const credentialNamed = (expr: ts.Node): boolean => {
    let hit = false;
    const walkIds = (n: ts.Node): void => {
      if (hit) return;
      if (ts.isIdentifier(n) && CREDENTIAL_NAMED.test(n.text)) hit = true;
      else ts.forEachChild(n, walkIds);
    };
    walkIds(expr);
    return hit;
  };

  /** Checks every dynamic part when `all`, else only credential-named parts. */
  const checkParts = (parts: ts.Expression[], all: boolean): void => {
    for (const part of parts) {
      if (ts.isTemplateExpression(part)) {
        for (const sp of part.templateSpans) {
          if (all || credentialNamed(sp.expression)) checkExpr(sp.expression);
        }
      } else if (staticText(part) === undefined) {
        if (all || credentialNamed(part)) checkExpr(part);
      }
    }
  };

  const visit = (node: ts.Node): void => {
    if (ts.isTemplateExpression(node)) {
      checkParts(
        node.templateSpans.map((sp) => sp.expression),
        REFUSAL_KEYWORD.test(staticText(node)!),
      );
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
      !(ts.isBinaryExpression(node.parent) && node.parent.operatorToken.kind === ts.SyntaxKind.PlusToken)
    ) {
      const parts = flattenPlus(node);
      if (parts.some((p) => staticText(p) !== undefined)) {
        const text = parts.map((p) => staticText(p) ?? "").join("");
        checkParts(parts, REFUSAL_KEYWORD.test(text));
      }
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(sf);
      const first = node.arguments[0];
      if (/(^|\.)format$/.test(callee) && first !== undefined && staticText(first) !== undefined) {
        checkParts([...node.arguments.slice(1)], REFUSAL_KEYWORD.test(staticText(first)!));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

function runCensus(): CensusResult {
  const result: CensusResult = { violations: [], allowlisted: new Map(), formatterSites: [] };
  for (const file of cliSourceFiles()) censusModule(relative(SRC, file), readFileSync(file, "utf8"), result);
  return result;
}

// 78 = interpolations routed through a formatter when this census was
// written: 67 unrecognized-token refusals (argvTokenForDisplay, one of them
// the config-reset `unknown.map(...)` form) plus 11 caught-error refusals
// (caughtErrorForDisplay). Exact, so a removed or added site is a decision.
const EXPECTED_FORMATTER_SITES = 78;

describe("source census: refusal strings route argv tokens through the formatter", () => {
  const census = runCensus();

  it("every interpolation in a refusal string is a whole formatter call or allowlisted", () => {
    expect(census.violations).toEqual([]);
  });

  it("every allowlist entry is still in use, with its pinned use count where one is set", () => {
    expect([...census.allowlisted.keys()].sort()).toEqual(Object.keys(ALLOWLIST).sort());
    for (const [key, entry] of Object.entries(ALLOWLIST)) {
      if (entry.count !== undefined) expect(census.allowlisted.get(key), key).toBe(entry.count);
    }
  });

  it("the formatter-site count is exact", () => {
    expect(census.formatterSites.length, census.formatterSites.join("\n")).toBe(
      EXPECTED_FORMATTER_SITES,
    );
  });

  it("every recorded out-of-scope site still exists, so the stated scope stays accurate", () => {
    for (const key of Object.keys(OUT_OF_SCOPE)) {
      const sep = key.indexOf("|");
      const source = readFileSync(join(SRC, key.slice(0, sep)), "utf8");
      expect(source.includes(key.slice(sep + 1)), key).toBe(true);
    }
  });

  it("catches planted credential-named and refusal interpolations in every string form", () => {
    const planted = [
      'export const a = (passphrase: string) => "invalid passphrase: " + passphrase;',
      'import { format } from "node:util";\nexport const b = (recoveryKey: string) => format("invalid recovery key: %s", recoveryKey);',
      "export const c = (token: string) => `invalid token: ${token}`;",
      'export const d = (arg: string) => "Unknown option: " + arg;',
      "export const e = (arg: string) => `Unknown option:\n  ${arg}`;",
      "export const f = (arg: string) => `Unknown option: ${argvTokenForDisplay(arg) + arg}`;",
      'import util from "node:util";\nexport const g = (arg: string) => util.format("Unknown option: %s", arg);',
    ];
    for (const source of planted) {
      const probe: CensusResult = { violations: [], allowlisted: new Map(), formatterSites: [] };
      censusModule("planted/cli.ts", source, probe);
      expect(probe.violations.length, source).toBeGreaterThan(0);
    }
    const clean: CensusResult = { violations: [], allowlisted: new Map(), formatterSites: [] };
    censusModule(
      "planted/cli.ts",
      "export const h = (arg: string) => `Unknown option: ${argvTokenForDisplay(arg)}`;",
      clean,
    );
    expect(clean.violations).toEqual([]);
    expect(clean.formatterSites.length).toBe(1);
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

/** Every printable layer of a thrown value: message, string throw, and the cause chain. */
function thrownText(e: unknown, depth = 0): string {
  // 8 = a cause chain deeper than any this CLI builds; the cap only stops a cycle.
  if (depth > 8 || e === undefined || e === null) return "";
  if (e instanceof Error) {
    return `${e.name}: ${e.message}\n${String(e.stack ?? "")}\n${thrownText(e.cause, depth + 1)}`;
  }
  return `${String(e)}\n`;
}

/**
 * Runs one refusal path and returns everything an operator would see:
 * injected streams, console, raw process stdout/stderr, and every layer of
 * any thrown value (the top-level printer renders it).
 */
async function seen(run: (io: Io) => Promise<unknown> | unknown): Promise<string> {
  const out = sink();
  const err = sink();
  let captured = "";
  const collect = (...args: unknown[]): void => {
    captured += args.map((a) => (a instanceof Error ? thrownText(a) : String(a))).join(" ") + "\n";
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
    if (!(e instanceof ExitSignal)) captured += thrownText(e);
  } finally {
    for (const s of spies) s.mockRestore();
  }
  return `${out.text()}${err.text()}${captured}`;
}

function expectRefusalWithoutValue(text: string, witness: string = EXPECTED_NOT_SHOWN): void {
  expect(text, "the path must produce a refusal").toContain(witness);
  for (const m of MARKERS) expect(text).not.toContain(m);
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
      // The verb refuses every other platform before it parses argv.
      platform: "darwin",
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
/** [case name, runner, argv prefix, refusal witness when not the placeholder]. */
const POSITIONAL_CASES: Array<[string, keyof typeof runners, string[], string?]> = [
  ["uninstall argument", "uninstall", []],
  ["sdw-owner argument", "sdwOwner", ["status"]],
  ["castle-wall repair-custody argument", "repairCustody", []],
  ["wrap argument", "wrap", [], "Unrecognized argument at position"],
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

  const label = (token: string): string =>
    token === FLAG_WITH_VALUE || token === FORTRESS_FLAG_WITH_VALUE
      ? "--flag=value"
      : token === FLAG_SHAPED_VALUE || token === FORTRESS_FLAG_SHAPED_VALUE
        ? "flag-shaped value"
        : token === VERB_SHAPED_VALUE
          ? "verb-shaped value"
          : token === POSITIONAL_VALUE
            ? "positional value"
            : "dash-leading value";

  for (const [name, runner, prefix, dashValue] of CASES) {
    for (const token of [FLAG_WITH_VALUE, dashValue ?? DASH_VALUE, FLAG_SHAPED_VALUE]) {
      it(`${name}: ${label(token)}`, async () => {
        const text = await seen((io) => runners[runner]!([...prefix, token], io));
        expectRefusalWithoutValue(text);
      });
    }
  }

  // Any token in a subcommand position that is not a known verb is a value.
  for (const [name, runner, prefix] of CASES.filter(([n]) => SUBCOMMAND_POSITION.test(n))) {
    for (const token of [POSITIONAL_VALUE, VERB_SHAPED_VALUE]) {
      it(`${name}: ${label(token)}`, async () => {
        const text = await seen((io) => runners[runner]!([...prefix, token], io));
        expectRefusalWithoutValue(text);
      });
    }
  }

  for (const [name, runner] of FORTRESS_CASES) {
    for (const token of [FORTRESS_FLAG_WITH_VALUE, FORTRESS_DASH_VALUE, FORTRESS_FLAG_SHAPED_VALUE]) {
      it(`${name}: ${label(token)}`, async () => {
        const text = await seen((io) => runners[runner]!([token], io));
        expectRefusalWithoutValue(text);
      });
    }
  }

  for (const [name, runner, prefix, witness] of POSITIONAL_CASES) {
    for (const token of [POSITIONAL_VALUE, VERB_SHAPED_VALUE]) {
      it(`${name}: ${label(token)}`, async () => {
        const text = await seen((io) => runners[runner]!([...prefix, token], io));
        expectRefusalWithoutValue(text, witness);
      });
    }
  }
});

describe("behavioral table: castle-wall dispatchers in the built CLI", () => {
  for (const prefix of [["castle-wall"], ["castle-wall", "signer-helper"]]) {
    for (const token of [
      FLAG_WITH_VALUE,
      DASH_VALUE,
      FLAG_SHAPED_VALUE,
      POSITIONAL_VALUE,
      VERB_SHAPED_VALUE,
    ]) {
      it(
        `${prefix.join(" ")}: ${MARKERS.reduce((t, m) => t.replace(m, "<value>"), token)}`,
        async () => {
          const { output } = await runCli(...prefix, token);
          expectRefusalWithoutValue(output);
        },
        CLI_SUBPROCESS_TEST_TIMEOUT_MS,
      );
    }
  }
});
