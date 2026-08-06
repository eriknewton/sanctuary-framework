/**
 * sanctuary generate
 *
 * Pure deployment-template generator. Does not read or write Sanctuary state.
 *
 * Four things this generator must never do. Every one of them produces a unit
 * systemd accepts and then fails to run usefully, which is why they are gated
 * in code rather than described in the help text:
 *   - emit an `ExecStart` naming the node binary with no script to run
 *     (observed: `ExecStart=/usr/local/bin/node dashboard --no-confirm`),
 *   - emit an `ExecStart` naming a script `node` cannot execute, which is what
 *     a source checkout under tsx resolves to (`.../src/cli.ts`); plain node
 *     rejects TypeScript, so the unit fails at every start,
 *   - emit a `~` anywhere in the unit, because systemd performs no tilde
 *     expansion and the service would silently use a literal `~` directory,
 *   - interpolate an operator-supplied value into unit text without systemd's
 *     own quoting, because a space truncates the value, a `%` is read as a
 *     specifier anywhere in the file, a `$` is read as a variable reference on
 *     a command line, and a newline injects a directive.
 */

import { execPath } from "node:process";
import { homedir, userInfo } from "node:os";
import { basename, dirname, extname, isAbsolute, join, sep } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { flagValue } from "./argv.js";

export interface GenerateCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  currentUser?: string;
  /** Override the resolved CLI entry; also the `--binary` flag's target. */
  binaryPath?: string;
  /** Home directory used to expand a `~` state dir (tests inject this). */
  homeDir?: string;
}

/**
 * Default state directory as the operator types it, kept in tilde form so the
 * refusal below can name the exact string that failed. It is expanded to an
 * absolute path before it ever reaches the unit.
 */
const DEFAULT_STATE_DIR = "~/.sanctuary";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runGenerateCommand(
  args: GenerateCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(sub ? out : err);
    return sub ? 0 : 2;
  }
  if (sub !== "systemd") {
    write(err, `Unknown generate command: ${sub}\n`);
    printUsage(err);
    return 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    printSystemdUsage(out);
    return 0;
  }

  const currentUser = args.currentUser ?? userInfo().username;
  const user = flagValue(rest, "--user") ?? currentUser;
  const platform = args.platform ?? process.platform;

  const stateDir = resolveSystemdStateDir({
    raw: flagValue(rest, "--state-dir") ?? DEFAULT_STATE_DIR,
    user,
    currentUser,
    home: args.homeDir ?? homedir(),
  });
  if ("error" in stateDir) {
    write(err, `sanctuary generate systemd: ${stateDir.error}\n`);
    return 2;
  }

  // An operator-supplied --binary is taken verbatim as the ExecStart head: it
  // is their own launcher (a wrapper script, a distro package path), and
  // prefixing it with this host's node would run their launcher as a node
  // script. Only the DEFAULT is composed as "<node> <cli script>".
  const explicitBinary = flagValue(rest, "--binary") ?? args.binaryPath;

  let scriptPath: string | undefined;
  if (!explicitBinary) {
    const script = resolveCliScriptPath(fileURLToPath(import.meta.url));
    if ("error" in script) {
      write(err, `sanctuary generate systemd: ${script.error}\n`);
      return 2;
    }
    scriptPath = script.scriptPath;
  }

  // renderSystemdUnit throws on anything it will not put in front of an
  // operator (non-absolute state dir, control characters, an unrunnable
  // script). Those are usage errors from this entry point's perspective, so
  // they exit 2 with the message rather than surfacing as a stack trace.
  let unit: string;
  try {
    unit = renderSystemdUnit({
      user,
      stateDir: stateDir.stateDir,
      binary: explicitBinary ?? execPath,
      ...(scriptPath === undefined ? {} : { scriptPath }),
      platform,
    });
  } catch (error) {
    write(err, `sanctuary generate systemd: ${(error as Error).message}\n`);
    return 2;
  }

  write(out, unit);
  return 0;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary generate <command> [options]

Commands:
  systemd   Emit a Linux systemd service unit for the Sanctuary daemon.
`,
  );
}

function printSystemdUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary generate systemd [--user <name>] [--state-dir <path>] [--binary <path>]

Options:
  --user <name>       Service user. Defaults to the current user.
  --state-dir <path>  Sanctuary state directory. Must be an absolute path:
                      systemd does not expand ~, so a tilde would become a
                      literal directory named "~". Defaults to the current
                      user's ~/.sanctuary, expanded.
  --binary <path>     Command to run, used verbatim as the ExecStart head.
                      Defaults to this host's node plus this CLI's entry
                      script. Required when generating from a source
                      checkout run under tsx: the entry there is TypeScript,
                      and the unit's node cannot execute it.
`,
  );
}

/**
 * Turn the operator's `--state-dir` into an absolute path, or refuse.
 *
 * ENFORCEMENT SITE for the no-tilde invariant: systemd performs no tilde
 * expansion in `Environment=`, so a unit carrying `~/.sanctuary` starts
 * cleanly and then reads and writes a literal directory named `~` under the
 * service's working directory. Nothing about that failure looks like a path
 * problem from the outside; the service simply behaves as if the fortress
 * were empty. Expansion happens here or the generator refuses to emit.
 *
 * A tilde is only expandable when the service user IS the user running this
 * command, because that is the only home directory this process can know. For
 * any other `User=`, refusing beats guessing `/home/<user>`: a wrong guess
 * produces the same silently-empty fortress the refusal exists to prevent.
 */
export function resolveSystemdStateDir(opts: {
  raw: string;
  user: string;
  currentUser: string;
  home: string;
}): { stateDir: string } | { error: string } {
  const { raw, user, currentUser, home } = opts;

  if (isAbsolute(raw)) return { stateDir: raw };

  if (raw === "~" || raw.startsWith("~/")) {
    if (user !== currentUser) {
      return {
        error:
          `cannot expand "${raw}" into the home directory of service user ` +
          `"${user}" (this command is running as "${currentUser}"). systemd ` +
          `does not expand ~, so pass an absolute path: ` +
          `--state-dir /home/${user}/.sanctuary`,
      };
    }
    if (!isAbsolute(home)) {
      return {
        error:
          `cannot expand "${raw}": this process has no absolute home ` +
          `directory. Pass an absolute path with --state-dir.`,
      };
    }
    return { stateDir: raw === "~" ? home : join(home, raw.slice("~/".length)) };
  }

  return {
    error:
      `--state-dir must be an absolute path, got "${raw}". systemd does not ` +
      `expand ~ or ~user and resolves nothing relative to your shell's ` +
      `working directory, so anything else becomes a literal directory name.`,
  };
}

export function renderSystemdUnit(opts: {
  user: string;
  stateDir: string;
  /** Executable for ExecStart (node, or an operator-supplied launcher). */
  binary: string;
  /** Script argument for ExecStart, when `binary` is an interpreter. */
  scriptPath?: string;
  platform?: NodeJS.Platform;
}): string {
  // Second enforcement point for the no-tilde invariant: resolveSystemdStateDir
  // is the CLI's gate, but renderSystemdUnit is exported and is the last line
  // before the text an operator installs, so it refuses rather than trusting
  // its caller to have gated.
  if (!isAbsolute(opts.stateDir)) {
    throw new Error(
      `renderSystemdUnit: stateDir must be absolute, got "${opts.stateDir}". ` +
        `systemd does not expand ~, so a relative or tilde path becomes a ` +
        `literal directory name.`,
    );
  }
  // ENFORCEMENT SITE for "no operator value may add a line to the unit".
  // Every interpolation below is quoted for systemd, and systemd's quoting has
  // no escape for a literal newline inside a directive value: a `\n` in
  // stateDir, user, or binary would end the directive and let whatever follows
  // be read as a new one (an extra `ExecStart=`, say). Quoting cannot fix
  // that, so the only correct answer is refusal.
  const interpolated: Array<readonly [string, string]> = [
    ["user", opts.user],
    ["stateDir", opts.stateDir],
    ["binary", opts.binary],
  ];
  if (opts.scriptPath !== undefined) {
    interpolated.push(["scriptPath", opts.scriptPath]);
  }
  for (const [label, value] of interpolated) {
    if (hasUnitUnsafeControlChar(value)) {
      throw new Error(
        `renderSystemdUnit: ${label} contains a control character or newline, ` +
          `which systemd quoting cannot escape inside a unit directive.`,
      );
    }
  }
  // A systemd `User=` takes a single account name; whitespace there is not a
  // quoting problem, it is a value systemd will reject at load time.
  if (/\s/.test(opts.user) || opts.user === "") {
    throw new Error(
      `renderSystemdUnit: user must be a single account name, got ` +
        `"${opts.user}". systemd's User= accepts no whitespace.`,
    );
  }
  // ENFORCEMENT SITE for "ExecStart must name a script node can execute".
  // resolveCliScriptPath is the CLI's gate; this is the last one before the
  // text an operator installs. A `.ts` here means a source checkout under tsx,
  // and `node foo.ts` under the plain node this unit names fails at every
  // start with no Sanctuary output at all.
  if (
    opts.scriptPath !== undefined &&
    !NODE_EXECUTABLE_SCRIPT_EXTENSIONS.has(extname(opts.scriptPath))
  ) {
    throw new Error(
      `renderSystemdUnit: scriptPath "${opts.scriptPath}" is not a script ` +
        `plain node can execute (expected one of ` +
        `${[...NODE_EXECUTABLE_SCRIPT_EXTENSIONS].join(", ")}).`,
    );
  }
  const execStart = opts.scriptPath
    ? `${systemdQuote(opts.binary)} ${systemdQuote(opts.scriptPath)}`
    : systemdQuote(opts.binary);
  const note =
    opts.platform === "darwin"
      ? "# Note: this host is macOS. This unit is for Linux systemd hosts; macOS launchd is out of scope.\n" +
        "# The paths below were resolved on THIS host. Replace them with the target host's\n" +
        "# paths, or the unit will fail to start there with a bare status=203/EXEC.\n"
      : "";
  return `# Sanctuary systemd unit
# Install:
#   sudo install -m 0644 sanctuary.service /etc/systemd/system/sanctuary.service
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now sanctuary.service
# If ExecStart names a path that does not exist on this host, systemd reports
# status=203/EXEC and the journal shows no Sanctuary output at all; check the
# ExecStart path first rather than reading it as a Sanctuary startup failure.
${note}[Unit]
Description=Sanctuary MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${opts.user}
${renderEnvironmentAssignment("SANCTUARY_STORAGE_PATH", opts.stateDir)}
ExecStart=${execStart} dashboard --no-confirm
Restart=on-failure
RestartSec=5
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
`;
}

/**
 * Extensions a bare `node <script>` runs with no loader flag. A unit's
 * ExecStart gets no `--import tsx` and no shell, so anything outside this set
 * is a script the generated unit cannot start.
 */
const NODE_EXECUTABLE_SCRIPT_EXTENSIONS: ReadonlySet<string> = new Set([
  ".js",
  ".cjs",
  ".mjs",
]);

/**
 * Values refused outright: the C0 control range (which includes LF and CR) plus
 * DEL. A newline ends a directive, and systemd's quoting has no escape that
 * keeps a literal newline inside one, so whatever follows would be read as a
 * fresh directive. Nothing legitimate in a path, user name, or binary needs
 * them.
 */
/** Last code point of the C0 control range (NUL through US); LF and CR are inside it. */
const C0_CONTROL_LAST_CODE_POINT = 0x1f;
/** DEL, the one control character above the C0 range. */
const DELETE_CODE_POINT = 0x7f;

/**
 * True when `value` carries a character that must never be interpolated into
 * the unit.
 *
 * Written as a code-point scan rather than a character-class regex because a
 * regex literal spelling the control range out is an eslint `no-control-regex`
 * error, and disabling that rule here would hide the next one somebody adds.
 */
function hasUnitUnsafeControlChar(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= C0_CONTROL_LAST_CODE_POINT || code === DELETE_CODE_POINT) {
      return true;
    }
  }
  return false;
}

export type CliScriptResolution =
  | { readonly scriptPath: string }
  | { readonly error: string };

/**
 * Resolve the CLI entry script to name in ExecStart, given this module's own
 * resolved path, or refuse when the resolved entry is not startable.
 *
 * ENFORCEMENT SITE for the "ExecStart must name a script node can execute"
 * invariant. The published package is a single bundled `dist/cli.js`;
 * `dist/cli/generate.js` exists only in an unbundled tree and never in an
 * installed package. The previous probe tested for exactly that path,
 * therefore missed on every real install, and fell back to the node binary
 * alone, emitting `ExecStart=<node> dashboard --no-confirm`. systemd starts
 * that happily and node exits immediately having been asked to run a script
 * called "dashboard".
 *
 * Anchoring on the nearest `dist`/`src` ancestor covers the three layouts the
 * CLI ships in as JavaScript: bundled (`dist/cli.js`, which is this module
 * itself), unbundled (`dist/cli/generate.js`), and the library entry a
 * consumer might call through (`dist/index.js`).
 *
 * The fourth layout the CLI RUNS in, a source checkout under tsx, is refused
 * rather than supported. It resolves to `.../src/cli.ts`, and the unit's
 * `ExecStart` names this host's plain `node`, which rejects TypeScript: the
 * unit would fail at every start. Naming the reason at generate time beats
 * handing the operator text that installs cleanly and never runs.
 */
export function resolveCliScriptPath(selfPath: string): CliScriptResolution {
  // ".js" for both the bundled and unbundled builds, ".ts" under tsx; the
  // sibling CLI entry always carries the same extension as this module.
  const extension = extname(selfPath) || ".js";
  const segments = selfPath.split(sep);
  let candidate: string | undefined;
  for (let i = segments.length - 1; i >= 0 && candidate === undefined; i--) {
    if (segments[i] === "dist" || segments[i] === "src") {
      candidate = [...segments.slice(0, i + 1), `cli${extension}`].join(sep);
    }
  }
  // No recognizable build root. Naming this module still beats naming nothing:
  // a wrong script path fails loudly at start, a missing one does not.
  const scriptPath = candidate ?? join(dirname(selfPath), basename(selfPath));

  if (!NODE_EXECUTABLE_SCRIPT_EXTENSIONS.has(extname(scriptPath))) {
    return {
      error:
        `cannot generate a unit from this checkout: the CLI entry resolves to ` +
        `"${scriptPath}", which plain node cannot execute. A systemd ExecStart ` +
        `gets no tsx loader and no shell, so the service would fail at every ` +
        `start. Generate from an installed package (npx ` +
        `@sanctuary-framework/mcp-server generate systemd), or name your own ` +
        `launcher with --binary <path>.`,
    };
  }
  return { scriptPath };
}

/**
 * Quote a value for a systemd command line (`ExecStart=`).
 *
 * systemd does its own quoting, NOT shell quoting: inside double quotes a
 * backslash escapes the next character, and there is no shell-style
 * `'\''` idiom. `%` is a specifier prefix ANYWHERE in a unit file, quoted or
 * not, so `/opt/%s/bin` would be rewritten by systemd before exec; `%%` is the
 * only way to mean a literal percent.
 *
 * Must stay paired with {@link renderEnvironmentAssignment}: the two share
 * {@link escapeForSystemd} and differ ONLY in the `$` rule below, which is a
 * real asymmetry in systemd and not an oversight in one of them.
 */
function systemdQuote(value: string): string {
  const escaped = escapeForCommandLine(value);
  // Unquoted is safe only for a value with no whitespace and nothing systemd
  // rewrites; the escape pass is a no-op on exactly that set.
  if (escaped === value && !/\s/.test(value) && value !== "") return value;
  return `"${escaped}"`;
}

/**
 * Render one `Environment=` assignment with systemd's quoting.
 *
 * `Environment=` takes SPACE-SEPARATED assignments, so an unquoted
 * `Environment=SANCTUARY_STORAGE_PATH=/var/lib/Sanctuary Test` sets the
 * variable to `/var/lib/Sanctuary` and then tries to read `Test` as a second
 * assignment. From the outside the service starts and behaves as though the
 * fortress were somewhere else entirely. The whole `NAME=value` goes inside
 * one pair of double quotes, which is the form systemd documents.
 *
 * ENFORCEMENT SITE for "an `Environment=` value is escaped for specifiers and
 * quoting but NEVER for `$`". systemd.exec(5) states outright that inside
 * `Environment=` "the $ character has no special meaning", so doubling it here
 * would not protect anything; it would put a second, literal `$` into the
 * variable the service reads. That is the mirror image of the command-line bug
 * this function is paired against, and both look fine in the emitted text.
 */
function renderEnvironmentAssignment(name: string, value: string): string {
  const escaped = escapeForSystemd(value);
  if (escaped === value && !/\s/.test(value) && value !== "") {
    return `Environment=${name}=${value}`;
  }
  return `Environment="${name}=${escaped}"`;
}

/**
 * Escaping common to every unit directive: backslash, double quote, and the
 * `%` specifier prefix, which systemd expands anywhere in a unit file
 * regardless of quoting.
 *
 * Order is irrelevant: no replacement introduces a character a later one
 * matches.
 */
function escapeForSystemd(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/%/g, "%%");
}

/**
 * ENFORCEMENT SITE for "a literal `$` in an ExecStart word is written `$$`".
 *
 * systemd performs environment-variable substitution on command lines
 * (`systemd.service(5)`, "Command Lines"): `$FOO` and `${FOO}` are replaced
 * before exec, quoted or not, and `$$` is the only way to mean a literal
 * dollar. A binary installed at `/opt/${SANCTUARY_BIN}/sanctuary` therefore
 * became `ExecStart=/opt//sanctuary` at start time, because the unset variable
 * expands to nothing. The service then fails with `status=203/EXEC` and a
 * journal that shows no Sanctuary output at all, so the operator reads it as a
 * Sanctuary startup failure rather than a mangled path.
 *
 * `Environment=` deliberately does NOT get this pass; see
 * {@link renderEnvironmentAssignment}.
 */
function escapeForCommandLine(value: string): string {
  return escapeForSystemd(value).replace(/\$/g, "$$$$");
}
