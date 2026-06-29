/**
 * Sanctuary Dashboard user-domain LaunchAgent (Slice 2, D2)
 *
 * Generates and validates the per-user macOS LaunchAgent that supervises the
 * standalone dashboard server: `RunAtLoad=true` + `KeepAlive=true` so the
 * dashboard auto-restarts after a crash, registered from the signed host app
 * via SMAppService at first run (one user consent, no separate installer).
 *
 * This is the USER-DOMAIN analogue of the ROOT boot daemon in
 * `castle-wall-boot.ts`. It mirrors that file's plist shape and reuses its
 * `FORBIDDEN_PLIST_ENV` hard constraint: the plist is world-readable, so it
 * MUST NOT carry the passphrase or recovery key. The supervised process boots
 * with `--allow-park`, so a locked start (no credential) parks instead of
 * crash-looping; the operator unlocks once in-process.
 *
 * SMAppService consumes a plist BUNDLED in the app
 * (`Contents/Library/LaunchAgents/<label>.plist`), so this generator is mainly
 * a build-time / validation artifact rather than something written into
 * `~/Library` at runtime. The validator (`dashboardLaunchAgentWellFormed`) is
 * the user-domain analogue of `bootServiceInstalled`: it confirms a plist is
 * THE dashboard supervision unit, not merely that a file exists.
 *
 * No em-dashes appear in this file (hyphens only).
 */

import { isAbsolute, join } from "node:path";
import { FORBIDDEN_PLIST_ENV } from "./castle-wall-boot.js";

/**
 * The LaunchAgent label (per Slice 2 spec). User session domain, NOT a
 * LaunchDaemon: the dashboard needs the user's unlock to function and must
 * never run as root.
 */
export const DASHBOARD_LAUNCHAGENT_LABEL = "ai.sanctuaryprotocol.dashboard";

/**
 * Canonical bundled path inside the signed host app that SMAppService reads.
 * Relative to the app bundle root; the Swift side resolves it against
 * `Bundle.main`.
 */
export const DASHBOARD_LAUNCHAGENT_BUNDLE_RELPATH = `Contents/Library/LaunchAgents/${DASHBOARD_LAUNCHAGENT_LABEL}.plist`;

const SAFE_NAME_RE = /^[a-zA-Z0-9._-]+$/;

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function assertNoControlChars(value: string, what: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

export interface DashboardLaunchAgentOptions {
  /**
   * Full argv the dashboard runs as, e.g.
   * ["/usr/local/bin/node", "/path/dist/cli.js", "dashboard", "--allow-park", "--no-open"].
   * First element must be an absolute path. The args MUST include `--allow-park`
   * (the park-not-exit opt-in that prevents the KeepAlive crash-loop on a
   * locked start).
   */
  programArguments: string[];
  /**
   * Optional absolute fortress path. Rendered as `SANCTUARY_STORAGE_PATH` in
   * the plist env. This is a PATH, not a secret, so it is safe to embed; it
   * pins the tenant the supervised dashboard boots against. Omit to inherit
   * the default `~/.sanctuary`.
   */
  fortressPath?: string;
  /** Absolute log directory. Defaults to <fortressPath>/logs when fortressPath is set. */
  logDir?: string;
  /**
   * Absolute directory of the Node interpreter (typically
   * `dirname(process.execPath)`), prepended to the agent's PATH so a
   * `#!/usr/bin/env node` shim resolves `node` under launchd's minimal PATH.
   * Same survival concern as the boot daemon. Omitted only when the program
   * path is already an absolute interpreter (dev/test).
   */
  nodeBinDir?: string;
  /**
   * Optional EXTRA non-secret env entries. Each name is checked against
   * FORBIDDEN_PLIST_ENV (the render throws if any forbidden name appears).
   * Use sparingly; the plist is world-readable.
   */
  extraEnv?: Array<[string, string]>;
}

/**
 * Render the user-domain dashboard LaunchAgent plist.
 *
 * Mirrors `castle-wall-boot.ts`'s daemon plist: `RunAtLoad=true`,
 * `KeepAlive=true`, `ThrottleInterval=5` (the crash-loop dampener),
 * `StandardOutPath`/`StandardErrorPath`, `WorkingDirectory`. Fail-closed:
 * throws on a non-absolute program path, on a missing `--allow-park`, on a
 * forbidden env name, or on any control character.
 */
export function generateDashboardLaunchAgentPlist(
  opts: DashboardLaunchAgentOptions,
): string {
  if (opts.programArguments.length === 0) {
    throw new Error("programArguments must not be empty.");
  }
  const programPath = opts.programArguments[0]!;
  if (!isAbsolute(programPath)) {
    throw new Error(
      `LaunchAgent program path must be absolute (got: ${programPath}).`,
    );
  }
  // HARD CONSTRAINT (park-not-exit): the supervised dashboard MUST boot with
  // --allow-park, or a locked start exits and KeepAlive crash-loops. Refuse to
  // render a unit that would re-introduce the loop.
  if (!opts.programArguments.includes("--allow-park")) {
    throw new Error(
      "Dashboard LaunchAgent ProgramArguments must include --allow-park " +
        "(park-not-exit is required so a locked start does not crash-loop " +
        "under KeepAlive).",
    );
  }
  for (const arg of opts.programArguments) {
    assertNoControlChars(arg, "program argument");
  }

  if (opts.fortressPath !== undefined) {
    if (!isAbsolute(opts.fortressPath)) {
      throw new Error(
        `Fortress path must be absolute (got: ${opts.fortressPath}).`,
      );
    }
    assertNoControlChars(opts.fortressPath, "fortress path");
  }

  const logDir =
    opts.logDir ??
    (opts.fortressPath ? join(opts.fortressPath, "logs") : undefined);
  if (logDir !== undefined) {
    if (!isAbsolute(logDir)) {
      throw new Error(`Log dir must be absolute (got: ${logDir}).`);
    }
    assertNoControlChars(logDir, "log dir");
  }

  // PATH: prepend the interpreter dir (validated) so a CLI shim resolves node.
  const pathDirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
  if (opts.nodeBinDir !== undefined) {
    if (!isAbsolute(opts.nodeBinDir)) {
      throw new Error(
        `node interpreter dir must be absolute (got: ${opts.nodeBinDir}).`,
      );
    }
    assertNoControlChars(opts.nodeBinDir, "node interpreter dir");
    if (!pathDirs.includes(opts.nodeBinDir)) {
      pathDirs.unshift(opts.nodeBinDir);
    }
  }

  const envEntries: Array<[string, string]> = [["PATH", pathDirs.join(":")]];
  if (opts.fortressPath !== undefined) {
    envEntries.push(["SANCTUARY_STORAGE_PATH", opts.fortressPath]);
  }
  for (const extra of opts.extraEnv ?? []) {
    envEntries.push(extra);
  }
  for (const [name, value] of envEntries) {
    if (FORBIDDEN_PLIST_ENV.includes(name)) {
      throw new Error(
        `Refusing to embed ${name} in a world-readable LaunchAgent plist.`,
      );
    }
    if (!SAFE_NAME_RE.test(name)) {
      throw new Error(`Unsafe environment variable name: ${name}`);
    }
    assertNoControlChars(value, `environment value for ${name}`);
  }

  const argsXml = opts.programArguments
    .map((a) => `\t\t<string>${xmlEscape(a)}</string>`)
    .join("\n");
  const envXml = envEntries
    .map(
      ([k, v]) =>
        `\t\t<key>${xmlEscape(k)}</key>\n\t\t<string>${xmlEscape(v)}</string>`,
    )
    .join("\n");

  const resolvedLogDir = logDir ?? "/tmp";
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(DASHBOARD_LAUNCHAGENT_LABEL)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>KeepAlive</key>
\t<true/>
\t<key>ThrottleInterval</key>
\t<integer>5</integer>
\t<key>EnvironmentVariables</key>
\t<dict>
${envXml}
\t</dict>
\t<key>StandardOutPath</key>
\t<string>${xmlEscape(join(resolvedLogDir, "dashboard.log"))}</string>
\t<key>StandardErrorPath</key>
\t<string>${xmlEscape(join(resolvedLogDir, "dashboard.err.log"))}</string>
\t<key>WorkingDirectory</key>
\t<string>/</string>
</dict>
</plist>
`;
}

/**
 * Validate that a string is a well-formed dashboard LaunchAgent plist: the
 * expected Label, `RunAtLoad=true`, `KeepAlive=true`, a `--allow-park`
 * ProgramArguments entry, and NEITHER forbidden env name present. The
 * user-domain analogue of `bootServiceInstalled` (well-formed, not merely
 * present). Returns false on any deviation (fail-closed). String-based so it
 * works on a bundled plist read by the host app or by a test, with no
 * filesystem dependency.
 */
export function dashboardLaunchAgentWellFormed(contents: string): boolean {
  // Label must match exactly.
  const labelMatch = contents.match(
    /<key>\s*Label\s*<\/key>\s*<string>([\s\S]*?)<\/string>/,
  );
  if (!labelMatch || labelMatch[1] !== DASHBOARD_LAUNCHAGENT_LABEL) {
    return false;
  }
  // RunAtLoad=true (key immediately followed by <true/>).
  if (!/<key>\s*RunAtLoad\s*<\/key>\s*<true\s*\/>/.test(contents)) {
    return false;
  }
  // KeepAlive=true.
  if (!/<key>\s*KeepAlive\s*<\/key>\s*<true\s*\/>/.test(contents)) {
    return false;
  }
  // --allow-park must be in the ProgramArguments.
  if (!/<string>\s*--allow-park\s*<\/string>/.test(contents)) {
    return false;
  }
  // Hard constraint: NEITHER forbidden env name may appear anywhere in the
  // plist (the world-readable-secret-leak guard).
  for (const forbidden of FORBIDDEN_PLIST_ENV) {
    if (contents.includes(forbidden)) {
      return false;
    }
  }
  return true;
}
