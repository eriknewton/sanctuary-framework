/**
 * sanctuary castle-wall install-boot | uninstall-boot | provision-boot-token
 *
 * F1 (Option C, hybrid split-credential): ship the Castle Wall fortress daemon
 * as a launchd boot service so a reboot while the wall is armed no longer
 * bricks the box — WITHOUT ever placing the high-value fortress secret in the
 * pre-login boot context.
 *
 * The brick condition this closes: the macOS content filter (sysext) is
 * re-engaged by the system at boot, but the fortress daemon that delivers
 * policy and answers approvals was never a boot service. The box came up
 * fail-closed (deny-by-default per the provider design) with no daemon, no
 * policy delivery, and no approval path: SSH locked out, "never reboot while
 * armed" discipline forced.
 *
 * THE SPLIT CREDENTIAL (why Option C, and what changed from the held #450):
 *   - A LaunchDaemon that must run unattended at cold boot, before any login,
 *     cannot use the Secure Enclave at all on macOS (SE needs a user session +
 *     the data-protection keychain, neither present pre-login — structural, not
 *     a missing entitlement; see F1_SecureEnclave_Feasibility_2026-06-10.md).
 *     #450 resolved this by copying the WHOLE fortress passphrase into a
 *     machine-key-encrypted file the boot daemon could read — a real custody
 *     downgrade the 2026-06-10 decision rejected.
 *   - Option C splits the one secret into two:
 *       BOOT TOKEN (this path) — a small software-protected random value, NOT
 *       the passphrase, sufficient only to bring the daemon up in SAFE MODE
 *       (enforce the persisted signed manifest, deny agents, keep SSH up,
 *       audit under a boot-token-derived key). Compromising it cannot decrypt
 *       fortress state or forge policy.
 *       OPERATIONAL SECRET — the high-value master key. It stays in the login
 *       Keychain (SE-binding is host-app follow-on work) and is NEVER present
 *       pre-login; full operation waits for first login.
 *
 * What launchd CAN and CANNOT guarantee, precisely:
 *   - launchd cannot order a LaunchDaemon strictly BEFORE the NE content
 *     filter engages; sysextd manages the filter independently of any
 *     daemon's plist. Strict happens-before is not achievable here.
 *   - It does not need to be. The provider design already fails SAFE
 *     (= CLOSED / deny) in the window before the daemon is up:
 *       (a) with a pinned key + persisted last-valid signed manifest, the
 *           sysext recovers that manifest (signature-verified against the
 *           pinned PUBLIC key, no secret) at start and enforces last-known
 *           policy;
 *       (b) with no recovered manifest, the engine has zero rules and no
 *           agent-origin descriptor, so everything classifies `.agent` and
 *           denies (machine-wide default-deny).
 *     The safe-mode daemon's job at boot is LIVENESS: come up within seconds,
 *     re-deliver the current signed manifest via the root helper, and keep the
 *     box reachable. KeepAlive restarts it on crash.
 *
 * Privilege model: the safe-mode boot LaunchDaemon runs in the SYSTEM (root)
 * context. This is a deliberate change from #450's operator daemon and is
 * sound BECAUSE of the split: the boot daemon holds only the low-value boot
 * token, so root context never exposes the secret that matters. Root is also
 * the only context that can read a root-only 0600 token and the file-based
 * System keychain at boot. Full-operation signing still routes through the
 * root signer helper (A2/B2); no private key reaches this process.
 *
 * Secrets NEVER go into the plist: /Library/LaunchDaemons plists are
 * root-owned but world-readable (0644). The renderer rejects any attempt to
 * embed direct Sanctuary secrets or proxy variables that may carry credentials.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, rm, stat } from "node:fs/promises";
import { createConnection } from "node:net";
import { basename, isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";

import { AuditLog } from "../operational/audit-log.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  CASTLE_BOOT_TOKEN_PATH,
  deriveSafeModeAuditKey,
  generateBootToken,
  persistBootToken,
  readBootToken,
  safeModeAuditStoragePath,
} from "../castle-wall/boot/boot-token.js";
import { resolveCastleWallSocketPath } from "../castle-wall/runtime/socket-path.js";
import {
  normalizeFortressCustody,
  resolveSudoIdentityDecision,
  type NormalizeFortressCustodyInput,
  type NormalizeFortressCustodyOutcome,
} from "../castle-wall/provision/fortress-custody.js";
import { resolveFortressCreateOwner } from "../castle-wall/runtime/fortress-create-owner.js";
import { consumeFlagValue } from "./argv.js";
import {
  CASTLE_WALL_BOOT_RUNTIME_DIR,
  installBootRuntimeSnapshot,
  isContentAddressedBootRuntimePath,
  removeBootRuntimeSnapshot,
  type InstallBootRuntimeOptions,
} from "./castle-wall-boot-runtime.js";

export const CASTLE_WALL_BOOT_LABEL = "ai.sanctuaryprotocol.castle-wall.daemon";
export const CASTLE_WALL_BOOT_PLIST_PATH = `/Library/LaunchDaemons/${CASTLE_WALL_BOOT_LABEL}.plist`;
export const LAUNCHCTL_TIMEOUT_MS = 15_000;
export const LAUNCHCTL_KILL_SIGNAL = "SIGKILL";
const CASTLE_GLOBAL_PINNED_PUBKEY_PATH =
  "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin";
const CASTLE_WALL_APP_PATH = "/Applications/Sanctuary-CastleWall.app";
const CASTLE_WALL_APP_BOOT_NODE =
  "/Applications/Sanctuary-CastleWall.app/Contents/Resources/boot-runtime/node";
const CASTLE_WALL_APP_BOOT_DAEMON =
  "/Applications/Sanctuary-CastleWall.app/Contents/Resources/boot-runtime/castle-wall-boot-daemon.js";
const CASTLE_WALL_BOOT_LOG_DIR = "/var/log";
const SAFE_NAME_RE = /^[a-zA-Z0-9._-]+$/;
/**
 * Env names that must never be rendered into a LaunchDaemon plist. The plist
 * is world-readable; these may carry master or proxy credentials.
 */
export const FORBIDDEN_PLIST_ENV = [
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_KEY",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "https_proxy",
  "http_proxy",
];

const CREDENTIALED_URL_VALUE_RE = /:\/\/[^/@\s]*:[^/@\s]*@/;

export interface ExecFileResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface CastleWallBootContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  getuid?: () => number;
  /** Run a binary WITHOUT a shell (no injection surface). Tests inject. */
  execFileFn?: (cmd: string, args: string[]) => ExecFileResult;
  /** Override the LaunchDaemon plist destination (tests). */
  plistPath?: string;
  /** Override the root-owned global pin path (tests). */
  globalPinPath?: string;
  /** Override the boot-token custody path (tests). */
  bootTokenPath?: string;
  /** Override the root-owned boot-runtime directory (tests). */
  bootRuntimeDir?: string;
  /** Override the runtime snapshot installer (tests). */
  installBootRuntimeFn?: typeof installBootRuntimeSnapshot;
  /** Override the runtime snapshot remover (tests). */
  removeBootRuntimeFn?: typeof removeBootRuntimeSnapshot;
  /** Override the running Node source copied into the root boot runtime (tests). */
  nodeExecPath?: string;
  /** Override the self-contained boot-daemon source copied into custody (tests). */
  bootDaemonSourcePath?: string;
  /** Extra custody overrides used only with a test bootRuntimeDir. */
  bootRuntimeProtectedDir?: string;
  bootRuntimeTrustedAncestorDir?: string;
  bootRuntimeExpectedOwnerUid?: number;
  /**
   * Sleep used by the post-bootstrap stability check (tests inject a no-op so
   * they don't actually wait). Defaults to a real timer.
   */
  sleepFn?: (ms: number) => Promise<void>;
  /**
   * Bounded live-listener probe for uninstall cleanup. Tests inject this so the
   * stale-socket guard does not depend on local Unix socket permissions.
   */
  socketHasLiveListenerFn?: (socketPath: string) => Promise<boolean>;
  /**
   * Override the end-of-flow custody-normalize chokepoint (tests). Defaults
   * to {@link normalizeFortressCustody}.
   */
  normalizeFortressCustody?: (
    input: NormalizeFortressCustodyInput,
  ) => Promise<NormalizeFortressCustodyOutcome>;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function writeBootParseError(parsed: ParsedBootArgs, err: Writable): boolean {
  if (parsed.error === undefined) return false;
  write(err, `${parsed.error}\n`);
  return true;
}

function defaultExecFile(cmd: string, args: string[]): ExecFileResult {
  const result = spawnSync(cmd, args, {
    encoding: "utf8",
    timeout: LAUNCHCTL_TIMEOUT_MS,
    killSignal: LAUNCHCTL_KILL_SIGNAL,
  });
  const errorText = result.error ? `${result.error.name}: ${result.error.message}` : "";
  return {
    code: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: [result.stderr ?? "", errorText].filter(Boolean).join("\n"),
  };
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function xmlUnescape(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

type ParsedPlistValue =
  | string
  | number
  | boolean
  | ParsedPlistValue[]
  | { [key: string]: ParsedPlistValue };

type PlistToken =
  | { type: "dict-open" }
  | { type: "dict-close" }
  | { type: "array-open" }
  | { type: "array-close" }
  | { type: "key"; value: string }
  | { type: "string"; value: string }
  | { type: "integer"; value: number }
  | { type: "boolean"; value: boolean };

function tokenizePlist(contents: string): PlistToken[] {
  const tokens: PlistToken[] = [];
  const tokenRe =
    /<dict(?:\s[^>]*)?>|<\/dict\s*>|<array(?:\s[^>]*)?>|<\/array\s*>|<key>([\s\S]*?)<\/key>|<string>([\s\S]*?)<\/string>|<integer>([-+]?\d+)<\/integer>|<true\s*\/>|<false\s*\/>/g;
  for (const match of contents.matchAll(tokenRe)) {
    const raw = match[0];
    if (raw.startsWith("<dict")) tokens.push({ type: "dict-open" });
    else if (raw.startsWith("</dict")) tokens.push({ type: "dict-close" });
    else if (raw.startsWith("<array")) tokens.push({ type: "array-open" });
    else if (raw.startsWith("</array")) tokens.push({ type: "array-close" });
    else if (raw.startsWith("<key>")) {
      tokens.push({ type: "key", value: xmlUnescape(match[1] ?? "") });
    } else if (raw.startsWith("<string>")) {
      tokens.push({ type: "string", value: xmlUnescape(match[2] ?? "") });
    } else if (raw.startsWith("<integer>")) {
      tokens.push({ type: "integer", value: Number.parseInt(match[3] ?? "", 10) });
    } else if (raw.startsWith("<true")) tokens.push({ type: "boolean", value: true });
    else if (raw.startsWith("<false")) tokens.push({ type: "boolean", value: false });
  }
  return tokens;
}

function parseBootPlist(contents: string): Record<string, ParsedPlistValue> | null {
  const tokens = tokenizePlist(contents);
  let index = 0;

  function parseValue(): ParsedPlistValue | null {
    const token = tokens[index++];
    if (!token) return null;
    if (
      token.type === "string" ||
      token.type === "integer" ||
      token.type === "boolean"
    ) {
      return token.value;
    }
    if (token.type === "array-open") {
      const values: ParsedPlistValue[] = [];
      while (tokens[index]?.type !== "array-close") {
        const value = parseValue();
        if (value === null) return null;
        values.push(value);
      }
      index++;
      return values;
    }
    if (token.type === "dict-open") {
      const obj: Record<string, ParsedPlistValue> = {};
      while (tokens[index]?.type !== "dict-close") {
        const keyToken = tokens[index++];
        if (!keyToken || keyToken.type !== "key") return null;
        if (Object.prototype.hasOwnProperty.call(obj, keyToken.value)) return null;
        const value = parseValue();
        if (value === null) return null;
        obj[keyToken.value] = value;
      }
      index++;
      return obj;
    }
    return null;
  }

  while (index < tokens.length && tokens[index]?.type !== "dict-open") index++;
  if (index >= tokens.length) return null;
  const parsed = parseValue();
  return parsed && !Array.isArray(parsed) && typeof parsed === "object"
    ? (parsed as Record<string, ParsedPlistValue>)
    : null;
}

function assertNoControlChars(value: string, what: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

function assertNoCredentialedPlistValue(name: string, value: string): void {
  if (CREDENTIALED_URL_VALUE_RE.test(value)) {
    throw new Error(
      `Refusing to embed ${name} value containing URL credentials in a world-readable LaunchDaemon plist.`,
    );
  }
}

export interface BootPlistOptions {
  /**
   * Full argv the daemon runs as, e.g.
   * ["/usr/local/bin/node", "/path/dist/cli.js", "castle-wall", "daemon", "--safe-mode", "--launchd"].
   * First element must be an absolute path; the args MUST include `--safe-mode`.
   */
  programArguments: string[];
  /** Absolute fortress path (SANCTUARY_STORAGE_PATH for the daemon). */
  fortressPath: string;
  /** Absolute path to the castle-wall-signer-client shim (helper mode, required). */
  signerClientPath: string;
  /** Log directory; defaults to <fortressPath>/logs. */
  logDir?: string;
}

/**
 * Render the SAFE-MODE boot LaunchDaemon plist. Pure: no I/O. Throws on any
 * input that would produce an unsafe or non-functional unit (fail-closed at
 * render time, not at boot time).
 *
 * The service runs in the SYSTEM (root) context (no `UserName` key). This is
 * the Option C model: a root daemon holding only the low-value boot token, so
 * no high-value secret enters the boot context. Signing is delegated to the
 * root signer helper; local signing (which needs the master key) is not a boot
 * option at all, so there is no `localSign` here.
 */
export function renderBootLaunchDaemonPlist(opts: BootPlistOptions): string {
  if (opts.programArguments.length === 0) {
    throw new Error("programArguments must not be empty.");
  }
  const program = opts.programArguments[0]!;
  if (!isAbsolute(program)) {
    throw new Error(`Program path must be absolute (got: ${program}).`);
  }
  for (const arg of opts.programArguments) {
    assertNoControlChars(arg, "program argument");
    assertNoCredentialedPlistValue("program argument", arg);
  }
  if (!opts.programArguments.includes("--safe-mode")) {
    // Fail-closed: the boot service must come up in safe mode (boot token only,
    // no master key). A boot unit that tried to run the full daemon would have
    // no passphrase at boot and never start.
    throw new Error(
      "The boot service must run in --safe-mode (the boot context never holds the master key).",
    );
  }
  if (!isAbsolute(opts.fortressPath)) {
    throw new Error(`Fortress path must be absolute (got: ${opts.fortressPath}).`);
  }
  assertNoControlChars(opts.fortressPath, "fortress path");
  if (!opts.signerClientPath) {
    // Fail-closed at render time: without a signer the safe-mode daemon refuses
    // to start at boot, which re-creates the brick condition under KeepAlive churn.
    throw new Error(
      "A signer-client shim is required: safe mode signs only via the root helper.",
    );
  }
  if (!isAbsolute(opts.signerClientPath)) {
    throw new Error(`Signer client path must be absolute (got: ${opts.signerClientPath}).`);
  }
  assertNoControlChars(opts.signerClientPath, "signer client path");
  const logDir = opts.logDir ?? join(opts.fortressPath, "logs");
  if (!isAbsolute(logDir)) {
    throw new Error(`Log dir must be absolute (got: ${logDir}).`);
  }
  assertNoControlChars(logDir, "log dir");

  // The root service executes a content-addressed Node snapshot by absolute
  // path. Keep PATH system-only so no operator-writable package-manager
  // directory can become an indirect root executable input.
  const pathDirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
  const envEntries: Array<[string, string]> = [
    ["PATH", pathDirs.join(":")],
    ["SANCTUARY_STORAGE_PATH", opts.fortressPath],
    ["SANCTUARY_CASTLE_SIGNER_CLIENT", opts.signerClientPath],
  ];
  for (const [name] of envEntries) {
    if (FORBIDDEN_PLIST_ENV.includes(name)) {
      throw new Error(
        `Refusing to embed ${name} in a world-readable LaunchDaemon plist.`,
      );
    }
  }
  for (const [name, value] of envEntries) {
    assertNoCredentialedPlistValue(name, value);
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

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(CASTLE_WALL_BOOT_LABEL)}</string>
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
\t<string>${xmlEscape(join(logDir, "castle-wall-daemon.log"))}</string>
\t<key>StandardErrorPath</key>
\t<string>${xmlEscape(join(logDir, "castle-wall-daemon.err.log"))}</string>
\t<key>WorkingDirectory</key>
\t<string>/</string>
</dict>
</plist>
`;
}

function plistDictValue(
  plist: Record<string, ParsedPlistValue>,
  key: string,
): Record<string, ParsedPlistValue> | null {
  const value = plist[key];
  return value && !Array.isArray(value) && typeof value === "object"
    ? (value as Record<string, ParsedPlistValue>)
    : null;
}

function plistStringArrayValue(
  plist: Record<string, ParsedPlistValue>,
  key: string,
): string[] | null {
  const value = plist[key];
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? (value as string[])
    : null;
}

function supportedLegacyCastleWallCliPath(path: string): boolean {
  const name = path.split("/").pop();
  return name === "sanctuary" || name === "sanctuary-framework" ||
    name === "cli.js" || name === "cli.cjs";
}

function programArgumentsRunCastleWallDaemon(
  programArguments: string[],
  allowLegacyTestPath = false,
): boolean {
  const daemonArgs = ["castle-wall", "daemon", "--safe-mode", "--launchd"];
  if (allowLegacyTestPath && programArguments.length === 5) {
    const [program, ...args] = programArguments;
    return Boolean(program && isAbsolute(program) && supportedLegacyCastleWallCliPath(program)) &&
      args.every((arg, index) => arg === daemonArgs[index]);
  }
  if (programArguments.length === 6) {
    const [interpreter, script, ...args] = programArguments;
    return Boolean(
      interpreter &&
        script &&
        (allowLegacyTestPath
          ? isAbsolute(interpreter) && isAbsolute(script) &&
            (supportedLegacyCastleWallCliPath(script) ||
              isContentAddressedBootRuntimePath(script, "cli"))
          : isContentAddressedBootRuntimePath(interpreter, "node") &&
            isContentAddressedBootRuntimePath(script, "cli")),
    ) && args.every((arg, index) => arg === daemonArgs[index]);
  }
  return false;
}

async function contentAddressedRuntimeFileValid(
  path: string,
  kind: "node" | "cli" | "signer-client",
): Promise<boolean> {
  if (!isContentAddressedBootRuntimePath(path, kind)) return false;
  const name = basename(path);
  const digest = name
    .replace(/^(?:node|cli|signer-client)-/, "")
    .replace(/\.js$/, "");
  const expectedMode = kind === "cli" ? 0o444 : 0o555;
  try {
    const data = await readFileCustody(path, {
      uid: 0,
      mode: { exact: expectedMode },
      parent: { uid: 0, mode: { rejectGroupOrOtherWrite: true } },
      verifyPathIdentity: true,
    });
    return createHash("sha256").update(data).digest("hex") === digest;
  } catch {
    return false;
  }
}

/**
 * Validate that a persistent, well-formed Castle Wall BOOT service is installed
 * — not merely that a file exists at the path (#450 item 5 / codex 2026-06-14).
 * Reads the world-readable plist and confirms it is THE boot-survival unit:
 * expected Label, `RunAtLoad=true`, `KeepAlive=true`, a launchd safe-mode
 * `castle-wall daemon` argv, and the signer/fortress environment required for
 * the daemon to start after reboot. When `expectedFortressPath` is supplied,
 * also confirms the service targets that same fortress through its
 * `SANCTUARY_STORAGE_PATH` environment value. Returns false on absent /
 * unreadable / malformed / wrong-label / non-safe-mode / wrong-fortress
 * (fail-closed: an unverifiable boot service is treated as not installed for
 * this guard).
 *
 * RESIDUAL (honest): from the operator context this cannot detect a root
 * `launchctl disable system/<label>` override — that state lives in launchd's
 * root-owned database, unreadable without root. `bootServiceReady` separately
 * requires a stable live pid for paths that want to no-op instead of
 * re-bootstrap.
 */
export async function bootServiceInstalled(
  plistPath: string = CASTLE_WALL_BOOT_PLIST_PATH,
  expectedFortressPath?: string,
): Promise<boolean> {
  let contents: string;
  try {
    contents = await readFileCustody(plistPath, {
      encoding: "utf8",
      verifyPathIdentity: true,
    });
  } catch {
    return false;
  }
  const plist = parseBootPlist(contents);
  if (!plist) return false;
  if (plist.Label !== CASTLE_WALL_BOOT_LABEL) return false;
  if (plist.RunAtLoad !== true) return false;
  if (plist.KeepAlive !== true) return false;
  const programArguments = plistStringArrayValue(plist, "ProgramArguments");
  const nonProductionPlistOverride = plistPath !== CASTLE_WALL_BOOT_PLIST_PATH;
  if (
    !programArguments ||
    !programArgumentsRunCastleWallDaemon(programArguments, nonProductionPlistOverride)
  ) return false;
  if (
    plistPath === CASTLE_WALL_BOOT_PLIST_PATH &&
    (
      !(await contentAddressedRuntimeFileValid(programArguments[0]!, "node")) ||
      !(await contentAddressedRuntimeFileValid(programArguments[1]!, "cli"))
    )
  ) return false;
  const environment = plistDictValue(plist, "EnvironmentVariables");
  if (!environment) return false;
  const installedFortressPathRaw = environment.SANCTUARY_STORAGE_PATH;
  if (typeof installedFortressPathRaw !== "string") return false;
  if (!isAbsolute(installedFortressPathRaw)) return false;
  const signerClientPath = environment.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (typeof signerClientPath !== "string" || !isAbsolute(signerClientPath)) return false;
  if (
    !nonProductionPlistOverride &&
    !isContentAddressedBootRuntimePath(signerClientPath, "signer-client")
  ) return false;
  if (
    plistPath === CASTLE_WALL_BOOT_PLIST_PATH &&
    !(await contentAddressedRuntimeFileValid(signerClientPath, "signer-client"))
  ) return false;
  if (expectedFortressPath !== undefined) {
    const installedFortressPath = resolve(installedFortressPathRaw);
    const expectedFortressPathResolved = resolve(expectedFortressPath);
    if (installedFortressPath !== expectedFortressPathResolved) return false;
  }
  return true;
}

export async function bootServicePlistPresent(
  plistPath: string = CASTLE_WALL_BOOT_PLIST_PATH,
): Promise<boolean> {
  try {
    await lstat(plistPath);
    return true;
  } catch (error) {
    const code = error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
    return code === "ENOENT" ? false : true;
  }
}

function printBootService(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
): ExecFileResult {
  return execFileFn("launchctl", ["print", `system/${CASTLE_WALL_BOOT_LABEL}`]);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function bootServiceEnabled(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult = defaultExecFile,
): boolean {
  const result = execFileFn("launchctl", ["print-disabled", "system"]);
  if (result.code !== 0) {
    return false;
  }
  const re = new RegExp(`["']?${escapeRegExp(CASTLE_WALL_BOOT_LABEL)}["']?\\s*=>\\s*([^\\n,;]+)`);
  const match = re.exec(result.stdout);
  if (!match) {
    return true;
  }
  const value = match[1]!.trim().replace(/^["']|["']$/g, "").toLowerCase();
  if (value === "false" || value === "enabled") {
    return true;
  }
  if (value === "true" || value === "disabled") {
    return false;
  }
  return false;
}

export interface BootServiceLoadState {
  loaded: boolean;
  fortressPath: string | null;
}

function fortressPathFromLaunchdPrint(stdout: string): string | null {
  const match =
    /"?SANCTUARY_STORAGE_PATH"?\s*=>\s*"?([^\n"]+)"?/.exec(stdout) ??
    /"?SANCTUARY_STORAGE_PATH"?\s*=\s*"?([^\n"]+)"?/.exec(stdout);
  const raw = match?.[1]?.trim().replace(/[;,]+$/, "") ?? null;
  return raw && isAbsolute(raw) ? resolve(raw) : null;
}

export function bootServiceLoadState(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult = defaultExecFile,
): BootServiceLoadState {
  const printed = printBootService(execFileFn);
  if (printed.code !== 0) {
    return { loaded: !launchctlResultWasNotLoaded(printed), fortressPath: null };
  }
  return {
    loaded: true,
    fortressPath: fortressPathFromLaunchdPrint(printed.stdout),
  };
}

export function bootServiceLoaded(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult = defaultExecFile,
): boolean {
  return bootServiceLoadState(execFileFn).loaded;
}

export async function bootServiceReady(
  plistPath: string = CASTLE_WALL_BOOT_PLIST_PATH,
  expectedFortressPath?: string,
  execFileFn: (cmd: string, args: string[]) => ExecFileResult = defaultExecFile,
  sleepFn: (ms: number) => Promise<void> = (ms) =>
    new Promise<void>((resolveSleep) => setTimeout(resolveSleep, ms)),
): Promise<boolean> {
  if (!(await bootServiceInstalled(plistPath, expectedFortressPath))) {
    return false;
  }
  if ((await awaitStableServicePid(execFileFn, sleepFn)) === null) {
    return false;
  }
  if (!bootServiceEnabled(execFileFn)) {
    return false;
  }
  if (expectedFortressPath === undefined) {
    return true;
  }
  const loaded = bootServiceLoadState(execFileFn);
  return loaded.loaded && loaded.fortressPath === resolve(expectedFortressPath);
}

interface ParsedBootArgs {
  fortress?: string;
  user?: string;
  binary?: string;
  signerClient?: string;
  yes: boolean;
  rotate: boolean;
  error?: string;
}

export function parseBootArgs(argv: string[]): ParsedBootArgs {
  const parsed: ParsedBootArgs = { yes: false, rotate: false };
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must refuse, never silently resolve the default fortress; wrong-fortress boot-service operations are a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) return { ...parsed, error: fortress.error };
  if (fortress.value !== undefined) parsed.fortress = fortress.value;

  for (let i = 0; i < fortress.argv.length; i++) {
    const arg = fortress.argv[i]!;
    if (arg === "--user") parsed.user = fortress.argv[++i];
    else if (arg.startsWith("--user=")) parsed.user = arg.slice("--user=".length);
    else if (arg === "--binary") parsed.binary = fortress.argv[++i];
    else if (arg.startsWith("--binary=")) parsed.binary = arg.slice("--binary=".length);
    else if (arg === "--signer-client") parsed.signerClient = fortress.argv[++i];
    else if (arg.startsWith("--signer-client=")) {
      parsed.signerClient = arg.slice("--signer-client=".length);
    } else if (arg === "--yes" || arg === "-y") parsed.yes = true;
    else if (arg === "--rotate") parsed.rotate = true;
  }
  return parsed;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function fortressPathFromBootPlistContents(contents: string | null): string | null {
  if (contents === null) return null;
  const plist = parseBootPlist(contents);
  if (!plist) return null;
  const environment = plist.EnvironmentVariables;
  if (!environment || Array.isArray(environment) || typeof environment !== "object") {
    return null;
  }
  const raw = environment.SANCTUARY_STORAGE_PATH;
  return typeof raw === "string" && isAbsolute(raw) ? resolve(raw) : null;
}

function resolveUninstallFortressPath(
  parsed: ParsedBootArgs,
  env: NodeJS.ProcessEnv,
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
  existingPlist: string | null,
): string | null {
  if (parsed.fortress && isAbsolute(parsed.fortress)) {
    return resolve(parsed.fortress);
  }
  const fromPlist = fortressPathFromBootPlistContents(existingPlist);
  if (fromPlist) {
    return fromPlist;
  }
  if (env.SANCTUARY_STORAGE_PATH && isAbsolute(env.SANCTUARY_STORAGE_PATH)) {
    return resolve(env.SANCTUARY_STORAGE_PATH);
  }
  const user = parsed.user ?? env.SUDO_USER;
  if (user && SAFE_NAME_RE.test(user)) {
    const home = deriveOperatorHome(user, execFileFn);
    if (home) {
      return resolve(home, ".sanctuary");
    }
  }
  return null;
}

async function removeStaleCastleSocket(
  socketPath: string,
  err: Writable,
  socketHasLiveListener: (socketPath: string) => Promise<boolean> = castleSocketHasLiveListener,
): Promise<{ ok: boolean; removed: boolean }> {
  try {
    const st = await lstat(socketPath);
    if (!st.isSocket() && !st.isSymbolicLink()) {
      write(err, `Warning: not removing ${socketPath}; it exists but is not a Unix socket.\n`);
      return { ok: true, removed: false };
    }
    let live = false;
    try {
      live = await socketHasLiveListener(socketPath);
    } catch (error) {
      write(
        err,
        `Warning: not removing ${socketPath}; could not prove it is stale: ${
          error instanceof Error ? error.message : String(error)
        }\n`,
      );
      return { ok: true, removed: false };
    }
    if (live) {
      write(
        err,
        `Warning: not removing ${socketPath}; a Castle Wall daemon is accepting connections there.\n`,
      );
      return { ok: true, removed: false };
    }
    await rm(socketPath);
    return { ok: true, removed: true };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: true, removed: false };
    }
    write(err, `Error removing stale Castle Wall socket ${socketPath}: ${(error as Error).message}\n`);
    return { ok: false, removed: false };
  }
}

function castleSocketHasLiveListener(socketPath: string): Promise<boolean> {
  return new Promise((resolveProbe) => {
    let settled = false;
    const socket = createConnection({ path: socketPath });
    const finish = (alive: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolveProbe(alive);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(1000, () => finish(false));
  });
}

function launchctlResultWasNotLoaded(result: ExecFileResult): boolean {
  if (result.code === 0) return false;
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return (
    text.includes("no such process") ||
    text.includes("could not find service") ||
    text.includes("not found") ||
    text.includes("does not exist")
  );
}

function bootOutFailedCastleWallUnit(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
  err: Writable,
  plistPath: string,
): boolean {
  const bootout = execFileFn("launchctl", ["bootout", `system/${CASTLE_WALL_BOOT_LABEL}`]);
  if (bootout.code === 0 || launchctlResultWasNotLoaded(bootout)) {
    return true;
  }
  write(
    err,
    `launchctl bootout after failed bootstrap did not complete (exit ${bootout.code}): ${
      bootout.stderr.trim() || bootout.stdout.trim()
    }\n` +
      `The failed unit may still be loaded; ${plistPath} is left installed for manual recovery.\n`,
  );
  return false;
}

/**
 */
function deriveOperatorHome(
  user: string,
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
): string | null {
  const result = execFileFn("dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"]);
  if (result.code !== 0) return null;
  const match = /NFSHomeDirectory:\s*(\S+)/.exec(result.stdout);
  return match?.[1] ?? null;
}

/**
 * Record a boot-token custody event in the boot-token-keyed audit segment.
 * The provisioning/install path runs as root and cannot open the operator's
 * master-key audit log, so boot-token lifecycle is recorded under the
 * safe-mode audit key (derivable from the token itself) in the `boot-audit`
 * namespace — the same segment the safe-mode daemon writes to. Best-effort:
 * a write failure is surfaced but never silently masks the primary outcome.
 */
async function auditBootTokenEvent(
  fortressPath: string,
  token: Uint8Array,
  operation: string,
  details: Record<string, unknown>,
): Promise<void> {
  const auditKey = deriveSafeModeAuditKey(token);
  const fortressCreateOwner = resolveFortressCreateOwner({ fortressPath });
  const storage = new FilesystemStorage(
    safeModeAuditStoragePath(fortressPath, token),
    fortressCreateOwner !== undefined ? { owner: fortressCreateOwner } : {},
  );
  const auditLog = new AuditLog(
    storage,
    auditKey,
    fortressCreateOwner !== undefined ? { createOwner: fortressCreateOwner } : undefined,
  );
  await auditLog.append(
    "l1",
    operation,
    fortressIdFromStoragePath(fortressPath),
    details,
    "success",
  );
  await auditLog.flush();
}

/**
 * Generate and persist the boot token (root-owned 0600). Idempotent: if a
 * valid token is already present it is kept unless `rotate` is set. Returns the
 * 32-byte token in use (existing or freshly minted) for any follow-on audit.
 */
async function ensureBootToken(
  bootTokenPath: string,
  rotate: boolean,
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
): Promise<{ token: Uint8Array; minted: boolean }> {
  if (!rotate) {
    const existing = await readBootToken({ path: bootTokenPath });
    if (existing.status === "ok") {
      return { token: existing.token, minted: false };
    }
  }
  const token = generateBootToken();
  await persistBootToken(token, {
    path: bootTokenPath,
    chownFn: (cmd, args) => {
      const r = execFileFn(cmd, args);
      return { code: r.code, stderr: r.stderr };
    },
  });
  return { token, minted: true };
}

/**
 * `provision-boot-token`: mint the software-protected boot token, root-owned
 * 0600, in the root-owned custody directory. Run with sudo. Idempotent; pass
 * `--rotate` to replace an existing token.
 */
export async function runProvisionBootToken(
  argv: string[] = [],
  ctx: CastleWallBootContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const execFileFn = ctx.execFileFn ?? defaultExecFile;
  const bootTokenPath = ctx.bootTokenPath ?? CASTLE_BOOT_TOKEN_PATH;
  const parsed = parseBootArgs(argv);
  if (writeBootParseError(parsed, err)) return 1;

  if (platform !== "darwin") {
    write(err, "castle-wall provision-boot-token is macOS-only.\n");
    return 1;
  }
  if (getuid?.() !== 0) {
    write(
      err,
      "provision-boot-token must run as root (it writes a root-owned 0600 token). Re-run: sudo sanctuary castle-wall provision-boot-token\n",
    );
    return 1;
  }

  // Resolve the operator fortress so the custody event lands in the right
  // boot-audit segment. The token itself lives in the system custody dir.
  const user = parsed.user ?? env.SUDO_USER;
  let fortressPath = parsed.fortress ?? env.SANCTUARY_STORAGE_PATH;
  if (!fortressPath && user && SAFE_NAME_RE.test(user)) {
    const home = deriveOperatorHome(user, execFileFn);
    if (home) fortressPath = join(home, ".sanctuary");
  }

  const normalizeFortressPath =
    fortressPath !== undefined && isAbsolute(fortressPath) ? fortressPath : undefined;
  if (normalizeFortressPath !== undefined && resolveSudoIdentityDecision(env) === undefined) {
    write(
      err,
      "Cannot resolve the non-root operator identity (SUDO_UID/SUDO_GID). Refusing to provision a boot token with fortress audit writes that cannot normalize custody. Re-run from a normal sudo invocation, not a raw root shell.\n",
    );
    return 1;
  }

  try {
    let result;
    try {
      result = await ensureBootToken(bootTokenPath, parsed.rotate, execFileFn);
    } catch (error) {
      write(err, `Error writing boot token: ${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }

    if (!result.minted) {
      write(out, `Boot token already present at ${bootTokenPath} (root-owned 0600); nothing to do. Pass --rotate to replace it.\n`);
      return 0;
    }

    if (normalizeFortressPath !== undefined) {
      try {
        await auditBootTokenEvent(normalizeFortressPath, result.token, "boot_token_provisioned", {
          source: "castle-wall-provision-boot-token",
          token_path: bootTokenPath,
          custody: "root-owned 0600, software-protected (FileVault at rest); NOT the fortress master key",
          rotated: parsed.rotate,
        });
      } catch (error) {
        write(err, `Boot token written to ${bootTokenPath}, but the boot-audit append failed: ${error instanceof Error ? error.message : String(error)}\n`);
        return 1;
      }
    }

    write(out, `Boot token provisioned: ${bootTokenPath} (root-owned, mode 0600).\n`);
    write(out, "This is the anti-brick credential only: it brings the daemon up in SAFE MODE at boot. It is NOT the fortress passphrase and cannot decrypt fortress state.\n");
    return 0;
  } finally {
    if (normalizeFortressPath !== undefined) {
      await normalizeInstallBootFortressCustody(
        normalizeFortressPath,
        env,
        err,
        ctx.normalizeFortressCustody,
      );
    }
  }
}

/**
 * Poll `launchctl print system/<label>` until the service reports a running
 * PID, or the budget is exhausted. Codex finding (a): bootstrap returning 0
 * only proves the job was accepted, NOT that the process actually started and
 * stayed up. Certifying a non-starting service would look like F1 is closed
 * while the brick survives. We require an observed running PID.
 */
function serviceRunningPid(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
): number | null {
  const printed = printBootService(execFileFn);
  if (printed.code !== 0) return null;
  // launchctl print emits a `pid = N` line only while the job has a live process.
  const match = /\bpid\s*=\s*(\d+)/.exec(printed.stdout);
  if (!match) return null;
  const pid = Number.parseInt(match[1]!, 10);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

/**
 * Confirm the boot service is STABLY running, not transiently alive. A single
 * `launchctl print` read after bootstrap can catch a doomed process in the
 * milliseconds before it exits non-zero (e.g. `env: node: No such file or
 * directory` exiting 127), then launchd throttle-restarts it on a new pid — a
 * crash loop that a one-shot check would certify as "running" (the codex-(a)
 * false-PASS observed on the 2026-06-14 drill).
 *
 * Sample the pid across a window longer than the plist's ThrottleInterval (5s):
 * tolerate a slow start (initial nulls), then require the SAME positive pid to
 * persist to the end with no restart (a restart shows a different pid or a null
 * gap). Returns the stable pid, or null if the service never stabilizes.
 */
async function awaitStableServicePid(
  execFileFn: (cmd: string, args: string[]) => ExecFileResult,
  sleepFn: (ms: number) => Promise<void>,
): Promise<number | null> {
  const SAMPLES = 6;
  const INTERVAL_MS = 1500; // 6 samples * 1.5s = ~7.5s > ThrottleInterval (5s)
  const seen: Array<number | null> = [];
  for (let i = 0; i < SAMPLES; i++) {
    if (i > 0) await sleepFn(INTERVAL_MS);
    seen.push(serviceRunningPid(execFileFn));
  }
  const last = seen[seen.length - 1];
  if (last === null) return null; // not running at the end of the window
  const distinctLivePids = new Set(seen.filter((p): p is number => p !== null));
  // Exactly one live pid across the whole window == no crash-restart happened.
  return distinctLivePids.size === 1 ? last : null;
}

/**
 * Custody-normalize chokepoint for root boot flows that touch the operator
 * fortress (fortress-ownership spec 2026-07-30 §4(a2)(1)). Hand every
 * root-owned entry back to the resolved operator before returning. Loud
 * (never silent) when the operator is unresolvable.
 */
async function normalizeInstallBootFortressCustody(
  fortressPath: string,
  env: NodeJS.ProcessEnv,
  err: Writable,
  override?: (
    input: NormalizeFortressCustodyInput,
  ) => Promise<NormalizeFortressCustodyOutcome>,
): Promise<void> {
  const identity = resolveSudoIdentityDecision(env);
  if (identity === undefined) {
    write(
      err,
      "Warning: could not resolve the operator identity (SUDO_UID/SUDO_GID), so fortress custody was not normalized. If operator surfaces report EACCES, run: sudo sanctuary castle-wall repair-custody\n",
    );
    return;
  }
  const normalize = override ?? normalizeFortressCustody;
  await normalize({
    fortressPath,
    operator: { uid: identity.uid, gid: identity.gid },
    log: (line) => write(err, `${line}\n`),
  });
}

/**
 * install-boot with the custody-normalize chokepoint on EVERY root exit path
 * (2026-07-31 gate HIGH). The log-dir `mkdir { recursive: true }` can CREATE
 * the fortress top-level dir root-owned (the Mini2 root cause), and the
 * launchd enable/bootout/bootstrap/certify sequence after it has many failure
 * returns; hanging the normalize off the success returns alone left
 * root-owned residue on all of them. Wrapping makes reachability structural.
 * The wrapper resolves the fortress the same way the inner flow does and
 * no-ops when it cannot (a pre-root/pre-arg-validation exit touched nothing).
 */
export async function runInstallBoot(
  argv: string[] = [],
  ctx: CastleWallBootContext = {},
): Promise<number> {
  const env = ctx.env ?? process.env;
  const err = ctx.err ?? process.stderr;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const parsed = parseBootArgs(argv);
  if (writeBootParseError(parsed, err)) return 1;
  if (
    (ctx.platform ?? process.platform) === "darwin" &&
    getuid?.() === 0 &&
    (parsed.user !== undefined || env.SUDO_USER !== undefined) &&
    resolveSudoIdentityDecision(env) === undefined
  ) {
    write(
      err,
      "Cannot resolve the non-root operator identity (SUDO_UID/SUDO_GID). Refusing to install a root boot service that cannot normalize fortress custody. Re-run from a normal sudo invocation, not a raw root shell.\n",
    );
    return 1;
  }
  try {
    return await runInstallBootInner(argv, ctx);
  } finally {
    if (getuid?.() === 0) {
      const fortressPath = resolveInstallBootFortressPath(argv, ctx, env);
      if (fortressPath !== undefined) {
        await normalizeInstallBootFortressCustody(
          fortressPath,
          env,
          err,
          ctx.normalizeFortressCustody,
        );
      }
    }
  }
}

/**
 * Resolve the fortress the install-boot run targets, for the wrapper's
 * chokepoint. Mirrors the inner flow's resolution (flag, then env, then the
 * operator's home via dscl) and returns undefined when it cannot be resolved
 * without guessing, in which case nothing was created to normalize.
 */
function resolveInstallBootFortressPath(
  argv: string[],
  ctx: CastleWallBootContext,
  env: NodeJS.ProcessEnv,
): string | undefined {
  const parsed = parseBootArgs(argv);
  if (parsed.error !== undefined) return undefined;
  let fortressPath = parsed.fortress ?? env.SANCTUARY_STORAGE_PATH;
  if (!fortressPath) {
    const user = parsed.user ?? env.SUDO_USER;
    if (!user || !SAFE_NAME_RE.test(user)) return undefined;
    const home = deriveOperatorHome(user, ctx.execFileFn ?? defaultExecFile);
    if (!home) return undefined;
    fortressPath = join(home, ".sanctuary");
  }
  if (!isAbsolute(fortressPath)) return undefined;
  return resolve(fortressPath);
}

async function runInstallBootInner(
  argv: string[] = [],
  ctx: CastleWallBootContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const execFileFn = ctx.execFileFn ?? defaultExecFile;
  const plistPath = ctx.plistPath ?? CASTLE_WALL_BOOT_PLIST_PATH;
  const globalPinPath = ctx.globalPinPath ?? CASTLE_GLOBAL_PINNED_PUBKEY_PATH;
  const bootTokenPath = ctx.bootTokenPath ?? CASTLE_BOOT_TOKEN_PATH;
  const sleepFn =
    ctx.sleepFn ?? ((ms: number) => new Promise<void>((resolveSleep) => setTimeout(resolveSleep, ms)));
  const parsed = parseBootArgs(argv);
  if (writeBootParseError(parsed, err)) return 1;

  if (platform !== "darwin") {
    write(err, "castle-wall install-boot is macOS-only (Linux uses the systemd unit; see castle-wall-daemon/systemd/).\n");
    return 1;
  }
  if (getuid?.() !== 0) {
    write(err, "install-boot must run as root. Re-run: sudo sanctuary castle-wall install-boot\n");
    return 1;
  }

  const user = parsed.user ?? env.SUDO_USER;
  if (!user) {
    write(err, "Cannot determine the operator account: pass --user <name> or run via sudo (SUDO_USER).\n");
    return 1;
  }
  if (!SAFE_NAME_RE.test(user)) {
    write(err, `Invalid operator account name: ${user}\n`);
    return 1;
  }

  let fortressPath = parsed.fortress ?? env.SANCTUARY_STORAGE_PATH;
  if (!fortressPath) {
    const home = deriveOperatorHome(user, execFileFn);
    if (!home) {
      write(err, `Cannot resolve ${user}'s home directory; pass --fortress <path>.\n`);
      return 1;
    }
    fortressPath = join(home, ".sanctuary");
  }
  if (!isAbsolute(fortressPath)) {
    write(err, `Fortress path must be absolute (got: ${fortressPath}).\n`);
    return 1;
  }
  fortressPath = resolve(fortressPath);

  // ── Preflight: refuse to install a unit that cannot actually enforce at
  // boot. Installing a non-starting boot service would LOOK like F1 is
  // closed while the brick condition survives (honesty over completeness).

  // 1. Trust anchor + signer (helper mode is the only boot signer).
  if (!(await fileExists(globalPinPath))) {
    write(
      err,
      `Helper mode requires the root-owned global pin at ${globalPinPath}.\n` +
        `Run: sudo sanctuary castle-wall setup-shared-dir, approve the signer helper in the Castle Wall app, then sanctuary castle-wall re-pin.\n`,
    );
    return 1;
  }
  const signerClient = parsed.signerClient ?? env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  if (!signerClient) {
    write(
      err,
      "install-boot requires the signer-client shim path: pass --signer-client <path> or set SANCTUARY_CASTLE_SIGNER_CLIENT.\n",
    );
    return 1;
  }
  if (!isAbsolute(signerClient) || !(await fileExists(signerClient))) {
    write(err, `Signer-client shim not found at: ${signerClient} (must be an absolute existing path).\n`);
    return 1;
  }

  // 2. Boot token. Auto-provision if absent (it is a low-value random value, no
  //    operator secret to supply), so a single `sudo install-boot` works end to
  //    end. Rotation stays explicit via `provision-boot-token --rotate`.
  let tokenResult;
  try {
    tokenResult = await ensureBootToken(bootTokenPath, false, execFileFn);
  } catch (error) {
    write(err, `Error provisioning the boot token: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  // 3. Snapshot every executable input into root-owned, content-addressed
  // custody before launchd can execute it. A root service must never retain a
  // user-writable CLI, Node interpreter, signer client, or PATH entry.
  const bootDaemonSourcePath = ctx.bootDaemonSourcePath ?? CASTLE_WALL_APP_BOOT_DAEMON;
  const nodeSourcePath = ctx.nodeExecPath ?? CASTLE_WALL_APP_BOOT_NODE;
  let bootRuntime;
  try {
    const installRuntime = ctx.installBootRuntimeFn ?? installBootRuntimeSnapshot;
    const runtimeOptions: InstallBootRuntimeOptions = {
      cliSourcePath: bootDaemonSourcePath,
      nodeSourcePath,
      signerClientSourcePath: signerClient,
      execFileFn,
      ...(ctx.installBootRuntimeFn === undefined
        ? { signedAppPath: CASTLE_WALL_APP_PATH }
        : {}),
      ...(ctx.bootRuntimeDir ? { runtimeDir: ctx.bootRuntimeDir } : {}),
      ...(ctx.bootRuntimeProtectedDir ? { protectedDir: ctx.bootRuntimeProtectedDir } : {}),
      ...(ctx.bootRuntimeTrustedAncestorDir
        ? { trustedAncestorDir: ctx.bootRuntimeTrustedAncestorDir }
        : {}),
      ...(ctx.bootRuntimeExpectedOwnerUid !== undefined
        ? { expectedOwnerUid: ctx.bootRuntimeExpectedOwnerUid }
        : {}),
    };
    bootRuntime = await installRuntime(runtimeOptions);
  } catch (error) {
    write(
      err,
      `Error installing the root-owned Castle Wall boot runtime: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }
  const programArguments = bootRuntime.programArguments;

  // ── Render + install (idempotent).
  let plist: string;
  const logDir = CASTLE_WALL_BOOT_LOG_DIR;
  try {
    plist = renderBootLaunchDaemonPlist({
      programArguments,
      fortressPath,
      signerClientPath: bootRuntime.signerClientPath,
      logDir,
    });
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  // Do not create `<fortress>/logs` here. Root path-based recursive mkdir under
  // the operator fortress cannot be made race-free without mkdirat/openat, and
  // a swapped symlinked fortress could redirect creation outside the custody
  // tree. The LaunchDaemon writes directly to `/var/log`, which already exists.

  const existing = await readFileCustody(plistPath, {
    encoding: "utf8",
    verifyPathIdentity: true,
  }).catch(() => null);
  const hadPlist = await bootServicePlistPresent(plistPath);
  const installedFortressPath = fortressPathFromBootPlistContents(existing);
  const launchdState = bootServiceLoadState(execFileFn);
  if (hadPlist) {
    if (!installedFortressPath) {
      write(
        err,
        `Refusing to replace ${plistPath}: the singleton boot service plist exists but does not expose a verifiable SANCTUARY_STORAGE_PATH.\n` +
          "Inspect or uninstall it explicitly before installing a new Castle Wall boot service.\n",
      );
      return 1;
    }
    if (installedFortressPath !== fortressPath) {
      write(
        err,
        `Refusing to replace ${plistPath}: the installed singleton boot service targets ${installedFortressPath}, not requested fortress ${fortressPath}.\n` +
          "Use uninstall-boot with the matching --fortress first, then re-run install-boot for the new fortress.\n",
      );
      return 1;
    }
  }
  if (launchdState.loaded && launchdState.fortressPath !== fortressPath) {
    write(
      err,
      `Refusing to replace loaded system/${CASTLE_WALL_BOOT_LABEL}: the loaded singleton boot service ${
        launchdState.fortressPath
          ? `targets ${launchdState.fortressPath}`
          : "does not expose a verifiable SANCTUARY_STORAGE_PATH"
      }, not requested fortress ${fortressPath}.\n` +
        "Boot out or uninstall the existing singleton service explicitly before installing this fortress.\n",
    );
    return 1;
  }
  // Idempotent shortcut: only when the plist already matches AND launchd proves
  // the stable loaded job targets this fortress. A matching disk plist plus a
  // stable singleton PID is not enough: the loaded job might predate the plist
  // or target a different fortress.
  if (existing === plist && (await bootServiceReady(plistPath, fortressPath, execFileFn, sleepFn))) {
    write(out, `Castle Wall boot service already installed and running (${plistPath}).\n`);
    return 0;
  }

  const restorePreviousService = async (): Promise<string> => {
    if (!hadPlist || existing === null) {
      return "No previous boot-service plist existed to restore.";
    }
    try {
      await writeFileCustody(plistPath, existing, {
        mode: 0o644,
        createParent: false,
      });
    } catch (error) {
      return `CRITICAL: could not restore the previous boot-service plist: ${error instanceof Error ? error.message : String(error)}`;
    }
    if (!launchdState.loaded) {
      return "Restored the previous boot-service plist; it was not loaded before this replacement attempt.";
    }
    const current = bootServiceLoadState(execFileFn);
    if (current.loaded && current.fortressPath === fortressPath) {
      return "Restored the previous boot-service plist; the prior same-fortress unit remains loaded.";
    }
    const restoreBootstrap = execFileFn("launchctl", ["bootstrap", "system", plistPath]);
    if (restoreBootstrap.code !== 0) {
      return (
        "CRITICAL: restored the previous plist but could not reload its same-fortress unit " +
        `(launchctl bootstrap exit ${restoreBootstrap.code}: ${restoreBootstrap.stderr.trim() || restoreBootstrap.stdout.trim()}).`
      );
    }
    return "Restored the previous boot-service plist and reloaded its same-fortress unit.";
  };

  try {
    await writeFileCustody(plistPath, plist, {
      mode: 0o644,
      createParent: false,
    });
  } catch (error) {
    write(err, `Error writing ${plistPath}: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }

  const enable = execFileFn("launchctl", ["enable", `system/${CASTLE_WALL_BOOT_LABEL}`]);
  if (enable.code !== 0 || !bootServiceEnabled(execFileFn)) {
    const rollback = await restorePreviousService();
    write(
      err,
      `launchctl enable failed (exit ${enable.code}): ${enable.stderr.trim() || enable.stdout.trim()}\n` +
        `${rollback}\nNot certifying boot survival; fix launchd disabled state and re-run install-boot.\n`,
    );
    return 1;
  }

  // Replace-or-load: with any disabled override repaired first, boot out any
  // previous instance (ignore "not loaded"), then bootstrap the new unit.
  const bootout = execFileFn("launchctl", ["bootout", `system/${CASTLE_WALL_BOOT_LABEL}`]);
  if (bootout.code !== 0 && !launchctlResultWasNotLoaded(bootout)) {
    const rollback = await restorePreviousService();
    write(
      err,
      `launchctl bootout failed (exit ${bootout.code}): ${bootout.stderr.trim() || bootout.stdout.trim()}\n` +
        `${rollback}\nNot certifying the replacement; fix launchd state and re-run install-boot.\n`,
    );
    return 1;
  }
  const bootstrap = execFileFn("launchctl", ["bootstrap", "system", plistPath]);
  if (bootstrap.code !== 0) {
    const rollback = await restorePreviousService();
    write(
      err,
      `launchctl bootstrap failed (exit ${bootstrap.code}): ${bootstrap.stderr.trim() || bootstrap.stdout.trim()}\n` +
        `${rollback}\nFix the replacement cause and re-run install-boot.\n`,
    );
    return 1;
  }
  // Codex (a): bootstrap success only means "accepted." Certify nothing until
  // we observe a STABLY live PID, exact fortress binding, and no disabled
  // override. A one-shot pid read can catch a doomed process in the moment
  // before it exits; a disabled override can leave a currently-live daemon that
  // will not return at reboot.
  if (!(await bootServiceReady(plistPath, fortressPath, execFileFn, sleepFn))) {
    // Stop the throttled crash loop we just bootstrapped so it does not churn
    // forever; the plist stays on disk for inspection and re-run.
    const bootedOut = bootOutFailedCastleWallUnit(execFileFn, err, plistPath);
    const rollback = await restorePreviousService();
    write(
      err,
      `Bootstrap was accepted but system/${CASTLE_WALL_BOOT_LABEL} did not stay running.\n` +
        `The daemon failed to start or is crash-looping (likely node is not resolvable on the daemon PATH, the signer helper is unreachable, or the boot token is unreadable). Inspect:\n` +
        `  sudo launchctl print system/${CASTLE_WALL_BOOT_LABEL}\n` +
        `  tail -n 50 ${join(logDir, "castle-wall-daemon.err.log")}\n` +
        `${bootedOut ? "Booted the failed unit out." : "Could not prove the failed unit was booted out."} ${rollback}\n` +
        "Not certifying the replacement; the new boot-runtime candidate is NOT approved and the brick condition is NOT yet closed by it.\n",
    );
    return 1;
  }
  const pid = serviceRunningPid(execFileFn);
  if (pid === null) {
    const bootedOut = bootOutFailedCastleWallUnit(execFileFn, err, plistPath);
    const rollback = await restorePreviousService();
    write(
      err,
      `Bootstrap was accepted but system/${CASTLE_WALL_BOOT_LABEL} vanished before certification completed.\n` +
        `${bootedOut ? "Booted the failed unit out." : "Could not prove the failed unit was booted out."} ${rollback}\n` +
        "Not certifying the replacement; the new boot-runtime candidate is NOT approved and the brick condition is NOT yet closed by it.\n",
    );
    return 1;
  }

  // The custody-normalize chokepoint runs in the runInstallBoot wrapper, so it
  // covers this success path AND every failure return above it.
  write(out, `Castle Wall safe-mode boot service installed and running (pid ${pid}): ${plistPath}\n`);
  write(out, `Runs as root at boot in SAFE MODE (boot token only, never the master key); fortress ${fortressPath}; KeepAlive on.\n`);
  if (tokenResult.minted) {
    write(out, `Boot token minted: ${bootTokenPath} (root-owned 0600).\n`);
  }
  write(out, `Root-owned boot runtime: ${ctx.bootRuntimeDir ?? CASTLE_WALL_BOOT_RUNTIME_DIR}\n`);
  write(out, `Daemon logs: ${join(logDir, "castle-wall-daemon.log")} (+ .err.log)\n`);
  write(
    out,
    "NOTE: install-boot proves the unit loads and the process starts NOW. Only a real reboot drill proves boot survival (daemon up in safe mode after restart, box reachable). Do not treat F1 as closed until that drill passes.\n",
  );
  return 0;
}

export async function runUninstallBoot(
  argv: string[] = [],
  ctx: CastleWallBootContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const execFileFn = ctx.execFileFn ?? defaultExecFile;
  const plistPath = ctx.plistPath ?? CASTLE_WALL_BOOT_PLIST_PATH;
  const socketHasLiveListenerFn = ctx.socketHasLiveListenerFn ?? castleSocketHasLiveListener;
  const parsed = parseBootArgs(argv);
  if (writeBootParseError(parsed, err)) return 1;

  if (platform !== "darwin") {
    write(err, "castle-wall uninstall-boot is macOS-only.\n");
    return 1;
  }
  if (getuid?.() !== 0) {
    write(err, "uninstall-boot must run as root. Re-run: sudo sanctuary castle-wall uninstall-boot\n");
    return 1;
  }

  // Codex (c): removing the boot service while the filter is armed re-arms the
  // brick — the next reboot comes up deny-by-default with no daemon. Refuse to
  // do that silently; require explicit confirmation so it can never be a stray
  // keystroke.
  if (!parsed.yes) {
    write(
      err,
      "Removing the boot service re-arms the brick condition: if the content filter is armed, the NEXT REBOOT comes up deny-by-default with NO daemon and SSH locked out.\n" +
        "Before uninstalling, DISABLE the filter (sanctuary castle-wall disable) if you intend to reboot.\n" +
        "Re-run with --yes to confirm you understand and want to remove the boot service.\n",
    );
    return 1;
  }

  const existing = await readFileCustody(plistPath, {
    encoding: "utf8",
    verifyPathIdentity: true,
  }).catch(() => null);
  const hadPlist = await bootServicePlistPresent(plistPath);
  if (parsed.fortress && !isAbsolute(parsed.fortress)) {
    write(err, `Fortress path must be absolute (got: ${parsed.fortress}).\n`);
    return 1;
  }
  const requestedFortressPath = parsed.fortress ? resolve(parsed.fortress) : null;
  const installedFortressPath = fortressPathFromBootPlistContents(existing);
  const launchdState = bootServiceLoadState(execFileFn);
  if ((hadPlist || launchdState.loaded) && requestedFortressPath) {
    if (!installedFortressPath) {
      write(
        err,
        `Refusing to uninstall ${plistPath}: --fortress ${requestedFortressPath} was requested, but the singleton boot service does not have a verifiable matching plist with SANCTUARY_STORAGE_PATH.\n`,
      );
      return 1;
    }
    if (installedFortressPath !== requestedFortressPath) {
      write(
        err,
        `Refusing to uninstall ${plistPath}: --fortress ${requestedFortressPath} was requested, but the installed boot service targets ${installedFortressPath}.\n`,
      );
      return 1;
    }
    if (launchdState.loaded && launchdState.fortressPath !== requestedFortressPath) {
      write(
        err,
        `Refusing to uninstall ${plistPath}: --fortress ${requestedFortressPath} was requested, but the loaded singleton boot service ${
          launchdState.fortressPath
            ? `targets ${launchdState.fortressPath}`
            : "does not expose a verifiable SANCTUARY_STORAGE_PATH"
        }.\n`,
      );
      return 1;
    }
  }
  const fortressPath =
    requestedFortressPath ?? resolveUninstallFortressPath(parsed, env, execFileFn, existing);
  const bootout = execFileFn("launchctl", ["bootout", `system/${CASTLE_WALL_BOOT_LABEL}`]);
  if ((hadPlist || launchdState.loaded) && bootout.code !== 0 && !launchctlResultWasNotLoaded(bootout)) {
    write(
      err,
      `launchctl bootout failed (exit ${bootout.code}): ${
        bootout.stderr.trim() || bootout.stdout.trim()
      }\nLeaving ${plistPath} and any Castle Wall socket untouched; the boot service may still be loaded.\n`,
    );
    return 1;
  }
  if (hadPlist) {
    try {
      await rm(plistPath);
    } catch (error) {
      write(err, `Error removing ${plistPath}: ${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }
  }
  let removedRuntime = false;
  // A test-only plist override must never make a unit test touch the host's
  // real /Library runtime. Production has no plist override and always cleans
  // residual snapshots after the launchd job is gone.
  if (ctx.plistPath === undefined || ctx.bootRuntimeDir !== undefined) {
    try {
      const removeRuntime = ctx.removeBootRuntimeFn ?? removeBootRuntimeSnapshot;
      removedRuntime = await removeRuntime({
        ...(ctx.bootRuntimeDir ? { runtimeDir: ctx.bootRuntimeDir } : {}),
        ...(ctx.bootRuntimeProtectedDir ? { protectedDir: ctx.bootRuntimeProtectedDir } : {}),
        ...(ctx.bootRuntimeTrustedAncestorDir
          ? { trustedAncestorDir: ctx.bootRuntimeTrustedAncestorDir }
          : {}),
        ...(ctx.bootRuntimeExpectedOwnerUid !== undefined
          ? { expectedOwnerUid: ctx.bootRuntimeExpectedOwnerUid }
          : {}),
      });
    } catch (error) {
      write(
        err,
        `Boot service removed, but root boot-runtime cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return 1;
    }
  }
  let removedSocket = false;
  if (fortressPath) {
    const socketPath = resolveCastleWallSocketPath({
      platform: "darwin",
      fortressPath,
    }).path;
    const socketCleanup = await removeStaleCastleSocket(
      socketPath,
      err,
      socketHasLiveListenerFn,
    );
    if (!socketCleanup.ok) {
      return 1;
    }
    removedSocket = socketCleanup.removed;
  }

  if (!hadPlist && bootout.code !== 0) {
    if (removedSocket) {
      write(out, `Castle Wall boot service was not installed; removed stale Castle Wall socket for fortress ${fortressPath}.\n`);
    } else {
      write(out, "Castle Wall boot service was not installed; nothing to remove.\n");
    }
    return 0;
  }

  write(out, "Castle Wall boot service removed (plist deleted; launchd job booted out or was not loaded).\n");
  if (removedRuntime) {
    write(out, "Removed the root-owned Castle Wall boot runtime.\n");
  }
  if (removedSocket) {
    write(out, `Removed stale Castle Wall socket for fortress ${fortressPath}.\n`);
  }
  write(
    out,
    "WARNING: this does NOT disarm the content filter. If the wall is armed, the next reboot comes up deny-by-default with NO daemon (the brick condition F1 exists to prevent). Disarm with 'sanctuary castle-wall disable' before rebooting, or reinstall with install-boot.\n",
  );
  return 0;
}
