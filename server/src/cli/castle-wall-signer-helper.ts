/**
 * sanctuary castle-wall signer-helper status
 *
 * Boot-readiness layer around the EXISTING root signer helper LaunchDaemon
 * (A2/B2). Per the 2026-06-26 design pass
 * (`Review/Sanctuary/Castle_Wall_Signer_Helper_Boot_Daemon_Design_Pass_2026-06-26.md`),
 * this does NOT invent a new boot daemon: the signer helper
 * (`ai.sanctuaryprotocol.macos.castle-wall.signer-helper`) is already a
 * root-owned SMAppService LaunchDaemon with `RunAtLoad` + `KeepAlive`, bundled
 * inside the host app and registered by `SignerHelperManager.register()`
 * (Swift, `castle-wall-macos/Sources/CastleWallHostApp/SignerHelperManager.swift`).
 * Once the operator approves it once in System Settings (a Background Item
 * consent, exactly like Little Snitch / Tailscale), launchd starts it at every
 * subsequent boot with no login required.
 *
 * What was missing (the 2026-06-25 drill finding): after a cold reboot,
 * `launchctl print system/ai.sanctuaryprotocol.macos.castle-wall.signer-helper`
 * did not show the helper, and there was no CLI-visible, fail-loud way for a
 * headless operator (or a drill harness) to tell WHY before attempting
 * `castle-wall enable`. This module makes that boot-readiness state explicit,
 * inspectable, and testable:
 *
 *   1. `castle-wall signer-helper status`: reports each precondition
 *      (launchd job visible, XPC answers publicKey, key matches the
 *      root-owned global pin, custody directory is root-owned and not
 *      group/other-writable) and an overall verdict.
 *   2. `assessSignerHelperReadiness`, the pure decision logic behind (1),
 *      reused by the `enable`/`daemon` (helper-sign mode) preflight gate in
 *      `castle-wall.ts` so a headless arm fails LOUD, with a specific
 *      diagnosis (open the app and approve the Background Item, versus
 *      repair the custody directory, versus a pin mismatch), instead of
 *      failing opaque or silently degrading.
 *
 * This module never invents custody behavior: it holds no secret, mints no
 * credential, and does not change what the helper can do. It only observes
 * and reports the boot-readiness state of the daemon that already exists.
 */

import { spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { Writable } from "node:stream";

import { HelperSignerClient, type ShimInvoker } from "../castle-wall/runtime/helper-signer.js";

/** Launchd label of the root signer helper (mirrors Swift `SignerConstants.signerHelperIdentifier`). */
export const CASTLE_SIGNER_HELPER_LABEL = "ai.sanctuaryprotocol.macos.castle-wall.signer-helper";

/** Root-owned custody directory holding the trust-anchor pin + the helper's private key. */
export const CASTLE_SIGNER_HELPER_CUSTODY_DIR = "/Library/Application Support/Sanctuary";

/** Root-owned global pinned public key path (the enforcement trust anchor; mirrors castle-wall.ts). */
export const CASTLE_SIGNER_HELPER_PINNED_PUBKEY_PATH = `${CASTLE_SIGNER_HELPER_CUSTODY_DIR}/castle-pinned-pubkey.bin`;

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** One named precondition in the signer-helper boot-readiness preflight. */
export type SignerHelperCheckId =
  | "launchd_job_visible"
  | "xpc_reachable"
  | "pin_match"
  | "custody_directory";

export type SignerHelperCheckStatus = "pass" | "fail" | "skipped";

export interface SignerHelperCheck {
  id: SignerHelperCheckId;
  status: SignerHelperCheckStatus;
  /** Human-readable detail; always populated for fail/skipped, may be populated for pass. */
  detail: string;
}

/**
 * The overall preflight verdict plus the specific remediation the design pass
 * asks for: distinguish "open the app and approve the Background Item" from
 * "repair root-owned custody directory" from "pin mismatch" rather than a
 * single generic failure message.
 */
export type SignerHelperRemediation =
  | "none"
  | "approve_background_item"
  | "repair_custody_directory"
  | "pin_mismatch"
  | "unknown";

export interface SignerHelperReadiness {
  ready: boolean;
  checks: SignerHelperCheck[];
  remediation: SignerHelperRemediation;
  /** Operator-facing guidance matching `remediation`. Empty when ready. */
  guidance: string;
}

export interface SignerHelperReadinessInputs {
  /** Run `launchctl print system/<label>`, or a test double. */
  execFileFn: (cmd: string, args: string[]) => ExecResult;
  /**
   * Query the running helper's public key over XPC (via the signer-client
   * shim). Absent/undefined when no shim is resolvable at all; that alone
   * does not fail the check if the launchd job is also absent (the
   * remediation should point at "approve the Background Item" first).
   */
  queryHelperPublicKey?: () => Promise<Uint8Array>;
  /** Read the root-owned global pin, or a test double. */
  readGlobalPin: () => Promise<Uint8Array>;
  /** Stat the custody directory, or a test double. */
  statCustodyDir: (path: string) => Promise<{ uid: number; mode: number }>;
  platform?: NodeJS.Platform;
}

/**
 * Parse `launchctl print system/<label>` output for a live pid, mirroring
 * `serviceRunningPid` in `castle-wall-boot.ts`. A non-zero exit or missing
 * `pid = N` line means the job is not loaded/running.
 */
export function parseLaunchctlPrintForPid(printed: ExecResult): number | null {
  if (printed.code !== 0) return null;
  const match = /\bpid\s*=\s*(\d+)/.exec(printed.stdout);
  if (!match) return null;
  const pid = Number.parseInt(match[1]!, 10);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

function fingerprint(publicKey: Uint8Array): string {
  // Local, dependency-free fingerprint (first 8 bytes hex), good enough for a
  // preflight equality check; the CLI's sha256-based fingerprint is used for
  // operator display in `status`/`re-pin`. This module compares full raw bytes
  // (see `bytesEqual`), never the fingerprint, so this helper is display-only.
  return Buffer.from(publicKey.slice(0, 8)).toString("hex");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/**
 * Assess signer-helper boot readiness. Pure aside from the injected I/O seams,
 * so the decision logic (what counts as ready, which remediation applies) is
 * fully unit-testable without a real helper, launchd, or root filesystem.
 *
 * Order of checks mirrors the design pass's item 1 list. `custody_directory`
 * and `pin_match` are independent of `launchd_job_visible`/`xpc_reachable` and
 * always run (a broken custody dir is worth reporting even if the job also
 * happens to be down), but the REMEDIATION returned favors the earliest
 * actionable cause in this order: launchd job missing -> XPC unreachable ->
 * pin mismatch -> custody directory. This ordering matches how an operator
 * would actually resolve the box: approve the Background Item first (it
 * usually also fixes XPC reachability), then worry about custody/pin state.
 */
export async function assessSignerHelperReadiness(
  inputs: SignerHelperReadinessInputs,
): Promise<SignerHelperReadiness> {
  const platform = inputs.platform ?? process.platform;
  const checks: SignerHelperCheck[] = [];

  if (platform !== "darwin") {
    checks.push({
      id: "launchd_job_visible",
      status: "skipped",
      detail: "signer-helper readiness is macOS-only.",
    });
    return {
      ready: false,
      checks,
      remediation: "unknown",
      guidance: "castle-wall signer-helper status is macOS-only.",
    };
  }

  // 1. launchd job visible.
  const printed = inputs.execFileFn("launchctl", ["print", `system/${CASTLE_SIGNER_HELPER_LABEL}`]);
  const pid = parseLaunchctlPrintForPid(printed);
  const jobVisible = pid !== null;
  checks.push({
    id: "launchd_job_visible",
    status: jobVisible ? "pass" : "fail",
    detail: jobVisible
      ? `system/${CASTLE_SIGNER_HELPER_LABEL} is loaded (pid ${pid}).`
      : `system/${CASTLE_SIGNER_HELPER_LABEL} is not loaded (launchctl print exited ${printed.code}).`,
  });

  // 2. XPC reachable (only meaningful to attempt if we have a way to ask).
  let helperPublicKey: Uint8Array | null = null;
  if (inputs.queryHelperPublicKey) {
    try {
      helperPublicKey = await inputs.queryHelperPublicKey();
      checks.push({
        id: "xpc_reachable",
        status: "pass",
        detail: `Helper answered publicKey (fingerprint ${fingerprint(helperPublicKey)}...).`,
      });
    } catch (error) {
      const xpcError = error instanceof Error ? error.message : String(error);
      checks.push({ id: "xpc_reachable", status: "fail", detail: `Helper XPC query failed: ${xpcError}` });
    }
  } else {
    checks.push({
      id: "xpc_reachable",
      status: "skipped",
      detail: "No signer-client shim resolvable; cannot query the helper over XPC.",
    });
  }

  // 3. Pin match: the returned key (if any) must match the root-owned global pin.
  let globalPin: Uint8Array | null = null;
  let globalPinError: string | null = null;
  try {
    globalPin = await inputs.readGlobalPin();
  } catch (error) {
    globalPinError = error instanceof Error ? error.message : String(error);
  }
  if (globalPin === null) {
    checks.push({
      id: "pin_match",
      status: "skipped",
      detail: globalPinError
        ? `Cannot read the global pin: ${globalPinError}`
        : "No global pin provisioned yet.",
    });
  } else if (helperPublicKey === null) {
    checks.push({
      id: "pin_match",
      status: "skipped",
      detail: "Cannot compare: no helper public key available (XPC unreachable).",
    });
  } else if (bytesEqual(globalPin, helperPublicKey)) {
    checks.push({
      id: "pin_match",
      status: "pass",
      detail: "Global pin matches the signer-helper key.",
    });
  } else {
    checks.push({
      id: "pin_match",
      status: "fail",
      detail: "Global pin does NOT match the signer-helper key; the box cannot arm until re-pinned.",
    });
  }

  // 4. Custody directory: root-owned, not group/other-writable.
  let custodyError: string | null = null;
  let custodyStats: { uid: number; mode: number } | null = null;
  try {
    custodyStats = await inputs.statCustodyDir(CASTLE_SIGNER_HELPER_CUSTODY_DIR);
  } catch (error) {
    custodyError = error instanceof Error ? error.message : String(error);
  }
  if (custodyStats === null) {
    checks.push({
      id: "custody_directory",
      status: "fail",
      detail: custodyError
        ? `Cannot stat ${CASTLE_SIGNER_HELPER_CUSTODY_DIR}: ${custodyError}`
        : `${CASTLE_SIGNER_HELPER_CUSTODY_DIR} does not exist.`,
    });
  } else {
    const groupOrOtherWritable = (custodyStats.mode & 0o022) !== 0;
    const rootOwned = custodyStats.uid === 0;
    if (rootOwned && !groupOrOtherWritable) {
      checks.push({
        id: "custody_directory",
        status: "pass",
        detail: `${CASTLE_SIGNER_HELPER_CUSTODY_DIR} is root-owned, mode ${custodyStats.mode.toString(8)}.`,
      });
    } else {
      checks.push({
        id: "custody_directory",
        status: "fail",
        detail: `${CASTLE_SIGNER_HELPER_CUSTODY_DIR} is ${rootOwned ? "root-owned" : `owned by uid ${custodyStats.uid}, not root`}${
          groupOrOtherWritable ? " and group/other-writable" : ""
        }.`,
      });
    }
  }

  const byId = new Map(checks.map((c) => [c.id, c]));
  const ready =
    byId.get("launchd_job_visible")?.status === "pass" &&
    byId.get("xpc_reachable")?.status === "pass" &&
    byId.get("pin_match")?.status === "pass" &&
    byId.get("custody_directory")?.status === "pass";

  if (ready) {
    return { ready: true, checks, remediation: "none", guidance: "" };
  }

  // Remediation precedence (design pass item 2): distinguish the three
  // operator-facing causes, favoring the earliest actionable one.
  if (byId.get("launchd_job_visible")?.status === "fail") {
    return {
      ready: false,
      checks,
      remediation: "approve_background_item",
      guidance:
        "The signer helper is not loaded. Open the Castle Wall app once and approve the Background Item " +
        "in System Settings > General > Login Items & Extensions, then reboot or re-run this check.",
    };
  }
  if (byId.get("xpc_reachable")?.status === "fail") {
    return {
      ready: false,
      checks,
      remediation: "approve_background_item",
      guidance:
        "The signer helper's launchd job is visible but did not answer over XPC. Confirm the Background Item " +
        "approval in System Settings > General > Login Items & Extensions, and that the signer-client shim path is correct.",
    };
  }
  if (byId.get("pin_match")?.status === "fail") {
    return {
      ready: false,
      checks,
      remediation: "pin_mismatch",
      guidance:
        "The global pin does not match the signer-helper key. Run 'sanctuary castle-wall re-pin' " +
        "to migrate the trust anchor to the signer helper.",
    };
  }
  if (byId.get("custody_directory")?.status === "fail") {
    return {
      ready: false,
      checks,
      remediation: "repair_custody_directory",
      guidance:
        `Repair root-owned custody directory: ${CASTLE_SIGNER_HELPER_CUSTODY_DIR} must be owned by root and not ` +
        "group/other-writable. Run 'sudo sanctuary castle-wall setup-shared-dir' to restore it.",
    };
  }
  return {
    ready: false,
    checks,
    remediation: "unknown",
    guidance: "Signer helper is not ready; see the individual check details above.",
  };
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function defaultExecFile(cmd: string, args: string[]): ExecResult {
  const result = spawnSync(cmd, args, { encoding: "utf8" });
  return {
    code: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

export interface SignerHelperStatusContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  execFileFn?: (cmd: string, args: string[]) => ExecResult;
  /** Override the signer-client shim path resolution (tests). */
  signerClientPath?: string;
  /** Override the shim invoker (tests drive the XPC query without a real helper). */
  signerClientInvoke?: ShimInvoker;
  /** Override the global-pin reader (tests). */
  globalPinReader?: () => Promise<Uint8Array>;
  /** Override the custody-directory stat (tests). */
  statCustodyDirFn?: (path: string) => Promise<{ uid: number; mode: number }>;
}

async function defaultStatCustodyDir(path: string): Promise<{ uid: number; mode: number }> {
  const info = await stat(path);
  return { uid: info.uid, mode: info.mode & 0o777 };
}

async function defaultReadGlobalPin(): Promise<Uint8Array> {
  return readFile(CASTLE_SIGNER_HELPER_PINNED_PUBKEY_PATH);
}

/**
 * Build the `queryHelperPublicKey` seam from CLI context (shim path/env/test
 * invoker), shared by `runSignerHelperStatus` and the `enable`/`daemon`
 * preflight gate in `castle-wall.ts` so both use the same resolution rule.
 * Returns undefined when no shim is resolvable at all (mirrors the "cannot
 * verify" fallback `castle-wall status` already uses for the softer local
 * comparison).
 */
export function buildHelperPublicKeyQuery(
  shimPath: string | undefined,
  signerClientInvoke: ShimInvoker | undefined,
): (() => Promise<Uint8Array>) | undefined {
  if (!shimPath && !signerClientInvoke) return undefined;
  return async (): Promise<Uint8Array> => {
    const client = new HelperSignerClient({
      clientBinaryPath: shimPath ?? "castle-wall-signer-client",
      ...(signerClientInvoke ? { invoke: signerClientInvoke } : {}),
    });
    return client.getPublicKey();
  };
}

/**
 * `castle-wall signer-helper status`: run the boot-readiness preflight and
 * print each check plus the overall verdict. Exit code 0 when ready, 1
 * otherwise (so a drill harness or `enable` preflight can script off it).
 *
 * Shim-path resolution here is deliberately env-only (`SANCTUARY_CASTLE_SIGNER_CLIENT`,
 * or the injected `ctx.signerClientPath`), to keep this module independently
 * testable and free of a static import back into `castle-wall.ts`. NOTE this is
 * NARROWER than `castle-wall status` / the `enable`/`daemon` preflight, which
 * additionally AUTO-DISCOVER the bundled `/Applications` shim via the
 * security-checked `resolveSignerClientPath`. Consequence: when the operator has
 * not set the env var, this command cannot reach the helper over XPC, so the
 * `xpc_reachable` check is SKIPPED and the verdict is NOT-READY (conservative,
 * never a false READY). Set `SANCTUARY_CASTLE_SIGNER_CLIENT` to the bundled
 * signer-client shim before running this as a standalone drill check, or rely on
 * the `enable`/`daemon` preflight, which auto-discovers. Wiring auto-discovery
 * into this command (share `resolveSignerClientPath` via a small extracted
 * module) is a tracked follow-up.
 */
export async function runSignerHelperStatus(
  _argv: string[] = [],
  ctx: SignerHelperStatusContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const execFileFn = ctx.execFileFn ?? defaultExecFile;

  if (platform !== "darwin") {
    write(err, "castle-wall signer-helper status is macOS-only.\n");
    return 1;
  }

  const shimPath = ctx.signerClientPath ?? env.SANCTUARY_CASTLE_SIGNER_CLIENT;
  const queryHelperPublicKey = buildHelperPublicKeyQuery(shimPath, ctx.signerClientInvoke);

  const readiness = await assessSignerHelperReadiness({
    execFileFn,
    queryHelperPublicKey,
    readGlobalPin: ctx.globalPinReader ?? defaultReadGlobalPin,
    statCustodyDir: ctx.statCustodyDirFn ?? defaultStatCustodyDir,
    platform,
  });

  for (const check of readiness.checks) {
    const marker = check.status === "pass" ? "PASS" : check.status === "fail" ? "FAIL" : "SKIP";
    write(out, `[${marker}] ${check.id}: ${check.detail}\n`);
  }

  if (readiness.ready) {
    write(out, "\nSigner helper: READY (boot-started, reachable, pin-consistent).\n");
    return 0;
  }

  write(out, `\nSigner helper: NOT READY.\n${readiness.guidance}\n`);
  return 1;
}
