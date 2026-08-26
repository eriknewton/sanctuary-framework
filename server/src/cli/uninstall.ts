import { execFile as nodeExecFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";

import { scrubProvisionedEgressRules, type ScrubProvisionedEgressResult } from "../castle-wall/provision/egress.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";
import { CASTLE_WALL_BOOT_PLIST_PATH, runUninstallBoot } from "./castle-wall-boot.js";
import type { DisableNePreferenceOutcome, SystemExtensionDeactivationRequestOutcome } from "./castle-wall.js";

// Must match CASTLE_GLOBAL_PINNED_PUBKEY_PATH in server/src/cli/castle-wall.ts.
export const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin";

type FootprintStatus = "absent" | "present" | "unknown" | "not-applicable";
const CASTLE_WALL_SYSTEM_EXTENSION_ID = "ai.sanctuaryprotocol.macos.castle-wall";
const execFileAsync = promisify(nodeExecFile);

export interface UninstallCommandContext {
  argv?: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  getuid?: () => number;
  ops?: Partial<UninstallOps>;
}

export interface UninstallOps {
  disarm(fortressPath: string): Promise<DisableNePreferenceOutcome>;
  uninstallHarnessDaemon(): Promise<void>;
  scrubProvisionedEgressRules(fortressPath: string, harnessId: string): Promise<ScrubProvisionedEgressResult>;
  bootServiceStatus(): Promise<FootprintStatus>;
  uninstallBootService(fortressPath: string): Promise<void>;
  globalPinStatus(): Promise<FootprintStatus>;
  systemExtensionStatus(): Promise<FootprintStatus>;
  deactivateSystemExtension(): Promise<SystemExtensionDeactivationRequestOutcome>;
}

interface ParsedUninstallArgs {
  help: boolean;
  fortress?: string;
  harnessId: string;
  removeOperatorData: boolean;
  error?: string;
}

interface ReportRow {
  label: string;
  status: "removed" | "skipped" | "preserved" | "cannot-remove" | "failed";
  detail: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function printUninstallHelp(out: Writable): void {
  write(
    out,
    `sanctuary uninstall. Remove Sanctuary's installed enforcement footprint without deleting operator data.

Usage:
  sanctuary uninstall [--fortress <path>] [--harness <id>]

Options:
  --fortress <path>       Fortress directory for policy cleanup. Defaults to the normal Sanctuary fortress.
  --harness <id>          Provisioned harness id whose egress rules are scrubbed. Default: hermes.
  --remove-operator-data  Refused by this verb; operator data deletion must use a separate recovery/data command.
  --help, -h              Show this help

Default behavior preserves the fortress state, keys, passphrase custody, recovery material, and audit log.
It reports any installed residue that needs sudo, the Castle Wall host app, or a reboot; it never reports a clean uninstall while that residue remains.
`,
  );
}

function parseUninstallArgs(argv: string[]): ParsedUninstallArgs {
  let remaining = [...argv];
  const fortress = consumeFlagValue(remaining, "--fortress");
  if (fortress.error !== undefined) {
    return { help: false, harnessId: "hermes", removeOperatorData: false, error: fortress.error };
  }
  remaining = fortress.argv;
  const harness = consumeFlagValue(remaining, "--harness");
  if (harness.error !== undefined) {
    return { help: false, harnessId: "hermes", removeOperatorData: false, error: harness.error };
  }
  remaining = harness.argv;

  const parsed: ParsedUninstallArgs = {
    help: false,
    ...(fortress.value !== undefined ? { fortress: fortress.value } : {}),
    harnessId: harness.value ?? "hermes",
    removeOperatorData: false,
  };

  for (const arg of remaining) {
    if (arg === "--help" || arg === "-h") parsed.help = true;
    else if (arg === "--remove-operator-data") parsed.removeOperatorData = true;
    else if (arg.startsWith("-")) parsed.error = `Unknown uninstall option: ${arg}`;
    else parsed.error = `Unexpected uninstall argument: ${arg}`;
    if (parsed.error !== undefined) break;
  }
  if (parsed.harnessId.trim() === "") parsed.error = "--harness must not be empty";
  return parsed;
}

function resolveFortressArg(fortress: string | undefined, env: NodeJS.ProcessEnv): string {
  const value = fortress ?? env.SANCTUARY_STORAGE_PATH ?? env.SANCTUARY_FORTRESS_PATH;
  if (value === undefined) return resolveStoragePath(env);
  return isAbsolute(value) ? resolve(value) : resolve(process.cwd(), value);
}

function nullWritable(): Writable {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}

/**
 * One uninstall report row renders on a single line for a human operator; an
 * unbounded multi-line disable transcript would break the row format and bury
 * the report. 600 chars holds the full two-sentence disable warning (the
 * lease-ratchet disclosure plus a long LaunchServices error is ~450 chars)
 * with headroom; longer transcripts keep the TAIL, because the disable verb
 * writes its diagnosis last, and the truncation is marked, never silent.
 */
const DISARM_FAILURE_DETAIL_MAX_CHARS = 600;

function collectingWritable(): { stream: Writable; text(): string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
  return { stream, text: () => chunks.join("") };
}

/**
 * The two sentences an operator must never lose from a truncated transcript.
 * Must match the warning rendered in the fail_open_deadman branch of
 * runDisable in cli/castle-wall.ts (the producer side carries the reciprocal
 * pin naming DISARM_DETAIL_PRIORITY_MARKERS). Matched by substring on the
 * newline-flattened RAW transcript, so line wrapping or wording extensions
 * around the markers cannot silently defeat the retention.
 *
 * Marker 1 opens the warning and is followed by the VARIABLE failure detail
 * (the underlying invoke error), so its retained window extends past the
 * marker. Marker 2 is a CONSTANT complete sentence - the full-deny
 * lease-ratchet disclosure - so the marker text is itself the retained
 * content and can never be cut mid-sentence, however long the warning line
 * that carries both markers grows.
 */
const DISARM_DETAIL_PRIORITY_MARKERS = [
  "NE preference disable did not complete",
  "the protected uid is fully denied until a later successful disable or re-enable",
] as const;

/**
 * Window kept from marker 1's start: the marker (38 chars) plus enough of the
 * parenthesized failure detail to identify the cause. 300 = half the 600-char
 * row budget, leaving room for marker 2 (79 chars) plus transcript tail.
 */
const DISARM_DETAIL_MARKER_WINDOW_CHARS = 300;

export function flattenDisarmDetail(raw: string): string {
  const flat = raw.trim().replace(/\s*\n\s*/g, " | ");
  if (flat.length <= DISARM_FAILURE_DETAIL_MAX_CHARS) return flat;
  // A plain keep-the-tail truncation can evict the diagnosis when later
  // output (audit failure text, custody normalization) follows the warning,
  // and a keep-the-head truncation can evict the SECOND marker when the
  // warning line itself is long (both markers live in one sentence). Each
  // marker therefore gets its own bounded window from the flattened raw text:
  // marker 1 keeps the failure detail that follows it, marker 2 is a constant
  // sentence kept verbatim. Remaining budget carries the transcript tail;
  // truncation stays marked, never silent.
  // Matching runs on a whitespace-normalized view so a marker split across
  // lines (or flattened into " | " separators) still matches - the documented
  // wrapping-immunity contract; windows are extracted from the same view.
  const normalized = raw.trim().replace(/\s+/g, " ");
  const windows: string[] = [];
  // cli-argv-indexof-allowed: scans a captured stderr transcript string, not CLI argv tokens.
  const idx1 = normalized.indexOf(DISARM_DETAIL_PRIORITY_MARKERS[0]);
  if (idx1 >= 0) {
    const window = normalized.slice(idx1, idx1 + DISARM_DETAIL_MARKER_WINDOW_CHARS);
    windows.push(
      window.length < DISARM_DETAIL_MARKER_WINDOW_CHARS ? window : `${window}…`,
    );
  }
  if (
    normalized.includes(DISARM_DETAIL_PRIORITY_MARKERS[1]) &&
    // Marker 2 already inside marker 1's window: appending it again would
    // repeat the disclosure verbatim.
    !windows.some((window) => window.includes(DISARM_DETAIL_PRIORITY_MARKERS[1]))
  ) {
    windows.push(DISARM_DETAIL_PRIORITY_MARKERS[1]);
  }
  const priority = windows.join(" | ");
  if (priority.length === 0) {
    return `…${flat.slice(flat.length - DISARM_FAILURE_DETAIL_MAX_CHARS)}`;
  }
  const remaining = DISARM_FAILURE_DETAIL_MAX_CHARS - priority.length;
  if (remaining <= 1) return priority;
  return `${priority} | …${flat.slice(flat.length - remaining)}`;
}

async function statFootprint(path: string): Promise<FootprintStatus> {
  try {
    await lstat(path);
    return "present";
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return "absent";
    return "unknown";
  }
}

function realUninstallOps(ctx: UninstallCommandContext): UninstallOps {
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const env = ctx.env ?? process.env;
  return {
    disarm: async (fortressPath) => {
      if (platform !== "darwin") return "corroborated_off";
      const { runDisable } = await import("./castle-wall.js");
      let observed: DisableNePreferenceOutcome | undefined;
      // The disable verb writes its diagnosis (the underlying invoke failure
      // AND, on the fail_open_deadman path, the lease-ratchet full-deny
      // disclosure) to stderr; capturing instead of null-writing is what keeps
      // this row truthful. Must match the warning rendered in the
      // fail_open_deadman branch of runDisable in cli/castle-wall.ts - the
      // disclosure is captured from there, never re-rendered here, so the two
      // surfaces can never disagree. Null-writing this stream was how a
      // hardware LaunchServices launch failure reached the operator as a bare
      // "fail_open_deadman" label (D5 drill 2026-08-25).
      const errCapture = collectingWritable();
      const code = await runDisable(["--fortress", fortressPath], {
        out: nullWritable(),
        err: errCapture.stream,
        env,
        platform,
        onDisableNePreferenceOutcome: (outcome) => {
          observed = outcome;
        },
      });
      const detail = flattenDisarmDetail(errCapture.text());
      if (code !== 0) {
        throw new Error(
          `castle-wall disable exited ${code}${detail ? ` (${detail})` : ""}`,
        );
      }
      if (observed !== "corroborated_off") {
        throw new Error(
          `castle-wall disable did not positively observe the filter off (${observed ?? "no outcome"})${detail ? `; underlying: ${detail}` : ""}`,
        );
      }
      return observed;
    },
    uninstallHarnessDaemon: async () => {
      const { uninstallAutoProvisionedHarnessDaemon } = await import("../wrap/auto-provision.js");
      await uninstallAutoProvisionedHarnessDaemon();
    },
    scrubProvisionedEgressRules: async (fortressPath, harnessId) =>
      scrubProvisionedEgressRules({ fortressPath, harnessId }),
    bootServiceStatus: async () => {
      if (platform !== "darwin") return "not-applicable";
      return statFootprint(CASTLE_WALL_BOOT_PLIST_PATH);
    },
    uninstallBootService: async (fortressPath) => {
      const code = await runUninstallBoot(["--yes", "--fortress", fortressPath], {
        out: nullWritable(),
        err: nullWritable(),
        env,
        platform,
        getuid,
      });
      if (code !== 0) throw new Error(`castle-wall uninstall-boot exited ${code}`);
    },
    globalPinStatus: async () => {
      if (platform !== "darwin") return "not-applicable";
      return statFootprint(CASTLE_GLOBAL_PINNED_PUBKEY_PATH);
    },
    systemExtensionStatus: async () => {
      if (platform !== "darwin") return "not-applicable";
      try {
        const { stdout } = await execFileAsync("/usr/bin/systemextensionsctl", ["list"], {
          encoding: "utf8",
          timeout: 10_000,
        });
        return stdout.includes(CASTLE_WALL_SYSTEM_EXTENSION_ID) ? "present" : "absent";
      } catch {
        // Unknown is intentionally distinct from absent: teardown may never
        // claim removal when the authoritative OS probe could not run.
        return "unknown";
      }
    },
    deactivateSystemExtension: async () => {
      const { requestSystemExtensionDeactivation } = await import("./castle-wall.js");
      return requestSystemExtensionDeactivation({ env, platform, getuid });
    },
  };
}

function printReport(out: Writable, rows: ReportRow[], clean: boolean): void {
  write(out, clean ? "Sanctuary uninstall: installed footprint removed.\n" : "Sanctuary uninstall: completed with residue or failed steps.\n");
  for (const row of rows) {
    write(out, `- ${row.status}: ${row.label} - ${row.detail}\n`);
  }
}

export async function runUninstallCommand(ctx: UninstallCommandContext = {}): Promise<number> {
  const argv = ctx.argv ?? [];
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const parsed = parseUninstallArgs(argv);

  if (parsed.help) {
    printUninstallHelp(out);
    return 0;
  }
  if (parsed.error !== undefined) {
    write(err, `${parsed.error}\n`);
    return 2;
  }
  if (parsed.removeOperatorData) {
    write(
      err,
      "Refusing --remove-operator-data here. Uninstall preserves the fortress, keys, passphrase custody, recovery material, and audit log; use an explicit data-recovery or reset command for destructive state removal.\n",
    );
    return 2;
  }

  const fortressPath = resolveFortressArg(parsed.fortress, env);
  const ops = { ...realUninstallOps(ctx), ...(ctx.ops ?? {}) };
  const rows: ReportRow[] = [];
  let safeToRemoveSupportingServices = false;

  try {
    const disarmOutcome = await ops.disarm(fortressPath);
    if (platform === "darwin" && disarmOutcome !== "corroborated_off") {
      throw new Error(
        `content filter was not positively observed disabled (${disarmOutcome})`,
      );
    }
    rows.push(
      platform === "darwin"
        ? {
            label: "castle-wall",
            status: "removed",
            detail: "content filter is positively observed disabled",
          }
        : {
            label: "castle-wall",
            status: "skipped",
            detail: "no macOS Castle Wall content filter exists on this platform",
          },
    );
    safeToRemoveSupportingServices = true;
  } catch (error) {
    rows.push({
      label: "castle-wall",
      status: "failed",
      detail: (error as Error).message,
    });
  }

  let daemonRemoved = false;
  let egressRulesRemoved = false;
  if (safeToRemoveSupportingServices) {
    try {
      await ops.uninstallHarnessDaemon();
      daemonRemoved = true;
      rows.push({
        label: "harness-daemon",
        status: "removed",
        detail: "auto-provisioned harness daemon uninstall completed",
      });
    } catch (error) {
      rows.push({ label: "harness-daemon", status: "failed", detail: (error as Error).message });
    }

    try {
      const scrubResult = await ops.scrubProvisionedEgressRules(fortressPath, parsed.harnessId);
      egressRulesRemoved = true;
      const reload = scrubResult.reloadOk === false ? "; policy reload was not confirmed" : "";
      rows.push({
        label: "scrub-egress-rules",
        status: "removed",
        detail: `${scrubResult.removedRuleIds.length} provisioned rule file(s) removed${reload}`,
      });
    } catch (error) {
      rows.push({ label: "scrub-egress-rules", status: "failed", detail: (error as Error).message });
    }
  } else {
    rows.push({
      label: "harness-daemon",
      status: "skipped",
      detail: "kept because the content filter was not positively observed disabled",
    });
    rows.push({
      label: "scrub-egress-rules",
      status: "skipped",
      detail: "kept because the content filter was not positively observed disabled",
    });
  }
  rows.push({
    label: "re-home restore",
    status: "skipped",
    detail:
      "no persisted successful-provision re-home result manifest exists for this CLI to replay; operator files and fortress data were not deleted",
  });

  const bootStatus = await ops.bootServiceStatus();
  let bootCleared = bootStatus === "absent" || bootStatus === "not-applicable";
  if (bootStatus === "present") {
    if (!safeToRemoveSupportingServices || !daemonRemoved || !egressRulesRemoved) {
      rows.push({
        label: "boot-service",
        status: "cannot-remove",
        detail:
          "kept because disarm and supporting-service teardown did not all complete; removing boot recovery would be unsafe",
      });
    } else if (platform === "darwin" && getuid?.() === 0) {
      try {
        await ops.uninstallBootService(fortressPath);
        bootCleared = true;
        rows.push({ label: "boot-service", status: "removed", detail: `${CASTLE_WALL_BOOT_PLIST_PATH} removed through uninstall-boot` });
      } catch (error) {
        rows.push({ label: "boot-service", status: "failed", detail: (error as Error).message });
      }
    } else {
      rows.push({
        label: "boot-service",
        status: "cannot-remove",
        detail: `${CASTLE_WALL_BOOT_PLIST_PATH} exists and requires sudo: sudo sanctuary --fortress ${fortressPath} castle-wall uninstall-boot --yes`,
      });
    }
  } else if (bootStatus === "absent") {
    rows.push({ label: "boot-service", status: "skipped", detail: "no Castle Wall boot LaunchDaemon plist found" });
  } else if (bootStatus === "unknown") {
    rows.push({ label: "boot-service", status: "cannot-remove", detail: `could not inspect ${CASTLE_WALL_BOOT_PLIST_PATH}; run with sudo and re-run uninstall-boot if present` });
  }

  const globalPinStatus = await ops.globalPinStatus();
  if (globalPinStatus === "present") {
    rows.push({
      label: "global-pin",
      status: "cannot-remove",
      detail: `${CASTLE_GLOBAL_PINNED_PUBKEY_PATH} exists; it is a host-wide trust anchor and this fortress-scoped uninstall leaves it for explicit operator removal`,
    });
  } else if (globalPinStatus === "absent") {
    rows.push({ label: "global-pin", status: "skipped", detail: "no host-wide Castle Wall global pin found" });
  } else if (globalPinStatus === "unknown") {
    rows.push({ label: "global-pin", status: "cannot-remove", detail: `could not inspect ${CASTLE_GLOBAL_PINNED_PUBKEY_PATH}; it may need sudo for manual removal` });
  }

  if (platform === "darwin") {
    const extensionStatus = await ops.systemExtensionStatus();
    if (extensionStatus === "absent") {
      rows.push({
        label: "system-extension",
        status: "skipped",
        detail: "Castle Wall system extension is observed absent",
      });
    } else if (extensionStatus === "unknown") {
      rows.push({
        label: "system-extension",
        status: "cannot-remove",
        detail: "could not inspect system-extension state; absence is not assumed",
      });
    } else if (!safeToRemoveSupportingServices || !daemonRemoved || !egressRulesRemoved || !bootCleared) {
      rows.push({
        label: "system-extension",
        status: "cannot-remove",
        detail:
          "deactivation not requested because filter, daemon, egress-rule, and boot-service teardown did not all complete safely",
      });
    } else {
      const deactivation = await ops.deactivateSystemExtension();
      // The host app disclosed a recovery mutation inside the teardown verb
      // (a single activate-replace before re-deactivating, clearing an
      // app-version skew). That disclosure must reach the operator row on
      // every outcome, success included: the verb submitted an activation the
      // operator did not directly ask for.
      const recoveryNote =
        deactivation.recovery === undefined
          ? ""
          : `; disclosed recovery ran (${deactivation.recovery})`;
      if (deactivation.kind === "reboot-required") {
        rows.push({
          label: "system-extension",
          status: "cannot-remove",
          detail:
            "deactivation accepted by macOS but requires reboot; reboot, then rerun uninstall to observe absence" +
            recoveryNote,
        });
      } else if (deactivation.kind === "needs-user-approval") {
        rows.push({
          label: "system-extension",
          status: "cannot-remove",
          detail: `${deactivation.detail}; approve at the console, then rerun uninstall${recoveryNote}`,
        });
      } else if (deactivation.kind === "failed") {
        rows.push({
          label: "system-extension",
          status: "failed",
          detail: `${deactivation.detail}${recoveryNote}`,
        });
      } else {
        const observedAfter = await ops.systemExtensionStatus();
        if (observedAfter === "absent") {
          rows.push({
            label: "system-extension",
            status: "removed",
            detail:
              "deactivation completed and the Castle Wall system extension is observed absent" +
              recoveryNote,
          });
        } else {
          rows.push({
            label: "system-extension",
            status: "cannot-remove",
            detail:
              observedAfter === "present"
                ? "deactivation request completed but the system extension is still present; reboot and rerun uninstall"
                : "deactivation request completed but absence could not be observed; rerun after reboot",
          });
        }
      }
    }
  }
  rows.push({
    label: "operator-data",
    status: "preserved",
    detail: `fortress state, keys, passphrase custody, recovery material, and audit log remain at ${fortressPath}`,
  });

  const hardResidue = rows.some((row) => row.status === "failed" || row.status === "cannot-remove");
  const clean = safeToRemoveSupportingServices && daemonRemoved && egressRulesRemoved && !hardResidue;
  printReport(out, rows, clean);
  return clean ? 0 : 1;
}
