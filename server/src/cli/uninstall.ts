import { lstat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { Writable } from "node:stream";

import { unprovision, unprovisionFullyOk, type UnprovisionStepOutcome } from "../castle-wall/provision/unprovision.js";
import { scrubProvisionedEgressRules, type ScrubProvisionedEgressResult } from "../castle-wall/provision/egress.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";
import { CASTLE_WALL_BOOT_PLIST_PATH, runUninstallBoot } from "./castle-wall-boot.js";

// Must match CASTLE_GLOBAL_PINNED_PUBKEY_PATH in server/src/cli/castle-wall.ts.
export const CASTLE_GLOBAL_PINNED_PUBKEY_PATH = "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin";

type FootprintStatus = "absent" | "present" | "unknown" | "not-applicable";

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
  disarm(fortressPath: string): Promise<void>;
  uninstallHarnessDaemon(): Promise<void>;
  scrubProvisionedEgressRules(fortressPath: string, harnessId: string): Promise<ScrubProvisionedEgressResult>;
  bootServiceStatus(): Promise<FootprintStatus>;
  uninstallBootService(fortressPath: string): Promise<void>;
  globalPinStatus(): Promise<FootprintStatus>;
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
      if (platform !== "darwin") return;
      const { runDisable } = await import("./castle-wall.js");
      const code = await runDisable(["--fortress", fortressPath], { out: nullWritable(), err: nullWritable(), env, platform });
      if (code !== 0) throw new Error(`castle-wall disable exited ${code}`);
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
  };
}

function noRehomeOps() {
  return {
    verifyDestinationHomeCustody: async () => {},
    prepareDestinationParentCustody: async () => ({ revalidate: async () => {}, close: async () => {} }),
    pathExists: async () => false,
    pathExistsNoFollow: async () => false,
    hashPath: async (path: string) => ({ algorithm: "sha256" as const, value: path }),
    readDestinationProvenance: async () => undefined,
    recordDestinationProvenance: async () => {},
    clearDestinationProvenance: async () => {},
    displaceDestination: async (destPath: string) => ({ displacedPath: `${destPath}.displaced` }),
    restoreDisplacedDestination: async () => ({ restored: true }),
    backup: async (path: string) => ({ backupPath: `${path}.bak` }),
    removeSourceDuplicate: async () => {},
    restoreSourceDuplicate: async () => ({ restored: true }),
    move: async () => {},
    chown: async () => ({ excludedPaths: [] }),
    restore: async () => ({ restored: true }),
    restoreCustody: async () => {},
  };
}

function rowFromUnprovisionOutcome(
  outcome: UnprovisionStepOutcome,
  scrubResult: ScrubProvisionedEgressResult | undefined,
  platform: NodeJS.Platform,
): ReportRow {
  if (!outcome.ok) {
    return { label: outcome.step, status: "failed", detail: outcome.error ?? "unknown error" };
  }
  if (outcome.step === "disarm") {
    if (platform !== "darwin") {
      return { label: "castle-wall", status: "skipped", detail: "no macOS Castle Wall content filter exists on this platform" };
    }
    return { label: "castle-wall", status: "removed", detail: "content filter disarm command completed" };
  }
  if (outcome.step === "uninstall-daemon") {
    return { label: "harness-daemon", status: "removed", detail: "auto-provisioned harness daemon uninstall completed" };
  }
  if (outcome.step === "scrub-egress-rules") {
    const count = scrubResult?.removedRuleIds.length ?? 0;
    const reload = scrubResult?.reloadOk === false ? "; policy reload was not confirmed" : "";
    return { label: "egress-rules", status: "removed", detail: `${count} provisioned rule file(s) removed${reload}` };
  }
  return {
    label: "re-home restore",
    status: "skipped",
    detail:
      "no persisted successful-provision re-home result manifest exists for this CLI to replay; operator files and fortress data were not deleted",
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
  let scrubResult: ScrubProvisionedEgressResult | undefined;

  const unprovisionOutcomes = await unprovision({
    rehomeResults: [],
    rehomeOps: noRehomeOps(),
    unprovisionOps: {
      disarm: () => ops.disarm(fortressPath),
      uninstallHarnessDaemon: () => ops.uninstallHarnessDaemon(),
      scrubProvisionedEgressRules: async () => {
        scrubResult = await ops.scrubProvisionedEgressRules(fortressPath, parsed.harnessId);
      },
    },
    operatorUidGid: { uid: getuid?.() ?? 0, gid: getuid?.() ?? 0 },
  });
  rows.push(...unprovisionOutcomes.map((outcome) => rowFromUnprovisionOutcome(outcome, scrubResult, platform)));

  const bootStatus = await ops.bootServiceStatus();
  if (bootStatus === "present") {
    if (platform === "darwin" && getuid?.() === 0) {
      try {
        await ops.uninstallBootService(fortressPath);
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
    rows.push({
      label: "system-extension",
      status: "cannot-remove",
      detail: "CLI disarms the filter but does not deactivate or remove the Castle Wall system extension; use the Castle Wall host app and reboot if macOS keeps it loaded",
    });
  }
  rows.push({
    label: "operator-data",
    status: "preserved",
    detail: `fortress state, keys, passphrase custody, recovery material, and audit log remain at ${fortressPath}`,
  });

  const hardResidue = rows.some((row) => row.status === "failed" || row.status === "cannot-remove");
  const clean = unprovisionFullyOk(unprovisionOutcomes) && !hardResidue;
  printReport(out, rows, clean);
  return clean ? 0 : 1;
}
