/**
 * Release barrier: durable launchd-disabled park + root-owned hold file +
 * exec-wrapper verification + the root-supervisor release sequence
 * (Unified Protect Slice 5 S5-5, folds Codex B2'; design "The release
 * barrier" section).
 *
 * INVARIANT (BLOCKER-2'): the agent's network-capable harness process runs
 * ONLY while a matching exclusive-egress generation is COMMITTED (G5). "Write
 * the plist but don't bootstrap" is not a durable park: launchd can load a
 * `RunAtLoad`/`KeepAlive` plist at boot and any root process can `bootstrap`
 * it before G5. The barrier is therefore layered so that no single stale
 * surface can release the agent:
 *
 *   1. LAUNCHD DISABLE STATE. The harness LaunchDaemon is rendered
 *      `Disabled=true` with `RunAtLoad=false` and a `{Crashed:true}`
 *      KeepAlive (crash-restart only, never start-at-load; NOT
 *      `SuccessfulExit`, which launchd.plist(5) documents as implying
 *      `RunAtLoad=true`), and the job is
 *      `launchctl disable`d. A disabled job is not bootstrapped at boot and
 *      cannot be bootstrapped until explicitly enabled -- root-only state in
 *      launchd's override database. Because `launchctl enable` PERSISTS, the
 *      release sequence RE-DISABLES the job as its final step after a
 *      successful bootstrap (re-parking the boot path while the live session
 *      continues); without that re-park the NEXT boot would auto-start the
 *      harness before G5 -- the exact B2' escape.
 *   2. ROOT-OWNED HOLD FILE at `/var/db/sanctuary/agent-harness/<uid>.release`.
 *      Root-authored in a root-owned directory; the agent uid can neither
 *      create, modify, nor remove it. It names the EXACT committed
 *      generation id, the agent uid, the harness label, the harness argv
 *      digest, and THIS BOOT SESSION's `kern.bootsessionuuid`. The G5 commit
 *      writes it; unprotect and EVERY abort branch remove it.
 *   3. EXEC WRAPPER (`ProgramArguments[0]`, root-owned). Before `exec`ing the
 *      real harness argv, it refuses unless the hold file exists, matches the
 *      expected generation id embedded in the plist at release time, matches
 *      its own runtime uid + label, was written in the CURRENT boot session,
 *      and names the digest of the exact argv being exec'd. So a mistaken
 *      `launchctl enable`, a stale plist, or a hold file surviving a reboot
 *      can never release the agent: a stale hold file fails the boot-session
 *      check, a stale plist fails the generation check, a swapped argv fails
 *      the digest check.
 *
 * FILE MODES (disclosed deviation from the design's "0600" note): the hold
 * file is root-owned mode 0644 in a root-owned 0755 directory, NOT 0600. The
 * wrapper runs AS THE AGENT UID (launchd's `UserName` drop -- the proven
 * confinement mechanism; the wrapper never runs as root, so a wrapper defect
 * can never be a root exploit) and must READ the hold file. The security
 * property the design requires -- the agent uid cannot create, modify, or
 * remove the hold file -- holds by ownership (root file, non-agent-writable
 * root directory); the file carries no secret (a generation id + digest), so
 * integrity, not confidentiality, is the guarantee.
 *
 * FAIL-CLOSED DIRECTION: every abort branch in the release sequence removes
 * the hold file and leaves the job disabled. No gate commit means no harness
 * start, ever; the trade is "agent may be down after boot" for "agent can
 * never run unconfined" (never-silently-degrade). A cleanup failure inside an
 * abort is reported LOUDLY in the outcome (`holdFileRemoved`/`jobDisabled`
 * false + `cleanupErrors`), never swallowed.
 *
 * HONESTY BOUNDS. This module is the release-barrier LIBRARY over injected
 * ops: it renders the parked plist + wrapper, plans/executes the parked
 * install, and sequences re-arm -> gate-verify -> commit -> verify-committed
 * -> hold-file -> released-plist -> enable -> bootstrap -> verify-running ->
 * re-park -> verify-running. It is WIRED (S5-6): `runProvisionFlow`'s
 * exclusive stage and the safe-mode boot daemon route through it via
 * `egress-gate/arming-wiring.ts` (S5-7 still wires unprotect). It advances
 * no capability claim: the Erik-present S5-DRILL is still owed.
 * The wrapper verifies the argv DIGEST, not binary content (a swapped binary
 * AT an allowed path is out of scope, per the design's argv-digest bound).
 * The `{Crashed:true}` KeepAlive semantics ("crash-restart within a
 * bootstrapped session, no start-at-load, no restart of a plain refusal
 * exit") and the disable-while-running re-park are drill-owed launchd
 * behaviors (S5-DRILL), stated here as the design intent, not as proven
 * facts. macOS-only (launchd + pf).
 */

import { createHash } from "node:crypto";
import { dirname, isAbsolute } from "node:path";

import {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  renderAgentHarnessDaemonPlist,
  type AgentHarnessDaemonPlistOptions,
  type HarnessDaemonStatus,
} from "./harness-daemon.js";

/** Root-owned parent directory for hold files + the exec wrapper (0755 root). */
export const AGENT_HARNESS_HOLD_DIR = "/var/db/sanctuary/agent-harness";

/**
 * The hold directory's REQUIRED mode: root-owned 0755 (the agent uid must be
 * able to traverse it and read the wrapper + its hold file; only root may
 * write it). Single source of truth -- `runtime-fs-plan.ts` imports this
 * rather than restating `0o755`, so the two layout statements cannot drift.
 */
export const AGENT_HARNESS_HOLD_DIR_MODE = 0o755;

/** First line of every hold file; the wrapper hard-checks it. */
export const HOLD_FILE_HEADER = "sanctuary-agent-harness-release v1";

/** The exec wrapper's file name inside {@link AGENT_HARNESS_HOLD_DIR}. */
export const RELEASE_WRAPPER_FILENAME = "release-exec-wrapper.sh";

/** Exit code the wrapper uses for every refusal (EX_CONFIG; never 0). */
export const RELEASE_WRAPPER_REFUSAL_EXIT_CODE = 78;

/**
 * The parked plist embeds this as the expected generation id. The wrapper
 * refuses any expected generation that is not a positive integer, so a parked
 * plist can NEVER release the agent even if the job were mistakenly enabled
 * and bootstrapped: release requires the supervisor to re-render the plist
 * with the real committed generation id first.
 */
export const PARKED_EXPECTED_GENERATION = 0;

/** Hold-file path for one confined agent uid. */
export function holdFilePathForUid(agentUid: number, dir: string = AGENT_HARNESS_HOLD_DIR): string {
  assertAgentUid(agentUid);
  return `${dir}/${agentUid}.release`;
}

/** Canonical wrapper path (root-owned 0755, inside the root-owned hold dir). */
export function releaseWrapperPath(dir: string = AGENT_HARNESS_HOLD_DIR): string {
  return `${dir}/${RELEASE_WRAPPER_FILENAME}`;
}

/** A release-barrier input or on-disk record violated a constraint. Fail-closed. */
export class ReleaseBarrierError extends Error {
  constructor(message: string) {
    super(`agent-harness release barrier: ${message}`);
    this.name = "ReleaseBarrierError";
  }
}

const SAFE_LABEL_RE = /^[A-Za-z0-9._-]{1,128}$/;
const HEX_SHA256_RE = /^[0-9a-f]{64}$/;
const BOOT_SESSION_UUID_RE = /^[0-9A-Fa-f-]{1,64}$/;
/**
 * Canonical positive decimal integer, wrapper-equivalent: the sh wrapper
 * compares hold-file numbers as STRINGS (`[ "$GEN" = "$EXPECTED" ]`), so the
 * TS parser must accept exactly the forms the wrapper would match -- no
 * leading zeros, no sign, no decimal point, no whitespace. `Number()`
 * coercion alone would accept "1.0" or "007" that the wrapper rejects,
 * making the two parsers disagree about the same file.
 */
const CANONICAL_POSITIVE_INT_RE = /^[1-9][0-9]*$/;

function assertAgentUid(agentUid: number): void {
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new ReleaseBarrierError(`agent uid must be a positive integer (got ${String(agentUid)})`);
  }
}

/**
 * Injected side effects for {@link writeIntoHoldDir}: the ONLY two operations
 * a hold-dir writer is given. There is deliberately no way to write without
 * also supplying the directory-ensure op.
 */
export interface HoldDirWriteOps {
  /**
   * Ensure the root-owned hold directory exists at `path` with EXACTLY `mode`
   * (production: mkdir -p + chown root:wheel + an explicit chmod, because
   * `mkdir`'s mode argument is umask-masked). An already-correct directory is
   * success. THROWS on failure -- a hold dir that is not root-owned 0755 is a
   * barrier defect, never something to write into anyway.
   */
  ensureHoldDir(path: string, mode: number): Promise<void>;
  /** Write `content` at `path` with `mode` (root-owned in production). */
  writeFile(path: string, content: string, mode: number): Promise<void>;
}

/**
 * THE CHOKEPOINT (drill D1, 2026-07-18): the one and only way to place a file
 * inside the root-owned hold directory.
 *
 * WHY THIS SHAPE. `/var/db/sanctuary/agent-harness` is root-owned and nothing
 * in a first-ever install creates it before the barrier needs it. Two writers
 * lived over that directory -- the parked install's exec wrapper and the
 * release sequence's hold file -- and they disagreed about whose job the
 * `mkdir` was: the hold-file writer did it, the wrapper writer did not, so
 * EVERY clean-host `sanctuary protect --hermes --exclusive-egress` died with
 * `ENOENT ... release-exec-wrapper.sh` before any account was created.
 *
 * Adding a second `mkdir` next to the wrapper write would have fixed that one
 * call site and left the same latent split for the third writer. Instead, the
 * ensure is not a step a writer may forget: it is fused to the write. The
 * directory is derived from the file being written (`dirname`), so a caller
 * cannot ensure one directory and then write into another, and the ops
 * interface hands out no bare `writeFile` for a hold-dir path. A structural
 * test pins that no module writes a hold-dir path by any other route.
 */
export async function writeIntoHoldDir(
  ops: HoldDirWriteOps,
  filePath: string,
  content: string,
  mode: number,
): Promise<void> {
  if (!isAbsolute(filePath)) {
    throw new ReleaseBarrierError(`hold-dir file path must be absolute (got ${JSON.stringify(filePath)})`);
  }
  const dir = dirname(filePath);
  if (dir === "/" || dir === "." || dir.length === 0) {
    throw new ReleaseBarrierError(
      `refusing to treat ${JSON.stringify(dir)} as the agent-harness hold directory`,
    );
  }
  await ops.ensureHoldDir(dir, AGENT_HARNESS_HOLD_DIR_MODE);
  await ops.writeFile(filePath, content, mode);
}

/**
 * The hold-file contents. Every field is verified by the wrapper (and by the
 * strict parser) before a release; the record carries NO secret.
 */
export interface HarnessReleaseHoldRecord {
  /** The COMMITTED (G5) generation id this release is bound to. Positive. */
  generation_id: number;
  /** The confined agent uid the wrapper must be running as. */
  agent_uid: number;
  /** The harness LaunchDaemon label the wrapper must have been invoked for. */
  harness_label: string;
  /** {@link computeHarnessArgvDigest} of the exact harness argv to exec. */
  argv_digest: string;
  /**
   * `kern.bootsessionuuid` at write time. A hold file persists on disk across
   * reboots, so without this binding a boot-time start (enable override left
   * on by a crash between bootstrap and re-park) would pass a stale hold file
   * before pf re-arm. The wrapper refuses any hold file not written in the
   * CURRENT boot session, closing that window fail-closed.
   */
  boot_session_uuid: string;
}

/**
 * Digest of a harness argv: sha256 over the argv strings each followed by a
 * NUL byte. MUST stay byte-equal to the wrapper's runtime computation
 * (`printf '%s\0' "$@" | shasum -a 256`); a structural test pins a known
 * vector on both definitions.
 */
export function computeHarnessArgvDigest(argv: readonly string[]): string {
  if (argv.length === 0) {
    throw new ReleaseBarrierError("refusing to digest an empty harness argv");
  }
  const hash = createHash("sha256");
  for (const arg of argv) {
    if (arg.includes("\0")) {
      throw new ReleaseBarrierError("harness argv must not contain NUL bytes");
    }
    hash.update(arg, "utf8");
    hash.update(Buffer.from([0]));
  }
  return hash.digest("hex");
}

function validateHoldRecord(record: HarnessReleaseHoldRecord): void {
  if (!Number.isInteger(record.generation_id) || record.generation_id <= 0) {
    throw new ReleaseBarrierError(
      `hold record generation_id must be a positive integer (got ${String(record.generation_id)})`,
    );
  }
  assertAgentUid(record.agent_uid);
  if (!SAFE_LABEL_RE.test(record.harness_label)) {
    throw new ReleaseBarrierError(`hold record harness_label is not a safe label (got ${JSON.stringify(record.harness_label)})`);
  }
  if (!HEX_SHA256_RE.test(record.argv_digest)) {
    throw new ReleaseBarrierError("hold record argv_digest must be 64 lowercase hex chars");
  }
  if (!BOOT_SESSION_UUID_RE.test(record.boot_session_uuid)) {
    throw new ReleaseBarrierError("hold record boot_session_uuid is missing or malformed");
  }
}

/**
 * Render the line-based hold file (header + `key=value` lines). Line-based so
 * the sh wrapper can parse it with grep/cut, with no JSON parsing in shell.
 * Throws on any field that violates its charset constraint (fail-closed at
 * render time; nothing unparseable-by-the-wrapper is ever written).
 */
export function renderHarnessReleaseHoldFile(record: HarnessReleaseHoldRecord): string {
  validateHoldRecord(record);
  return (
    `${HOLD_FILE_HEADER}\n` +
    `generation_id=${record.generation_id}\n` +
    `agent_uid=${record.agent_uid}\n` +
    `harness_label=${record.harness_label}\n` +
    `argv_digest=${record.argv_digest}\n` +
    `boot_session_uuid=${record.boot_session_uuid}\n`
  );
}

/**
 * Strict parse of a hold file: exact header, exactly one occurrence of each
 * required key, no unknown keys, every value re-validated. Throws on ANY
 * deviation (a malformed hold file must read as "parked", never as a release).
 */
export function parseHarnessReleaseHoldFile(text: string): HarnessReleaseHoldRecord {
  const lines = text.split("\n").filter((l) => l.length > 0);
  if (lines[0] !== HOLD_FILE_HEADER) {
    throw new ReleaseBarrierError("hold file header mismatch");
  }
  const seen = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const eq = line.indexOf("=");
    if (eq <= 0) {
      throw new ReleaseBarrierError(`hold file line is not key=value: ${JSON.stringify(line)}`);
    }
    const key = line.slice(0, eq);
    if (seen.has(key)) {
      throw new ReleaseBarrierError(`hold file key duplicated: ${key}`);
    }
    seen.set(key, line.slice(eq + 1));
  }
  const required = ["generation_id", "agent_uid", "harness_label", "argv_digest", "boot_session_uuid"];
  for (const key of required) {
    if (!seen.has(key)) {
      throw new ReleaseBarrierError(`hold file key missing: ${key}`);
    }
  }
  for (const key of seen.keys()) {
    if (!required.includes(key)) {
      throw new ReleaseBarrierError(`hold file has an unknown key: ${key}`);
    }
  }
  for (const key of ["generation_id", "agent_uid"]) {
    const value = seen.get(key)!;
    if (!CANONICAL_POSITIVE_INT_RE.test(value)) {
      // Wrapper equivalence: the wrapper string-compares these fields, so any
      // non-canonical integer form ("1.0", "007", " 1") must fail here too.
      throw new ReleaseBarrierError(
        `hold file ${key} is not a canonical positive integer (got ${JSON.stringify(value)})`,
      );
    }
  }
  const record: HarnessReleaseHoldRecord = {
    generation_id: Number(seen.get("generation_id")),
    agent_uid: Number(seen.get("agent_uid")),
    harness_label: seen.get("harness_label")!,
    argv_digest: seen.get("argv_digest")!,
    boot_session_uuid: seen.get("boot_session_uuid")!,
  };
  validateHoldRecord(record);
  return record;
}

/**
 * The exec wrapper, as a STATIC POSIX-sh script: nothing is interpolated into
 * the script body (the hold-file path, expected generation, and label arrive
 * as launchd-controlled `ProgramArguments`, and the harness argv arrives as
 * `"$@"`), so there is no render-time injection surface at all. Root-owned
 * 0755; runs as the agent uid via the plist's `UserName` drop. Every refusal
 * exits {@link RELEASE_WRAPPER_REFUSAL_EXIT_CODE} without exec.
 */
export const RELEASE_EXEC_WRAPPER_SCRIPT = `#!/bin/sh
# Sanctuary agent-harness release-barrier exec wrapper (Unified Protect S5-5).
# Constraint: exec the harness ONLY when the root-written hold file names the
# exact expected generation, this boot session, this uid, this label, and the
# digest of the exact argv below. Any absence or mismatch exits 78, no exec.
# macOS-only (kern.bootsessionuuid, /usr/bin/shasum).
set -eu

fail() {
  echo "sanctuary-release-wrapper: refusing to start agent harness: $1" >&2
  exit 78
}

[ "$#" -ge 5 ] || fail "bad invocation (expected hold-file, generation, label, --, argv...)"
HOLD_FILE="$1"
EXPECTED_GENERATION="$2"
EXPECTED_LABEL="$3"
[ "$4" = "--" ] || fail "bad invocation (missing -- separator)"
shift 4

case "$EXPECTED_GENERATION" in
  ""|*[!0-9]*) fail "expected generation is not a number" ;;
esac
[ "$EXPECTED_GENERATION" -gt 0 ] || fail "parked plist (expected generation 0); no release is possible"

[ -f "$HOLD_FILE" ] || fail "hold file absent (agent is parked; no committed generation released this uid)"

head -n 1 "$HOLD_FILE" | grep -q "^sanctuary-agent-harness-release v1$" || fail "hold file header mismatch"

hold_field() {
  n=$(grep -c "^$1=" "$HOLD_FILE" || true)
  [ "$n" = "1" ] || fail "hold file field $1 missing or duplicated"
  grep "^$1=" "$HOLD_FILE" | cut -d= -f2-
}

GEN=$(hold_field generation_id)
UID_EXPECTED=$(hold_field agent_uid)
LABEL=$(hold_field harness_label)
DIGEST=$(hold_field argv_digest)
BOOT_UUID=$(hold_field boot_session_uuid)

[ "$GEN" = "$EXPECTED_GENERATION" ] || fail "hold generation $GEN does not match expected generation $EXPECTED_GENERATION (stale plist or stale hold file)"
[ "$LABEL" = "$EXPECTED_LABEL" ] || fail "hold label does not match this job"
[ "$UID_EXPECTED" = "$(id -u)" ] || fail "hold uid $UID_EXPECTED does not match runtime uid $(id -u)"

CURRENT_BOOT=$(/usr/sbin/sysctl -n kern.bootsessionuuid 2>/dev/null || true)
[ -n "$CURRENT_BOOT" ] || fail "cannot read kern.bootsessionuuid"
[ "$BOOT_UUID" = "$CURRENT_BOOT" ] || fail "hold file was written in a previous boot session (park until the boot daemon re-commits)"

case "$DIGEST" in
  ""|*[!0-9a-f]*) fail "hold argv digest malformed" ;;
esac
ACTUAL_DIGEST=$(printf '%s\\0' "$@" | /usr/bin/shasum -a 256 | cut -d" " -f1)
[ "$DIGEST" = "$ACTUAL_DIGEST" ] || fail "argv digest mismatch (the committed release names a different harness argv)"

exec "$@"
`;

/** Returns the static wrapper script (a function so callers never mutate the constant). */
export function renderReleaseExecWrapperScript(): string {
  return RELEASE_EXEC_WRAPPER_SCRIPT;
}

/** Inputs for {@link buildBarrierProgramArguments}. */
export interface BarrierProgramArgumentsInput {
  /** Absolute path of the installed wrapper script. */
  wrapperPath: string;
  /** Absolute path of this uid's hold file. */
  holdFilePath: string;
  /**
   * The generation id the plist releases, or {@link PARKED_EXPECTED_GENERATION}
   * for the parked form (which the wrapper refuses unconditionally).
   */
  expectedGenerationId: number;
  /** The job label the wrapper cross-checks against the hold file. */
  harnessLabel: string;
  /** The REAL harness argv (absolute program path first). */
  harnessArgv: readonly string[];
}

/**
 * Compose the barrier-form `ProgramArguments`: wrapper first, then the
 * wrapper's own arguments, then `--`, then the untouched harness argv. The
 * plist renderer's control-character validation applies to every element.
 */
export function buildBarrierProgramArguments(input: BarrierProgramArgumentsInput): string[] {
  if (!isAbsolute(input.wrapperPath)) {
    throw new ReleaseBarrierError(`wrapper path must be absolute (got ${input.wrapperPath})`);
  }
  if (!isAbsolute(input.holdFilePath)) {
    throw new ReleaseBarrierError(`hold-file path must be absolute (got ${input.holdFilePath})`);
  }
  if (!SAFE_LABEL_RE.test(input.harnessLabel)) {
    throw new ReleaseBarrierError(`harness label is not a safe label (got ${JSON.stringify(input.harnessLabel)})`);
  }
  const gen = input.expectedGenerationId;
  if (!Number.isInteger(gen) || gen < 0) {
    throw new ReleaseBarrierError(`expected generation id must be a non-negative integer (got ${String(gen)})`);
  }
  if (input.harnessArgv.length === 0 || !isAbsolute(input.harnessArgv[0]!)) {
    throw new ReleaseBarrierError("harness argv must be non-empty with an absolute program path first");
  }
  return [input.wrapperPath, input.holdFilePath, String(gen), input.harnessLabel, "--", ...input.harnessArgv];
}

/** Options for {@link planParkedHarnessInstall}. */
export interface ParkedHarnessInstallOptions {
  /** The dedicated agent service account (same constraints as the plain renderer). */
  agentAccount: string;
  /** The confined agent uid (names the hold file). */
  agentUid: number;
  /** The REAL harness argv the wrapper will digest-check and exec. */
  harnessArgv: string[];
  /** Passed through to the plist renderer. */
  fortressPath?: string;
  /** Passed through to the plist renderer. */
  logDir?: string;
  /** Passed through to the plist renderer (forbidden-env list still applies). */
  environment?: Record<string, string>;
  /** Hold dir override (tests only). Default {@link AGENT_HARNESS_HOLD_DIR}. */
  holdDir?: string;
  /**
   * Expected generation for the rendered plist. Default
   * {@link PARKED_EXPECTED_GENERATION} (parked: the wrapper refuses). The
   * release sequence re-renders with the real committed id before enabling.
   */
  expectedGenerationId?: number;
}

/** A planned parked install: plist + wrapper + where the hold file will live. */
export interface ParkedHarnessInstallPlan {
  plistPath: string;
  plistContent: string;
  wrapperPath: string;
  wrapperContent: string;
  holdFilePath: string;
  harnessLabel: string;
}

/**
 * Build the PARKED install plan (pure). The rendered plist is the barrier
 * form: `Disabled=true`, `RunAtLoad=false`, `{Crashed:true}` KeepAlive
 * (crash-restart only; `SuccessfulExit` would imply `RunAtLoad=true` per
 * launchd.plist(5) and restart wrapper refusals in a loop), and
 * `ProgramArguments` routed through the wrapper with the parked expected
 * generation (unless a committed one is supplied for a release re-render).
 */
export function planParkedHarnessInstall(options: ParkedHarnessInstallOptions): ParkedHarnessInstallPlan {
  assertAgentUid(options.agentUid);
  const holdDir = options.holdDir ?? AGENT_HARNESS_HOLD_DIR;
  const wrapperPath = releaseWrapperPath(holdDir);
  const holdFilePath = holdFilePathForUid(options.agentUid, holdDir);
  const programArguments = buildBarrierProgramArguments({
    wrapperPath,
    holdFilePath,
    expectedGenerationId: options.expectedGenerationId ?? PARKED_EXPECTED_GENERATION,
    harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
    harnessArgv: options.harnessArgv,
  });
  const plistOptions: AgentHarnessDaemonPlistOptions = {
    agentAccount: options.agentAccount,
    programArguments,
    fortressPath: options.fortressPath,
    logDir: options.logDir,
    environment: options.environment,
    disabled: true,
    runAtLoad: false,
    keepAliveCrashedOnly: true,
  };
  return {
    plistPath: AGENT_HARNESS_DAEMON_PLIST_PATH,
    plistContent: renderAgentHarnessDaemonPlist(plistOptions),
    wrapperPath,
    wrapperContent: renderReleaseExecWrapperScript(),
    holdFilePath,
    harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
  };
}

/**
 * launchctl `bootout` stderr that means "the job was not running", which is
 * SUCCESS for a stand-down. Kept byte-identical to the tolerance the shipped
 * `arming-wiring.ts` bootout ops already use, so the two never disagree about
 * what counts as "already stopped".
 */
const BOOTOUT_NOT_RUNNING_RE = /No such process|Could not find|not find service/i;

/** Injected side effects for the parked install (root in production; mocks in tests). */
export interface ParkedInstallOps extends HoldDirWriteOps {
  /** Remove the file at `path` (ENOENT is not an error). */
  removeFile(path: string): Promise<void>;
  /** Run launchctl with argv (never a shell). */
  runLaunchctl(args: readonly string[]): Promise<{ code: number; stdout: string; stderr: string }>;
  /** The harness job's launchd status (the shipped `agentHarnessDaemonStatus`). */
  harnessStatus(): Promise<HarnessDaemonStatus>;
  /**
   * Surface one line to the operator running the flow. REQUIRED (not
   * optional): the stand-down below stops a live, privileged agent process,
   * and an install that silently kills the user's running harness would be a
   * worse defect than the one it fixes. A caller that genuinely wants silence
   * must say so with an explicit no-op.
   */
  notify(message: string): void;
}

/**
 * Execute a parked install: write the wrapper (0755, through the hold-dir
 * chokepoint) and the barrier plist (0644), `launchctl disable` the job, STAND
 * DOWN any already-running instance, and remove any stale hold file. This
 * function NEVER bootstraps (a structural test pins that no `bootstrap`
 * launchctl verb can be issued from here), and it fails LOUD if the job
 * reports running afterwards -- a parked install with a live harness is a
 * barrier violation, not a warning.
 *
 * THE STAND-DOWN (drill D2, 2026-07-18). `launchctl disable` only stops
 * FUTURE bootstrapping; it does not stop a job that is already running. Any
 * host that ran a pre-Slice-5 `protect` has a KeepAlive harness running, so
 * the post-install assertion below tripped and every upgrade-host arm aborted.
 * The park is now ASSERTED rather than assumed:
 *
 *   1. `disable` FIRST, so nothing can re-bootstrap the job underneath the
 *      bootout (the reverse order leaves a window where launchd restarts it).
 *   2. `bootout` the running instance. "No such process" / "Could not find"
 *      means it was already stopped and is success; ANY other failure REFUSES
 *      -- a stand-down we could not perform must not be reported as a park.
 *   3. The pre-existing fail-closed assertion is unchanged and still the last
 *      word: an untrustworthy status, or a job STILL running after all of the
 *      above, refuses exactly as before.
 */
export async function executeParkedHarnessInstall(
  plan: ParkedHarnessInstallPlan,
  ops: ParkedInstallOps,
): Promise<void> {
  await writeIntoHoldDir(ops, plan.wrapperPath, plan.wrapperContent, 0o755);
  await ops.writeFile(plan.plistPath, plan.plistContent, 0o644);
  const disable = await ops.runLaunchctl(["disable", `system/${plan.harnessLabel}`]);
  if (disable.code !== 0) {
    throw new ReleaseBarrierError(
      `launchctl disable system/${plan.harnessLabel} exited ${disable.code}: ${disable.stderr.trim()}`,
    );
  }
  const bootout = await ops.runLaunchctl(["bootout", `system/${plan.harnessLabel}`]);
  if (bootout.code === 0) {
    // A privileged, agent-stopping action actually happened. Never silent.
    ops.notify(
      `Stopped the already-running ${plan.harnessLabel} job (launchctl bootout) so the parked ` +
        "install can hold; the release barrier restarts it after the gate generation commits.",
    );
  } else if (!BOOTOUT_NOT_RUNNING_RE.test(bootout.stderr)) {
    throw new ReleaseBarrierError(
      `could not stand down the running harness job: launchctl bootout system/${plan.harnessLabel} ` +
        `exited ${bootout.code}: ${bootout.stderr.trim()}; refusing to report a park that was not asserted`,
    );
  }
  await ops.removeFile(plan.holdFilePath);
  const status = await ops.harnessStatus();
  if (!status.known) {
    throw new ReleaseBarrierError(
      "launchctl did not return a trustworthy harness status after the parked install; refusing to report parked",
    );
  }
  if (status.running) {
    throw new ReleaseBarrierError(
      "the harness job reports RUNNING after a parked install; the park did not hold (manual intervention required)",
    );
  }
}

/** The stages of the release sequence, in order; abort outcomes name one. */
export type ReleaseBarrierStage =
  | "reassert-parked"
  | "rearm-anchor"
  | "gate-verify"
  | "commit-generation"
  | "verify-committed"
  | "write-hold-file"
  | "write-released-plist"
  | "enable"
  | "bootstrap"
  | "verify-running"
  | "repark-boot-state";

/** What the release sequence needs to know about the agent it releases. */
export interface ReleaseBarrierContext {
  agentUid: number;
  /** The job label (cross-checked into the hold file). */
  harnessLabel: string;
  /** The REAL harness argv (digest source; must match the installed plist's). */
  harnessArgv: readonly string[];
}

/** The committed-generation shape the sequence keys the release on. */
export interface CommittedGenerationIdentity {
  generation_id: number;
  agent_uid: number;
}

/**
 * Injected side effects for the release sequence. Production wiring (S5-6)
 * maps these onto launchctl, the hold-file FS ops, the S5-1 registry re-arm,
 * the gate/oracle verify, and the S5-2 `GenerationCoordinator`; tests inject
 * spies so every abort branch is assertable host-free.
 */
export interface ReleaseBarrierOps {
  /** `launchctl disable system/<label>` (persistent park state). Throws on failure. */
  disableJob(): Promise<void>;
  /** `launchctl enable system/<label>`. Throws on failure. */
  enableJob(): Promise<void>;
  /** `launchctl bootstrap` + `kickstart` the job. Throws on failure. */
  bootstrapJob(): Promise<void>;
  /**
   * `launchctl bootout` (reassert-parked stop of any live job + abort
   * cleanup; production treats not-running as success). Throws on failure.
   */
  bootoutJob(): Promise<void>;
  /** Remove the hold file (ENOENT is success). Throws on failure. */
  removeHoldFile(): Promise<void>;
  /** Atomically write the hold file as root. Throws on failure. */
  writeHoldFile(record: HarnessReleaseHoldRecord): Promise<void>;
  /** Current `kern.bootsessionuuid`. Throws when unreadable (fail-closed). */
  bootSessionUuid(): Promise<string>;
  /**
   * Boot path: re-arm the pf anchor union from the S5-1 registry. Install
   * path (the generation bring-up already armed pf at G3) supplies an ok
   * no-op. Discriminated, never throws.
   */
  rearmAnchor(): Promise<{ ok: true } | { ok: false; reason: string }>;
  /**
   * Gate up + port owner verified + generation surfaces matching.
   * Discriminated. On success it MUST return the LIVE generation identity it
   * verified (`observed`): the sequence calls this twice -- once before the
   * commit (gate liveness), once after (binding the verified identity to the
   * exact committed identity, closing the verify-A/commit-B TOCTOU window
   * where a hold file could name a generation nobody proved is the live
   * gate/pf generation).
   */
  verifyGate(): Promise<
    { ok: true; observed: CommittedGenerationIdentity } | { ok: false; reasons: string[] }
  >;
  /**
   * Commit the generation this release is bound to: the S5-2 G5 commit at
   * install, or the boot rebind-or-new-generation commit. Throws on failure;
   * the returned identity MUST name the agent uid being released.
   */
  commitGeneration(): Promise<CommittedGenerationIdentity>;
  /**
   * Re-render + atomically write the RELEASED harness plist: the barrier
   * plist form with `expectedGenerationId` = the committed generation id
   * (`planParkedHarnessInstall({..., expectedGenerationId})`). REQUIRED for
   * every release: the parked plist on disk embeds
   * {@link PARKED_EXPECTED_GENERATION}, which the wrapper refuses
   * unconditionally, so without this stage a "released" verdict would
   * describe a harness whose wrapper refuses every start. Throws on failure.
   */
  writeReleasedPlist(committed: CommittedGenerationIdentity): Promise<void>;
  /**
   * Restore the PARKED plist form (expected generation
   * {@link PARKED_EXPECTED_GENERATION}) on disk. Called by reassert-parked
   * (a crashed prior run may have left a released plist behind), by every
   * abort branch after {@link writeReleasedPlist}, and by the final
   * boot-state re-park (the parked plist is part of the persistent parked
   * posture, alongside the launchctl disable override). Throws on failure.
   */
  restoreParkedPlist(): Promise<void>;
  /**
   * The harness job's launchd status. Production wiring MUST make `running`
   * mean STABLE-running (the exported `agentHarnessDaemonStableRunning`
   * sampling bar), not a single point sample: a kickstarted process that
   * immediately exits (a refusing wrapper) must read as not running.
   */
  harnessStatus(): Promise<HarnessDaemonStatus>;
}

/** Terminal outcome of one release-sequence run. */
export type ReleaseBarrierOutcome =
  | { kind: "released"; generation_id: number }
  /**
   * The harness WAS released (running, confined, hold file in place) but the
   * final re-disable of the persistent boot state failed -- the next boot
   * could auto-start the harness before G5. Callers MUST surface this as a
   * non-green (amber) state and retry the re-park; it is never a clean green.
   */
  | { kind: "released-repark-failed"; generation_id: number; reparkError: string }
  | {
      kind: "parked";
      stage: ReleaseBarrierStage;
      reason: string;
      /** True when the hold file is confirmed absent after this abort. */
      holdFileRemoved: boolean;
      /** True when the job is confirmed disabled after this abort. */
      jobDisabled: boolean;
      /** Cleanup failures (LOUD; never swallowed). Empty on a clean abort. */
      cleanupErrors: string[];
    };

interface ParkCleanupResult {
  holdFileRemoved: boolean;
  jobDisabled: boolean;
  errors: string[];
}

async function parkCleanup(
  ops: ReleaseBarrierOps,
  input: { removeHold: boolean; disable: boolean; bootout?: boolean; restorePlist?: boolean },
): Promise<ParkCleanupResult> {
  const errors: string[] = [];
  let jobDisabled = !input.disable;
  let holdFileRemoved = !input.removeHold;
  if (input.bootout === true) {
    try {
      await ops.bootoutJob();
    } catch (err) {
      errors.push(`bootout failed: ${(err as Error).message}`);
    }
  }
  if (input.removeHold) {
    try {
      await ops.removeHoldFile();
      holdFileRemoved = true;
    } catch (err) {
      errors.push(`hold-file removal failed: ${(err as Error).message}`);
    }
  }
  if (input.disable) {
    try {
      await ops.disableJob();
      jobDisabled = true;
    } catch (err) {
      errors.push(`disable failed: ${(err as Error).message}`);
    }
  }
  if (input.restorePlist === true) {
    try {
      await ops.restoreParkedPlist();
    } catch (err) {
      errors.push(`parked-plist restore failed: ${(err as Error).message}`);
    }
  }
  return { holdFileRemoved, jobDisabled, errors };
}

/**
 * Run the release sequence: reassert-parked -> re-arm -> gate-verify ->
 * commit -> verify-committed -> hold-file -> released-plist -> enable ->
 * bootstrap -> verify-running -> re-park boot state -> verify-running.
 *
 * ORDERING CONSTRAINTS (the design's barrier line, unit-pinned):
 *   - `enableJob` is called ONLY after `commitGeneration` returned, the
 *     committed identity was RE-VERIFIED as the live gate generation
 *     (verify-committed: the verified identity is bound to the committed one,
 *     never "verified something earlier, committed something else"), the hold
 *     file for that exact committed generation was written, AND the released
 *     plist embedding that generation was written (a parked plist embeds
 *     generation 0, which the wrapper refuses unconditionally).
 *   - `bootstrapJob` is called ONLY after `enableJob` succeeded.
 *   - "released" is returned ONLY after the harness reports STABLE-running
 *     both after bootstrap and after the final boot-state re-park -- a
 *     kickstart whose process immediately exits (a refusing wrapper) is a
 *     parked abort, never a silent green.
 *   - EVERY abort branch removes the hold file, leaves the job disabled, and
 *     (once the released plist may be on disk) restores the parked plist
 *     (fail-closed; a cleanup failure is reported, never swallowed).
 *   - The FIRST step re-asserts the parked state (bootout any live job +
 *     disable + remove any stale hold file + restore the parked plist) so a
 *     crashed previous run -- or a coarse-mode-running harness on the repair
 *     path -- can never leak a releasable state OR a live process into this
 *     one; if the park cannot be asserted, the sequence refuses to proceed
 *     at all.
 */
export async function runReleaseBarrierSequence(
  ctx: ReleaseBarrierContext,
  ops: ReleaseBarrierOps,
): Promise<ReleaseBarrierOutcome> {
  assertAgentUid(ctx.agentUid);
  if (!SAFE_LABEL_RE.test(ctx.harnessLabel)) {
    throw new ReleaseBarrierError(`harness label is not a safe label (got ${JSON.stringify(ctx.harnessLabel)})`);
  }

  // Stage: reassert-parked. Refuse to proceed unless the parked state holds.
  // Restores the parked plist too: a crashed previous run may have left a
  // released plist (embedding a real generation id) on disk. BOOTS OUT any
  // live job as well (fix-round BLOCKER-3): a crashed prior run -- or the
  // repair path, whose harness may be running in coarse mode -- can have a
  // LIVE process; "parked" asserted over a still-running harness is not a
  // park. The production bootout op treats not-running as success.
  const initial = await parkCleanup(ops, {
    removeHold: true,
    disable: true,
    bootout: true,
    restorePlist: true,
  });
  if (initial.errors.length > 0) {
    return {
      kind: "parked",
      stage: "reassert-parked",
      reason:
        "could not re-assert the parked state (bootout + disable + stale-hold-file removal + parked-plist restore); refusing to run the release sequence",
      holdFileRemoved: initial.holdFileRemoved,
      jobDisabled: initial.jobDisabled,
      cleanupErrors: initial.errors,
    };
  }

  // Stage: rearm-anchor. Already parked; an abort here needs no new cleanup.
  const rearm = await ops.rearmAnchor();
  if (!rearm.ok) {
    return {
      kind: "parked",
      stage: "rearm-anchor",
      reason: `pf anchor re-arm failed: ${rearm.reason}`,
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
    };
  }

  // Stage: gate-verify.
  const gate = await ops.verifyGate();
  if (!gate.ok) {
    return {
      kind: "parked",
      stage: "gate-verify",
      reason: `gate verification failed: ${gate.reasons.join("; ")}`,
      holdFileRemoved: true,
      jobDisabled: true,
      cleanupErrors: [],
    };
  }

  // Stage: commit-generation.
  let committed: CommittedGenerationIdentity;
  try {
    committed = await ops.commitGeneration();
  } catch (err) {
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
    return {
      kind: "parked",
      stage: "commit-generation",
      reason: `generation commit failed: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }
  if (
    committed.agent_uid !== ctx.agentUid ||
    !Number.isInteger(committed.generation_id) ||
    committed.generation_id <= 0
  ) {
    // Identity keying (design: "the G5 commit names what it releases"). A
    // commit for a different uid, or a non-positive id, must never release.
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
    return {
      kind: "parked",
      stage: "commit-generation",
      reason:
        `committed generation identity mismatch: commit names uid ${String(committed.agent_uid)} ` +
        `generation ${String(committed.generation_id)}, release is for uid ${ctx.agentUid}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: verify-committed. Bind the verified identity to the COMMITTED one
  // (TOCTOU close): the pre-commit gate-verify proved gate liveness, but only
  // a re-verify AFTER the commit proves the exact committed generation is the
  // live gate/pf generation the hold file is about to release.
  try {
    const reverify = await ops.verifyGate();
    if (!reverify.ok) {
      const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
      return {
        kind: "parked",
        stage: "verify-committed",
        reason: `post-commit gate verification failed: ${reverify.reasons.join("; ")}`,
        holdFileRemoved: cleanup.holdFileRemoved,
        jobDisabled: cleanup.jobDisabled,
        cleanupErrors: cleanup.errors,
      };
    }
    if (
      reverify.observed.generation_id !== committed.generation_id ||
      reverify.observed.agent_uid !== committed.agent_uid
    ) {
      const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
      return {
        kind: "parked",
        stage: "verify-committed",
        reason:
          `post-commit verification observed uid ${String(reverify.observed.agent_uid)} ` +
          `generation ${String(reverify.observed.generation_id)}, but the commit named uid ` +
          `${String(committed.agent_uid)} generation ${String(committed.generation_id)}; ` +
          "refusing to release a generation that is not the verified live gate generation",
        holdFileRemoved: cleanup.holdFileRemoved,
        jobDisabled: cleanup.jobDisabled,
        cleanupErrors: cleanup.errors,
      };
    }
  } catch (err) {
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
    return {
      kind: "parked",
      stage: "verify-committed",
      reason: `post-commit gate verification errored: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: write-hold-file. Render first (validates every field fail-closed).
  try {
    const record: HarnessReleaseHoldRecord = {
      generation_id: committed.generation_id,
      agent_uid: ctx.agentUid,
      harness_label: ctx.harnessLabel,
      argv_digest: computeHarnessArgvDigest(ctx.harnessArgv),
      boot_session_uuid: await ops.bootSessionUuid(),
    };
    renderHarnessReleaseHoldFile(record);
    await ops.writeHoldFile(record);
  } catch (err) {
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true });
    return {
      kind: "parked",
      stage: "write-hold-file",
      reason: `hold-file write failed: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: write-released-plist. The parked plist embeds generation 0, which
  // the wrapper refuses unconditionally: without this re-render the enable +
  // bootstrap below would "succeed" while the wrapper refuses every start.
  try {
    await ops.writeReleasedPlist(committed);
  } catch (err) {
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true, restorePlist: true });
    return {
      kind: "parked",
      stage: "write-released-plist",
      reason: `released-plist write failed: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: enable. Strictly after commit + hold-file + released plist (the
  // barrier line).
  try {
    await ops.enableJob();
  } catch (err) {
    const cleanup = await parkCleanup(ops, { removeHold: true, disable: true, restorePlist: true });
    return {
      kind: "parked",
      stage: "enable",
      reason: `enable failed: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: bootstrap (+ kickstart, inside the op).
  try {
    await ops.bootstrapJob();
  } catch (err) {
    const cleanup = await parkCleanup(ops, {
      removeHold: true,
      disable: true,
      bootout: true,
      restorePlist: true,
    });
    return {
      kind: "parked",
      stage: "bootstrap",
      reason: `bootstrap failed: ${(err as Error).message}`,
      holdFileRemoved: cleanup.holdFileRemoved,
      jobDisabled: cleanup.jobDisabled,
      cleanupErrors: cleanup.errors,
    };
  }

  // Stage: verify-running (post-bootstrap). A bootstrap/kickstart that
  // launchctl accepted proves nothing about the harness actually running:
  // the wrapper may be refusing (exit 78) on every start. Require a live
  // status probe (stable-running in production wiring) before claiming
  // anything.
  {
    const probe = await probeHarnessRunning(ops);
    if (!probe.ok) {
      const cleanup = await parkCleanup(ops, {
        removeHold: true,
        disable: true,
        bootout: true,
        restorePlist: true,
      });
      return {
        kind: "parked",
        stage: "verify-running",
        reason: `harness is not running after bootstrap: ${probe.reason}`,
        holdFileRemoved: cleanup.holdFileRemoved,
        jobDisabled: cleanup.jobDisabled,
        cleanupErrors: cleanup.errors,
      };
    }
  }

  // Stage: repark-boot-state. `launchctl enable` persists across boots and
  // the released plist embeds a real generation id; the re-disable + parked-
  // plist restore re-park the persistent boot path while the live
  // bootstrapped session continues. A failure here is a LOUD distinct
  // outcome: the harness is confined and running, but the NEXT boot could
  // auto-start it pre-G5.
  try {
    await ops.disableJob();
    await ops.restoreParkedPlist();
  } catch (err) {
    return {
      kind: "released-repark-failed",
      generation_id: committed.generation_id,
      reparkError: (err as Error).message,
    };
  }

  // Stage: verify-running (post-re-park). The re-park must not have taken
  // the live session down; "released" with a dead harness would be a
  // deceptive green. The job is already disabled and the parked plist is
  // already restored; the cleanup removes the hold file and boots the dead
  // job out.
  {
    const probe = await probeHarnessRunning(ops);
    if (!probe.ok) {
      const cleanup = await parkCleanup(ops, { removeHold: true, disable: false, bootout: true });
      return {
        kind: "parked",
        stage: "verify-running",
        reason: `harness is not running after the boot-state re-park: ${probe.reason}`,
        holdFileRemoved: cleanup.holdFileRemoved,
        jobDisabled: cleanup.jobDisabled,
        cleanupErrors: cleanup.errors,
      };
    }
  }

  return { kind: "released", generation_id: committed.generation_id };
}

/** Fail-closed harness liveness probe: unknown status or a throw is NOT running. */
async function probeHarnessRunning(
  ops: ReleaseBarrierOps,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  let status: HarnessDaemonStatus;
  try {
    status = await ops.harnessStatus();
  } catch (err) {
    return { ok: false, reason: `status probe errored: ${(err as Error).message}` };
  }
  if (!status.known) {
    return { ok: false, reason: "launchctl did not return a trustworthy harness status" };
  }
  if (!status.running) {
    return { ok: false, reason: "the job has no stable running pid (the release wrapper may be refusing to exec)" };
  }
  return { ok: true };
}
