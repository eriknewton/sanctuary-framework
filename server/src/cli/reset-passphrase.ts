/**
 * Sanctuary MCP Server — `sanctuary reset-passphrase` CLI subcommand
 *
 * Recovery flow for passphrase loss. Three mutually exclusive paths:
 *
 *   (a) Recovery shares   — reconstruct the master key from M-of-N shares.
 *                           Operationally available only when the operator has
 *                           previously persisted shares to this fortress. v1.0.x
 *                           does not yet ship share persistence; this path
 *                           degrades gracefully today.
 *
 *   (b) Guardian quorum   — initiate a federation v0.1
 *                           `guardian_recovery_request` and wait for the
 *                           configured guardian threshold. Requires an
 *                           unlocked local fortress to talk to the federation,
 *                           which the lost-passphrase scenario does not have.
 *                           Path ships with v1.1 federation full mesh.
 *
 *   (c) Nuke and rebind   — destroy the fortress entirely and re-initialize.
 *                           ALL state (identities, broker tokens, audit log,
 *                           federation membership) is permanently lost. The
 *                           operator types the fortress name and the literal
 *                           word DESTROY before the wipe runs.
 *
 * Deliberately ABSENT fourth path (ratified posture 2026-07-22,
 * docs/custody-recovery-posture.md): "unlock with the OS-keyring custody key
 * and enroll a new passphrase." The keyring key is released to any process in
 * the logged-in session, so that path would let anyone at an unlocked machine
 * take over custody without holding a human credential. Machine-resident
 * factors never bootstrap human-held custody; do not add that mode without
 * superseding the posture doc.
 *
 * Refuse-if-unlocked guard: if `<storage>/runtime.json` exists, refuse with a
 * clear hint to stop the dashboard and any wrapped agents first. Operators on
 * a stale runtime file can remove it manually after confirming nothing is
 * running.
 *
 * Multi-principal note: v1.0.x fortresses are single-principal. When a future
 * v1.x ships multi-principal fortresses (Federation Protocol §10 reservation,
 * Architecture Walk Q4), this command MUST branch on principal selection so a
 * single principal's lost passphrase does not silently nuke the whole
 * fortress. The hook point is `selectMode()` below; the survey logic at
 * `surveyAvailableModes()` is the right place to enumerate per-principal
 * mode availability when that lands.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import { createInterface, Interface as ReadlineInterface } from "node:readline";
import {
  readdir,
  rm,
  stat,
  writeFile,
  appendFile,
  access,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";

import { resolveStoragePath } from "../paths.js";
import { execKeychain } from "../wrap/keychain-exec.js";
import { keychainServiceFor } from "../wrap/passphrase.js";
import { consumeFlagValue } from "./argv.js";

// ── Types ───────────────────────────────────────────────────────────

export type RecoveryMode = "shares" | "guardian" | "nuke";

export interface ResetPassphraseArgs {
  argv: string[];
  /** Output stream (stdout in prod; captured in tests). */
  out?: NodeJS.WritableStream;
  /** Error stream (stderr in prod; captured in tests). */
  err?: NodeJS.WritableStream;
  /** Stdin source for prompts (tests inject Readable; prod uses process.stdin). */
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  /** Override storage path (tests; prod resolves from env). */
  storagePath?: string;
  /** Override home directory (tests). */
  home?: string;
  /** Override platform detection (tests). */
  platformOverride?: NodeJS.Platform;
  /**
   * Override `security` exec for Keychain cleanup (tests). Production uses a
   * default that spawns `/usr/bin/security`.
   */
  exec?: (
    cmd: string,
    args: string[]
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  /**
   * Optional buffers holding key material the caller wants zeroed before this
   * command returns. Each entry has `.fill(0)` applied in a `finally` block,
   * including on early aborts. Production v1.x reset paths hold no key
   * material in this CLI module; the hook exists so future recovery-share
   * reconstruction (path (a)) and any caller that constructs the command
   * with a pre-decoded passphrase Buffer cannot forget to zeroize.
   *
   * JS strings are immutable in V8 and cannot be zeroed; route key material
   * through Buffer / Uint8Array, place it on this list, and the buffer will
   * be cleared post-use. See `runNukePath` doc block for the full threat
   * model.
   */
  keyMaterialToZeroize?: Array<Buffer | Uint8Array>;
  /**
   * Override for `process.exit`. The `--exit-on-completion` flag calls this
   * with code 0 after a successful nuke to limit the post-nuke window an
   * attacker-on-host with heap-dump access could exploit. Tests inject a
   * spy so the test process does not actually exit; production passes
   * `process.exit`.
   */
  exitProcess?: (code: number) => void;
}

interface ModeAvailability {
  shares: { available: boolean; reason: string };
  guardian: { available: boolean; reason: string };
  nuke: { available: boolean; reason: string };
}

interface ParsedArgs {
  mode?: RecoveryMode;
  storage?: string;
  fortress?: string;
  exitOnCompletion: boolean;
  help: boolean;
}

function isStorageTargetFlagParseError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.startsWith("--fortress requires ") ||
    message.startsWith("--fortress may ") ||
    message.startsWith("--storage requires ") ||
    message.startsWith("--storage may ")
  );
}

// ── Public entry ────────────────────────────────────────────────────

export async function runResetPassphraseCommand(
  args: ResetPassphraseArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin = args.stdin ?? (process.stdin as NodeJS.ReadableStream & { isTTY?: boolean });
  const home = args.home ?? homedir();
  const plat = args.platformOverride ?? process.platform;

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(args.argv);
  } catch (error) {
    if (isStorageTargetFlagParseError(error)) {
      err.write(`${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }
    throw error;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const storagePath =
    parsed.storage ??
    parsed.fortress ??
    args.storagePath ??
    resolveStoragePath(process.env, home);

  out.write(banner(storagePath));

  // Refuse-if-unlocked guard.
  const runtimeFile = join(storagePath, "runtime.json");
  if (await fileExists(runtimeFile)) {
    err.write(
      `Refusing to reset: ${runtimeFile} exists, indicating a Sanctuary process may be running.\n` +
        `Close the dashboard and stop all wrapped agents before running reset-passphrase.\n` +
        `If you have already stopped everything and the file is stale, remove it manually:\n` +
        `  rm ${runtimeFile}\n` +
        `Then re-run this command.\n`
    );
    return 1;
  }

  // Single readline interface shared across all prompts in this command run.
  // Tests pass a pre-loaded Readable; production hands process.stdin which
  // stays open for the duration of the command.
  const lines = new LineReader(stdin);
  let code: number;
  let nukeSucceeded = false;
  try {
    const availability = await surveyAvailableModes(storagePath);
    const mode = parsed.mode ?? (await selectMode(lines, out, err, availability));
    if (!mode) {
      err.write("Aborted: no recovery mode selected.\n");
      code = 1;
    } else if (mode === "shares") {
      code = await runSharesPath(out, err, availability);
    } else if (mode === "guardian") {
      code = await runGuardianPath(out, err, availability);
    } else {
      code = await runNukePath({
        out,
        err,
        lines,
        storagePath,
        home,
        plat,
        exec: args.exec ?? defaultExec,
      });
      nukeSucceeded = mode === "nuke" && code === 0;
    }
  } finally {
    // Zeroize any caller-supplied key-material buffers regardless of which
    // path we took or whether it succeeded. JS strings on the heap remain
    // immutable and cannot be cleared; callers MUST pass key material as
    // Buffer / Uint8Array on `keyMaterialToZeroize` for this hook to do
    // anything. Order matters: run AFTER the recovery path returns, BEFORE
    // the readline interface closes (so a buffer that was decrypted
    // mid-prompt and not yet consumed still gets zeroed on early abort),
    // and BEFORE any --exit-on-completion process.exit() so the heap is
    // wiped before the kernel reaps the address space.
    zeroizeBuffers(args.keyMaterialToZeroize);
    lines.close();
  }

  // --exit-on-completion: bound the heap-dump window for extreme threat
  // models. Only fires after a successful nuke; aborts and degraded-shares
  // / degraded-guardian returns leave the shell intact for re-run. The
  // `finally` block above has already zeroed any caller-supplied buffers;
  // process.exit reaps everything else.
  if (parsed.exitOnCompletion && nukeSucceeded) {
    const doExit = args.exitProcess ?? ((c: number) => process.exit(c));
    doExit(0);
  }
  return code;
}

// ── Argument parsing ────────────────────────────────────────────────

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { exitOnCompletion: false, help: false };
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/--storage value must refuse, never silently resolve the default fortress; wrong-fortress custody operations are a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) throw new Error(fortress.error);
  const storage = consumeFlagValue(fortress.argv, "--storage");
  if (storage.error !== undefined) throw new Error(storage.error);
  if (fortress.value !== undefined) out.fortress = fortress.value;
  if (storage.value !== undefined) out.storage = storage.value;

  for (let i = 0; i < storage.argv.length; i++) {
    const a = storage.argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
    } else if (a === "--mode" && storage.argv[i + 1]) {
      const v = storage.argv[++i] as RecoveryMode;
      if (v !== "shares" && v !== "guardian" && v !== "nuke") {
        throw new Error(
          `--mode must be one of: shares, guardian, nuke (got ${v})`
        );
      }
      out.mode = v;
    } else if (a === "--exit-on-completion") {
      out.exitOnCompletion = true;
    } else if (a && a.startsWith("--")) {
      throw new Error(`Unknown flag: ${a}`);
    }
  }
  return out;
}

function printUsage(out: NodeJS.WritableStream): void {
  out.write(`
Usage: sanctuary reset-passphrase [options]

Recover a fortress whose passphrase has been lost or corrupted. Three modes:

  shares     Reconstruct the master key from M-of-N recovery shares.
             Available only when shares were previously persisted to this
             fortress. Not yet configured by default in v1.0.x.

  guardian   Initiate a guardian-quorum recovery via the federation. Ships
             with v1.1 federation full mesh; not operational on a single
             unreachable local fortress today.

  nuke       Destroy the fortress entirely and re-initialize. ALL identities,
             broker tokens, audit log entries, and federation membership are
             permanently lost. Operator types the fortress name and the
             literal word DESTROY before the wipe runs. Use this only when
             paths (shares) and (guardian) are unavailable and you accept
             starting over.

Options:
  --mode <shares|guardian|nuke>   Pick a path non-interactively.
  --fortress <path>               Override the fortress storage path.
                                  Consistent with "sanctuary wrap --fortress".
  --storage <path>                Alias for --fortress.
  --exit-on-completion            After a successful nuke, call process.exit(0)
                                  immediately so the post-wipe heap is reaped
                                  by the OS without re-entering the shell. Use
                                  on extreme-threat-model deployments where an
                                  attacker-on-host with heap-dump access could
                                  recover residual passphrase or key bytes
                                  between the wipe and the next operator
                                  command. JS strings cannot be explicitly
                                  zeroed; this flag is the supported way to
                                  bound the heap-dump window.
  --help, -h                      Show this help.

Without --mode, the command surveys which paths are operationally available
on this fortress and presents an interactive menu.

Refuse-if-unlocked: this command refuses to run while runtime.json exists
under the storage path, since that signals a live Sanctuary process. Close
the dashboard and stop all wrapped agents first.

After a successful nuke, run:
  sanctuary wrap

to re-initialize a fresh fortress.
`);
}

// ── Mode survey ─────────────────────────────────────────────────────

async function surveyAvailableModes(
  storagePath: string
): Promise<ModeAvailability> {
  const sharesFile = join(storagePath, "recovery-shares.json");
  const guardianFile = join(storagePath, "guardian-roster.json");

  const sharesPresent = await fileExists(sharesFile);
  const guardianPresent = await fileExists(guardianFile);

  return {
    shares: {
      available: sharesPresent,
      reason: sharesPresent
        ? "recovery shares persisted on this fortress"
        : "not yet configured on this fortress (M-of-N share persistence ships with v1.1)",
    },
    guardian: {
      available: false,
      reason: guardianPresent
        ? "guardian roster present, but the guardian recovery transport ships with v1.1 federation full mesh"
        : "not-yet-supported: guardian path ships with federation v0.1 full mesh, expected v1.1; use shares (when configured) or nuke for now",
    },
    nuke: {
      available: true,
      reason: "destroys all state and re-initializes a fresh fortress",
    },
  };
}

// ── Mode selection (interactive) ────────────────────────────────────

async function selectMode(
  lines: LineReader,
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<RecoveryMode | undefined> {
  out.write(`
Pick a recovery path:

  1) shares    ${availability.shares.available ? "(available)" : "(unavailable)"}
     ${availability.shares.reason}

  2) guardian  ${availability.guardian.available ? "(available)" : "(unavailable)"}
     ${availability.guardian.reason}

  3) nuke      (available, DESTRUCTIVE)
     ${availability.nuke.reason}

`);
  const answer = await prompt(lines, err, "Choose 1, 2, or 3 (or q to abort): ");
  const trimmed = answer.trim().toLowerCase();
  if (trimmed === "1" || trimmed === "shares") return "shares";
  if (trimmed === "2" || trimmed === "guardian") return "guardian";
  if (trimmed === "3" || trimmed === "nuke") return "nuke";
  return undefined;
}

// ── Path (a) shares ─────────────────────────────────────────────────

async function runSharesPath(
  _out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<number> {
  if (!availability.shares.available) {
    err.write(
      `Recovery shares: ${availability.shares.reason}.\n` +
        `Falling through. Re-run with --mode guardian or --mode nuke to choose another path,\n` +
        `or omit --mode for the interactive menu.\n`
    );
    return 2;
  }
  // Reserved for v1.1 implementation. When share persistence lands, this
  // branch prompts for M shares, reconstructs the master, asks for the new
  // passphrase, derives a new Argon2id key via core/key-derivation, re-wraps,
  // and writes a passphrase_reset audit entry signed by the preserved
  // identity.
  err.write(
    "Recovery-share reconstruction is reserved for v1.1. The detection branch\n" +
      "is in place, but the reconstruction primitive has not yet shipped.\n"
  );
  return 2;
}

// ── Path (b) guardian ───────────────────────────────────────────────

async function runGuardianPath(
  _out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<number> {
  err.write(
    `Guardian recovery: ${availability.guardian.reason}.\n` +
      `The federation v0.1 \`guardian_recovery_request\` message class lands with v1.1\n` +
      `full-mesh transport. Use --mode shares (when configured) or --mode nuke today.\n`
  );
  return 2;
}

// ── Path (c) nuke ───────────────────────────────────────────────────

interface NukeContext {
  out: NodeJS.WritableStream;
  err: NodeJS.WritableStream;
  lines: LineReader;
  storagePath: string;
  home: string;
  plat: NodeJS.Platform;
  exec: (
    cmd: string,
    args: string[]
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
}

/**
 * Nuke-path memory-hygiene threat model
 * --------------------------------------
 *
 * Adversary: an attacker-on-host with the ability to capture a heap dump of
 * this Node.js process between the moment `wipeStorage()` returns and the
 * moment the process exits or is reaped. Such an adversary could potentially
 * recover residual passphrase or key bytes that lived in the V8 heap before
 * the wipe ran.
 *
 * Defenses in this path:
 *
 *   1. Buffers and Uint8Arrays holding key material are zeroed via
 *      `Buffer.fill(0)` / `Uint8Array.fill(0)` AFTER their last legitimate
 *      use and BEFORE this function returns. The current v1.x nuke flow
 *      holds NO such buffers itself: keychain entries are deleted via
 *      `security delete-generic-password` (which never reads the value),
 *      and the encrypted `passphrase.enc` file is removed by `wipeStorage`
 *      without being decrypted. The `zeroizeBuffers` helper at the bottom
 *      of this module is the structural hook for any future code path that
 *      DOES decrypt or fetch key material in the nuke flow.
 *
 *   2. JS strings (UTF-16 in V8) cannot be explicitly zeroed in user-space:
 *      they are immutable, GC-managed, and may be string-interned or copied
 *      by the runtime. Any passphrase that flows through this command as a
 *      `string` will linger on the heap until V8 reclaims its slot. Callers
 *      that require mem-hygiene MUST route key material through Buffer or
 *      Uint8Array (and put those on `args.keyMaterialToZeroize`) rather than
 *      as `string`.
 *
 *   3. The `--exit-on-completion` flag, when set, calls `process.exit(0)`
 *      immediately after the wipe summary prints. This is the supported
 *      mitigation for the string-immutability gap: the kernel reclaims the
 *      whole address space, so any residual heap bytes (string or otherwise)
 *      become unreachable to a heap-dump attacker who races the OS reaper.
 *      It is opt-in because operators on standard threat models prefer the
 *      shell to return normally so they can immediately run `sanctuary wrap`.
 *
 * Out of scope (longer-term hardening):
 *
 *   - WASM-backed zeroizer that mlock()s a page, holds key material there,
 *     and sodium_memzero()s on drop. Tracked for v1.x security hardening.
 *   - End-to-end heap-dump test that captures the process heap mid-flight
 *     and asserts no key material is present. Documented in PR body as
 *     verified by code review and unit test of the buffer-zero path; full
 *     heap-dump test deferred.
 */
async function runNukePath(ctx: NukeContext): Promise<number> {
  const fortressName = basename(ctx.storagePath) || "sanctuary";

  // 1. Enumerate what is about to die.
  const inventory = await inventoryStorage(ctx.storagePath);
  ctx.out.write(`
About to permanently destroy the fortress at:
  ${ctx.storagePath}

Contents (${inventory.entries.length} entries, ${formatBytes(inventory.totalBytes)} total):
`);
  for (const e of inventory.entries) {
    ctx.out.write(`  ${e.kind === "dir" ? "d" : "f"} ${e.name}  (${formatBytes(e.bytes)})\n`);
  }
  if (inventory.entries.length === 0) {
    ctx.out.write(`  (storage path is empty, nothing to destroy)\n`);
  }

  ctx.out.write(`
This action is IRREVERSIBLE. You will lose:
  - All wrapped agent identities (Ed25519 private keys)
  - All Secret Broker tokens and grants
  - The encrypted audit log and policy configuration
  - Federation membership and guardian roster
  - All L1 cognitive state, L3 commitments, L4 reputation attestations

If you have backups (state_export, identity export, recovery shares, guardian
quorum), use those instead. Closing this prompt with anything other than the
exact confirmations below aborts the wipe.

`);

  // 2. Type the fortress name.
  const nameAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Type the fortress name (${fortressName}) to continue: `
  );
  if (nameAnswer.trim() !== fortressName) {
    ctx.err.write(
      `Aborted: fortress name did not match (expected "${fortressName}", got "${nameAnswer.trim()}").\n`
    );
    return 1;
  }

  // 3. Type the literal word DESTROY.
  const destroyAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Type the word DESTROY (uppercase) to continue: `
  );
  if (destroyAnswer.trim() !== "DESTROY") {
    ctx.err.write(`Aborted: confirmation word did not match.\n`);
    return 1;
  }

  // 4. Final yes/no.
  const finalAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Final confirmation. Wipe ${ctx.storagePath} now? [y/N] `
  );
  if (!/^y(es)?$/i.test(finalAnswer.trim())) {
    ctx.err.write(`Aborted: final confirmation declined.\n`);
    return 1;
  }

  // 5. Perform the wipe.
  const startedAt = new Date().toISOString();
  await wipeStorage(ctx.storagePath);

  // 6. Clear the macOS Keychain entry for this storage path so a fresh
  //    `sanctuary wrap` regenerates a fresh passphrase rather than picking
  //    up the orphaned entry.
  let keychainCleared = false;
  if (ctx.plat === "darwin") {
    keychainCleared = await clearKeychainEntry(ctx);
  }

  // 7. Write a plaintext reset marker so a future fortress at the same
  //    storage path can show this history on first boot. Audit-log
  //    continuity is impossible by definition (the audit log was just
  //    destroyed), so this marker is the best-effort substitute.
  const completedAt = new Date().toISOString();
  await writeResetMarker(ctx.storagePath, {
    started_at: startedAt,
    completed_at: completedAt,
    recovery_mode: "nuke",
    fortress_name: fortressName,
    storage_path: ctx.storagePath,
    keychain_cleared: keychainCleared,
  });

  ctx.out.write(`
Reset complete.
  recovery_mode: nuke
  started_at:    ${startedAt}
  completed_at:  ${completedAt}
  storage_path:  ${ctx.storagePath}
  keychain:      ${ctx.plat === "darwin" ? (keychainCleared ? "cleared" : "no entry to clear") : "skipped (non-darwin)"}

Reset marker: ${join(ctx.storagePath, ".reset-history.log")}
Next step:    sanctuary wrap
`);
  return 0;
}

// ── Storage helpers ─────────────────────────────────────────────────

interface InventoryEntry {
  name: string;
  kind: "file" | "dir";
  bytes: number;
}

interface Inventory {
  entries: InventoryEntry[];
  totalBytes: number;
}

async function inventoryStorage(storagePath: string): Promise<Inventory> {
  if (!(await fileExists(storagePath))) {
    return { entries: [], totalBytes: 0 };
  }
  const names = await readdir(storagePath);
  const entries: InventoryEntry[] = [];
  let totalBytes = 0;
  for (const name of names) {
    const full = join(storagePath, name);
    try {
      const s = await stat(full);
      const bytes = s.isDirectory() ? await dirSize(full) : s.size;
      entries.push({
        name,
        kind: s.isDirectory() ? "dir" : "file",
        bytes,
      });
      totalBytes += bytes;
    } catch {
      // Permission denied or vanished mid-scan; skip.
    }
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  return { entries, totalBytes };
}

async function dirSize(path: string): Promise<number> {
  let total = 0;
  try {
    const names = await readdir(path);
    for (const name of names) {
      const full = join(path, name);
      try {
        const s = await stat(full);
        total += s.isDirectory() ? await dirSize(full) : s.size;
      } catch {
        // Skip unreadable.
      }
    }
  } catch {
    // Skip unreadable directory.
  }
  return total;
}

async function wipeStorage(storagePath: string): Promise<void> {
  if (!(await fileExists(storagePath))) return;
  const names = await readdir(storagePath);
  for (const name of names) {
    if (name === ".reset-history.log") {
      // Preserve any prior reset history across iterative resets.
      continue;
    }
    await rm(join(storagePath, name), { recursive: true, force: true });
  }
}

async function clearKeychainEntry(ctx: NukeContext): Promise<boolean> {
  const service = keychainServiceFor(ctx.storagePath, ctx.home);
  try {
    const result = await ctx.exec("security", [
      "delete-generic-password",
      "-a",
      "sanctuary",
      "-s",
      service,
    ]);
    return result.code === 0;
  } catch {
    return false;
  }
}

interface ResetMarker {
  started_at: string;
  completed_at: string;
  recovery_mode: RecoveryMode;
  fortress_name: string;
  storage_path: string;
  keychain_cleared: boolean;
}

async function writeResetMarker(
  storagePath: string,
  marker: ResetMarker
): Promise<void> {
  const path = join(storagePath, ".reset-history.log");
  const line = JSON.stringify(marker) + "\n";
  if (await fileExists(path)) {
    await appendFile(path, line, { mode: 0o600 });
  } else {
    await writeFile(path, line, { mode: 0o600 });
  }
}

// ── Misc helpers ────────────────────────────────────────────────────

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function banner(storagePath: string): string {
  return `
Sanctuary reset-passphrase
Storage: ${storagePath}

`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

async function prompt(
  lines: LineReader,
  err: NodeJS.WritableStream,
  question: string
): Promise<string> {
  err.write(question);
  return await lines.next();
}

/**
 * Single-readline-interface-per-command wrapper. Buffers `line` events and
 * serves them on demand so multiple `prompt()` calls in the same command can
 * share one underlying interface (a fresh readline.Interface per prompt
 * stops working when the source stdin is a one-shot Readable, like the test
 * harness uses).
 */
class LineReader {
  private readonly rl: ReadlineInterface;
  private readonly queue: string[] = [];
  private readonly waiters: Array<(line: string) => void> = [];
  private closed = false;

  constructor(stdin: NodeJS.ReadableStream) {
    this.rl = createInterface({ input: stdin });
    this.rl.on("line", (line) => {
      const w = this.waiters.shift();
      if (w) {
        w(line);
      } else {
        this.queue.push(line);
      }
    });
    this.rl.on("close", () => {
      this.closed = true;
      while (this.waiters.length > 0) {
        const w = this.waiters.shift();
        if (w) w("");
      }
    });
  }

  next(): Promise<string> {
    if (this.queue.length > 0) {
      return Promise.resolve(this.queue.shift() as string);
    }
    if (this.closed) return Promise.resolve("");
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.rl.close();
    } catch {
      // Already closed.
    }
  }
}

/**
 * Zero each Buffer / Uint8Array in `buffers`. Safe on `undefined`, an empty
 * list, and individual `undefined` entries: callers can pass a sparse list
 * without checking. Errors during `.fill(0)` (e.g., a detached / shared
 * buffer view) are swallowed: best-effort hygiene must not throw and abort
 * a command's `finally` cleanup. See the `runNukePath` threat-model block
 * for the full motivation and limitations (V8 string immutability is out
 * of reach of this helper).
 *
 * Exported so tests can verify the zeroize semantics directly without
 * driving a full nuke flow.
 */
export function zeroizeBuffers(
  buffers: ReadonlyArray<Buffer | Uint8Array | undefined> | undefined
): void {
  if (!buffers) return;
  for (const b of buffers) {
    if (!b) continue;
    try {
      b.fill(0);
    } catch {
      // Detached / shared / read-only view; best-effort.
    }
  }
}

/**
 * Default credential-CLI runner. Routed through the single chokepoint
 * (`wrap/keychain-exec`) rather than spawning `security` here: this module is
 * the FOURTH call site, and the chokepoint exists precisely because per-site
 * spawns are whack-a-mole. Under test the chokepoint refuses the real binary,
 * so a reset path can never delete from the operator's real login keychain.
 */
async function defaultExec(
  cmd: string,
  args: string[]
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  const result = await execKeychain(cmd, args);
  return { stdout: result.stdout, stderr: result.stderr, code: result.code };
}
