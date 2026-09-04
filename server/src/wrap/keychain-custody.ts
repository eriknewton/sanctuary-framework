/**
 * Sanctuary wrap - OS-keyring-held custody key (second factor)
 *
 * A random 32-byte key stored in the OS keyring (macOS Keychain / Linux
 * Secret Service) that wraps the fortress master alongside the user-held
 * recovery key. Machine-resident but user-visible (Keychain Access /
 * Seahorse) and OS-managed; it is only ever a *second* factor - never the
 * sole custody of a trust-bearing fortress.
 *
 * Deliberately NO fallback file: a machine-bound file secret the user never
 * sees is the F3 lockout generator this build removes. When no OS keyring
 * is available this module returns null and the caller enrolls a different
 * second factor (or records an explicit degraded install mode).
 *
 * RATIFIED POSTURE (2026-07-22, docs/custody-recovery-posture.md): this
 * machine-resident factor may UNLOCK the master for daily use but must never
 * BOOTSTRAP new human-held custody. No verb enrolls a new passphrase, mints a
 * recovery key, or rotates the master from a keychain-only unlock — the OS
 * keyring releases this key to any process in the logged-in session, so such
 * a verb would let anyone at an unlocked machine silently take over custody.
 * Custody-changing ceremonies require a human-held credential (passphrase or
 * recovery key). The absence of that verb is the security property; do not
 * "fix" it without superseding the posture doc.
 */

import { realpathSync } from "node:fs";
import { homedir, platform } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha256";

import { generateRandomKey } from "../core/random.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import type { RotationRecoveryEscrowAuthority } from "../core/master-rotation.js";
import { DEFAULT_STORAGE_DIR } from "../paths.js";
import type { ExecResult } from "./exec-result.js";
import { execKeychain } from "./keychain-exec.js";

const CUSTODY_ACCOUNT = "sanctuary";
const CUSTODY_SERVICE_PREFIX = "sanctuary-custody";
const CUSTODY_LABEL = "Sanctuary Custody Key";
const RECOVERY_SERVICE_PREFIX = "sanctuary-recovery";
const RECOVERY_LABEL = "Sanctuary Recovery Key";

export interface KeychainCustodyOptions {
  /** Override home directory (for tests). */
  home?: string;
  /** Override platform detection (for tests). */
  platformOverride?: NodeJS.Platform;
  /** Command executor (tests inject a mock). */
  exec?: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  /** Test only: retain secret-buffer references to prove zeroization. */
  __testObserveSecretBuffer?: (
    label:
      | "generated-custody-key"
      | "custody-key-readback"
      | "custody-probe-key"
      | "recovery-probe-key"
      | "decoded-recovery-key"
      | "recovery-key-readback",
    buffer: Uint8Array,
  ) => void;
}

export class RecoveryKeyKeychainStoreError extends Error {
  readonly service: string;

  constructor(service: string) {
    super(
      `Recovery key could not be stored in OS keyring service '${service}'; refusing to continue.`
    );
    this.name = "RecoveryKeyKeychainStoreError";
    this.service = service;
  }
}

function serviceForStoragePath(
  prefix: string,
  storagePath: string,
  home: string,
  canonicalize: (path: string) => string = resolve,
): string {
  const defaultPath = canonicalize(join(home, DEFAULT_STORAGE_DIR));
  const canonicalStorage = canonicalize(storagePath);
  if (canonicalStorage === defaultPath) return prefix;
  const digest = sha256(Buffer.from(canonicalStorage, "utf-8"));
  const suffix = Buffer.from(digest).toString("hex").slice(0, 16);
  return `${prefix}-${suffix}`;
}

/**
 * Resolve the deepest existing ancestor so one physical fortress has one
 * custody/recovery keyring identity even when reached through a symlink alias.
 * Only ENOENT is recoverable; every indeterminate identity failure propagates
 * fail-closed instead of silently splitting custody.
 */
function canonicalCredentialStoragePath(storagePath: string): string {
  const absolute = resolve(storagePath);
  const suffix: string[] = [];
  let cursor = absolute;
  while (true) {
    try {
      return join(realpathSync(cursor), ...suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = dirname(cursor);
      if (parent === cursor) throw error;
      suffix.unshift(basename(cursor));
      cursor = parent;
    }
  }
}

/**
 * Keyring service name for the fortress's custody key. Same canonical-path
 * hashing scheme as the passphrase service (stable across cosmetic path
 * differences), distinct prefix so the custody key and the passphrase are
 * separate keyring items.
 */
export function custodyServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  return serviceForStoragePath(CUSTODY_SERVICE_PREFIX, storagePath, home);
}

/** Canonical write identity for the machine-local custody factor. */
export function canonicalCustodyServiceFor(
  storagePath: string,
  home: string = homedir(),
): string {
  return serviceForStoragePath(
    CUSTODY_SERVICE_PREFIX,
    storagePath,
    home,
    canonicalCredentialStoragePath,
  );
}

/**
 * Keyring service name for the fortress recovery key. Same canonical-path
 * hashing as passphrase and custody services, but with a separate prefix so
 * the recovery key is a distinct OS-keyring item.
 */
export function recoveryKeyServiceFor(
  storagePath: string,
  home: string = homedir()
): string {
  return serviceForStoragePath(RECOVERY_SERVICE_PREFIX, storagePath, home);
}

/** Canonical write identity for the machine-local recovery escrow. */
export function canonicalRecoveryKeyServiceFor(
  storagePath: string,
  home: string = homedir(),
): string {
  return serviceForStoragePath(
    RECOVERY_SERVICE_PREFIX,
    storagePath,
    home,
    canonicalCredentialStoragePath,
  );
}

/**
 * Complete read/delete compatibility registry for custody and recovery items.
 * New writes use the canonical realpath identity; the lexical identity remains
 * readable/removable for installations created before canonicalization.
 */
export function fortressCustodyCredentialServices(
  storagePath: string,
  home: string = homedir(),
): string[] {
  const ordered = [
    canonicalCustodyServiceFor(storagePath, home),
    custodyServiceFor(storagePath, home),
    canonicalRecoveryKeyServiceFor(storagePath, home),
    recoveryKeyServiceFor(storagePath, home),
  ];
  return ordered.filter((name, index) => ordered.indexOf(name) === index);
}

function custodyReadServices(storagePath: string, home: string): string[] {
  return [
    canonicalCustodyServiceFor(storagePath, home),
    custodyServiceFor(storagePath, home),
  ].filter((name, index, all) => all.indexOf(name) === index);
}

function recoveryReadServices(storagePath: string, home: string): string[] {
  return [
    canonicalRecoveryKeyServiceFor(storagePath, home),
    recoveryKeyServiceFor(storagePath, home),
  ].filter((name, index, all) => all.indexOf(name) === index);
}

function escapeForSecurity(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Why a keyring read produced no key. The boot diagnostic (element 2/3) needs
 * to tell "the keyring item is genuinely absent" apart from "the keyring is
 * present but this process cannot reach it". Collapsing both to `null`
 * (the old behavior) silently dropped the keychain factor with zero signal,
 * which is exactly how the headless/SSH lockout surfaced (the macOS login
 * Keychain returns error 36 / errSecInteractionNotAllowed over SSH).
 *
 *  - "found":        a valid 32-byte key was returned.
 *  - "not-found":    the keyring is reachable and reports no such item.
 *  - "unreachable":  the keyring exists but could not be queried in this
 *                    session (macOS error 36 / errSecInteractionNotAllowed,
 *                    a locked keychain, no GUI / no D-Bus session bus, or the
 *                    keyring binary missing). The item MAY exist; we cannot say.
 */
export type KeychainReadStatus = "found" | "not-found" | "unreachable";

export interface KeychainReadResult {
  status: KeychainReadStatus;
  /** Present only when status === "found". */
  key?: Uint8Array;
  /** Non-secret reason string for the boot diagnostic (never key material). */
  detail?: string;
}

/**
 * macOS `security` exit code for errSecInteractionNotAllowed. The CLI maps the
 * Security.framework status -25308 to exit code 36 (the classic "user
 * interaction is not allowed" / locked-keychain-over-SSH signal). We treat
 * this (and the textual marker, in case a future CLI changes the numeric code)
 * as "unreachable", not "not-found".
 */
const SECURITY_INTERACTION_NOT_ALLOWED_CODE = 36;
const SECURITY_INTERACTION_NOT_ALLOWED_MARKERS = [
  "interaction is not allowed",
  "interactionnotallowed",
  "-25308",
  "25308",
];

/** macOS `security` exit code for errSecItemNotFound (status -25300). */
const SECURITY_ITEM_NOT_FOUND_CODE = 44;

/**
 * Classify a non-zero macOS `security` outcome into found / not-found /
 * unreachable. Exported so the wrap passphrase path (passphrase.ts) reuses
 * the SAME error-36 / errSecInteractionNotAllowed detection rather than
 * re-implementing it (the fortress-key-root-cause-2026-06-23 class: a locked
 * login keychain over SSH must read as "unreachable", never "not-found").
 */
export function classifyDarwinFailure(result: ExecResult): KeychainReadResult {
  const stderr = (result.stderr ?? "").toLowerCase();
  const interactionBlocked =
    result.code === SECURITY_INTERACTION_NOT_ALLOWED_CODE ||
    SECURITY_INTERACTION_NOT_ALLOWED_MARKERS.some((m) => stderr.includes(m));
  if (interactionBlocked) {
    return {
      status: "unreachable",
      detail:
        "macOS Keychain is locked or unreachable in this session " +
        "(error 36 / interaction not allowed), typical over SSH / headless",
    };
  }
  if (result.code === SECURITY_ITEM_NOT_FOUND_CODE) {
    return { status: "not-found", detail: "no such keychain item" };
  }
  // Any other non-zero exit: be conservative and treat as unreachable so the
  // factor is never silently dropped as "absent" when it may exist.
  return {
    status: "unreachable",
    detail: `keychain query failed (security exit ${result.code ?? "unknown"})`,
  };
}

/**
 * Classify a non-zero Linux `secret-tool` outcome into not-found vs
 * unreachable. Exported so the wrap passphrase path (passphrase.ts) reuses
 * the SAME D-Bus/locked-collection detection rather than re-implementing it.
 */
export function classifyLinuxFailure(result: ExecResult): KeychainReadResult {
  // secret-tool exits 1 with empty stdout for BOTH "no such item" and a
  // refused/locked Secret Service. Distinguish by stderr: a D-Bus / collection
  // error means the keyring is unreachable; a clean empty result means the
  // item is simply absent.
  const stderr = (result.stderr ?? "").toLowerCase();
  const reachableButAbsent =
    stderr.length === 0 ||
    stderr.includes("no such") ||
    stderr.includes("not found");
  if (reachableButAbsent) {
    return { status: "not-found", detail: "no such secret-service item" };
  }
  return {
    status: "unreachable",
    detail:
      "Linux Secret Service is locked or unreachable in this session " +
      "(no D-Bus session bus, locked collection, or refused connection)",
  };
}

/**
 * Read a keyring item by service, classifying the outcome (element 3).
 * Never throws on a keyring failure: a spawn error (binary missing, no
 * keyring at all) is "unreachable", same as a locked keychain, so the caller
 * always falls through to explicit env factors rather than treating the
 * keyring as authoritatively empty. A `found` result transfers ownership of
 * `key` to the caller, which must scrub it after use.
 */
async function readKeyClassified(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string
): Promise<KeychainReadResult> {
  let result: ExecResult;
  try {
    if (plat === "darwin") {
      result = await exec("security", [
        "find-generic-password",
        "-a",
        CUSTODY_ACCOUNT,
        "-s",
        service,
        "-w",
      ]);
    } else if (plat === "linux") {
      result = await exec("secret-tool", [
        "lookup",
        "service",
        service,
        "account",
        CUSTODY_ACCOUNT,
      ]);
    } else {
      return {
        status: "unreachable",
        detail: "no supported OS keyring on this platform",
      };
    }
  } catch {
    // Spawn failed (binary missing / ENOENT): the keyring is not usable here.
    return {
      status: "unreachable",
      detail:
        plat === "linux"
          ? "secret-tool not installed (no Secret Service access)"
          : "OS keyring binary unavailable",
    };
  }

  if (result.code === 0) {
    const value = result.stdout.replace(/\r?\n$/, "").trim();
    if (value.length === 0) {
      return { status: "not-found", detail: "keychain item empty" };
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64url(value);
    } catch {
      // A present-but-malformed value is a real item that is corrupt; treat as
      // unreachable (the operator should investigate) rather than "not-found".
      return { status: "unreachable", detail: "keychain item is malformed" };
    }
    // 32 = the 256-bit width of every key this reader classifies. It is
    // generic over the two keyring items (the custody key read by
    // `readKeychainCustodyKey` and the recovery key probed by
    // `probeKeychainRecoveryKey`), so it names neither; both are consumed at
    // that width in `core/master-custody.ts`.
    if (bytes.length !== 32) {
      bytes.fill(0);
      return { status: "unreachable", detail: "keychain item has wrong length" };
    }
    return { status: "found", key: bytes };
  }

  return plat === "darwin"
    ? classifyDarwinFailure(result)
    : classifyLinuxFailure(result);
}

/**
 * Read-and-classify a keyring item by service, for the boot diagnostic and
 * orphan detection. Public so the boot paths can probe a factor's reachability
 * without resolving the master.
 */
export async function readKeychainKeyStatus(
  service: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult> {
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  return readKeyClassified(exec, plat, service);
}

/**
 * Read a keyring item by service, returning the key bytes or null. Thin
 * compatibility wrapper over {@link readKeyClassified}: callers that only need
 * the key (not the reachability reason) keep the original null-on-miss shape,
 * but error-36 / locked / not-installed all still return null here exactly as
 * before; they just no longer LOSE the distinction, because the classifying
 * read is available separately.
 */
async function readKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string
): Promise<Uint8Array | null> {
  const result = await readKeyClassified(exec, plat, service);
  return result.status === "found" ? (result.key ?? null) : null;
}

async function readKeyFamilyClassified(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  services: readonly string[],
): Promise<KeychainReadResult & { service: string }> {
  let unreachable: (KeychainReadResult & { service: string }) | undefined;
  for (const service of services) {
    const result = await readKeyClassified(exec, plat, service);
    if (result.status === "found") return { ...result, service };
    if (result.status === "unreachable" && unreachable === undefined) {
      unreachable = { ...result, service };
    }
  }
  return unreachable ?? {
    status: "not-found",
    service: services[0] ?? "unknown",
    detail: "no compatible keychain item",
  };
}

/**
 * Read the custody-key family without creating or promoting an item. A found
 * result transfers `key` ownership to the caller; all presence-only callers
 * must use {@link probeKeychainCustodyKey}, which scrubs internally.
 */
export async function readKeychainCustodyKeyStatus(
  storagePath: string,
  opts: KeychainCustodyOptions = {},
): Promise<KeychainReadResult & { service: string }> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  return readKeyFamilyClassified(exec, plat, custodyReadServices(storagePath, home));
}

async function writeKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string,
  value: string,
  label: string
): Promise<boolean> {
  if (/[\r\n]/.test(value)) return false;
  try {
    if (plat === "darwin") {
      // Secret via `security -i` batch script on stdin, never argv (F5).
      const batch =
        `add-generic-password -U -a "${escapeForSecurity(CUSTODY_ACCOUNT)}" ` +
        `-s "${escapeForSecurity(service)}" -w "${escapeForSecurity(value)}"\n`;
      const result = await exec("security", ["-i"], batch);
      return result.code === 0;
    }
    if (plat === "linux") {
      const result = await exec(
        "secret-tool",
        [
          "store",
          "--label",
          label,
          "service",
          service,
          "account",
          CUSTODY_ACCOUNT,
        ],
        value + "\n"
      );
      return result.code === 0;
    }
    return false;
  } catch {
    return false;
  }
}

async function deleteKey(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string,
): Promise<boolean> {
  try {
    const result = plat === "darwin"
      ? await exec("security", [
          "delete-generic-password",
          "-a",
          CUSTODY_ACCOUNT,
          "-s",
          service,
        ])
      : plat === "linux"
        ? await exec("secret-tool", [
            "clear",
            "service",
            service,
            "account",
            CUSTODY_ACCOUNT,
          ])
        : { stdout: "", stderr: "unsupported", code: 1 };
    if (result.code === 0) return true;
    const classified = plat === "darwin"
      ? classifyDarwinFailure(result)
      : classifyLinuxFailure(result);
    return classified.status === "not-found";
  } catch {
    return false;
  }
}

export interface KeychainMutation<T> {
  value: T;
  service: string;
  rollback(): Promise<void>;
  commit(): void;
}

export interface RecoveryKeyRotationMutation {
  captured: true;
  authority: RotationRecoveryEscrowAuthority;
  service: string;
  stagingService: string;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}

async function restoreKeychainSnapshot(
  exec: NonNullable<KeychainCustodyOptions["exec"]>,
  plat: NodeJS.Platform,
  service: string,
  label: string,
  prior: KeychainReadResult,
): Promise<void> {
  if (prior.status === "found" && prior.key) {
    const encoded = toBase64url(prior.key);
    if (!(await writeKey(exec, plat, service, encoded, label))) {
      throw new Error(`could not restore prior OS keyring service '${service}'`);
    }
    const restored = await readKeyClassified(exec, plat, service);
    try {
      if (restored.status !== "found" || !restored.key ||
          !buffersEqual(restored.key, prior.key)) {
        throw new Error(`restored OS keyring service '${service}' did not verify`);
      }
    } finally {
      restored.key?.fill(0);
    }
    return;
  }
  if (!(await deleteKey(exec, plat, service))) {
    throw new Error(`could not delete new OS keyring service '${service}'`);
  }
  const absent = await readKeyClassified(exec, plat, service);
  absent.key?.fill(0);
  if (absent.status !== "not-found") {
    throw new Error(`new OS keyring service '${service}' survived rollback`);
  }
}

async function verifiedKeychainMutation(
  service: string,
  value: string,
  label: string,
  opts: KeychainCustodyOptions,
  readbackLabel?: "custody-key-readback" | "recovery-key-readback",
  requireAbsent = false,
): Promise<KeychainMutation<undefined>> {
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const prior = await readKeyClassified(exec, plat, service);
  if (prior.status === "unreachable") {
    throw new Error(`OS keyring service '${service}' is unreachable`);
  }
  if (requireAbsent && prior.status === "found") {
    prior.key?.fill(0);
    throw new Error(
      `OS keyring service '${service}' already contains recovery material; refusing to retain or overwrite it across the attended confirmation`,
    );
  }
  if (!(await writeKey(exec, plat, service, value, label))) {
    try {
      await restoreKeychainSnapshot(exec, plat, service, label, prior);
    } finally {
      prior.key?.fill(0);
    }
    throw new Error(`OS keyring service '${service}' refused the write`);
  }
  const confirmed = await readKeyClassified(exec, plat, service);
  if (confirmed.status !== "found") {
    try {
      await restoreKeychainSnapshot(exec, plat, service, label, prior);
    } finally {
      prior.key?.fill(0);
    }
    throw new Error(`OS keyring service '${service}' did not return the written value`);
  }
  let expected: Uint8Array | undefined;
  try {
    if (readbackLabel && confirmed.key) {
      opts.__testObserveSecretBuffer?.(readbackLabel, confirmed.key);
    }
    expected = fromBase64url(value);
    if (!buffersEqual(confirmed.key!, expected)) {
      throw new Error(`OS keyring service '${service}' returned a mismatched value`);
    }
  } catch (error) {
    try {
      await restoreKeychainSnapshot(exec, plat, service, label, prior);
    } finally {
      prior.key?.fill(0);
    }
    throw error;
  } finally {
    expected?.fill(0);
    confirmed.key?.fill(0);
  }
  let completed = false;
  const finish = (): void => {
    if (completed) return;
    completed = true;
    prior.key?.fill(0);
  };
  return {
    value: undefined,
    service,
    commit: finish,
    rollback: async () => {
      if (completed) return;
      try {
        await restoreKeychainSnapshot(exec, plat, service, label, prior);
      } finally {
        finish();
      }
    },
  };
}

/**
 * Read the fortress's keyring custody key, creating it if absent. Returns
 * null when no OS keyring is usable (no fallback file by design - F3).
 * Creation is read-back-verified so a keyring that accepts the write but
 * cannot return it never counts as an enrolled factor. A non-null return
 * transfers the sole live buffer to the caller, which must scrub it.
 */
export async function getOrCreateKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<Uint8Array | null> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalCustodyServiceFor(storagePath, home);

  const existing = await readKeyFamilyClassified(
    exec,
    plat,
    custodyReadServices(storagePath, home),
  );
  if (existing.status === "found") return existing.key ?? null;
  if (existing.status === "unreachable") return null;

  const key = generateRandomKey();
  let transferred = false;
  try {
    opts.__testObserveSecretBuffer?.("generated-custody-key", key);
    const encoded = toBase64url(key);
    const wrote = await writeKey(exec, plat, service, encoded, CUSTODY_LABEL);
    if (!wrote) return null;

    const readBack = await readKey(exec, plat, service);
    if (!readBack) return null;
    try {
      opts.__testObserveSecretBuffer?.("custody-key-readback", readBack);
      if (!buffersEqual(readBack, key)) return null;
    } finally {
      // The generated key is the only buffer transferred to the caller. The
      // separately decoded verification copy is never returned and is scrubbed
      // on match, mismatch, observer failure, and every other exit.
      readBack.fill(0);
    }
    transferred = true;
    return key;
  } finally {
    // Until the successful return above transfers ownership, this helper owns
    // the generated key and must erase it after write/read-back failure.
    if (!transferred) key.fill(0);
  }
}

export async function getOrCreateKeychainCustodyKeyTransactional(
  storagePath: string,
  opts: KeychainCustodyOptions = {},
): Promise<KeychainMutation<Uint8Array> | null> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalCustodyServiceFor(storagePath, home);
  const existing = await readKeyFamilyClassified(
    exec,
    plat,
    custodyReadServices(storagePath, home),
  );
  if (existing.status === "found" && existing.key) {
    return {
      value: existing.key,
      service: existing.service,
      rollback: async () => undefined,
      commit: () => undefined,
    };
  }
  if (existing.status === "unreachable") return null;

  const key = generateRandomKey();
  try {
    opts.__testObserveSecretBuffer?.("generated-custody-key", key);
    const mutation = await verifiedKeychainMutation(
      service,
      toBase64url(key),
      CUSTODY_LABEL,
      opts,
      "custody-key-readback",
    );
    return {
      value: key,
      service,
      rollback: mutation.rollback,
      commit: mutation.commit,
    };
  } catch (error) {
    key.fill(0);
    throw error;
  }
}

/** Read-only variant for unlock paths. */
export async function readKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<Uint8Array | null> {
  const result = await readKeychainCustodyKeyStatus(storagePath, opts);
  return result.status === "found" ? (result.key ?? null) : null;
}

/**
 * Classify the keychain CUSTODY-KEY item for a fortress (the second factor
 * that wraps the master). Feeds the boot diagnostic (element 2) and orphan
 * detection (element 5): "found" / "not-found" / "unreachable", with the
 * service name so the operator can locate / unlock it.
 */
export async function probeKeychainCustodyKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult & { service: string }> {
  const result = await readKeychainCustodyKeyStatus(storagePath, opts);
  const safe: KeychainReadResult & { service: string } = {
    status: result.status,
    service: result.service,
  };
  if (result.detail !== undefined) safe.detail = result.detail;
  try {
    // Presence diagnostics never own or expose custody material. The observer
    // is adversarial in tests: even if it throws, the decoded factor is erased.
    if (result.key) opts.__testObserveSecretBuffer?.("custody-probe-key", result.key);
    return safe;
  } finally {
    result.key?.fill(0);
  }
}

/**
 * Classify the keychain RECOVERY-KEY escrow item for a fortress (the
 * convenient machine-local copy of the user-held recovery key that #661
 * escrows). Feeds orphan detection (element 5): if a fortress was provisioned
 * with a keychain recovery escrow and that item is now "not-found", the only
 * recovery copy may have been deleted; warn before lockout.
 */
export async function probeKeychainRecoveryKey(
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<KeychainReadResult & { service: string }> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const result = await readKeyFamilyClassified(
    exec,
    plat,
    recoveryReadServices(storagePath, home),
  );
  const safe: KeychainReadResult & { service: string } = {
    status: result.status,
    service: result.service,
  };
  if (result.detail !== undefined) safe.detail = result.detail;
  try {
    // Zero the recovered key immediately: orphan detection only needs presence,
    // never the secret itself, including when an injected observer throws.
    if (result.key) opts.__testObserveSecretBuffer?.("recovery-probe-key", result.key);
    return safe;
  } finally {
    result.key?.fill(0);
  }
}

/**
 * Store the user fortress recovery key in the OS keyring and verify it by
 * reading it back. This is the convenient, machine-local store for the same
 * already-minted recovery key that is disclosed once to the operator. It is
 * never a wrap derivation change, and failure is fail-closed.
 */
export async function storeRecoveryKeyInKeychain(
  storagePath: string,
  recoveryKey: string,
  opts: KeychainCustodyOptions = {}
): Promise<{ service: string }> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalRecoveryKeyServiceFor(storagePath, home);
  let recoveryKeyBytes: Uint8Array;

  try {
    recoveryKeyBytes = fromBase64url(recoveryKey);
  } catch {
    throw new RecoveryKeyKeychainStoreError(service);
  }

  try {
    opts.__testObserveSecretBuffer?.("decoded-recovery-key", recoveryKeyBytes);
    // 32 = the 256-bit recovery key. Same minted value the operator is shown
    // once (see this function's doc comment), so the width must match
    // `decodeRecoveryKey` in `core/master-custody.ts`, which accepts it.
    if (recoveryKeyBytes.length !== 32) {
      throw new RecoveryKeyKeychainStoreError(service);
    }
    const wrote = await writeKey(
      exec,
      plat,
      service,
      recoveryKey,
      RECOVERY_LABEL
    );
    if (!wrote) throw new RecoveryKeyKeychainStoreError(service);

    const readBack = await readKey(exec, plat, service);
    if (!readBack) throw new RecoveryKeyKeychainStoreError(service);
    try {
      opts.__testObserveSecretBuffer?.("recovery-key-readback", readBack);
      if (!buffersEqual(readBack, recoveryKeyBytes)) {
        throw new RecoveryKeyKeychainStoreError(service);
      }
    } finally {
      readBack.fill(0);
    }
    return { service };
  } finally {
    recoveryKeyBytes.fill(0);
  }
}

export async function storeRecoveryKeyInKeychainTransactional(
  storagePath: string,
  recoveryKey: string,
  opts: KeychainCustodyOptions = {},
): Promise<KeychainMutation<undefined>> {
  const home = opts.home ?? homedir();
  const service = canonicalRecoveryKeyServiceFor(storagePath, home);
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(recoveryKey);
  } catch {
    throw new RecoveryKeyKeychainStoreError(service);
  }
  try {
    opts.__testObserveSecretBuffer?.("decoded-recovery-key", decoded);
    if (decoded.length !== 32) throw new RecoveryKeyKeychainStoreError(service);
    try {
      return await verifiedKeychainMutation(
        service,
        recoveryKey,
        RECOVERY_LABEL,
        opts,
        "recovery-key-readback",
        true,
      );
    } catch {
      throw new RecoveryKeyKeychainStoreError(service);
    }
  } finally {
    decoded.fill(0);
  }
}

/**
 * Stage a rotated recovery key under a distinct deterministic service. The
 * canonical service is not touched until commit, so re-entry refusal, preflight
 * failure, or process death before the rotation's commit boundary preserves the
 * previously valid machine escrow byte-for-byte.
 */
export async function stageRecoveryKeyRotationInKeychain(
  storagePath: string,
  recoveryKey: string,
  rotationId: string,
  opts: KeychainCustodyOptions = {},
  registerPendingAuthority?: (
    authority: RotationRecoveryEscrowAuthority,
  ) => Promise<void>,
): Promise<RecoveryKeyRotationMutation> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalRecoveryKeyServiceFor(storagePath, home);
  const stagingService = `${service}:rotation:${rotationId}`;
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(recoveryKey);
  } catch {
    throw new RecoveryKeyKeychainStoreError(service);
  }
  try {
    if (decoded.length !== 32) throw new RecoveryKeyKeychainStoreError(service);
    const authority: RotationRecoveryEscrowAuthority = {
      kind: "os-keyring",
      canonical_service: service,
      staging_service: stagingService,
    };
    const existing = await readKeyClassified(exec, plat, stagingService);
    try {
      if (existing.status === "unreachable") {
        throw new RecoveryKeyKeychainStoreError(service);
      }
      if (existing.status === "found") {
        throw new Error(
          `OS keyring service '${stagingService}' already exists without an authenticated pending rotation record`,
        );
      }
    } finally {
      existing.key?.fill(0);
    }
    await registerPendingAuthority?.(authority);
    let staged: KeychainMutation<undefined>;
    try {
      staged = await verifiedKeychainMutation(
        stagingService,
        recoveryKey,
        `${RECOVERY_LABEL} (pending rotation)`,
        opts,
        "recovery-key-readback",
        true,
      );
    } catch (error) {
      // Authority is already durable. A normal return must not continue as if
      // no keyring staging was attempted; abort so the engine can roll back the
      // authenticated pending record. Hard process death is reconciled later.
      if (registerPendingAuthority === undefined) {
        throw new RecoveryKeyKeychainStoreError(service);
      }
      throw new Error(
        "OS keyring recovery staging failed after pending authority registration",
        { cause: error },
      );
    }
    let finished = false;
    return {
      captured: true,
      authority,
      service,
      stagingService,
      rollback: async () => {
        if (finished) return;
        await staged.rollback();
        finished = true;
      },
      commit: async () => {
        if (finished) return;
        const pending = await readKeyClassified(exec, plat, stagingService);
        if (pending.status !== "found" || !pending.key) {
          pending.key?.fill(0);
          throw new RecoveryKeyKeychainStoreError(stagingService);
        }
        let canonical: KeychainMutation<undefined> | undefined;
        try {
          const encoded = toBase64url(pending.key);
          canonical = await verifiedKeychainMutation(
            service,
            encoded,
            RECOVERY_LABEL,
            opts,
            "recovery-key-readback",
            false,
          );
          // Canonical promotion is now durable and read-back verified. Commit
          // that authority before best-effort staging cleanup: a crash or a
          // keyring read failure after deletion must never restore the old
          // canonical recovery key after conversion has completed.
          canonical.commit();
          if (!(await deleteKey(exec, plat, stagingService))) {
            throw new Error(`could not remove staged OS keyring service '${stagingService}'`);
          }
          const absent = await readKeyClassified(exec, plat, stagingService);
          absent.key?.fill(0);
          if (absent.status !== "not-found") {
            throw new Error(`staged OS keyring service '${stagingService}' survived commit`);
          }
          staged.commit();
          finished = true;
        } catch (error) {
          // Before canonical.commit() the mutation remains reversible. After
          // commit it is deliberately final: the new key is already a verified
          // recovery factor and restoring the old key would strand the rotated
          // fortress.
          await canonical?.rollback();
          throw error;
        } finally {
          pending.key.fill(0);
        }
      },
    };
  } finally {
    decoded.fill(0);
  }
}

/**
 * Roll back only the deterministic pre-journal staging item authenticated by
 * the pending record. The canonical old recovery escrow is never touched.
 * Missing staging is idempotent success; an unreadable or non-verifying item
 * fails closed rather than deleting unknown keyring material.
 */
export async function reconcilePendingRecoveryKeyRotationInKeychain(
  storagePath: string,
  rotationId: string,
  authority: RotationRecoveryEscrowAuthority,
  verify: (candidate: string) => Promise<boolean>,
  opts: KeychainCustodyOptions = {},
): Promise<void> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalRecoveryKeyServiceFor(storagePath, home);
  const stagingService = `${service}:rotation:${rotationId}`;
  if (
    authority.kind !== "os-keyring"
    || authority.canonical_service !== service
    || authority.staging_service !== stagingService
  ) {
    throw new Error("pending OS-keyring recovery authority does not match this fortress");
  }
  const pending = await readKeyClassified(exec, plat, stagingService);
  if (pending.status === "not-found") return;
  if (pending.status !== "found" || !pending.key) {
    pending.key?.fill(0);
    throw new Error(`OS keyring service '${stagingService}' is unreachable`);
  }
  try {
    if (!(await verify(toBase64url(pending.key)))) {
      throw new Error(
        `OS keyring service '${stagingService}' does not unlock the pending rotation envelope`,
      );
    }
    if (!(await deleteKey(exec, plat, stagingService))) {
      throw new Error(`could not remove staged OS keyring service '${stagingService}'`);
    }
    const absent = await readKeyClassified(exec, plat, stagingService);
    absent.key?.fill(0);
    if (absent.status !== "not-found") {
      throw new Error(`staged OS keyring service '${stagingService}' survived rollback`);
    }
  } finally {
    pending.key.fill(0);
  }
}

/**
 * Re-adopt the non-secret OS-keyring authority authenticated by an interrupted
 * rotation journal. The service names are not trusted merely because they came
 * from disk: they must equal the deterministic names for this physical
 * fortress and rotation. A candidate is accepted only after the rotation
 * engine proves that it unlocks the staged/live new-master envelope.
 */
export async function adoptRecoveryKeyRotationInKeychain(
  storagePath: string,
  rotationId: string,
  authority: RotationRecoveryEscrowAuthority,
  verify: (candidate: string) => Promise<boolean>,
  opts: KeychainCustodyOptions = {},
): Promise<{ commit(): Promise<void> }> {
  const home = opts.home ?? homedir();
  const plat = opts.platformOverride ?? platform();
  const exec = opts.exec ?? defaultExec;
  const service = canonicalRecoveryKeyServiceFor(storagePath, home);
  const stagingService = `${service}:rotation:${rotationId}`;
  if (
    authority.kind !== "os-keyring" ||
    authority.canonical_service !== service ||
    authority.staging_service !== stagingService
  ) {
    throw new Error(
      "rotation journal recovery-escrow authority does not match this fortress",
    );
  }

  const verifyService = async (candidateService: string): Promise<"found" | "missing"> => {
    const result = await readKeyClassified(exec, plat, candidateService);
    if (result.status === "not-found") return "missing";
    if (result.status !== "found" || !result.key) {
      result.key?.fill(0);
      throw new Error(`OS keyring service '${candidateService}' is unreachable`);
    }
    try {
      if (!(await verify(toBase64url(result.key)))) {
        throw new Error(
          `OS keyring service '${candidateService}' does not unlock the rotated custody envelope`,
        );
      }
      return "found";
    } finally {
      result.key.fill(0);
    }
  };

  // Refuse early unless at least one durable location already holds the exact
  // new recovery key. Staging is preferred; canonical is the idempotent
  // recovery path for a crash during/after promotion.
  const stagedStatus = await verifyService(stagingService);
  if (stagedStatus === "missing" && await verifyService(service) === "missing") {
    throw new Error("both staged and canonical OS-keyring recovery escrows are missing");
  }

  return {
    commit: async () => {
      const pending = await readKeyClassified(exec, plat, stagingService);
      if (pending.status === "not-found") {
        // A prior attempt may have promoted and removed staging immediately
        // before power loss. Canonical must still prove the new recovery wrap.
        if (await verifyService(service) === "missing") {
          throw new Error("promoted OS-keyring recovery escrow is missing");
        }
        return;
      }
      if (pending.status !== "found" || !pending.key) {
        pending.key?.fill(0);
        throw new Error(`OS keyring service '${stagingService}' is unreachable`);
      }
      let canonical: KeychainMutation<undefined> | undefined;
      try {
        const encoded = toBase64url(pending.key);
        if (!(await verify(encoded))) {
          throw new Error(
            `OS keyring service '${stagingService}' no longer unlocks the rotated custody envelope`,
          );
        }
        canonical = await verifiedKeychainMutation(
          service,
          encoded,
          RECOVERY_LABEL,
          opts,
          "recovery-key-readback",
          false,
        );
        canonical.commit();
        if (!(await deleteKey(exec, plat, stagingService))) {
          throw new Error(`could not remove staged OS keyring service '${stagingService}'`);
        }
        const absent = await readKeyClassified(exec, plat, stagingService);
        absent.key?.fill(0);
        if (absent.status !== "not-found") {
          throw new Error(`staged OS keyring service '${stagingService}' survived commit`);
        }
      } catch (error) {
        await canonical?.rollback();
        throw error;
      } finally {
        pending.key.fill(0);
      }
    },
  };
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

async function defaultExec(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  // Routed through the single credential-CLI chokepoint so tests can never
  // reach the operator's real login keychain. See src/wrap/keychain-exec.ts.
  return execKeychain(cmd, args, input);
}
