/**
 * Sanctuary wrap - the host's STABLE identity, and the bounded set of names it
 * may have answered to before.
 *
 * WHY THIS MODULE EXISTS. The machine-local key that encrypts the
 * no-OS-keyring passphrase fallback file was derived from `os.hostname()`.
 * That value is not boot-invariant on macOS: the same physical machine can
 * resolve as `<name>.localdomain` on one boot and `<name>.local` on the next,
 * depending on which of DHCP, mDNS, and the static configuration answers first
 * at startup. A key derived from a value that changes across reboots is not a
 * machine binding; it is a delayed lockout. This module supplies the host fact
 * that IS boot-invariant so the key can be bound to the host itself, plus the
 * short, offline candidate list a read uses to recognize a file written under
 * the older derivation.
 *
 * SCOPE, stated so nobody reads more into it. This module resolves FACTS. It
 * holds no key material, no HKDF label, and no crypto: the derivations, the
 * labels, and the read-time migration ladder all live in `passphrase.ts`,
 * which owns the credential. Neither the platform UUID nor `/etc/machine-id`
 * is a secret; both are readable by any local user, exactly like the hostname
 * they replace. The security property of the fallback file is unchanged (see
 * the threat-model note in `server/docs/keychain-schema.md`); only its
 * survival across a reboot is.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { hostname, platform } from "node:os";

/**
 * The host facts the machine-local fallback-file key is derived from.
 *
 * Production never constructs this by hand; {@link resolveMachineIdentity}
 * reads it from the host. Tests construct it to model a specific host, which
 * is the only way to exercise a hostname change without rebooting a Mac.
 */
export interface MachineIdentity {
  /**
   * A boot-invariant identifier for this physical or virtual host, or `null`
   * when the platform exposes none. `null` is an honest absence, never a
   * placeholder: the caller must decide what to do without one rather than
   * substitute a value that only looks stable.
   */
  stableHostId: string | null;
  /**
   * What `os.hostname()` resolves to on THIS run. Retained precisely because
   * it is not boot-invariant: it is the material superseded keys were derived
   * from, so it is what a migration read needs.
   */
  hostname: string;
}

/**
 * macOS: the IOPlatformExpertDevice node carries `IOPlatformUUID`, the
 * per-machine identifier that survives reboots, renames, and network changes.
 * Must match the parse in {@link parseDarwinPlatformUuidDump}; `ioreg` prints
 * it as a quoted key/value pair inside the -rd1 device dump.
 *
 * INVARIANT (enforcement site): the tool is named by ABSOLUTE path, never by a
 * bare `ioreg` that `execFileSync` would resolve through the inherited `PATH`.
 * This value decides which key opens a custody credential, so the process
 * environment must not be able to choose the binary that supplies it.
 * `/usr/sbin/ioreg` is the OS-owned location on every supported macOS release.
 *
 * FAILURE MODE: if a future macOS moves the binary, the probe simply fails and
 * `resolveStableHostId` returns `null` — the honest absence, not a silently
 * different identity. That is the correct direction to fail in.
 */
const DARWIN_PLATFORM_UUID_TOOL = "/usr/sbin/ioreg";
const DARWIN_PLATFORM_UUID_ARGS = ["-rd1", "-c", "IOPlatformExpertDevice"];
/**
 * A hyphenated UUID in canonical 8-4-4-4-12 text form.
 * 36 = 32 hex digits + 4 hyphens; the pattern is written out rather than
 * counted so a malformed or truncated dump cannot be accepted as an identity.
 */
const CANONICAL_UUID_PATTERN = /^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/;
const DARWIN_PLATFORM_UUID_LINE = /"IOPlatformUUID"\s*=\s*"([^"]+)"/;

/**
 * Linux: systemd's machine id. `/etc/machine-id` is 32 lowercase hex digits
 * with no hyphens, generated once at install and stable thereafter.
 * 32 = the documented width of that file's contents.
 */
const LINUX_MACHINE_ID_PATH = "/etc/machine-id";
const LINUX_MACHINE_ID_PATTERN = /^[0-9a-f]{32}$/;

/**
 * Bounds on the one subprocess this module spawns. A wedged or hostile `ioreg`
 * must not stall a custody read or exhaust the process, and this call happens
 * while the caller may be holding a custody lock.
 *
 * FAILURE MODE, for anyone reading this at 2am: if these bounds are hit, the
 * resolver returns `null` and the caller derives from the resolved hostname
 * instead (still under the current HKDF label; see `deriveMachineKey` in
 * `passphrase.ts`). It does not throw and it does not invent an identity, but a
 * file already written under the stable identity will NOT open on that run. So
 * the timeout is a safety stop for a wedged binary, deliberately set far above
 * any healthy latency for what is a local IOKit query with no network in it: a
 * heavily loaded machine must never be misread as a host without an identity.
 * Do not tune this down to make anything faster; the probe is lazy and its
 * result is cached, so it runs at most once per process and only when a
 * machine-local key is actually needed.
 */
const HOST_IDENTITY_PROBE_TIMEOUT_MS = 10_000;
/** 256 KiB: an -rd1 dump of one device node is a few KiB; this is slack, not a target. */
const HOST_IDENTITY_PROBE_MAX_OUTPUT_BYTES = 256 * 1024;

/**
 * Suffixes a short host name is commonly published under on a local network,
 * in the order a migration read tries them. This list is deliberately CLOSED
 * and offline: it recognizes the spellings one machine gives itself, and it
 * performs no lookup that could let a network answer decide which key is
 * tried.
 */
const LOCAL_NAME_SUFFIXES = [".local", ".localdomain"] as const;

/**
 * Memoized per platform token. The identity cannot change inside one process,
 * and the darwin branch spawns a subprocess, so re-resolving it on every
 * credential read would be a spawn per read. A test that wants a different
 * identity supplies one explicitly rather than clearing this cache, so there
 * is deliberately no reset function.
 */
const stableHostIdCache = new Map<string, string | null>();

/**
 * The macOS platform UUID carried by an `ioreg -rd1 -c IOPlatformExpertDevice`
 * dump, or `null` when the dump does not carry one in canonical form.
 *
 * Exported because it is the only part of the darwin probe that can be tested
 * without a Mac: the subprocess call itself is deliberately NOT mocked (a mock
 * would prove only that the mock was called), so this parser plus the real-host
 * witness in `server/test/wrap/host-identity.test.ts` are the evidence that the
 * production resolver works. Keep the two in step: that test feeds this
 * function a captured dump shape, a malformed UUID, and a dump with the key
 * absent.
 */
export function parseDarwinPlatformUuidDump(dump: string): string | null {
  const matched = DARWIN_PLATFORM_UUID_LINE.exec(dump);
  if (matched === null) return null;
  const uuid = matched[1]!.trim();
  // INVARIANT (enforcement site): a value that is not a canonical UUID is not
  // this identity, whatever else it is. Accepting it would bind a custody key
  // to an unvalidated string that a future OS release could reshape without
  // notice, and an empty or truncated capture would then read as an identity.
  return CANONICAL_UUID_PATTERN.test(uuid) ? uuid : null;
}

/**
 * The systemd machine id carried by the contents of `/etc/machine-id`, or
 * `null` when those contents are not one. Exported for the same reason as
 * {@link parseDarwinPlatformUuidDump}: the file read is trivial, the shape
 * check is the part worth pinning.
 */
export function parseLinuxMachineId(raw: string): string | null {
  const id = raw.trim();
  // INVARIANT (enforcement site): an uninitialized machine id is an empty
  // file; the pattern rejects it along with any other shape, so a first-boot
  // host is never bound to "" — which every such host would share.
  return LINUX_MACHINE_ID_PATTERN.test(id) ? id : null;
}

/** Read the macOS platform UUID, or `null` when it cannot be established. */
function readDarwinPlatformUuid(): string | null {
  let dump: string;
  try {
    dump = execFileSync(DARWIN_PLATFORM_UUID_TOOL, DARWIN_PLATFORM_UUID_ARGS, {
      encoding: "utf-8",
      timeout: HOST_IDENTITY_PROBE_TIMEOUT_MS,
      maxBuffer: HOST_IDENTITY_PROBE_MAX_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    // Missing binary, non-zero exit, timeout, or output over the cap. Absent
    // evidence is not a pass: report absence and let the caller keep its
    // existing behavior.
    return null;
  }
  return parseDarwinPlatformUuidDump(dump);
}

/** Read the systemd machine id, or `null` when it cannot be established. */
function readLinuxMachineId(): string | null {
  let raw: string;
  try {
    raw = readFileSync(LINUX_MACHINE_ID_PATH, "utf-8");
  } catch {
    // Not present (a container image that strips it, a non-systemd distro) or
    // unreadable. Same disposition as darwin: absence, not a substitute.
    return null;
  }
  return parseLinuxMachineId(raw);
}

/**
 * The boot-invariant host identity for `plat`, or `null` when this platform
 * exposes none (Windows and everything else).
 */
export function resolveStableHostId(plat: NodeJS.Platform = platform()): string | null {
  const cached = stableHostIdCache.get(plat);
  if (cached !== undefined) return cached;
  let resolved: string | null;
  if (plat === "darwin") resolved = readDarwinPlatformUuid();
  else if (plat === "linux") resolved = readLinuxMachineId();
  else resolved = null;
  stableHostIdCache.set(plat, resolved);
  return resolved;
}

/** The live host facts: the stable identity, plus this run's resolved hostname. */
export function resolveMachineIdentity(
  plat: NodeJS.Platform = platform(),
): MachineIdentity {
  return { stableHostId: resolveStableHostId(plat), hostname: hostname() };
}

/**
 * The bounded, ordered list of host names a fallback file on THIS host may
 * have been keyed to before the current derivation: the name it answers to
 * now, its short form, and that short form under each local-network suffix.
 *
 * INVARIANT (enforcement site): this list is closed, de-duplicated, and
 * derived only from `current`. A read that widens it widens what a stolen
 * fallback file can be opened against, so a candidate is added here only with
 * the same scrutiny as a key. Nothing here performs a lookup of any kind.
 */
export function hostnameMigrationCandidates(current: string): string[] {
  const short = current.split(".")[0] ?? "";
  const ordered = [
    current,
    short,
    ...LOCAL_NAME_SUFFIXES.map((suffix) => `${short}${suffix}`),
  ];
  return ordered.filter(
    (name, index) => name.length > 0 && ordered.indexOf(name) === index,
  );
}
