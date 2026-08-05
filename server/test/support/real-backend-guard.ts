/**
 * The gate on the ONE test file that removes the in-memory credential store.
 *
 * `test/keychain-linux-real-backend-integration.test.ts` exists to shell out to
 * a genuine `secret-tool`, so it takes the safety net off. Taking the net off is
 * only acceptable against a keyring that was created for this CI run and dies
 * with the runner. Everything here answers one question: is that true, provably,
 * right now?
 *
 * WHY THIS IS A MODULE AND NOT AN `if` IN THAT FILE. The predicate has to be
 * callable so its truth table can be exercised directly. The previous version of
 * this gate was asserted by grepping the test file for the string
 * `SANCTUARY_TEST_DISPOSABLE_KEYRING`, which would have kept passing if the
 * condition were ORed instead of ANDed, checked after the store was already
 * removed, or never read at all. A substring is not an enforcement.
 *
 * WHY AN ENV VAR ALONE IS NOT PROOF. The condition used to be
 * `SANCTUARY_TEST_DISPOSABLE_KEYRING === "1"`. A Linux desktop has
 * `secret-tool` and a session bus, so one stale exported variable in a shell
 * profile was the whole distance between "skip" and "write to the operator's
 * real Secret Service". A bare env var is a declaration; the run has to be able
 * to prove it.
 */

import { readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

import {
  setKeychainExec,
  execKeychain,
  ALLOW_REAL_KEYCHAIN_ENV,
} from "../../src/wrap/keychain-exec.js";
import { installInMemoryKeychainStore } from "../setup/keychain-fake.js";

/**
 * Env var naming the provisioning token file. It holds a PATH now, not "1", so
 * the old forgeable value satisfies nothing.
 *
 * MUST MATCH the variable exported by `scripts/ci/provision-disposable-keyring.sh`,
 * which is the only thing that writes a token this module will accept.
 */
export const DISPOSABLE_KEYRING_ENV = "SANCTUARY_TEST_DISPOSABLE_KEYRING";

/**
 * Secret Service coordinates of the nonce the provisioning step stores.
 *
 * MUST MATCH `PROBE_SERVICE` / `PROBE_ACCOUNT` in
 * `scripts/ci/provision-disposable-keyring.sh`. The round trip through these
 * exact coordinates is what proves the keyring answering on this bus is the one
 * the run provisioned, rather than whatever keyring happens to be listening.
 */
export const PROBE_SERVICE = "sanctuary-disposable-keyring-probe";
export const PROBE_ACCOUNT = "nonce";

/**
 * How long a provisioning token stays acceptable. A CI job that reaches the
 * tests hours after provisioning is already broken; the point of the bound is
 * that a token file left on a developer's disk goes stale on its own.
 * 6 * 60 * 60 * 1000 = six hours in milliseconds.
 */
export const TOKEN_MAX_AGE_MS = 6 * 60 * 60 * 1000;

/** 64 = the hex length of the 32 random bytes the provisioning script mints. */
const NONCE_HEX_LENGTH = 64;

export interface DisposableKeyringToken {
  nonce: string;
  dbusAddress: string;
  createdAtMs: number;
}

export interface DisposableKeyringProbe {
  /** Raw value of {@link DISPOSABLE_KEYRING_ENV}. */
  tokenPath: string | undefined;
  /** Live `DBUS_SESSION_BUS_ADDRESS` at the moment the guard runs. */
  busAddress: string | undefined;
  /** Reads the token file. Returns undefined when it cannot be read. */
  readToken: (path: string) => string | undefined;
  /** Looks the nonce up in the Secret Service on the live bus. */
  lookupNonce: () => string | undefined;
  /** Injected clock so the freshness bound is testable. */
  now: number;
  /** Directory prefixes a throwaway bus socket may live under. */
  tempRoots: readonly string[];
}

export interface DisposableVerdict {
  disposable: boolean;
  /** Non-secret explanation, surfaced when a CI job unexpectedly skips. */
  reason: string;
}

/**
 * Pull the socket identifier out of a D-Bus address.
 *
 * Two forms occur in practice: `unix:path=/run/user/1000/bus` (a systemd login
 * session, i.e. a REAL desktop keyring) and `unix:abstract=/tmp/dbus-XXXXXXXX`
 * (what `dbus-launch` / `dbus-run-session` produce from the stock session.conf,
 * i.e. a throwaway). An abstract socket has no filesystem entry, so the
 * identifier is compared as a string either way rather than stat'ed.
 */
export function dbusSocketIdentifier(address: string): string | null {
  for (const field of address.split(",")) {
    const [rawKey, ...rest] = field.split("=");
    const key = (rawKey ?? "").trim();
    if (key === "unix:path" || key === "unix:abstract" || key === "path" || key === "abstract") {
      return rest.join("=");
    }
  }
  return null;
}

function isUnderAnyRoot(path: string, roots: readonly string[]): boolean {
  return roots.some((root) => path === root || path.startsWith(root + sep));
}

/**
 * Decide whether the keyring reachable right now is provably the disposable one
 * this run provisioned. Every condition must hold; the first failure names
 * itself so a CI skip is diagnosable without a rerun.
 */
export function verifyDisposableKeyring(
  probe: DisposableKeyringProbe
): DisposableVerdict {
  const tokenPath = probe.tokenPath;
  if (tokenPath === undefined || tokenPath.length === 0) {
    return { disposable: false, reason: `${DISPOSABLE_KEYRING_ENV} is not set` };
  }
  if (!tokenPath.startsWith("/")) {
    // Rejects the old "1" value outright, so an environment carrying the
    // superseded declaration is treated as no declaration at all.
    return {
      disposable: false,
      reason: `${DISPOSABLE_KEYRING_ENV} must be an absolute path to a provisioning token, got ${JSON.stringify(tokenPath)}`,
    };
  }

  const raw = probe.readToken(tokenPath);
  if (raw === undefined) {
    return { disposable: false, reason: `provisioning token ${tokenPath} is unreadable` };
  }

  let token: Partial<DisposableKeyringToken>;
  try {
    token = JSON.parse(raw) as Partial<DisposableKeyringToken>;
  } catch {
    return { disposable: false, reason: `provisioning token ${tokenPath} is not valid JSON` };
  }
  if (
    typeof token.nonce !== "string" ||
    token.nonce.length !== NONCE_HEX_LENGTH ||
    typeof token.dbusAddress !== "string" ||
    typeof token.createdAtMs !== "number"
  ) {
    return { disposable: false, reason: `provisioning token ${tokenPath} is malformed` };
  }

  if (probe.now - token.createdAtMs > TOKEN_MAX_AGE_MS) {
    return {
      disposable: false,
      reason: "provisioning token is stale; it belongs to an earlier run, not this one",
    };
  }
  if (token.createdAtMs > probe.now) {
    return { disposable: false, reason: "provisioning token is dated in the future" };
  }

  if (probe.busAddress === undefined || probe.busAddress.length === 0) {
    return { disposable: false, reason: "DBUS_SESSION_BUS_ADDRESS is not set" };
  }
  if (token.dbusAddress !== probe.busAddress) {
    // Kills the stale-shell-export case: the token names the bus it provisioned,
    // so a token that outlived its bus can never match a later one.
    return {
      disposable: false,
      reason: "the live session bus is not the one the provisioning step recorded",
    };
  }

  const socket = dbusSocketIdentifier(probe.busAddress);
  if (socket === null) {
    return { disposable: false, reason: `unrecognized D-Bus address form: ${probe.busAddress}` };
  }
  if (!isUnderAnyRoot(socket, probe.tempRoots)) {
    // The structural condition a developer's own desktop cannot satisfy: a login
    // session bus lives at /run/user/<uid>/bus, and a keyring on that bus is the
    // operator's real one no matter what any env var declares.
    return {
      disposable: false,
      reason: `session bus socket ${socket} is not a throwaway bus under ${probe.tempRoots.join(", ")}`,
    };
  }

  const looked = probe.lookupNonce();
  if (looked === undefined) {
    return {
      disposable: false,
      reason: "the Secret Service on this bus holds no provisioning nonce",
    };
  }
  if (looked.trim() !== token.nonce) {
    return {
      disposable: false,
      reason: "the Secret Service on this bus is not the one this run provisioned",
    };
  }

  return { disposable: true, reason: "keyring provisioned by this run" };
}

/** Live probe of the current process environment. */
export function probeDisposableKeyring(): DisposableVerdict {
  return verifyDisposableKeyring({
    tokenPath: process.env[DISPOSABLE_KEYRING_ENV],
    busAddress: process.env.DBUS_SESSION_BUS_ADDRESS,
    readToken: (path) => {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    lookupNonce: () => {
      const result = spawnSync(
        "secret-tool",
        ["lookup", "service", PROBE_SERVICE, "account", PROBE_ACCOUNT],
        { encoding: "utf8" }
      );
      if (result.status !== 0 || typeof result.stdout !== "string") return undefined;
      return result.stdout;
    },
    now: Date.now(),
    tempRoots: temporaryRoots(),
  });
}

function temporaryRoots(): readonly string[] {
  const roots = new Set<string>(["/tmp"]);
  for (const candidate of [tmpdir(), process.env.RUNNER_TEMP]) {
    if (candidate === undefined || candidate.length === 0) continue;
    roots.add(resolve(candidate));
    try {
      roots.add(realpathSync(candidate));
    } catch {
      // A configured-but-absent temp dir simply contributes nothing.
    }
  }
  return Array.from(roots);
}

// ── The skip decision ───────────────────────────────────────────────────

export interface RealBackendProbe {
  isLinux: boolean;
  hasSecretTool: boolean;
  hasDbus: boolean;
  keyringIsDisposable: boolean;
}

/**
 * All four conditions are required. Each one alone is satisfiable by an
 * ordinary Linux desktop, which is why this is an AND and why the truth table
 * is tested condition by condition in `test/wrap/keychain-exec-guard.test.ts`.
 */
export function shouldSkipRealBackend(probe: RealBackendProbe): boolean {
  return (
    !probe.isLinux ||
    !probe.hasSecretTool ||
    !probe.hasDbus ||
    !probe.keyringIsDisposable
  );
}

export interface RealBackendModeState {
  savedAllowReal: string | undefined;
}

/**
 * Remove the in-memory credential store so the production code shells out for
 * real, and REFUSE to do it unless {@link shouldSkipRealBackend} says the run
 * qualifies.
 *
 * This is the enforcement, not the `describe.skipIf`. A skip guard that drifts
 * out of agreement with the gate fails here, loudly, instead of quietly writing
 * to somebody's keyring: the store stays installed and the suite errors.
 */
export function enterRealBackendMode(probe: RealBackendProbe): RealBackendModeState {
  if (shouldSkipRealBackend(probe)) {
    throw new Error(
      "refusing to remove the in-memory credential store: this run is not on a " +
        "CI-provisioned disposable keyring " +
        `(linux=${probe.isLinux}, secret-tool=${probe.hasSecretTool}, ` +
        `dbus=${probe.hasDbus}, disposable=${probe.keyringIsDisposable})`
    );
  }
  const savedAllowReal = process.env[ALLOW_REAL_KEYCHAIN_ENV];
  // `execKeychain` consults the store BEFORE the opt-in env var, so removing the
  // store is what actually restores the spawn path; the env var alone is inert.
  // Both are required: the removal to reach `spawn`, the var to get past the
  // under-test refusal.
  process.env[ALLOW_REAL_KEYCHAIN_ENV] = "1";
  setKeychainExec(null);
  return { savedAllowReal };
}

/** Put the safety net back. Runs even when the suite failed or timed out. */
export function leaveRealBackendMode(state: RealBackendModeState): void {
  installInMemoryKeychainStore();
  if (state.savedAllowReal !== undefined) {
    process.env[ALLOW_REAL_KEYCHAIN_ENV] = state.savedAllowReal;
  } else {
    delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
  }
}

/**
 * True when the in-memory store is currently serving, i.e. the safety net is on.
 * Probes by BEHAVIOR (issue a harmless lookup and see whether the chokepoint
 * refuses) rather than by reading module state, so it cannot disagree with what
 * a real call site would experience.
 */
export async function credentialStoreIsInstalled(): Promise<boolean> {
  const savedAllowReal = process.env[ALLOW_REAL_KEYCHAIN_ENV];
  delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
  try {
    await execKeychain("security", [
      "find-generic-password",
      "-s",
      "sanctuary-store-installed-probe",
      "-a",
      "sanctuary",
      "-w",
    ]);
    return true;
  } catch {
    return false;
  } finally {
    if (savedAllowReal !== undefined) {
      process.env[ALLOW_REAL_KEYCHAIN_ENV] = savedAllowReal;
    }
  }
}
