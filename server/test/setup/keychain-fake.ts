/**
 * Global test setup: install an IN-MEMORY credential store for every test.
 *
 * See `src/wrap/keychain-exec.ts` for why. Short version: the suite used to
 * write ~61 entries per run into the developer's real login keychain, and under
 * vitest's parallel workers the serialized keychain daemon turned that into
 * timeouts whose workers survived and poisoned later runs.
 *
 * An in-memory store is preferred over a temporary REAL keychain because it
 * removes the `security` subprocess entirely. That kills the worker-hang vector
 * rather than making it less likely - no child process means nothing to orphan.
 *
 * The store is per-worker-process and cleared before each test, so tests cannot
 * leak credentials into each other.
 *
 * The fake covers the whole verb surface the codebase actually issues, which
 * includes the broker backend's `security -i` BATCH verbs (`create-keychain`,
 * `unlock-keychain`) and `dump-keychain`, not only the generic-password trio.
 * That completeness is what lets EVERY call site route through the chokepoint:
 * a fake that knows three verbs forces the fourth call site to keep its own
 * `spawn`, and one unrouted call site falsifies the whole guarantee.
 *
 * ONE FILE OPTS OUT: `test/keychain-linux-real-backend-integration.test.ts`
 * exists to exercise the genuine `secret-tool` shell-out, so serving it from
 * this fake would defeat its purpose - and worse, would make a DEAD Secret
 * Service look alive, because the fake answers happily no matter what
 * DBUS_SESSION_BUS_ADDRESS points at. That file calls
 * {@link installInMemoryKeychainStore} in its `afterAll` to put the fake back.
 */

import { existsSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve, sep } from "node:path";
import { beforeEach } from "vitest";

import { setKeychainExec, type KeychainExec } from "../../src/wrap/keychain-exec.js";
import type { ExecResult } from "../../src/wrap/exec-result.js";

/**
 * Separator joining the two halves of a `store` key. NUL is the one byte that
 * cannot occur in a keychain path or a service name, so a key always splits
 * back into exactly the pair that formed it. Written as an escape, never as a
 * raw byte: a literal NUL in source is invisible in a diff.
 */
const KEY_SEPARATOR = "\u0000";

/**
 * Sentinel for "no keychain file named on the command line", i.e. the default
 * keychain. `wrap/keychain-custody.ts` and `wrap/passphrase.ts` address the
 * default keychain; `disclosure/broker/keychain-backend.ts` always names a
 * dedicated keychain file. Keying the store by keychain identity keeps those
 * two worlds from colliding on a shared service name.
 */
const DEFAULT_KEYCHAIN = `${KEY_SEPARATOR}default-keychain`;

/** `keychain -> service -> account -> secret` flattened one level. */
const store = new Map<string, Map<string, string>>();
/**
 * Keychain files the fake has "created", with the passphrase they were created
 * under, so `unlock-keychain` can reject a wrong passphrase the way the real
 * CLI does. Cleared with the secret store before each test; a keychain must
 * therefore be created inside the test (or its `beforeEach`) that uses it, not
 * in a `beforeAll`.
 */
const keychains = new Map<string, { passphrase: string }>();

const ok = (stdout = ""): ExecResult => ({ stdout, stderr: "", code: 0 });
/** macOS errSecItemNotFound. The classifier in keychain-custody.ts reads this. */
const NOT_FOUND_CODE = 44;
/** macOS errSecDuplicateItem, as surfaced by `security` exit status. */
const DUPLICATE_ITEM_CODE = 45;
/** macOS errSecAuthFailed: wrong passphrase on unlock-keychain. */
const AUTH_FAILED_CODE = 51;
const notFound = (): ExecResult => ({
  stdout: "",
  stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
  code: NOT_FOUND_CODE,
});
const fail = (code: number, stderr: string): ExecResult => ({ stdout: "", stderr, code });

function storeKey(keychain: string, service: string): string {
  return `${keychain}${KEY_SEPARATOR}${service}`;
}

function put(keychain: string, service: string, account: string, secret: string): void {
  const key = storeKey(keychain, service);
  let byAccount = store.get(key);
  if (byAccount === undefined) {
    byAccount = new Map();
    store.set(key, byAccount);
  }
  byAccount.set(account, secret);
}

function get(keychain: string, service: string, account: string): string | undefined {
  return store.get(storeKey(keychain, service))?.get(account);
}

function del(keychain: string, service: string, account: string): boolean {
  return store.get(storeKey(keychain, service))?.delete(account) ?? false;
}

/** Pull `-a <account>` / `-s <service>` out of a flag list. */
function flagValue(tokens: string[], flag: string): string | undefined {
  const i = tokens.indexOf(flag);
  return i >= 0 && i + 1 < tokens.length ? tokens[i + 1] : undefined;
}

// ── `security` argument grammar ─────────────────────────────────────────
//
// `-w` is the reason this needs a per-verb table rather than a generic
// "next token is the value" scan: on `add-generic-password` it CARRIES the
// secret, on `find-generic-password` it is a bare "print the password" switch.
// Treating it uniformly either swallows the trailing keychain path as a secret
// or stores the literal string "-w".
const VERB_BOOLEAN_FLAGS: Record<string, readonly string[]> = {
  "add-generic-password": ["-U"],
  "find-generic-password": ["-w", "-g"],
  "delete-generic-password": [],
  "create-keychain": [],
  "unlock-keychain": [],
  "dump-keychain": ["-d", "-a"],
};

interface ParsedCommand {
  verb: string;
  flags: Map<string, string>;
  booleans: Set<string>;
  /** Non-flag operands. For every verb here, operand 0 is the keychain file. */
  positionals: string[];
}

function parseSecurityCommand(tokens: string[]): ParsedCommand {
  const verb = tokens[0] ?? "";
  const booleanNames = new Set(VERB_BOOLEAN_FLAGS[verb] ?? []);
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  const positionals: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (!token.startsWith("-")) {
      positionals.push(token);
      continue;
    }
    if (booleanNames.has(token)) {
      booleans.add(token);
      continue;
    }
    flags.set(token, tokens[++i] ?? "");
  }
  return { verb, flags, booleans, positionals };
}

// ── Keychain-file emulation ─────────────────────────────────────────────
//
// A macOS keychain is a FILE, and the broker backend uses `existsSync` on that
// path as its "does this keychain exist yet" oracle (keychain-backend.ts
// `ensureInitialized` / `unlock` / `isUnlocked`). A purely in-memory fake would
// answer `create-keychain` with success and then have the very next
// `existsSync` say the keychain is absent, so the fake has to reproduce the
// filesystem side effect as well as the CLI one.

function canonical(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

/**
 * Directory under which the fake is willing to materialize a keychain file.
 * Everything else is refused: creating files at an operator-supplied path is
 * exactly the blast the chokepoint exists to stop, and a test that wants a
 * keychain has no business putting it outside its own temp dir.
 */
const TEMP_ROOT = canonical(tmpdir());

function isUnderTempRoot(path: string): boolean {
  const parent = canonical(dirname(resolve(path)));
  return parent === TEMP_ROOT || parent.startsWith(TEMP_ROOT + sep);
}

/**
 * Split a `security -i` batch line into tokens, honoring the double-quoting
 * that `escapeForSecurity` produces. Secrets are delivered on stdin precisely
 * so they never reach argv, so the fake has to parse them the same way.
 */
function tokenizeBatchLine(line: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inQuotes = false;
  let escaped = false;
  for (const ch of line) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === " " && !inQuotes) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

function runSecurityVerb(tokens: string[]): ExecResult {
  const { verb, flags, booleans, positionals } = parseSecurityCommand(tokens);
  const account = flags.get("-a");
  const service = flags.get("-s");
  const keychain = positionals[0] ?? DEFAULT_KEYCHAIN;

  if (verb === "create-keychain") {
    const path = positionals[0];
    if (path === undefined) {
      return fail(1, "security: create-keychain requires a keychain path");
    }
    if (!isUnderTempRoot(path)) {
      // Loud on purpose. The real CLI would happily create this; the fake will
      // not, because a test that names a path outside its own temp dir is about
      // to litter (or clobber) an operator-owned location.
      return fail(
        1,
        `security: test keychain fake refuses to create '${path}' outside the temp root ` +
          `(${TEMP_ROOT}). Point the test at a mkdtemp() directory.`
      );
    }
    if (existsSync(path)) {
      return fail(DUPLICATE_ITEM_CODE, "security: A keychain with the same name already exists.");
    }
    mkdirSync(dirname(resolve(path)), { recursive: true });
    // Content is irrelevant: nothing reads the file, but `existsSync` on it is
    // what keychain-backend.ts checks. 0o600 mirrors the real CLI's mode.
    writeFileSync(path, "", { mode: 0o600 });
    keychains.set(canonical(path), { passphrase: flags.get("-p") ?? "" });
    return ok();
  }

  if (verb === "unlock-keychain") {
    const path = positionals[0];
    if (path !== undefined && !existsSync(path)) {
      return fail(NOT_FOUND_CODE, "security: The specified keychain could not be found.");
    }
    const known = path === undefined ? undefined : keychains.get(canonical(path));
    if (known !== undefined && known.passphrase !== (flags.get("-p") ?? "")) {
      return fail(
        AUTH_FAILED_CODE,
        "security: The user name or passphrase you entered is not correct."
      );
    }
    return ok();
  }

  if (verb === "dump-keychain") {
    const path = positionals[0];
    if (path !== undefined && !existsSync(path)) {
      return fail(NOT_FOUND_CODE, "security: The specified keychain could not be found.");
    }
    // One `keychain: ` block per item: keychain-backend.ts `listSecretNames`
    // splits on /^keychain: /m and reads one "acct" per block.
    let out = "";
    for (const [key, byAccount] of store) {
      const separator = key.indexOf(KEY_SEPARATOR);
      if (key.slice(0, separator) !== keychain) continue;
      const itemService = key.slice(separator + 1);
      for (const itemAccount of byAccount.keys()) {
        out +=
          `keychain: "${keychain}"\nversion: 512\nclass: "genp"\nattributes:\n` +
          `    "acct"<blob>="${itemAccount}"\n` +
          `    "svce"<blob>="${itemService}"\n`;
      }
    }
    return ok(out);
  }

  if (verb === "add-generic-password") {
    if (account === undefined || service === undefined) {
      return fail(1, "security: missing -a/-s");
    }
    const secret = flags.get("-w") ?? "";
    // `-U` updates in place; without it, a duplicate is an error (errSecDuplicateItem).
    if (!booleans.has("-U") && get(keychain, service, account) !== undefined) {
      return fail(
        DUPLICATE_ITEM_CODE,
        "security: The specified item already exists in the keychain."
      );
    }
    put(keychain, service, account, secret);
    return ok();
  }

  if (verb === "find-generic-password") {
    if (account === undefined || service === undefined) return notFound();
    const secret = get(keychain, service, account);
    if (secret === undefined) return notFound();
    // `-w` prints the bare secret; without it the metadata dump is enough for
    // existence checks, and no caller parses it today.
    return ok(booleans.has("-w") ? `${secret}\n` : `service: "${service}"\n`);
  }

  if (verb === "delete-generic-password") {
    if (account === undefined || service === undefined) return notFound();
    return del(keychain, service, account) ? ok() : notFound();
  }

  return fail(1, `security: unsupported verb '${verb}' in test fake`);
}

const fakeExec: KeychainExec = async (cmd, args, input) => {
  // Two spellings reach here: `security` (wrap/keychain-custody.ts,
  // wrap/passphrase.ts) and the absolute `/usr/bin/security` (SECURITY_BIN in
  // disclosure/broker/keychain-backend.ts). Match on the basename so adding a
  // call site with either spelling is served, not silently unsupported.
  const binary = cmd.slice(cmd.lastIndexOf("/") + 1);

  if (binary === "security") {
    // Batch mode: verbs arrive on stdin so secrets never touch argv.
    if (args[0] === "-i") {
      let last: ExecResult = ok();
      for (const line of (input ?? "").split("\n")) {
        if (line.trim().length === 0) continue;
        last = runSecurityVerb(tokenizeBatchLine(line));
        if (last.code !== 0) return last;
      }
      return last;
    }
    return runSecurityVerb(args);
  }

  // Linux Secret Service. `store` reads the secret from stdin; `lookup` prints it.
  if (binary === "secret-tool") {
    const verb = args[0];
    const service = flagValue(args, "service") ?? args.join(" ");
    const account = flagValue(args, "account") ?? "default";
    // Linux has no per-file keychain, so every item lands in the default bucket.
    if (verb === "store") {
      put(DEFAULT_KEYCHAIN, service, account, input ?? "");
      return ok();
    }
    if (verb === "lookup") {
      const secret = get(DEFAULT_KEYCHAIN, service, account);
      return secret === undefined ? { stdout: "", stderr: "", code: 1 } : ok(secret);
    }
    if (verb === "clear") {
      del(DEFAULT_KEYCHAIN, service, account);
      return ok();
    }
  }

  return { stdout: "", stderr: `unsupported command '${cmd}' in test keychain fake`, code: 1 };
};

/**
 * (Re)install the in-memory store as the credential-CLI implementation. Called
 * once at setup time for every test file, and again by any file that
 * deliberately removed it, so the removal cannot outlive the suite that asked
 * for it even if that suite fails or times out.
 */
export function installInMemoryKeychainStore(): void {
  setKeychainExec(fakeExec);
}

installInMemoryKeychainStore();

beforeEach(() => {
  store.clear();
  keychains.clear();
});
