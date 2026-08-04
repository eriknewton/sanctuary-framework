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
 */

import { beforeEach } from "vitest";

import { setKeychainExec, type KeychainExec } from "../../src/wrap/keychain-exec.js";
import type { ExecResult } from "../../src/wrap/exec-result.js";

/** service -> account -> secret */
const store = new Map<string, Map<string, string>>();

const ok = (stdout = ""): ExecResult => ({ stdout, stderr: "", code: 0 });
/** macOS errSecItemNotFound. The classifier in keychain-custody.ts reads this. */
const NOT_FOUND_CODE = 44;
const notFound = (): ExecResult => ({
  stdout: "",
  stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
  code: NOT_FOUND_CODE,
});

function put(service: string, account: string, secret: string): void {
  let byAccount = store.get(service);
  if (byAccount === undefined) {
    byAccount = new Map();
    store.set(service, byAccount);
  }
  byAccount.set(account, secret);
}

function get(service: string, account: string): string | undefined {
  return store.get(service)?.get(account);
}

function del(service: string, account: string): boolean {
  const byAccount = store.get(service);
  if (byAccount === undefined) return false;
  return byAccount.delete(account);
}

/** Pull `-a <account>` / `-s <service>` out of a flag list. */
function flagValue(tokens: string[], flag: string): string | undefined {
  const i = tokens.indexOf(flag);
  return i >= 0 && i + 1 < tokens.length ? tokens[i + 1] : undefined;
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
  const verb = tokens[0];
  const account = flagValue(tokens, "-a");
  const service = flagValue(tokens, "-s");

  if (verb === "add-generic-password") {
    if (account === undefined || service === undefined) {
      return { stdout: "", stderr: "security: missing -a/-s", code: 1 };
    }
    const secret = flagValue(tokens, "-w") ?? "";
    // `-U` updates in place; without it, a duplicate is an error (errSecDuplicateItem).
    if (!tokens.includes("-U") && get(service, account) !== undefined) {
      return { stdout: "", stderr: "security: The specified item already exists in the keychain.", code: 45 };
    }
    put(service, account, secret);
    return ok();
  }

  if (verb === "find-generic-password") {
    if (account === undefined || service === undefined) return notFound();
    const secret = get(service, account);
    if (secret === undefined) return notFound();
    // `-w` prints the bare secret; without it the metadata dump is enough for
    // existence checks, and no caller parses it today.
    return ok(tokens.includes("-w") ? `${secret}\n` : `service: "${service}"\n`);
  }

  if (verb === "delete-generic-password") {
    if (account === undefined || service === undefined) return notFound();
    return del(service, account) ? ok() : notFound();
  }

  return { stdout: "", stderr: `security: unsupported verb '${verb ?? ""}' in test fake`, code: 1 };
}

const fakeExec: KeychainExec = async (cmd, args, input) => {
  if (cmd === "security") {
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
  if (cmd === "secret-tool") {
    const verb = args[0];
    const service = flagValue(args, "service") ?? args.join(" ");
    const account = flagValue(args, "account") ?? "default";
    if (verb === "store") {
      put(service, account, input ?? "");
      return ok();
    }
    if (verb === "lookup") {
      const secret = get(service, account);
      return secret === undefined ? { stdout: "", stderr: "", code: 1 } : ok(secret);
    }
    if (verb === "clear") {
      del(service, account);
      return ok();
    }
  }

  return { stdout: "", stderr: `unsupported command '${cmd}' in test keychain fake`, code: 1 };
};

setKeychainExec(fakeExec);

beforeEach(() => {
  store.clear();
});
