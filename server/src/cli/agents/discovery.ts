/**
 * Sanctuary MCP Server — tenant discovery
 *
 * Enumerates every Sanctuary tenant visible on the local host without
 * decrypting any state. Discovery sources, in order:
 *
 *   1. The default storage root (`~/.sanctuary/`) itself — included as the
 *      tenant named "default" if it looks initialized (has `state/` or
 *      `cocoon-profile.json` or `passphrase.enc`).
 *   2. Each immediate sub-directory of the default root that itself looks
 *      initialized — included as a tenant named after its directory basename.
 *   3. Any additional paths listed in `SANCTUARY_AGENTS_EXTRA_PATHS`,
 *      `<default-root>/agents-extra.json`, or the wrap-maintained
 *      `<default-root>/tenants.json`. These let users register tenants whose
 *      storage lives outside `~/.sanctuary/`.
 *
 * The `TenantDescriptor` never contains secrets. The `keychain_service` is
 * a stable hash of the path (same function `passphrase.keychainServiceFor`
 * uses at wrap time), so two processes agree on where to look, but it does
 * not include the passphrase itself.
 */

import { stat, readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, basename, resolve } from "node:path";
import { DEFAULT_STORAGE_DIR } from "../../paths.js";
import { keychainServiceFor } from "../../wrap/passphrase.js";
import {
  readTenantRuntime,
  type TenantRuntimeState,
} from "./runtime.js";
import { readHostTenantRegistry } from "./tenant-registry.js";

export type PassphraseStatus =
  | "keychain"
  | "fallback-file"
  | "not-initialized";

export interface TenantDescriptor {
  /** Human-readable name. "default" for the legacy root, directory basename otherwise. */
  name: string;
  /** Absolute storage path. */
  storage_path: string;
  /** Directory exists on disk. Always true for returned tenants. */
  exists: true;
  /** Has `state/` subdirectory — i.e. encrypted artifacts live here. */
  initialized: boolean;
  /** `cocoon-profile.json` present (plaintext sovereignty profile written at wrap time). */
  has_profile: boolean;
  /** Keychain service name (stable hash of storage path on macOS). */
  keychain_service: string;
  /** Whether a passphrase is stored in keychain vs encrypted fallback file vs unknown. */
  passphrase_status: PassphraseStatus;
  /**
   * Best-effort last-activity ISO timestamp — most recent mtime among
   * `state/_audit/*` files. Null when no audit log yet.
   */
  last_activity: string | null;
  /**
   * Live runtime state as written by a running wrap/dashboard process.
   * Null when no process has registered or after clean shutdown.
   */
  runtime: TenantRuntimeState | null;
}

export interface DiscoveryOptions {
  /** Override `HOME` (tests). */
  home?: string;
  /** Override process.env (tests). */
  env?: NodeJS.ProcessEnv;
  /**
   * Override the base root that holds per-tenant sub-directories. Defaults
   * to `<home>/.sanctuary`. Primarily an escape hatch for tests.
   */
  root?: string;
}

const EXTRAS_FILE_NAME = "agents-extra.json";

/** Return true when path looks like an initialized Sanctuary tenant dir. */
async function isTenantDir(path: string): Promise<{
  initialized: boolean;
  hasProfile: boolean;
  passphraseStatus: PassphraseStatus;
}> {
  const [hasState, hasProfile, hasFallback] = await Promise.all([
    dirExists(join(path, "state")),
    fileExists(join(path, "cocoon-profile.json")),
    fileExists(join(path, "passphrase.enc")),
  ]);
  const initialized = hasState;
  // Passphrase status is best-effort: we can check for the fallback file
  // directly; a Keychain-stored passphrase is not directly observable from
  // the filesystem, so we treat "has profile file but no fallback file" as
  // likely-keychain. If neither present → not-initialized.
  let passphraseStatus: PassphraseStatus;
  if (hasFallback) passphraseStatus = "fallback-file";
  else if (hasProfile || hasState) passphraseStatus = "keychain";
  else passphraseStatus = "not-initialized";
  return { initialized, hasProfile, passphraseStatus };
}

async function dirExists(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isDirectory();
  } catch {
    return false;
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isFile();
  } catch {
    return false;
  }
}

async function newestAuditMtime(storagePath: string): Promise<string | null> {
  const auditDir = join(storagePath, "state", "_audit");
  let entries: string[] = [];
  try {
    entries = await readdir(auditDir);
  } catch {
    return null;
  }
  let newest = 0;
  for (const name of entries) {
    try {
      const s = await stat(join(auditDir, name));
      if (s.isFile() && s.mtimeMs > newest) newest = s.mtimeMs;
    } catch {
      // skip
    }
  }
  if (newest === 0) return null;
  return new Date(newest).toISOString();
}

async function readExtraPaths(
  root: string,
  env: NodeJS.ProcessEnv,
  options: { home: string; root: string }
): Promise<string[]> {
  const out: string[] = [];
  const fromEnv = env.SANCTUARY_AGENTS_EXTRA_PATHS;
  if (fromEnv && fromEnv.length > 0) {
    for (const part of fromEnv.split(":")) {
      const trimmed = part.trim();
      if (trimmed.length > 0) out.push(resolve(trimmed));
    }
  }
  try {
    const raw = await readFile(join(root, EXTRAS_FILE_NAME), "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) {
      for (const p of parsed) {
        if (typeof p === "string" && p.trim().length > 0) out.push(resolve(p));
      }
    }
  } catch {
    // no extras file — fine.
  }
  try {
    const registry = await readHostTenantRegistry(options);
    for (const tenant of registry.tenants) {
      if (tenant.storage_path.trim().length > 0) {
        out.push(resolve(tenant.storage_path));
      }
    }
  } catch {
    // Bad registry state should not break discovery; describeTenant below
    // still filters entries to real Sanctuary-looking directories.
  }
  // De-duplicate.
  return Array.from(new Set(out));
}

async function describeTenant(
  name: string,
  storagePath: string,
  home: string
): Promise<TenantDescriptor | null> {
  const exists = await dirExists(storagePath);
  if (!exists) return null;
  const { initialized, hasProfile, passphraseStatus } = await isTenantDir(storagePath);
  // A directory that has nothing Sanctuary-ish in it should not show up.
  if (!initialized && !hasProfile && passphraseStatus === "not-initialized") {
    return null;
  }
  const last_activity = await newestAuditMtime(storagePath);
  const runtime = await readTenantRuntime(storagePath);
  return {
    name,
    storage_path: storagePath,
    exists: true,
    initialized,
    has_profile: hasProfile,
    keychain_service: keychainServiceFor(storagePath, home),
    passphrase_status: passphraseStatus,
    last_activity,
    runtime,
  };
}

/**
 * Enumerate every Sanctuary tenant Sanctuary can find on the local host.
 * Results are sorted by name (with "default" first).
 */
export async function discoverTenants(
  options: DiscoveryOptions = {}
): Promise<TenantDescriptor[]> {
  const home = options.home ?? homedir();
  const env = options.env ?? process.env;
  const root = options.root ?? join(home, DEFAULT_STORAGE_DIR);

  const tenants: TenantDescriptor[] = [];

  // 1. Default root itself — "default" tenant when initialized.
  const rootTenant = await describeTenant("default", root, home);
  if (rootTenant) tenants.push(rootTenant);

  // 2. Immediate sub-directories of the root.
  let children: string[] = [];
  try {
    children = await readdir(root);
  } catch {
    // root missing — only extras below may return anything.
  }
  for (const child of children) {
    const childPath = join(root, child);
    // Skip files, hidden dirs, and the "state" / "backup" / etc. directories
    // that belong to the *default* tenant so we don't double-count them.
    if (child.startsWith(".")) continue;
    if (child === "state" || child === "backup" || child === "config" || child === "default") continue;
    const s = await stat(childPath).catch(() => null);
    if (!s || !s.isDirectory()) continue;
    const desc = await describeTenant(child, childPath, home);
    if (desc) tenants.push(desc);
  }

  // 3. Extras (env + file).
  const extras = await readExtraPaths(root, env, { home, root });
  for (const extra of extras) {
    if (tenants.some((t) => t.storage_path === extra)) continue;
    const desc = await describeTenant(basename(extra), extra, home);
    if (desc) tenants.push(desc);
  }

  // Warn on duplicate tenant names (defensive against extras or future collision classes).
  const seen = new Map<string, number>();
  for (const t of tenants) {
    seen.set(t.name, (seen.get(t.name) ?? 0) + 1);
  }
  for (const [name, count] of seen) {
    if (count > 1) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `[sanctuary] warning: ${count} tenants share the name "${name}". ` +
          `Use --tenant with a unique name or storage path to disambiguate.`
      );
    }
  }

  tenants.sort((a, b) => {
    if (a.name === "default") return -1;
    if (b.name === "default") return 1;
    return a.name.localeCompare(b.name);
  });
  return tenants;
}

/**
 * Resolve a single tenant by name. Returns null when no tenant matches.
 */
export async function findTenant(
  name: string,
  options: DiscoveryOptions = {}
): Promise<TenantDescriptor | null> {
  const tenants = await discoverTenants(options);
  return tenants.find((t) => t.name === name) ?? null;
}
