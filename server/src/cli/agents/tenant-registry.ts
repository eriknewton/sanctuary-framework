/**
 * Host-level tenant registry for storage paths outside ~/.sanctuary.
 *
 * `sanctuary agents list` can discover tenants under the default root by
 * scanning directories, but wrapped drill tenants often live under /tmp or
 * another operator-selected fortress path. Wrap registers those absolute
 * paths here so later CLI invocations can find them without env vars.
 */

import { chmod, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { DEFAULT_STORAGE_DIR } from "../../paths.js";

export const TENANTS_REGISTRY_FILE_NAME = "tenants.json";

export interface HostTenantRegistryEntry {
  name: string;
  storage_path: string;
  registered_at: string;
  updated_at: string;
}

export interface HostTenantRegistry {
  version: 1;
  tenants: HostTenantRegistryEntry[];
}

export interface HostTenantRegistryOptions {
  home?: string;
  root?: string;
  now?: Date;
}

const LOCK_RETRY_MS = 25;
const LOCK_TIMEOUT_MS = 5000;

function registryRoot(options: HostTenantRegistryOptions = {}): string {
  const home = options.home ?? homedir();
  return options.root ?? join(home, DEFAULT_STORAGE_DIR);
}

function registryPath(options: HostTenantRegistryOptions = {}): string {
  return join(registryRoot(options), TENANTS_REGISTRY_FILE_NAME);
}

function lockPath(options: HostTenantRegistryOptions = {}): string {
  return `${registryPath(options)}.lock`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

async function withRegistryLock<T>(
  options: HostTenantRegistryOptions,
  fn: () => Promise<T>,
): Promise<T> {
  const lock = lockPath(options);
  const started = Date.now();
  await mkdir(dirname(lock), { recursive: true, mode: 0o700 });

  while (true) {
    let handle: Awaited<ReturnType<typeof open>> | null = null;
    try {
      handle = await open(lock, "wx", 0o600);
      await handle.writeFile(
        JSON.stringify({ pid: process.pid, created_at: new Date().toISOString() }) + "\n",
        "utf-8",
      );
      await handle.close();
      handle = null;
      try {
        return await fn();
      } finally {
        await rm(lock, { force: true });
      }
    } catch (err) {
      if (handle) await handle.close().catch(() => {});
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw err;
      if (Date.now() - started > LOCK_TIMEOUT_MS) {
        throw new Error(`timed out waiting for tenant registry lock at ${lock}`);
      }
      await sleep(LOCK_RETRY_MS);
    }
  }
}

function parseRegistry(raw: string): HostTenantRegistry {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") return { version: 1, tenants: [] };
  const tenantsRaw = (parsed as { tenants?: unknown }).tenants;
  if (!Array.isArray(tenantsRaw)) return { version: 1, tenants: [] };

  const tenants: HostTenantRegistryEntry[] = [];
  for (const entry of tenantsRaw) {
    if (!entry || typeof entry !== "object") continue;
    const maybe = entry as Partial<HostTenantRegistryEntry>;
    if (
      typeof maybe.name !== "string" ||
      typeof maybe.storage_path !== "string" ||
      maybe.storage_path.trim().length === 0
    ) {
      continue;
    }
    tenants.push({
      name: maybe.name,
      storage_path: resolve(maybe.storage_path),
      registered_at:
        typeof maybe.registered_at === "string" ? maybe.registered_at : new Date(0).toISOString(),
      updated_at:
        typeof maybe.updated_at === "string" ? maybe.updated_at : new Date(0).toISOString(),
    });
  }
  return { version: 1, tenants };
}

export async function readHostTenantRegistry(
  options: HostTenantRegistryOptions = {},
): Promise<HostTenantRegistry> {
  try {
    const raw = await readFile(registryPath(options), "utf-8");
    return parseRegistry(raw);
  } catch {
    return { version: 1, tenants: [] };
  }
}

async function writeHostTenantRegistryAtomic(
  registry: HostTenantRegistry,
  options: HostTenantRegistryOptions = {},
): Promise<void> {
  const path = registryPath(options);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmp, JSON.stringify(registry, null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });
  await chmod(tmp, 0o600);
  await rename(tmp, path);
  await chmod(path, 0o600);
}

export async function registerHostTenant(
  storagePath: string,
  options: HostTenantRegistryOptions = {},
): Promise<HostTenantRegistryEntry> {
  const absoluteStoragePath = resolve(storagePath);
  const now = (options.now ?? new Date()).toISOString();
  let result: HostTenantRegistryEntry | null = null;

  await withRegistryLock(options, async () => {
    const registry = await readHostTenantRegistry(options);
    const existing = registry.tenants.find((t) => t.storage_path === absoluteStoragePath);
    if (existing) {
      existing.name = basename(absoluteStoragePath);
      existing.updated_at = now;
      result = existing;
    } else {
      result = {
        name: basename(absoluteStoragePath),
        storage_path: absoluteStoragePath,
        registered_at: now,
        updated_at: now,
      };
      registry.tenants.push(result);
    }
    registry.tenants.sort((a, b) => a.name.localeCompare(b.name));
    await writeHostTenantRegistryAtomic(registry, options);
  });

  return result!;
}
