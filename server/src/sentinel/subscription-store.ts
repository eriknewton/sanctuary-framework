/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel subscription persistence.
 *
 * Persists which sentinels the operator has opted into. Read on
 * server boot to populate the dispatcher; written by the CLI +
 * dashboard subscribe/unsubscribe routes so the next server boot
 * picks up the change without re-asking.
 *
 * Storage shape: a single JSON file `sentinel-subscriptions.json` in
 * the storage path (sibling to broker-policy.json). Schema is a
 * version-stamped record of subscribed sentinel ids; nothing
 * encrypted because the file contains opt-in flags only and no
 * secret material.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

const FILE_VERSION = 1 as const;

interface PersistedSubscriptions {
  version: 1;
  subscribed: string[];
}

export function sentinelSubscriptionsPath(storagePath: string): string {
  return join(storagePath, "sentinel-subscriptions.json");
}

/**
 * Load subscriptions from disk. Returns an empty set when the file
 * does not yet exist or cannot be parsed; the file is treated as a
 * cache, not a source of truth.
 */
export async function loadSentinelSubscriptions(
  storagePath: string,
): Promise<Set<string>> {
  const filePath = sentinelSubscriptionsPath(storagePath);
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedSubscriptions;
    if (parsed.version !== FILE_VERSION) return new Set();
    if (!Array.isArray(parsed.subscribed)) return new Set();
    const cleaned = parsed.subscribed.filter(
      (id): id is string => typeof id === "string" && id.length > 0,
    );
    return new Set(cleaned);
  } catch {
    return new Set();
  }
}

/**
 * Persist subscriptions to disk. Atomically replaces the file.
 */
export async function saveSentinelSubscriptions(
  storagePath: string,
  subscribed: Iterable<string>,
): Promise<void> {
  const filePath = sentinelSubscriptionsPath(storagePath);
  await mkdir(dirname(filePath), { recursive: true });
  const payload: PersistedSubscriptions = {
    version: FILE_VERSION,
    subscribed: [...new Set(subscribed)].filter((s) => s.length > 0).sort(),
  };
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, {
    mode: 0o600,
  });
}
