/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-3 Anomaly subscription persistence.
 *
 * Mirrors the Phi-1 sentinel subscription-store. Persists which
 * (detector_id, classifier_id) tuples the operator has opted into.
 * Read on server boot to populate the dispatcher; written by the
 * CLI + dashboard subscribe routes so the next server boot picks up
 * the change without re-asking.
 *
 * Storage shape: single JSON file `anomaly-subscriptions.json` in
 * the storage path. Version-stamped; unencrypted because the file
 * contains opt-in flags only and no secret material.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

const FILE_VERSION = 1 as const;

export interface AnomalySubscriptionTuple {
  detector_id: string;
  classifier_id: string;
}

interface PersistedSubscriptions {
  version: 1;
  subscribed: AnomalySubscriptionTuple[];
}

export function anomalySubscriptionsPath(storagePath: string): string {
  return join(storagePath, "anomaly-subscriptions.json");
}

/**
 * Load subscriptions from disk. Returns an empty array when the
 * file does not yet exist or cannot be parsed; cached, not source
 * of truth.
 */
export async function loadAnomalySubscriptions(
  storagePath: string,
): Promise<AnomalySubscriptionTuple[]> {
  const filePath = anomalySubscriptionsPath(storagePath);
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedSubscriptions;
    if (parsed.version !== FILE_VERSION) return [];
    if (!Array.isArray(parsed.subscribed)) return [];
    return parsed.subscribed.filter(
      (t): t is AnomalySubscriptionTuple =>
        t !== null &&
        typeof t === "object" &&
        typeof (t as AnomalySubscriptionTuple).detector_id === "string" &&
        typeof (t as AnomalySubscriptionTuple).classifier_id === "string",
    );
  } catch {
    return [];
  }
}

/** Save subscriptions to disk. Creates the parent dir if missing. */
export async function saveAnomalySubscriptions(
  storagePath: string,
  subscriptions: AnomalySubscriptionTuple[],
): Promise<void> {
  const filePath = anomalySubscriptionsPath(storagePath);
  await mkdir(dirname(filePath), { recursive: true });
  const payload: PersistedSubscriptions = {
    version: FILE_VERSION,
    // Deduplicate.
    subscribed: dedupe(subscriptions),
  };
  await writeFile(filePath, JSON.stringify(payload, null, 2), {
    mode: 0o600,
  });
}

function dedupe(items: AnomalySubscriptionTuple[]): AnomalySubscriptionTuple[] {
  const seen = new Set<string>();
  const out: AnomalySubscriptionTuple[] = [];
  for (const item of items) {
    const key = `${item.detector_id}|${item.classifier_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
