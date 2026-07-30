/**
 * Evidence-pack read boundary for Castle Wall observe candidates.
 *
 * The observe CLI keeps `ObserveStore.listCandidates()` best-effort for legacy
 * operator workflows. The evidence pack is different: these rows become signed
 * denied-flow prose, so a malformed persisted row fails the read closed.
 */

import type { StateStore } from "../cognitive/state-store.js";
import {
  OBSERVE_NAMESPACE,
  type CandidateObservation,
} from "../castle-wall/observe/index.js";
import {
  MALFORMED_OBSERVED_DESTINATIONS_REASON,
  validatePersistedObservedDestinationCandidate,
  type InventorySourceRead,
} from "./inventory.js";

const CANDIDATE_KEY_PREFIX = "candidate:";
const PAGE_SIZE = 100;

/**
 * Read persisted observe candidates for evidence-pack inventory. Three states:
 * valid records, verified empty (ok with zero records), or read_failed.
 */
export async function readObservedDestinationCandidatesStrict(
  stateStore: StateStore
): Promise<InventorySourceRead<CandidateObservation>> {
  const records: CandidateObservation[] = [];
  let offset = 0;
  for (;;) {
    const { keys, total } = await stateStore.list(
      OBSERVE_NAMESPACE,
      CANDIDATE_KEY_PREFIX,
      undefined,
      PAGE_SIZE,
      offset
    );
    for (const { key } of keys) {
      const result = await stateStore.read(OBSERVE_NAMESPACE, key);
      if (!result) {
        return {
          ok: false,
          records: [],
          reason: MALFORMED_OBSERVED_DESTINATIONS_REASON,
        };
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(result.value);
      } catch {
        return {
          ok: false,
          records: [],
          reason: MALFORMED_OBSERVED_DESTINATIONS_REASON,
        };
      }
      const candidate = validatePersistedObservedDestinationCandidate(parsed, key);
      if (!candidate) {
        return {
          ok: false,
          records: [],
          reason: MALFORMED_OBSERVED_DESTINATIONS_REASON,
        };
      }
      records.push(candidate);
    }
    offset += keys.length;
    if (keys.length === 0 || offset >= total) break;
  }
  return { ok: true, records };
}
