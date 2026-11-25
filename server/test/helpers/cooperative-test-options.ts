// fail-before-exempt: a test helper only; the namespace insert store it stands in for has its own witnesses.
/** Required cooperative-factory options that a direct-factory test supplies as recording no-ops. */
import type { BaselineNamespaceInserts } from "../../src/principal-policy/baseline.js";

/** A namespace insert store that records each namespace and writes nothing. */
export function recordingNamespaceInserts(): Pick<BaselineNamespaceInserts, "record"> & { recorded: string[] } {
  const recorded: string[] = [];
  return {
    recorded,
    async record(namespace: string) {
      recorded.push(namespace);
      return [];
    },
  };
}
