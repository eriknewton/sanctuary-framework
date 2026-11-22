/** Namespace policy shared by agent discovery and local job storage. */
// The three reserved local stores have one source; compartments extend this predicate.
// Must match listNamespacesForAgentDiscovery and totalSizeOfNonReservedNamespaces
// in storage/filesystem.ts and storage/memory.ts, and the dispatch in
// storage/directory-capability-worker.ts.
export const AGENT_DISCOVERY_SKIPPED_NAMESPACES = [
  "_local_results", "_local_disclosure", "_local_oplog",
] as const;

export function isAgentDiscoverySkippedNamespace(name: string): boolean {
  return AGENT_DISCOVERY_SKIPPED_NAMESPACES.some((namespace) => namespace === name);
}

// Must match isReservedNamespace in cognitive/state-store.ts; storage cannot import its consumers.
export function isAgentAggregateReservedNamespace(name: string): boolean {
  return name.startsWith("_");
}
