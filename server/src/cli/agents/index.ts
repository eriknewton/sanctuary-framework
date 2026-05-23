/**
 * Sanctuary MCP Server — `sanctuary agents` public entry
 *
 * Re-export surface for the multi-tenant inventory CLI + runtime hint
 * helpers. The hint helpers are used by the wrap + standalone dashboard
 * flows so a running instance advertises its actual dashboard port.
 */

export {
  discoverTenants,
  findTenant,
  type TenantDescriptor,
  type PassphraseStatus,
  type DiscoveryOptions,
} from "./discovery.js";

export {
  probeTenantDashboard,
  type HealthProbeResult,
  type HealthProbeOptions,
} from "./health.js";

export {
  writeTenantRuntime,
  readTenantRuntime,
  clearTenantRuntime,
  RUNTIME_FILE_NAME,
  type TenantRuntimeState,
} from "./runtime.js";

export {
  registerHostTenant,
  readHostTenantRegistry,
  TENANTS_REGISTRY_FILE_NAME,
  type HostTenantRegistry,
  type HostTenantRegistryEntry,
  type HostTenantRegistryOptions,
} from "./tenant-registry.js";

export {
  runAgentsCommand,
  printAgentsHelp,
  type AgentsCommandArgs,
} from "./cli.js";
