/**
 * Sanctuary MCP Proxy Router - Public surface.
 *
 * Wraps upstream MCP tools through the full Sanctuary enforcement chain
 * (injection scan, approval gate, context gating, governor, remote-bound
 * privacy filter, audit) and re-namespaces them as proxy/{server}/{tool}.
 *
 * ClientManager owns the upstream connection lifecycle; ProxyRouter runs
 * the per-call enforcement path; the dynamic registry republishes the
 * proxied tool list on discovery changes; the SSRF validator guards
 * SSE-transport URLs before any bytes leave the fortress. Native
 * sanctuary/* tools are never affected by this layer.
 */

export * from "./client-manager.js";
export * from "./proxy-router.js";
export * from "./dynamic-proxy.js";
export * from "./ssrf-validator.js";
