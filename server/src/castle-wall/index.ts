/**
 * Castle Wall (Castle Architecture Layer 1) : public module surface.
 *
 * PR 1 of 6 ships interfaces and types only. No runtime, no OS calls. The
 * Linux filter daemon (PR 2), macOS Network Extension (PR 3), IPC plus
 * dashboard wiring (PR 4), audit plus menubar approval wiring (PR 5), and
 * cross-platform integration tests (PR 6) build against these types.
 *
 * Source: Castle_Wall_Phase1_Scope_Lock_2026-05-03.md (ratified post-Codex
 * review). Parent ADR: Castle_Architecture_ADR_2026-04-30.md.
 */

export * from "./constants.js";
export * from "./errors.js";

export * from "./allowlist/index.js";
export * from "./ipc/index.js";
export * from "./audit/index.js";
export * from "./decision/index.js";
export * from "./failure/index.js";
export * from "./approval/index.js";
export * from "./runtime/index.js";
export * from "./observe/index.js";
export * from "./egress-proxy.js";
