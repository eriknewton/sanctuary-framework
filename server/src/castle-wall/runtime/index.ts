/**
 * Castle Wall runtime module.
 *
 * PR 2a public surface: lifecycle wrapper, IPC client, manifest publisher,
 * audit consumer, approval stub, installer plan helper, firewall detection,
 * curated-allowlist data. The Linux daemon launcher + UDS transport + audit
 * drain pull-loop (the "PR 2b" piece) and the opt-in producer-signed activation
 * gate (C4) bind the real Linux path on top of the IPC client; PR 5 replaces
 * the approval stub with the menubar UI.
 *
 * Source: Castle_Wall_Phase1_Scope_Lock_2026-05-03.md (sections 4-8).
 */

export * from "./errors.js";
export * from "./curated-allowlist.js";
export * from "./detect-firewall.js";
export * from "./installer.js";
export * from "./manifest-publisher.js";
export * from "./audit-consumer.js";
export * from "./approval-stub.js";
export * from "./ipc-client.js";
export * from "./lifecycle.js";
export * from "./macos-flow-events.js";
export * from "./macos-ipc-listener.js";
export * from "./enforcement-availability.js";
export * from "./system-resolvers.js";
export * from "./macos-daemon.js";
export * from "./linux-daemon.js";
export * from "./linux-audit-drain.js";
export * from "./linux-activation-gate.js";
