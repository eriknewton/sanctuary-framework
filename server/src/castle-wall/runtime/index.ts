/**
 * Castle Wall runtime module.
 *
 * PR 2a public surface: lifecycle wrapper, IPC client, manifest publisher,
 * audit consumer, approval stub, installer plan helper, firewall detection,
 * curated-allowlist data. PR 2b adds the daemon-process supervisor and
 * binds the actual Linux UDS transport on top of the IPC client; PR 5
 * replaces the approval stub with the menubar UI.
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
