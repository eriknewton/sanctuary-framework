//! IPC surface: framing, message envelopes, JSON-RPC method dispatch.
//!
//! PR 2a ships the full framing parser plus the message envelope types.
//! The dispatcher (server-side accept loop, handshake, JSON-RPC method
//! routing) ships in PR 2b once the kernel-touching modules have real
//! implementations to dispatch into.

pub mod framing;
pub mod messages;
