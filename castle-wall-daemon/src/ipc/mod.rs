//! IPC surface: framing, message envelopes, JSON-RPC method dispatch.
//!
//! PR 2a shipped the framing parser plus the message envelope types. PR 2b
//! adds the accept-loop server with the Ed25519 challenge-response handshake
//! (`auth`) and the JSON-RPC method dispatcher (`server`). The kernel-touching
//! handlers under those JSON-RPC methods land alongside in Checkpoints 2-3.

pub mod auth;
pub mod framing;
pub mod messages;
pub mod server;
