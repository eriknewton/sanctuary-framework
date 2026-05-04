//! IPC message envelopes shared between Sanctuary main and the filter daemon.
//!
//! These types mirror `server/src/castle-wall/ipc/messages.ts`. The
//! serde-derived JSON shape is the wire shape.

use serde::{Deserialize, Serialize};

/// Tagged union of every Castle Wall IPC message body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum IpcMessage {
    #[serde(rename = "status_request")]
    StatusRequest { request_id: String },
    #[serde(rename = "status_response")]
    StatusResponse {
        request_id: String,
        uptime_seconds: u64,
        loaded_manifest_signature_b64url: Option<String>,
        loaded_rule_count: u32,
        no_wall_engaged: bool,
    },
    #[serde(rename = "policy_reload_request")]
    PolicyReloadRequest {
        request_id: String,
        manifest_path: String,
    },
    #[serde(rename = "policy_reload_response")]
    PolicyReloadResponse {
        request_id: String,
        ok: bool,
        loaded_manifest_signature_b64url: Option<String>,
        loaded_rule_count: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "decision_request")]
    DecisionRequest {
        request_id: String,
        surface: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        timeout_seconds: u32,
    },
    #[serde(rename = "decision_response")]
    DecisionResponse {
        request_id: String,
        decision: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        learn: Option<LearnedDecisionEnvelope>,
    },
    #[serde(rename = "audit_emit")]
    AuditEmit {
        event: serde_json::Value,
    },
    #[serde(rename = "audit_emit_metric_batch")]
    AuditEmitMetricBatch {
        window_start: String,
        window_end: String,
        by_destination: Vec<MetricBatchEntry>,
    },
    #[serde(rename = "unlock_notification")]
    UnlockNotification {
        fortress_id: String,
        unlocked_at: String,
    },
    #[serde(rename = "lock_notification")]
    LockNotification {
        fortress_id: String,
        locked_at: String,
    },
    #[serde(rename = "handshake_challenge")]
    HandshakeChallenge { nonce_b64url: String },
    #[serde(rename = "handshake_response")]
    HandshakeResponse {
        fortress_id: String,
        signing_key_id: String,
        nonce_signature_b64url: String,
    },
}

/// JSON-RPC-style outer envelope when bodies need a request/notification tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub jsonrpc: String,
    pub method: String,
    pub params: IpcMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcDestination {
    pub host: Option<String>,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub hostname_source: Option<String>,
    pub opaque: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcAgentAttribution {
    pub id: String,
    pub template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LearnedDecisionEnvelope {
    pub granularity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricBatchEntry {
    pub host: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub agent_id: String,
    pub allowed_count: u64,
    pub blocked_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_challenge_round_trip() {
        let msg = IpcMessage::HandshakeChallenge {
            nonce_b64url: "AAAA".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
        assert!(json.contains("\"type\":\"handshake_challenge\""));
    }

    #[test]
    fn decision_response_with_learn_round_trip() {
        let msg = IpcMessage::DecisionResponse {
            request_id: "req".to_string(),
            decision: "allow_always".to_string(),
            learn: Some(LearnedDecisionEnvelope {
                granularity: "per_template_etld1".to_string(),
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn decision_response_without_learn_omits_field() {
        let msg = IpcMessage::DecisionResponse {
            request_id: "req".to_string(),
            decision: "deny_once".to_string(),
            learn: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("learn"));
    }

    #[test]
    fn unknown_type_fails_to_deserialize() {
        let raw = "{\"type\":\"bogus\",\"x\":1}";
        let result: Result<IpcMessage, _> = serde_json::from_str(raw);
        assert!(result.is_err());
    }
}
