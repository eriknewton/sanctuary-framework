//! A live append consumes one marker completion into one matching effect token.
use super::{append_contract, records, writer_protocol};
use serde_json::Value;

/// Required effect intent is frozen from W's independently admitted flow and bounds.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EffectIntent {
    OpenAdmission { flow: Value, payload: Value },
    LinkBinding { flow: Value, payload: Value },
    PacketAllowance { flow: Value, payload: Value },
}
impl EffectIntent {
    /// Match every flow and payload field against the verified record, including its identifiers and bounds.
    pub fn matches(&self, body: &Value) -> bool {
        let (kind, flow, payload) = match self {
            Self::OpenAdmission { flow, payload } => ("open", flow, payload),
            Self::LinkBinding { flow, payload } => ("link", flow, payload),
            Self::PacketAllowance { flow, payload } => ("allowance", flow, payload),
        };
        body["record_kind"] == kind
            && &body["payload"]["context"]["flow"] == flow
            && &body["payload"] == payload
    }
}
/// Owned durable marker result. It is never reconstructed from a reloaded row.
pub struct MarkerCompletion {
    sequence: u64,
    commitment: String,
    envelope_sha256: String,
}
#[cfg(feature = "test-isolation")]
pub(super) enum MarkerObservation {
    Sequence,
    Commitment,
    Envelope,
}
impl MarkerCompletion {
    // The sealed actor fixture observes one decoded identity field; it never creates a completion capability.
    #[cfg(feature = "test-isolation")]
    pub(super) fn observe_for_test(&mut self, observation: MarkerObservation) {
        match observation {
            MarkerObservation::Sequence => self.sequence ^= 1,
            MarkerObservation::Commitment => self.commitment.push('x'),
            MarkerObservation::Envelope => self.envelope_sha256.push('x'),
        }
    }
    pub(super) fn from_wal(sequence: u64, commitment: String, envelope_sha256: String) -> Self {
        Self {
            sequence,
            commitment,
            envelope_sha256,
        }
    }
}
/// Consumers must take this token by value. Its fields cannot authorize another append.
pub struct EffectPermit {
    sequence: u64,
    id: String,
    expires: u64,
    commitment: String,
}
impl EffectPermit {
    pub(crate) fn construct(
        marker: MarkerCompletion,
        intent: &EffectIntent,
        envelope: &[u8],
        id: String,
        now: u64,
        expires: u64,
    ) -> Option<Self> {
        let record = writer_protocol::decode_envelope(envelope).ok()?;
        let identity = append_contract::identity(envelope)?;
        // The live marker names the exact verified E; caller intent never substitutes its own record identity.
        if now >= expires
            || !intent.matches(&record["body"])
            || identity["sequence"] != marker.sequence
            || identity["envelope_sha256"] != marker.envelope_sha256
            || records::join_commitment(&record)? != marker.commitment
        {
            return None;
        }
        Some(Self {
            sequence: marker.sequence,
            id,
            expires,
            commitment: marker.commitment,
        })
    }
    /// Isolated consumers exercise the exact marker-to-token transition, including its time and intent checks.
    #[cfg(feature = "test-isolation")]
    pub fn from_marker_for_test(
        marker: MarkerCompletion,
        intent: &EffectIntent,
        envelope: &[u8],
        id: String,
        now: u64,
        expires: u64,
    ) -> Option<Self> {
        Self::construct(marker, intent, envelope, id, now, expires)
    }
    /// Read-only receipt fields let a by-value test sink observe the one delivered effect.
    pub fn receipt(&self) -> (u64, &str, u64, &str) {
        (self.sequence, &self.id, self.expires, &self.commitment)
    }
}
/// Composition supplies a sink that consumes tokens immediately, without waiting or cloning.
pub trait EffectSink: Send {
    fn deliver(&mut self, permit: EffectPermit);
}
