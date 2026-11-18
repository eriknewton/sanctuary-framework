//! One authenticated connection owns a bounded delivery outside the WAL executor.
use super::{
    append_actor::AppendActor,
    append_contract,
    business_wal::{PolledBusinessSink, PolledSinkAdapter, Refusal, Result, TsReleaseFact},
};
use crate::ipc::messages::BusinessDrainEvent;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Required server endpoint. Only the native writer adapter can publish a delivery.
pub struct BusinessDeliveryHandle {
    state: Arc<Mutex<DeliveryState>>,
}
#[derive(Default)]
struct DeliveryState {
    next_owner: u64,
    owner: Option<u64>,
    envelope: Option<Vec<u8>>,
    ack: Option<Value>,
    fact_issued: bool,
    fact_pending: bool,
}
/// Writer-side pump. Peer waits never hold its actor's one-operation store slot.
/// Must match business-record-consumer.ts: ACK follows durable exact acceptance.
pub struct BusinessDelivery {
    adapter: PolledSinkAdapter<NativeSink>,
    state: Arc<Mutex<DeliveryState>>,
    fact: Option<TsReleaseFact>,
    offered: Option<Vec<u8>>,
    submitted: bool,
}
struct NativeSink(Arc<Mutex<DeliveryState>>);
#[cfg(not(feature = "test-isolation"))]
impl super::business_wal::sink_seal::Sealed for NativeSink {}
impl BusinessDeliveryHandle {
    /// Create the two sealed endpoints; neither endpoint accepts caller-provided ACK authority.
    pub fn channel() -> (BusinessDelivery, Self) {
        let state = Arc::new(Mutex::new(DeliveryState::default()));
        (
            BusinessDelivery {
                adapter: PolledSinkAdapter::new(NativeSink(state.clone())),
                state: state.clone(),
                fact: None,
                offered: None,
                submitted: false,
            },
            Self { state },
        )
    }
    pub(crate) fn connect(&self) -> Result<BusinessSession> {
        let mut state = self.state.try_lock().map_err(|_| Refusal::Held)?;
        // A timeout is not ownership transfer; only the previous connection's drop releases this slot.
        if state.owner.is_some() {
            return Err(Refusal::Held);
        }
        state.next_owner = state.next_owner.checked_add(1).ok_or(Refusal::Capacity)?;
        let owner = state.next_owner;
        state.owner = Some(owner);
        Ok(BusinessSession {
            state: self.state.clone(),
            owner,
            served: None,
        })
    }
}
impl BusinessDelivery {
    /// Offer only a WAL-minted token to the authenticated connection owner.
    pub fn offer(&mut self, token: &super::business_wal::DeliveryToken) -> Result<()> {
        self.adapter.offer(token)
    }
    /// Poll correlated durable ACK evidence without entering the WAL executor.
    pub fn complete(&mut self) -> Result<Option<TsReleaseFact>> {
        self.adapter.poll()
    }
    /// Poll alongside the actor; an incomplete local fact keeps the same delivery until readback.
    ///
    /// Error contract for the driver: `Held`, `Deadline` and `Conflict` are retryable on a
    /// later pump, because none consumes the retained fact, the offer or the actor's token.
    /// `Conflict` reports a refused ACK: the adapter's wait stays pending and the sink latch
    /// is released, so only a later correlated ACK on the same wait can supply the one fact.
    /// If that release finds the lock poisoned, `Held` replaces `Conflict` and the latch stays
    /// set; every later pump also reports `Held`, which fails closed until restart replay.
    /// Dropping this delivery loses only in-memory state (a polled fact input and the offer
    /// latch); rows and cursors are durable, and restart replay derives the same delivery
    /// again. A disconnect while a fact persists without an intent leaves the actor Held:
    /// that fails closed, and restart replay is the recovery.
    pub fn pump(&mut self, actor: &mut AppendActor) -> Result<()> {
        if let Some(fact) = actor.take_failed_delivery() {
            self.fact = Some(fact);
            self.submitted = false;
        }
        let token = actor.pending_delivery();
        if self.submitted {
            if token.is_some_and(|t| self.offered.as_deref() == Some(t.envelope())) {
                return Ok(());
            }
            // Token retirement follows both WAL readbacks; only now is the consumed ACK final.
            self.state
                .try_lock()
                .map_err(|_| Refusal::Held)?
                .fact_issued = true;
            self.offered = None;
            self.submitted = false;
        }
        if self.offered.is_none() {
            let Some(token) = token else {
                return Ok(());
            };
            self.adapter.offer(token)?;
            self.offered = Some(token.envelope().to_vec());
        }
        if self.fact.is_none() {
            self.fact = self.adapter.poll()?;
        }
        // complete_delivery consumes a fact only after checking executor availability.
        // The actor's store slot must be free before ownership of that capability moves.
        // Must match AppendActor::can_complete_delivery in either fact order; pending peer waits retain their owner.
        if self.fact.is_some() && actor.can_complete_delivery() {
            actor.complete_delivery(&mut self.fact)?;
            self.submitted = true;
        }
        Ok(())
    }
}
impl PolledBusinessSink for NativeSink {
    fn offer(&mut self, envelope: &[u8]) -> Result<()> {
        let mut state = self.0.try_lock().map_err(|_| Refusal::Held)?;
        if state.envelope.is_some() && !state.fact_issued {
            return if state.envelope.as_deref() == Some(envelope) {
                Ok(())
            } else {
                Err(Refusal::Held)
            };
        }
        state.envelope = Some(envelope.to_vec());
        state.ack = None;
        state.fact_issued = false;
        state.fact_pending = false;
        Ok(())
    }
    fn poll(&mut self) -> Result<Option<Value>> {
        let mut state = self.0.try_lock().map_err(|_| Refusal::Held)?;
        // fact_pending is dominated by pending consumption in business_wal.rs; keep both one-fact guards paired.
        if state.fact_issued || state.fact_pending {
            return Ok(None);
        }
        let ack = state.ack.take();
        if ack.is_some() {
            state.fact_pending = true;
        }
        Ok(ack)
    }
    fn refused(&mut self) -> Result<()> {
        // A blocking lock: session critical sections do no I/O, and a contended refusal must not leave the latch set.
        // A poisoned lock keeps the latch and fails closed until restart replay.
        let mut state = self.0.lock().map_err(|_| Refusal::Held)?;
        // The adapter still holds its pending wait, so clearing the latch cannot release a second fact.
        // Must match the refusal arm of PolledSinkAdapter::poll in business_wal.rs.
        state.fact_pending = false;
        Ok(())
    }
}
pub(crate) struct BusinessSession {
    state: Arc<Mutex<DeliveryState>>,
    owner: u64,
    served: Option<Value>,
}
impl BusinessSession {
    pub(crate) fn offer(&mut self) -> Result<Option<BusinessDrainEvent>> {
        let state = self.state.try_lock().map_err(|_| Refusal::Held)?;
        if state.owner != Some(self.owner) {
            return Err(Refusal::Authority);
        }
        let Some(envelope) = &state.envelope else {
            return Ok(None);
        };
        if state.fact_issued {
            return Ok(None);
        }
        let identity = append_contract::identity(envelope).ok_or(Refusal::Shape)?;
        let record: Value = serde_json::from_slice(envelope).map_err(|_| Refusal::Shape)?;
        let body = &record["body"];
        let event = BusinessDrainEvent {
            seq: identity["sequence"].as_u64().ok_or(Refusal::Shape)?,
            captured_at_unix_ms: body["captured_at_unix_ms"].as_u64().ok_or(Refusal::Shape)?,
            prior_sha256_hex: body["prior_commitment"]
                .as_str()
                .and_then(|v| v.strip_prefix("sha256:"))
                .map(str::to_string),
            event_canonical_json: crate::smb::jcs::encode(body).map_err(|_| Refusal::Shape)?,
            critical: true,
            business_envelope: URL_SAFE_NO_PAD.encode(envelope),
            producer_signature_b64url: None,
            producer_key_id: None,
        };
        self.served = Some(identity);
        Ok(Some(event))
    }
    pub(crate) fn acknowledge(&mut self, ack: &Value) -> Result<()> {
        let mut state = self.state.try_lock().map_err(|_| Refusal::Held)?;
        // Correlation alone grants nothing: this session passed the shared UID/key gate and owns the offered token.
        if state.owner != Some(self.owner)
            || !append_contract::shape("ack", ack)
            || self.served.as_ref() != Some(&ack["identity"])
            || state
                .envelope
                .as_deref()
                .and_then(append_contract::identity)
                .as_ref()
                != Some(&ack["identity"])
        {
            return Err(Refusal::Authority);
        }
        // fact_pending must stay paired with pending consumption in business_wal.rs before another ACK can mint a fact.
        if !state.fact_issued && !state.fact_pending {
            state.ack = Some(ack.clone());
        }
        Ok(())
    }
}
impl Drop for BusinessSession {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if state.owner == Some(self.owner) {
                state.owner = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_owner_reconnect_exact_replay_and_wrong_identity() {
        let vectors: Value =
            serde_json::from_str(include_str!("record_join_vectors.json")).unwrap();
        let envelope = crate::smb::jcs::encode(&vectors["cases"][0]["records"][0])
            .unwrap()
            .into_bytes();
        let (_, handle) = BusinessDeliveryHandle::channel();
        let mut native = NativeSink(handle.state.clone());
        native.offer(&envelope).unwrap();
        let mut first = handle.connect().unwrap();
        assert!(handle.connect().is_err(), "one connection owns delivery");
        let ack = serde_json::json!({"version":1,"identity":append_contract::identity(&envelope).unwrap()});
        assert!(
            first.acknowledge(&ack).is_err(),
            "unserved identity grants no ACK authority"
        );
        assert!(native.poll().unwrap().is_none());
        let event = first.offer().unwrap().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(event.business_envelope).unwrap(),
            envelope
        );
        assert!(event.producer_signature_b64url.is_none() && event.producer_key_id.is_none());
        let mut wrong = ack.clone();
        wrong["identity"]["sequence"] = serde_json::json!(2);
        assert!(first.acknowledge(&wrong).is_err());
        assert!(
            native.poll().unwrap().is_none(),
            "wrong identity mints no fact input"
        );
        drop(first);
        let mut second = handle.connect().unwrap();
        assert!(
            second.acknowledge(&ack).is_err(),
            "reconnect must re-serve exact E"
        );
        second.offer().unwrap().unwrap();
        second.acknowledge(&ack).unwrap();
        second.acknowledge(&ack).unwrap();
        assert_eq!(native.poll().unwrap(), Some(ack.clone()));
        second.acknowledge(&ack).unwrap();
        assert!(
            native.poll().unwrap().is_none(),
            "exact replay advances only once"
        );
    }

    #[test]
    fn refused_ack_releases_pending_fact_latch() {
        let vectors: Value =
            serde_json::from_str(include_str!("record_join_vectors.json")).unwrap();
        let envelope = crate::smb::jcs::encode(&vectors["cases"][0]["records"][0])
            .unwrap()
            .into_bytes();
        let (_, handle) = BusinessDeliveryHandle::channel();
        let mut native = NativeSink(handle.state.clone());
        native.offer(&envelope).unwrap();
        let mut session = handle.connect().unwrap();
        session.offer().unwrap().unwrap();
        let ack = serde_json::json!({"version":1,"identity":append_contract::identity(&envelope).unwrap()});
        session.acknowledge(&ack).unwrap();
        assert_eq!(native.poll().unwrap(), Some(ack.clone()));
        session.acknowledge(&ack).unwrap();
        assert!(
            native.poll().unwrap().is_none(),
            "pending fact holds the latch"
        );
        native.refused().unwrap();
        assert!(
            !handle.state.lock().unwrap().fact_pending,
            "refused ACK releases the pending fact latch"
        );
        session.acknowledge(&ack).unwrap();
        assert_eq!(
            native.poll().unwrap(),
            Some(ack),
            "a correlated ACK still supplies the one fact input"
        );
    }
}
