//! Operator approval-prompt coalescing and replay protection.
//!
//! Per scope-lock §5 amendment 2 + Codex amendment: novel-destination
//! prompts are coalesced by `(agent / template, eTLD+1 or host, port,
//! window)` with a default cap of 5 prompts per 30s per agent. Each
//! prompt issued carries a 16-byte random nonce; approval responses MUST
//! present the matching nonce within a 5-minute window.
//!
//! PR 2a ships pure data structures (window record, nonce store) plus a
//! deterministic decision function that PR 2b drives from the daemon's
//! prompt-emit path. PR 2b wires the random nonce generation and the
//! 5-minute expiry sweep.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-agent prompt-flood window state.
#[derive(Debug, Clone, Copy)]
pub struct CoalescingWindow {
    pub count: u32,
    pub window_started_at: Instant,
}

/// Coalescing config; defaults match scope-lock §5.
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    pub default_cap_per_agent: u32,
    pub default_window: Duration,
    pub per_template_overrides: HashMap<String, (u32, Duration)>,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            default_cap_per_agent: 5,
            default_window: Duration::from_secs(30),
            per_template_overrides: HashMap::new(),
        }
    }
}

/// Decision returned by the coalescer for one would-be prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceDecision {
    Emit,
    SuppressFloodCap,
}

/// Pure decision function: given the prior window and config, decide whether
/// to emit a new prompt or suppress with `prompt_flood_blocked`. Returns the
/// updated window state alongside the decision.
pub fn decide_coalesce(
    prior: Option<CoalescingWindow>,
    now: Instant,
    config: &CoalescingConfig,
    template: &str,
) -> (CoalesceDecision, CoalescingWindow) {
    let (cap, window) = config
        .per_template_overrides
        .get(template)
        .copied()
        .unwrap_or((config.default_cap_per_agent, config.default_window));

    let mut state = match prior {
        Some(prior) if now.duration_since(prior.window_started_at) < window => prior,
        _ => CoalescingWindow {
            count: 0,
            window_started_at: now,
        },
    };

    if state.count >= cap {
        return (CoalesceDecision::SuppressFloodCap, state);
    }
    state.count += 1;
    (CoalesceDecision::Emit, state)
}

/// Nonce store for replay protection on approval responses.
#[derive(Debug, Default)]
pub struct NonceStore {
    issued: HashMap<String, Instant>,
    consumed: HashMap<String, Instant>,
}

impl NonceStore {
    pub fn record_issued(&mut self, nonce_hex: &str, now: Instant) {
        self.issued.insert(nonce_hex.to_string(), now);
    }

    /// Validate that a presented nonce was issued, has not been consumed, and
    /// has not aged past `expiry`. On success, marks the nonce consumed and
    /// returns Ok; on failure returns the reason.
    pub fn try_consume(
        &mut self,
        nonce_hex: &str,
        now: Instant,
        expiry: Duration,
    ) -> Result<(), NonceError> {
        if self.consumed.contains_key(nonce_hex) {
            return Err(NonceError::AlreadyConsumed);
        }
        let issued_at = self.issued.get(nonce_hex).copied();
        match issued_at {
            None => Err(NonceError::Unknown),
            Some(t) if now.duration_since(t) > expiry => Err(NonceError::Expired),
            Some(_) => {
                self.issued.remove(nonce_hex);
                self.consumed.insert(nonce_hex.to_string(), now);
                Ok(())
            }
        }
    }

    /// Sweep nonces older than `expiry` from both maps.
    pub fn sweep_expired(&mut self, now: Instant, expiry: Duration) {
        self.issued
            .retain(|_, t| now.duration_since(*t) <= expiry);
        self.consumed
            .retain(|_, t| now.duration_since(*t) <= expiry);
    }

    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }
}

/// Errors emitted by the nonce store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    #[error("nonce was never issued")]
    Unknown,
    #[error("nonce was already consumed")]
    AlreadyConsumed,
    #[error("nonce expired before being consumed")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_prompt_emits() {
        let cfg = CoalescingConfig::default();
        let now = Instant::now();
        let (d, _) = decide_coalesce(None, now, &cfg, "any");
        assert_eq!(d, CoalesceDecision::Emit);
    }

    #[test]
    fn cap_exhaustion_suppresses() {
        let cfg = CoalescingConfig::default();
        let mut state: Option<CoalescingWindow> = None;
        let mut emit_count = 0;
        let mut suppress_count = 0;
        for _ in 0..10 {
            let (d, w) = decide_coalesce(state, Instant::now(), &cfg, "x");
            match d {
                CoalesceDecision::Emit => emit_count += 1,
                CoalesceDecision::SuppressFloodCap => suppress_count += 1,
            }
            state = Some(w);
        }
        assert_eq!(emit_count, 5);
        assert_eq!(suppress_count, 5);
    }

    #[test]
    fn nonce_round_trips_within_expiry() {
        let mut store = NonceStore::default();
        let now = Instant::now();
        store.record_issued("abc", now);
        assert!(store.try_consume("abc", now, Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn nonce_replay_rejected() {
        let mut store = NonceStore::default();
        let now = Instant::now();
        store.record_issued("abc", now);
        store
            .try_consume("abc", now, Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.try_consume("abc", now, Duration::from_secs(60)),
            Err(NonceError::AlreadyConsumed)
        );
    }

    #[test]
    fn unknown_nonce_rejected() {
        let mut store = NonceStore::default();
        let now = Instant::now();
        assert_eq!(
            store.try_consume("never-issued", now, Duration::from_secs(60)),
            Err(NonceError::Unknown)
        );
    }
}
