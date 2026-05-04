//! NFQUEUE bind and verdict loop.
//!
//! PR 2a stub: declares the public surface that PR 2b will implement.
//! Per scope-lock §1 + Codex amendment 7: the daemon binds NFQUEUE with
//! `NFQA_CFG_F_FAIL_OPEN` explicitly **disabled**. Queue saturation
//! surfaces as `queue_saturated` audit events, never as silent fail-open.

use std::time::Duration;

/// Errors emitted by the nfqueue module.
#[derive(Debug, thiserror::Error)]
pub enum NfqueueError {
    #[error("nfqueue operation not implemented in PR 2a (kernel enforcement lands in PR 2b)")]
    NotImplementedInPhase2a,
    #[error("kernel queue bind failed: {0}")]
    BindFailed(String),
    #[error("CAP_NET_ADMIN missing: cannot bind NFQUEUE")]
    CapabilityMissing,
}

/// Configuration for the NFQUEUE verdict loop.
#[derive(Debug, Clone)]
pub struct NfqueueConfig {
    /// Queue number (NFQUEUE id). Must match the nftables `queue num <n>`.
    pub queue_number: u16,
    /// FAIL_OPEN flag. MUST be `false` for security; surfaced as a constant
    /// here so a code review trivially shows the safe value.
    pub fail_open: bool,
    /// Per-verdict-call deadline; if userspace can't decide in time, the
    /// failure-mode dispatch handles the fall-through.
    pub verdict_deadline: Duration,
}

impl Default for NfqueueConfig {
    fn default() -> Self {
        Self {
            queue_number: 0,
            fail_open: false,
            verdict_deadline: Duration::from_secs(2),
        }
    }
}

/// PR 2b: bind the NFQUEUE with FAIL_OPEN explicitly off. Returns a handle
/// the verdict loop reads packets from.
pub fn bind_queue(_config: &NfqueueConfig) -> Result<QueueHandle, NfqueueError> {
    Err(NfqueueError::NotImplementedInPhase2a)
}

/// PR 2b: opaque handle to a bound NFQUEUE.
#[derive(Debug)]
pub struct QueueHandle {
    _marker: (),
}

/// PR 2b: a single packet awaiting a verdict.
#[derive(Debug)]
pub struct PendingPacket {
    pub packet_id: u32,
    pub source_cgroup_id: u64,
}

/// PR 2b: the four legitimate verdicts the daemon can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    /// Queue the packet for the operator-prompt path; if the prompt times
    /// out, the failure-mode dispatch defaults to Drop per E6.2.
    Queue,
}
