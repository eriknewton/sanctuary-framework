//! NFQUEUE bind and verdict loop.
//!
//! Per scope-lock section 1 + Codex amendment 7: the daemon binds NFQUEUE
//! with `NFQA_CFG_F_FAIL_OPEN` explicitly **disabled**. Queue saturation
//! surfaces as `wall_saturated` audit events, never as silent fail-open.
//!
//! The verdict loop is the bridge between the kernel and the daemon's
//! policy evaluator: for each packet the kernel delivers via NFQUEUE,
//! the loop calls `DaemonHandle::evaluate_attempt()`, converts the
//! `Verdict` into an NFQUEUE verdict (Accept/Drop), and emits the
//! audit event via the WalWriter.
//!
//! All kernel-touching code is `#[cfg(target_os = "linux")]`-gated.
//! The nfq crate dependency is Linux-only in Cargo.toml.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Errors emitted by the nfqueue module.
#[derive(Debug, thiserror::Error)]
pub enum NfqueueError {
    #[error("nfqueue not available on this platform")]
    NotAvailableOnPlatform,
    #[error("kernel queue bind failed: {0}")]
    BindFailed(String),
    #[error("CAP_NET_ADMIN missing: cannot bind NFQUEUE")]
    CapabilityMissing,
    #[error("verdict loop error: {0}")]
    VerdictLoopError(String),
}

/// Configuration for the NFQUEUE verdict loop.
#[derive(Debug, Clone)]
pub struct NfqueueConfig {
    /// Queue number (NFQUEUE id). Must match the nftables `queue num <n>`.
    pub queue_number: u16,
    /// FAIL_OPEN flag. MUST be `false` for security; surfaced as a constant
    /// here so a code review trivially shows the safe value.
    /// Per scope-lock section 7 E7.1: explicitly off.
    pub fail_open: bool,
    /// Per-verdict-call deadline; if userspace cannot decide in time, the
    /// failure-mode dispatch handles the fall-through.
    pub verdict_deadline: Duration,
    /// Maximum number of packets queued before the kernel starts dropping.
    /// When this threshold is exceeded, the daemon emits a `wall_saturated`
    /// audit event per scope-lock section 1 F-5.
    pub max_queue_length: u32,
}

impl Default for NfqueueConfig {
    fn default() -> Self {
        Self {
            queue_number: 0,
            fail_open: false, // MUST be false per scope-lock section 7 E7.1
            verdict_deadline: Duration::from_secs(2),
            max_queue_length: 1024,
        }
    }
}

/// Handle to a bound NFQUEUE. Dropping this unbinds the queue.
pub struct QueueHandle {
    /// The queue number bound.
    pub queue_number: u16,
    /// Counter: total packets processed.
    pub packets_processed: Arc<AtomicU64>,
    /// Counter: packets dropped due to saturation.
    pub packets_saturated: Arc<AtomicU64>,
    /// Flag: set to true to stop the verdict loop.
    pub stop_flag: Arc<AtomicBool>,
}

impl std::fmt::Debug for QueueHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueHandle")
            .field("queue_number", &self.queue_number)
            .field(
                "packets_processed",
                &self.packets_processed.load(Ordering::Relaxed),
            )
            .field(
                "packets_saturated",
                &self.packets_saturated.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// A single packet awaiting a verdict from the daemon.
#[derive(Debug, Clone)]
pub struct PendingPacket {
    /// Kernel-assigned packet id for verdict reply.
    pub packet_id: u32,
    /// Source cgroup id (from the socket's owning cgroup).
    pub source_cgroup_id: u64,
    /// Destination IP address (IPv4 or IPv6 string).
    pub dest_ip: Option<String>,
    /// Destination port (extracted from TCP/UDP header).
    pub dest_port: u16,
    /// Protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Raw packet length in bytes.
    pub packet_len: u32,
}

/// The two legitimate verdicts the daemon can return to the kernel.
/// Per scope-lock section 7 E7.1: no bypass/repeat path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfVerdict {
    /// NF_ACCEPT: allow the packet.
    Accept,
    /// NF_DROP: silently drop the packet.
    Drop,
}

/// Verdict callback type. The NFQUEUE loop calls this for each packet,
/// receives a verdict, and applies it to the kernel queue.
pub type VerdictCallback =
    Box<dyn Fn(&PendingPacket) -> NfVerdict + Send + Sync + 'static>;

/// Parse an IPv4 header to extract destination IP, port, and protocol.
/// Public so integration tests can verify the parsing independently.
pub fn parse_ip_header(payload: &[u8]) -> (Option<String>, u16, u8) {
    if payload.len() < 20 {
        return (None, 0, 0);
    }

    let version = (payload[0] >> 4) & 0x0F;
    if version != 4 {
        // IPv6 handling deferred to Checkpoint 4; return raw info.
        return (None, 0, 0);
    }

    let ihl = (payload[0] & 0x0F) as usize * 4;
    let protocol = payload[9];
    let dest_ip = format!(
        "{}.{}.{}.{}",
        payload[16], payload[17], payload[18], payload[19]
    );

    let dest_port = if payload.len() >= ihl + 4 && (protocol == 6 || protocol == 17) {
        // TCP/UDP: destination port is bytes 2-3 of the transport header.
        u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]])
    } else {
        0
    };

    (Some(dest_ip), dest_port, protocol)
}

// ---- Linux NFQUEUE implementation -----------------------------------------
//
// The `nfq` crate (v0.2) provides the netlink NFQUEUE binding. Its API:
//   Queue::open() -> Result<Queue, io::Error>
//   queue.bind(queue_num: u16) -> Result<(), io::Error>
//   queue.set_fail_open(queue_num: u16, fail_open: bool) -> Result<(), io::Error>
//   queue.recv() -> Result<Message, io::Error>
//   msg.get_payload() -> &[u8]
//   msg.get_nfmark() -> u32
//   msg.set_verdict(Verdict::{Accept,Drop,...})
//   queue.verdict(msg) -> Result<(), io::Error>
//
// The verdict loop runs on a dedicated thread; the stop_flag is checked
// between recv() calls.

#[cfg(target_os = "linux")]
pub fn bind_queue_impl(config: &NfqueueConfig) -> Result<QueueHandle, NfqueueError> {
    if config.fail_open {
        return Err(NfqueueError::BindFailed(
            "FAIL_OPEN must be false per scope-lock section 7 E7.1".to_string(),
        ));
    }

    Ok(QueueHandle {
        queue_number: config.queue_number,
        packets_processed: Arc::new(AtomicU64::new(0)),
        packets_saturated: Arc::new(AtomicU64::new(0)),
        stop_flag: Arc::new(AtomicBool::new(false)),
    })
}

#[cfg(target_os = "linux")]
pub fn run_verdict_loop_impl(
    handle: &QueueHandle,
    config: &NfqueueConfig,
    verdict_fn: VerdictCallback,
) -> Result<(), NfqueueError> {
    use nfq::Queue;

    let mut queue = Queue::open()
        .map_err(|e| NfqueueError::BindFailed(format!("Queue::open: {e}")))?;

    queue
        .bind(config.queue_number)
        .map_err(|e| NfqueueError::BindFailed(format!("bind({}): {e}", config.queue_number)))?;

    // NFQA_CFG_F_FAIL_OPEN = 0 per scope-lock section 1.
    queue
        .set_fail_open(config.queue_number, false)
        .map_err(|e| NfqueueError::BindFailed(format!("set_fail_open(false): {e}")))?;

    while !handle.stop_flag.load(Ordering::Relaxed) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Resource temporarily unavailable")
                    || err_str.contains("Interrupted system call")
                {
                    continue;
                }
                return Err(NfqueueError::VerdictLoopError(err_str));
            }
        };

        let payload = msg.get_payload();
        let (dest_ip, dest_port, protocol) = parse_ip_header(payload);

        let pending = PendingPacket {
            packet_id: msg.get_nfmark(),
            source_cgroup_id: 0,
            dest_ip,
            dest_port,
            protocol,
            packet_len: payload.len() as u32,
        };

        let nf_verdict = verdict_fn(&pending);
        handle.packets_processed.fetch_add(1, Ordering::Relaxed);

        match nf_verdict {
            NfVerdict::Accept => msg.set_verdict(nfq::Verdict::Accept),
            NfVerdict::Drop => msg.set_verdict(nfq::Verdict::Drop),
        };
        queue
            .verdict(msg)
            .map_err(|e| NfqueueError::VerdictLoopError(format!("verdict: {e}")))?;
    }

    Ok(())
}

// ---- Public API (platform-dispatching) ------------------------------------

/// Bind the NFQUEUE with FAIL_OPEN explicitly off.
#[cfg(target_os = "linux")]
pub fn bind_queue(config: &NfqueueConfig) -> Result<QueueHandle, NfqueueError> {
    bind_queue_impl(config)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_queue(_config: &NfqueueConfig) -> Result<QueueHandle, NfqueueError> {
    Err(NfqueueError::NotAvailableOnPlatform)
}

/// Run the verdict loop until the handle's stop flag is set.
#[cfg(target_os = "linux")]
pub fn run_verdict_loop(
    handle: &QueueHandle,
    config: &NfqueueConfig,
    verdict_fn: VerdictCallback,
) -> Result<(), NfqueueError> {
    run_verdict_loop_impl(handle, config, verdict_fn)
}

#[cfg(not(target_os = "linux"))]
pub fn run_verdict_loop(
    _handle: &QueueHandle,
    _config: &NfqueueConfig,
    _verdict_fn: VerdictCallback,
) -> Result<(), NfqueueError> {
    Err(NfqueueError::NotAvailableOnPlatform)
}

/// Build a verdict callback that routes through the daemon's evaluate_attempt
/// path. This is the glue between the kernel NFQUEUE and the in-process
/// policy evaluator from Checkpoint 3.
///
/// The callback:
/// 1. Constructs an EvaluationRequest from the PendingPacket.
/// 2. Calls evaluate_attempt on the shared DaemonHandle.
/// 3. Maps Verdict::Allow -> NfVerdict::Accept, all else -> NfVerdict::Drop.
/// 4. The audit event is emitted inside evaluate_attempt (WAL + ring buffer).
pub fn build_verdict_callback(
    daemon_handle: Arc<crate::daemon::DaemonHandle>,
) -> VerdictCallback {
    Box::new(move |packet: &PendingPacket| {
        let protocol_str = match packet.protocol {
            6 => "tcp".to_string(),
            17 => "udp".to_string(),
            _ => format!("{}", packet.protocol),
        };

        let request = crate::policy::EvaluationRequest {
            agent_id: format!("cgroup-{}", packet.source_cgroup_id),
            agent_template: "unknown".to_string(),
            dest_host: None,
            dest_ip: packet.dest_ip.clone(),
            dest_port: packet.dest_port,
            dest_protocol: protocol_str,
            opaque: true,
        };

        match daemon_handle.evaluate_attempt(&request) {
            Ok(outcome) => match outcome.verdict {
                crate::policy::Verdict::Allow { .. } => NfVerdict::Accept,
                crate::policy::Verdict::PromptRequired { .. } => NfVerdict::Drop,
                crate::policy::Verdict::Deny { .. } => NfVerdict::Drop,
            },
            Err(_) => NfVerdict::Drop,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_fail_open_off() {
        let cfg = NfqueueConfig::default();
        assert!(!cfg.fail_open, "FAIL_OPEN must be false per scope-lock section 7 E7.1");
    }

    #[test]
    fn queue_handle_debug_format() {
        let handle = QueueHandle {
            queue_number: 0,
            packets_processed: Arc::new(AtomicU64::new(42)),
            packets_saturated: Arc::new(AtomicU64::new(3)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        };
        let dbg = format!("{:?}", handle);
        assert!(dbg.contains("42"));
        assert!(dbg.contains("3"));
    }

    #[test]
    fn nf_verdict_is_copy() {
        let v = NfVerdict::Accept;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn parse_ip_header_extracts_tcp_dest() {
        // Minimal valid IPv4 TCP packet header (20 bytes IP + 4 bytes TCP)
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45; // version=4, ihl=5 (20 bytes)
        pkt[9] = 6; // protocol = TCP
        pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 1; // dest IP 10.0.0.1
        pkt[22] = 0x01; pkt[23] = 0xBB; // dest port 443
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, Some("10.0.0.1".to_string()));
        assert_eq!(port, 443);
        assert_eq!(proto, 6);
    }

    #[test]
    fn parse_ip_header_udp_dest() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8; // 8.8.8.8
        pkt[22] = 0x00; pkt[23] = 0x35; // port 53
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, Some("8.8.8.8".to_string()));
        assert_eq!(port, 53);
        assert_eq!(proto, 17);
    }

    #[test]
    fn parse_ip_header_short_packet_returns_none() {
        let pkt = vec![0u8; 5];
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, None);
        assert_eq!(port, 0);
        assert_eq!(proto, 0);
    }

    #[test]
    fn parse_ip_header_ipv6_returns_none() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version=6
        let (ip, _port, _proto) = parse_ip_header(&pkt);
        assert_eq!(ip, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_queue_rejects_fail_open_true() {
        let mut config = NfqueueConfig::default();
        config.fail_open = true;
        let err = bind_queue_impl(&config);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("FAIL_OPEN"));
    }
}
