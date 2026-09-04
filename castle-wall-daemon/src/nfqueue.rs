//! NFQUEUE bind and verdict loop.
//!
//! Per scope-lock section 1 + Codex amendment 7: the daemon binds NFQUEUE
//! with `NFQA_CFG_F_FAIL_OPEN` explicitly **disabled**. Queue saturation
//! surfaces as `wall_saturated` audit events, never as silent fail-open.
//!
//! The verdict loop is the bridge between the kernel and the daemon's
//! policy evaluator: for each packet the kernel delivers via NFQUEUE,
//! the loop calls `DecisionEngine::evaluate_attempt()`, converts the
//! `Verdict` into an NFQUEUE verdict (Accept/Drop), and emits the
//! audit event via the WalWriter.
//!
//! All kernel-touching code is `#[cfg(target_os = "linux")]`-gated.
//! The nfq crate dependency is Linux-only in Cargo.toml.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
    #[error("NFQUEUE verdict exceeded fail-closed deadline of {0:?}")]
    VerdictDeadlineExceeded(Duration),
    #[error("NFQUEUE saturated or dropped netlink messages: {0}")]
    QueueSaturated(String),
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
    /// Packet mark set by the per-agent nftables chain before queueing.
    pub nfmark: u32,
    /// Wrapped agent identity resolved from the packet mark.
    pub source_agent_id: Option<String>,
    /// Legacy numeric attribution field. Linux NFQUEUE does not expose the
    /// socket cgroup id through this binding, so Phase 1 stores `nfmark`
    /// here for callers that still log the numeric source field.
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
pub type VerdictCallback = Box<dyn Fn(&PendingPacket) -> NfVerdict + Send + Sync + 'static>;

static VERDICT_DEADLINE_FAIL_STOP_LATCH: AtomicBool = AtomicBool::new(false);

pub fn verdict_deadline_fail_stop_latched() -> bool {
    VERDICT_DEADLINE_FAIL_STOP_LATCH.load(Ordering::SeqCst)
}

#[cfg(not(test))]
fn verdict_deadline_fail_stop(deadline: Duration) -> Result<(), NfqueueError> {
    VERDICT_DEADLINE_FAIL_STOP_LATCH.store(true, Ordering::SeqCst);
    // The evaluator is a Rust thread and cannot be cancelled safely. Do not
    // return through ordinary runtime release while it is still running: that
    // would detach authority-bearing work after the wall reports stopped.
    eprintln!(
        "castle-wall-daemon: FATAL NFQUEUE verdict deadline exceeded ({deadline:?}); fail-stopping process so systemd kills the stuck worker"
    );
    std::process::exit(75)
}

#[cfg(test)]
fn verdict_deadline_fail_stop(deadline: Duration) -> Result<(), NfqueueError> {
    VERDICT_DEADLINE_FAIL_STOP_LATCH.store(true, Ordering::SeqCst);
    Err(NfqueueError::VerdictDeadlineExceeded(deadline))
}

#[cfg(feature = "test-isolation")]
pub fn trigger_verdict_deadline_fail_stop_for_test() -> ! {
    let _ = verdict_deadline_fail_stop(Duration::from_millis(1));
    unreachable!("test-isolation fail-stop must terminate the process")
}

static AGENT_MARK_REGISTRY: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();

fn agent_mark_registry() -> &'static Mutex<HashMap<u32, Option<String>>> {
    AGENT_MARK_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Deterministic nonzero mark used to carry the agent chain identity through
/// NFQUEUE. A registry collision is treated as unverifiable attribution.
pub fn agent_mark(agent_id: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in agent_id.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// Register the mark emitted by nftables for an agent. If two raw agent IDs
/// ever collide on the same 32-bit mark, the mark becomes intentionally
/// unresolvable and the NFQUEUE callback fails closed.
pub fn register_agent_mark(agent_id: &str) -> u32 {
    let mark = agent_mark(agent_id);
    if let Ok(mut guard) = agent_mark_registry().lock() {
        match guard.get(&mark) {
            Some(Some(existing)) if existing != agent_id => {
                guard.insert(mark, None);
            }
            Some(None) => {}
            _ => {
                guard.insert(mark, Some(agent_id.to_string()));
            }
        }
    }
    mark
}

pub fn resolve_agent_mark(mark: u32) -> Option<String> {
    agent_mark_registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(&mark).cloned().flatten())
}

/// Parse an IPv4 header to extract destination IP, port, and protocol.
/// Public so integration tests can verify the parsing independently.
pub fn parse_ip_header(payload: &[u8]) -> (Option<String>, u16, u8) {
    if payload.len() < 20 {
        return (None, 0, 0);
    }

    let version = (payload[0] >> 4) & 0x0F;
    if version == 6 {
        return parse_ipv6_header(payload);
    }
    if version != 4 {
        return (None, 0, 0);
    }

    let ihl = (payload[0] & 0x0F) as usize * 4;
    // RFC 791: IHL is at least five 32-bit words. A smaller value used to make
    // the parser read the IPv4 total-length/header bytes as a TCP/UDP port,
    // manufacturing a policy tuple the packet never carried.
    if ihl < 20 || payload.len() < ihl {
        return (None, 0, 0);
    }
    let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if total_len < ihl || total_len > payload.len() {
        return (None, 0, 0);
    }
    // This slice does not perform IP reassembly. Never evaluate a fragment as
    // though it were a complete flow: non-first fragments have no transport
    // header, and accepting a first fragment while later fragments are
    // unclassified would make the policy result packet-order dependent.
    let fragment = u16::from_be_bytes([payload[6], payload[7]]);
    if fragment & 0x3fff != 0 {
        return (None, 0, 0);
    }
    let protocol = payload[9];
    let dest_ip = format!(
        "{}.{}.{}.{}",
        payload[16], payload[17], payload[18], payload[19]
    );

    let dest_port = if total_len >= ihl + 4 && (protocol == 6 || protocol == 17) {
        // TCP/UDP: destination port is bytes 2-3 of the transport header.
        u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]])
    } else {
        0
    };

    (Some(dest_ip), dest_port, protocol)
}

fn parse_ipv6_header(payload: &[u8]) -> (Option<String>, u16, u8) {
    if payload.len() < 40 {
        return (None, 0, 0);
    }
    let declared_payload_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    let declared_total_len = match 40usize.checked_add(declared_payload_len) {
        Some(total) if total <= payload.len() => total,
        _ => return (None, 0, 0),
    };

    let dest_ip = Ipv6Addr::from([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
        payload[32],
        payload[33],
        payload[34],
        payload[35],
        payload[36],
        payload[37],
        payload[38],
        payload[39],
    ])
    .to_string();

    let mut next_header = payload[6];
    let mut offset = 40usize;
    loop {
        match next_header {
            0 | 43 | 60 => {
                if declared_total_len < offset + 2 {
                    return (Some(dest_ip), 0, next_header);
                }
                let header_len = (usize::from(payload[offset + 1]) + 1) * 8;
                next_header = payload[offset];
                offset = offset.saturating_add(header_len);
                if declared_total_len < offset {
                    return (Some(dest_ip), 0, next_header);
                }
            }
            44 => {
                if declared_total_len < offset + 8 {
                    return (None, 0, 0);
                }
                // IPv6 Fragment headers require reassembly state this decision
                // engine intentionally does not own. Refuse every fragment,
                // including the first, rather than deriving a partial tuple.
                return (None, 0, 0);
            }
            _ => break,
        }
    }

    let dest_port = if declared_total_len >= offset + 4 && (next_header == 6 || next_header == 17) {
        u16::from_be_bytes([payload[offset + 2], payload[offset + 3]])
    } else {
        0
    };

    (Some(dest_ip), dest_port, next_header)
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

/// A queue that has been opened, bound, and configured fail-closed. Owning one
/// of these is the proof the NFQUEUE is really bound (not merely allocated), so
/// the enforcement runtime signals readiness only after
/// [`open_bind_fail_closed`] returns one. Kept `pub(crate)` so the `nfq::Queue`
/// dependency type never leaks across the crate boundary.
#[cfg(target_os = "linux")]
pub(crate) struct BoundQueue {
    queue: nfq::Queue,
}

/// Open the netlink NFQUEUE, bind the configured queue number, and DISABLE
/// FAIL_OPEN. This is the one-shot bind the runtime's readiness gates on: it
/// returns only after the kernel queue is really bound with fail-open off, so a
/// component that holds a `BoundQueue` is genuinely intercepting, not just
/// allocated. Per scope-lock section 7 E7.1 a `fail_open = true` config is
/// rejected before any kernel call.
#[cfg(target_os = "linux")]
pub(crate) fn open_bind_fail_closed(config: &NfqueueConfig) -> Result<BoundQueue, NfqueueError> {
    use nfq::Queue;

    if config.fail_open {
        return Err(NfqueueError::BindFailed(
            "FAIL_OPEN must be false per scope-lock section 7 E7.1".to_string(),
        ));
    }

    let mut queue =
        Queue::open().map_err(|e| NfqueueError::BindFailed(format!("Queue::open: {e}")))?;
    queue
        .bind(config.queue_number)
        .map_err(|e| NfqueueError::BindFailed(format!("bind({}): {e}", config.queue_number)))?;
    // NFQA_CFG_F_FAIL_OPEN = 0 per scope-lock section 1: saturation surfaces as
    // wall_saturated, never a silent fail-open that would let egress escape.
    queue
        .set_fail_open(config.queue_number, false)
        .map_err(|e| NfqueueError::BindFailed(format!("set_fail_open(false): {e}")))?;
    queue
        .set_queue_max_len(config.queue_number, config.max_queue_length)
        .map_err(|e| {
            NfqueueError::BindFailed(format!(
                "set_queue_max_len({}): {e}",
                config.max_queue_length
            ))
        })?;
    // Non-blocking recv so the serve loop checks its stop flag on a bounded
    // cadence instead of blocking indefinitely on a quiet network.
    queue.set_nonblocking(true);
    Ok(BoundQueue { queue })
}

/// Is this `recv()` failure the benign "nothing to read yet" case rather than a
/// real queue fault?
///
/// `nfq::Queue::recv()` returns a `std::io::Result`, so the kernel's `errno` is
/// available STRUCTURALLY through [`std::io::Error::kind`]:
///
/// * `EAGAIN`/`EWOULDBLOCK` map to [`ErrorKind::WouldBlock`] — the queue is
///   non-blocking (see `open_bind_fail_closed`) and simply has no packet ready;
/// * `EINTR` maps to [`ErrorKind::Interrupted`] — a signal (SIGTERM during
///   shutdown, a profiler tick) landed mid-syscall; the loop must retry, not die.
///
/// Everything else is a genuine fault and MUST end the serve loop so the
/// component turns health non-green (fail-closed: a queue we cannot read is a
/// queue that is not intercepting).
///
/// This is deliberately NOT a match on `err.to_string()`. `Display` for a raw-OS
/// `io::Error` renders libc's `strerror`, which is localized: under a non-English
/// `LC_MESSAGES` the English substrings this used to look for never appear, every
/// idle poll would be classified as fatal, and the daemon would restart-loop on a
/// healthy host. Keeping the classification on `ErrorKind` also means an error
/// whose MESSAGE happens to read like "Resource temporarily unavailable" but whose
/// kind is not `WouldBlock` is correctly treated as fatal.
///
/// Compiled on Linux (the only platform with a serve loop) and under `test`, so
/// the contract is provable on the macOS dev host without a kernel queue.
#[cfg(any(target_os = "linux", test))]
fn is_transient_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

/// Run the verdict loop over an already-[`open_bind_fail_closed`] queue until the
/// stop flag is set. Returning (cleanly or via `Err`) ends the loop; the
/// runtime treats that as the verdict thread dying and turns health non-green.
#[cfg(target_os = "linux")]
pub(crate) fn serve_bound_queue(
    bound: &mut BoundQueue,
    verdict_fn: VerdictCallback,
    verdict_deadline: Duration,
    packets_processed: &AtomicU64,
    packets_saturated: &AtomicU64,
    stop_flag: &AtomicBool,
) -> Result<(), NfqueueError> {
    enum DecisionJob {
        Evaluate(PendingPacket, std::sync::mpsc::SyncSender<NfVerdict>),
        Stop,
    }
    let (decision_tx, decision_rx) = std::sync::mpsc::sync_channel::<DecisionJob>(1);
    let decision_worker = std::thread::spawn(move || {
        while let Ok(job) = decision_rx.recv() {
            match job {
                DecisionJob::Evaluate(packet, reply) => {
                    let _ = reply.send(verdict_fn(&packet));
                }
                DecisionJob::Stop => return,
            }
        }
    });
    while !stop_flag.load(Ordering::Relaxed) {
        let mut msg = match bound.queue.recv() {
            Ok(msg) => msg,
            Err(e) => {
                // Classify by `ErrorKind`, never by the rendered `strerror`
                // text: `Display` for a raw-OS `io::Error` interpolates the
                // C library's LOCALE-DEPENDENT message, so a substring match on
                // the English "Resource temporarily unavailable" silently stops
                // recognizing an idle queue under any non-English `LC_MESSAGES`.
                // That misclassification is now safety-critical: an `Err` return
                // here ends the verdict thread, which withdraws component health
                // and drives a full daemon restart, so a mis-read idle poll would
                // become a restart loop on an otherwise healthy host.
                if is_transient_recv_error(&e) {
                    // No packet ready; brief sleep avoids a busy-loop while
                    // keeping the stop_flag check responsive (~10ms).
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    packets_saturated.fetch_add(1, Ordering::Relaxed);
                    return Err(NfqueueError::QueueSaturated(e.to_string()));
                }
                return Err(NfqueueError::VerdictLoopError(e.to_string()));
            }
        };

        let payload = msg.get_payload();
        let (dest_ip, dest_port, protocol) = parse_ip_header(payload);

        let nfmark = msg.get_nfmark();
        let pending = PendingPacket {
            packet_id: nfmark,
            nfmark,
            source_agent_id: resolve_agent_mark(nfmark),
            source_cgroup_id: u64::from(nfmark),
            dest_ip,
            dest_port,
            protocol,
            packet_len: payload.len() as u32,
        };

        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(0);
        if let Err(err) = decision_tx.try_send(DecisionJob::Evaluate(pending, reply_tx)) {
            packets_saturated.fetch_add(1, Ordering::Relaxed);
            // This packet has already left the kernel queue. Give it an
            // explicit DROP verdict before terminating the unhealthy serve
            // loop; relying on queue teardown would leave its disposition to
            // kernel cleanup timing.
            msg.set_verdict(nfq::Verdict::Drop);
            let _ = bound.queue.verdict(msg);
            return Err(NfqueueError::QueueSaturated(format!(
                "decision worker unavailable: {err}"
            )));
        }
        let nf_verdict = match reply_rx.recv_timeout(verdict_deadline) {
            Ok(verdict) => verdict,
            Err(_) => {
                packets_saturated.fetch_add(1, Ordering::Relaxed);
                msg.set_verdict(nfq::Verdict::Drop);
                let _ = bound.queue.verdict(msg);
                verdict_deadline_fail_stop(verdict_deadline)?;
                unreachable!("production deadline path fail-stops the process");
            }
        };
        packets_processed.fetch_add(1, Ordering::Relaxed);

        match nf_verdict {
            NfVerdict::Accept => msg.set_verdict(nfq::Verdict::Accept),
            NfVerdict::Drop => msg.set_verdict(nfq::Verdict::Drop),
        };
        bound
            .queue
            .verdict(msg)
            .map_err(|e| NfqueueError::VerdictLoopError(format!("verdict: {e}")))?;
    }

    let _ = decision_tx.send(DecisionJob::Stop);
    let _ = decision_worker.join();
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run_verdict_loop_impl(
    handle: &QueueHandle,
    config: &NfqueueConfig,
    verdict_fn: VerdictCallback,
) -> Result<(), NfqueueError> {
    // Open+bind (fail-open off) then serve: the same two steps the enforcement
    // runtime drives separately so it can gate readiness on the bind. Sharing
    // them here keeps the standalone loop and the runtime path byte-identical.
    let mut bound = open_bind_fail_closed(config)?;
    serve_bound_queue(
        &mut bound,
        verdict_fn,
        config.verdict_deadline,
        &handle.packets_processed,
        &handle.packets_saturated,
        &handle.stop_flag,
    )
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

/// Build a verdict callback that routes through the shared decision engine's
/// evaluate_attempt
/// path. This is the glue between the kernel NFQUEUE and the in-process
/// policy evaluator from Checkpoint 3.
///
/// The callback:
/// 1. Constructs an EvaluationRequest from the PendingPacket.
/// 2. Calls evaluate_attempt on the shared DecisionEngine.
/// 3. Maps Verdict::Allow -> NfVerdict::Accept, all else -> NfVerdict::Drop.
/// 4. The audit event is emitted inside evaluate_attempt (WAL + ring buffer).
pub fn build_verdict_callback(
    decision_engine: Arc<crate::decision::DecisionEngine>,
) -> VerdictCallback {
    Box::new(move |packet: &PendingPacket| {
        // Teardown's mutation fence is also a verdict fence. A worker that was
        // already inside recv/evaluation when shutdown began must never emit a
        // late NF_ACCEPT while the runtime is stopping.
        if decision_engine
            .mutation_cancel_flag()
            .load(Ordering::SeqCst)
        {
            return NfVerdict::Drop;
        }
        let Some(agent_id) = packet.source_agent_id.clone() else {
            return NfVerdict::Drop;
        };
        // Kept for the superseding record below, which must name the same
        // subject the superseded receipt did.
        let agent_id_for_audit = agent_id.clone();

        let protocol_str = match packet.protocol {
            6 => "tcp".to_string(),
            17 => "udp".to_string(),
            _ => format!("{}", packet.protocol),
        };

        let request = crate::policy::EvaluationRequest {
            agent_id,
            agent_template: "unknown".to_string(),
            dest_host: None,
            dest_ip: packet.dest_ip.clone(),
            dest_port: packet.dest_port,
            dest_protocol: protocol_str,
            opaque: true,
        };

        let evaluated = decision_engine.evaluate_attempt(&request);
        if decision_engine
            .mutation_cancel_flag()
            .load(Ordering::SeqCst)
        {
            // Teardown began DURING evaluation. The packet is dropped, but
            // `evaluate_attempt` has already made its decision durable — by
            // design, so evidence never trails the packet. When that decision was
            // an ALLOW, the WAL is now holding a canonical `egress_approved`
            // receipt for a packet the kernel never released, and the audit log
            // is the product's evidence claim. Append a SUPERSEDING record naming
            // the exact sequence it overrides, so the trail says what actually
            // happened instead of ending on a receipt for a non-event.
            //
            // Only the allow case needs it: a deny/prompt receipt already agrees
            // with the drop.
            if let Ok(outcome) = evaluated.as_ref() {
                if matches!(outcome.verdict, crate::policy::Verdict::Allow { .. }) {
                    supersede_allow_receipt(&decision_engine, outcome, &agent_id_for_audit);
                }
            }
            return NfVerdict::Drop;
        }
        match evaluated {
            Ok(outcome) => match outcome.verdict {
                crate::policy::Verdict::Allow { .. } => NfVerdict::Accept,
                crate::policy::Verdict::PromptRequired { .. } => NfVerdict::Drop,
                crate::policy::Verdict::Deny { .. } => NfVerdict::Drop,
            },
            Err(_) => NfVerdict::Drop,
        }
    })
}

/// Wall-clock budget for writing a superseding-verdict record on the NFQUEUE
/// verdict thread during teardown.
///
/// 50ms, derived from what it must not disturb: teardown joins this thread, so
/// the budget has to be far below the join's tolerance while still spanning the
/// microsecond-scale WAL appends the shutdown path is doing. It is a bound on a
/// CORRECTION, never on the drop: the packet is refused whether or not the
/// record lands.
const SUPERSEDING_RECORD_BUDGET: Duration = Duration::from_millis(50);

/// Emit the superseding record for an allow receipt that the teardown fence
/// overrode, or say loudly why it could not.
///
/// Split out of the callback so the fence reads as one decision. Never returns a
/// value the caller could act on: the verdict is already decided (Drop), and
/// making the packet's fate depend on an audit write would invert the fail-closed
/// direction.
fn supersede_allow_receipt(
    decision_engine: &crate::decision::DecisionEngine,
    outcome: &crate::decision::EvaluationOutcome,
    identity_id: &str,
) {
    let Some(seq) = outcome.wal_seq else {
        // No durable receipt was written, so there is nothing to supersede and
        // no divergence to close.
        return;
    };
    if let Err(err) = decision_engine.append_superseding_verdict(
        seq,
        "drop",
        "teardown mutation fence dropped the packet after the allow decision was recorded",
        identity_id,
        SUPERSEDING_RECORD_BUDGET,
    ) {
        // LOUD, never silent: an absent correction is exactly the shape of the
        // defect this exists to close, so it must be visible in the journal
        // rather than inferred from a missing record.
        eprintln!(
            "castle-wall-daemon: dropped packet at the teardown fence after WAL seq {seq} \
             recorded an allow, and the superseding record could not be written ({err}); \
             the audit trail for that sequence overstates what happened"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditRingBuffer;
    use crate::decision::DecisionEngine;

    /// The two kernel conditions that mean "no packet ready / retry", expressed
    /// as the raw errnos the kernel actually returns, must classify transient.
    /// Using `from_raw_os_error` (not a hand-built `ErrorKind`) proves the
    /// libc-to-`ErrorKind` mapping this classifier depends on really holds.
    #[test]
    fn idle_and_interrupted_recv_errnos_classify_transient() {
        for errno in [libc::EAGAIN, libc::EWOULDBLOCK, libc::EINTR] {
            let err = std::io::Error::from_raw_os_error(errno);
            assert!(
                is_transient_recv_error(&err),
                "errno {errno} ({err:?}) must be a retryable idle/interrupted poll, \
                 not a fatal verdict-loop error"
            );
        }
    }

    /// FAIL-BEFORE for the locale defect: an idle poll whose rendered message is
    /// NOT the English `strerror` text (the shape produced under a non-English
    /// `LC_MESSAGES`) must still classify transient. The previous substring match
    /// returned `false` here, ending the verdict thread and restart-looping the
    /// daemon on a healthy host; this test fails against that implementation.
    #[test]
    fn a_non_english_idle_message_is_still_transient() {
        let localized = std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Ressource temporairement indisponible",
        );
        assert!(
            is_transient_recv_error(&localized),
            "idle classification must come from ErrorKind, never from the localized strerror text"
        );
        let localized_eintr = std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Unterbrechung waehrend des Betriebssystemaufrufs",
        );
        assert!(is_transient_recv_error(&localized_eintr));
    }

    /// The converse half of the same contract: a REAL fault whose message happens
    /// to contain the English idle text must still be fatal. A text matcher would
    /// swallow it and spin the serve loop forever on a dead queue while reporting
    /// the component healthy.
    #[test]
    fn a_fatal_error_that_merely_reads_like_an_idle_poll_is_not_transient() {
        let impostor =
            std::io::Error::other("netlink socket closed: Resource temporarily unavailable");
        assert!(
            !is_transient_recv_error(&impostor),
            "only the ErrorKind decides; a fatal error must never be retried because its \
             message resembles the idle one"
        );
        for errno in [libc::ENOBUFS, libc::EPERM, libc::ENODEV] {
            assert!(
                !is_transient_recv_error(&std::io::Error::from_raw_os_error(errno)),
                "errno {errno} is a genuine queue fault and must end the serve loop"
            );
        }
    }

    #[test]
    fn default_config_has_fail_open_off() {
        let cfg = NfqueueConfig::default();
        assert!(
            !cfg.fail_open,
            "FAIL_OPEN must be false per scope-lock section 7 E7.1"
        );
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
    fn mutation_fence_drops_without_entering_policy_evaluation() {
        let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
            1024,
            Duration::from_secs(60),
        )));
        let engine = Arc::new(DecisionEngine::new(
            "mutation-fence".to_string(),
            None,
            None,
            Arc::clone(&audit),
        ));
        engine.mutation_cancel_flag().store(true, Ordering::SeqCst);
        let callback = build_verdict_callback(engine);
        let packet = PendingPacket {
            packet_id: 1,
            nfmark: 1,
            source_agent_id: Some("agent-fenced".to_string()),
            source_cgroup_id: 1,
            dest_ip: Some("203.0.113.10".to_string()),
            dest_port: 443,
            protocol: 6,
            packet_len: 64,
        };

        assert_eq!(callback(&packet), NfVerdict::Drop);
        assert_eq!(
            audit.lock().unwrap().len(),
            0,
            "the pre-evaluation fence must return before policy/audit mutation"
        );
    }

    #[test]
    fn parse_ip_header_extracts_tcp_dest() {
        // Minimal valid IPv4 TCP packet header (20 bytes IP + 4 bytes TCP)
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45; // version=4, ihl=5 (20 bytes)
        pkt[2..4].copy_from_slice(&24u16.to_be_bytes());
        pkt[9] = 6; // protocol = TCP
        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 1; // dest IP 10.0.0.1
        pkt[22] = 0x01;
        pkt[23] = 0xBB; // dest port 443
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, Some("10.0.0.1".to_string()));
        assert_eq!(port, 443);
        assert_eq!(proto, 6);
    }

    #[test]
    fn parse_ip_header_udp_dest() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[9] = 17; // UDP
        pkt[16] = 8;
        pkt[17] = 8;
        pkt[18] = 8;
        pkt[19] = 8; // 8.8.8.8
        pkt[22] = 0x00;
        pkt[23] = 0x35; // port 53
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
    fn parse_ip_header_rejects_a_truncated_ipv4_payload() {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        // The kernel-reported IP packet length is authoritative. Accepting a
        // shorter capture could parse a transport header from incomplete data.
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[9] = 6;
        pkt[16..20].copy_from_slice(&[203, 0, 113, 8]);
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(parse_ip_header(&pkt), (None, 0, 0));
    }

    #[test]
    fn parse_ip_header_rejects_invalid_ihl_and_fragmented_ipv4() {
        let mut invalid_ihl = vec![0u8; 24];
        invalid_ihl[0] = 0x41;
        invalid_ihl[2..4].copy_from_slice(&24u16.to_be_bytes());
        invalid_ihl[9] = 6;
        invalid_ihl[16..20].copy_from_slice(&[203, 0, 113, 8]);
        assert_eq!(parse_ip_header(&invalid_ihl), (None, 0, 0));

        let mut fragment = vec![0u8; 24];
        fragment[0] = 0x45;
        fragment[2..4].copy_from_slice(&24u16.to_be_bytes());
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // more-fragments flag
        fragment[9] = 6;
        fragment[16..20].copy_from_slice(&[203, 0, 113, 8]);
        fragment[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(parse_ip_header(&fragment), (None, 0, 0));
    }

    #[test]
    fn parse_ip_header_rejects_ipv6_fragment_header() {
        let mut packet = vec![0u8; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        packet[6] = 44;
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40] = 6;
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(parse_ip_header(&packet), (None, 0, 0));
    }

    #[test]
    fn parse_ip_header_ipv6_tcp_dest() {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60; // version=6
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = 6; // TCP
        pkt[39] = 1; // ::1
        pkt[42] = 0x01;
        pkt[43] = 0xBB;
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, Some("::1".to_string()));
        assert_eq!(port, 443);
        assert_eq!(proto, 6);
    }

    #[test]
    fn parse_ip_header_ipv6_udp_dest() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[6] = 17; // UDP
        pkt[24] = 0x20;
        pkt[25] = 0x01;
        pkt[26] = 0x0d;
        pkt[27] = 0xb8;
        pkt[39] = 0x42;
        pkt[42] = 0x00;
        pkt[43] = 0x35;
        let (ip, port, proto) = parse_ip_header(&pkt);
        assert_eq!(ip, Some("2001:db8::42".to_string()));
        assert_eq!(port, 53);
        assert_eq!(proto, 17);
    }

    #[test]
    fn agent_mark_registry_resolves_registered_agent() {
        let mark = register_agent_mark("agent-attribution-test");
        assert_eq!(
            resolve_agent_mark(mark),
            Some("agent-attribution-test".to_string())
        );
        assert_ne!(mark, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_queue_rejects_fail_open_true() {
        let config = NfqueueConfig {
            fail_open: true,
            ..Default::default()
        };
        let err = bind_queue_impl(&config);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("FAIL_OPEN"));
    }
}
