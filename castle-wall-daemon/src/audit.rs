//! WAL audit writer (append-only, plaintext newline-delimited JSON in PR 2a).
//!
//! Per scope-lock §8 Phase 1 decision: the WAL is plaintext with mode 0600
//! during the Sanctuary-main-down window. Phase 1.5 will encrypt it via the
//! OS keychain (Linux Secret Service, macOS Keychain Services).
//!
//! PR 2a ships the in-memory ring buffer that the WAL writer flushes to disk
//! plus the drain protocol shape. PR 2b wires the actual filesystem writer
//! with `fsync` per entry and the TTL + size-cap eviction policy.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// One audit event awaiting durable persistence.
#[derive(Debug, Clone)]
pub struct PendingAuditEvent {
    pub event_canonical_json: String,
    pub captured_at: SystemTime,
}

/// In-memory ring buffer for events that have not yet been ACK'd by main.
/// Once main ACKs an event, it's truncated from the WAL. PR 2b adds the
/// disk-backed half (write-then-IPC, truncate-on-ACK).
#[derive(Debug)]
pub struct AuditRingBuffer {
    buffer: VecDeque<PendingAuditEvent>,
    max_bytes: u64,
    ttl: Duration,
    current_bytes: u64,
    overflow_count: u64,
}

impl AuditRingBuffer {
    pub fn new(max_bytes: u64, ttl: Duration) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            ttl,
            current_bytes: 0,
            overflow_count: 0,
        }
    }

    /// Append a pending event. If the cap is hit, drop oldest first and
    /// increment the overflow counter (surfaces as wal_overflow audit
    /// event on next ACK per scope-lock §8).
    pub fn append(&mut self, event: PendingAuditEvent) {
        let event_bytes = event.event_canonical_json.len() as u64;
        while self.current_bytes + event_bytes > self.max_bytes && !self.buffer.is_empty() {
            if let Some(dropped) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(dropped.event_canonical_json.len() as u64);
                self.overflow_count = self.overflow_count.saturating_add(1);
            }
        }
        self.current_bytes += event_bytes;
        self.buffer.push_back(event);
    }

    /// Evict events older than the TTL. Returns the number dropped.
    pub fn evict_expired(&mut self, now: SystemTime) -> u64 {
        let mut dropped = 0u64;
        while let Some(front) = self.buffer.front() {
            let age = now
                .duration_since(front.captured_at)
                .unwrap_or(Duration::ZERO);
            if age <= self.ttl {
                break;
            }
            if let Some(evicted) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(evicted.event_canonical_json.len() as u64);
                dropped += 1;
                self.overflow_count = self.overflow_count.saturating_add(1);
            }
        }
        dropped
    }

    /// Truncate the buffer up to and including the event at `index`. Used
    /// when Sanctuary main has ACK'd a batch.
    pub fn truncate_through(&mut self, index_inclusive: usize) {
        let to_drop = (index_inclusive + 1).min(self.buffer.len());
        for _ in 0..to_drop {
            if let Some(evicted) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(evicted.event_canonical_json.len() as u64);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    pub fn current_bytes(&self) -> u64 {
        self.current_bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = &PendingAuditEvent> {
        self.buffer.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(body: &str, t: SystemTime) -> PendingAuditEvent {
        PendingAuditEvent {
            event_canonical_json: body.to_string(),
            captured_at: t,
        }
    }

    #[test]
    fn append_grows_buffer() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_secs(60));
        buf.append(pending("{\"a\":1}", SystemTime::now()));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.current_bytes(), 7);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut buf = AuditRingBuffer::new(20, Duration::from_secs(60));
        let now = SystemTime::now();
        buf.append(pending("{\"first\":1}", now));
        buf.append(pending("{\"second\":2}", now));
        buf.append(pending("{\"third\":3}", now));
        assert!(buf.overflow_count() >= 1);
        let bodies: Vec<&str> = buf
            .iter()
            .map(|e| e.event_canonical_json.as_str())
            .collect();
        assert!(!bodies.iter().any(|b| b.contains("first")));
    }

    #[test]
    fn ttl_eviction_drops_expired() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_millis(100));
        let earlier = SystemTime::now() - Duration::from_secs(1);
        buf.append(pending("{\"old\":1}", earlier));
        let now = SystemTime::now();
        buf.append(pending("{\"new\":2}", now));
        let dropped = buf.evict_expired(now);
        assert_eq!(dropped, 1);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn truncate_through_drops_acked() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_secs(60));
        let now = SystemTime::now();
        buf.append(pending("{\"a\":1}", now));
        buf.append(pending("{\"b\":2}", now));
        buf.append(pending("{\"c\":3}", now));
        buf.truncate_through(1);
        assert_eq!(buf.len(), 1);
    }
}
