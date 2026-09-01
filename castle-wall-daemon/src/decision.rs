//! Policy decision engine shared by daemon lifecycle and kernel verdict loops.
//!
//! The daemon owns process lifetime and kernel resources. The decision engine
//! owns the smaller, cloneable security path: verified policy lookup, durable
//! audit emission, and fail-closed behavior when evidence cannot be written.
//! Keeping this object independent avoids a circular ownership relationship
//! when the daemon later owns an NFQUEUE thread whose callback must evaluate
//! packets through the daemon's policy state.

use std::sync::{Arc, Mutex};

use crate::audit::{AuditRingBuffer, WalError, WalWriter};
use crate::failure::{default_disposition, FailureDisposition, FailureMode};
use crate::manifest::canonical_json::CanonicalJsonError;
use crate::manifest::ManifestStore;
use crate::policy::{build_audit_event_canonical_json, DeniedReason, EvaluationRequest, Verdict};

/// Cloneable decision surface used by both daemon compatibility methods and
/// the production NFQUEUE callback.
pub struct DecisionEngine {
    fortress_id: String,
    manifest_store: Option<Arc<Mutex<ManifestStore>>>,
    wal_writer: Option<Arc<Mutex<WalWriter>>>,
    audit_buffer: Arc<Mutex<AuditRingBuffer>>,
}

impl DecisionEngine {
    pub(crate) fn new(
        fortress_id: String,
        manifest_store: Option<Arc<Mutex<ManifestStore>>>,
        wal_writer: Option<Arc<Mutex<WalWriter>>>,
        audit_buffer: Arc<Mutex<AuditRingBuffer>>,
    ) -> Self {
        Self {
            fortress_id,
            manifest_store,
            wal_writer,
            audit_buffer,
        }
    }

    /// Verified manifest state shared with authenticated policy reloads.
    pub fn manifest_store(&self) -> Option<&Arc<Mutex<ManifestStore>>> {
        self.manifest_store.as_ref()
    }

    /// Durable WAL shared with authenticated audit drain and test injection.
    pub fn wal_writer(&self) -> Option<&Arc<Mutex<WalWriter>>> {
        self.wal_writer.as_ref()
    }

    /// Evaluate one outbound attempt and durably record the decision.
    pub fn evaluate_attempt(
        &self,
        request: &EvaluationRequest,
    ) -> Result<EvaluationOutcome, AttemptError> {
        let store = self
            .manifest_store
            .as_ref()
            .ok_or(AttemptError::ManifestStoreUnwired)?;
        let wal = self.wal_writer.as_ref().ok_or(AttemptError::WalUnwired)?;

        let (verdict, audit_fortress_id, audit_confined_agent_uid) = {
            let guard = store
                .lock()
                .map_err(|_| AttemptError::ManifestStorePoisoned)?;
            match guard.current_snapshot() {
                Some(snapshot) => (
                    snapshot.evaluate(request),
                    snapshot.fortress_id.clone(),
                    snapshot.confined_agent_uid,
                ),
                None => (
                    Verdict::Deny {
                        reason: DeniedReason::DefaultDeny,
                    },
                    self.fortress_id.clone(),
                    None,
                ),
            }
        };

        let timestamp_iso = current_timestamp_iso8601();
        let event_canonical_json = build_audit_event_canonical_json(
            &verdict,
            request,
            &audit_fortress_id,
            audit_confined_agent_uid,
            &timestamp_iso,
        )
        .map_err(AttemptError::AuditCanonicalize)?;

        let append_result = {
            let mut guard = wal.lock().map_err(|_| AttemptError::WalPoisoned)?;
            guard.append_critical(&event_canonical_json)
        };

        match append_result {
            Ok(seq) => {
                if let Ok(mut buffer) = self.audit_buffer.lock() {
                    buffer.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: event_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        critical: false,
                    });
                }
                Ok(EvaluationOutcome {
                    verdict,
                    wal_seq: Some(seq),
                    event_canonical_json,
                    timestamp_iso8601: timestamp_iso,
                })
            }
            Err(_wal_error) => {
                let disposition = default_disposition(FailureMode::RuntimeAuditWalAppendFailed);
                debug_assert!(
                    matches!(
                        disposition,
                        FailureDisposition::FailClosed {
                            emit_event: "egress_blocked",
                            reason: "audit_wal_append_failed",
                        }
                    ),
                    "RuntimeAuditWalAppendFailed must dispatch to FailClosed with the audit failure reason",
                );

                let fail_closed_verdict = Verdict::Deny {
                    reason: DeniedReason::AuditWalAppendFailed,
                };
                let fail_closed_canonical_json = build_audit_event_canonical_json(
                    &fail_closed_verdict,
                    request,
                    &audit_fortress_id,
                    audit_confined_agent_uid,
                    &timestamp_iso,
                )
                .map_err(AttemptError::AuditCanonicalize)?;

                if let Ok(mut buffer) = self.audit_buffer.lock() {
                    buffer.append(crate::audit::PendingAuditEvent {
                        event_canonical_json: fail_closed_canonical_json.clone(),
                        captured_at: std::time::SystemTime::now(),
                        critical: true,
                    });
                }

                Ok(EvaluationOutcome {
                    verdict: fail_closed_verdict,
                    wal_seq: None,
                    event_canonical_json: fail_closed_canonical_json,
                    timestamp_iso8601: timestamp_iso,
                })
            }
        }
    }
}

/// Policy decision plus its durable evidence receipt.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub verdict: Verdict,
    pub wal_seq: Option<u64>,
    pub event_canonical_json: String,
    pub timestamp_iso8601: String,
}

/// Errors returned before a kernel verdict can be produced.
#[derive(Debug, thiserror::Error)]
pub enum AttemptError {
    #[error("manifest store not wired into this decision engine")]
    ManifestStoreUnwired,
    #[error("WAL writer not wired into this decision engine")]
    WalUnwired,
    #[error("manifest store mutex poisoned")]
    ManifestStorePoisoned,
    #[error("WAL writer mutex poisoned")]
    WalPoisoned,
    #[error("audit-event canonicalization failed: {0}")]
    AuditCanonicalize(CanonicalJsonError),
    #[error("WAL append failed: {0}")]
    WalAppend(WalError),
}

fn current_timestamp_iso8601() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_ms = duration.as_millis() as i128;
    let seconds = (total_ms / 1000) as i64;
    let milliseconds = (total_ms % 1000) as i64;
    let (year, month, day, hour, minute, second) = ymd_hms_from_unix_seconds(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

fn ymd_hms_from_unix_seconds(unix_seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let seconds_per_day: i64 = 86_400;
    let mut days = unix_seconds.div_euclid(seconds_per_day);
    let mut seconds_of_day = unix_seconds.rem_euclid(seconds_per_day);
    if seconds_of_day < 0 {
        seconds_of_day += seconds_per_day;
        days -= 1;
    }
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = (if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    }) as u32;
    let calendar_year = (if month <= 2 { year + 1 } else { year }) as i32;
    let hour = (seconds_of_day / 3600) as u32;
    let minute = ((seconds_of_day % 3600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    (calendar_year, month, day, hour, minute, second)
}
