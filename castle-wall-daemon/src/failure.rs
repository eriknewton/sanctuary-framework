//! Failure-mode dispatch (F-1 through F-8 per scope-lock §7).
//!
//! Mirrors `server/src/castle-wall/failure/modes.ts`. Each FailureMode pairs
//! with a FailureDisposition; the daemon-side watchdog calls `dispatch()`
//! when it detects a fault and follows the disposition. PR 2a ships the
//! pure mapping; PR 2b wires the watchdogs (process-supervisor restart on
//! daemon crash, IPC-drop detection, external-firewall-rule clobber sweep).

/// Every named failure mode the Castle Wall recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    StartupFilterInstallFailed,
    StartupPolicyParseFailed,
    StartupIpcBindFailed,
    RuntimeDaemonCrash,
    RuntimeKernelModuleUnloaded,
    RuntimeIpcDropKernelUp,
    RuntimeExternalFirewallClobber,
    RuntimeQueueSaturated,
    /// Mid-session manifest signature or rule-digest verification failed
    /// during a reload attempt. Disposition: keep prior good policy in
    /// force, surface error to operator. Distinct from F-4 startup failure
    /// which refuses to start.
    RuntimeManifestVerifyFailed,
    /// inotify subscription or watcher loop failed; daemon is degraded to
    /// periodic mtime polling at 1s interval. Enforcement is unaffected;
    /// reload latency increases.
    RuntimeManifestWatcherDegraded,
    /// Daemon-side WAL append failed (filesystem error, permission denied,
    /// disk full). The audit ring buffer absorbs the event in memory; if
    /// the buffer overflows the next ACK carries a wal_overflow_loss
    /// audit entry per scope-lock §8.
    RuntimeAuditWalAppendFailed,
}

/// Disposition the daemon and main apply when a FailureMode fires.
#[derive(Debug, Clone)]
pub enum FailureDisposition {
    RefuseToStart {
        operator_message_key: &'static str,
    },
    FailClosed {
        emit_event: &'static str,
        reason: &'static str,
    },
    FailDegraded {
        allowed_until: &'static str,
    },
    RestoreAndAudit {
        restored_within_ms: u32,
    },
    /// Mid-session reload failure: daemon retains the prior verified policy
    /// in force and surfaces the failure to the operator. Used for F-2
    /// manifest-signature / rule-digest verification failures during a
    /// reload that did not affect the in-force ruleset.
    KeepPriorAndAudit {
        emit_event: &'static str,
    },
    /// Watcher subsystem fell back to a less-efficient polling path. Audit
    /// the degradation; reload still works, just with higher latency.
    DegradeWatcherToPoll {
        poll_interval_ms: u32,
    },
}

/// Static mapping from FailureMode to its v1.0 default disposition.
/// Mirrors DEFAULT_FAILURE_DISPOSITIONS in failure/modes.ts.
pub fn default_disposition(mode: FailureMode) -> FailureDisposition {
    match mode {
        FailureMode::StartupFilterInstallFailed => FailureDisposition::RefuseToStart {
            operator_message_key: "F-1",
        },
        FailureMode::StartupPolicyParseFailed => FailureDisposition::RefuseToStart {
            operator_message_key: "F-4",
        },
        FailureMode::StartupIpcBindFailed => FailureDisposition::RefuseToStart {
            operator_message_key: "F-3-startup",
        },
        FailureMode::RuntimeDaemonCrash => FailureDisposition::FailClosed {
            emit_event: "egress_blocked",
            reason: "no_matching_rule",
        },
        FailureMode::RuntimeKernelModuleUnloaded => FailureDisposition::FailClosed {
            emit_event: "egress_blocked",
            reason: "no_matching_rule",
        },
        FailureMode::RuntimeIpcDropKernelUp => FailureDisposition::FailDegraded {
            allowed_until: "+60s",
        },
        FailureMode::RuntimeExternalFirewallClobber => FailureDisposition::RestoreAndAudit {
            restored_within_ms: 5_000,
        },
        FailureMode::RuntimeQueueSaturated => FailureDisposition::FailClosed {
            emit_event: "egress_blocked",
            reason: "queue_saturated",
        },
        FailureMode::RuntimeManifestVerifyFailed => FailureDisposition::KeepPriorAndAudit {
            emit_event: "manifest_verify_failed_kept_prior",
        },
        FailureMode::RuntimeManifestWatcherDegraded => FailureDisposition::DegradeWatcherToPoll {
            poll_interval_ms: 1_000,
        },
        FailureMode::RuntimeAuditWalAppendFailed => FailureDisposition::FailClosed {
            emit_event: "egress_blocked",
            reason: "audit_wal_append_failed",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_failures_refuse_to_start() {
        for mode in [
            FailureMode::StartupFilterInstallFailed,
            FailureMode::StartupPolicyParseFailed,
            FailureMode::StartupIpcBindFailed,
        ] {
            assert!(matches!(
                default_disposition(mode),
                FailureDisposition::RefuseToStart { .. }
            ));
        }
    }

    #[test]
    fn runtime_crash_fails_closed() {
        let d = default_disposition(FailureMode::RuntimeDaemonCrash);
        match d {
            FailureDisposition::FailClosed { emit_event, reason } => {
                assert_eq!(emit_event, "egress_blocked");
                assert_eq!(reason, "no_matching_rule");
            }
            _ => panic!("expected FailClosed"),
        }
    }

    #[test]
    fn ipc_drop_kernel_up_fails_degraded() {
        let d = default_disposition(FailureMode::RuntimeIpcDropKernelUp);
        assert!(matches!(d, FailureDisposition::FailDegraded { .. }));
    }

    #[test]
    fn manifest_verify_failure_keeps_prior_policy() {
        let d = default_disposition(FailureMode::RuntimeManifestVerifyFailed);
        match d {
            FailureDisposition::KeepPriorAndAudit { emit_event } => {
                assert_eq!(emit_event, "manifest_verify_failed_kept_prior");
            }
            _ => panic!("expected KeepPriorAndAudit"),
        }
    }

    #[test]
    fn watcher_degradation_emits_poll_disposition() {
        let d = default_disposition(FailureMode::RuntimeManifestWatcherDegraded);
        match d {
            FailureDisposition::DegradeWatcherToPoll { poll_interval_ms } => {
                assert_eq!(poll_interval_ms, 1_000);
            }
            _ => panic!("expected DegradeWatcherToPoll"),
        }
    }

    #[test]
    fn audit_wal_append_failure_fails_closed() {
        let d = default_disposition(FailureMode::RuntimeAuditWalAppendFailed);
        match d {
            FailureDisposition::FailClosed { reason, .. } => {
                assert_eq!(reason, "audit_wal_append_failed");
            }
            _ => panic!("expected FailClosed"),
        }
    }
}
