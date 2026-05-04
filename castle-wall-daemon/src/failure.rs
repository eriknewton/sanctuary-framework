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
}
