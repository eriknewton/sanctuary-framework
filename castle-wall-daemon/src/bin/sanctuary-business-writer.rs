//! Fixed writer composition; no unit installation or grant authority.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::{refused, ROOT_UID},
        signer_peer::{drop_capabilities_with, CapabilityDrop},
        signer_watchdog::boottime_ns,
        writer_peer::{BusTarget, HeldConfig, ListenerExpectations},
        writer_service::{
            self, Activation, ClientSignerPort, ClosedReconciler, ClosurePaths, Dependencies,
            Notifier, SystemNotifier,
        },
    };
    use std::{
        os::fd::{FromRawFd, OwnedFd},
        sync::Arc,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "test-isolation")]
    if args.len() == 2 && args[0] == std::hint::black_box("--test-writer") {
        std::hint::black_box(writer_service::WRITER_TEST_SEAM_MARKER);
        drop_capabilities_with(CapabilityDrop::Writer { isolation: true })?;
        return writer_service::test_entry(std::path::Path::new(&args[1]));
    }
    if !args.is_empty() || unsafe { libc::geteuid() } != ROOT_UID {
        return Err(refused());
    }
    drop_capabilities_with(CapabilityDrop::Writer { isolation: false })?;
    let setup = (|| {
        let config = HeldConfig::production().map_err(|_| refused())?;
        let expectations = ListenerExpectations::production(config.value.writer_socket_gid);
        let signer =
            ClientSignerPort::bootstrap(config.value.signer.clone()).map_err(|_| refused())?;
        // fd 3 is systemd's first inherited descriptor; run validates its complete identity before READY.
        if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
            return Err(refused());
        }
        Ok(Dependencies {
            signer,
            // Must match test_isolation_gate::writer_execute_composes_the_closed_reconciler.
            reconciler: ClosedReconciler::production(),
            notifier: SystemNotifier,
            config,
            bus: BusTarget::production(),
            listener: unsafe { OwnedFd::from_raw_fd(3) },
            expectations,
            activation: Activation::environment()?,
            clock: Arc::new(boottime_ns),
            paths: ClosurePaths::production(),
            environment: std::env::vars_os().map(|(k, _)| k).collect(),
        })
    })();
    match setup {
        Ok(deps) => writer_service::run(deps).map_err(|_| refused()),
        Err(e) => {
            let _ = SystemNotifier.notify("STATUS=writer refused at start");
            Err(e)
        }
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    if execute().is_ok() {
        return;
    }
    // SAFETY: The fixed refusal discloses neither record bytes nor factor material.
    eprintln!("K1_REFUSED");
    std::process::exit(1);
}
