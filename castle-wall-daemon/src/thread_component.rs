//! Thread-backed enforcement component: bind-then-serve with honest health.
//!
//! Both the NFQUEUE verdict loop and the manifest watcher are the same lifecycle
//! shape: the boot thread performs a one-shot BIND (open+bind the queue; start
//! the inotify/poll watch), an optional worker startup check completes an
//! explicit handshake, and only then does the component become ready; the
//! thread then runs a serve loop until asked to stop. This
//! type factors that shape out so the readiness, health, thread-ownership, and
//! join-on-release invariants are written and TESTED once, cross-platform, with
//! the kernel-specific work supplied as closures.
//!
//! The invariants it guarantees, exercised by the tests below on the dev host
//! (no kernel required):
//!
//! * **Ready only after a successful bind.** The BIND runs SYNCHRONOUSLY on the
//!   calling (boot) thread; `spawn` returns `Ok` only after it succeeds, so a
//!   component is never handed to the runtime in a not-yet-bound state. A bind
//!   that fails yields `AcquireFailed` and no thread is ever spawned.
//! * **Worker startup checks are readiness barriers.** The watcher uses
//!   `spawn_with_worker_init` to perform its first actual inotify/poll read on
//!   the worker. A failed first read is returned before the runtime can become
//!   ready or the daemon can send `READY=1`.
//! * **No false bounded ready timeout, no leaked binder.** (blocker 8) Earlier
//!   this type bound the bind with a `ready_timeout` on a worker thread, but a
//!   wedged kernel bind ignores the stop flag, so the timeout path's join could
//!   block forever — the "bound" was a lie and the binder thread was
//!   uninterruptible. Binding synchronously removes the timeout entirely: a
//!   wedged bind blocks the boot thread and is bounded at the PROCESS level by
//!   systemd's `TimeoutStartSec` (see the shipped unit), which kills the whole
//!   process. Nothing is detached, because the serve thread is spawned only
//!   AFTER the bind returns.
//! * **Health goes non-green the instant the thread stops.** If the serve loop
//!   returns (queue closed, watcher error) OR panics, the worker clears the
//!   health flag on its way out, so [`is_ready`](AcquiredComponent::is_ready)
//!   flips to false. A dead verdict thread can never read as ready.
//! * **Exclusive teardown.** `release` sets the stop flag and joins the worker
//!   before returning. A worker stuck in an uninterruptible kernel/filesystem
//!   call intentionally keeps teardown and the host ownership lock blocked;
//!   systemd `TimeoutStopSec`/`KillMode=control-group` supplies the outer hard
//!   bound by killing the whole process, atomically releasing worker resources
//!   and the process-held ownership lock. No worker is ever detached while a
//!   successor can acquire exclusivity.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::enforcement::{AcquiredComponent, ComponentKind, EnforcementError};

/// A component whose resource is owned by a worker thread. Construct with
/// [`spawn`](Self::spawn).
pub struct ThreadBackedComponent {
    kind: ComponentKind,
    /// True once the worker startup handshake succeeds; cleared on worker exit.
    ready: Arc<AtomicBool>,
    /// True while the worker thread is alive and its serve loop has not
    /// returned/panicked. Cleared on any thread exit, which is what turns
    /// readiness non-green on a verdict-thread death.
    healthy: Arc<AtomicBool>,
    heartbeat: Option<(Arc<Mutex<Instant>>, Duration)>,
    /// Set by `release` to ask the serve loop to stop.
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    released: bool,
}

impl ThreadBackedComponent {
    /// Bind the resource SYNCHRONOUSLY on the calling thread, then spawn the
    /// serve loop. `bind` returns the owned resource (or fails-before); `serve`
    /// then runs the loop on a worker thread, checking the shared stop flag.
    ///
    /// On a successful bind, returns a ready component owning the live serve
    /// thread. On a bind failure, no thread is spawned and `AcquireFailed` is
    /// returned. There is deliberately NO ready timeout (blocker 8): a wedged
    /// kernel bind blocks THIS call, and process-level bounding is delegated to
    /// systemd's `TimeoutStartSec` rather than to a fake in-process deadline
    /// whose recovery join could itself block forever on an uninterruptible
    /// binder. Because the serve thread is spawned only after the bind returns,
    /// a failed or wedged bind never leaves a detached thread behind.
    pub fn spawn<S, B, R>(kind: ComponentKind, bind: B, serve: R) -> Result<Self, EnforcementError>
    where
        // `S` is the bound resource. Binding synchronously here and then moving
        // the resource INTO the serve thread means `S` crosses the thread
        // boundary exactly once, so it must be `Send + 'static`. `bind` runs on
        // the calling thread and needs no `Send`/`'static` bound; only `serve`
        // (moved to the worker) and the moved resource do.
        S: Send + 'static,
        B: FnOnce() -> Result<S, EnforcementError>,
        R: FnOnce(S, &AtomicBool) + Send + 'static,
    {
        Self::spawn_with_worker_init(kind, bind, |_| Ok(()), serve)
    }

    /// Bind synchronously, then require a worker-thread startup check to succeed
    /// before returning a ready component. The caller blocks on an explicit
    /// handshake from the worker; a failed or panicking check is joined and
    /// returned as a fail-before, so callers cannot observe a transient ready
    /// state before the worker has proved it can perform its first operation.
    ///
    /// This is the watcher path's readiness primitive: `initialize` performs the
    /// first real inotify/poll read on the worker thread. Like the synchronous
    /// bind, a wedged startup check is bounded by systemd `TimeoutStartSec`.
    pub fn spawn_with_worker_init<S, B, I, R>(
        kind: ComponentKind,
        bind: B,
        initialize: I,
        serve: R,
    ) -> Result<Self, EnforcementError>
    where
        S: Send + 'static,
        B: FnOnce() -> Result<S, EnforcementError>,
        I: FnOnce(&mut S) -> Result<(), EnforcementError> + Send + 'static,
        R: FnOnce(S, &AtomicBool) + Send + 'static,
    {
        // Synchronous bind on the calling thread. A bind failure fails-before
        // with no thread spawned; a wedged bind blocks here and is bounded by
        // systemd `TimeoutStartSec` at the process level.
        let mut resource = bind()?;

        // Bind succeeded, but readiness remains false until the worker completes
        // its startup check and sends the explicit success handshake below.
        let ready = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let (startup_tx, startup_rx) = mpsc::sync_channel(0);

        let worker_ready = Arc::clone(&ready);
        let worker_healthy = Arc::clone(&healthy);
        let worker_stop = Arc::clone(&stop);

        let thread = std::thread::spawn(move || {
            let startup = std::panic::catch_unwind(AssertUnwindSafe(|| initialize(&mut resource)));
            match startup {
                Ok(Ok(())) => {
                    // Publish ready BEFORE the handshake. The zero-capacity channel
                    // means the caller cannot return until this exact worker has
                    // completed the check and rendezvoused with it.
                    worker_ready.store(true, Ordering::SeqCst);
                    if startup_tx.send(Ok(())).is_err() {
                        worker_ready.store(false, Ordering::SeqCst);
                        worker_healthy.store(false, Ordering::SeqCst);
                        return;
                    }
                }
                Ok(Err(err)) => {
                    let _ = startup_tx.send(Err(err));
                    worker_healthy.store(false, Ordering::SeqCst);
                    return;
                }
                Err(_) => {
                    let _ = startup_tx.send(Err(EnforcementError::AcquireFailed {
                        kind: kind.as_str(),
                        detail: "worker startup check panicked".to_string(),
                    }));
                    worker_healthy.store(false, Ordering::SeqCst);
                    return;
                }
            }
            // Serve until stopped. A panic in the serve loop is caught so it turns
            // into loss-of-health (below) rather than a silent thread death whose
            // panic payload is lost; either way the thread is exiting.
            let stop_ref: &AtomicBool = &worker_stop;
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| serve(resource, stop_ref)));
            // Thread is exiting (clean return OR caught panic): no longer serving,
            // so readiness and health both go non-green. This is the signal a
            // dead verdict thread / failed watcher surfaces to `is_ready`.
            worker_ready.store(false, Ordering::SeqCst);
            worker_healthy.store(false, Ordering::SeqCst);
        });

        match startup_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = thread.join();
                return Err(err);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(EnforcementError::AcquireFailed {
                    kind: kind.as_str(),
                    detail: "worker exited before completing its startup handshake".to_string(),
                });
            }
        }

        Ok(Self {
            kind,
            ready,
            healthy,
            heartbeat: None,
            stop,
            thread: Some(thread),
            released: false,
        })
    }

    /// Spawn a component whose serve loop publishes a heartbeat. `is_ready`
    /// becomes false if the worker remains alive but makes no progress for the
    /// supplied deadline (for example, a manifest read wedged in a filesystem
    /// syscall). The outer systemd timeout still owns forced process cleanup.
    pub fn spawn_with_worker_init_and_heartbeat<S, B, I, R>(
        kind: ComponentKind,
        bind: B,
        initialize: I,
        max_staleness: Duration,
        serve: R,
    ) -> Result<Self, EnforcementError>
    where
        S: Send + 'static,
        B: FnOnce() -> Result<S, EnforcementError>,
        I: FnOnce(&mut S) -> Result<(), EnforcementError> + Send + 'static,
        R: FnOnce(S, &AtomicBool, Arc<Mutex<Instant>>) + Send + 'static,
    {
        let heartbeat = Arc::new(Mutex::new(Instant::now()));
        let worker_heartbeat = Arc::clone(&heartbeat);
        let mut component =
            Self::spawn_with_worker_init(kind, bind, initialize, move |resource, stop| {
                serve(resource, stop, worker_heartbeat);
            })?;
        component.heartbeat = Some((heartbeat, max_staleness));
        Ok(component)
    }
}

impl AcquiredComponent for ThreadBackedComponent {
    fn kind(&self) -> ComponentKind {
        self.kind
    }

    fn is_ready(&self) -> bool {
        matches!(self.health(), crate::enforcement::ComponentHealth::Ready)
    }

    fn health(&self) -> crate::enforcement::ComponentHealth {
        use crate::enforcement::ComponentHealth;
        use std::sync::TryLockError;
        if self.released
            || !self.ready.load(Ordering::SeqCst)
            || !self.healthy.load(Ordering::SeqCst)
        {
            return ComponentHealth::Lost;
        }
        let Some((heartbeat, deadline)) = self.heartbeat.as_ref() else {
            return ComponentHealth::Ready;
        };
        match heartbeat.try_lock() {
            Ok(at) if at.elapsed() <= *deadline => ComponentHealth::Ready,
            Ok(_) | Err(TryLockError::Poisoned(_)) => ComponentHealth::Lost,
            Err(TryLockError::WouldBlock) => ComponentHealth::ProbeUnavailable,
        }
    }

    fn release(&mut self) {
        if self.released {
            return; // idempotent
        }
        // Ask the serve loop to stop, then retain this component (and therefore
        // the runtime's predecessor host lock) until the worker is actually
        // gone. An uninterruptible syscall is bounded by systemd killing the
        // whole process; detaching here would let a successor acquire the host
        // lock while the old NFQUEUE/watcher still owns resources.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        self.released = true;
    }
}

impl Drop for ThreadBackedComponent {
    fn drop(&mut self) {
        // Last line of defense for the no-detached-thread invariant.
        self.release();
    }
}

impl std::fmt::Debug for ThreadBackedComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadBackedComponent")
            .field("kind", &self.kind)
            .field("ready", &self.ready.load(Ordering::SeqCst))
            .field("healthy", &self.healthy.load(Ordering::SeqCst))
            .field("released", &self.released)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_until(mut predicate: impl FnMut() -> bool, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        predicate()
    }

    #[test]
    fn ready_only_after_a_successful_bind() {
        // The synchronous bind sleeps briefly; spawn blocks until it completes,
        // then the component is ready. Proves readiness is gated on the bind
        // returning Ok before any serve thread runs.
        let component = ThreadBackedComponent::spawn(
            ComponentKind::Nfqueue,
            || {
                std::thread::sleep(Duration::from_millis(20));
                Ok(())
            },
            |(), stop| {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        )
        .expect("bind succeeds");
        assert!(component.is_ready(), "ready after a successful bind");
    }

    #[test]
    fn bind_failure_is_a_fail_before_with_no_spawned_thread() {
        // A failing SYNCHRONOUS bind yields AcquireFailed and spawns no thread,
        // so nothing is left running. The bind closure records that it ran and
        // the serve closure records that it did NOT.
        let bind_ran = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicBool::new(false));
        let bind_ran_c = Arc::clone(&bind_ran);
        let served_c = Arc::clone(&served);
        let err = ThreadBackedComponent::spawn(
            ComponentKind::Nfqueue,
            move || -> Result<(), EnforcementError> {
                bind_ran_c.store(true, Ordering::SeqCst);
                Err(EnforcementError::AcquireFailed {
                    kind: ComponentKind::Nfqueue.as_str(),
                    detail: "kernel bind refused".into(),
                })
            },
            move |(), _stop| served_c.store(true, Ordering::SeqCst),
        )
        .expect_err("bind failure must fail-before");
        assert!(matches!(err, EnforcementError::AcquireFailed { .. }));
        assert!(
            bind_ran.load(Ordering::SeqCst),
            "the bind ran on this thread"
        );
        // Give any (erroneously) spawned thread a chance to run before asserting.
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !served.load(Ordering::SeqCst),
            "a failed bind must spawn no serve thread"
        );
    }

    #[test]
    fn worker_startup_error_is_a_fail_before_and_never_serves() {
        let initialized = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicBool::new(false));
        let initialized_c = Arc::clone(&initialized);
        let served_c = Arc::clone(&served);
        let err = ThreadBackedComponent::spawn_with_worker_init(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            move |()| {
                initialized_c.store(true, Ordering::SeqCst);
                Err(EnforcementError::AcquireFailed {
                    kind: ComponentKind::ManifestWatcher.as_str(),
                    detail: "first watcher read failed".to_string(),
                })
            },
            move |(), _stop| served_c.store(true, Ordering::SeqCst),
        )
        .expect_err("a first-read error must fail before readiness");
        assert!(matches!(err, EnforcementError::AcquireFailed { .. }));
        assert!(initialized.load(Ordering::SeqCst));
        assert!(
            !served.load(Ordering::SeqCst),
            "serve must never run after the startup check fails"
        );
    }

    #[test]
    fn worker_success_handshake_completes_before_component_is_returned_ready() {
        let initialized = Arc::new(AtomicBool::new(false));
        let initialized_c = Arc::clone(&initialized);
        let component = ThreadBackedComponent::spawn_with_worker_init(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            move |()| {
                initialized_c.store(true, Ordering::SeqCst);
                Ok(())
            },
            |(), stop| {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        )
        .expect("startup handshake succeeds");
        assert!(
            initialized.load(Ordering::SeqCst),
            "spawn must not return before the worker startup check completes"
        );
        assert!(component.is_ready());
    }

    #[test]
    fn thread_exit_turns_health_non_green() {
        // The serve loop returns immediately (as if the queue closed). Health must
        // go non-green so the component reads not-ready without any manual probe.
        let component = ThreadBackedComponent::spawn(
            ComponentKind::Nfqueue,
            || Ok(()),
            |(), _stop| { /* serve returns at once: models a dead verdict loop */ },
        )
        .expect("bind succeeds");
        assert!(
            wait_until(|| !component.is_ready(), Duration::from_secs(2)),
            "a serve loop that exits must turn is_ready false"
        );
    }

    #[test]
    fn thread_panic_turns_health_non_green() {
        // A panic in the serve loop is caught and turned into loss-of-health, not
        // a silent death; the component reads not-ready afterward.
        let component = ThreadBackedComponent::spawn(
            ComponentKind::Nfqueue,
            || Ok(()),
            |(), _stop| panic!("verdict loop panicked"),
        )
        .expect("bind succeeds");
        assert!(
            wait_until(|| !component.is_ready(), Duration::from_secs(2)),
            "a panicking serve loop must turn is_ready false"
        );
    }

    #[test]
    fn release_joins_the_worker_thread() {
        // The serve loop marks itself alive and clears the flag only after its
        // loop exits; release must join, so the flag is observably cleared once
        // release returns.
        let alive = Arc::new(AtomicBool::new(false));
        let alive_for_worker = Arc::clone(&alive);
        let mut component = ThreadBackedComponent::spawn(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            move |(), stop| {
                alive_for_worker.store(true, Ordering::SeqCst);
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                alive_for_worker.store(false, Ordering::SeqCst);
            },
        )
        .expect("bind succeeds");
        assert!(wait_until(
            || alive.load(Ordering::SeqCst),
            Duration::from_secs(2)
        ));
        component.release();
        assert!(
            !alive.load(Ordering::SeqCst),
            "release must join the worker before returning"
        );
        component.release(); // idempotent, no panic
    }

    #[test]
    fn release_never_detaches_a_worker_that_has_not_stopped() {
        let blocked = Arc::new(AtomicBool::new(true));
        let blocked_worker = Arc::clone(&blocked);
        let component = ThreadBackedComponent::spawn(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            move |(), _stop| {
                while blocked_worker.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            },
        )
        .expect("bind succeeds");
        let release_done = Arc::new(AtomicBool::new(false));
        let release_done_worker = Arc::clone(&release_done);
        let releaser = std::thread::spawn(move || {
            let mut component = component;
            component.release();
            release_done_worker.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !release_done.load(Ordering::SeqCst),
            "release must retain ownership while the worker is still alive"
        );
        blocked.store(false, Ordering::SeqCst);
        releaser.join().expect("release joins after worker exits");
        assert!(release_done.load(Ordering::SeqCst));
    }

    #[test]
    fn contended_heartbeat_is_unavailable_while_stale_or_poisoned_is_lost() {
        use crate::enforcement::ComponentHealth;
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let release = Arc::new(AtomicBool::new(false));
        let release_worker = Arc::clone(&release);
        let mut component = ThreadBackedComponent::spawn_with_worker_init_and_heartbeat(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            |_| Ok(()),
            Duration::from_millis(25),
            move |(), stop, heartbeat| {
                let _guard = heartbeat.lock().unwrap();
                holding_tx.send(()).unwrap();
                while !stop.load(Ordering::SeqCst) && !release_worker.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        )
        .unwrap();
        holding_rx.recv().unwrap();
        assert_eq!(component.health(), ComponentHealth::ProbeUnavailable);
        release.store(true, Ordering::SeqCst);
        assert!(wait_until(
            || component.health() == ComponentHealth::Lost,
            Duration::from_secs(1)
        ));
        component.release();
    }

    #[test]
    fn stale_and_poisoned_heartbeats_are_proven_lost() {
        use crate::enforcement::ComponentHealth;
        let mut stale = ThreadBackedComponent::spawn_with_worker_init_and_heartbeat(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            |_| Ok(()),
            Duration::from_millis(5),
            |(), stop, _heartbeat| {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(stale.health(), ComponentHealth::Lost);
        stale.release();

        let mut poisoned = ThreadBackedComponent::spawn_with_worker_init_and_heartbeat(
            ComponentKind::ManifestWatcher,
            || Ok(()),
            |_| Ok(()),
            Duration::from_secs(1),
            |(), stop, _heartbeat| {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            },
        )
        .unwrap();
        let heartbeat = Arc::clone(&poisoned.heartbeat.as_ref().unwrap().0);
        let _ = std::thread::spawn(move || {
            let _guard = heartbeat.lock().unwrap();
            panic!("poison heartbeat");
        })
        .join();
        assert_eq!(poisoned.health(), ComponentHealth::Lost);
        poisoned.release();
    }
}
