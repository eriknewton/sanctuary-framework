# castle-wall-daemon

For one release, manifest verification accepts the exact legacy
`castle-wall:<base64url(public-key)>` signing-key ID for the pinned key. New
manifests always use the canonical 16-character SHA-256 fingerprint; legacy
emission is deprecated. The configured WAL cap also reserves one eighth of its
capacity (at most 64 KiB) for lifecycle/control recovery evidence, so ordinary
traffic cannot prevent authenticated drain recovery or force deletion of
unacknowledged rows.

The Linux Castle Wall enforcement candidate. It composes nftables, cgroup v2,
NFQUEUE, the signed policy store, authenticated IPC, and the durable audit WAL.
The privileged boot path acquires an authenticated nft ownership inventory,
binds NFQUEUE with fail-open disabled, starts a liveness-checked manifest
watcher, and sends systemd `READY=1` only after those components are live.
Per-agent mutation is one atomic nft transaction and all signed rule semantics
run in one ordered Rust evaluator behind NFQUEUE; caller-provided nft fragments
never reach the root daemon.

This is still **drill-gated**. Source and automated tests do not establish that
the reference Ubuntu host, its nft build, queue pressure behavior, reboot
recovery, and real wrapped-agent traffic satisfy the release claim. Until the
captured Gate A hardware drill passes, the published assurance remains
`not_verified`, never “Linux enforcement available.”

## Status

Linux L2 code-complete candidate: boot/runtime ownership, per-agent cgroup
binding, queue verdicts, signed policy reload, restart reconciliation, and live
health/evidence are wired. Hostname, hostname-pattern, template-id, and time
window rules are deliberately refused at policy admission: the packet path has
no authenticated DNS/SNI correlation or template attestation yet. Enforceable
rules must name a non-empty IP or CIDR destination and may narrow by port and
the exact protocol tokens `tcp`, `udp`, or `tcp+udp`.
`server/src/castle-wall/runtime/linux-policy-compatibility.ts` applies that
same typed profile before manifest signing or broker storage. The existing
host-based curated catalog is therefore intentionally refused on Linux; use an
explicit IP/CIDR Linux profile until authenticated DNS/SNI correlation lands.

Two deployment profiles are intentionally distinct:

- **Server assurance profile:** a pre-provisioned root systemd daemon and a
  dedicated non-root Sanctuary service/broker principal. Root owns the unit,
  environment, policy, keys, WAL, and state directories. Runtime code only
  attaches to the fixed active service and authenticates over its UDS; it never
  writes `/etc` or rewrites/restarts the unit. A stronger pre-auth isolation
  claim is available only after the installer and hardware drill verify this
  dedicated-principal composition.
- **Desktop/Omarchy composition profile:** the broker may share the logged-in
  desktop UID. The same framing caps, short handshake deadline, admission rate
  limits, and bounded connection slots apply, but another process with that UID
  can still consume those slots. This profile therefore carries an explicit
  residual same-UID availability limitation and must never inherit the server
  assurance claim.

Phase 2 macOS Network Extension: queued behind Apple Developer Program
filing.

Phase 3 Windows WFP: queued behind Phase 2.

## Architecture

Three layers of source, named after the surface they own.

1. **Manifest store + WAL audit.** `src/manifest/` parses, verifies, and
   pins the signed allowlist; `src/audit.rs` writes a tamper-evident
   disk-backed WAL with chained SHA-256 hashes, fsync-per-critical-entry,
   and a strict on-disk size cap. At cap, no unacknowledged evidence is
   deleted: enforcement attempts deny and policy mutations refuse until an
   authenticated drain ACK reclaims space. Any error after an append or atomic
   rewrite crosses an ambiguous durability boundary poisons that writer until
   restart/replay; supervision treats the poison as runtime loss rather than
   allowing later decisions on uncertain evidence. `src/manifest/watcher.rs` reloads on
   inotify events with TOFU pinning and cross-signed rotation. The manifest's
   fortress id must equal the configured fortress, and a durable fsynced
   generation high-water record is itself fortress-bound and refuses rollback,
   cross-fortress replacement, or same-generation reforks across daemon restart.
   A drain ACK can retire only the latest sequence actually returned on that
   same authenticated IPC connection; an empty drain, another connection's
   batch, a replay, or a guessed sequence grants no truncation authority.
   Policy reads are bounded, regular-file, single-link,
   `O_NOFOLLOW` reads. Dynamic server policy arrives only as a bounded complete
   signed bundle over the authenticated IPC session; the daemon stages it in a
   root-owned generation directory and atomically switches a durable pointer,
   so no caller path and no partially-written rule set can become active.
2. **IPC contract.** `src/ipc/` exposes the LSP-style framing parser
   (`framing.rs`), the JSON-RPC envelope shapes (`messages.rs`), the
   handshake authenticator (`auth.rs`), and the UDS server
   (`server.rs`). The framing is byte-for-byte compatible with the
   TypeScript main-process side at `server/src/castle-wall/ipc/`. Privileged
   inbound frames have independent header/body ceilings, and audit drains are
   capped by both event count and encoded response bytes.
3. **Kernel binding.** `src/nftables.rs`, `src/cgroup.rs`, and
   `src/nfqueue.rs` implement and test the `sanctuary-castle` table,
   per-agent cgroup scopes, and NFQUEUE verdict loop. `src/runtime_providers.rs`
   assembles them (plus `src/runtime_lock.rs`, `src/systemd_notify.rs`, and
   `src/thread_component.rs`) into the ordered enforcement runtime that
   `src/enforcement.rs` acquires with all-or-nothing startup, readiness gating,
   and reverse-order teardown. The shipped boot path drives this to
   `KernelRuntimeReady`; the agent lifecycle installs a marker-bound cgroup
   jump and NFQUEUE body as one transaction before it can report enforcement.
   Once acquired, the owned nftables table and its authenticated, root-owned
   ownership journal are PRESERVED across every ordinary userspace loss
   (SIGTERM, `systemctl stop`, a crash, a readiness-notify failure, a partial
   startup): ordinary teardown releases only the process-local host lock, and the
   next start ADOPTS the preserved object. Deleting the table is a separate,
   explicit recovery action (`castle-wall-daemon --disarm`), which deletes the
   owned table by handle under the host lock, verifies its absence, and clears the
   journal only after both are confirmed; it refuses a foreign or drifted table.
   `systemctl stop` is never disarm. If that authenticated proof is lost,
   corrupt, or no longer matches the installed binary source, `--disarm` cannot
   safely guess: follow the evidence-preserving, manual last-resort procedure in
   `server/docs/castle-wall-linux-deploy.md`; never delete by name merely to make
   startup pass.

`src/daemon.rs` owns the boot sequence: it starts IPC and WAL handling, then
activates the kernel runtime and sends the systemd readiness beacon only when
that runtime is live. On a supported Linux host a runtime-acquisition failure or
a failed `READY=1` delivery to a configured `NOTIFY_SOCKET` is a fail-before: the
daemon unwinds acquired resources in order (enforcement before IPC), emits no
`READY=1`, and returns a typed error so `main` exits nonzero and systemd
restarts it; it never returns a control-plane-only handle on Linux. After
readiness it SUPERVISES the runtime on a two-second cadence: the nft ownership
proof is isolated behind a one-second, fail-closed health deadline and is
single-flight and rate-limited, so a status query never forks a proof of its own
and cannot amplify into probe load. The proof is three-valued. A COMPLETED
negative proof is a PROVEN loss and is acted on at once: the daemon attempts a
critical `kernel_runtime_lost` WAL record under a short bounded deadline, tears
down enforcement before IPC even when that evidence resource is stuck, and
exits nonzero so systemd restarts it rather than leaving a live-but-not-enforcing
service reporting itself active. A deadline overrun or momentary contention
proves nothing, so it is reported as INDETERMINATE (`probe_unavailable` on the
status wire) rather than as a loss; readiness is still withheld, and three
consecutive indeterminate readings fail closed the same way a proven loss does,
bounding worst-case detection of a wedged proof at about six seconds from onset.
A wedged proof keeps the single-flight slot until it actually terminates rather
than releasing it when a caller stops waiting, so that whole sequence forks
exactly one `nft` child; the calling thread still returns within its own deadline
and shutdown stays bounded. Initial inotify subscription failure may use
the synchronously validated 2-second poll adapter only after a durable
`manifest_watcher_degraded_to_poll` audit; the serve loop stats at that audited
two-second cadence while still waking every 200ms so a stop request stays
bounded. Native inotify delivery is event-driven at the 200ms interruptible
wait and is not throttled to the fallback stat cadence. Later watcher loss is
fatal and never silently changes modes. Watcher reloads verify and stage the exact policy, write
a durable `manifest_watcher_reload_authorized` precommit record, and only then
make it live.

A policy bundle whose active pointer committed but whose required durable
success audit fails enters a distinct fatal-control state before ordinary
shutdown is requested. The supervisor prioritizes that state, performs the same
ordered enforcement-before-IPC teardown, and exits nonzero; it cannot be
misreported as a clean `systemctl stop` that bypasses `Restart=on-failure`.

The daemon and the npm consumer negotiate a protocol version and a capability
set in the handshake, so neither side assumes the other's shape and a version
skew degrades rather than deadlocks. One capability changes what Sanctuary may
claim: `audit_drain_ack_response`, the daemon's explicit confirmation that a WAL
truncation was applied. Per the 2026-09-02 owner ruling a CONFIRMED ACK is
mandatory before Sanctuary reports drain health, arms a full activation, or
claims complete enforcement. A pre-v2 daemon that does not advertise it keeps
operating (the consumer sends the ACK one-way, exactly as before, so a partial
upgrade never becomes an outage), but the consumer cannot tell a refused
truncation from an applied one, so that activation is reported as
`unconfirmed_audit_ack` and reads degraded on every health surface. A current
daemon also requires the handshake signature to cover the fortress id, key-id
label, protocol version, and complete capability list; nonce-only legacy client
signatures are rejected rather than silently downgraded. `src/failure.rs`
maps failure modes to fail-closed, fail-degraded, or refuse-to-start
dispositions with operator-facing messages.

## Local setup

Requires Rust stable 1.75 or newer (Cargo.toml `rust-version`). Local
developer checks and CI use the pinned toolchain in `rust-toolchain.toml`
so clippy diagnostics stay stable across Rust releases. The committed lockfile
and direct compatibility pins keep the dependency graph parseable and buildable
by Cargo/Rust 1.75; the dedicated `castle-wall-msrv` CI job checks the complete
locked all-target/all-feature graph on 1.75.0. Update dependency pins and the
declared floor only together with that proof.

Linux build dependencies:

The current supported enforcement baseline is Ubuntu 24.04/reference-server
hardware with an `nft` build that supports table comments and emits them through
`nft -a -j`. Absolute binary paths for Debian/Fedora/Arch layouts provide
discovery compatibility; they are not a claim that every historical distro nft
version can satisfy the ownership proof. An incompatible version refuses
activation rather than downgrading to control-plane-only.

```sh
sudo apt-get install -y nftables libnetfilter-queue-dev libnfnetlink-dev
```

Build and run unit tests on any platform:

```sh
cd castle-wall-daemon
cargo build --locked
cargo test --locked --features test-isolation
cargo clippy --locked --all-targets --all-features -- -D warnings
```

`--features test-isolation` is not optional in that command. Every test target
that can reach a host-global object (the `sanctuary-castle` nftables table, the
host ownership lock, the ownership journal and its MAC key) declares the feature
in `required-features`, so a plain `cargo test` silently builds none of them and
reports a green run that exercised no boot path at all. The feature also compiles
in the guard that refuses any `nft` call against the production table from a test
build. `tests/test_isolation_gate.rs` is the mechanical check that the two sets
stay equal, and it runs without the feature so a plain `cargo test` still catches
a missing gate.

The Linux integration tests under `tests/` additionally need root, because they
install real nftables tables, attach NFQUEUE binds, and create cgroup v2 scopes.
They install into a per-process `sanctuary-castle-test-<pid>` table and a
temporary lock/journal root, never the operator's live enforcement state:

```sh
cd castle-wall-daemon
sudo -E env "PATH=$PATH" cargo test --locked --all-targets --features test-isolation \
  -- --test-threads=1
```

The release binary is intended to land at
`/usr/local/libexec/sanctuary/castle-wall-daemon` per the systemd unit at
`systemd/sanctuary-castle-wall.service`. Inspect the unit before installing
locally; it constrains `CapabilityBoundingSet` and `RestrictAddressFamilies`
to the minimum set the daemon needs.

To cross-check Linux builds from a macOS host:

```sh
rustup target add x86_64-unknown-linux-gnu
cd castle-wall-daemon
cargo check --locked --target x86_64-unknown-linux-gnu --all-targets
cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```

## CI surface

The **`Castle Wall Linux Integration`** workflow at
`.github/workflows/castle-wall-linux.yml` runs `cargo check --locked`,
`cargo clippy --locked --all-targets --all-features -- -D warnings`, and the full
`cargo test --locked --all-targets --features test-isolation` suite (lib unittests
plus integration) on `ubuntu-24.04` as root with `CAP_NET_ADMIN`. It fires on
every PR to main and every push to main. The job asserts each gated suite appears
in the run log and that every started test binary reported a result, because a
`required-features` target that was not selected is absent from the run while
cargo still exits 0.

Both jobs must be green before this PR can be marked ready-for-review.

## Source

- `Review/Sanctuary/Castle_Wall_Phase1_Scope_Lock_2026-05-03.md`
  (ratified post-Codex amendments).
- `Review/Sanctuary/Castle_Architecture_ADR_2026-04-30.md` (parent ADR;
  the architectural intent this crate is meant to serve once the daemon boot
  path is wired to live enforcement).
- PR #117 (PR 1: TypeScript interfaces and types).
- PR #119 (PR 2a: IPC contract path plus Rust scaffold).
- PR #124 (PR 2b: kernel enforcement binding).
