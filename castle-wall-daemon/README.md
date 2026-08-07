# castle-wall-daemon

The Linux Castle Wall source crate. Its nftables, cgroup, and NFQUEUE modules
are tested against a real kernel, but the shipped daemon boot path does not
install those modules into live enforcement yet. Open defect: **IC-02, IC-03,
IC-04** (`Review/Sanctuary/Inert_Capability_Sweep_2026-08-07.md`).
Cooperative MCP gates sit on top for compliant agents; Linux kernel enforcement
is still partial until the shipped daemon assembles the tested loop.

## Status

Phase 1 Linux: partial, not shipped as live enforcement. PR 2b landed and tests
the kernel-touching modules (`nftables`, `cgroup`, `nfqueue`), but
`daemon::boot` does not install an nftables table, bind NFQUEUE, create cgroup
scopes, or call the deny-by-default evaluator. The shipped systemd unit is also
`Type=notify` while the daemon never sends readiness. Open defect: **IC-02,
IC-03, IC-04** (`Review/Sanctuary/Inert_Capability_Sweep_2026-08-07.md`).

Phase 2 macOS Network Extension: queued behind Apple Developer Program
filing.

Phase 3 Windows WFP: queued behind Phase 2.

## Architecture

Three layers of source, named after the surface they own.

1. **Manifest store + WAL audit.** `src/manifest/` parses, verifies, and
   pins the signed allowlist; `src/audit.rs` writes a tamper-evident
   ring-buffer-backed WAL with chained SHA-256 hashes, fsync-per-entry,
   and TTL plus size-cap eviction. `src/manifest/watcher.rs` reloads on
   inotify events with TOFU pinning and cross-signed rotation.
2. **IPC contract.** `src/ipc/` exposes the LSP-style framing parser
   (`framing.rs`), the JSON-RPC envelope shapes (`messages.rs`), the
   handshake authenticator (`auth.rs`), and the UDS server
   (`server.rs`). The framing is byte-for-byte compatible with the
   TypeScript main-process side at `server/src/castle-wall/ipc/`.
3. **Kernel binding.** `src/nftables.rs`, `src/cgroup.rs`, and
   `src/nfqueue.rs` implement and test the intended `sanctuary-castle`
   table, per-agent cgroup scopes, and NFQUEUE verdict loop. The shipped
   daemon boot path does not call them yet. Open defect: **IC-02, IC-04**
   (`Review/Sanctuary/Inert_Capability_Sweep_2026-08-07.md`).

`src/daemon.rs` owns the boot sequence but currently starts IPC and WAL
handling without installing kernel enforcement. Open defect: **IC-02, IC-04**
(`Review/Sanctuary/Inert_Capability_Sweep_2026-08-07.md`). `src/failure.rs`
maps failure modes to fail-closed, fail-degraded, or refuse-to-start
dispositions with operator-facing messages.

## Local setup

Requires Rust stable 1.74 or newer (Cargo.toml `rust-version`). Local
developer checks and CI use the pinned toolchain in `rust-toolchain.toml`
so clippy diagnostics stay stable across Rust releases.

Linux build dependencies:

```sh
sudo apt-get install -y nftables libnetfilter-queue-dev libnfnetlink-dev
```

Build and run unit tests on any platform:

```sh
cd castle-wall-daemon
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The Linux integration tests under `tests/` need root because they install
real nftables tables, attach NFQUEUE binds, and create cgroup v2 scopes:

```sh
cd castle-wall-daemon
sudo -E env "PATH=$PATH" cargo test --all-targets -- --test-threads=1
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
cargo check --target x86_64-unknown-linux-gnu --all-targets
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```

## CI surface

Two GitHub Actions workflows guard this crate.

1. **`Castle Wall Linux Integration`** at
   `.github/workflows/castle-wall-linux.yml`. Runs `cargo check`,
   `cargo clippy --all-targets --all-features -- -D warnings`, and the full
   `cargo test --all-targets` suite (lib unittests plus integration) on
   `ubuntu-24.04` as root with `CAP_NET_ADMIN`. Fires on every PR to main
   and every push to main.
2. **`CI` Linux cross-compile gate** at `.github/workflows/ci.yml`. Runs
   `cargo check --target x86_64-unknown-linux-gnu --all-targets` from a
   macOS-style developer host so contract changes that compile on macOS
   but break on Linux are caught before they reach the Linux runner.

Both jobs must be green before this PR can be marked ready-for-review.

## Source

- `Review/Sanctuary/Castle_Wall_Phase1_Scope_Lock_2026-05-03.md`
  (ratified post-Codex amendments).
- `Review/Sanctuary/Castle_Architecture_ADR_2026-04-30.md` (parent ADR;
  the architectural intent that this crate enforces).
- PR #117 (PR 1: TypeScript interfaces and types).
- PR #119 (PR 2a: IPC contract path plus Rust scaffold).
- PR #124 (PR 2b: kernel enforcement binding).
