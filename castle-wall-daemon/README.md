# castle-wall-daemon

The OS-level egress filter that enforces the operator's allow-list at the
kernel boundary. Castle Architecture Layer 1: the kernel itself blocks
unauthorized cross-boundary calls, so even a prompt-injected agent cannot
exfiltrate. Cooperative MCP gates (Castle Layer 3) sit on top for compliant
agents; this daemon is the deterministic enforcement layer underneath them.

## Status

Phase 1 Linux: shipped through PR 2b checkpoints 1 to 5 on
`wp-castle-wall-pr2b-kernel-impl`. The crate compiles on macOS, Linux, and
Windows; the kernel-touching modules (`nftables`, `cgroup`, `nfqueue`) only
bind real kernel resources on Linux and refuse to start with structured
errors elsewhere.

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
3. **Kernel binding.** `src/nftables.rs` installs the `sanctuary-castle`
   table and per-agent rulesets via the `nft` CLI with atomic
   `add table` plus `flush` plus `add rule` transactions; `src/cgroup.rs`
   creates systemd transient scopes per wrapped agent and resolves their
   numeric cgroup-id through the systemd journal listener;
   `src/nfqueue.rs` binds the `nfq` crate with `NFQA_CFG_F_FAIL_OPEN`
   explicitly disabled (Codex amendment 7).

`src/daemon.rs` ties the three layers together and orchestrates the boot
sequence; `src/failure.rs` maps every failure mode to a fail-closed,
fail-degraded, or refuse-to-start disposition with operator-facing
messages.

## Local setup

Requires Rust stable 1.74 or newer (Cargo.toml `rust-version`).

Linux build dependencies:

```sh
sudo apt-get install -y nftables libnetfilter-queue-dev libnfnetlink-dev
```

Build and run unit tests on any platform:

```sh
cd castle-wall-daemon
cargo build
cargo test
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
   `cargo clippy --all-targets -- -D warnings`, and the full
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
