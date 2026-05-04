# castle-wall-daemon

Sanctuary Castle Wall filter daemon. Castle Architecture Layer 1 enforcement: the kernel itself blocks unauthorized cross-boundary calls so even prompt-injected agents cannot bypass.

This crate ships in two PRs.

## PR 2a (this PR): IPC contract path + Rust scaffold

Lands the load-bearing surfaces that PR 2b's kernel work needs:

- LSP-style framing: `src/ipc/framing.rs`. Mirrors `server/src/castle-wall/ipc/framing.ts` byte-for-byte.
- Message envelopes: `src/ipc/messages.rs`. Mirrors `server/src/castle-wall/ipc/messages.ts`. Serde-derived JSON.
- Manifest verifier: `src/manifest/verify.rs`. Ed25519 + canonical-JSON + per-rule SHA-256, mirroring `server/src/castle-wall/allowlist/parse.ts`.
- Canonical-JSON encoder: `src/manifest/canonical_json.rs`. Mirrors `server/src/mesh/canonical-json.ts`.
- WAL audit ring buffer: `src/audit.rs`. In-memory portion; PR 2b adds the disk writer.
- Approval coalescing + nonce store: `src/approval.rs`. Pure data structures and pure decision functions.
- Failure-mode dispatch: `src/failure.rs`. F-1 through F-8 default disposition table.
- Policy snapshot types: `src/policy.rs`. The shape PR 2b's evaluator runs against.
- Daemon configuration: `src/config.rs`. CLI argv parsing and canonical Linux layout defaults.
- Module stubs (kernel-touching): `src/nftables.rs`, `src/cgroup.rs`, `src/nfqueue.rs`. Each declares its public surface and returns `NotImplementedInPhase2a` until PR 2b lands.

Binary behavior in PR 2a: `--help` and `--phase2a-stub` flags work end-to-end. Without `--phase2a-stub` the binary refuses to run and points the operator at the README.

## PR 2b (separate dispatch): kernel enforcement

Replaces the stubs with real implementations:

- nftables CLI shell-out with atomic ruleset replacement; rules installed in dedicated `sanctuary-castle` table for E7.2 namespace separation.
- cgroup v2 systemd transient scope creation per wrapped agent; cgroup-id resolution via systemd journal listener (the cgroup-id-renumbering pattern from `systemd-cgroup-nftables-policy-manager`).
- NFQUEUE bind via the `nfq` crate with `NFQA_CFG_F_FAIL_OPEN` explicitly **disabled** (Codex amendment 7).
- inotify manifest watcher with TOFU pinning + cross-signed rotation acceptance.
- Disk-backed WAL writer with `fsync`-per-entry and TTL + size-cap eviction.
- Watchdogs that detect each FailureMode and call `failure::default_disposition()`.
- DNS / DoH / DoT bypass test suite per scope-lock §1 + §9.

PR 2b also adds the new `castle-wall-linux-integration` GitHub Actions job that runs the kernel integration tests on `ubuntu-22.04` and `ubuntu-24.04` runners with `CAP_NET_ADMIN`.

## Source

- `Review/Sanctuary/Castle_Wall_Phase1_Scope_Lock_2026-05-03.md` (ratified post-Codex amendments)
- `Review/Sanctuary/Castle_Architecture_ADR_2026-04-30.md` (parent ADR)
- PR #117 on `eriknewton/sanctuary-framework` (PR 1: TypeScript interfaces and types)

## Build

```sh
cargo build --release
cargo test
```

The release binary is intended to land at `/usr/local/libexec/sanctuary/castle-wall-daemon` per the systemd unit at `systemd/sanctuary-castle-wall.service`.

## Castle-walking test answer for PR 2a

PR 2a ships the contract path that PR 2b's kernel enforcement consumes. The Castle Layer 1 enforcement promise is satisfied across the wave (PR 2a + PR 2b merged); PR 2a alone does not enforce. The TS runtime + Rust scaffold + module stubs are designed so PR 2b's drop-in implementations land without contract changes.
