# Plugin-host hostile-plugin drill (slice S5) — 2026-06-24

Pre-declared acceptance drill for the Linux plugin host. A **hostile plugin** — one
that actively tries to break out of its jail and break the vendor contract — must be
fully contained. This drill banks the evidence (drill-acceptance rule: N>=3 each).

The drill has two halves, because plugin confinement is enforced at two layers:

| Layer | What it proves | Where it runs | Test file |
|---|---|---|---|
| Kernel confinement | the `plugin-v1` seccomp jail + launcher pivot_root deny the escape syscalls and host-filesystem reads | Rust, Linux only | `castle-wall-daemon/tests/plugin_hostile_drill.rs` |
| Contract confinement | a plugin that lies / desyncs / floods / exfils on the wire is contained by the host; a plugin can never pick its own enforcement trigger | TypeScript, any platform | `server/test/substrate/reference-plugin/hostile-plugin-contract.drill.test.ts` |

## Pre-declared probes (fixed before the run)

Kernel (Rust drill), each DENIED, N>=3:

1. raw socket: `socket(AF_INET, ...)` returns `EPERM`. The `plugin-v1` seccomp profile
   allows only `AF_UNIX`, so a plugin cannot open any internet socket.
2. ptrace: `ptrace(PTRACE_TRACEME)` returns `EPERM`. No process inspection.
3. daemon-port connect: a connect to a loopback daemon port is unreachable because
   probe 1 denies creating the `AF_INET` socket the connect needs.
4. host-file read: a host path (`/etc/shadow`) outside the bundle is absent (`ENOENT`)
   after entering a user+mount namespace and pivoting into an empty rootfs. When
   unprivileged userns is unavailable in the CI sandbox the probe is recorded as
   `launcher_covered` (the launcher's pivot_root is the file-confinement mechanism,
   proven by `plugin_launcher_failclosed.rs`), never silently skipped.

A liveness check (the allowed `AF_UNIX` socketpair still works) accompanies every run
so the jail is proven selective, not "deny everything".

Contract (TypeScript drill), each contained -> egress DENY, N>=3: `allow` (fabricated
verdict), `plugin_error` (host-minted only), `bad_nonce`, `bad_request_id`,
`dup_decision` (split-brain duplicate key), `oversized` frame, `proto_pollute`
(`__proto__` key), `silent` (timeout), `crash`. Plus: an undeclared signal key is
dropped/rejected (return-path exfil contained), and a plugin-sourced finding can never
pick an enforcement trigger (H1 governed-side-door: `plugin:`-prefixed findings are
inbox-only regardless of the vendor-chosen id or any vendor-supplied detail key).

## How to run

```sh
# Contract drill (any platform):
cd server
npx vitest run test/substrate/reference-plugin/hostile-plugin-contract.drill.test.ts

# Kernel drill (Linux):
cd castle-wall-daemon
cargo test --test plugin_hostile_drill -- --nocapture
# (also compiled against the musl static-jail target in CI:
#  cargo test --target x86_64-unknown-linux-musl --test plugin_hostile_drill)
```

Both drills print one JSON evidence line per run plus a summary line.

## Banked evidence (this run)

Build host: macOS (the contract drill is platform-independent; the kernel drill runs
in Linux CI — consistent with the thesis-gate rule that Linux-confinement claims trace
to Linux evidence, the kernel half is CI-verified, not locally captured on this run).

Contract drill, N=3, all 9 attack modes contained to egress DENY every run:

```
{"drill":"plugin-hostile-contract","run":1,"results":[{"mode":"allow","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"plugin_error","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_nonce","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_request_id","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"dup_decision","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"oversized","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"proto_pollute","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"silent","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"crash","disposition":"deny","verdict":"fail_mode_applied"}],"pass":true}
{"drill":"plugin-hostile-contract","run":2,"results":[{"mode":"allow","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"plugin_error","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_nonce","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_request_id","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"dup_decision","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"oversized","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"proto_pollute","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"silent","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"crash","disposition":"deny","verdict":"fail_mode_applied"}],"pass":true}
{"drill":"plugin-hostile-contract","run":3,"results":[{"mode":"allow","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"plugin_error","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_nonce","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"bad_request_id","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"dup_decision","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"oversized","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"proto_pollute","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"silent","disposition":"deny","verdict":"fail_mode_applied"},{"mode":"crash","disposition":"deny","verdict":"fail_mode_applied"}],"pass":true}
```

Kernel drill: CI-runnable on Linux (gnu + musl targets compile clean from the build
host). The same seccomp denials are already proven in-kernel by
`jail_confinement.rs::plugin_v1_profile_denies_escape_syscalls_in_kernel`; this drill
adds the N>=3 banked framing + the namespace file-confinement probe. Capture its
`--nocapture` JSON on a Linux host to bank the kernel half.

## Status

Per the drill-acceptance rule, S5 is "smoke-passed, contract-acceptance banked (N=3);
kernel-confinement is CI-runnable on Linux and pending a captured Linux run." No
external "contained" claim until the kernel half banks on Linux.
