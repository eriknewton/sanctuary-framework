# sanctuary-jail

`sanctuary-jail` is the trusted preamble for the loop-worker confinement layer.
It installs a seccomp-BPF filter before `execve` and then runs:

```bash
sanctuary-jail -- <program> [args...]
```

The filter denies `socket(AF_VSOCK, ...)` with `EPERM`. That removes the
vminitd escape vector proven in
`Review/Sanctuary/Castle_Wall_B2_Escape_Drill_Verdict_2026-06-09.md` while
preserving `AF_UNIX` for the legitimate egress relay and preserving ordinary
`AF_INET` socket creation. The reference drill is
`Review/Sanctuary/drills/b2-escape/confined-probe.py`.

The shim applies confinement in this order:

1. Set `PR_SET_NO_NEW_PRIVS = 1`.
2. Clear ambient capabilities and best-effort drop the bounding set.
3. Install a default-allow seccomp filter that returns `EPERM` only for
   `socket(AF_VSOCK, ...)`.
4. `execve` the target command. An exec failure exits non-zero.

The BPF program branches on the runtime seccomp `arch` field and includes both
`AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64`. The direct `socket` syscall
numbers are verified against Linux syscall tables and represented in code as
x86_64 `41` and aarch64 `198`; `AF_VSOCK` comes from `libc::AF_VSOCK` on Linux
and is asserted as `40` in the portable builder tests. Unknown arch paths deny
the known direct socket syscall numbers instead of silently allowing them.

The coordinator loop will prepend this shim to the untrusted worker command in
a follow-on change outside this crate.

## Claim Boundary

This shim removes the vminitd escape vector (`AF_VSOCK`) and reduces
capability/privilege before the worker starts. It is one inner-confinement
layer, not the full worker-in-box containment story. Host-secret absence,
egress allowlisting, network-namespace 0-NIC confinement, import quarantine,
and the macOS box launcher remain separate layers described in
`Loop_Worker_Under_CastleWall_Design_v2_2026-06-07.md`.
