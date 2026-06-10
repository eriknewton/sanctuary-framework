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

On a successful confinement install the shim writes one stderr marker before
exec -- `[JAIL] launcher-applied seccomp-deny-AF_VSOCK installed before plugin
exec (sanctuary-jail)` -- containing the same substring the
launcher-integration drill greps for, so drill evidence is delivery-vehicle
agnostic.

## Static-binary build (B2 delivery vehicle for python-less guests)

The macOS Castle Wall launcher (`castle-wall-vmm`,
`SanctuaryGuestJail` static-binary delivery) bind-mounts this shim read-only
into guest images that lack python3 and prepends
`/run/sanctuary-jail/sanctuary-jail -- <plugin> [args...]` to the plugin
argv. For that to work on ANY image -- including libc-less ones -- the shim
must be a STATIC Linux binary.

Build (Linux host or CI):

```bash
castle-wall-daemon/scripts/build-sanctuary-jail-static.sh
```

This builds `sanctuary-jail` for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` with `+crt-static` (per-target config in
`.cargo/config.toml`; the default glibc daemon build is unaffected) and FAILS
if either output is not statically linked. CI runs the same script plus a
functional smoke (confinement install + exec, usage fail-closed, exec
fail-closed) in the `sanctuary-jail-static` job of
`.github/workflows/castle-wall-linux.yml`, emits a
`sanctuary-jail.SHA256SUMS` manifest, and uploads both artifacts plus the
manifest.

The launcher's guest platform is `linuxArm`, so the **aarch64** artifact is
the one delivered into guests; the x86_64 artifact exists for the Linux
loop-worker confinement path and for runner-side smoke tests. On macOS only
`cargo check --target <musl target>` is possible (no musl cross-linker);
real artifacts come from Linux CI.

### Artifact authentication (pinned SHA-256, trusted-admin TCB inputs)

The macOS launcher does NOT trust `staticJailBinaryPath` by shape. Its
structural ELF checks (static aarch64, no `PT_INTERP`) are a secondary
sanity layer only -- any hostile static aarch64 ELF would pass them. Trust
is established by a REQUIRED `staticJailBinarySHA256` pin (64 hex chars)
supplied alongside the path: the launcher stages the file into a fresh
private share directory, computes SHA-256 of the STAGED copy (closing the
validate-then-swap TOCTOU window), and refuses to launch on any mismatch or
when the pin is absent or malformed. No hash, no static delivery.

Both `staticJailBinaryPath` and `staticJailBinarySHA256` are trusted-admin
TCB inputs: the operator who configures them vouches for them as a pair.
The authentic pin source is the `sanctuary-jail.SHA256SUMS` manifest emitted
by the `sanctuary-jail-static` CI job that built the artifact (also printed
in the job log).

## Claim Boundary

This shim removes the vminitd escape vector (`AF_VSOCK`) and reduces
capability/privilege before the worker starts. It is one inner-confinement
layer, not the full worker-in-box containment story. Host-secret absence,
egress allowlisting, network-namespace 0-NIC confinement, import quarantine,
and the macOS box launcher remain separate layers described in
`Loop_Worker_Under_CastleWall_Design_v2_2026-06-07.md`.
