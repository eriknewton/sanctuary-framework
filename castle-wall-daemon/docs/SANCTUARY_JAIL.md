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

## Threat-Model Assumptions

### vsock is the sole guest-to-host channel

Denying `socket(AF_VSOCK, ...)` confines the worker only because, in the
Castle Wall box as launched today, **vsock is the only guest-to-host
communication channel**: the VM boots with zero network attachments
(host-asserted in `SanctuaryContainerLauncher`, castle-wall-vmm), a single
vsock device, and a UDS-over-vsock egress relay. Every guest-initiated path to
the host therefore requires an `AF_VSOCK` socket, except the bind-mounted
egress UDS, which is allowed by design.

**macOS 27 exception.** The macOS 27 SDK (beta announced WWDC 2026, session
224 "Expand the capabilities of your Virtualization app"; GA expected
~September 2026) adds `VZCustomVirtioDeviceConfiguration`, which lets a VMM
define custom paravirtualized virtio guest-to-host channels that are **not**
`AF_VSOCK`. A guest kernel carrying a matching custom virtio driver could
reach the host over a channel this seccomp filter does not cover.

**Mitigating control (explicit invariant): the host VMM never configures
custom virtio devices for confined workers.** This holds the same rank as the
zero-NIC rule. It is not a live hole today: only the host-side launcher can
attach devices to the VM (a confined worker cannot add devices to its own
box), the current floor is macOS 26 whose SDK has no such API, and
`SanctuaryContainerLauncher` builds the VM exclusively through Apple's
`ContainerManager` without adding custom devices. The invariant's natural
enforcement point is the existing host-side assertion in
`castle-wall-vmm/Sources/SanctuaryVMM/SanctuaryContainerLauncher.swift`
(`container.interfaces.count == 0`, both launch paths): when castle-wall-vmm
adopts the macOS 27 SDK, extend it (or add a sibling assertion) to verify the
VM configuration contains no custom virtio devices, if Containerization
exposes the device list.

**Re-evaluation trigger: macOS 27 GA (~September 2026).** At GA, re-check
(a) whether Apple Containerization configures any custom virtio device by
default, (b) whether the device list is host-enumerable so the assertion above
can land, and (c) whether the pinned guest kernel/initfs ships any
custom-virtio driver.
