# Castle Wall VMM

Apple Containerization-based VM launcher for Castle Wall (the "box" runtime,
B1/B2). Boots no-network Linux guests with single-vsock egress.

## Why this is a separate package

This package was split out of `castle-wall-macos` on 2026-06-04. Apple's
[Containerization](https://github.com/apple/containerization) library requires
**macOS 26** and Swift tools **6.2**. SwiftPM has no per-target deployment
floor, so while the VM lived in the `castle-wall-macos` package it forced the
whole package — including the **system extension and host app** — up to a
macOS-26 floor. That made the released sysext refuse to install on the macOS
13/14/15 Macs most operators run (a latent product bug caught by the A1
acceptance drill).

Splitting the VM here lets the enforcement package (`castle-wall-macos`:
sysext, host app, packet filter, IPC library) keep a **macOS-13** floor with no
Containerization dependency, while the VM keeps its macOS-26 requirement.

The two packages do not depend on each other. The enforcement layer talks to
the daemon over a unix socket; the VM is launched separately by the server's
`SanctuaryVMMCliLauncher` adapter (`server/src/agent-contract/adapters/vm-launcher.ts`)
via the `sanctuary-vmm` CLI.

## Build

```sh
# Requires macOS 26 + Xcode 26 (Swift tools 6.2).
swift build --build-tests
swift test
```

## Targets

- `SanctuaryVMM` — library: Containerization-based VM launcher + image
  integrity + vsock egress config.
- `sanctuary-vmm` — CLI entry point.
