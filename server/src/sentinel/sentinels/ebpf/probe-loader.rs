// Sanctuary v1.3 eBPF probe loader (Aya-based, Linux only).
//
// This is a placeholder for the Aya eBPF program that attaches to:
//   - sys_enter_execve (process spawn)
//   - sys_enter_openat (file access)
//   - sys_enter_connect (outbound network)
//
// The probe writes structured events to a user-space ring buffer that
// the TypeScript EbpfSyscallWatcher drains on each evaluate() tick.
//
// Build prerequisites:
//   - Linux kernel >= 5.8 (BPF ring buffer support)
//   - Rust toolchain with `cargo`
//   - Aya crate (https://aya-rs.dev/)
//
// This file is not compiled as part of the npm build. It is compiled
// separately via Cargo when deploying on Linux. The TypeScript sentinel
// uses a StubProbeLoader on non-Linux platforms.
//
// TODO: Implement real eBPF probes when Aya build pipeline is established.
//       See: https://aya-rs.dev/book/
//
// Structure:
//   #[map] static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024);
//
//   #[tracepoint(name = "sys_enter_execve")]
//   fn trace_execve(ctx: TracePointContext) -> ... { ... }
//
//   #[tracepoint(name = "sys_enter_openat")]
//   fn trace_openat(ctx: TracePointContext) -> ... { ... }
//
//   #[tracepoint(name = "sys_enter_connect")]
//   fn trace_connect(ctx: TracePointContext) -> ... { ... }
