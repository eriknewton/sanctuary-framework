import Foundation

/// Trusted, launcher-applied inner-confinement for guest plugin processes.
///
/// THE B2 INNER-CONFINEMENT FIX (productionized). The B2 escape drill proved a
/// hostile guest userspace process can drive Apple's `vminitd` control plane over
/// `vsock` port 1024 (no peer auth) = full box escape (verdict
/// `Castle_Wall_B2_Escape_Drill_Verdict_2026-06-09.md`). The proven fix: a
/// seccomp-BPF filter that denies `socket(AF_VSOCK, …)` installed BEFORE the
/// (untrusted) plugin runs. AF_UNIX (the bind-mounted egress relay) and AF_INET
/// stay creatable, so the deny is surgical and egress is unaffected.
///
/// "Trusted, launcher-applied" is the whole point: the plugin does NOT confine
/// itself (it is the adversary). The launcher (this trusted code) prepends the
/// confinement to the plugin's argv, so the plugin is born confined regardless of
/// whether it cooperates. seccomp survives `execve` and is inherited, so the
/// re-exec'd plugin runs under the filter.
///
/// Delivery (drill scope): the filter is installed by a small Python preamble that
/// then `execvp`s the real command. The drill guest (`python:3.12-alpine`) has
/// python3. This is the EXACT BPF program proven 3/3 on the box by
/// `drills/b2-escape/confined-probe.py`.
///
/// Production generalization (documented follow-on, NOT this path): for guest
/// images without python, bind-mount the static `sanctuary-jail` Rust binary
/// (castle-wall-daemon, PR #439 — multi-arch seccomp-deny-AF_VSOCK + cap-drop +
/// no-new-privs + fail-closed exec) into the guest and prepend its path instead.
/// The mechanism is identical; only the delivery vehicle differs.
public enum SanctuaryGuestJail {

    /// Trusted seccomp preamble. Installs PR_SET_NO_NEW_PRIVS then a seccomp-BPF
    /// filter denying `socket(AF_VSOCK)` (arm64 — the guest is `.linuxArm`), then
    /// `execvp`s the real command (everything after the `--` sentinel in argv).
    /// Fail-closed: if either prctl fails it raises and the plugin never runs
    /// unconfined. Raw string so the python `\n` escapes are preserved literally.
    static let seccompDenyVsockPreamble = #"""
import ctypes, os, sys
AF_VSOCK = 40
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
AUDIT_ARCH_AARCH64 = 0xC00000B7
NR_SOCKET_AARCH64 = 198
RET_ALLOW = 0x7FFF0000
RET_ERRNO_EPERM = 0x00050001
class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.c_void_p)]
prog = [
    (0x20, 0, 0, 4),
    (0x15, 0, 4, AUDIT_ARCH_AARCH64),
    (0x20, 0, 0, 0),
    (0x15, 0, 2, NR_SOCKET_AARCH64),
    (0x20, 0, 0, 16),
    (0x15, 1, 0, AF_VSOCK),
    (0x06, 0, 0, RET_ALLOW),
    (0x06, 0, 0, RET_ERRNO_EPERM),
]
arr = (SockFilter * len(prog))()
for i, (c, jt, jf, k) in enumerate(prog):
    arr[i] = SockFilter(c, jt, jf, k)
fprog = SockFprog(len(prog), ctypes.cast(arr, ctypes.c_void_p))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")
sys.stderr.write("[JAIL] launcher-applied seccomp-deny-AF_VSOCK installed before plugin exec\n")
sys.stderr.flush()
argv = sys.argv
sep = argv.index("--")
real = argv[sep + 1:]
if not real:
    raise SystemExit("[JAIL] no command after -- to exec")
os.execvp(real[0], real)
"""#

    /// Wrap a plugin command+args so the trusted seccomp-deny-AF_VSOCK filter is
    /// installed by the launcher (not the plugin) before the plugin runs. Requires
    /// python3 in the guest image (drill scope). Returns the jailed argv.
    public static func wrap(command: String, args: [String]) -> [String] {
        return ["python3", "-c", seccompDenyVsockPreamble, "--", command] + args
    }
}
