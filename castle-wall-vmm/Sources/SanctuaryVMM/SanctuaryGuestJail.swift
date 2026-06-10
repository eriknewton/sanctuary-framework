import Foundation

/// How the trusted seccomp-deny-`AF_VSOCK` jail is delivered into the guest.
///
/// Both modes install the SAME filter semantics (deny `socket(AF_VSOCK)` with
/// EPERM, allow AF_UNIX/AF_INET) before the untrusted plugin runs; only the
/// delivery vehicle differs.
public enum SanctuaryGuestJailDelivery: Equatable, Sendable {
    /// Drill-proven python preamble (GREEN 3/3 on the box, 2026-06-09).
    /// Requires python3 in the guest image. Fail-closed property: if the
    /// image has no python3, the guest exec of `python3` fails and the
    /// plugin NEVER runs unjailed — the box exits instead.
    case pythonPreamble

    /// Static `sanctuary-jail` Rust binary (castle-wall-daemon, PR #439:
    /// multi-arch seccomp-deny-AF_VSOCK + cap-drop + no-new-privs +
    /// fail-closed exec) bind-mounted read-only into the guest and prepended
    /// to the plugin argv. Works on python-less images.
    ///
    /// TRUST MODEL: `hostBinaryPath` AND `expectedSHA256` are trusted-admin
    /// TCB inputs supplied together by the operator. The launcher
    /// authenticates the artifact by IDENTITY, not shape: after staging the
    /// file into a fresh private share directory it computes SHA-256 of the
    /// STAGED copy and refuses to launch on any mismatch (post-stage hashing
    /// also closes the validate-then-swap TOCTOU window). The structural ELF
    /// checks (static aarch64 Linux ELF, no PT_INTERP) remain as a secondary
    /// sanity layer only — they prove loadability, NOT that the file is the
    /// trusted jail shim. No hash, no static delivery: an absent or
    /// malformed `expectedSHA256` refuses to launch (fail closed). Obtain
    /// the authentic hash from the `sanctuary-jail-static` CI job's
    /// SHA256SUMS manifest.
    case staticBinary(hostBinaryPath: String, expectedSHA256: String)
}

/// Fail-closed errors from jail-delivery planning. Every case means the
/// plugin was NOT launched.
public enum SanctuaryGuestJailError: Error, CustomStringConvertible {
    case staticBinaryMissing(path: String)
    case staticBinaryInvalid(path: String, reason: String)
    case staticBinaryHashMismatch(path: String, expected: String, actual: String)
    case stagingFailed(reason: String)
    case invalidDeliveryConfiguration(reason: String)

    public var description: String {
        switch self {
        case .staticBinaryMissing(let path):
            return "guest jail static binary not found at \(path); refusing to launch plugin unjailed"
        case .staticBinaryInvalid(let path, let reason):
            return "guest jail static binary at \(path) rejected: \(reason); refusing to launch plugin unjailed"
        case .staticBinaryHashMismatch(let path, let expected, let actual):
            return "guest jail static binary STAGED from \(path) failed SHA-256 authentication: "
                + "expected \(expected), got \(actual); the artifact is not the pinned sanctuary-jail shim; "
                + "refusing to launch plugin unjailed"
        case .stagingFailed(let reason):
            return "guest jail staging failed: \(reason); refusing to launch plugin unjailed"
        case .invalidDeliveryConfiguration(let reason):
            return "guest jail delivery configuration invalid: \(reason); refusing to launch plugin unjailed"
        }
    }
}

/// The launcher-consumable result of jail planning: the born-confined argv
/// plus (static mode only) the host directory to share read-only into the
/// guest at `guestMountPoint`.
public struct SanctuaryGuestJailPlan: Sendable {
    /// The jailed argv to run as the guest init process.
    public let argv: [String]
    /// Host directory containing ONLY the staged shim binary, to be shared
    /// read-only into the guest. `nil` for python delivery. The launcher
    /// owns cleanup of this staging directory after the box exits.
    public let hostShareDirectory: String?
    /// In-guest mount point for `hostShareDirectory`. `nil` for python delivery.
    public let guestMountPoint: String?
}

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
/// Two delivery vehicles (`SanctuaryGuestJailDelivery`):
///   - `.pythonPreamble` (drill-proven 2026-06-09, GREEN 3/3 on the box): a
///     small python preamble installs the filter then `execvp`s the real
///     command. Requires python3 in the guest image (the drill guest was
///     `python:3.12-alpine`).
///   - `.staticBinary` (production generalization for python-less images):
///     the static `sanctuary-jail` Rust binary (castle-wall-daemon, PR #439)
///     is bind-mounted read-only into the guest at
///     `staticBinaryGuestMountPoint` and prepended to the plugin argv. The
///     artifact is AUTHENTICATED host-side BEFORE boot: it is staged into a
///     fresh private directory and the SHA-256 of the STAGED copy must equal
///     the operator-pinned `expectedSHA256` (trusted-admin TCB input,
///     sourced from the `sanctuary-jail-static` CI SHA256SUMS manifest).
///     Structural ELF checks (static aarch64, no PT_INTERP) run as a
///     secondary sanity layer only — they do NOT establish trust. Any
///     missing/malformed hash, hash mismatch, or validation failure aborts
///     the launch. Mechanism identical to the python preamble; pending its
///     own box drill (see the static-binary addendum in
///     `B2_Launcher_Integration_Drill_Runbook_2026-06-09.md`).
///
/// FAIL-CLOSED INVARIANT: with `applyGuestJail` on, there is NO path on which
/// the plugin runs unjailed. Python delivery without python3 in the image
/// fails the guest exec (plugin never starts); static delivery with a
/// missing binary, an absent/malformed expected hash, a staged-copy hash
/// mismatch, or a failed sanity check throws before boot (plugin never
/// starts).
public enum SanctuaryGuestJail {

    /// In-guest directory where the static shim share is mounted.
    public static let staticBinaryGuestMountPoint = "/run/sanctuary-jail"
    /// Staged name of the shim inside the share.
    public static let staticBinaryName = "sanctuary-jail"
    /// Full in-guest path the plugin argv execs through.
    public static var staticBinaryGuestPath: String {
        "\(staticBinaryGuestMountPoint)/\(staticBinaryName)"
    }

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
    /// python3 in the guest image. Returns the jailed argv.
    public static func wrap(command: String, args: [String]) -> [String] {
        return ["python3", "-c", seccompDenyVsockPreamble, "--", command] + args
    }

    /// Wrap a plugin command+args to exec through the bind-mounted static
    /// `sanctuary-jail` shim. Returns the jailed argv. The caller is
    /// responsible for actually mounting the shim at
    /// `staticBinaryGuestMountPoint` (see `makePlan`).
    public static func wrapWithStaticBinary(command: String, args: [String]) -> [String] {
        return [staticBinaryGuestPath, "--", command] + args
    }

    /// Parse an operator-supplied delivery mode (CLI JSON surface) into a
    /// `SanctuaryGuestJailDelivery`. FAIL-CLOSED: unknown modes and
    /// inconsistent or partial combinations throw — they NEVER fall back to
    /// a different delivery mode or to an unjailed launch. Static delivery
    /// requires BOTH `staticBinaryPath` and a well-formed 64-hex-char
    /// `staticBinarySHA256` pin (no hash, no static delivery).
    public static func parseDelivery(
        mode: String?,
        staticBinaryPath: String?,
        staticBinarySHA256: String?
    ) throws -> SanctuaryGuestJailDelivery {
        switch mode {
        case nil, "python-preamble":
            if let path = staticBinaryPath, !path.isEmpty {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "staticJailBinaryPath provided but guestJailDelivery is not 'static-binary'"
                )
            }
            if let sha = staticBinarySHA256, !sha.isEmpty {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "staticJailBinarySHA256 provided but guestJailDelivery is not 'static-binary'"
                )
            }
            return .pythonPreamble
        case "static-binary":
            guard let path = staticBinaryPath, !path.isEmpty else {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "guestJailDelivery 'static-binary' requires staticJailBinaryPath"
                )
            }
            guard let sha = staticBinarySHA256, !sha.isEmpty else {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "guestJailDelivery 'static-binary' requires staticJailBinarySHA256 "
                        + "(64 hex chars; the pinned hash of the trusted sanctuary-jail artifact). "
                        + "No hash, no static delivery."
                )
            }
            guard isValidSHA256Hex(sha) else {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "staticJailBinarySHA256 is malformed (expected exactly 64 hex characters). "
                        + "No hash, no static delivery."
                )
            }
            return .staticBinary(hostBinaryPath: path, expectedSHA256: sha.lowercased())
        case .some(let other):
            throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                reason: "unknown guestJailDelivery '\(other)' (expected 'python-preamble' or 'static-binary')"
            )
        }
    }

    /// True iff `value` is exactly 64 ASCII hex characters (a SHA-256 digest).
    static func isValidSHA256Hex(_ value: String) -> Bool {
        guard value.count == 64 else { return false }
        return value.allSatisfy { $0.isHexDigit && $0.isASCII }
    }

    /// Build the launch plan for a jailed plugin. For static delivery this
    /// AUTHENTICATES the artifact (fail-closed) in this order:
    ///
    ///   1. Refuse if the expected SHA-256 pin is absent or malformed
    ///      (no hash, no static delivery).
    ///   2. Stage the file into a fresh private directory containing ONLY
    ///      the shim, so the read-only guest share exposes nothing else.
    ///      Staging copies the BYTES (single read, symlinks resolved once);
    ///      the source file is never referenced again afterwards.
    ///   3. Compute SHA-256 of the STAGED copy and refuse on any mismatch
    ///      with the pin. Hashing the staged copy (the exact file that gets
    ///      bind-mounted) closes the validate-then-swap TOCTOU window:
    ///      swapping the source after staging cannot change what the guest
    ///      executes or what was hashed.
    ///   4. Run the structural ELF checks on the STAGED copy as a secondary
    ///      sanity layer (catches a wrong-but-correctly-pinned artifact,
    ///      e.g. an x86_64 build pinned by mistake). These checks prove
    ///      loadability only; identity comes from the hash in step 3.
    ///
    /// Throws on ANY problem — the launcher must treat a throw as "do not
    /// launch".
    public static func makePlan(
        delivery: SanctuaryGuestJailDelivery,
        command: String,
        args: [String]
    ) throws -> SanctuaryGuestJailPlan {
        switch delivery {
        case .pythonPreamble:
            return SanctuaryGuestJailPlan(
                argv: wrap(command: command, args: args),
                hostShareDirectory: nil,
                guestMountPoint: nil
            )
        case .staticBinary(let hostBinaryPath, let expectedSHA256):
            // Step 1: the pin is a REQUIRED precondition. Direct Swift-API
            // construction bypasses parseDelivery, so re-check here.
            guard isValidSHA256Hex(expectedSHA256) else {
                throw SanctuaryGuestJailError.invalidDeliveryConfiguration(
                    reason: "static-binary delivery requires a well-formed expectedSHA256 pin "
                        + "(64 hex chars); got '\(expectedSHA256)'. No hash, no static delivery."
                )
            }
            // Step 2: stage first (single byte-level read of the source).
            let stagingDir = try stageShim(fromPath: hostBinaryPath)
            let stagedPath = "\(stagingDir)/\(staticBinaryName)"
            do {
                // Step 3: authenticate the STAGED copy against the pin.
                let actual = try SanctuaryImageIntegrity.computeDigest(
                    at: URL(fileURLWithPath: stagedPath)
                )
                guard actual == expectedSHA256.lowercased() else {
                    throw SanctuaryGuestJailError.staticBinaryHashMismatch(
                        path: hostBinaryPath,
                        expected: expectedSHA256.lowercased(),
                        actual: actual
                    )
                }
                // Step 4: secondary structural sanity on the staged copy.
                try validateStaticShim(atPath: stagedPath)
            } catch {
                // Fail closed: never leave a staged-but-unverified share behind.
                try? FileManager.default.removeItem(atPath: stagingDir)
                throw error
            }
            return SanctuaryGuestJailPlan(
                argv: wrapWithStaticBinary(command: command, args: args),
                hostShareDirectory: stagingDir,
                guestMountPoint: staticBinaryGuestMountPoint
            )
        }
    }

    // MARK: - Static shim structural sanity checks (fail-closed, SECONDARY)

    /// SECONDARY SANITY ONLY — this proves the file is a plausible static
    /// aarch64 Linux ELF (loadable in the `.linuxArm` guest, no PT_INTERP,
    /// parseable headers). It does NOT authenticate the file as the trusted
    /// `sanctuary-jail` shim: any hostile static aarch64 ELF passes these
    /// shape checks. Identity/trust is established exclusively by the
    /// pinned SHA-256 comparison against the STAGED copy in `makePlan`.
    /// These checks exist to catch a wrong-architecture or dynamically
    /// linked artifact early (clear host-side error instead of a confusing
    /// in-guest exec failure). Any malformed/truncated header is rejected:
    /// this function only ever errs toward NOT launching.
    public static func validateStaticShim(atPath path: String) throws {
        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            throw SanctuaryGuestJailError.staticBinaryMissing(path: path)
        }
        guard let data = fm.contents(atPath: path), !data.isEmpty else {
            throw SanctuaryGuestJailError.staticBinaryInvalid(path: path, reason: "file is empty or unreadable")
        }

        func invalid(_ reason: String) -> SanctuaryGuestJailError {
            .staticBinaryInvalid(path: path, reason: reason)
        }

        // ELF identification.
        guard data.count >= 64 else { throw invalid("file smaller than an ELF64 header") }
        guard data[0] == 0x7F, data[1] == 0x45, data[2] == 0x4C, data[3] == 0x46 else {
            throw invalid("not an ELF file")
        }
        guard data[4] == 2 else { throw invalid("not a 64-bit ELF (EI_CLASS != ELFCLASS64)") }
        guard data[5] == 1 else { throw invalid("not little-endian ELF (EI_DATA != ELFDATA2LSB)") }

        // e_machine at offset 18 (u16 LE). EM_AARCH64 = 0xB7: the guest is .linuxArm.
        let machine = readU16LE(data, at: 18)
        guard machine == 0xB7 else {
            throw invalid(
                "ELF machine 0x\(String(machine, radix: 16)) is not aarch64 (0xb7); the guest platform is linuxArm"
            )
        }

        // Program headers: e_phoff (u64 LE @ 32), e_phentsize (u16 @ 54), e_phnum (u16 @ 56).
        let phoff = readU64LE(data, at: 32)
        let phentsize = UInt64(readU16LE(data, at: 54))
        let phnum = UInt64(readU16LE(data, at: 56))
        guard phnum > 0, phentsize >= 56 else {
            throw invalid("ELF has no parseable program headers")
        }
        // Overflow-safe bounds check: phnum and phentsize are both u16-derived
        // so their product fits comfortably in UInt64; phoff is attacker-/file-
        // controlled and must be range-checked BEFORE any addition.
        let tableSize = phnum * phentsize
        guard phoff >= 64, phoff <= UInt64(data.count),
              UInt64(data.count) - phoff >= tableSize else {
            throw invalid("ELF program header table out of bounds (truncated file?)")
        }

        // PT_INTERP (p_type == 3) means dynamically linked.
        for i in 0..<phnum {
            let pType = readU32LE(data, at: Int(phoff + i * phentsize))
            if pType == 3 {
                throw invalid("PT_INTERP present: binary is dynamically linked; a static binary is required")
            }
        }
    }

    /// Copy the shim BYTES into a fresh private staging directory that
    /// contains ONLY the shim, mode 0555. The read-only guest share therefore
    /// exposes exactly one file. Caller owns removal of the returned directory.
    ///
    /// Deliberately a byte-level read + write (NOT `FileManager.copyItem`,
    /// which preserves symlinks): the source is read exactly once, with any
    /// symlink resolved at that moment, and the staged file is a fresh
    /// regular file in a directory no other principal can pre-create. All
    /// subsequent verification (SHA-256 pin, ELF sanity) runs against this
    /// staged copy, so post-stage swaps of the source are irrelevant.
    static func stageShim(fromPath path: String) throws -> String {
        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            throw SanctuaryGuestJailError.staticBinaryMissing(path: path)
        }
        let stagingDir = fm.temporaryDirectory
            .appendingPathComponent("sanctuary-jail-share-\(UUID().uuidString)")
        let stagedBinary = stagingDir.appendingPathComponent(staticBinaryName)
        do {
            let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
            try fm.createDirectory(
                at: stagingDir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
            try bytes.write(to: stagedBinary, options: [.atomic])
            try fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: stagedBinary.path)
        } catch {
            // Best-effort cleanup of a half-built staging dir, then fail closed.
            try? fm.removeItem(at: stagingDir)
            throw SanctuaryGuestJailError.stagingFailed(reason: String(describing: error))
        }
        return stagingDir.path
    }

    // MARK: - Little-endian readers. Callers bounds-check every read against
    // data.count before calling; these guard anyway and return 0 on
    // out-of-bounds rather than trapping.

    private static func readU16LE(_ data: Data, at offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= data.count else { return 0 }
        let base = data.startIndex + offset
        return UInt16(data[base]) | (UInt16(data[base + 1]) << 8)
    }

    private static func readU32LE(_ data: Data, at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        let base = data.startIndex + offset
        var value: UInt32 = 0
        for i in 0..<4 {
            value |= UInt32(data[base + i]) << (8 * i)
        }
        return value
    }

    private static func readU64LE(_ data: Data, at offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= data.count else { return 0 }
        let base = data.startIndex + offset
        var value: UInt64 = 0
        for i in 0..<8 {
            value |= UInt64(data[base + i]) << (8 * i)
        }
        return value
    }
}
