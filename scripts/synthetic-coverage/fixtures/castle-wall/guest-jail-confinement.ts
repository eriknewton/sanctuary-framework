/**
 * Synthetic fixtures for assurance row 21: hostile-guest containment — the
 * macOS box launcher jails uncooperative plugins via the B2 inner-confinement
 * seccomp-deny-AF_VSOCK shim.
 *
 * The end-to-end claim ("the launcher applies the shim to an uncooperative
 * plugin and the vminitd vsock-escape confirmed without it is shut with it,
 * N=3/3") is proven by the box drill on the signing/boot host (GREEN 3/3,
 * 2026-06-09, PRs #439/#441/#443) and by the Rust (`cargo test`) and Swift
 * (`swift test`) unit suites. Those require the signing/boot host and a real
 * Linux guest kernel; they cannot run in the cross-platform Node CI harness,
 * and a Linux-only real-`socket()` fixture would diverge from macOS and trip
 * the parity gate.
 *
 * What IS faithfully and deterministically testable on BOTH platforms — which
 * is what this parity-gated harness counts — is the load-bearing logic the
 * drill depends on:
 *
 *   1. The seccomp-BPF deny program's verdicts: it is a 1:1 port of
 *      `build_deny_vsock_socket_filter()` from castle-wall-daemon/src/jail.rs
 *      (the exact program CI installs in the guest), exercised by a port of
 *      that file's `simulate()` BPF interpreter. Asserts the deny is surgical:
 *      `socket(AF_VSOCK)` → EPERM on both supported arches, AF_UNIX / AF_INET
 *      stay creatable (egress relay intact), and the filter fails closed on an
 *      unknown arch.
 *   2. The port is bound to the real source: the fixture reads jail.rs and
 *      asserts the canonical constants it depends on (AF_VSOCK, socket NRs,
 *      arch audit constants, EPERM/ALLOW returns) are unchanged, so source
 *      drift fails the fixture instead of silently passing a stale copy.
 *   3. The launcher's born-confined composition + fail-closed delivery rules
 *      from castle-wall-vmm/.../SanctuaryGuestJail.swift: the untrusted plugin
 *      argv is prepended with the trusted jail (it does not confine itself),
 *      and static-binary delivery refuses to launch without a valid 64-hex
 *      SHA-256 pin ("no hash, no static delivery").
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { registerFixture, type FixtureOutcome } from "../../registry.js";

const CLAIM_ID = "21";
const CLAIM_LABEL =
  "Hostile-guest containment: macOS box launcher jails uncooperative plugins (B2 inner-confinement, seccomp-deny-AF_VSOCK)";

// ---------------------------------------------------------------------------
// Canonical constants (must match castle-wall-daemon/src/jail.rs). Fixture
// "jail source still encodes the deny" below re-reads jail.rs and asserts the
// real source still defines these exact values, binding this port to source.
// ---------------------------------------------------------------------------
const BPF_LD_W_ABS = 0x00 | 0x00 | 0x20; // load word, absolute
const BPF_JMP_JEQ_K = 0x05 | 0x10 | 0x00; // jump-if-equal, constant
const BPF_RET_K = 0x06 | 0x00; // return constant

const SECCOMP_DATA_NR_OFFSET = 0;
const SECCOMP_DATA_ARCH_OFFSET = 4;
const SECCOMP_DATA_ARG0_OFFSET = 16;

const AUDIT_ARCH_X86_64 = 0xc000_003e;
const AUDIT_ARCH_AARCH64 = 0xc000_00b7;
const NR_SOCKET_X86_64 = 41;
const NR_SOCKET_AARCH64 = 198;
const AF_VSOCK = 40;
const AF_UNIX = 1;
const AF_INET = 2;

const SECCOMP_RET_ALLOW = 0x7fff_0000;
const SECCOMP_RET_ERRNO_EPERM = 0x0005_0001;

interface BpfInstruction {
  code: number;
  jt: number;
  jf: number;
  k: number;
}

function loadAbs(offset: number): BpfInstruction {
  return { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: offset };
}
function jumpEqual(k: number, jt: number, jf: number): BpfInstruction {
  return { code: BPF_JMP_JEQ_K, jt, jf, k };
}
function ret(k: number): BpfInstruction {
  return { code: BPF_RET_K, jt: 0, jf: 0, k };
}

/**
 * 1:1 port of `build_deny_vsock_socket_filter()` (castle-wall-daemon/src/jail.rs).
 * Keep in lockstep with that function; the source-binding fixture guards drift.
 */
function buildDenyVsockSocketFilter(): BpfInstruction[] {
  return [
    loadAbs(SECCOMP_DATA_ARCH_OFFSET),
    jumpEqual(AUDIT_ARCH_X86_64, 0, 6),
    loadAbs(SECCOMP_DATA_NR_OFFSET),
    jumpEqual(NR_SOCKET_X86_64, 0, 3),
    loadAbs(SECCOMP_DATA_ARG0_OFFSET),
    jumpEqual(AF_VSOCK, 0, 1),
    ret(SECCOMP_RET_ERRNO_EPERM),
    ret(SECCOMP_RET_ALLOW),
    jumpEqual(AUDIT_ARCH_AARCH64, 0, 6),
    loadAbs(SECCOMP_DATA_NR_OFFSET),
    jumpEqual(NR_SOCKET_AARCH64, 0, 3),
    loadAbs(SECCOMP_DATA_ARG0_OFFSET),
    jumpEqual(AF_VSOCK, 0, 1),
    ret(SECCOMP_RET_ERRNO_EPERM),
    ret(SECCOMP_RET_ALLOW),
    loadAbs(SECCOMP_DATA_NR_OFFSET),
    jumpEqual(NR_SOCKET_X86_64, 2, 0),
    jumpEqual(NR_SOCKET_AARCH64, 1, 0),
    ret(SECCOMP_RET_ALLOW),
    ret(SECCOMP_RET_ERRNO_EPERM),
  ];
}

/** Port of the `simulate()` BPF interpreter from jail.rs tests. */
function simulate(
  program: BpfInstruction[],
  arch: number,
  nr: number,
  arg0: number,
): number {
  let pc = 0;
  let accumulator = 0;
  // Bounded: the deny program is acyclic and always reaches a RET.
  for (let steps = 0; steps < program.length + 1; steps++) {
    const insn = program[pc]!;
    if (insn.code === BPF_LD_W_ABS) {
      if (insn.k === SECCOMP_DATA_NR_OFFSET) accumulator = nr;
      else if (insn.k === SECCOMP_DATA_ARCH_OFFSET) accumulator = arch;
      else if (insn.k === SECCOMP_DATA_ARG0_OFFSET) accumulator = arg0;
      else throw new Error(`unexpected load offset ${insn.k}`);
      pc += 1;
    } else if (insn.code === BPF_JMP_JEQ_K) {
      pc += accumulator === insn.k ? insn.jt + 1 : insn.jf + 1;
    } else if (insn.code === BPF_RET_K) {
      return insn.k;
    } else {
      throw new Error(`unexpected instruction code ${insn.code}`);
    }
  }
  throw new Error("BPF program did not terminate");
}

function timed(passed: boolean, started: number, message?: string): FixtureOutcome {
  return {
    passed,
    durationMs: Math.round(performance.now() - started),
    message: passed ? undefined : message,
  };
}

function findRepoRoot(start = process.cwd()): string {
  let current = resolve(start);
  for (;;) {
    try {
      readFileSync(resolve(current, "ASSURANCE_MATRIX.md"));
      return current;
    } catch {
      const parent = dirname(current);
      if (parent === current) {
        throw new Error(`Unable to locate repository root from ${start}`);
      }
      current = parent;
    }
  }
}

// ---------------------------------------------------------------------------
// Filter-semantics fixtures: the deny is surgical and fails closed.
// ---------------------------------------------------------------------------

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: socket(AF_VSOCK) denied with EPERM on both supported arches",
  async () => {
    const started = performance.now();
    const program = buildDenyVsockSocketFilter();
    const x86 = simulate(program, AUDIT_ARCH_X86_64, NR_SOCKET_X86_64, AF_VSOCK);
    const arm = simulate(program, AUDIT_ARCH_AARCH64, NR_SOCKET_AARCH64, AF_VSOCK);
    const passed = x86 === SECCOMP_RET_ERRNO_EPERM && arm === SECCOMP_RET_ERRNO_EPERM;
    return timed(
      passed,
      started,
      `AF_VSOCK should be EPERM; got x86=0x${x86.toString(16)}, arm=0x${arm.toString(16)}`,
    );
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: AF_UNIX and AF_INET sockets stay allowed (egress relay intact)",
  async () => {
    const started = performance.now();
    const program = buildDenyVsockSocketFilter();
    const verdicts = [
      simulate(program, AUDIT_ARCH_X86_64, NR_SOCKET_X86_64, AF_UNIX),
      simulate(program, AUDIT_ARCH_X86_64, NR_SOCKET_X86_64, AF_INET),
      simulate(program, AUDIT_ARCH_AARCH64, NR_SOCKET_AARCH64, AF_UNIX),
      simulate(program, AUDIT_ARCH_AARCH64, NR_SOCKET_AARCH64, AF_INET),
    ];
    const passed = verdicts.every((v) => v === SECCOMP_RET_ALLOW);
    return timed(
      passed,
      started,
      `AF_UNIX/AF_INET should be ALLOW; got ${verdicts.map((v) => `0x${v.toString(16)}`).join(", ")}`,
    );
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: unknown-arch path fails closed (denies known socket syscalls)",
  async () => {
    const started = performance.now();
    const program = buildDenyVsockSocketFilter();
    const unknownArch = 0x0000_1234;
    // A known socket() NR under an unrecognized arch is denied (cannot trust
    // ARG0 layout across arches), while a non-socket syscall passes through.
    const x86Socket = simulate(program, unknownArch, NR_SOCKET_X86_64, AF_INET);
    const armSocket = simulate(program, unknownArch, NR_SOCKET_AARCH64, AF_INET);
    const nonSocket = simulate(program, unknownArch, 999, AF_VSOCK);
    const passed =
      x86Socket === SECCOMP_RET_ERRNO_EPERM &&
      armSocket === SECCOMP_RET_ERRNO_EPERM &&
      nonSocket === SECCOMP_RET_ALLOW;
    return timed(
      passed,
      started,
      `unknown-arch socket should EPERM and non-socket ALLOW; got ` +
        `x86=0x${x86Socket.toString(16)}, arm=0x${armSocket.toString(16)}, other=0x${nonSocket.toString(16)}`,
    );
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: non-socket syscalls pass through the filter unaffected",
  async () => {
    const started = performance.now();
    const program = buildDenyVsockSocketFilter();
    // e.g. read(2): x86_64 NR 0, aarch64 NR 63 — not socket(), must ALLOW even
    // when arg0 happens to equal AF_VSOCK.
    const x86Read = simulate(program, AUDIT_ARCH_X86_64, 0, AF_VSOCK);
    const armRead = simulate(program, AUDIT_ARCH_AARCH64, 63, AF_VSOCK);
    const passed = x86Read === SECCOMP_RET_ALLOW && armRead === SECCOMP_RET_ALLOW;
    return timed(
      passed,
      started,
      `non-socket syscalls should ALLOW; got x86=0x${x86Read.toString(16)}, arm=0x${armRead.toString(16)}`,
    );
  },
);

// ---------------------------------------------------------------------------
// Source-binding fixture: keep the port above honest against jail.rs.
// ---------------------------------------------------------------------------

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: jail.rs still encodes the seccomp-deny-AF_VSOCK confinement",
  async () => {
    const started = performance.now();
    const root = findRepoRoot();
    const src = readFileSync(
      resolve(root, "castle-wall-daemon/src/jail.rs"),
      "utf8",
    );
    const required: Array<[string, RegExp]> = [
      ["AF_VSOCK_LINUX = 40", /AF_VSOCK_LINUX:\s*u32\s*=\s*40\b/],
      ["NR_SOCKET_X86_64 = 41", /NR_SOCKET_X86_64:\s*u32\s*=\s*41\b/],
      ["NR_SOCKET_AARCH64 = 198", /NR_SOCKET_AARCH64:\s*u32\s*=\s*198\b/],
      ["AUDIT_ARCH_X86_64 = 0xC000_003E", /AUDIT_ARCH_X86_64:\s*u32\s*=\s*0xC000_003E/i],
      ["AUDIT_ARCH_AARCH64 = 0xC000_00B7", /AUDIT_ARCH_AARCH64:\s*u32\s*=\s*0xC000_00B7/i],
      ["SECCOMP_RET_ERRNO_EPERM = 0x0005_0001", /SECCOMP_RET_ERRNO_EPERM:\s*u32\s*=\s*0x0005_0001/i],
      ["SECCOMP_RET_ALLOW = 0x7fff_0000", /SECCOMP_RET_ALLOW:\s*u32\s*=\s*0x7fff_0000/i],
      ["build_deny_vsock_socket_filter", /fn build_deny_vsock_socket_filter\(\)/],
      // confine_current_process must compose no-new-privs + cap-drop + seccomp.
      ["confine: set_no_new_privs", /fn confine_current_process[\s\S]{0,200}set_no_new_privs\(\)/],
      ["confine: drop_capabilities", /fn confine_current_process[\s\S]{0,200}drop_capabilities\(\)/],
      ["confine: install_seccomp_deny_vsock", /fn confine_current_process[\s\S]{0,200}install_seccomp_deny_vsock\(\)/],
    ];
    const missing = required.filter(([, re]) => !re.test(src)).map(([label]) => label);
    return timed(
      missing.length === 0,
      started,
      `jail.rs missing expected invariants: ${missing.join("; ")}`,
    );
  },
);

// ---------------------------------------------------------------------------
// Launcher composition + fail-closed delivery fixtures (SanctuaryGuestJail.swift).
// ---------------------------------------------------------------------------

/** Port of `isValidSHA256Hex` from SanctuaryGuestJail.swift. */
function isValidSHA256Hex(value: string): boolean {
  return value.length === 64 && /^[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Port of the `parseDelivery` fail-closed decision (SanctuaryGuestJail.swift):
 * returns the resolved delivery mode, or throws on any inconsistent/partial
 * configuration. Never falls back to a different mode or an unjailed launch.
 */
function parseDelivery(
  mode: string | null,
  staticBinaryPath: string | null,
  staticBinarySHA256: string | null,
): { kind: "python" } | { kind: "static"; path: string; sha: string } {
  if (mode === null || mode === "python-preamble") {
    if (staticBinaryPath && staticBinaryPath.length > 0) {
      throw new Error("staticJailBinaryPath provided but delivery is not static-binary");
    }
    if (staticBinarySHA256 && staticBinarySHA256.length > 0) {
      throw new Error("staticJailBinarySHA256 provided but delivery is not static-binary");
    }
    return { kind: "python" };
  }
  if (mode === "static-binary") {
    if (!staticBinaryPath || staticBinaryPath.length === 0) {
      throw new Error("static-binary requires staticJailBinaryPath");
    }
    if (!staticBinarySHA256 || staticBinarySHA256.length === 0) {
      throw new Error("static-binary requires staticJailBinarySHA256. No hash, no static delivery.");
    }
    if (!isValidSHA256Hex(staticBinarySHA256)) {
      throw new Error("staticJailBinarySHA256 malformed. No hash, no static delivery.");
    }
    return { kind: "static", path: staticBinaryPath, sha: staticBinarySHA256.toLowerCase() };
  }
  throw new Error(`unknown guestJailDelivery '${mode}'`);
}

/** Port of `wrap()`: born-confined argv for the python preamble delivery. */
function wrapPython(preamble: string, command: string, args: string[]): string[] {
  return ["python3", "-c", preamble, "--", command, ...args];
}

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: launcher prepends the jail so an uncooperative plugin is born confined",
  async () => {
    const started = performance.now();
    // The untrusted plugin does not confine itself; the launcher wraps it.
    const argv = wrapPython("<preamble>", "/usr/bin/hostile-plugin", ["--exfil"]);
    const sep = argv.indexOf("--");
    const pluginStartsAfterSeparator =
      sep > 0 && argv[sep + 1] === "/usr/bin/hostile-plugin";
    // Confinement is installed BEFORE the plugin: python3 -c <preamble> runs
    // first, the real command only appears after the `--` sentinel.
    const confinementBeforePlugin =
      argv[0] === "python3" && argv[1] === "-c" && argv.indexOf("/usr/bin/hostile-plugin") > sep;
    const passed = pluginStartsAfterSeparator && confinementBeforePlugin;
    return timed(
      passed,
      started,
      `born-confined argv shape wrong: ${JSON.stringify(argv)}`,
    );
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: static-binary delivery fails closed without a valid SHA-256 pin",
  async () => {
    const started = performance.now();
    let allFailClosed = true;
    const detail: string[] = [];

    // Missing path -> throw.
    try {
      parseDelivery("static-binary", null, "a".repeat(64));
      allFailClosed = false;
      detail.push("missing-path did not throw");
    } catch {
      /* expected */
    }
    // Missing hash -> throw ("no hash, no static delivery").
    try {
      parseDelivery("static-binary", "/run/sanctuary-jail", null);
      allFailClosed = false;
      detail.push("missing-hash did not throw");
    } catch {
      /* expected */
    }
    // Malformed hash -> throw.
    try {
      parseDelivery("static-binary", "/run/sanctuary-jail", "not-a-valid-sha");
      allFailClosed = false;
      detail.push("malformed-hash did not throw");
    } catch {
      /* expected */
    }
    // python mode + stray static path -> throw (no silent mode fallback).
    try {
      parseDelivery("python-preamble", "/run/sanctuary-jail", null);
      allFailClosed = false;
      detail.push("python+static-path did not throw");
    } catch {
      /* expected */
    }
    // unknown mode -> throw (never an unjailed launch).
    try {
      parseDelivery("disabled", null, null);
      allFailClosed = false;
      detail.push("unknown-mode did not throw");
    } catch {
      /* expected */
    }
    // Valid static config resolves.
    let validResolves = false;
    try {
      const d = parseDelivery("static-binary", "/run/sanctuary-jail", "A".repeat(64));
      validResolves = d.kind === "static" && d.sha === "a".repeat(64);
    } catch (err) {
      detail.push(`valid config threw: ${String(err)}`);
    }

    const passed = allFailClosed && validResolves;
    return timed(passed, started, detail.join("; ") || "valid static config did not resolve");
  },
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "guest-jail: SanctuaryGuestJail.swift still encodes the launcher-applied deny + fail-closed invariants",
  async () => {
    const started = performance.now();
    const root = findRepoRoot();
    const src = readFileSync(
      resolve(root, "castle-wall-vmm/Sources/SanctuaryVMM/SanctuaryGuestJail.swift"),
      "utf8",
    );
    const required: Array<[string, RegExp]> = [
      ["AF_VSOCK = 40 in preamble", /AF_VSOCK\s*=\s*40\b/],
      ["PR_SET_NO_NEW_PRIVS", /PR_SET_NO_NEW_PRIVS/],
      ["PR_SET_SECCOMP", /PR_SET_SECCOMP/],
      ["EPERM seccomp return", /RET_ERRNO_EPERM\s*=\s*0x00050001/i],
      ["[JAIL] marker", /\[JAIL\] launcher-applied seccomp-deny-AF_VSOCK/],
      ["wrap() prepends python3 -c preamble -- command", /\["python3",\s*"-c",\s*seccompDenyVsockPreamble,\s*"--",\s*command\]/],
      ["no hash, no static delivery", /No hash, no static delivery/],
      ["parseDelivery fail-closed", /func parseDelivery/],
      ["makePlan authenticates staged copy", /func makePlan/],
    ];
    const missing = required.filter(([, re]) => !re.test(src)).map(([label]) => label);
    return timed(
      missing.length === 0,
      started,
      `SanctuaryGuestJail.swift missing expected invariants: ${missing.join("; ")}`,
    );
  },
);
