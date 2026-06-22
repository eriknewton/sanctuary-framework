//! `sanctuary-jail` confinement primitives.
//!
//! The load-bearing filter is Linux seccomp-BPF. The builder is portable so
//! macOS development builds can inspect the exact program CI installs on
//! Linux.

use std::io;

use thiserror::Error;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
const SECCOMP_DATA_ARG1_OFFSET: u32 = 24;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const NR_SOCKET_X86_64: u32 = 41;
pub const NR_SOCKET_AARCH64: u32 = 198;
pub const NR_SOCKETPAIR_X86_64: u32 = 53;
pub const NR_SOCKETPAIR_AARCH64: u32 = 199;
pub const AF_VSOCK_LINUX: u32 = 40;
pub const AF_UNIX_LINUX: u32 = 1;
pub const AF_INET_LINUX: u32 = 2;
pub const AF_INET6_LINUX: u32 = 10;
pub const AF_NETLINK_LINUX: u32 = 16;
pub const AF_PACKET_LINUX: u32 = 17;
pub const TIOCSTI_LINUX: u32 = 0x5412;

pub const CLONE_NEWNS_LINUX: u32 = 0x0002_0000;
pub const CLONE_NEWCGROUP_LINUX: u32 = 0x0200_0000;
pub const CLONE_NEWUTS_LINUX: u32 = 0x0400_0000;
pub const CLONE_NEWIPC_LINUX: u32 = 0x0800_0000;
pub const CLONE_NEWUSER_LINUX: u32 = 0x1000_0000;
pub const CLONE_NEWPID_LINUX: u32 = 0x2000_0000;
pub const CLONE_NEWNET_LINUX: u32 = 0x4000_0000;
pub const CLONE_NAMESPACE_FLAGS_LINUX: u32 = CLONE_NEWNS_LINUX
    | CLONE_NEWCGROUP_LINUX
    | CLONE_NEWUTS_LINUX
    | CLONE_NEWIPC_LINUX
    | CLONE_NEWUSER_LINUX
    | CLONE_NEWPID_LINUX
    | CLONE_NEWNET_LINUX;

pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompProfile {
    LoopV1,
    PluginV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedSyscall {
    pub name: &'static str,
    pub nr: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct PluginV1SyscallTable {
    pub arch_name: &'static str,
    pub arch: u32,
    pub socket: u32,
    pub socketpair: u32,
    pub clone: u32,
    pub ioctl: u32,
    pub denied: &'static [NamedSyscall],
}

pub const PLUGIN_V1_DENIED_X86_64: &[NamedSyscall] = &[
    NamedSyscall {
        name: "ptrace",
        nr: 101,
    },
    NamedSyscall {
        name: "process_vm_readv",
        nr: 310,
    },
    NamedSyscall {
        name: "process_vm_writev",
        nr: 311,
    },
    NamedSyscall {
        name: "mount",
        nr: 165,
    },
    NamedSyscall {
        name: "umount2",
        nr: 166,
    },
    NamedSyscall {
        name: "pivot_root",
        nr: 155,
    },
    NamedSyscall {
        name: "setns",
        nr: 308,
    },
    NamedSyscall {
        name: "unshare",
        nr: 272,
    },
    NamedSyscall {
        name: "kcmp",
        nr: 312,
    },
    NamedSyscall {
        name: "perf_event_open",
        nr: 298,
    },
    NamedSyscall {
        name: "bpf",
        nr: 321,
    },
    NamedSyscall {
        name: "clone3",
        nr: 435,
    },
    NamedSyscall {
        name: "chroot",
        nr: 161,
    },
    NamedSyscall {
        name: "open_tree",
        nr: 428,
    },
    NamedSyscall {
        name: "move_mount",
        nr: 429,
    },
    NamedSyscall {
        name: "fsopen",
        nr: 430,
    },
    NamedSyscall {
        name: "fsconfig",
        nr: 431,
    },
    NamedSyscall {
        name: "fsmount",
        nr: 432,
    },
    NamedSyscall {
        name: "fspick",
        nr: 433,
    },
    NamedSyscall {
        name: "mount_setattr",
        nr: 442,
    },
    NamedSyscall {
        name: "name_to_handle_at",
        nr: 303,
    },
    NamedSyscall {
        name: "open_by_handle_at",
        nr: 304,
    },
    NamedSyscall {
        name: "pidfd_open",
        nr: 434,
    },
    NamedSyscall {
        name: "pidfd_getfd",
        nr: 438,
    },
    NamedSyscall {
        name: "pidfd_send_signal",
        nr: 424,
    },
    NamedSyscall {
        name: "process_madvise",
        nr: 440,
    },
    NamedSyscall {
        name: "process_mrelease",
        nr: 448,
    },
    NamedSyscall {
        name: "userfaultfd",
        nr: 323,
    },
    NamedSyscall {
        name: "io_uring_setup",
        nr: 425,
    },
    NamedSyscall {
        name: "io_uring_enter",
        nr: 426,
    },
    NamedSyscall {
        name: "io_uring_register",
        nr: 427,
    },
    NamedSyscall {
        name: "add_key",
        nr: 248,
    },
    NamedSyscall {
        name: "request_key",
        nr: 249,
    },
    NamedSyscall {
        name: "keyctl",
        nr: 250,
    },
    NamedSyscall {
        name: "init_module",
        nr: 175,
    },
    NamedSyscall {
        name: "finit_module",
        nr: 313,
    },
    NamedSyscall {
        name: "delete_module",
        nr: 176,
    },
    NamedSyscall {
        name: "kexec_load",
        nr: 246,
    },
    NamedSyscall {
        name: "kexec_file_load",
        nr: 320,
    },
    NamedSyscall {
        name: "reboot",
        nr: 169,
    },
    NamedSyscall {
        name: "swapon",
        nr: 167,
    },
    NamedSyscall {
        name: "swapoff",
        nr: 168,
    },
    NamedSyscall {
        name: "acct",
        nr: 163,
    },
    NamedSyscall {
        name: "quotactl",
        nr: 179,
    },
    NamedSyscall {
        name: "quotactl_fd",
        nr: 443,
    },
    NamedSyscall {
        name: "syslog",
        nr: 103,
    },
    NamedSyscall {
        name: "fanotify_init",
        nr: 300,
    },
];

pub const PLUGIN_V1_DENIED_AARCH64: &[NamedSyscall] = &[
    NamedSyscall {
        name: "ptrace",
        nr: 117,
    },
    NamedSyscall {
        name: "process_vm_readv",
        nr: 270,
    },
    NamedSyscall {
        name: "process_vm_writev",
        nr: 271,
    },
    NamedSyscall {
        name: "mount",
        nr: 40,
    },
    NamedSyscall {
        name: "umount2",
        nr: 39,
    },
    NamedSyscall {
        name: "pivot_root",
        nr: 41,
    },
    NamedSyscall {
        name: "setns",
        nr: 268,
    },
    NamedSyscall {
        name: "unshare",
        nr: 97,
    },
    NamedSyscall {
        name: "kcmp",
        nr: 272,
    },
    NamedSyscall {
        name: "perf_event_open",
        nr: 241,
    },
    NamedSyscall {
        name: "bpf",
        nr: 280,
    },
    NamedSyscall {
        name: "clone3",
        nr: 435,
    },
    NamedSyscall {
        name: "chroot",
        nr: 51,
    },
    NamedSyscall {
        name: "open_tree",
        nr: 428,
    },
    NamedSyscall {
        name: "move_mount",
        nr: 429,
    },
    NamedSyscall {
        name: "fsopen",
        nr: 430,
    },
    NamedSyscall {
        name: "fsconfig",
        nr: 431,
    },
    NamedSyscall {
        name: "fsmount",
        nr: 432,
    },
    NamedSyscall {
        name: "fspick",
        nr: 433,
    },
    NamedSyscall {
        name: "mount_setattr",
        nr: 442,
    },
    NamedSyscall {
        name: "name_to_handle_at",
        nr: 264,
    },
    NamedSyscall {
        name: "open_by_handle_at",
        nr: 265,
    },
    NamedSyscall {
        name: "pidfd_open",
        nr: 434,
    },
    NamedSyscall {
        name: "pidfd_getfd",
        nr: 438,
    },
    NamedSyscall {
        name: "pidfd_send_signal",
        nr: 424,
    },
    NamedSyscall {
        name: "process_madvise",
        nr: 440,
    },
    NamedSyscall {
        name: "process_mrelease",
        nr: 448,
    },
    NamedSyscall {
        name: "userfaultfd",
        nr: 282,
    },
    NamedSyscall {
        name: "io_uring_setup",
        nr: 425,
    },
    NamedSyscall {
        name: "io_uring_enter",
        nr: 426,
    },
    NamedSyscall {
        name: "io_uring_register",
        nr: 427,
    },
    NamedSyscall {
        name: "add_key",
        nr: 217,
    },
    NamedSyscall {
        name: "request_key",
        nr: 218,
    },
    NamedSyscall {
        name: "keyctl",
        nr: 219,
    },
    NamedSyscall {
        name: "init_module",
        nr: 105,
    },
    NamedSyscall {
        name: "finit_module",
        nr: 273,
    },
    NamedSyscall {
        name: "delete_module",
        nr: 106,
    },
    NamedSyscall {
        name: "kexec_load",
        nr: 104,
    },
    NamedSyscall {
        name: "kexec_file_load",
        nr: 294,
    },
    NamedSyscall {
        name: "reboot",
        nr: 142,
    },
    NamedSyscall {
        name: "swapon",
        nr: 224,
    },
    NamedSyscall {
        name: "swapoff",
        nr: 225,
    },
    NamedSyscall {
        name: "acct",
        nr: 89,
    },
    NamedSyscall {
        name: "quotactl",
        nr: 60,
    },
    NamedSyscall {
        name: "quotactl_fd",
        nr: 443,
    },
    NamedSyscall {
        name: "syslog",
        nr: 116,
    },
    NamedSyscall {
        name: "fanotify_init",
        nr: 262,
    },
];

pub const PLUGIN_V1_X86_64_SYSCALLS: PluginV1SyscallTable = PluginV1SyscallTable {
    arch_name: "x86_64",
    arch: AUDIT_ARCH_X86_64,
    socket: NR_SOCKET_X86_64,
    socketpair: NR_SOCKETPAIR_X86_64,
    clone: 56,
    ioctl: 16,
    denied: PLUGIN_V1_DENIED_X86_64,
};

pub const PLUGIN_V1_AARCH64_SYSCALLS: PluginV1SyscallTable = PluginV1SyscallTable {
    arch_name: "aarch64",
    arch: AUDIT_ARCH_AARCH64,
    socket: NR_SOCKET_AARCH64,
    socketpair: NR_SOCKETPAIR_AARCH64,
    clone: 220,
    ioctl: 29,
    denied: PLUGIN_V1_DENIED_AARCH64,
};

#[derive(Debug, Error)]
pub enum JailError {
    #[error("sanctuary-jail is only supported on Linux")]
    UnsupportedPlatform,

    #[error("{operation} failed: {source}")]
    Syscall {
        operation: &'static str,
        source: io::Error,
    },
}

pub fn build_deny_vsock_socket_filter() -> Vec<BpfInstruction> {
    vec![
        load_abs(SECCOMP_DATA_ARCH_OFFSET),
        jump_equal(AUDIT_ARCH_X86_64, 0, 6),
        load_abs(SECCOMP_DATA_NR_OFFSET),
        jump_equal(NR_SOCKET_X86_64, 0, 3),
        load_abs(SECCOMP_DATA_ARG0_OFFSET),
        jump_equal(af_vsock(), 0, 1),
        ret(SECCOMP_RET_ERRNO_EPERM),
        ret(SECCOMP_RET_ALLOW),
        jump_equal(AUDIT_ARCH_AARCH64, 0, 6),
        load_abs(SECCOMP_DATA_NR_OFFSET),
        jump_equal(NR_SOCKET_AARCH64, 0, 3),
        load_abs(SECCOMP_DATA_ARG0_OFFSET),
        jump_equal(af_vsock(), 0, 1),
        ret(SECCOMP_RET_ERRNO_EPERM),
        ret(SECCOMP_RET_ALLOW),
        load_abs(SECCOMP_DATA_NR_OFFSET),
        jump_equal(NR_SOCKET_X86_64, 2, 0),
        jump_equal(NR_SOCKET_AARCH64, 1, 0),
        ret(SECCOMP_RET_ALLOW),
        ret(SECCOMP_RET_ERRNO_EPERM),
    ]
}

pub fn build_filter(profile: SeccompProfile) -> Vec<BpfInstruction> {
    match profile {
        SeccompProfile::LoopV1 => build_deny_vsock_socket_filter(),
        SeccompProfile::PluginV1 => build_plugin_v1_filter(),
    }
}

pub fn build_plugin_v1_filter() -> Vec<BpfInstruction> {
    let x86_64 = build_plugin_v1_arch_branch(PLUGIN_V1_X86_64_SYSCALLS);
    let aarch64 = build_plugin_v1_arch_branch(PLUGIN_V1_AARCH64_SYSCALLS);

    let mut program = Vec::with_capacity(4 + x86_64.len() + aarch64.len());
    program.push(load_abs(SECCOMP_DATA_ARCH_OFFSET));
    program.push(jump_equal(
        AUDIT_ARCH_X86_64,
        0,
        checked_jump_offset(x86_64.len()),
    ));
    program.extend(x86_64);
    program.push(jump_equal(
        AUDIT_ARCH_AARCH64,
        0,
        checked_jump_offset(aarch64.len()),
    ));
    program.extend(aarch64);
    program.push(ret(SECCOMP_RET_ERRNO_EPERM));
    program
}

pub fn confine_current_process() -> Result<(), JailError> {
    set_no_new_privs()?;
    drop_capabilities()?;
    install_seccomp_deny_vsock()
}

pub fn confine_current_process_with_profile(profile: SeccompProfile) -> Result<(), JailError> {
    set_no_new_privs()?;
    drop_capabilities()?;
    install_seccomp_profile(profile)
}

pub fn af_vsock() -> u32 {
    linux_af_vsock()
}

#[cfg(target_os = "linux")]
fn linux_af_vsock() -> u32 {
    libc::AF_VSOCK as u32
}

#[cfg(not(target_os = "linux"))]
fn linux_af_vsock() -> u32 {
    AF_VSOCK_LINUX
}

#[cfg(target_os = "linux")]
pub fn current_arch_audit_constant() -> u32 {
    if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else if cfg!(target_arch = "aarch64") {
        AUDIT_ARCH_AARCH64
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<(), JailError> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_os_error("PR_SET_NO_NEW_PRIVS"))
    }
}

#[cfg(not(target_os = "linux"))]
fn set_no_new_privs() -> Result<(), JailError> {
    Err(JailError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn drop_capabilities() -> Result<(), JailError> {
    clear_ambient_capabilities()?;
    drop_capability_bounding_set()
}

#[cfg(not(target_os = "linux"))]
fn drop_capabilities() -> Result<(), JailError> {
    Err(JailError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn clear_ambient_capabilities() -> Result<(), JailError> {
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EINVAL) => Ok(()),
        _ => Err(JailError::Syscall {
            operation: "PR_CAP_AMBIENT_CLEAR_ALL",
            source: err,
        }),
    }
}

#[cfg(target_os = "linux")]
fn drop_capability_bounding_set() -> Result<(), JailError> {
    for cap in 0..=63 {
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc == 0 {
            continue;
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINVAL) => break,
            Some(libc::EPERM) if !running_as_root() => continue,
            _ => {
                return Err(JailError::Syscall {
                    operation: "PR_CAPBSET_DROP",
                    source: err,
                });
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn install_seccomp_deny_vsock() -> Result<(), JailError> {
    install_seccomp_profile(SeccompProfile::LoopV1)
}

#[cfg(not(target_os = "linux"))]
fn install_seccomp_deny_vsock() -> Result<(), JailError> {
    Err(JailError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn install_seccomp_profile(profile: SeccompProfile) -> Result<(), JailError> {
    let program = build_filter(profile);
    let mut raw_program: Vec<libc::sock_filter> = program
        .iter()
        .map(|insn| libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        })
        .collect();
    let mut filter = libc::sock_fprog {
        len: raw_program.len() as libc::c_ushort,
        filter: raw_program.as_mut_ptr(),
    };

    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut filter as *mut libc::sock_fprog,
            0,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_os_error("PR_SET_SECCOMP"))
    }
}

#[cfg(not(target_os = "linux"))]
fn install_seccomp_profile(_profile: SeccompProfile) -> Result<(), JailError> {
    Err(JailError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn last_os_error(operation: &'static str) -> JailError {
    JailError::Syscall {
        operation,
        source: io::Error::last_os_error(),
    }
}

const fn load_abs(offset: u32) -> BpfInstruction {
    BpfInstruction {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

const fn jump_equal(k: u32, jt: u8, jf: u8) -> BpfInstruction {
    BpfInstruction {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

const fn jump_set(k: u32, jt: u8, jf: u8) -> BpfInstruction {
    BpfInstruction {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt,
        jf,
        k,
    }
}

const fn ret(k: u32) -> BpfInstruction {
    BpfInstruction {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

fn build_plugin_v1_arch_branch(table: PluginV1SyscallTable) -> Vec<BpfInstruction> {
    let mut branch = Vec::new();
    branch.push(load_abs(SECCOMP_DATA_NR_OFFSET));
    append_socket_family_gate(&mut branch, table.socket);
    append_socket_family_gate(&mut branch, table.socketpair);
    append_clone_namespace_gate(&mut branch, table.clone);
    append_ioctl_tiocsti_gate(&mut branch, table.ioctl);
    for syscall in table.denied {
        append_unconditional_deny(&mut branch, syscall.nr);
    }
    branch.push(ret(SECCOMP_RET_ALLOW));
    branch
}

fn append_socket_family_gate(branch: &mut Vec<BpfInstruction>, syscall_nr: u32) {
    branch.push(jump_equal(syscall_nr, 0, 4));
    branch.push(load_abs(SECCOMP_DATA_ARG0_OFFSET));
    branch.push(jump_equal(AF_UNIX_LINUX, 1, 0));
    branch.push(ret(SECCOMP_RET_ERRNO_EPERM));
    branch.push(ret(SECCOMP_RET_ALLOW));
}

fn append_clone_namespace_gate(branch: &mut Vec<BpfInstruction>, syscall_nr: u32) {
    branch.push(jump_equal(syscall_nr, 0, 4));
    branch.push(load_abs(SECCOMP_DATA_ARG0_OFFSET));
    branch.push(jump_set(CLONE_NAMESPACE_FLAGS_LINUX, 0, 1));
    branch.push(ret(SECCOMP_RET_ERRNO_EPERM));
    branch.push(ret(SECCOMP_RET_ALLOW));
}

fn append_ioctl_tiocsti_gate(branch: &mut Vec<BpfInstruction>, syscall_nr: u32) {
    branch.push(jump_equal(syscall_nr, 0, 4));
    branch.push(load_abs(SECCOMP_DATA_ARG1_OFFSET));
    branch.push(jump_equal(TIOCSTI_LINUX, 0, 1));
    branch.push(ret(SECCOMP_RET_ERRNO_EPERM));
    branch.push(ret(SECCOMP_RET_ALLOW));
}

fn append_unconditional_deny(branch: &mut Vec<BpfInstruction>, syscall_nr: u32) {
    branch.push(jump_equal(syscall_nr, 0, 1));
    branch.push(ret(SECCOMP_RET_ERRNO_EPERM));
}

fn checked_jump_offset(len: usize) -> u8 {
    len.try_into()
        .expect("seccomp branch exceeds classic BPF jump range")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const _: () = {
    assert!(NR_SOCKET_X86_64 as libc::c_long == libc::SYS_socket);
    assert!(NR_SOCKETPAIR_X86_64 as libc::c_long == libc::SYS_socketpair);
    assert!(PLUGIN_V1_X86_64_SYSCALLS.clone as libc::c_long == libc::SYS_clone);
    assert!(PLUGIN_V1_X86_64_SYSCALLS.ioctl as libc::c_long == libc::SYS_ioctl);
    assert!(PLUGIN_V1_DENIED_X86_64[0].nr as libc::c_long == libc::SYS_ptrace);
    assert!(PLUGIN_V1_DENIED_X86_64[1].nr as libc::c_long == libc::SYS_process_vm_readv);
    assert!(PLUGIN_V1_DENIED_X86_64[2].nr as libc::c_long == libc::SYS_process_vm_writev);
    assert!(PLUGIN_V1_DENIED_X86_64[3].nr as libc::c_long == libc::SYS_mount);
    assert!(PLUGIN_V1_DENIED_X86_64[4].nr as libc::c_long == libc::SYS_umount2);
    assert!(PLUGIN_V1_DENIED_X86_64[5].nr as libc::c_long == libc::SYS_pivot_root);
    assert!(PLUGIN_V1_DENIED_X86_64[6].nr as libc::c_long == libc::SYS_setns);
    assert!(PLUGIN_V1_DENIED_X86_64[7].nr as libc::c_long == libc::SYS_unshare);
    assert!(PLUGIN_V1_DENIED_X86_64[8].nr as libc::c_long == libc::SYS_kcmp);
    assert!(PLUGIN_V1_DENIED_X86_64[9].nr as libc::c_long == libc::SYS_perf_event_open);
    assert!(PLUGIN_V1_DENIED_X86_64[10].nr as libc::c_long == libc::SYS_bpf);
    assert!(PLUGIN_V1_DENIED_X86_64[11].nr as libc::c_long == libc::SYS_clone3);
};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const _: () = {
    assert!(NR_SOCKET_AARCH64 as libc::c_long == libc::SYS_socket);
    assert!(NR_SOCKETPAIR_AARCH64 as libc::c_long == libc::SYS_socketpair);
    assert!(PLUGIN_V1_AARCH64_SYSCALLS.clone as libc::c_long == libc::SYS_clone);
    assert!(PLUGIN_V1_AARCH64_SYSCALLS.ioctl as libc::c_long == libc::SYS_ioctl);
    assert!(PLUGIN_V1_DENIED_AARCH64[0].nr as libc::c_long == libc::SYS_ptrace);
    assert!(PLUGIN_V1_DENIED_AARCH64[1].nr as libc::c_long == libc::SYS_process_vm_readv);
    assert!(PLUGIN_V1_DENIED_AARCH64[2].nr as libc::c_long == libc::SYS_process_vm_writev);
    assert!(PLUGIN_V1_DENIED_AARCH64[3].nr as libc::c_long == libc::SYS_mount);
    assert!(PLUGIN_V1_DENIED_AARCH64[4].nr as libc::c_long == libc::SYS_umount2);
    assert!(PLUGIN_V1_DENIED_AARCH64[5].nr as libc::c_long == libc::SYS_pivot_root);
    assert!(PLUGIN_V1_DENIED_AARCH64[6].nr as libc::c_long == libc::SYS_setns);
    assert!(PLUGIN_V1_DENIED_AARCH64[7].nr as libc::c_long == libc::SYS_unshare);
    assert!(PLUGIN_V1_DENIED_AARCH64[8].nr as libc::c_long == libc::SYS_kcmp);
    assert!(PLUGIN_V1_DENIED_AARCH64[9].nr as libc::c_long == libc::SYS_perf_event_open);
    assert!(PLUGIN_V1_DENIED_AARCH64[10].nr as libc::c_long == libc::SYS_bpf);
    assert!(PLUGIN_V1_DENIED_AARCH64[11].nr as libc::c_long == libc::SYS_clone3);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_contains_both_supported_arch_branches() {
        let program = build_deny_vsock_socket_filter();
        assert!(program.iter().any(|insn| insn.k == AUDIT_ARCH_X86_64));
        assert!(program.iter().any(|insn| insn.k == AUDIT_ARCH_AARCH64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKET_X86_64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKET_AARCH64));
    }

    #[test]
    fn filter_denies_af_vsock_with_eperm() {
        let program = build_deny_vsock_socket_filter();
        assert!(program.iter().any(|insn| insn.k == af_vsock()));
        assert!(program.iter().any(|insn| insn.k == SECCOMP_RET_ERRNO_EPERM));
        assert!(program.iter().any(|insn| insn.k == SECCOMP_RET_ALLOW));
        assert_eq!(af_vsock(), AF_VSOCK_LINUX);
    }

    #[test]
    fn filter_verdicts_are_surgical_for_supported_arches() {
        let program = build_deny_vsock_socket_filter();
        assert_eq!(
            simulate(&program, AUDIT_ARCH_X86_64, NR_SOCKET_X86_64, af_vsock()),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            simulate(&program, AUDIT_ARCH_X86_64, NR_SOCKET_X86_64, 2),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            simulate(&program, AUDIT_ARCH_AARCH64, NR_SOCKET_AARCH64, af_vsock()),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            simulate(&program, AUDIT_ARCH_AARCH64, NR_SOCKET_AARCH64, 1),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn unknown_arch_path_denies_known_socket_syscall_numbers() {
        let program = build_deny_vsock_socket_filter();
        let unknown_arch = 0x0000_1234;
        assert_eq!(
            simulate(&program, unknown_arch, NR_SOCKET_X86_64, 2),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            simulate(&program, unknown_arch, NR_SOCKET_AARCH64, 2),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            simulate(&program, unknown_arch, 999, af_vsock()),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn plugin_v1_filter_contains_both_supported_arch_branches() {
        let program = build_plugin_v1_filter();
        assert!(program.iter().any(|insn| insn.k == AUDIT_ARCH_X86_64));
        assert!(program.iter().any(|insn| insn.k == AUDIT_ARCH_AARCH64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKET_X86_64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKET_AARCH64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKETPAIR_X86_64));
        assert!(program.iter().any(|insn| insn.k == NR_SOCKETPAIR_AARCH64));
    }

    #[test]
    fn plugin_v1_allows_only_af_unix_socket_families() {
        let program = build_plugin_v1_filter();
        for table in plugin_v1_tables() {
            for syscall_nr in [table.socket, table.socketpair] {
                assert_eq!(
                    simulate(&program, table.arch, syscall_nr, AF_UNIX_LINUX),
                    SECCOMP_RET_ALLOW,
                    "{} should allow AF_UNIX for syscall {}",
                    table.arch_name,
                    syscall_nr
                );
                for family in [
                    AF_INET_LINUX,
                    AF_INET6_LINUX,
                    af_vsock(),
                    AF_NETLINK_LINUX,
                    AF_PACKET_LINUX,
                    999,
                ] {
                    assert_eq!(
                        simulate(&program, table.arch, syscall_nr, family),
                        SECCOMP_RET_ERRNO_EPERM,
                        "{} should deny socket family {} for syscall {}",
                        table.arch_name,
                        family,
                        syscall_nr
                    );
                }
            }
        }
    }

    #[test]
    fn plugin_v1_denies_required_escape_syscalls_for_both_arches() {
        let program = build_plugin_v1_filter();
        let required = [
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "mount",
            "umount2",
            "pivot_root",
            "setns",
            "unshare",
            "kcmp",
            "perf_event_open",
            "bpf",
            "clone3",
        ];

        for table in plugin_v1_tables() {
            for name in required {
                let syscall = table
                    .denied
                    .iter()
                    .find(|syscall| syscall.name == name)
                    .unwrap_or_else(|| panic!("{} missing {name}", table.arch_name));
                assert_eq!(
                    simulate(&program, table.arch, syscall.nr, 0),
                    SECCOMP_RET_ERRNO_EPERM,
                    "{} should deny {}",
                    table.arch_name,
                    name
                );
            }
        }
    }

    #[test]
    fn plugin_v1_denies_extra_hardening_syscalls_for_both_arches() {
        let program = build_plugin_v1_filter();
        for table in plugin_v1_tables() {
            for syscall in table.denied {
                assert_eq!(
                    simulate(&program, table.arch, syscall.nr, 0),
                    SECCOMP_RET_ERRNO_EPERM,
                    "{} should deny {}",
                    table.arch_name,
                    syscall.name
                );
            }
        }
    }

    #[test]
    fn plugin_v1_clone_gate_denies_namespace_flags_only() {
        let program = build_plugin_v1_filter();
        for table in plugin_v1_tables() {
            assert_eq!(
                simulate(&program, table.arch, table.clone, 17),
                SECCOMP_RET_ALLOW,
                "{} should allow clone without namespace flags",
                table.arch_name
            );
            for flags in [
                CLONE_NEWNS_LINUX,
                CLONE_NEWCGROUP_LINUX,
                CLONE_NEWUTS_LINUX,
                CLONE_NEWIPC_LINUX,
                CLONE_NEWUSER_LINUX,
                CLONE_NEWPID_LINUX,
                CLONE_NEWNET_LINUX,
                CLONE_NEWNET_LINUX | 17,
            ] {
                assert_eq!(
                    simulate(&program, table.arch, table.clone, flags),
                    SECCOMP_RET_ERRNO_EPERM,
                    "{} should deny clone flags {flags:#x}",
                    table.arch_name
                );
            }
        }
    }

    #[test]
    fn plugin_v1_ioctl_gate_denies_tiocsti_only() {
        let program = build_plugin_v1_filter();
        for table in plugin_v1_tables() {
            assert_eq!(
                simulate_args(&program, table.arch, table.ioctl, 0, TIOCSTI_LINUX),
                SECCOMP_RET_ERRNO_EPERM,
                "{} should deny ioctl TIOCSTI",
                table.arch_name
            );
            assert_eq!(
                simulate_args(&program, table.arch, table.ioctl, 0, 0x5401),
                SECCOMP_RET_ALLOW,
                "{} should allow non-TIOCSTI ioctl",
                table.arch_name
            );
        }
    }

    #[test]
    fn plugin_v1_unknown_arch_fails_closed() {
        let program = build_plugin_v1_filter();
        let unknown_arch = 0x0000_1234;
        assert_eq!(
            simulate(&program, unknown_arch, NR_SOCKET_X86_64, AF_UNIX_LINUX),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            simulate(&program, unknown_arch, 999, 0),
            SECCOMP_RET_ERRNO_EPERM
        );
    }

    fn plugin_v1_tables() -> [PluginV1SyscallTable; 2] {
        [PLUGIN_V1_X86_64_SYSCALLS, PLUGIN_V1_AARCH64_SYSCALLS]
    }

    fn simulate(program: &[BpfInstruction], arch: u32, nr: u32, arg0: u32) -> u32 {
        simulate_args(program, arch, nr, arg0, 0)
    }

    fn simulate_args(program: &[BpfInstruction], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;
        loop {
            let insn = program[pc];
            match insn.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    accumulator = match insn.k {
                        SECCOMP_DATA_NR_OFFSET => nr,
                        SECCOMP_DATA_ARCH_OFFSET => arch,
                        SECCOMP_DATA_ARG0_OFFSET => arg0,
                        SECCOMP_DATA_ARG1_OFFSET => arg1,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    pc += if accumulator == insn.k {
                        usize::from(insn.jt) + 1
                    } else {
                        usize::from(insn.jf) + 1
                    };
                }
                code if code == (BPF_JMP | BPF_JSET | BPF_K) => {
                    pc += if accumulator & insn.k != 0 {
                        usize::from(insn.jt) + 1
                    } else {
                        usize::from(insn.jf) + 1
                    };
                }
                code if code == (BPF_RET | BPF_K) => return insn.k,
                other => panic!("unexpected instruction code {other}"),
            }
        }
    }
}
