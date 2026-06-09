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
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const NR_SOCKET_X86_64: u32 = 41;
pub const NR_SOCKET_AARCH64: u32 = 198;
pub const AF_VSOCK_LINUX: u32 = 40;

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

pub fn confine_current_process() -> Result<(), JailError> {
    set_no_new_privs()?;
    drop_capabilities()?;
    install_seccomp_deny_vsock()
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
    let program = build_deny_vsock_socket_filter();
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
fn install_seccomp_deny_vsock() -> Result<(), JailError> {
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

const fn ret(k: u32) -> BpfInstruction {
    BpfInstruction {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

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

    fn simulate(program: &[BpfInstruction], arch: u32, nr: u32, arg0: u32) -> u32 {
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
                code if code == (BPF_RET | BPF_K) => return insn.k,
                other => panic!("unexpected instruction code {other}"),
            }
        }
    }
}
