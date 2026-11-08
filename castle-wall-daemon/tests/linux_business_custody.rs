#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::custody::*;
use std::{os::unix::fs::PermissionsExt,process::Stdio};
#[test]
fn environment_drops_unlisted_variables(){let cmd=worker_command(std::path::Path::new("/bin/echo"),std::path::Path::new("/fixture"));let env:Vec<_>=cmd.get_envs().filter_map(|(k,v)|v.map(|v|(k.to_string_lossy().into_owned(),v.to_string_lossy().into_owned()))).collect();assert_eq!(env,vec![("LANG".into(),"C.UTF-8".into()),("TZ".into(),"UTC".into())]);assert!(cmd.get_args().any(|a|a=="--disable-sigusr1"));}
#[test]
fn closed_environment_applies_to_child(){
    let root=tempfile::tempdir().unwrap();let script=root.path().join("environment.cjs");
    std::fs::write(&script,"process.stdout.write(JSON.stringify(process.env))").unwrap();
    std::env::set_var("K1_UNLISTED_SENTINEL", "should-not-inherit");
    let output=worker_command(std::path::Path::new("/usr/bin/node"),&script).stdout(Stdio::piped()).output().unwrap();
    std::env::remove_var("K1_UNLISTED_SENTINEL");
    assert!(output.status.success());let value:serde_json::Value=serde_json::from_slice(&output.stdout).unwrap();
    assert!(value.get("K1_UNLISTED_SENTINEL").is_none());assert!(value.get("HOME").is_none());assert_eq!(value.as_object().unwrap().len(),2);
}
#[test]
fn custody_file_owner_mode_size_and_symlink_are_checked(){let root=tempfile::tempdir().unwrap();let path=root.path().join("file");std::fs::write(&path,b"public ciphertext").unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();let uid=unsafe{libc::geteuid()};
    use sha2::{Digest,Sha256};let digest=hex::encode(Sha256::digest(b"public ciphertext"));assert!(artifact(&path,&digest,uid).is_ok());assert!(artifact(&path,&"0".repeat(64),uid).is_err());
    assert!(read_pinned(&path,uid,CONFIG_MAX_BYTES,PRIVATE_MODE).is_ok());assert!(read_pinned(&path,uid,1,PRIVATE_MODE).is_err());let link=root.path().join("link");std::os::unix::fs::symlink(&path,&link).unwrap();assert!(read_pinned(&link,uid,CONFIG_MAX_BYTES,PRIVATE_MODE).is_err());std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();assert!(read_pinned(&path,uid,CONFIG_MAX_BYTES,PRIVATE_MODE).is_err());}
#[test]
#[ignore = "needs root host: root-owned socket UID and mode under protected control parent"]
fn root_socket_ownership(){use std::os::unix::fs::MetadataExt;assert_eq!(unsafe{libc::geteuid()},0);let root=tempfile::tempdir().unwrap();std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();let socket=root.path().join("sign.sock");let _fd=castle_wall_daemon::business_profile::signer_peer::listen(&socket).unwrap();let m=std::fs::metadata(&socket).unwrap();assert_eq!(m.uid(),ROOT_UID);assert_eq!(m.mode()&0o777,PRIVATE_MODE);assert!(check_root(root.path(),ROOT_UID).is_ok());}
#[test]
#[ignore = "needs root host: system manager filesystem confinement is enforced"]
fn root_system_unit_filesystem_confinement(){
    assert_eq!(unsafe{libc::geteuid()},0);
    let root=tempfile::tempdir().unwrap();let forbidden=root.path().join("forbidden");let allowed=root.path().join("allowed");std::fs::create_dir(&allowed).unwrap();
    let unit=include_str!("../systemd/sanctuary-business-signer.service");
    let mut command=std::process::Command::new("systemd-run");command.args(["--system","--wait","--collect","--quiet"]);
    for name in ["ProtectSystem","ProtectHome","PrivateDevices","NoNewPrivileges","CapabilityBoundingSet","RestrictAddressFamilies"] {
        let prefix=format!("{name}=");let directive=unit.lines().find(|line|line.starts_with(&prefix)).unwrap();command.arg("-p").arg(directive);
    }
    let status=command.arg("-p").arg(format!("ReadWritePaths={}",allowed.display())).args(["/bin/sh","-c","touch \"$1/positive\" && ! touch \"$2\"","k1-confinement"]).arg(&allowed).arg(&forbidden).status().unwrap();
    assert!(status.success());assert!(allowed.join("positive").exists());assert!(!forbidden.exists());
}
#[test]
#[ignore = "needs root host: host swap and hibernation are disabled before readiness"]
fn root_host_memory_policy(){assert_eq!(unsafe{libc::geteuid()},0);verify_host_memory_policy().unwrap();}

#[test]
fn production_store_is_pinned_beneath_role_root() {
    let mut config: Config = serde_json::from_value(serde_json::json!({
        "controller":{"uid":0,"executable_sha256":"0".repeat(64),"cgroup":"fixture"},
        "launcher":{"uid":0,"executable_sha256":"0".repeat(64),"cgroup":"fixture"},
        "node_sha256":"0".repeat(64),"worker_sha256":"0".repeat(64),
        "grant":{"role":"extension:linux-business-producer-v0"},"fortress_id":"fixture-fortress",
        "roster_digest":"public","binding_high_water":0,"runtime":[]
    })).unwrap();
    assert_eq!(production_custody_path(&config).unwrap(), std::path::Path::new(CUSTODY_ROOT).join("fixture-fortress").join(PRODUCER_ROLE_SLOT));
    config.fortress_id = "../other".into(); assert!(production_custody_path(&config).is_err());
    config.fortress_id = "fixture-fortress".into(); config.grant["role"] = serde_json::json!("evidence-pack:manifest-v0");
    assert!(production_custody_path(&config).is_err());
}
