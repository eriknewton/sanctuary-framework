//! Fixed native service entrypoint; no daemon boot wiring is performed here.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::*,
        signer_peer::PeerPolicy,
        signer_service::{self, Paths},
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "test-isolation")]
    {
        // Isolation arguments do not exist in the default release artifact.
        if args.len() == 6 && args[0] == "--test-service" {
            let owner = unsafe { libc::geteuid() };
            let bytes = read_pinned(
                std::path::Path::new(&args[1]),
                owner,
                CONFIG_MAX_BYTES,
                PRIVATE_MODE,
            )?;
            let config = serde_json::from_slice(&bytes).map_err(|_| refused())?;
            return signer_service::run(
                config,
                Paths {
                    control: args[2].clone().into(),
                    custody: args[3].clone().into(),
                    node: args[4].clone().into(),
                    worker: args[5].clone().into(),
                    owner,
                },
            );
        }
        if args.len() == 4 && args[0] == "--test-bridge" {
            let policy: PeerPolicy = serde_json::from_str(&args[2]).map_err(|_| refused())?;
            let parent: PeerPolicy = serde_json::from_str(&args[3]).map_err(|_| refused())?;
            return signer_service::bridge(std::path::Path::new(&args[1]), &policy, &parent);
        }
    }
    if args == ["--bridge"] {
        let bytes = read_pinned(
            std::path::Path::new("/etc/sanctuary/business-signer-peer.json"),
            ROOT_UID,
            CONFIG_MAX_BYTES,
            0o644,
        )?;
        let policy: PeerPolicy = serde_json::from_slice(&bytes).map_err(|_| refused())?;
        let bytes = read_pinned(
            std::path::Path::new("/etc/sanctuary/business-signer-controller.json"),
            ROOT_UID,
            CONFIG_MAX_BYTES,
            0o644,
        )?;
        let parent: PeerPolicy = serde_json::from_slice(&bytes).map_err(|_| refused())?;
        return signer_service::bridge(
            &std::path::Path::new(CONTROL_ROOT).join(signer_service::SIGN_SOCKET),
            &policy,
            &parent,
        );
    }
    if !args.is_empty() || unsafe { libc::geteuid() } != ROOT_UID {
        return Err(refused());
    }
    let bytes = read_pinned(
        std::path::Path::new(CONFIG_PATH),
        ROOT_UID,
        CONFIG_MAX_BYTES,
        PRIVATE_MODE,
    )?;
    let config: Config =
        serde_json::from_value(signer_service::canonical(&bytes, CONFIG_MAX_BYTES)?)
            .map_err(|_| refused())?;
    let paths = Paths {
        custody: production_custody_path(&config)?,
        ..Paths::default()
    };
    signer_service::run(config, paths)
}
fn main() {
    #[cfg(target_os = "linux")]
    if execute().is_ok() {
        return;
    }
    // SAFETY: Fixed error codes cannot disclose a worker exception or any factor material.
    eprintln!("K1_REFUSED");
    std::process::exit(1);
}
