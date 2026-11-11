//! Fixed native service entrypoint; no daemon boot wiring is performed here.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::*,
        signer_service::{self, Paths},
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "test-isolation")]
    {
        // Isolation arguments do not exist in the default release artifact.
        if (args.len() == 6
            || (args.len() == 8 && args[6] == std::hint::black_box("--test-boot-id")))
            && args[0] == "--test-service"
        {
            let owner = unsafe { libc::geteuid() };
            let bytes = read_pinned(
                std::path::Path::new(&args[1]),
                owner,
                CONFIG_MAX_BYTES,
                PRIVATE_MODE,
            )?;
            let config = serde_json::from_slice(&bytes).map_err(|_| refused())?;
            let paths = Paths {
                control: args[2].clone().into(),
                custody: args[3].clone().into(),
                node: args[4].clone().into(),
                worker: args[5].clone().into(),
                owner,
            };
            return if args.len() == 8 {
                signer_service::run_with_test_boot_id(config, paths, std::path::Path::new(&args[7]))
            } else {
                signer_service::run(config, paths)
            };
        }
        // test-isolation only: this probe authenticates the signer but not its parent, so it must never exist in a release artifact; release absence is proven by the release-closure test.
        if args.len() == 3 && args[0] == std::hint::black_box("--test-client") {
            use castle_wall_daemon::business_profile::{
                signer_client::BusinessSignerClient, signer_peer,
            };
            let policy = serde_json::from_str(&args[2]).map_err(|_| refused())?;
            signer_peer::drop_capabilities()?;
            let mut client =
                BusinessSignerClient::bootstrap_at(std::path::Path::new(&args[1]), policy)
                    .map_err(|_| refused())?;
            let status = client.status().map_err(|_| refused())?;
            let value = serde_json::to_value(status).map_err(|_| refused())?;
            // The probe shares the signer's bounded canonical response encoding, so its stdout cannot drift from STATUS packets.
            let packet = signer_service::encode(&value, &[])?;
            let line = std::str::from_utf8(&packet[signer_service::LENGTH_BYTES..])
                .map_err(|_| refused())?;
            // SAFETY: The test-only probe emits only the public canonical STATUS observation as its stdout contract.
            println!("{line}");
            client.close_and_settle();
            return Ok(());
        }
        // Keep the entry literal observable so release byte checks detect an accidentally removed feature gate.
        if args.len() == 3 && args[0] == std::hint::black_box("--test-relay") {
            let policy = serde_json::from_str(&args[2]).map_err(|_| refused())?;
            return test_relay(std::path::Path::new(&args[1]), &policy);
        }
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

#[cfg(all(target_os = "linux", feature = "test-isolation"))]
fn test_relay(
    path: &std::path::Path,
    policy: &castle_wall_daemon::business_profile::signer_peer::PeerPolicy,
) -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::refused,
        signer_contract::{
            SIGNER_FRAME_MAX_BYTES, SIGNER_IDLE_DEADLINE_MS, SIGNER_REQUEST_DEADLINE_MS,
        },
        signer_peer::{self, Peer},
        signer_service::{LENGTH_BYTES, RESPONSE_MAX_BYTES},
        signer_watchdog::boottime_ns,
    };
    use std::os::fd::AsRawFd;
    const INPUT: i32 = libc::STDIN_FILENO;
    const OUTPUT: i32 = libc::STDOUT_FILENO;
    const NS_PER_MS: u64 = 1_000_000; // Nanoseconds per millisecond.
                                      // test-isolation only: this relay authenticates the signer but not its parent, so it must never exist in a release artifact; release absence is proven by the release-closure test.
                                      // Must match require_unix_socket in signer_peer.rs and k1-relay-client.ts: stdin is an AF_UNIX socket.
    signer_peer::require_unix_socket(INPUT)?;
    signer_peer::drop_capabilities()?;
    let socket = signer_peer::connect(path)?;
    signer_peer::passcred(socket.as_raw_fd())?;
    let peer = Peer::capture(socket.as_raw_fd(), policy)?;
    let wait = |fd, events, end| -> std::io::Result<()> {
        let now = boottime_ns()?;
        if now >= end || !peer.live() {
            return Err(refused());
        }
        let timeout = ((end - now) / NS_PER_MS).min(i32::MAX as u64) as i32;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, timeout) } != 1
            || poll.revents & events == 0
            || boottime_ns()? >= end
        {
            return Err(refused());
        }
        Ok(())
    };
    loop {
        let input_end = boottime_ns()? + SIGNER_IDLE_DEADLINE_MS as u64 * NS_PER_MS;
        let mut bytes = Vec::new();
        loop {
            wait(INPUT, libc::POLLIN, input_end)?;
            let mut chunk = [0u8; SIGNER_FRAME_MAX_BYTES + LENGTH_BYTES];
            let count = unsafe {
                libc::recv(
                    INPUT,
                    chunk.as_mut_ptr() as _,
                    chunk.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            // Test input is bounded even though its parent is deliberately unauthenticated.
            if count <= 0 || bytes.len() + count as usize > chunk.len() {
                return Err(refused());
            }
            bytes.extend_from_slice(&chunk[..count as usize]);
            if bytes.len() < LENGTH_BYTES {
                continue;
            }
            let length =
                u32::from_be_bytes(bytes[..LENGTH_BYTES].try_into().map_err(|_| refused())?)
                    as usize;
            if length > SIGNER_FRAME_MAX_BYTES || bytes.len() > length + LENGTH_BYTES {
                return Err(refused());
            }
            if bytes.len() == length + LENGTH_BYTES {
                break;
            }
        }
        let end = boottime_ns()? + SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS;
        signer_peer::send(socket.as_raw_fd(), &bytes[LENGTH_BYTES..], &[])?;
        wait(socket.as_raw_fd(), libc::POLLIN, end)?;
        let packet = signer_peer::receive(socket.as_raw_fd(), RESPONSE_MAX_BYTES + LENGTH_BYTES)?;
        // Only the captured signer may produce a reply, and test transport never conveys descriptors.
        if !peer.matches(&packet) || !packet.rights.is_empty() {
            return Err(refused());
        }
        let output = [
            &(packet.bytes.len() as u32).to_be_bytes()[..],
            &packet.bytes,
        ]
        .concat();
        let mut offset = 0;
        while offset < output.len() {
            wait(OUTPUT, libc::POLLOUT, end)?;
            let count = unsafe {
                libc::send(
                    OUTPUT,
                    output[offset..].as_ptr() as _,
                    output.len() - offset,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if count <= 0 {
                return Err(refused());
            }
            offset += count as usize;
        }
    }
}
