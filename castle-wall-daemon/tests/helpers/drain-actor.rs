// fail-before-exempt: isolated actor commands exercise authenticated W client primitives against the actual drain service.
// fail-before-exempt: New isolated native actor and capability-drop launcher; the drain entrypoint is absent at the base.
//! Test-only real socket principal; stdin commands never exist in a shipped service.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::refused,
        drain_protocol::{D_HEADER_MAX_BYTES, D_REQUEST_DEADLINE_MS, D_REQUEST_MAX_BYTES},
        signer_peer,
    };
    use std::{
        io::{BufRead, Read, Write},
        os::fd::{AsRawFd, OwnedFd},
    };
    // The driver permits five service deadlines for classification, a reply and scheduling overhead.
    const DRIVER_WAIT_MS: u64 = D_REQUEST_DEADLINE_MS as u64 * 5;
    // Match the writer stand-in: empty peer capabilities permit the service's unprivileged executable inspection in root CI.
    signer_peer::drop_capabilities()?;
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--transport-child" {
        use std::os::unix::process::CommandExt;
        // Must match drain_transport_child_driver in linux_business_drain.rs; exec preserves this dropped principal and PID.
        return Err(std::process::Command::new(&args[2])
            .args([
                "drain_transport_child_driver",
                "--ignored",
                "--exact",
                "--nocapture",
            ])
            .exec());
    }
    if args.len() != 1 {
        return Err(refused());
    }
    let mut socket: Option<OwnedFd> = None;
    use castle_wall_daemon::business_profile::append_clients as clients;
    struct ClientHooks;
    impl clients::ClientHooks for ClientHooks {
        fn before_send(&mut self) -> clients::Result<()> {
            Ok(())
        }
        fn closed(&mut self) {}
    }
    let mut client: Option<clients::DrainClient> = None;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        // Hex encoding doubles packet bytes; one protocol header bounds the command metadata.
        let n = std::io::Read::by_ref(&mut input)
            .take((D_REQUEST_MAX_BYTES * 2 + D_HEADER_MAX_BYTES) as u64)
            .read_until(b'\n', &mut bytes)?;
        if n == 0 {
            return Ok(());
        }
        if bytes.last() != Some(&b'\n') {
            return Err(refused());
        }
        let command: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
        let result = (|| -> std::io::Result<serde_json::Value> {
            match command["op"].as_str().ok_or_else(refused)? {
                "client-connect" => {
                    socket=None;
                    let root=clients::HeldSocketRoot::checked(std::fs::File::open(command["root"].as_str().ok_or_else(refused)?)?,unsafe{libc::geteuid()}).map_err(|_|refused())?;
                    let pins=clients::ServerPins {
                        writer:serde_json::from_value(command["writer"].clone()).map_err(|_|refused())?,
                        drain:serde_json::from_value(command["drain"].clone()).map_err(|_|refused())?,
                    };
                    client=Some(clients::DrainClient::connect(&root,command["leaf"].as_str().ok_or_else(refused)?,pins,
                        std::sync::Arc::new(castle_wall_daemon::business_profile::signer_watchdog::boottime_ns),Box::new(ClientHooks)).map_err(|_|refused())?);
                    Ok(serde_json::json!({"ok":true}))
                }
                "client-read" => {
                    client.as_mut().ok_or_else(refused)?.read(command["id"].as_str().ok_or_else(refused)?,u64::MAX).map_err(|_|refused())?;
                    Ok(serde_json::json!({"ok":true}))
                }
                "client-mutation" => {
                    let proposal=clients::FrozenMutation::checked(hex::decode(command["hex"].as_str().ok_or_else(refused)?).map_err(|_|refused())?).map_err(|_|refused())?;
                    client.as_mut().ok_or_else(refused)?.mutation(&proposal,u64::MAX).map_err(|_|refused())?;
                    Ok(serde_json::json!({"ok":true}))
                }
                "client-original" => {
                    let bytes=hex::decode(command["hex"].as_str().ok_or_else(refused)?).map_err(|_|refused())?;
                    client.as_mut().ok_or_else(refused)?.original(command["id"].as_str().ok_or_else(refused)?,&bytes,u64::MAX).map_err(|_|refused())?;
                    Ok(serde_json::json!({"ok":true}))
                }
                "client-poll" => {
                    let c=client.as_mut().ok_or_else(refused)?;
                    let reply=c.poll().map_err(|_|refused())?;
                    let held=c.retained_mutation().is_some();
                    Ok(match reply {
                        None=>serde_json::json!({"kind":"pending","held":held}),
                        Some(clients::DrainReply::Read(o))=>serde_json::json!({"kind":"read","value":o.value(),"observed":o.observed(),"held":held}),
                        Some(clients::DrainReply::Acknowledged(a))=>serde_json::json!({"kind":"ack","value":a,"held":held}),
                        Some(clients::DrainReply::Released(f))=>serde_json::json!({"kind":"released","identity":f.identity(),"held":held}),
                        Some(clients::DrainReply::Refused)=>serde_json::json!({"kind":"refused","held":held}),
                    })
                }
                "connect" => {
                    socket = Some(signer_peer::connect(std::path::Path::new(
                        command["path"].as_str().ok_or_else(refused)?,
                    ))?);
                    Ok(serde_json::json!({"ok":true}))
                }
                "close" => {
                    client = None;
                    socket = None;
                    Ok(serde_json::json!({"ok":true}))
                }
                "send" => {
                    let fd = socket.as_ref().ok_or_else(refused)?.as_raw_fd();
                    let bytes = hex::decode(command["hex"].as_str().ok_or_else(refused)?)
                        .map_err(|_| refused())?;
                    signer_peer::send(fd, &bytes, &[])?;
                    Ok(serde_json::json!({"ok":true}))
                }
                "receive" => {
                    let fd = socket.as_ref().ok_or_else(refused)?.as_raw_fd();
                    let ms = command["ms"]
                        .as_u64()
                        .filter(|n| *n <= DRIVER_WAIT_MS)
                        .ok_or_else(refused)? as i32;
                    let mut p = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut p, 1, ms) } == 0 {
                        return Ok(serde_json::json!({"timeout":true}));
                    }
                    let packet = signer_peer::receive(fd, D_REQUEST_MAX_BYTES)?;
                    Ok(serde_json::json!({"hex":hex::encode(packet.bytes)}))
                }
                _ => Err(refused()),
            }
        })()
        .unwrap_or_else(|_| serde_json::json!({"closed":true}));
        // SAFETY: this feature-gated helper's explicit driver channel carries only isolated fixture packets.
        writeln!(stdout, "{result}")?;
        stdout.flush()?;
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    if execute().is_ok() {
        return;
    }
    std::process::exit(1);
}
