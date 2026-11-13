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
    let mut socket: Option<OwnedFd> = None;
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
                "connect" => {
                    socket = Some(signer_peer::connect(std::path::Path::new(
                        command["path"].as_str().ok_or_else(refused)?,
                    ))?);
                    Ok(serde_json::json!({"ok":true}))
                }
                "close" => {
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
