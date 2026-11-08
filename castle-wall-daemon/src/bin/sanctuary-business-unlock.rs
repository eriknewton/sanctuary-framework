//! The only ceremony sender opens its own controlling terminal and never reads it.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{custody::*, signer_contract::*, signer_peer::{self, Peer, PeerPolicy}, signer_service::{self, LENGTH_BYTES, RESPONSE_MAX_BYTES}, signer_watchdog::{boottime_ns,NS_PER_SECOND,WATCHDOG_TICK_MS}};
    use std::{os::{fd::AsRawFd,unix::fs::OpenOptionsExt},path::Path};
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[allow(unused_mut)] let mut socket_path = Path::new(CONTROL_ROOT).join(signer_service::LIFECYCLE_SOCKET);
    #[allow(unused_mut)] let mut policy_path = "/etc/sanctuary/business-signer-peer.json".to_string();
    #[allow(unused_mut)] let mut owner = ROOT_UID;
    #[allow(unused_mut)] let mut lock = args == ["lock"];
    #[cfg(feature="test-isolation")]
    if args.len() == 4 && args[0] == "--test-ceremony" {
        socket_path = args[1].clone().into(); policy_path = args[2].clone(); owner = unsafe {libc::geteuid()}; lock = args[3] == "lock";
    } else if !args.is_empty() && !lock {return Err(refused());}
    #[cfg(not(feature="test-isolation"))]
    if !args.is_empty() && !lock { return Err(refused()); }
    let bytes = read_pinned(Path::new(&policy_path), owner, CONFIG_MAX_BYTES, 0o644)?;
    let policy: PeerPolicy = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let socket = signer_peer::connect(&socket_path)?; let peer = Peer::capture(socket.as_raw_fd(),&policy)?;
    if lock { signer_peer::send(socket.as_raw_fd(),b"{\"op\":\"LOCK\"}",&[])?; }
    else {
        // No argument selects a terminal and no factor bytes ever enter the launcher.
        let tty = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/dev/tty")?;
        signer_peer::tty_check(tty.as_raw_fd(),unsafe {libc::getpid()})?;
        let frame = format!("{{\"op\":\"UNLOCK\",\"ttl\":{UNLOCK_TTL_MAX_SECONDS}}}");
        #[allow(unused_mut)] let mut rights = vec![tty.as_raw_fd()];
        #[cfg(feature="test-isolation")]
        let mut fixture_fds: Vec<std::os::fd::OwnedFd> = Vec::new();
        #[cfg(feature="test-isolation")]
        if args.len() == 4 {
            use std::os::fd::FromRawFd;
            match args[3].as_str() {
                "extra" => rights.push(tty.as_raw_fd()),
                "non-tty" => { let fd = std::fs::File::open("/dev/null")?; rights = vec![fd.as_raw_fd()]; fixture_fds.push(fd.into()); },
                "foreign" => {
                    let (mut master,mut slave)=(-1,-1);
                    if unsafe {libc::openpty(&mut master,&mut slave,std::ptr::null_mut(),std::ptr::null(),std::ptr::null())} != 0 {return Err(refused());}
                    fixture_fds.push(unsafe{std::os::fd::OwnedFd::from_raw_fd(master)});
                    fixture_fds.push(unsafe{std::os::fd::OwnedFd::from_raw_fd(slave)});rights=vec![slave];
                },
                _ => (),
            }
        }
        signer_peer::send(socket.as_raw_fd(),frame.as_bytes(),&rights)?;
    }
    let end = boottime_ns()? + (UNLOCKING_DEADLINE_SECONDS as u64 + 1) * NS_PER_SECOND;
    while !signer_service::readable(socket.as_raw_fd()) {
        if !peer.live() || boottime_ns()? >= end {return Err(refused());}
        std::thread::sleep(std::time::Duration::from_millis(WATCHDOG_TICK_MS as u64));
    }
    let packet = signer_peer::receive(socket.as_raw_fd(),RESPONSE_MAX_BYTES + LENGTH_BYTES)?;
    if !peer.matches(&packet.cred) || !packet.rights.is_empty() {return Err(refused());}
    let expected = signer_service::encode(&serde_json::json!({"op":if lock {"LOCKING"}else{"READY"}}),&[])?;
    if packet.bytes != expected {return Err(refused());} Ok(())
}
fn main() {
    #[cfg(target_os="linux")]
    if execute().is_ok() {return;}
    eprintln!("K1_REFUSED"); std::process::exit(1);
}
