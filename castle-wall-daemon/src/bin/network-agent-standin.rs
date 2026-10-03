//! Finite network workload testimony. Independent wall, manager and sentinel
//! observations decide enforcement; this process only records its own attempts.

#[cfg(target_os = "linux")]
mod linux {
    use castle_wall_daemon::linux_install::contract::*;
    use ed25519_dalek::Signature;
    use rand_core::{OsRng, RngCore};
    use serde::{Deserialize, Serialize};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const ROLES: usize = ATTEMPTS_PER_ENDPOINT as usize; // Parent, child, grandchild.
    const NONCE_BYTES: usize = 32; // 256 bits from the OS RNG, one per logical attempt.
    const RESPONSE_BYTES: usize = NONCE_BYTES + ed25519_dalek::SIGNATURE_LENGTH;
    const COLLECTION_SLACK_MS: u64 = ATTEMPT_TIMEOUT_MS as u64 + 2_000; // One 3s attempt plus 2s pipe/reap allowance.
    const PROC_STAT_MAX_BYTES: u64 = 4 * KIB as u64; // One /proc stat row including the bounded comm field.
    const OBSERVATION: &str = "observations.json"; // Must match P2 evidence allow-list.

    fn bad(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn monotonic_ns() -> io::Result<u64> {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let ts = unsafe { ts.assume_init() };
        Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
    }
    fn sleep_until(ns: u64) -> io::Result<()> {
        let now = monotonic_ns()?;
        if ns > now {
            std::thread::sleep(Duration::from_nanos(ns - now));
        }
        Ok(())
    }
    fn wait_fd(fd: i32, events: i16, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ETIMEDOUT))?;
            let mut p = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let ms = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
            let n = unsafe { libc::poll(&mut p, 1, ms) };
            if n > 0 {
                return Ok(());
            }
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }
    fn option(fd: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&value as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn connect(stream: &TcpStream, address: SocketAddr, deadline: Instant) -> io::Result<()> {
        use nix::sys::socket::{connect as connect_raw, SockaddrIn, SockaddrIn6};
        let result = match address {
            SocketAddr::V4(v) => connect_raw(stream.as_raw_fd(), &SockaddrIn::from(v)),
            SocketAddr::V6(v) => connect_raw(stream.as_raw_fd(), &SockaddrIn6::from(v)),
        };
        match result {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::EINPROGRESS) => {
                wait_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
                match stream.take_error()? {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }
    fn tcp_socket(family: Family) -> io::Result<TcpStream> {
        let domain = if family == Family::Ipv4 {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        // Must match PMAX's substantiation inputs: one SYN retry, one absolute
        // user timeout, no Nagle accumulation and no lingering teardown retries.
        option(fd, libc::IPPROTO_TCP, libc::TCP_SYNCNT, 1)?;
        option(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
            ATTEMPT_TIMEOUT_MS as i32,
        )?;
        option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of_val(&linger) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }
    fn errno<T>(result: &io::Result<T>) -> i32 {
        result
            .as_ref()
            .err()
            .map(|e| e.raw_os_error().unwrap_or(libc::EIO))
            .unwrap_or(0)
    }
    fn authenticated(bytes: &[u8], nonce: &[u8; NONCE_BYTES], key: &str) -> bool {
        if bytes.len() != RESPONSE_BYTES || &bytes[..NONCE_BYTES] != nonce {
            return false;
        }
        let Ok(raw) = hex::decode(key) else {
            return false;
        };
        let Ok(key) = castle_wall_daemon::crypto::parse_strict_verifying_key(&raw) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&bytes[NONCE_BYTES..]) else {
            return false;
        };
        // The signature's subject is this attempt's unpredictable nonce, not a
        // reusable "success" string or a response from another connection.
        key.verify_strict(nonce, &signature).is_ok()
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Attempt {
        index: usize,
        worker: usize,
        pid: u32,
        phase: String,
        endpoint: Endpoint,
        nonce_hex: String,
        local_tuple: Option<String>,
        start_ns: u64,
        end_ns: u64,
        socket_errno: i32,
        connect_errno: Option<i32>,
        send_errno: Option<i32>,
        recv_errno: Option<i32>,
        sent_bytes: usize,
        received_bytes: usize,
        authenticated: bool,
    }
    fn attempt(index: usize, worker: usize, ep: &Endpoint) -> io::Result<Attempt> {
        let mut nonce = [0; NONCE_BYTES];
        OsRng.try_fill_bytes(&mut nonce).map_err(io::Error::other)?;
        let mut row = Attempt {
            index,
            worker,
            pid: std::process::id(),
            phase: "attempt".into(),
            endpoint: ep.clone(),
            nonce_hex: hex::encode(nonce),
            local_tuple: None,
            start_ns: monotonic_ns()?,
            end_ns: 0,
            socket_errno: 0,
            connect_errno: None,
            send_errno: None,
            recv_errno: None,
            sent_bytes: 0,
            received_bytes: 0,
            authenticated: false,
        };
        let deadline = Instant::now() + Duration::from_millis(ATTEMPT_TIMEOUT_MS.into());
        let address = SocketAddr::new(ep.ip.parse().map_err(|_| bad("IP literal"))?, ep.port);
        if ep.protocol == Protocol::Tcp {
            match tcp_socket(ep.family) {
                Err(e) => row.socket_errno = e.raw_os_error().unwrap_or(libc::EIO),
                Ok(mut stream) => {
                    let connected = connect(&stream, address, deadline);
                    row.connect_errno = Some(errno(&connected));
                    row.local_tuple = stream.local_addr().ok().map(|v| v.to_string());
                    if connected.is_ok() {
                        let sent = (|| {
                            while row.sent_bytes < nonce.len() {
                                wait_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
                                match stream.write(&nonce[row.sent_bytes..]) {
                                    Ok(0) => return Err(bad("zero write")),
                                    Ok(n) => row.sent_bytes += n,
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                    Err(e) => return Err(e),
                                }
                            }
                            Ok(())
                        })();
                        row.send_errno = Some(errno(&sent));
                        if sent.is_ok() {
                            let mut response = Vec::new();
                            let received = (|| {
                                loop {
                                    wait_fd(stream.as_raw_fd(), libc::POLLIN, deadline)?;
                                    let mut buf = [0; MAX_RESPONSE_BYTES as usize + 1];
                                    let remaining = buf.len() - response.len();
                                    match stream.read(&mut buf[..remaining]) {
                                        Ok(0) => break,
                                        Ok(n) => response.extend_from_slice(&buf[..n]),
                                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                        Err(e) => return Err(e),
                                    }
                                    // Oversize evidence is a failed attempt, never an unbounded read.
                                    if response.len() > MAX_RESPONSE_BYTES as usize {
                                        return Err(bad("response cap"));
                                    }
                                }
                                Ok(())
                            })();
                            row.recv_errno = Some(errno(&received));
                            row.received_bytes = response.len();
                            if received.is_ok() {
                                row.authenticated = ep
                                    .response_public_key_hex
                                    .as_deref()
                                    .is_some_and(|key| authenticated(&response, &nonce, key));
                            }
                        }
                    }
                }
            }
        } else {
            let bind = if ep.family == Family::Ipv4 {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            match UdpSocket::bind(bind) {
                Err(e) => row.socket_errno = e.raw_os_error().unwrap_or(libc::EIO),
                Ok(socket) => {
                    socket.set_nonblocking(true)?;
                    let connected = socket.connect(address);
                    row.connect_errno = Some(errno(&connected));
                    let sent = connected.and_then(|()| socket.send(&nonce));
                    row.send_errno = Some(errno(&sent));
                    row.sent_bytes = sent.unwrap_or(0);
                    row.local_tuple = socket.local_addr().ok().map(|v| v.to_string());
                    if row.sent_bytes > 0 {
                        let received = (|| {
                            wait_fd(socket.as_raw_fd(), libc::POLLIN, deadline)?;
                            let mut buf = [0; MAX_RESPONSE_BYTES as usize + 1];
                            let (n, _) = socket.recv_from(&mut buf)?;
                            if n > MAX_RESPONSE_BYTES as usize {
                                return Err(bad("UDP response exceeds quota"));
                            }
                            Ok(n)
                        })();
                        row.recv_errno = Some(errno(&received));
                        row.received_bytes = received.unwrap_or(0);
                    }
                }
            }
        }
        row.end_ns = monotonic_ns()?;
        Ok(row)
    }
    fn collect(child: &mut Child, deadline: Instant) -> io::Result<Vec<Attempt>> {
        let mut pipe = child
            .stdout
            .take()
            .ok_or_else(|| bad("worker stdout missing"))?;
        let fd = pipe.as_raw_fd();
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = Vec::new();
        loop {
            wait_fd(fd, libc::POLLIN, deadline)?;
            let mut buf = [0; KIB];
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
            if bytes.len() > OBSERVATION_MAX_BYTES {
                return Err(bad("worker observation cap"));
            }
        }
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
    fn idle() -> ! {
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    fn worker(role: usize, start_ns: u64, leader: u32) -> io::Result<()> {
        let schedule = castle_wall_daemon::agent_launch::installed_endpoints()?;
        let mut child = if role + 1 < ROLES {
            Some(
                Command::new("/proc/self/exe")
                    .args([
                        "--worker",
                        &(role + 1).to_string(),
                        &start_ns.to_string(),
                        &leader.to_string(),
                    ])
                    .env_clear()
                    .env("HOME", WORKSPACE_PATH)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()?,
            )
        } else {
            None
        };
        if role + 1 == ROLES {
            // The predeclared leaf remains after SIGTERM; unit cgroup SIGKILL
            // must bound stop even when the finite workload has already idled.
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
        }
        let mut rows = Vec::new();
        for (endpoint, ep) in schedule.endpoints.iter().enumerate() {
            let index = endpoint * ROLES + role;
            let slot_ms =
                u64::from(INITIAL_DELAY_MS) + index as u64 * u64::from(ATTEMPT_TIMEOUT_MS);
            sleep_until(start_ns + slot_ms * 1_000_000)?;
            rows.push(attempt(index, role, ep)?);
        }
        let end_ns = start_ns
            + (u64::from(INITIAL_DELAY_MS)
                + ATTEMPTS_PER_ACTIVATION as u64 * u64::from(ATTEMPT_TIMEOUT_MS)
                + COLLECTION_SLACK_MS)
                * 1_000_000;
        if let Some(child) = child.as_mut() {
            let remaining = end_ns.saturating_sub(monotonic_ns()?);
            rows.extend(collect(
                child,
                Instant::now() + Duration::from_nanos(remaining),
            )?);
        }
        if role != 0 {
            let encoded = serde_json::to_vec(&rows).map_err(io::Error::other)?;
            if encoded.len() > OBSERVATION_MAX_BYTES {
                return Err(bad("worker record quota"));
            }
            io::stdout().write_all(&encoded)?;
            io::stdout().flush()?;
            unsafe {
                libc::close(libc::STDOUT_FILENO);
            }
            idle();
        }
        rows.sort_by_key(|r| r.index);
        if rows.len() != ATTEMPTS_PER_ACTIVATION
            || rows
                .iter()
                .enumerate()
                .any(|(i, r)| r.index != i || r.worker != i % ROLES)
        {
            return Err(bad("incomplete schedule"));
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let ticks = stat
            .rsplit_once(')')
            .and_then(|(_, s)| s.split_whitespace().nth(22 - 3) /* starttime is field 22; suffix begins at field 3. */)
            .ok_or_else(|| bad("start ticks"))?;
        let record = serde_json::json!({"version":VERSION,"phase":"idle","boot_id":boot.trim(),
            "invocation":{"leader_pid":leader,"start_ticks":ticks,"start_monotonic_ns":start_ns},
            "attempt_count":rows.len(),"planned_wal_max_bytes":PLANNED_WAL_MAX_BYTES,
            "pmax":PMAX,"emax":EMAX,"cmax":CMAX,"attempts":rows});
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() > OBSERVATION_MAX_BYTES {
            return Err(bad("observation quota"));
        }
        // A unique create-new inode prevents workspace symlinks from redirecting
        // output; rename publishes one complete bounded record, never a prefix.
        let temp = format!("{WORKSPACE_PATH}/.observation-{leader}-{start_ns}.tmp");
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600) // Owner read/write only; the root evidence reader remains able to inspect it.
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, format!("{WORKSPACE_PATH}/{OBSERVATION}"))?;
            File::open(WORKSPACE_PATH)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result?;
        idle()
    }
    fn validate_worker_lineage(role: usize, start: u64, leader: u32) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let parent = unsafe { libc::getppid() } as u32;
        let now = monotonic_ns()?;
        // Internal worker argv is not a public shortened-schedule mode. Only
        // this executable's live predeclared parent/child chain may select it.
        if leader == 0
            || start > now
            || now - start > u64::from(INITIAL_DELAY_MS) * 1_000_000
            || (role == 1 && parent != leader)
            || (role == 2 && parent == leader)
        {
            return Err(bad("worker lineage or epoch"));
        }
        let own = std::fs::metadata("/proc/self/exe")?;
        let ancestor = std::fs::metadata(format!("/proc/{parent}/exe"))?;
        if own.dev() != ancestor.dev() || own.ino() != ancestor.ino() {
            return Err(bad("worker parent executable"));
        }
        if role == 2 {
            let mut text = String::new();
            File::open(format!("/proc/{parent}/stat"))?
                .take(PROC_STAT_MAX_BYTES + 1)
                .read_to_string(&mut text)?;
            if text.len() as u64 > PROC_STAT_MAX_BYTES {
                return Err(bad("worker parent status cap"));
            }
            // After comm (field 2), state is field 3 and ppid is field 4.
            let grandparent = text
                .rsplit_once(')')
                .and_then(|(_, s)| s.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u32>().ok());
            if grandparent != Some(leader) {
                return Err(bad("worker grandparent"));
            }
        }
        Ok(())
    }

    fn instrument_endpoints(path: &str, purpose: EndpointPurpose) -> io::Result<EndpointsV1> {
        // The ordinary-operator control runs before provisioning. Its supplied
        // file is bounded input testimony, never Configured or launch authority.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file() || before.len() > ENDPOINTS_MAX_BYTES as u64 {
            return Err(bad("control endpoint file type or size"));
        }
        let bytes = instrument_snapshot(file, before, path)?;
        EndpointsV1::parse_for(&bytes, purpose).map_err(io::Error::other)
    }

    fn instrument_snapshot(
        mut file: File,
        before: std::fs::Metadata,
        path: &str,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        (&mut file)
            .take(ENDPOINTS_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > ENDPOINTS_MAX_BYTES
            || bytes.len() as u64 != before.len()
            || !castle_wall_daemon::agent_launch::same_file(&before, &file.metadata()?)
            || !castle_wall_daemon::agent_launch::same_file(
                &before,
                &std::fs::symlink_metadata(path)?,
            )
        {
            return Err(bad("control endpoints changed during read"));
        }
        Ok(bytes)
    }

    fn control_endpoints(path: &str) -> io::Result<EndpointsV1> {
        instrument_endpoints(path, EndpointPurpose::Product)
    }

    fn control(path: &str) -> io::Result<()> {
        let schedule = control_endpoints(path)?;
        let start = monotonic_ns()?;
        let mut rows = Vec::with_capacity(ENDPOINT_COUNT);
        // One ordinary-operator attempt per declared endpoint, immediately and
        // without descendants. This six-attempt control exits; it is never an
        // alternate product schedule or a retry allowance for missing evidence.
        for (index, endpoint) in schedule.endpoints.iter().enumerate() {
            let mut row = attempt(index, 0, endpoint)?;
            row.phase = "control".into();
            rows.push(row);
        }
        let record = serde_json::json!({"version":VERSION,"phase":"control-complete",
            "boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "pid":std::process::id(),"uid":unsafe {libc::geteuid()},
            "start_monotonic_ns":start,"end_monotonic_ns":monotonic_ns()?,
            "attempt_count":rows.len(),"attempts":rows});
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() + 1 > OBSERVATION_MAX_BYTES {
            return Err(bad("control observation quota"));
        }
        // Before install there is no workspace; stdout carries bounded testimony
        // for the operator to join with independent sentinel receipts.
        io::stdout().write_all(&bytes)?;
        io::stdout().write_all(b"\n")
    }

    fn fault_probe(path: &str) -> io::Result<()> {
        let schedule = instrument_endpoints(path, EndpointPurpose::FaultInstrument)?;
        // The separate instrument consumes exactly one denied IPv4 TCP attempt;
        // reduced schedules never authorize a product activation or retries.
        if schedule
            .endpoints
            .iter()
            .enumerate()
            .any(|(index, endpoint)| endpoint.attempts != u8::from(index == 0))
        {
            return Err(bad(
                "fault probe requires exactly one IPv4 denied TCP attempt",
            ));
        }
        let start = monotonic_ns()?;
        let mut row = attempt(0, 0, &schedule.endpoints[0])?;
        row.phase = "fault-probe".into();
        let record = serde_json::json!({"version":VERSION,"phase":"fault-probe-complete",
            "boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "pid":std::process::id(),"uid":unsafe {libc::geteuid()},
            "start_ticks":std::fs::read_to_string("/proc/self/stat")?.rsplit_once(')').and_then(|(_, tail)| tail.split_whitespace().nth(22 - 3) /* starttime is field 22; suffix begins at field 3. */).ok_or_else(|| bad("start ticks"))?,
            "start_monotonic_ns":start,"end_monotonic_ns":monotonic_ns()?,
            "attempt_count":1,"attempts":[row]});
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() + 1 > OBSERVATION_MAX_BYTES {
            return Err(bad("fault observation quota"));
        }
        io::stdout().write_all(&bytes)?;
        io::stdout().write_all(b"\n")
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["--control", "--endpoints", path] => control(path),
            ["--fault-probe", "--endpoints", path] => fault_probe(path),
            ["--endpoints", ENDPOINTS_PATH] => worker(0, monotonic_ns()?, std::process::id()),
            ["--worker", role, start, leader] => {
                let role: usize = role.parse().map_err(|_| bad("worker role"))?;
                if !(1..ROLES).contains(&role) {
                    return Err(bad("worker role"));
                }
                let start = start.parse().map_err(|_| bad("worker epoch"))?;
                let leader = leader.parse().map_err(|_| bad("worker leader"))?;
                validate_worker_lineage(role, start, leader)?;
                worker(role, start, leader)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unknown or invalid argument: {}",
                    args.first().map(String::as_str).unwrap_or("<missing>")
                ),
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::{Signer, SigningKey};
        #[test]
        fn response_is_exact_capped_and_nonce_bound() {
            let signing = SigningKey::from_bytes(&[7; 32]);
            let nonce = [9; NONCE_BYTES];
            let key = hex::encode(signing.verifying_key().as_bytes());
            let mut response = nonce.to_vec();
            response.extend_from_slice(&signing.sign(&nonce).to_bytes());
            assert!(authenticated(&response, &nonce, &key));
            assert!(!authenticated(&response, &[8; NONCE_BYTES], &key));
            for n in [0, NONCE_BYTES, RESPONSE_BYTES - 1] {
                assert!(!authenticated(&response[..n], &nonce, &key));
            }
            response.push(0);
            assert!(!authenticated(&response, &nonce, &key));
            response.pop();
            response[NONCE_BYTES] ^= 1;
            assert!(!authenticated(&response, &nonce, &key));
        }
        #[test]
        fn finite_roles_partition_all_eighteen_slots_once() {
            let mut slots: Vec<_> = (0..ROLES)
                .flat_map(|r| (0..ENDPOINT_COUNT).map(move |e| e * ROLES + r))
                .collect();
            slots.sort();
            assert_eq!(slots, (0..ATTEMPTS_PER_ACTIVATION).collect::<Vec<_>>());
            assert!(RESPONSE_BYTES <= MAX_RESPONSE_BYTES as usize);
            assert_eq!(PLANNED_WAL_MAX_BYTES, 71_303_168);
        }
        #[test]
        fn actual_socket_settings_bound_retries_and_teardown() {
            let stream = tcp_socket(Family::Ipv4).unwrap();
            for (name, want) in [
                (libc::TCP_SYNCNT, 1),
                (libc::TCP_USER_TIMEOUT, ATTEMPT_TIMEOUT_MS as i32),
                (libc::TCP_NODELAY, 1),
            ] {
                let mut value = 0i32;
                let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            stream.as_raw_fd(),
                            libc::IPPROTO_TCP,
                            name,
                            (&mut value as *mut i32).cast(),
                            &mut len,
                        )
                    },
                    0
                );
                assert_eq!(value, want);
            }
            let mut linger = std::mem::MaybeUninit::<libc::linger>::uninit();
            let mut len = std::mem::size_of::<libc::linger>() as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        linger.as_mut_ptr().cast(),
                        &mut len,
                    )
                },
                0
            );
            let linger = unsafe { linger.assume_init() };
            assert_eq!((linger.l_onoff, linger.l_linger), (1, 0));
            assert_ne!(
                unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
                0
            );
            assert_ne!(
                unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        fn response_fixture(dribble: bool) -> (Attempt, Duration) {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut nonce = [0; NONCE_BYTES];
                stream.read_exact(&mut nonce).unwrap();
                if dribble {
                    // A peer keeps making progress beyond the one attempt deadline;
                    // partial reads may not restart a fresh three-second budget.
                    for _ in 0..40 {
                        if stream.write_all(b"x").is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                } else {
                    let _ = stream.write_all(&[0; MAX_RESPONSE_BYTES as usize + 1]);
                }
            });
            let ep = Endpoint {
                family: Family::Ipv4,
                role: Role::Allow,
                protocol: Protocol::Tcp,
                ip: address.ip().to_string(),
                port: address.port(),
                attempts: ATTEMPTS_PER_ENDPOINT,
                response_public_key_hex: Some(hex::encode(
                    SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes(),
                )),
            };
            let start = Instant::now();
            let row = attempt(0, 0, &ep).unwrap();
            let elapsed = start.elapsed();
            server.join().unwrap();
            (row, elapsed)
        }
        #[test]
        fn oversized_udp_response_is_not_complete() {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let address = socket.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let mut nonce = [0; NONCE_BYTES];
                let (_, peer) = socket.recv_from(&mut nonce).unwrap();
                socket
                    .send_to(&[0; MAX_RESPONSE_BYTES as usize + 1], peer)
                    .unwrap();
            });
            let ep = Endpoint {
                family: Family::Ipv4,
                role: Role::Deny,
                protocol: Protocol::Udp,
                ip: address.ip().to_string(),
                port: address.port(),
                attempts: ATTEMPTS_PER_ENDPOINT,
                response_public_key_hex: None,
            };
            let row = attempt(0, 0, &ep).unwrap();
            server.join().unwrap();
            assert_eq!(row.recv_errno, Some(libc::EIO));
            assert_eq!(row.received_bytes, 0);
        }
        #[test]
        fn control_snapshot_refuses_same_inode_rewrites_and_growth() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("input");
            for changed in [b"bbbb".as_slice(), b"longer".as_slice()] {
                std::fs::write(&path, b"aaaa").unwrap();
                let file = File::open(&path).unwrap();
                let before = file.metadata().unwrap();
                std::thread::sleep(Duration::from_millis(1));
                std::fs::write(&path, changed).unwrap();
                assert!(instrument_snapshot(file, before, path.to_str().unwrap()).is_err());
            }
        }
        #[test]
        fn oversized_response_is_bounded_and_is_not_complete() {
            let (row, _) = response_fixture(false);
            assert_eq!(row.received_bytes, MAX_RESPONSE_BYTES as usize + 1);
            assert_eq!(row.recv_errno, Some(libc::EIO));
            assert!(!row.authenticated);
        }
        #[test]
        fn partial_reads_share_one_absolute_deadline() {
            let (row, elapsed) = response_fixture(true);
            assert_eq!(row.recv_errno, Some(libc::ETIMEDOUT));
            assert!(!row.authenticated);
            assert!(elapsed < Duration::from_millis(u64::from(ATTEMPT_TIMEOUT_MS) + 500));
            // Scheduling tolerance, not a second network budget.
        }
        #[test]
        fn control_input_is_regular_bounded_and_not_symlinked() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("endpoints.json");
            let key = hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
            let endpoints: Vec<_> = ENDPOINT_ORDER.iter().map(|(family, role, protocol)| serde_json::json!({
                "family":family,"role":role,"protocol":protocol,
                "ip":if *family==Family::Ipv4 {"127.0.0.1"}else{"::1"},
                "port":if *role==Role::Allow {41003}else if *protocol==Protocol::Tcp {41001}else{41002},
                "attempts":ATTEMPTS_PER_ENDPOINT,
                "response_public_key_hex":if *role==Role::Allow {Some(&key)}else{None}
            })).collect();
            let bytes = serde_json::to_vec(&serde_json::json!({"version":VERSION,
                "initial_delay_ms":INITIAL_DELAY_MS,"attempt_timeout_ms":ATTEMPT_TIMEOUT_MS,
                "max_response_bytes":MAX_RESPONSE_BYTES,"endpoints":endpoints}))
            .unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(control_endpoints(path.to_str().unwrap()).is_ok());
            let alias = dir.path().join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(control_endpoints(alias.to_str().unwrap()).is_err());
            std::fs::write(&path, vec![b' '; ENDPOINTS_MAX_BYTES + 1]).unwrap();
            assert_eq!(
                control_endpoints(path.to_str().unwrap())
                    .unwrap_err()
                    .to_string(),
                "control endpoint file type or size"
            );
            assert_eq!(
                control_endpoints("/dev/null").unwrap_err().to_string(),
                "control endpoint file type or size"
            );
        }
        #[test]
        fn worker_arguments_require_the_live_executable_lineage() {
            assert!(validate_worker_lineage(1, 0, 1).is_err());
            assert!(validate_worker_lineage(1, u64::MAX, 1).is_err());
            assert!(validate_worker_lineage(
                1,
                monotonic_ns().unwrap(),
                unsafe { libc::getppid() } as u32
            )
            .is_err());
        }
    }
}
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match linux::run() {
        Ok(()) => return std::process::ExitCode::SUCCESS,
        Err(error) => {
            // SAFETY: launch errors use the stand-in's operator-visible stderr channel.
            eprintln!("network-agent-standin: {error}");
        }
    }
    std::process::ExitCode::FAILURE
}
