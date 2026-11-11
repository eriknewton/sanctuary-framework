#![allow(dead_code)]
use castle_wall_daemon::business_profile::writer_peer::{
    self, BusTarget, UnitSnapshot, WriterConfig,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
pub const OWN: &str = ":1.77";
pub const OWNER: &str = ":1.88";
fn pad(v: &mut Vec<u8>, n: usize) {
    v.resize((v.len() + n - 1) & !(n - 1), 0);
}
pub fn string(v: &mut Vec<u8>, s: &str, g: bool) {
    if g {
        v.push(s.len() as u8)
    } else {
        pad(v, 4);
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    }
    v.extend_from_slice(s.as_bytes());
    v.push(0);
}
fn field(v: &mut Vec<u8>, code: u8, sig: &str, value: &str) {
    pad(v, 8);
    v.push(code);
    string(v, sig, true);
    string(v, value, sig == "g");
}
pub fn reply(serial: u32, sender: &str, sig: &str, body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut v = vec![0; 16];
    pad(&mut v, 8);
    v.push(5);
    string(&mut v, "u", true);
    pad(&mut v, 4);
    v.extend_from_slice(&serial.to_le_bytes());
    field(&mut v, 6, "s", OWN);
    field(&mut v, 7, "s", sender);
    field(&mut v, 8, "g", sig);
    let fields = v.len() - 16;
    pad(&mut v, 8);
    let start = v.len();
    body(&mut v);
    let len = v.len() - start;
    v[..4].copy_from_slice(&[b'l', 2, 0, 1]);
    v[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    v[8..12].copy_from_slice(&serial.to_le_bytes());
    v[12..16].copy_from_slice(&(fields as u32).to_le_bytes());
    v
}
fn array(v: &mut Vec<u8>, alignment: usize, body: impl FnOnce(&mut Vec<u8>)) {
    pad(v, 4);
    let at = v.len();
    v.extend_from_slice(&[0; 4]);
    pad(v, alignment);
    let start = v.len();
    body(v);
    let len = v.len() - start;
    v[at..at + 4].copy_from_slice(&(len as u32).to_le_bytes());
}
fn property(v: &mut Vec<u8>, name: &str, u: &UnitSnapshot) {
    let spec = writer_peer::PROPERTY_REGISTRY
        .iter()
        .find(|p| p.member == name)
        .unwrap();
    string(v, spec.signature, true);
    match name {
        "Id" => string(v, &u.id, false),
        "LoadState" => string(v, &u.load, false),
        "ActiveState" => string(v, &u.active, false),
        "SubState" => string(v, &u.sub, false),
        "FragmentPath" => string(v, &u.fragment, false),
        "ControlGroup" => string(v, &u.cgroup, false),
        "InvocationID" => array(v, 1, |v| v.extend_from_slice(&u.invocation)),
        "MainPID" => {
            pad(v, 4);
            v.extend_from_slice(&u.pid.to_le_bytes());
        }
        "DropInPaths" => array(v, 4, |v| {
            for path in &u.dropins {
                string(v, path, false);
            }
        }),
        "ExecStart" => array(v, 8, |v| {
            string(v, &u.exec, false);
            array(v, 4, |v| {
                for arg in &u.argv {
                    string(v, arg, false);
                }
            });
            pad(v, 4);
            v.extend_from_slice(&0u32.to_le_bytes());
            pad(v, 8);
            for _ in 0..4 {
                v.extend_from_slice(&0u64.to_le_bytes());
            }
            for _ in 0..3 {
                v.extend_from_slice(&0u32.to_le_bytes());
            }
        }),
        _ => panic!("unknown property"),
    }
}
#[derive(Clone, Default)]
pub struct Fault {
    pub pid_offset: u32,
    pub uid_offset: u32,
    pub signals: usize,
    pub invalid_signal: bool,
    pub trickle: bool,
    pub change_owner: bool,
    pub malformed: Option<String>,
    pub final_capture_change: bool,
}
pub struct Fixture {
    pub fault: Arc<Mutex<Fault>>,
    pub root: tempfile::TempDir,
    pub config: WriterConfig,
    pub unit: Arc<Mutex<UnitSnapshot>>,
    pub target: BusTarget,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Fixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let wall = root.path().join("wall");
        let fragment = root.path().join("wall.service");
        std::fs::write(&wall, b"installed wall artifact").unwrap();
        std::fs::write(&fragment, b"[Service]\nExecStart=/test/wall\n").unwrap();
        let argv = vec![
            wall.to_str().unwrap().to_owned(),
            "--fortress-id".into(),
            "fixture".into(),
        ];
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let pid = std::process::id();
        let cgroup =
            writer_peer::normalized_cgroup(&std::fs::read_to_string("/proc/self/cgroup").unwrap())
                .unwrap();
        let config:WriterConfig=serde_json::from_value(json!({"version":1,"wall_unit":"fixture.service","wall_exec":wall,"wall_sha256":hex::encode(Sha256::digest(std::fs::read(&wall).unwrap())),"wall_argv_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&argv).unwrap())),"wall_unit_sha256":hex::encode(Sha256::digest(std::fs::read(&fragment).unwrap())),"wall_dropins":[],"wall_gid":gid,"writer_socket_gid":gid,"writer_sha256":"0".repeat(64),"fortress_id":"fixture","enrollment_revision":1,"signer":{"uid":uid,"gid":gid,"executable_sha256":"0".repeat(64),"cgroup":format!("0::{cgroup}")}})).unwrap();
        let unit = Arc::new(Mutex::new(UnitSnapshot {
            owner: OWNER.into(),
            id: config.wall_unit.clone(),
            load: "loaded".into(),
            active: "active".into(),
            sub: "running".into(),
            invocation: vec![1; 16],
            fragment: fragment.to_str().unwrap().into(),
            dropins: vec![],
            cgroup,
            pid,
            exec: wall.to_str().unwrap().into(),
            argv,
        }));
        let path = root.path().join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = BusTarget::isolated(path, uid, pid, "fixture.service".into());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let shared = unit.clone();
        let fault = Arc::new(Mutex::new(Fault::default()));
        let faults = fault.clone();
        let thread = thread::spawn(move || {
            let mut connections = 0;
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        connections += 1;
                        if connections == 2 && faults.lock().unwrap().final_capture_change {
                            shared.lock().unwrap().invocation[0] ^= 1;
                        }
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap();
                        let _ = serve(&mut stream, &shared, &faults, uid, pid);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            root,
            config,
            unit,
            target,
            fault,
            stop,
            thread: Some(thread),
        }
    }
    pub fn config_path(&self) -> std::path::PathBuf {
        let path = self.root.path().join("config");
        let c = &self.config;
        let value = json!({"version":c.version,"wall_unit":c.wall_unit,"wall_exec":c.wall_exec,"wall_sha256":c.wall_sha256,"wall_argv_sha256":c.wall_argv_sha256,"wall_unit_sha256":c.wall_unit_sha256,"wall_dropins":[],"wall_gid":c.wall_gid,"writer_socket_gid":c.writer_socket_gid,"writer_sha256":c.writer_sha256,"fortress_id":c.fortress_id,"enrollment_revision":c.enrollment_revision,"signer":c.signer});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn line(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut v = vec![];
    while !v.ends_with(b"\r\n") {
        let mut b = [0];
        stream.read_exact(&mut b)?;
        v.push(b[0]);
        if v.len() > 512 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(v)
}
fn serve(
    stream: &mut UnixStream,
    unit: &Arc<Mutex<UnitSnapshot>>,
    faults: &Arc<Mutex<Fault>>,
    uid: u32,
    pid: u32,
) -> std::io::Result<()> {
    assert_eq!(
        line(stream)?,
        format!("\0AUTH EXTERNAL {}\r\n", hex::encode(uid.to_string())).as_bytes()
    );
    stream.write_all(b"OK 11111111111111111111111111111111\r\n")?;
    assert_eq!(line(stream)?, b"BEGIN\r\n");
    loop {
        let mut fixed = [0u8; 16];
        stream.read_exact(&mut fixed)?;
        let body = u32::from_le_bytes(fixed[4..8].try_into().unwrap()) as usize;
        let serial = u32::from_le_bytes(fixed[8..12].try_into().unwrap());
        let fields = u32::from_le_bytes(fixed[12..16].try_into().unwrap()) as usize;
        let size = ((16 + fields + 7) & !7) + body;
        assert!(size <= writer_peer::BUS_MESSAGE_MAX_BYTES);
        let mut bytes = fixed.to_vec();
        bytes.resize(size, 0);
        stream.read_exact(&mut bytes[16..])?;
        let (member, args) = writer_peer::test_support::decode_request(&bytes).unwrap();
        let u = unit.lock().unwrap().clone();
        let fault = faults.lock().unwrap().clone();
        let mut response = match member.as_str() {
            "Hello" => reply(serial, "org.freedesktop.DBus", "s", |v| {
                string(v, OWN, false)
            }),
            "GetNameOwner" => reply(serial, "org.freedesktop.DBus", "s", |v| {
                string(
                    v,
                    if fault.change_owner && serial > 3 {
                        ":1.89"
                    } else {
                        &u.owner
                    },
                    false,
                )
            }),
            "GetConnectionCredentials" => reply(serial, "org.freedesktop.DBus", "a{sv}", |v| {
                array(v, 8, |v| {
                    for (key, n) in [
                        ("UnixUserID", uid + fault.uid_offset),
                        ("ProcessID", pid + fault.pid_offset),
                    ] {
                        pad(v, 8);
                        string(v, key, false);
                        string(v, "u", true);
                        pad(v, 4);
                        v.extend_from_slice(&n.to_le_bytes());
                    }
                })
            }),
            "GetUnit" => reply(serial, OWNER, "o", |v| {
                string(v, "/org/freedesktop/systemd1/unit/fixture", false)
            }),
            "Get" => reply(serial, OWNER, "v", |v| property(v, &args[1], &u)),
            _ => panic!("unauthorized method {member}"),
        };
        if member == "Hello" {
            if let Some(case) = &fault.malformed {
                if case == "signature" {
                    response = reply(serial, "org.freedesktop.DBus", "u", |v| {
                        pad(v, 4);
                        v.extend_from_slice(&0u32.to_le_bytes());
                    });
                } else {
                    // Framing rejects these fields before reply identity or semantic acceptance.
                    let corpus: serde_json::Value =
                        serde_json::from_str(include_str!("../fixtures/writer_bus_replies.json"))
                            .unwrap();
                    let row = corpus["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["id"] == *case)
                        .unwrap();
                    response = hex::decode(row["packet_hex"].as_str().unwrap()).unwrap();
                }
            }
            for _ in 0..fault.signals {
                let mut signal = signal();
                if fault.invalid_signal {
                    signal[1] = 1;
                }
                stream.write_all(&signal)?;
            }
            if fault.trickle {
                for byte in &response {
                    stream.write_all(&[*byte])?;
                    thread::sleep(Duration::from_millis(10));
                }
                continue;
            }
        }
        stream.write_all(&response)?;
    }
}

fn signal() -> Vec<u8> {
    let mut v = vec![0; 16];
    field(&mut v, 1, "o", "/org/freedesktop/DBus");
    field(&mut v, 2, "s", "org.freedesktop.DBus");
    field(&mut v, 3, "s", "NameAcquired");
    field(&mut v, 7, "s", "org.freedesktop.DBus");
    field(&mut v, 8, "g", "s");
    let fields = v.len() - 16;
    pad(&mut v, 8);
    let start = v.len();
    string(&mut v, OWN, false);
    let body = v.len() - start;
    v[..4].copy_from_slice(&[b'l', 4, 0, 1]);
    v[4..8].copy_from_slice(&(body as u32).to_le_bytes());
    v[8..12].copy_from_slice(&1u32.to_le_bytes());
    v[12..16].copy_from_slice(&(fields as u32).to_le_bytes());
    v
}
