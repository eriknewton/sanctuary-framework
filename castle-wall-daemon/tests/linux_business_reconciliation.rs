// fail-before-exempt: New drain start and recovery paths run through the isolated native binary.
#![cfg(target_os = "linux")]
#[path = "support/drain_run.rs"]
mod drain_run;
mod isolation;
#[path = "support/writer_bus.rs"]
mod writer_bus;
use drain_run::*;
use std::{fs, os::unix::fs::symlink};
#[test]
fn start_without_wall_or_bus_and_restart_stale_socket() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    fs::remove_file(f.bus.root.path().join("bus")).unwrap();
    f.start();
    assert_eq!(f.read(true)["state"], "ABSENT");
    f.prepare();
    f.stop();
    assert!(f.socket().exists());
    f.start();
    assert_eq!(f.read(true)["state"], "PRESENT");
}
#[test]
fn second_instance_and_foreign_socket_entries_refuse() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    let mut other = Reaped(f.spawn());
    assert!(!f.notification().contains("READY=1"));
    assert!(!other.0.wait().unwrap().success());
    assert_eq!(f.read(true)["state"], "ABSENT");
    f.stop();
    fs::remove_file(f.socket()).unwrap();
    for symbolic in [false, true] {
        if symbolic {
            symlink("missing", f.socket()).unwrap();
        } else {
            fs::write(f.socket(), b"retained").unwrap();
        }
        let mut child = Reaped(f.spawn());
        assert!(!f.notification().contains("READY=1"));
        assert!(!child.0.wait().unwrap().success());
        fs::remove_file(f.socket()).unwrap();
    }
}

#[test]
fn latched_recovery_ready_without_bus_and_bad_state_refuses() {
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.prepare();
    let mut next = f.anchor.clone();
    next["recovery_required"] = serde_json::json!(true);
    next["recovery_reason"] = serde_json::json!("integrity");
    next["recovery_revision"] = serde_json::json!(1);
    let m = serde_json::json!({"version":1,"op":"LATCH","request_id":"d".repeat(32),"expected":f.anchor,"next":next});
    assert_eq!(
        f.request(true, &anchor_packet(&m, &[])).unwrap()["op"],
        "ANCHOR_ACK"
    );
    f.stop();
    fs::remove_file(f.bus.root.path().join("bus")).unwrap();
    f.child = Some(f.spawn());
    let ready = f.notification();
    assert!(ready.contains("READY=1"));
    assert!(ready.contains("latched=true"));
    assert_eq!(f.read(true)["latched"], true);
    f.stop();
    write_private(
        &f.root
            .join("state")
            .join(FORTRESS)
            .join("anchors")
            .join(format!("{SLOT}.json")),
        b"{}",
    );
    let mut child = Reaped(f.spawn());
    let status = f.notification();
    assert!(!status.contains("READY=1"));
    assert!(status.contains("refused at start"));
    assert!(!child.0.wait().unwrap().success());
}

#[test]
fn contending_start_cannot_unlink_an_unsettled_publication() {
    use serde_json::json;
    use std::{
        os::unix::fs::MetadataExt,
        time::{Duration, Instant},
    };
    let _guard = isolation::guard();
    let mut f = Fixture::new();
    f.start();
    f.fault("record", "FileSync", "hold", json!("lock"), 1);
    let mut next = f.anchor.clone();
    next["transaction_id"] = json!("d".repeat(32));
    let p = anchor_packet(
        &json!({"version":1,"op":"PREPARE","request_id":"d".repeat(32),"expected":null,"next":next}),
        &[],
    );
    let path = f.socket();
    f.s.connect(&path);
    f.s.send(&p);
    let end = Instant::now() + Duration::from_millis(WAIT_MS);
    while !f
        .events()
        .iter()
        .any(|v| v["event"] == "StepCompleted" && v["step"] == "Write")
    {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    let socket = fs::metadata(f.socket()).unwrap().ino();
    let staging = f
        .root
        .join("state")
        .join(FORTRESS)
        .join("anchors")
        .join(format!(".{SLOT}.json.staging"));
    let held = fs::metadata(&staging).unwrap().ino();
    let bytes = fs::read(&staging).unwrap();
    let mut other = Reaped(f.spawn());
    assert!(!f.notification().contains("READY=1"));
    assert!(!other.0.wait().unwrap().success());
    assert_eq!(fs::metadata(f.socket()).unwrap().ino(), socket);
    assert_eq!(fs::metadata(&staging).unwrap().ino(), held);
    assert_eq!(fs::read(&staging).unwrap(), bytes);
    write_private(&f.root.join("release-lock"), b"");
    assert!(f.s.receive(WAIT_MS).is_some());
}
