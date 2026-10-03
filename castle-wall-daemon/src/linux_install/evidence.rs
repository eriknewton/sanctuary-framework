//! Bounded public evidence; no private keys, WAL recovery, truncation, or ACK.
use super::{
    command,
    contract::*,
    transaction::{checked, run_bounded, sha256, Root, Transaction},
    Result,
};
use crate::audit::{validate_wal_line, WalValidationState};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const WAL_MAX: usize = crate::constants::DEFAULT_WAL_SIZE_CAP_BYTES as usize;
const PUBLIC_MAX: usize = crate::manifest::store::MAX_PUBLISH_BUNDLE_BYTES;

/// Validate exactly the on-disk writer encoding, including a retained ACK anchor.
/// Uses the writer's read-only validator; this path never opens WalWriter.
pub fn verify_wal(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') || bytes.len() > WAL_MAX {
        return Err("WAL prefix is empty, incomplete, or oversized".into());
    }
    let mut state = WalValidationState::default();
    let mut count = 0;
    for (index, line) in bytes[..bytes.len() - 1].split(|b| *b == b'\n').enumerate() {
        validate_wal_line(std::str::from_utf8(line)?, index as u64 + 1, &mut state)?;
        count += 1;
    }
    Ok(count)
}
fn wal_prefix(root: &Root, path: &str) -> Result<(Vec<u8>, Value)> {
    let mut file = root.file(path)?;
    let before = file.metadata()?;
    if before.len() > WAL_MAX as u64 {
        return Err("WAL exceeds daemon quota".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(before.len()).read_to_end(&mut bytes)?;
    // Only complete rows belong to a captured prefix; a concurrent append may finish afterward.
    let complete = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .ok_or("no complete WAL prefix")?
        + 1;
    bytes.truncate(complete);
    let rows = verify_wal(&bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let mut again = Vec::new();
    (&mut file).take(complete as u64).read_to_end(&mut again)?;
    let after = root.file(path)?.metadata()?;
    if bytes != again
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.len() < before.len()
    {
        return Err("WAL prefix changed or inode replaced".into());
    }
    Ok((
        bytes,
        json!({"inode":before.ino(),"device":before.dev(),"rows":rows,"captured_bytes":complete,"observed_bytes_before":before.len(),"observed_bytes_after":after.len(),"remaining_bytes":(WAL_MAX as u64).saturating_sub(after.len()),"reserved_control_bytes":crate::audit::WAL_CONTROL_HEADROOM_MAX_BYTES}),
    ))
}
fn observation(t: &Transaction) -> Result<(Vec<u8>, Value)> {
    // Must match OBSERVATION in src/bin/network-agent-standin.rs.
    let path = format!("{WORKSPACE_PATH}/observations.json");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let before = file.metadata()?;
    // Workload testimony is intentionally U-owned, never mistaken for root authority.
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != t.agent_uid
        || before.len() > OBSERVATION_MAX_BYTES as u64
    {
        return Err("stand-in observation custody or quota".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(OBSERVATION_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    if bytes.len() != before.len() as usize
        || after.len() != before.len()
        || !unchanged_observation(&before, &after, &current)
    {
        return Err("stand-in observation changed".into());
    }
    Ok((
        bytes,
        json!({"inode":before.ino(),"device":before.dev(),"owner":before.uid(),"authority":"workload testimony only"}),
    ))
}
fn unchanged_observation(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    current: &std::fs::Metadata,
) -> bool {
    // U can restore mtime after rewriting testimony; ctime must agree across the opened-file snapshot too.
    before.mtime_nsec() == after.mtime_nsec()
        && before.mtime() == after.mtime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.ctime() == after.ctime()
        && current.ino() == before.ino()
        && current.dev() == before.dev()
        && current.ctime_nsec() == after.ctime_nsec()
        && current.ctime() == after.ctime()
}

/// Export only enumerated public files and finite observations into a new empty directory.
pub fn capture(root: &Root, t: &Transaction, output: &Path) -> Result<Value> {
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    let output_text = absolute
        .to_str()
        .ok_or("output path")?
        .trim_start_matches('/');
    let dest = root.output(output_text, super::account::operator_uid()?)?;
    let mut files = Vec::new();
    let mut missing = Vec::new();
    let dir = format!("var/lib/sanctuary/{}/policy/egress", t.fortress_id);
    let public = [
        (
            COMMAND_PATH.trim_start_matches('/').into(),
            "command-v1.json",
        ),
        (
            ENDPOINTS_PATH.trim_start_matches('/').into(),
            "endpoints.json",
        ),
        (
            CONFIGURED_PATH.trim_start_matches('/').into(),
            "configured-v1.json",
        ),
        (ENV_PATH.trim_start_matches('/').into(), "castle-wall.env"),
        (command::BUILD_IDENTITY.into(), "build-identity"),
        (format!("{dir}/manifest.json"), "manifest.json"),
        (format!("{dir}/pinned.key"), "pinned.key"),
        (
            format!("{dir}/.manifest-high-water.json"),
            "manifest-high-water.json",
        ),
    ];
    for (source, name) in public {
        match root.read(&source, PUBLIC_MAX) {
            Ok(bytes) => {
                dest.write(name, &bytes, 0o600)?;
                files.push(json!({"name":name,"bytes":bytes.len(),"sha256":sha256(&bytes)}));
            }
            Err(_) => missing.push(name.to_owned()),
        }
    }
    // Signed rule names are admitted by the existing manifest identity preflight before any file read.
    if let Ok(raw) = root.read(&format!("{dir}/manifest.json"), PUBLIC_MAX) {
        let signed: crate::manifest::verify::SignedManifest = serde_json::from_slice(&raw)?;
        if !crate::manifest::rule_identity::preflight_manifest_rule_entries(&signed.manifest.rules)
            .is_empty()
        {
            return Err("evidence rule identity refused".into());
        }
        dest.mkdir("rules", 0o700)?;
        let mut total = 0;
        for rule in signed.manifest.rules {
            let bytes = root.read(&format!("{dir}/rules/{}", rule.file), PUBLIC_MAX)?;
            total += bytes.len();
            if total > PUBLIC_MAX {
                return Err("evidence rule quota".into());
            }
            dest.write(&format!("rules/{}", rule.file), &bytes, 0o600)?;
        }
    }
    match root.read(
        "var/lib/sanctuary/nft-ownership.json",
        crate::ownership_journal::MAX_ENVELOPE_BYTES as usize,
    ) {
        Ok(envelope) => {
            use base64::Engine;
            let raw: Value = serde_json::from_slice(&envelope)?;
            let decoded = base64::engine::general_purpose::STANDARD.decode(
                raw["record_b64"]
                    .as_str()
                    .ok_or("ownership record missing")?,
            )?;
            if decoded.len() > crate::ownership_journal::MAX_RECORD_BYTES {
                return Err("ownership public record quota".into());
            }
            let record: crate::ownership_journal::OwnershipJournal =
                serde_json::from_slice(&decoded)?;
            dest.write("ownership-public.json",&serde_json::to_vec(&json!({"record":record,"envelope_sha256":sha256(&envelope),"authentication":"not independently verified; root-custodied observation"}))?,0o600)?;
        }
        Err(_) => missing.push("public ownership history".into()),
    }
    let before = command::properties(&command::instance(t))?;
    let workload_before = workload_identity(root, &before);
    if workload_before.is_err() {
        missing.push("workload identity before capture".into());
    }
    let wal = match wal_prefix(
        root,
        &format!("var/lib/sanctuary/{}/filter-events.wal", t.fortress_id),
    ) {
        Ok((bytes, meta)) => {
            dest.write("filter-events.wal", &bytes, 0o600)?;
            files.push(json!({"name":"filter-events.wal","sha256":sha256(&bytes)}));
            meta
        }
        Err(_) => {
            missing.push("complete WAL prefix".into());
            Value::Null
        }
    };
    let record = match observation(t).and_then(|(bytes, meta)| {
        let record: Value = serde_json::from_slice(&bytes)?;
        Ok((bytes, meta, record))
    }) {
        Ok((bytes, meta, record)) => {
            let current_boot = checked("/usr/bin/cat", &["/proc/sys/kernel/random/boot_id"])?;
            let matches = workload_before.as_ref().is_ok_and(|(pid, ticks, _)| {
                record["invocation"]["leader_pid"].as_u64() == Some(u64::from(*pid))
                    && record["invocation"]["start_ticks"].as_str()
                        == Some(ticks.to_string().as_str())
            });
            if !matches
                || record["boot_id"].as_str() != Some(std::str::from_utf8(&current_boot)?.trim())
            {
                missing.push("stand-in activation identity".into());
            }
            dest.write("observations.json", &bytes, 0o600)?;
            files.push(json!({"name":"observations.json","sha256":sha256(&bytes)}));
            meta
        }
        Err(_) => {
            missing.push("stand-in observation".into());
            Value::Null
        }
    };
    for (name, program, args) in [
        (
            "nft.json",
            "/usr/sbin/nft",
            vec!["-j", "-a", "list", "ruleset"],
        ),
        ("mountinfo", "/usr/bin/cat", vec!["/proc/self/mountinfo"]),
        (
            "boot-id",
            "/usr/bin/cat",
            vec!["/proc/sys/kernel/random/boot_id"],
        ),
    ] {
        match checked(program, &args) {
            Ok(bytes) => dest.write(name, &bytes, 0o600)?,
            Err(_) => missing.push(name.into()),
        }
    }
    let after = command::properties(&command::instance(t))?;
    let workload_after = workload_identity(root, &after);
    if workload_before.as_ref().ok() != workload_after.as_ref().ok() || workload_after.is_err() {
        missing.push("stable workload PID/start ticks/executable".into());
    }
    if before.get("MainPID") != after.get("MainPID")
        || before.get("InvocationID") != after.get("InvocationID")
    {
        missing.push("stable workload identity".into());
    }
    if let Some(pid) = before
        .get("MainPID")
        .filter(|p| p.parse::<u32>().is_ok_and(|n| n > 0))
    {
        for suffix in ["stat", "status", "cgroup"] {
            match checked("/usr/bin/cat", &[&format!("/proc/{pid}/{suffix}")]) {
                Ok(bytes) => dest.write(&format!("process-{suffix}"), &bytes, 0o600)?,
                Err(_) => missing.push(format!("process-{suffix}")),
            }
        }
    } else {
        missing.push("live workload identity".into());
    }
    for (name, unit) in [
        ("wall.service", command::WALL),
        ("agent.service", "sanctuary-agent@.service"),
        ("workspace.mount", WORKSPACE_MOUNT_UNIT),
    ] {
        match root.read(&format!("etc/systemd/system/{unit}"), PUBLIC_MAX) {
            Ok(bytes) => dest.write(name, &bytes, 0o600)?,
            Err(_) => missing.push(name.into()),
        }
    }
    let agent_unit = command::instance(t);
    // One boot's unit journal is finite and separately capped at the frozen lifecycle/control byte allowance.
    match run_bounded(
        "/usr/bin/journalctl",
        &[
            "--boot",
            "--unit",
            command::WALL,
            "--unit",
            &agent_unit,
            "--output=json",
            "--no-pager",
        ],
        std::time::Duration::from_secs(10), // Fixed 10-second evidence latency ceiling; expiry records incomplete.
        CMAX,
    ) {
        Ok(result) if result.code == Some(0) && !result.stdout.is_empty() => {
            dest.write("journal.jsonl", &result.stdout, 0o600)?
        }
        _ => missing.push("bounded unit journal".into()),
    }
    let status = command::status(root, t)?;
    if let Some(items) = status["missing_evidence"].as_array() {
        for item in items {
            if let Some(text) = item.as_str() {
                missing.push(format!("status: {text}"));
            }
        }
    }

    dest.write("status.json", &serde_json::to_vec(&status)?, 0o600)?;
    let report = json!({"version":VERSION,"observed_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),"complete":missing.is_empty(),"missing":missing,"files":files,"wal":wal,"workload_record":record,"manager_before":before,"manager_after":after});
    dest.write("evidence.json", &serde_json::to_vec(&report)?, 0o600)?;
    Ok(report)
}

fn workload_identity(
    root: &Root,
    unit: &std::collections::BTreeMap<String, String>,
) -> Result<(u32, u64, String)> {
    let pid: u32 = unit.get("MainPID").ok_or("no MainPID")?.parse()?;
    if pid == 0 {
        return Err("no live workload".into());
    }
    let command =
        CommandV1::parse(&root.read(COMMAND_PATH.trim_start_matches('/'), COMMAND_MAX_BYTES)?)?;
    let raw = checked("/usr/bin/cat", &[&format!("/proc/{pid}/stat")])?;
    let stat = std::str::from_utf8(&raw)?;
    let ticks = stat
        .rsplit_once(')')
        .ok_or("process stat")?
        .1
        .split_whitespace()
        .nth(22 - 3)
        .ok_or("start ticks")?
        .parse()?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    if exe != Path::new(&command.executable) {
        return Err("configured second exec missing".into());
    }
    Ok((pid, ticks, command.executable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn workload_metadata_changes_invalidate_the_observed_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observation");
        std::fs::write(&path, b"{}").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        assert!(unchanged_observation(&before, &before, &before));
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert!(!unchanged_observation(&before, &after, &after));
    }
}
