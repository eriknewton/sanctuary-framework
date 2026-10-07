//! The installed CLI: literal commands, exact request resumption, and manager observations.
use super::{
    account::{self, AccountStep},
    contract::*,
    policy,
    transaction::{
        checked, run_bounded, sha256, Root, State, Transaction, HELPER_MAX_BYTES, HELPER_TIMEOUT,
        RECORD_MAX_BYTES,
    },
    Result,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

pub const WALL: &str = "sanctuary-castle-wall.service";
const PACKAGE: &str = "sanctuary-castle-wall";
const START_DEADLINE: Duration = Duration::from_secs(100); // Wall 60s + agent 30s + second-exec observation allowance 10s.
const STOP_DEADLINE: Duration = Duration::from_secs(15); // Unit stop 10s + cgroup-empty observation allowance 5s.
const IDENTITY_STABILITY: Duration = Duration::from_millis(100); // Two independently sampled PID/start-tick observations.
pub const BUILD_IDENTITY: &str = "usr/share/doc/sanctuary-castle-wall/build-identity";
fn relative(path: &str) -> &str {
    path.trim_start_matches('/')
}

pub fn verify_elf(root: &Root, path: &str) -> Result<File> {
    let file = root.file(relative(path))?;
    let meta = file.metadata()?;
    let mut magic = [0; 64]; // ELF64_Ehdr is 64 bytes; e_machine 62 names AMD64.
    (&file).read_exact(&mut magic)?;
    // Root-installed regular ELF only; scripts, privileged modes and file capabilities are outside this profile.
    if &magic[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16::from_le_bytes([magic[16], magic[17]]), 2 | 3)
        || u16::from_le_bytes([magic[18], magic[19]]) != 62
        || meta.mode() & 0o111 == 0
        || meta.mode() & 0o6000 != 0
    {
        return Err("workload must be an ordinary executable ELF".into());
    }
    use std::os::fd::AsRawFd;
    let result = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            b"security.capability\0".as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
        return Err("executable capability observation refused".into());
    }
    Ok(file)
}
fn systemctl(args: &[&str]) -> Result<Vec<u8>> {
    checked("/usr/bin/systemctl", args)
}
pub fn properties(unit: &str) -> Result<BTreeMap<String, String>> {
    properties_until(unit, Instant::now() + HELPER_TIMEOUT)
}
fn properties_until(unit: &str, deadline: Instant) -> Result<BTreeMap<String, String>> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(HELPER_TIMEOUT);
    if remaining.is_zero() {
        return Err("manager observation deadline exceeded".into());
    }
    let result=run_bounded("/usr/bin/systemctl", &["show",unit,"--no-pager","--property=Id,Names,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,MainPID,ControlGroup,InvocationID,Result,ExecMainStatus,NRestarts,ExecMainStartTimestampMonotonic,ActiveEnterTimestampMonotonic,ActiveExitTimestampMonotonic,InactiveEnterTimestampMonotonic,StateChangeTimestampMonotonic,MemoryMax,TasksMax,LimitCORE"],remaining,HELPER_MAX_BYTES)?;
    if result.code != Some(0) {
        return Err("manager observation refused".into());
    }
    let bytes = result.stdout;
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (k, v) = line
            .split_once('=')
            .ok_or("malformed manager observation")?;
        if values.insert(k.into(), v.into()).is_some() {
            return Err("duplicate manager property".into());
        }
    }
    Ok(values)
}
fn prop<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing manager property {name}").into())
}
pub fn instance(t: &Transaction) -> String {
    format!("sanctuary-agent@{}.service", t.agent_uid)
}
pub fn stopped(t: &Transaction) -> Result<()> {
    for unit in [WALL.to_owned(), instance(t)] {
        let p = properties(&unit)?;
        if !matches!(prop(&p, "ActiveState")?, "inactive" | "failed") || prop(&p, "MainPID")? != "0"
        {
            return Err("wall and agent must be stopped".into());
        }
    }
    no_jobs()
}
fn no_jobs() -> Result<()> {
    let jobs = systemctl(&["list-jobs", "--no-legend", "--no-pager"])?;
    if std::str::from_utf8(&jobs)?.contains("sanctuary") {
        return Err("pending Sanctuary manager job".into());
    }
    Ok(())
}
fn package(root: &Root) -> Result<()> {
    package_for(root)
}
fn package_for(root: &Root) -> Result<()> {
    let mut snapshot = super::pacman::installed(root, PACKAGE)?;
    // Must match packaging/arch/build-arch-package.py's install identity; the compiled pins bind it to this build.
    let value = super::pacman::verified_identity(root, &mut snapshot)?;
    let hashes = value["payload_sha256"]
        .as_object()
        .ok_or("missing payload identity")?;
    if hashes.len() > 16 {
        return Err("payload identity quota".into());
    } // Four binaries, three units, two documentation/schema files, with bounded version headroom.
    let mandatory = [
        DAEMON_PATH.to_owned(),
        super::pacman::ARCH_CLI_PATH.to_owned(),
        LAUNCHER_PATH.to_owned(),
        STANDIN_PATH.to_owned(),
        format!("/etc/systemd/system/{WALL}"),
        "/etc/systemd/system/sanctuary-agent@.service".into(),
        format!("/etc/systemd/system/{WORKSPACE_MOUNT_UNIT}"),
    ];
    if mandatory
        .iter()
        .any(|path| !hashes.contains_key(relative(path)))
    {
        return Err("incomplete payload identity".into());
    }
    for (path, digest) in hashes {
        let file = root.file(path)?;
        let before = file.metadata()?;
        const BINARY_MAX: u64 = 100 * 1024 * 1024; // Fixed 100 MiB installed-file admission ceiling.
        if before.len() > BINARY_MAX {
            return Err("installed file quota".into());
        }
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let count = {
            let mut reader = (&file).take(BINARY_MAX + 1);
            let mut count = 0;
            let mut block = [0u8; 16 * 1024];
            loop {
                let n = reader.read(&mut block)?;
                if n == 0 {
                    break;
                }
                hash.update(&block[..n]);
                count += n as u64;
            }
            count
        };
        let after = file.metadata()?;
        if count != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || Some(hex::encode(hash.finalize()).as_str()) != digest.as_str()
        {
            return Err("installed payload digest mismatch".into());
        }
    }
    for path in [
        DAEMON_PATH,
        super::pacman::ARCH_CLI_PATH,
        LAUNCHER_PATH,
        STANDIN_PATH,
    ] {
        verify_elf(root, path)?;
    }
    super::pacman::recheck(root, &snapshot)
}
/// Admit one complete effective-unit observation against its packaged identity.
pub fn verify_unit_observation(
    values: &BTreeMap<String, String>,
    unit: &str,
    expected: &str,
) -> Result<()> {
    // systemd 255 renders Names as a quoted C-escaped string list for the fixed mount name.
    // Exact singleton comparison preserves alias refusal; Id and FragmentPath remain literal fields.
    let names = if unit == WORKSPACE_MOUNT_UNIT {
        format!("\"{}\"", unit.replace('\\', "\\\\"))
    } else {
        unit.to_owned()
    };
    if prop(values, "Id")? != unit
        || prop(values, "Names")? != names
        || prop(values, "FragmentPath")? != expected
        || prop(values, "LoadState")? != "loaded"
        || !prop(values, "DropInPaths")?.is_empty()
        || prop(values, "NeedDaemonReload")? != "no"
    {
        return Err("effective unit identity or overrides refused".into());
    }
    if !matches!(
        prop(values, "UnitFileState")?,
        "enabled" | "disabled" | "static"
    ) {
        return Err("unexpected unit enablement state".into());
    }
    Ok(())
}
fn units(root: &Root, t: &Transaction, _retiring: bool) -> Result<()> {
    package_for(root)?;
    for (unit, fragment) in [
        (WALL.to_owned(), WALL.to_owned()),
        (instance(t), "sanctuary-agent@.service".into()),
        (WORKSPACE_MOUNT_UNIT.into(), WORKSPACE_MOUNT_UNIT.into()),
    ] {
        let expected = format!("/etc/systemd/system/{fragment}");
        root.read(relative(&expected), RECORD_MAX_BYTES)?;
        let values = properties(&unit)?;
        verify_unit_observation(&values, &unit, &expected)?;
    }
    unit_links(root, t, false)?;
    no_jobs()
}
fn configured(root: &Root, t: &Transaction) -> Result<CommandV1> {
    account::verify(root, t)?;
    account::require_system_gid(root, t)?;
    if !t.policy_complete {
        return Err("incomplete policy transaction".into());
    }
    let marker = ConfiguredV1::parse(&root.read(relative(CONFIGURED_PATH), CONFIGURED_MAX_BYTES)?)?;
    marker.validate_identity(&policy::identity(t, account::overflow_uid()?))?;
    let bytes = root.read(relative(COMMAND_PATH), COMMAND_MAX_BYTES)?;
    let endpoints = root.read(relative(ENDPOINTS_PATH), ENDPOINTS_MAX_BYTES)?;
    let command = CommandV1::parse(&bytes)?;
    command.validate_identity(&policy::identity(t, account::overflow_uid()?))?;
    EndpointsV1::parse(&endpoints)?;
    if sha256(&bytes) != marker.command_sha256
        || sha256(&endpoints) != marker.endpoints_sha256
        || marker.policy_generation != t.policy_generation
    {
        return Err("Configured digest mismatch".into());
    }
    let config = crate::config::DaemonConfig::defaults_for_fortress(&t.fortress_id);
    let dir = config.policy_dir.to_str().ok_or("policy path")?;
    let manifest = root.read(
        relative(&format!("{dir}/manifest.json")),
        crate::manifest::store::MAX_PUBLISH_BUNDLE_BYTES,
    )?;
    let pin = root.read(
        relative(config.pinned_public_key_path.to_str().ok_or("pin path")?),
        ed25519_dalek::PUBLIC_KEY_LENGTH,
    )?;
    if sha256(&manifest) != marker.policy_sha256 || sha256(&pin) != marker.public_pin_sha256 {
        return Err("Configured policy identity mismatch".into());
    }
    policy::read_installed(root, t, &marker)?;
    let expected_env = format!(
        "SANCTUARY_FORTRESS_ID={}\nSANCTUARY_TRUSTED_SERVICE_UID={}\n",
        t.fortress_id, t.service_uid
    );
    if root.read(relative(ENV_PATH), RECORD_MAX_BYTES)? != expected_env.as_bytes()
        || root.file(relative(ENV_PATH))?.metadata()?.mode() & 0o777 != 0o600
    {
        return Err("environment identity mismatch".into());
    }
    verify_elf(root, &command.executable)?;
    Ok(command)
}
fn fresh(root: &Root, t: &Transaction) -> Result<()> {
    package(root)?;
    stopped(t)?;
    unit_links(root, t, true)?;
    for path in [COMMAND_PATH, ENDPOINTS_PATH, CONFIGURED_PATH, ENV_PATH] {
        if root.optional(relative(path), RECORD_MAX_BYTES)?.is_some() {
            return Err("existing provisioned footprint".into());
        }
    }
    match root.entries("var/lib/sanctuary", HELPER_MAX_BYTES) {
        Ok(entries) if !entries.is_empty() => return Err("existing Sanctuary state".into()),
        Ok(_) => (),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(e) => return Err(e),
    }
    let nft = checked("/usr/sbin/nft", &["-j", "list", "ruleset"])?;
    if std::str::from_utf8(&nft)?.contains("sanctuary") {
        return Err("existing Sanctuary kernel footprint".into());
    }
    Ok(())
}
fn input(root: &Root, path: &str, cap: usize) -> Result<Vec<u8>> {
    let absolute = if path.starts_with('/') {
        Path::new(path).to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    root.input(
        relative(absolute.to_str().ok_or("input path")?),
        cap,
        account::operator_uid()?,
    )
}
pub fn provision(root: &Root, args: &[String]) -> Result<()> {
    package(root)?;
    let divider = args
        .iter()
        .position(|a| a == "--")
        .ok_or("provision requires -- EXEC ARGS...")?;
    let options = parse_options(
        &args[..divider],
        &[
            "--agent-uid",
            "--service-uid",
            "--fortress-id",
            "--stage-file",
        ],
    )?;
    let exec = args.get(divider + 1).ok_or("missing executable")?;
    let command = CommandV1 {
        version: VERSION,
        agent_uid: options["--agent-uid"].parse()?,
        fortress_id: options["--fortress-id"].clone(),
        executable: exec.clone(),
        argv: args[divider + 2..].to_vec(),
        env: BTreeMap::new(),
        resource_profile: RESOURCE_PROFILE.into(),
    };
    command.validate()?;
    if exec == LAUNCHER_PATH {
        return Err("workload cannot be the trampoline itself".into());
    }
    verify_elf(root, exec)?;
    let endpoints = input(root, &options["--stage-file"], ENDPOINTS_MAX_BYTES)?;
    EndpointsV1::parse(&endpoints)?;
    let command_bytes = serde_json::to_vec(&command)?;
    let b: u32 = options["--service-uid"].parse()?;
    let request = sha256(&serde_json::to_vec(&(b, &command_bytes, &endpoints))?);
    let mut t = match Transaction::load(root)? {
        Some(t) => {
            if t.request_sha256 != request {
                return Err("only the identical provision request can resume".into());
            }
            t
        }
        None => {
            let t = Transaction {
                version: VERSION,
                request_sha256: request,
                state: State::Absent,
                agent_uid: command.agent_uid,
                service_uid: b,
                operator_uid: account::operator_uid()?,
                fortress_id: command.fortress_id.clone(),
                sanctuary_gid: None,
                account_step: AccountStep::Fresh,
                policy_generation: 0,
                policy_request_sha256: None,
                policy_complete: false,
            };
            account::validate_ids(&t, account::overflow_uid()?)?;
            fresh(root, &t)?;
            root.mkdir("etc/sanctuary", 0o755)?;
            t.save(root)?;
            t
        }
    };
    // Resumption retains the recorded operator and also excludes the current
    // login principal; a new audit session cannot become the workload identity.
    account::validate_current_operator(&t, account::operator_uid()?)?;
    if t.policy_complete {
        configured(root, &t)?;
        return Ok(());
    }
    account::provision(root, &mut t)?;
    root.mkdir("etc/sanctuary/agent", 0o755)?;
    for dir in [
        "var/lib/sanctuary".to_owned(),
        format!("var/lib/sanctuary/{}", t.fortress_id),
        format!("var/lib/sanctuary/{}/policy", t.fortress_id),
        format!("var/lib/sanctuary/{}/policy/egress", t.fortress_id),
    ] {
        root.mkdir(&dir, 0o700)?;
    }
    root.write(relative(COMMAND_PATH), &command_bytes, 0o644)?;
    root.write(relative(ENDPOINTS_PATH), &endpoints, 0o644)?;
    root.write(
        relative(ENV_PATH),
        format!(
            "SANCTUARY_FORTRESS_ID={}\nSANCTUARY_TRUSTED_SERVICE_UID={}\n",
            t.fortress_id, t.service_uid
        )
        .as_bytes(),
        0o600,
    )?;
    t.state = State::CommandStaged;
    t.save(root)
}
pub fn parse_options(args: &[String], required: &[&str]) -> Result<BTreeMap<String, String>> {
    if args.len() != required.len() * 2 {
        return Err("wrong option count".into());
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !required.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err("unknown or repeated option".into());
        }
    }
    Ok(values)
}
fn process_identity(pid: u32, expected: &str) -> Result<(u32, u64)> {
    if pid == 0 {
        return Err("workload has no MainPID".into());
    }
    let mut raw = Vec::new();
    let file = File::open(format!("/proc/{pid}/stat"))?;
    const PROC_STAT_MAX: u64 = 4 * KIB as u64; // One kernel stat row, including the bounded comm field.
    file.take(PROC_STAT_MAX + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > PROC_STAT_MAX {
        return Err("process stat quota".into());
    }

    let stat = std::str::from_utf8(&raw)?;
    let tail = stat.rsplit_once(')').ok_or("invalid process stat")?.1;
    // starttime is field 22; tail starts at field 3 after the parenthesized comm.
    let ticks: u64 = tail
        .split_whitespace()
        .nth(22 - 3)
        .ok_or("missing start ticks")?
        .parse()?;
    if std::fs::read_link(format!("/proc/{pid}/exe"))? != Path::new(expected) {
        return Err("second exec not observed".into());
    }
    Ok((pid, ticks))
}
pub fn manager_action(root: &Root, t: &mut Transaction, action: &str) -> Result<()> {
    let unit = instance(t);
    match action {
        "start" | "enable" => {
            let command = configured(root, t)?;
            systemctl(&["daemon-reload"])?;
            units(root, t, false)?;
            if action == "enable" {
                systemctl(&["enable", WALL, &unit])?;
                units(root, t, false)?;
                for enabled in [WALL, &unit] {
                    if prop(&properties(enabled)?, "UnitFileState")? != "enabled" {
                        return Err("enablement not observed".into());
                    }
                }
                t.state = State::Enabled;
            } else {
                let overall_deadline = Instant::now() + START_DEADLINE;
                let result = run_bounded(
                    "/usr/bin/systemctl",
                    &["start", &unit],
                    Duration::from_secs(60 + 30), // The frozen wall and agent manager start bounds.
                    HELPER_MAX_BYTES,
                )?;
                if result.code != Some(0) {
                    return Err("manager refused start".into());
                }
                let deadline = overall_deadline.min(Instant::now() + Duration::from_secs(10)); // Frozen second-exec observation allowance.
                loop {
                    let before = properties_until(&unit, deadline)?;
                    let pid = prop(&before, "MainPID")?.parse()?;
                    if let Ok(identity) = process_identity(pid, &command.executable) {
                        std::thread::sleep(IDENTITY_STABILITY);
                        let after = properties_until(&unit, deadline)?;
                        if prop(&after, "ActiveState")? == "active"
                            && prop(&after, "MainPID")?.parse::<u32>()? == pid
                            && process_identity(pid, &command.executable)? == identity
                        {
                            break;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err("stable second exec unavailable".into());
                    }
                    std::thread::sleep(IDENTITY_STABILITY);
                }
                t.state = State::Running;
            }
        }
        "disable" | "stop" => {
            units(root, t, true)?;
            // Reboot intent is removed before stop, so interruption cannot re-enable a workload.
            systemctl(&["disable", &unit])?;
            if prop(&properties(&unit)?, "UnitFileState")? != "disabled" {
                return Err("agent reboot intent remains".into());
            }
            if action == "stop" {
                let before = properties(&unit)?;
                let cgroup = prop(&before, "ControlGroup")?.to_owned();
                let result = run_bounded(
                    "/usr/bin/systemctl",
                    &["stop", &unit],
                    STOP_DEADLINE,
                    HELPER_MAX_BYTES,
                )?;
                if result.code != Some(0) {
                    return Err("manager refused stop".into());
                }
                let after = properties(&unit)?;
                if prop(&after, "MainPID")? != "0"
                    || !matches!(prop(&after, "ActiveState")?, "inactive" | "failed")
                {
                    return Err("agent stop incomplete".into());
                }
                if !cgroup.is_empty() {
                    if !cgroup.starts_with("/system.slice/") || cgroup.split('/').any(|c| c == "..")
                    {
                        return Err("unexpected unit cgroup".into());
                    }
                    match std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.events")) {
                        Ok(events) if !events.lines().any(|l| l == "populated 0") => {
                            return Err("descendants remain in stopped cgroup".into())
                        }
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                        _ => (),
                    }
                }
                t.state = State::Stopped;
            } else {
                t.state = State::Configured;
            }
        }
        _ => return Err("unknown manager action".into()),
    }
    t.save(root)
}
pub fn status(root: &Root, t: &Transaction) -> Result<Value> {
    let agent = properties(&instance(t));
    let wall = properties(WALL);
    let group = account::sanctuary_group_observation();
    let ranges = super::login_defs::read(root).ok();
    let config = configured(root, t);
    let effective_units = units(root, t, true);
    let marker = root
        .read(relative(CONFIGURED_PATH), CONFIGURED_MAX_BYTES)
        .ok()
        .and_then(|b| ConfiguredV1::parse(&b).ok());
    let build = root
        .read(super::pacman::ARCH_BUILD_IDENTITY, RECORD_MAX_BYTES)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let recovery = root
        .optional("etc/sanctuary/install-recovery.json", RECORD_MAX_BYTES)?
        .map(|b| serde_json::from_slice::<Value>(&b))
        .transpose()?;
    let workload = agent
        .as_ref()
        .ok()
        .and_then(|a| a.get("MainPID"))
        .and_then(|p| p.parse().ok())
        .and_then(|pid| {
            config
                .as_ref()
                .ok()
                .and_then(|c| process_identity(pid, &c.executable).ok())
        });
    let binding = checked(
        "/usr/sbin/nft",
        &["-j", "-a", "list", "table", "inet", "sanctuary-castle"],
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let observed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let mut missing = Vec::new();
    if agent.is_err() {
        missing.push("agent manager observation");
    }
    if wall.is_err() {
        missing.push("wall manager observation");
    }
    if group.is_err() {
        missing.push("NSS group observation");
    }
    if build.is_none() {
        missing.push("build identity");
    }
    if effective_units.is_err() {
        missing.push("verified package and effective units");
    }
    if config.is_err() {
        missing.push("validated configuration");
    }
    if workload.is_none() {
        missing.push("stable workload identity");
    }
    if binding.is_none() {
        missing.push("kernel binding observation");
    }
    Ok(
        json!({"version":VERSION,"agent_uid":t.agent_uid,"service_uid":t.service_uid,"fortress_id":t.fortress_id,"state":t.state,
        "sanctuary_group_present":group.as_ref().ok().map(Option::is_some),"sanctuary_gid":group.ok().flatten(),"configured_valid":config.is_ok(),"effective_units_valid":effective_units.is_ok(),
        "build_identity":build,"policy_identity":marker,"policy_generation":t.policy_generation,"agent":agent.ok(),"wall":wall.ok(),
        "workload":workload.map(|(pid,ticks)|json!({"pid":pid,"start_ticks":ticks})),"binding_observed_at_unix_ms":binding.as_ref().map(|_|observed),"binding_observation":binding,
        "last_operation_recovery":recovery,"missing_evidence":missing,"enforcement_claim":"unproven","package_manager":"pacman","system_id_ranges":ranges,"package_pins":super::pacman::pins_for_status()}),
    )
}

pub fn run(args: &[String]) -> Result<Value> {
    super::pacman::require_pins()?;
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::getuid() } != 0
        || unsafe { libc::getegid() } != 0
        || unsafe { libc::getgid() } != 0
    {
        return Err("root required".into());
    }
    let verb = args.first().ok_or("missing command; use --help")?;
    if ![
        "provision",
        "policy-install",
        "start",
        "enable",
        "disable",
        "stop",
        "status",
        "evidence",
    ]
    .contains(&verb.as_str())
    {
        return Err(format!("unknown command: {verb}").into());
    }
    let root = Root::open(Path::new("/"))?;
    if verb == "status" {
        if args[1..] != ["--json"] {
            return Err("status requires --json".into());
        }
        return status(&root, &Transaction::load(&root)?.ok_or("not provisioned")?);
    }
    root.mkdir("run/sanctuary-linux", 0o700)?;
    let _lock = root.lock("run/sanctuary-linux/mutation.lock")?;
    let result = (|| -> Result<Value> {
        if verb == "provision" {
            provision(&root, &args[1..])?;
        } else {
            let mut t = Transaction::load(&root)?.ok_or("not provisioned")?;
            match verb.as_str() {
                "policy-install" => {
                    let options =
                        parse_options(&args[1..], &["--bundle", "--expected-key-sha256"])?;
                    package(&root)?;
                    stopped(&t)?;
                    let bytes = input(
                        &root,
                        &options["--bundle"],
                        crate::manifest::store::MAX_PUBLISH_BUNDLE_BYTES,
                    )?;
                    policy::install(&root, &mut t, &bytes, &options["--expected-key-sha256"])?;
                }
                "evidence" => {
                    let options = parse_options(&args[1..], &["--output"])?;
                    return super::evidence::capture(&root, &t, Path::new(&options["--output"]));
                }
                _ => {
                    if args.len() != 1 {
                        return Err("unexpected arguments".into());
                    }
                    manager_action(&root, &mut t, verb)?;
                }
            }
        }
        let mut result = json!({"ok":true,"command":verb});
        if ["disable", "stop"].contains(&verb.as_str()) {
            let wall = properties(WALL)?;
            result["wall_active_state"] = json!(prop(&wall, "ActiveState")?);
            result["wall_enablement"] = json!(prop(&wall, "UnitFileState")?);
        }
        Ok(result)
    })();
    if result.is_ok() && Transaction::load(&root)?.is_some() {
        root.remove("etc/sanctuary/install-recovery.json")?;
    }
    if let Err(ref error) = result {
        // One bounded recovery record replaces prior failures, never an unbounded error history.
        let message = error.to_string();
        let bounded: String = message.chars().take(STRING_MAX_BYTES / 4).collect(); // UTF-8 is at most four bytes per scalar.
        if Transaction::load(&root)?.is_some() {
            root.write(
                "etc/sanctuary/install-recovery.json",
                &serde_json::to_vec(
                    &json!({"state":State::RepairRequired,"command":verb,"reason":bounded}),
                )?,
                0o600,
            )?;
        }
    }
    result
}

fn unit_links(root: &Root, t: &Transaction, fresh: bool) -> Result<()> {
    // Only these two boot links may refer to the package; aliases and other instances are not launch authority.
    let allowed = [
        (
            instance(t),
            "/etc/systemd/system/sanctuary-agent@.service".to_owned(),
        ),
        (WALL.to_owned(), format!("/etc/systemd/system/{WALL}")),
    ];
    // Must match SYSTEMD_ROOTS in packaging/ubuntu/install-lifecycle-guard.py; only the canonical boot links differ.
    const UNIT_ROOTS: [&str; 12] = [
        "etc/systemd/system.control",
        "run/systemd/system.control",
        "run/systemd/transient",
        "run/systemd/generator.early",
        "etc/systemd/system",
        "etc/systemd/system.attached",
        "run/systemd/system",
        "run/systemd/system.attached",
        "run/systemd/generator",
        "usr/local/lib/systemd/system",
        "usr/lib/systemd/system",
        "run/systemd/generator.late",
    ];
    let raw = systemctl(&["show", "--property=UnitPath", "--value", "--no-pager"])?;
    let paths: Vec<_> = std::str::from_utf8(&raw)?.split_whitespace().collect();
    if paths.is_empty() || paths.len() > UNIT_ROOTS.len() + 1 {
        return Err("manager unit path inventory unavailable".into());
    }
    for path in paths {
        if path == "/lib/systemd/system"
            && std::fs::canonicalize(path)? == Path::new("/usr/lib/systemd/system")
        {
            continue;
        }
        if !UNIT_ROOTS.contains(&relative(path)) {
            return Err("unsupported manager unit search path".into());
        }
    }
    for dir in UNIT_ROOTS {
        inspect_unit_tree(root, dir, &allowed, fresh)?;
    }
    Ok(())
}

/// Walk every dependency suffix, including Upholds, through custodied directories.
pub fn inspect_unit_tree(
    root: &Root,
    initial: &str,
    allowed: &[(String, String)],
    fresh: bool,
) -> Result<()> {
    let mut pending = vec![(initial.to_owned(), 0usize)];
    let mut count = 0usize;
    while let Some((dir, depth)) = pending.pop() {
        let entries = match root.entries(&dir, HELPER_MAX_BYTES) {
            Ok(entries) => entries,
            Err(e)
                if depth == 0
                    && e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        count += entries.len();
        // Same 100,000-entry host inventory ceiling as install-lifecycle-guard.py;
        // 16 levels bound recursive dependency trees without following symlinks.
        if count > 100_000 || depth > 16 {
            return Err("unit inventory quota".into());
        }
        for name in entries {
            let path = format!("{dir}/{name}");
            let target = root.link_target(&path)?;
            let relevant = name.contains("sanctuary")
                || target.as_ref().is_some_and(|v| v.contains("sanctuary"));
            let canonical = !fresh
                && dir == "etc/systemd/system/multi-user.target.wants"
                && allowed
                    .iter()
                    .any(|(n, d)| *n == name && target.as_ref() == Some(d));
            let fragment = dir == "etc/systemd/system"
                && target.is_none()
                && [WALL, "sanctuary-agent@.service", WORKSPACE_MOUNT_UNIT]
                    .contains(&name.as_str());
            if relevant && !canonical && !fragment {
                return Err("unexpected Sanctuary unit or enablement link".into());
            }
            if ["service.d", "mount.d", "var-.mount.d", "var-lib-.mount.d"].contains(&name.as_str())
            {
                return Err("inherited unit override".into());
            }
            if root.is_directory(&path)? {
                // Must match install-lifecycle-guard.py: an unwalked directory cannot prove aliases absent.
                if target.is_some() {
                    return Err("symlinked systemd directory".into());
                }
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(())
}
