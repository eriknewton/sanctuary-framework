//! nftables CLI shell-out wrappers.
//!
//! Per scope-lock section 1 Option A: the daemon shells out to the `nft` binary
//! with atomic ruleset replacement, installs rules in a dedicated
//! `sanctuary-castle` table (E7.2 namespace separation), binds rules to
//! cgroup IDs via `socket cgroupv2 level N "<scope-path>"` matches.
//!
//! All kernel-touching functions are `#[cfg(target_os = "linux")]`-gated;
//! on macOS (the dev sandbox) the stubs return structured errors so
//! `cargo check` passes cross-platform.

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::OnceLock;

/// Errors emitted by the nftables module.
#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables not available on this platform")]
    NotAvailableOnPlatform,
    #[error("nft binary missing: {0}")]
    BinaryMissing(String),
    #[error("nft invocation failed: {0}")]
    InvocationFailed(String),
    #[error("failed to parse nft output: {0}")]
    ParseFailed(String),
    /// A table named `sanctuary-castle` exists but does not have the shape this
    /// daemon installs (missing/foreign base output chain, wrong hook, or a
    /// non-`accept` policy). The daemon refuses to adopt or clobber foreign
    /// state that merely shares its table name; it neither enforces through an
    /// unknown ruleset nor deletes another owner's table.
    #[error("foreign or incompatible sanctuary-castle table: {0}")]
    ForeignState(String),
}

/// Identifier for a wrapped agent's cgroup-bound ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRulesetId {
    pub agent_id: String,
    pub cgroup_path: PathBuf,
}

/// The dedicated nftables table name PRODUCTION installs into. Per scope-lock
/// section 7 E7.2, the daemon installs into its own table so it never conflicts
/// with ufw / firewalld / operator rules.
///
/// Every operational site reads [`castle_table()`], not this constant, so a test
/// binary can be pointed at an isolated table name; the resolver's DEFAULT is
/// this value, so production is byte-for-byte unchanged.
pub const CASTLE_TABLE: &str = "sanctuary-castle";

/// Prefix every isolated test table name must carry. Enforced by
/// [`use_isolated_castle_table`], so the isolation seam can never be used to
/// point a daemon at an arbitrary operator table.
#[cfg(any(test, feature = "test-isolation"))]
pub const ISOLATED_TABLE_PREFIX: &str = "sanctuary-castle-test-";

/// Process-wide resolved table name. Set at most once, before any nftables call.
static ACTIVE_CASTLE_TABLE: OnceLock<String> = OnceLock::new();

/// The nftables table this process operates on.
///
/// Resolves to [`CASTLE_TABLE`] unless an isolated name was installed first.
/// The table is a HOST-GLOBAL kernel object, so this is process-wide rather than
/// threaded through ~100 call sites: a second table name inside one process
/// would be a split-brain, not a feature.
///
/// The reason it is overridable at all: `cargo test` on a Linux host drove the
/// real `sanctuary-castle` table, and its cleanup ran
/// `nft delete table inet sanctuary-castle` — deleting the operator's LIVE
/// enforcement table (AGENTS.md, "the operator's machine is not a fixture").
/// The override exists only in `cfg(test)` and `feature = "test-isolation"`
/// builds; the shipped binary contains no way to call it.
pub fn castle_table() -> &'static str {
    ACTIVE_CASTLE_TABLE
        .get_or_init(|| CASTLE_TABLE.to_string())
        .as_str()
}

/// Has this process resolved the PRODUCTION table name?
///
/// The isolation proof the test suite asserts: after installing an isolated
/// table, this must stay false for the whole run. A `false` here means no code
/// path in this process has named the operator's live table.
pub fn production_castle_table_in_use() -> bool {
    ACTIVE_CASTLE_TABLE
        .get()
        .map(|name| name == CASTLE_TABLE)
        .unwrap_or(false)
}

/// Point this process at an isolated table for the rest of its life.
///
/// Fails (rather than silently no-opping) when the table name has ALREADY been
/// resolved, because a caller that has begun touching one table cannot be moved
/// to another without leaking the first. Refuses any name that is not
/// [`ISOLATED_TABLE_PREFIX`]-prefixed, so this can never redirect a daemon onto
/// an operator's table.
///
/// Absent from the shipped binary: `cfg(test)` covers the crate's own unit tests,
/// and `feature = "test-isolation"` covers the integration test binaries (which
/// declare it through `required-features`). A release build has neither.
#[cfg(any(test, feature = "test-isolation"))]
pub fn use_isolated_castle_table(name: &str) -> Result<&'static str, String> {
    if !name.starts_with(ISOLATED_TABLE_PREFIX) {
        return Err(format!(
            "an isolated castle table must be named `{ISOLATED_TABLE_PREFIX}<tag>`; \
             refusing `{name}` so this seam can never redirect a daemon onto a \
             production or operator-owned table"
        ));
    }
    match ACTIVE_CASTLE_TABLE.set(name.to_string()) {
        Ok(()) => Ok(castle_table()),
        Err(_) => {
            let active = castle_table();
            if active == name {
                Ok(active)
            } else {
                Err(format!(
                    "this process already resolved the castle table as `{active}`; refusing \
                     to switch to `{name}` (state acquired under the first name would leak)"
                ))
            }
        }
    }
}

/// The nftables table family. `inet` covers both IPv4 and IPv6.
pub const CASTLE_FAMILY: &str = "inet";
const NFT_CHAIN_MAX_LEN: usize = 256;
const AGENT_CHAIN_PREFIX: &str = "agent_";

/// Prefix of the ownership marker stamped as a `comment` on the acquisition
/// path's table. The full marker is `OWNER_MARKER_PREFIX` followed by a random
/// per-acquisition nonce, so two acquisitions (even of a same-named table) are
/// distinguishable and a foreign table that merely shares the `sanctuary-castle`
/// name cannot forge it. The marker is a table COMMENT, not a rule, so it does
/// not count against the "zero rules" ownership invariant. Must match the marker
/// the journal records for the same acquisition (see `ownership_journal`).
pub const OWNER_MARKER_PREFIX: &str = "sanctuary-castle-owner:v1:";

/// The exact, verified identity of a `sanctuary-castle` table THIS daemon
/// created and owns. (blocker 2/3)
///
/// Ownership is not "a table by that name exists"; it is this precise tuple:
/// the nft-assigned table handle, the base output chain's handle, and the
/// ownership marker/nonce stamped as the table comment at create time. A
/// delete-and-recreate of a same-shaped table yields DIFFERENT handles (nft
/// hands out monotonically increasing handles), and a foreign table cannot
/// carry our random marker, so binding readiness and teardown to this tuple —
/// not to the name — is what makes "same-shape replacement withdraws readiness"
/// and "release deletes only the exact owned object, never by name" true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastleTableOwnership {
    /// nft-assigned handle of the owned `inet sanctuary-castle` table.
    pub table_handle: u64,
    /// nft-assigned handle of the owned base `output` chain.
    pub base_chain_handle: u64,
    /// The full ownership marker (`OWNER_MARKER_PREFIX` + nonce) stamped as the
    /// table comment at create time and recorded in the ownership journal.
    pub marker: String,
}

#[cfg(target_os = "linux")]
static ACTIVE_RUNTIME_OWNERSHIP: OnceLock<Mutex<Option<CastleTableOwnership>>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn runtime_ownership() -> &'static Mutex<Option<CastleTableOwnership>> {
    ACTIVE_RUNTIME_OWNERSHIP.get_or_init(|| Mutex::new(None))
}

/// Bind subsequent production agent mutations to the exact authenticated
/// table identity acquired through the host lock + ownership journal.
#[cfg(target_os = "linux")]
pub(crate) fn activate_runtime_ownership(
    ownership: &CastleTableOwnership,
) -> Result<(), NftablesError> {
    let mut guard = runtime_ownership().lock().map_err(|_| {
        NftablesError::InvocationFailed("runtime ownership state is poisoned".to_string())
    })?;
    match guard.as_ref() {
        Some(active) if active != ownership => Err(NftablesError::ForeignState(
            "a different nft runtime identity is already active in this process".to_string(),
        )),
        _ => {
            *guard = Some(ownership.clone());
            Ok(())
        }
    }
}

/// Test-only reset of the process-global authenticated-ownership latch.
///
/// This seam exists because `ACTIVE_RUNTIME_OWNERSHIP` models a property a real
/// daemon has for its whole life: a production process acquires ONE runtime
/// identity at boot and never clears it, so `activate_runtime_ownership`
/// deliberately refuses a second, different identity in the same process. A test
/// BINARY, however, drives the acquisition path many times in one process; the
/// second boot would otherwise hit that refusal ("a different nft runtime
/// identity is already active in this process") even though each boot is a
/// distinct, legitimate daemon lifetime. Clearing the latch here lets each test
/// start from the same clean process state a freshly-exec'd daemon would have.
/// Compiled ONLY under `--features test-isolation`; a release build has no way to
/// clear the latch, exactly like production. Analogous to the kernel-lock poison
/// reset seam.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn reset_runtime_ownership_for_tests() {
    // Recover a poisoned lock rather than panic: a prior failed test must not
    // convert this reset into a cascade that masks the real failure.
    let mut guard = runtime_ownership()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    *guard = None;
}

#[cfg(target_os = "linux")]
fn verify_active_runtime_ownership() -> Result<(), NftablesError> {
    if castle_table() != CASTLE_TABLE {
        // The integration-test namespace has no production journal. Its
        // isolation prefix and test-build mutation guard are the boundary.
        return Ok(());
    }
    let active = runtime_ownership()
        .lock()
        .map_err(|_| {
            NftablesError::InvocationFailed("runtime ownership state is poisoned".to_string())
        })?
        .clone()
        .ok_or_else(|| {
            NftablesError::ForeignState(
                "production agent mutation has no authenticated active ownership identity"
                    .to_string(),
            )
        })?;
    verify_owned_castle_table(&active)
}

/// A single nftables rule fragment generated from a PolicySnapshot rule.
#[derive(Debug, Clone)]
pub struct NftRuleFragment {
    /// The allowlist rule id this fragment was generated from.
    pub rule_id: String,
    /// nft rule expression (e.g., `ip daddr 1.2.3.4 tcp dport 443 accept`).
    pub nft_expr: String,
}

/// Translate a PolicySnapshot into nftables rule fragments for one agent.
/// The fragments are installed inside a per-agent chain within the
/// `sanctuary-castle` table. The chain ends with a `queue num 0` verdict
/// for any unmatched traffic (NFQUEUE with FAIL_OPEN explicitly off).
///
/// `cgroup_relative_path` is the cgroup-v2 path with the `/sys/fs/cgroup/`
/// prefix stripped, e.g. `system.slice/sanctuary-agent-foo.service`. nft
/// expects a quoted path string at rule-load time and walks
/// `/sys/fs/cgroup/<path>` at depth `cgroup_level` to validate the cgroup
/// exists. Earlier production code emitted the cgroup inode integer
/// instead, which nft 1.x rejects: the integer is the post-resolution
/// internal form (what `nft list rules` displays back), not the documented
/// input form. Compute the relative path via `cgroup::cgroup_relative_path`
/// from a `ScopeHandle.cgroup_path`.
///
/// `cgroup_level` is the depth at which the agent's cgroup lives in the
/// cgroup-v2 hierarchy (counted from `/sys/fs/cgroup` as depth 0). It comes
/// from `cgroup::ScopeHandle::cgroup_level`, which is derived from
/// systemd's reported ControlGroup. If the level is wrong (because the
/// deployment is nested), nft rejects with "cgroupv2 path fails: No such
/// file or directory". Threading the actual level through avoids that.
pub fn build_agent_ruleset(
    agent_id: &str,
    cgroup_relative_path: &str,
    cgroup_level: u32,
    rules: &[NftRuleFragment],
) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    let agent_mark = crate::nfqueue::register_agent_mark(agent_id);
    let mut script = String::new();
    // Atomic replace: flush the chain then re-add all rules.
    script.push_str(&format!(
        "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n"
    ));
    // cgroup match: only packets from this agent's cgroup enter this chain.
    // The cgroup match is installed as a jump rule in the base output chain.
    // Static fragments are intentionally ignored. All signed rule semantics
    // execute in the ordered Rust evaluator behind the one NFQUEUE rule below.
    // Keeping this parameter during the API migration avoids a broad caller
    // break while removing raw fragment text from the privileged script.
    let _ = rules;
    // Default: send unmatched traffic to NFQUEUE 0 for userspace verdict.
    // Per scope-lock section 1: `queue num 0` without `bypass` flag.
    script.push_str(&format!(
        "add rule {CASTLE_FAMILY} {castle_table} {chain_name} \
         socket cgroupv2 level {cgroup_level} \"{cgroup_relative_path}\" \
         meta mark set 0x{agent_mark:08x} queue num 0\n\
         add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop\n"
    ));
    script
}

/// Build the jump rule that routes packets from an agent's cgroup-v2
/// directory into its per-agent chain in the `sanctuary-castle` output
/// chain. Pure helper: emits the nft rule string only; callers shell out
/// to apply it.
///
/// The base `output` chain created by [`install_castle_table`] is hooked
/// into netfilter (`type filter hook output priority 0`) but has no rules
/// of its own. Per-agent chains are non-base chains and stay dead until
/// something jumps to them. This helper produces the `goto agent_<id>`
/// rule that gates entry into the per-agent chain on the cgroup-v2
/// `socket cgroupv2 level <N> "<path>"` match: only packets owned by a
/// socket inside the agent's cgroup transit the per-agent rules. Every
/// other packet in the operator's host (browser, OS daemons, the
/// operator's other apps) flows past the jump and is allowed by the base
/// chain's `policy accept`.
///
/// The path is quoted at emission time (the same correctness invariant
/// pinned for [`build_agent_ruleset`] in PR #130). `cgroup_level` mirrors
/// the same dynamic-depth shape: depth 2 in canonical
/// `system.slice/<unit>` placement, deeper for nested deployments.
pub fn build_agent_jump_rule(
    agent_id: &str,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    format!(
        "add rule {CASTLE_FAMILY} {castle_table} output \
         socket cgroupv2 level {cgroup_level} \"{cgroup_relative_path}\" goto {chain_name}"
    )
}

/// Build a fail-closed per-agent chain body for a refreshed cgroup.
///
/// During systemd scope recreation there is a short interval where the old
/// base-chain jump points at an obsolete cgroup identity and the new cgroup
/// identity is not yet wired. This ruleset is the first stage of refresh:
/// replace the per-agent chain with a single drop verdict, then wire the
/// refreshed cgroup jump to it before the normal policy rules are restored.
pub fn build_agent_fail_closed_ruleset(agent_id: &str) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    format!(
        "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n\
         add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop\n"
    )
}

/// Derive a sanitized chain name from an agent id.
pub(crate) fn agent_chain_name(agent_id: &str) -> String {
    let max_component_len = NFT_CHAIN_MAX_LEN - AGENT_CHAIN_PREFIX.len();
    let encoded = crate::identity::encode_agent_component(agent_id, max_component_len);
    format!("{AGENT_CHAIN_PREFIX}{encoded}")
}

// ---- nft binary resolution (cross-platform, PATH-free) --------------------
//
// A root daemon that activates nftables MUST resolve its enforcement binary by
// DIRECT absolute-path existence/executable checks, never through a PATH search
// or `which`: PATH is attacker-influenceable and a wrong `nft` on it would let a
// non-root-controlled binary run with the daemon's privilege. (blocker 9) These
// helpers are cross-platform + pure over an injected probe so the "absolute
// only, no PATH fallback" rule is unit-testable on the macOS dev host too.

/// Absolute nft locations, checked in order. Deliberately contains NO bare
/// `nft` entry: there is no PATH fallback. Must stay absolute-only; a bare name
/// here would reintroduce the PATH-resolution hazard this design removes.
///
/// The three entries cover common shipping layouts: `/usr/sbin/nft` and
/// `/sbin/nft` are the Debian/Ubuntu/Fedora
/// locations (nft is an sbin admin tool there), and `/usr/bin/nft` is where
/// Arch Linux — and the Arch-derived Omarchy — install it, since Arch places
/// nftables under `/usr/bin` (its usr-merge unifies `sbin` into `bin`). Adding
/// the Arch path makes Arch/Omarchy discoverable rather than silently failing
/// binary resolution. This is path compatibility, not a version-support claim:
/// enforcement also requires table-comment and JSON-comment support, and an
/// incompatible nft build fails activation closed. All three paths are absolute,
/// so the no-PATH-search contract is unchanged.
///
/// The nft-resolution helpers are production-used only on Linux (the `linux`
/// module below), but unit-tested on every host, so they are gated to
/// `any(target_os = "linux", test)`: on a non-Linux, non-test library build
/// they have no consumer and would otherwise trip `clippy -D warnings` as dead
/// code. Keep this cfg in lockstep with `is_executable_file` and
/// `resolve_nft_binary` — the tests exercise all three together.
#[cfg(any(target_os = "linux", test))]
pub(crate) const NFT_ABSOLUTE_PATHS: [&str; 3] = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

/// True iff `path` is a regular file with at least one execute bit set. The nft
/// binary is selected by this direct check, never a PATH lookup.
#[cfg(all(unix, any(target_os = "linux", test)))]
pub(crate) fn is_executable_file(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(all(not(unix), any(target_os = "linux", test)))]
pub(crate) fn is_executable_file(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

/// Resolve the nft binary to the first absolute candidate that exists and is
/// executable. Pure over the candidate list + an injected probe so the
/// no-PATH-fallback contract is testable without a real `/usr/sbin/nft`.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn resolve_nft_binary(
    candidates: &[&'static str],
    is_exec: impl Fn(&str) -> bool,
) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|&candidate| is_exec(candidate))
}

// ---- Linux implementations ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::{Child, Command, Output};
    use std::time::Duration;

    const NFT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

    fn wait_nft_bounded(child: Child) -> Result<Output, NftablesError> {
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(NFT_COMMAND_TIMEOUT) {
            Ok(result) => {
                let _ = waiter.join();
                result.map_err(|err| NftablesError::InvocationFailed(err.to_string()))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Absolute binary, direct child: terminate the process whose
                // bounded output waiter we own, then join it so no detached nft
                // worker survives a control-path timeout.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                let result = rx.recv().map_err(|err| {
                    NftablesError::InvocationFailed(format!(
                        "nft timed out and waiter result was lost: {err}"
                    ))
                })?;
                let _ = waiter.join();
                let _ = result;
                Err(NftablesError::InvocationFailed(format!(
                    "nft invocation exceeded {}ms deadline",
                    NFT_COMMAND_TIMEOUT.as_millis()
                )))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = waiter.join();
                Err(NftablesError::InvocationFailed(
                    "nft output waiter disconnected".to_string(),
                ))
            }
        }
    }

    /// Locate the `nft` binary by DIRECT absolute-path existence/executable
    /// check. NO PATH search, NO `which`: a PATH fallback is the exact hazard
    /// removed in blocker 9, so a missing absolute binary is a hard error, never
    /// a silent degrade to a bare `nft` resolved through PATH.
    fn nft_path() -> Result<&'static str, NftablesError> {
        super::resolve_nft_binary(&super::NFT_ABSOLUTE_PATHS, super::is_executable_file).ok_or_else(
            || {
                NftablesError::BinaryMissing(
                    "nft binary not found at /usr/sbin/nft, /sbin/nft, or /usr/bin/nft \
                     (no PATH fallback)"
                        .to_string(),
                )
            },
        )
    }

    /// Refuse to execute any `nft` command against the PRODUCTION table from a
    /// build that carries the test-isolation seams.
    ///
    /// This is the structural half of AGENTS.md's "the operator's machine is not
    /// a fixture". A convention ("remember to isolate") is what failed: the
    /// activation suite ran `nft delete table inet sanctuary-castle` on every
    /// setup, deleting the operator's LIVE enforcement table on any Linux host
    /// where `cargo test` ran. With this guard, a test build that forgot to call
    /// `use_isolated_castle_table` gets a LOUD error instead of silently mutating
    /// host state, and the failure names the fix.
    ///
    /// A production build has neither `cfg(test)` nor `feature = "test-isolation"`,
    /// so this compiles to nothing there and the shipped daemon is unchanged.
    #[cfg(any(test, feature = "test-isolation"))]
    fn refuse_production_table_under_test() -> Result<(), NftablesError> {
        // `castle_table()` RESOLVES as it reads. Consulting a non-resolving
        // predicate here would let the very first nft call of a process slip
        // through (nothing resolved yet -> "not production" -> pass) and only
        // then resolve to the production name.
        if super::castle_table() == super::CASTLE_TABLE {
            return Err(NftablesError::InvocationFailed(format!(
                "refusing to run nft against the PRODUCTION table `{}` from a \
                 test-isolation build: call nftables::use_isolated_castle_table(\"{}<tag>\") \
                 before any nftables call so this run cannot touch operator state",
                super::CASTLE_TABLE,
                super::ISOLATED_TABLE_PREFIX
            )));
        }
        Ok(())
    }

    #[cfg(not(any(test, feature = "test-isolation")))]
    fn refuse_production_table_under_test() -> Result<(), NftablesError> {
        Ok(())
    }

    fn run_nft(args: &[&str]) -> Result<String, NftablesError> {
        refuse_production_table_under_test()?;
        let nft = nft_path()?;
        let child = Command::new(nft)
            .env("LC_ALL", "C")
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        let output = wait_nft_bounded(child)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft {} exited {}: {}",
                args.join(" "),
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_nft_stdin(script: &str) -> Result<(), NftablesError> {
        refuse_production_table_under_test()?;
        let nft = nft_path()?;
        let mut child = Command::new(nft)
            .env("LC_ALL", "C")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        }
        // Closing stdin is required before waiting; otherwise nft correctly
        // waits forever for more script bytes.
        drop(child.stdin.take());
        let output = wait_nft_bounded(child)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft -f - exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Generate a fresh ownership marker (`OWNER_MARKER_PREFIX` + a 128-bit hex
    /// nonce) for the idempotent installer. Mirrors the production acquisition
    /// path's `new_owner_marker` (runtime_providers.rs) so a table this helper
    /// creates is indistinguishable from a real owned table to the load path.
    fn fresh_install_owner_marker() -> Result<String, NftablesError> {
        use std::io::Read;
        let mut nonce = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .map_err(|err| {
                NftablesError::InvocationFailed(format!(
                    "could not read /dev/urandom for the install ownership marker: {err}"
                ))
            })?;
        Ok(format!("{}{}", OWNER_MARKER_PREFIX, hex::encode(nonce)))
    }

    pub fn install_castle_table_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        // Invariant: the tightened load path (`load_agent_ruleset` ->
        // `capture_owned_castle_table_impl_from_live_inventory` ->
        // `parse_owned_table_identity`) refuses any owned table whose comment is
        // not an `OWNER_MARKER_PREFIX` ownership marker. This idempotent installer
        // therefore stamps a marker at create time, exactly as the production
        // acquisition path does via `build_create_castle_table_script`, instead of
        // a bare unmarked `add table` the load path would reject as ForeignState.
        // A table this helper leaves behind is always a validly-marked owned
        // object, so the agent-management / test load path exercises the real
        // capture -> parse contract rather than a shape production can never emit.
        if !table_exists_impl()? {
            let marker = fresh_install_owner_marker()?;
            // Table + base output chain land in one `create` transaction WITH the
            // marker comment. `create` is fail-on-exists, but we only reach it when
            // the table is absent (checked just above); this helper is the
            // single-threaded test / agent-management path, so a racing writer is
            // out of scope (the ACQUISITION path uses the host-lock-guarded
            // `create_castle_table_exclusive_impl`).
            run_nft_stdin(&super::build_create_castle_table_script(&marker))?;
        } else {
            // Idempotent: the marked table already exists. Ensure the base output
            // chain is present without disturbing the marker; `add chain` is a
            // no-op when the chain already exists.
            let chain_script = format!(
                "add chain {CASTLE_FAMILY} {castle_table} output \
                 {{ type filter hook output priority 0 ; policy accept ; }}\n"
            );
            let _ = run_nft_stdin(&chain_script);
        }
        Ok(())
    }

    /// GF1 deny-all safety net (the load-bearing fail-closed fix).
    ///
    /// Force the owned scopes to a fail-CLOSED state in ONE atomic `nft -f`
    /// transaction: recreate `<castle_table>` from scratch carrying a single
    /// base output chain whose default `policy` is `drop`. Whatever was present
    /// -- an empty base with `policy accept`, a full live-agent ruleset, an
    /// externally mutated/drifted chain, a drifted `accept` rule in the base
    /// chain, or nothing at all -- is replaced by a hooked output chain that
    /// DROPS every packet by default and carries no `accept` rule. The whole
    /// file is one atomic transaction, so the kernel never observes the
    /// intermediate deleted/empty state: there is NO fail-open window between
    /// tearing the old state down and the drop policy taking effect.
    ///
    /// The `add table` before the `delete table` makes the `delete` succeed even
    /// when the table is already gone (an external `nft delete table` while
    /// agents are live): add-then-delete-then-add yields a guaranteed-fresh table
    /// in both the absent and present cases, with no leftover agent chains/jumps.
    ///
    /// This is deliberately NOT a captured owned table: it carries `policy drop`,
    /// while the owned-table parser (`parse_owned_table_inventory`) requires
    /// `policy accept`, so a caller installs this and then REFUSES readiness
    /// rather than presenting it as a verified wall. Its sole guarantee is that
    /// owned-table LOSS or DRIFT can never leave `policy accept` in force for a
    /// live agent. Contract: Linux_Enforcement_Sprint_Architecture failure table
    /// ("Owned nft table flushed | Protected agents block; repair deny-all
    /// first") and product item 6 (external nftables mutation never creates a
    /// fail-open window). Callers: the reclaim/acquire path in
    /// `runtime_providers.rs` on owned-table LOSS and on captured-identity DRIFT,
    /// and the runtime health path on detected loss (GF1.3).
    ///
    /// GF1.4 threat-boundary note (assessed, inherent): the `delete table` here
    /// removes OUR named table by NAME. If a foreign table raced into the
    /// `sanctuary-castle` name in the sub-millisecond window between a caller's
    /// `table_exists()==false` observation and this transaction, that foreign
    /// table is replaced by our `policy drop` net. This is INHERENT to the
    /// CAP_NET_ADMIN threat model and is NOT a fail-open regression: (a) the
    /// replacement is fail-CLOSED (`policy drop`, no accept), so no traffic
    /// escapes; (b) the caller holds the host ownership lock and, on the reclaim
    /// paths, an authenticated this-boot ownership proof for this exact name, so
    /// the name is ours to force to deny-all; (c) a root actor racing nft cannot
    /// be defeated by any userspace check -- re-checking existence and refusing
    /// would REINTRODUCE a fail-open window (no drop table installed), the exact
    /// defect this net exists to prevent. The safety net's contract is "guarantee
    /// deny-all regardless of what currently holds the name," so add-delete-add is
    /// deliberate, not a bug to be narrowed.
    pub fn install_deny_all_safety_net_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        // add (ensure exists) -> delete (drop any drifted/leftover contents of
        // OUR named table) -> add (fresh empty) -> base output chain, policy DROP.
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n\
             add table {CASTLE_FAMILY} {castle_table}\n\
             add chain {CASTLE_FAMILY} {castle_table} output \
             {{ type filter hook output priority 0 ; policy drop ; }}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to install the GF1 deny-all safety net (kernel egress \
                 state for the owned scopes may be indeterminate): {err}"
            ))
        })
    }

    /// GF1.1: whether the LIVE `sanctuary-castle` table is exactly this daemon's
    /// deny-all safety net (see [`super::is_deny_all_safety_net_json`]). Absence
    /// or an nft error reads as "not the net" (false / propagated error), so a
    /// caller only ever recovers on a positively-recognized fail-closed net.
    pub fn live_table_is_deny_all_safety_net_impl() -> Result<bool, NftablesError> {
        match run_nft(&["-j", "list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(json) => Ok(super::is_deny_all_safety_net_json(&json)),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// GF1.1 recovery: atomically replace the deny-all safety net with a FRESH
    /// owned table (base output chain `policy accept`, stamped `new_marker`) in ONE
    /// `nft -f` transaction. `add`->`delete`->`create` means the kernel transitions
    /// directly from the `policy drop` net to the owned table with no intermediate
    /// absent/`accept`-without-the-owned-shape state: deny-all is held until the
    /// owned wall is up. Used only after `live_table_is_deny_all_safety_net_impl`
    /// has proven the current table is our own net AND the authenticated journal is
    /// `Preparing` for this boot (a create-failure that ReArmLostOwned armed); no
    /// agents exist in that state, so no per-agent jump is lost.
    pub fn atomic_reset_deny_all_net_to_fresh_owned_impl(
        new_marker: &str,
    ) -> Result<(), NftablesError> {
        if new_marker.contains('"') || new_marker.contains('\n') || new_marker.contains('\\') {
            return Err(NftablesError::InvocationFailed(
                "ownership marker contains characters unsafe for an nft comment".to_string(),
            ));
        }
        let castle_table = castle_table();
        // add (ensure exists) -> delete (remove the net) -> create fresh owned
        // table + base output chain, policy ACCEPT, all in one atomic transaction.
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n\
             create table {CASTLE_FAMILY} {castle_table} {{ comment \"{new_marker}\" ; }}\n\
             create chain {CASTLE_FAMILY} {castle_table} output \
             {{ type filter hook output priority 0 ; policy accept ; }}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to atomically reset the deny-all net to a fresh owned table: {err}"
            ))
        })
    }

    /// GF1.2 last-resort escalation: delete the `sanctuary-castle` table by NAME
    /// so no live `policy accept` castle path can remain when the deny-all net
    /// itself could not be installed. `add`->`delete` is idempotent (succeeds
    /// whether or not the table is present). Used ONLY on the reclaim DRIFT path,
    /// where the caller holds the host lock and an authenticated this-boot
    /// ownership proof for this exact name, after `install_deny_all_safety_net`
    /// has already FAILED; the daemon then refuses readiness, so no agent is
    /// launched behind the (now table-less) host.
    pub fn force_delete_castle_table_by_name_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to force-delete the drifted sanctuary-castle table by name: {err}"
            ))
        })
    }

    /// Create the `sanctuary-castle` table AND its exact base output chain in
    /// ONE atomic `nft -f` transaction using nft's FAIL-ON-EXISTS `create`
    /// verbs, propagating any error. (blocker 1)
    ///
    /// The verbs are `create table` / `create chain`, NOT the idempotent `add`.
    /// `create` fails the whole transaction if the object already exists, so a
    /// `sanctuary-castle` table that appears AFTER the caller's preflight
    /// existence check (a racing writer, a foreign table) makes this call fail
    /// rather than silently adopt or mutate it. `add` would have quietly
    /// succeeded against that pre-existing table — exactly the adoption the L2
    /// ownership model forbids. The table carries `marker` as its `comment` so
    /// the ownership can later be proven by nonce, not by name.
    ///
    /// Contract for the caller (the acquisition path): the host ownership lock
    /// is held AND the table has been confirmed ABSENT before this is called.
    /// Because table + chain land in a single `create` transaction, a partial
    /// install (table present, base chain missing) is impossible: nft applies
    /// the whole transaction or none of it.
    ///
    /// Failure-mode note: a raced foreign table that appears in the window
    /// between the caller's existence check and this call makes `create table`
    /// return a nonzero nft exit ("File exists"), surfaced here as
    /// `InvocationFailed`. The transaction was atomic, so this acquisition
    /// created NOTHING — it fails-before and never deletes the racer's table.
    pub fn create_castle_table_exclusive_impl(marker: &str) -> Result<(), NftablesError> {
        // Reject a marker that would break out of the nft comment string. The
        // marker is our own `OWNER_MARKER_PREFIX` + hex nonce, so this never
        // triggers in production; it is a defense-in-depth guard against a caller
        // passing an unexpected value into a shelled-out script.
        if marker.contains('"') || marker.contains('\n') || marker.contains('\\') {
            return Err(NftablesError::InvocationFailed(
                "ownership marker contains characters unsafe for an nft comment".to_string(),
            ));
        }
        run_nft_stdin(&super::build_create_castle_table_script(marker)).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "exclusive owned-table creation failed (Sanctuary requires nft table-comment and JSON-comment support): {err}"
            ))
        })
    }

    /// List `inet sanctuary-castle` as structured JSON and parse it into the
    /// EXACT owned identity, requiring the marker to equal `expected_marker`.
    /// Used right after [`create_castle_table_exclusive_impl`] to CAPTURE the
    /// handles this acquisition owns (blocker 3, the "capture/verify handles"
    /// step of prepare -> create -> capture -> finalize).
    pub fn capture_owned_castle_table_impl(
        expected_marker: &str,
    ) -> Result<CastleTableOwnership, NftablesError> {
        // `-a/--handle` is mandatory: libnftables omits handles from listings by
        // default, while the ownership parser deliberately requires both the
        // table and base-chain handles as part of the exact live identity.
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        let owned = super::parse_owned_table_identity(&json)?;
        if owned.marker != expected_marker {
            return Err(NftablesError::ForeignState(format!(
                "captured table marker does not match the marker just written \
                 (expected {expected_marker}, found {})",
                owned.marker
            )));
        }
        Ok(owned)
    }

    /// Re-list the live table and require it to STILL be exactly the captured
    /// owned identity — same handles, same marker, same pristine shape. A
    /// delete/recreate (new handles), a mutation, an injected rule, an extra
    /// chain, or a marker change all fail here. (blocker 2)
    pub fn verify_owned_castle_table_impl(
        ownership: &CastleTableOwnership,
    ) -> Result<Vec<String>, NftablesError> {
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        let live = super::parse_owned_table_inventory(&json)?;
        if &live.ownership == ownership {
            Ok(live.agent_ids)
        } else {
            Err(NftablesError::ForeignState(format!(
                "sanctuary-castle table identity changed since acquisition \
                 (expected handles table={}/chain={} marker={}, found table={}/chain={} marker={}); \
                 a same-name replacement or mutation is not the owned object",
                ownership.table_handle,
                ownership.base_chain_handle,
                ownership.marker,
                live.ownership.table_handle,
                live.ownership.base_chain_handle,
                live.ownership.marker,
            )))
        }
    }

    /// Delete ONLY the exact captured owned table, using a HANDLE-qualified
    /// delete (`delete table inet handle <N>`), and only after re-verifying the
    /// live identity still matches. (blocker 2/3)
    ///
    /// If the live identity no longer matches (a foreign table replaced ours, or
    /// the shape changed), this REFUSES rather than deleting: we never delete a
    /// `sanctuary-castle` table by name once its identity has drifted, so a
    /// foreign object that squatted the name is left intact. Deleting by the
    /// captured handle (not by name) means that even if a foreign table now
    /// holds the name, our stale handle either no longer resolves (nft errors)
    /// or resolves to a different object we already refused above.
    pub fn remove_owned_castle_table_impl(
        ownership: &CastleTableOwnership,
    ) -> Result<(), NftablesError> {
        // Prove the live table is still exactly ours before removing anything.
        verify_owned_castle_table_impl(ownership)?;
        run_nft(&[
            "delete",
            "table",
            CASTLE_FAMILY,
            "handle",
            &ownership.table_handle.to_string(),
        ])
        .map(|_| ())
    }

    fn replace_agent_chain_and_jump_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        cgroup_level: u32,
        cgroup_relative_path: &str,
        fail_closed: bool,
    ) -> Result<(), NftablesError> {
        super::verify_active_runtime_ownership()?;
        validate_agent_binding_input(id, cgroup_level, cgroup_relative_path)?;
        let expected_script = if fail_closed {
            build_agent_fail_closed_ruleset(&id.agent_id)
        } else {
            build_agent_ruleset(&id.agent_id, cgroup_relative_path, cgroup_level, &[])
        };
        if ruleset_script != expected_script {
            return Err(NftablesError::InvocationFailed(
                "agent ruleset must be the exact typed NFQUEUE-only lowering; raw nft fragments are forbidden"
                    .to_string(),
            ));
        }
        let chain_name = agent_chain_name(&id.agent_id);
        let castle_table = castle_table();
        let ownership = capture_owned_castle_table_impl_from_live_inventory()?;
        let chain_comment = format!("{}:agent:{}", ownership.marker, id.agent_id);
        let rule_role = if fail_closed { "failclosed" } else { "queue" };
        // GF2: seal the exact installed cgroup path into the authenticated,
        // marker-bound comment of every rule that carries a `socket cgroupv2`
        // match (the base-output jump always; the per-agent body only when it is
        // the queued cgroup match, NOT the fail-closed unconditional drop, which
        // has no cgroup match to seal). `parse_owned_table_inventory` recomputes
        // this seal from the live match path and refuses a re-parented/widened
        // match. Must match the seal the parser recomputes; see `cgroup_path_seal`.
        let path_seal = super::cgroup_path_seal(cgroup_relative_path);
        let queue_comment = if fail_closed {
            format!("{}:{rule_role}:{}", ownership.marker, id.agent_id)
        } else {
            format!(
                "{}:{rule_role}:{}:cg:{}",
                ownership.marker, id.agent_id, path_seal
            )
        };
        let jump_comment = format!("{}:jump:{}:cg:{}", ownership.marker, id.agent_id, path_seal);
        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, castle_table, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                String::new()
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);

        let agent_rule = if fail_closed {
            format!("add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop comment \"{queue_comment}\"\n")
        } else {
            let agent_mark = crate::nfqueue::register_agent_mark(&id.agent_id);
            format!(
                "add rule {CASTLE_FAMILY} {castle_table} {chain_name} socket cgroupv2 level {cgroup_level} \"{cgroup_relative_path}\" meta mark set 0x{agent_mark:08x} queue num 0 comment \"{queue_comment}\"\n"
            )
        };
        // Chain creation/adoption, body replacement, stale-jump removal, and
        // the new jump land in one nft transaction. A crash can therefore
        // expose either the complete prior binding or the complete new one,
        // never an empty agent chain or a half-wired replacement.
        let mut script = format!(
            "add chain {CASTLE_FAMILY} {castle_table} {chain_name} {{ comment \"{chain_comment}\" ; }}\n\
             flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n{agent_rule}"
        );
        for handle in handles {
            script.push_str(&format!(
                "delete rule {CASTLE_FAMILY} {castle_table} output handle {handle}\n"
            ));
        }
        let rule = build_agent_jump_rule(&id.agent_id, cgroup_level, cgroup_relative_path);
        script.push_str(&format!("{rule} comment \"{jump_comment}\"\n"));
        run_nft_stdin(&script)
    }

    fn capture_owned_castle_table_impl_from_live_inventory(
    ) -> Result<CastleTableOwnership, NftablesError> {
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        super::parse_owned_table_identity(&json)
    }

    fn validate_agent_binding_input(
        id: &AgentRulesetId,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        if id.agent_id.is_empty()
            || id.agent_id.len() > 128
            || !id
                .agent_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(NftablesError::InvocationFailed(
                "agent id is outside the typed nft identifier grammar".to_string(),
            ));
        }
        if cgroup_level == 0
            || cgroup_relative_path.is_empty()
            || cgroup_relative_path.starts_with('/')
            || cgroup_relative_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !cgroup_relative_path.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'@' | b':')
            })
        {
            return Err(NftablesError::InvocationFailed(
                "cgroup path/level is outside the typed nft path grammar".to_string(),
            ));
        }
        Ok(())
    }

    pub fn load_agent_ruleset_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        // Atomically replace the per-agent chain body and the base output
        // jump that reaches it. This keeps policy reloads and cgroup refresh
        // from leaking a stale jump to an old cgroup identity.
        replace_agent_chain_and_jump_impl(
            id,
            ruleset_script,
            cgroup_level,
            cgroup_relative_path,
            false,
        )
    }

    pub fn load_agent_fail_closed_ruleset_impl(
        id: &AgentRulesetId,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        let ruleset_script = build_agent_fail_closed_ruleset(&id.agent_id);
        replace_agent_chain_and_jump_impl(
            id,
            &ruleset_script,
            cgroup_level,
            cgroup_relative_path,
            true,
        )
    }

    pub fn remove_agent_ruleset_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        super::verify_active_runtime_ownership()?;
        let chain_name = agent_chain_name(&id.agent_id);
        let castle_table = castle_table();
        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, castle_table, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // Jump deletion, chain flush, and chain deletion are atomic. This is
        // the inverse of replacement above and prevents restart from finding
        // a marker-bound chain without its required jump/body pair.
        let mut script = String::new();
        for handle in parse_jump_rule_handles(&listing, &chain_name) {
            script.push_str(&format!(
                "delete rule {CASTLE_FAMILY} {castle_table} output handle {handle}\n"
            ));
        }
        script.push_str(&format!(
            "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n\
             delete chain {CASTLE_FAMILY} {castle_table} {chain_name}\n"
        ));
        run_nft_stdin(&script)
    }

    /// Install the jump rule from the base `output` chain into this agent's
    /// per-agent chain, gated on the cgroup-v2 socket match. Idempotent:
    /// any prior jump rule pointing at the same agent's chain is removed
    /// (handle-based delete) before the new rule is added. This lets the
    /// function double as both the fresh-install and policy-reload path
    /// without leaking stale jumps.
    pub fn install_agent_jump_rule_impl(
        id: &AgentRulesetId,
        cgroup_level: u32,
        cgroup_relative_path: &str,
    ) -> Result<(), NftablesError> {
        // Drop any existing jump rule for this agent before adding a new
        // one. Failures during the lookup are not fatal here: a missing
        // base chain (table just created, nothing in output yet) returns
        // an error from `nft -a list chain`; the upcoming add will fail
        // with a clearer message if the table is genuinely absent.
        let _ = remove_agent_jump_rule_impl(id);
        let rule = build_agent_jump_rule(&id.agent_id, cgroup_level, cgroup_relative_path);
        let script = format!("{rule}\n");
        run_nft_stdin(&script)
    }

    /// Remove the jump rule from the base `output` chain that targets this
    /// agent's per-agent chain. Idempotent: zero matching rules returns
    /// `Ok(())` rather than an error so policy-reload code paths can call
    /// it unconditionally.
    pub fn remove_agent_jump_rule_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // `-a` annotates each rule with `# handle <N>`; we parse those
        // handles for any rule whose verdict targets our chain.
        let listing = match run_nft(&[
            "-a",
            "list",
            "chain",
            CASTLE_FAMILY,
            castle_table(),
            "output",
        ]) {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                // Base chain absent (table was deleted or never installed).
                // Treat as zero matching rules.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);
        for handle in handles {
            run_nft(&[
                "delete",
                "rule",
                CASTLE_FAMILY,
                castle_table(),
                "output",
                "handle",
                &handle.to_string(),
            ])?;
        }
        Ok(())
    }

    /// Parse `nft -a list chain ... output` output, returning the handle
    /// integer for every rule whose verdict is `goto <chain_name>`. The
    /// match is token-precise (no substring match) so chain names that
    /// share a prefix (`agent_foo`, `agent_foo_bar`) do not collide.
    pub(super) fn parse_jump_rule_handles(listing: &str, chain_name: &str) -> Vec<u64> {
        let mut handles = Vec::new();
        for line in listing.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Find a `goto <chain_name>` token pair. nft also emits `jump`
            // for non-terminating verdicts; we only emit `goto` so we
            // restrict the match to that.
            let has_goto = tokens
                .iter()
                .enumerate()
                .any(|(i, tok)| *tok == "goto" && tokens.get(i + 1) == Some(&chain_name));
            if !has_goto {
                continue;
            }
            // Extract handle from "# handle <N>". `nft -a` always emits
            // both tokens together at the end of the rule line.
            if let Some(handle_idx) = tokens.iter().position(|t| *t == "handle") {
                if handle_idx > 0 && tokens[handle_idx - 1] == "#" {
                    if let Some(handle_tok) = tokens.get(handle_idx + 1) {
                        if let Ok(h) = handle_tok.parse::<u64>() {
                            handles.push(h);
                        }
                    }
                }
            }
        }
        handles
    }

    pub fn list_agent_rulesets_impl() -> Result<Vec<AgentRulesetId>, NftablesError> {
        let output = run_nft(&["list", "chains", CASTLE_FAMILY])?;
        let mut results = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("chain agent_") {
                // Extract chain name between "chain " and the next space or '{'
                if let Some(name) = trimmed
                    .strip_prefix("chain ")
                    .and_then(|s| s.split_whitespace().next())
                {
                    if let Some(agent_id) = name.strip_prefix("agent_") {
                        results.push(AgentRulesetId {
                            agent_id: agent_id.to_string(),
                            cgroup_path: PathBuf::new(),
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    pub fn remove_castle_table_impl() -> Result<(), NftablesError> {
        run_nft(&["delete", "table", CASTLE_FAMILY, castle_table()]).map(|_| ())
    }

    pub fn table_exists_impl() -> Result<bool, NftablesError> {
        match run_nft(&["list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(_) => Ok(true),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    pub fn verify_castle_table_shape_impl() -> Result<(), NftablesError> {
        // List OUR table by exact family+name in STRUCTURED JSON (`nft -j`).
        // Absence is a hard error here: the readiness check runs right after the
        // table is created, so a missing table means the create silently did not
        // take. Structured parsing (not a substring scan) is what lets us tell a
        // base output chain from a same-named regular chain, and a chain in our
        // table from one in a foreign table. (blocker 2)
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        // A table that shares the `sanctuary-castle` name but lacks our exact
        // base-output-chain shape — or carries any foreign base chain — is
        // foreign/incompatible state (another owner, a hand-edited ruleset, a
        // leftover from an incompatible version); adopting it would enforce
        // through — or later clobber — a ruleset we do not own.
        if super::output_chain_shape_is_ours_json(&json) {
            Ok(())
        } else {
            Err(NftablesError::ForeignState(format!(
                "sanctuary-castle table does not have this daemon's exact base output chain \
                 (inet/sanctuary-castle output: type filter hook output priority 0 policy \
                 accept), or carries foreign base-chain state: {}",
                json.trim()
            )))
        }
    }
}

/// Whether an `nft -j list table inet sanctuary-castle` JSON document shows
/// EXACTLY this daemon's base output chain and no foreign base-chain state.
///
/// This is the STRUCTURED replacement for the old substring scan (blocker 2). A
/// substring match cannot distinguish a base chain from a same-named regular
/// chain, cannot tell a chain in OUR table from one in a foreign table (a
/// "split" shape), and can be fooled by comments or unrelated rules. Parsing the
/// nft JSON lets the check be tied to the exact fields.
///
/// Returns true only when a `chain` object exists with ALL of: `family` ==
/// `inet`, `table` == `sanctuary-castle`, `name` == `output`, `type` ==
/// `filter`, `hook` == `output`, `prio` == 0, `policy` == `accept`. It returns
/// FALSE — refuse — for every other shape: an unparseable or empty document
/// (unknown ownership), a table with no base chain, a base chain with the wrong
/// hook / type / priority / a `drop` policy, a chain in a different family or
/// table (split/foreign), or ANY additional base chain (one carrying a `hook`)
/// that is not this exact shape. Refuse is the safe default: absent,
/// indeterminate, and foreign all read as not-ours.
///
/// Pure and cross-platform so the foreign-table refusal is unit-testable without
/// a live kernel (see the adversarial-JSON tests below).
pub fn output_chain_shape_is_ours_json(json: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        // Unparseable -> unknown ownership state -> refuse.
        return false;
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return false;
    };
    let mut found_ours = false;
    for item in items {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        // Only BASE chains carry a `hook`; a regular (non-base) chain has none.
        // A base chain is the only thing that can hook egress, so any base chain
        // present must be exactly ours — a foreign base chain is refusable state.
        let Some(hook) = chain.get("hook").and_then(|v| v.as_str()) else {
            continue;
        };
        let is_ours = chain.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
            && chain.get("table").and_then(|v| v.as_str()) == Some(castle_table())
            && chain.get("name").and_then(|v| v.as_str()) == Some("output")
            && chain.get("type").and_then(|v| v.as_str()) == Some("filter")
            && hook == "output"
            && chain.get("prio").and_then(|v| v.as_i64()) == Some(0)
            && chain.get("policy").and_then(|v| v.as_str()) == Some("accept");
        if is_ours {
            found_ours = true;
        } else {
            // A base chain (has a hook) that is not exactly ours — wrong hook,
            // wrong priority, drop policy, or a split chain whose family/table
            // do not match — is foreign/incompatible state we must refuse rather
            // than enforce through or adopt.
            return false;
        }
    }
    found_ours
}

/// GF1.1: whether an `nft -j list table inet sanctuary-castle` JSON document is
/// EXACTLY this daemon's deny-all safety net (`install_deny_all_safety_net_impl`
/// output): one `inet/sanctuary-castle` table with NO owner marker comment, one
/// base `output` chain (`type filter hook output priority 0`, `policy DROP`), and
/// NOTHING else -- zero rules, zero agent chains, zero sets/maps.
///
/// This is the recognizer for the create-failure recovery state. When the
/// authenticated journal is `Preparing` for THIS boot but `capture` fails, the
/// live table being this exact fail-CLOSED net (never any shape the owned path
/// emits, which is always `policy accept`) is what distinguishes "our own
/// half-finished acquisition that ReArmLostOwned armed" from a foreign table.
/// Combined with the authenticated Preparing-this-boot journal at the call site,
/// it is the "this boot + source" proof that the daemon created this net, so
/// recovery may reset/clear it. Residual (a foreign actor swapping in an
/// identical-shape `policy drop` net in the window) is the inherent CAP_NET_ADMIN
/// bound documented on `install_deny_all_safety_net_impl` (GF1.4), and is
/// fail-CLOSED either way.
///
/// Pure and cross-platform so the recognizer is unit-testable without a kernel.
pub fn is_deny_all_safety_net_json(json: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return false;
    };
    let mut saw_table = false;
    let mut saw_drop_base_chain = false;
    for item in items {
        let Some(obj) = item.as_object() else {
            return false;
        };
        if obj.len() != 1 {
            return false;
        }
        for (kind, val) in obj {
            match kind.as_str() {
                "metainfo" => {}
                "table" => {
                    if saw_table {
                        return false; // more than one table object
                    }
                    let ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("name").and_then(|v| v.as_str()) == Some(castle_table());
                    // The net is UNMARKED by construction; an owner marker here
                    // means this is NOT the bare safety net (it would be a captured
                    // owned table, handled by the normal parser instead).
                    let has_owner_marker = val
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .is_some_and(|c| c.starts_with(OWNER_MARKER_PREFIX));
                    if !ours || has_owner_marker {
                        return false;
                    }
                    saw_table = true;
                }
                "chain" => {
                    if saw_drop_base_chain {
                        return false; // more than one chain
                    }
                    let is_deny_all_base = val.get("family").and_then(|v| v.as_str())
                        == Some(CASTLE_FAMILY)
                        && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                        && val.get("name").and_then(|v| v.as_str()) == Some("output")
                        && val.get("type").and_then(|v| v.as_str()) == Some("filter")
                        && val.get("hook").and_then(|v| v.as_str()) == Some("output")
                        && val.get("prio").and_then(|v| v.as_i64()) == Some(0)
                        && val.get("policy").and_then(|v| v.as_str()) == Some("drop");
                    if !is_deny_all_base {
                        return false;
                    }
                    saw_drop_base_chain = true;
                }
                // A rule, agent chain, set, map, flowtable, or any other object
                // means this is NOT the bare deny-all net.
                _ => return false,
            }
        }
    }
    saw_table && saw_drop_base_chain
}

/// Build the atomic nft script that CREATES the owned table + its base output
/// chain using nft's fail-on-exists `create` verbs, stamping `marker` as the
/// table comment. Pure/cross-platform so the "uses `create`, never `add`" and
/// marker-embedding invariants are unit-testable without a kernel. (blocker 1)
///
/// Production-used only on Linux (the acquisition path), but exercised by the
/// cross-platform tests, so gated to `any(target_os = "linux", test)` to avoid a
/// dead-code diagnostic under `clippy -D warnings` on the macOS dev lib build.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn build_create_castle_table_script(marker: &str) -> String {
    let castle_table = castle_table();
    // `create` (not `add`): fails the whole transaction if the table/chain
    // already exists, so a raced or foreign same-named table is refused, never
    // adopted or mutated.
    format!(
        "create table {CASTLE_FAMILY} {castle_table} {{ comment \"{marker}\" ; }}\n\
         create chain {CASTLE_FAMILY} {castle_table} output \
         {{ type filter hook output priority 0 ; policy accept ; }}\n"
    )
}

/// Parse `nft -j list table inet sanctuary-castle` into the EXACT owned identity,
/// or reject the whole document as foreign/incompatible. (blocker 2)
///
/// This is stricter than [`output_chain_shape_is_ours_json`] on purpose: that
/// helper only asks "is a correct base output chain present?" and ignores rule
/// objects and regular (non-base) chains, so it would accept a table carrying
/// injected rules, extra chains, or a same-shape delete/recreate. This parser
/// instead requires the document to contain EXACTLY the pristine L2 slice:
///
/// * exactly one `table` object — family `inet`, name `sanctuary-castle`, with a
///   `comment` marker that begins with [`OWNER_MARKER_PREFIX`];
/// * exactly one base output chain, plus zero or more marker-bound `agent_*`
///   chains created by the typed mutation path;
/// * only marker-bound queue/jump rules in those chains; no other nft object.
///
/// Any deviation returns [`NftablesError::ForeignState`]. On success it returns
/// the captured [`CastleTableOwnership`] (both handles + the marker), which the
/// caller binds so a later `nft -j` that no longer matches this exact tuple —
/// including a same-shape replacement whose handles changed — is refused.
///
/// Pure and cross-platform so the exact-ownership refusal is unit-testable
/// without a live kernel (see the adversarial-JSON tests below).
fn has_exact_keys(value: &serde_json::Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

/// GF2 per-agent isolation seal: a fixed-length, domain-separated digest of the
/// EXACT cgroup-v2 path the daemon installed for one agent's `socket cgroupv2`
/// match. It is embedded in the marker-bound rule COMMENT (`:cg:<seal>`) so
/// verification can reject a re-parented/widened match (same leaf, different
/// parent — e.g. `other.slice/sanctuary-agent-x.service`) that the leaf-only pin
/// accepted while the real agent's traffic missed the goto and hit `policy
/// accept`.
///
/// Why a digest, not the raw path: nft caps a comment at 128 bytes (confirmed nft
/// 1.0.9), and `{marker}:queue:{agent_id}` already consumes most of that, so the
/// path is sealed by its 64-bit digest. Why UNKEYED: the pure parser has no key,
/// and the security level is deliberately exactly that of every other rule-shape
/// check. An in-place expression mutation (the natural GF2 attack: rewrite only
/// the `socket cgroupv2` path) leaves this comment intact, so the recomputed
/// digest no longer matches and the rule is refused; only an actor that
/// reconstructs a full marker-bound comment can evade it, which is the inherent
/// CAP_NET_ADMIN nft threat boundary (see the GF1.4 note on
/// `install_deny_all_safety_net_impl`), the same bar the ownership marker sets.
/// 64 bits makes a second-preimage (a different path with the same seal AND the
/// agent's own leaf) computationally infeasible.
///
/// Pure and cross-platform (used by both the linux emission site and the pure
/// parser, and by the adversarial-JSON tests) so it must not be linux-gated.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn cgroup_path_seal(cgroup_relative_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Domain separation: this digest is never interchangeable with any other
    // SHA-256 use in the daemon (WAL chaining, manifest hashing).
    hasher.update(b"sanctuary-castle:cgroup-path-seal:v1\0");
    hasher.update(cgroup_relative_path.as_bytes());
    let digest = hasher.finalize();
    // 8 bytes = 16 lowercase hex chars: the whole `:cg:<seal>` suffix is 20 bytes,
    // leaving comment headroom under nft's 128-byte cap for the marker + agent id.
    hex::encode(&digest[..8])
}

fn parse_cgroup_match(expr: &serde_json::Value) -> Option<(u32, String)> {
    if !has_exact_keys(expr, &["match"]) {
        return None;
    }
    let matched = expr.get("match")?;
    if !has_exact_keys(matched, &["op", "left", "right"])
        || !has_exact_keys(matched.get("left")?, &["socket"])
    {
        return None;
    }
    if matched.get("op")?.as_str()? != "==" {
        return None;
    }
    let socket = matched.get("left")?.get("socket")?;
    // nft's JSON serializer for the cgroupv2 socket match omits the `level`
    // field on some builds: confirmed on nft 1.0.9 / Ubuntu 24.04 (kernel 6.8),
    // where a rule loaded with `socket cgroupv2 level 1 "system.slice"` round-
    // trips as {"socket":{"key":"cgroupv2"}} with no `level`. Accept BOTH the
    // level-present and level-absent shapes, and no other socket keys, so a
    // foreign socket match (extra keys or a non-cgroupv2 key) is still rejected.
    let level_present = if has_exact_keys(socket, &["key", "level"]) {
        true
    } else if has_exact_keys(socket, &["key"]) {
        false
    } else {
        return None;
    };
    if socket.get("key")?.as_str()? != "cgroupv2" {
        return None;
    }
    let path = matched.get("right")?.as_str()?.to_string();
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'@' | b':')
        })
    {
        return None;
    }
    // `level` is redundant with the path: nft requires the level to equal the
    // path's component count at load time, so ownership is fully keyed by the
    // marker-bound table + exact rule body + validated path, never by `level`.
    // When nft omits it, reconstruct the depth from the already-validated path
    // (no leading slash, no empty components) so the level-present and level-
    // absent shapes yield the identical owned-binding tuple that body/jump
    // agreement is checked against.
    let level = if level_present {
        let explicit = u32::try_from(socket.get("level")?.as_u64()?).ok()?;
        if explicit == 0 {
            return None;
        }
        explicit
    } else {
        u32::try_from(path.split('/').count()).ok()?
    };
    Some((level, path))
}

fn parse_mark_assignment(expr: &serde_json::Value) -> Option<u32> {
    if !has_exact_keys(expr, &["mangle"]) {
        return None;
    }
    let mangle = expr.get("mangle")?;
    if !has_exact_keys(mangle, &["key", "value"])
        || !has_exact_keys(mangle.get("key")?, &["meta"])
        || !has_exact_keys(mangle.get("key")?.get("meta")?, &["key"])
    {
        return None;
    }
    if mangle.get("key")?.get("meta")?.get("key")?.as_str()? != "mark" {
        return None;
    }
    u32::try_from(mangle.get("value")?.as_u64()?).ok()
}

fn validate_owned_body_expr(
    expr: &serde_json::Value,
    agent_id: &str,
    fail_closed: bool,
) -> Result<Option<(u32, String)>, NftablesError> {
    let terms = expr.as_array().ok_or_else(|| {
        NftablesError::ForeignState("owned agent body has no expression array".to_string())
    })?;
    if fail_closed {
        if terms.len() == 1
            && has_exact_keys(&terms[0], &["drop"])
            && terms[0].get("drop").is_some_and(serde_json::Value::is_null)
        {
            return Ok(None);
        }
        return Err(NftablesError::ForeignState(
            "fail-closed agent body is not one unconditional drop".to_string(),
        ));
    }
    if terms.len() != 3 {
        return Err(NftablesError::ForeignState(
            "queued agent body is not the exact cgroup/mark/queue expression".to_string(),
        ));
    }
    let binding = parse_cgroup_match(&terms[0]).ok_or_else(|| {
        NftablesError::ForeignState("queued agent body has no typed cgroup match".to_string())
    })?;
    if parse_mark_assignment(&terms[1]) != Some(crate::nfqueue::agent_mark(agent_id)) {
        return Err(NftablesError::ForeignState(
            "queued agent body does not set the derived attribution mark".to_string(),
        ));
    }
    if !has_exact_keys(&terms[2], &["queue"])
        || !has_exact_keys(
            terms[2].get("queue").unwrap_or(&serde_json::Value::Null),
            &["num"],
        )
        || terms[2]
            .get("queue")
            .and_then(|queue| queue.get("num"))
            .and_then(|num| num.as_u64())
            != Some(0)
    {
        return Err(NftablesError::ForeignState(
            "queued agent body does not terminate at NFQUEUE 0".to_string(),
        ));
    }
    Ok(Some(binding))
}

fn validate_owned_jump_expr(
    expr: &serde_json::Value,
    expected_chain: &str,
) -> Result<(u32, String), NftablesError> {
    let terms = expr.as_array().ok_or_else(|| {
        NftablesError::ForeignState("owned output jump has no expression array".to_string())
    })?;
    if terms.len() != 2 {
        return Err(NftablesError::ForeignState(
            "owned output jump is not the exact cgroup/jump expression".to_string(),
        ));
    }
    let binding = parse_cgroup_match(&terms[0]).ok_or_else(|| {
        NftablesError::ForeignState("owned output jump has no typed cgroup match".to_string())
    })?;
    // Must match `build_agent_jump_rule` and `parse_jump_rule_handles`: the base
    // output rule routes the agent cgroup with a `goto` (a TERMINATING verdict,
    // so control never returns to the accept-policy base chain), which nft JSON
    // keys as `"goto"`, NOT `"jump"`. Checking `"jump"` here rejected the
    // daemon's OWN base-output rule, so every capture/verify of an owned table
    // already carrying a wired agent goto failed as "wrong agent chain" (the
    // second agent load, and production reclaim/verify once an agent is wired).
    // The verb this validator accepts MUST equal the verb the builder emits;
    // `parse_jump_rule_handles` documents the same "only goto" contract.
    if !has_exact_keys(&terms[1], &["goto"])
        || !has_exact_keys(
            terms[1].get("goto").unwrap_or(&serde_json::Value::Null),
            &["target"],
        )
        || terms[1]
            .get("goto")
            .and_then(|goto| goto.get("target"))
            .and_then(|target| target.as_str())
            != Some(expected_chain)
    {
        return Err(NftablesError::ForeignState(
            "owned output jump targets the wrong agent chain".to_string(),
        ));
    }
    Ok(binding)
}

struct ParsedOwnedTableInventory {
    ownership: CastleTableOwnership,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    agent_ids: Vec<String>,
}

fn parse_owned_table_inventory(json: &str) -> Result<ParsedOwnedTableInventory, NftablesError> {
    let doc: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| NftablesError::ForeignState(format!("nft -j output did not parse: {e}")))?;
    let items = doc
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            NftablesError::ForeignState("nft -j output has no `nftables` array".to_string())
        })?;

    let mut table_handle: Option<u64> = None;
    let mut marker: Option<String> = None;
    let mut base_chain_handle: Option<u64> = None;
    let mut agent_chains = std::collections::HashMap::<String, String>::new();
    let mut owned_rules: Vec<(String, String, serde_json::Value)> = Vec::new();

    // Resolve the authenticated acquisition marker first; nft JSON ordering is
    // not a contract and later chain/rule validation depends on it.
    let table_values: Vec<&serde_json::Value> =
        items.iter().filter_map(|item| item.get("table")).collect();
    if table_values.len() != 1 {
        return Err(NftablesError::ForeignState(
            "expected exactly one owned table object".to_string(),
        ));
    }
    let expected_marker = table_values[0]
        .get("comment")
        .and_then(|value| value.as_str())
        .filter(|value| value.starts_with(OWNER_MARKER_PREFIX))
        .ok_or_else(|| {
            NftablesError::ForeignState("owned table has no valid ownership marker".to_string())
        })?
        .to_string();

    for item in items {
        let obj = item.as_object().ok_or_else(|| {
            NftablesError::ForeignState("nft -j item was not an object".to_string())
        })?;
        // Each nft -j item is a single-key object keyed by its kind.
        if obj.len() != 1 {
            return Err(NftablesError::ForeignState(
                "nft -j inventory item must contain exactly one object kind".to_string(),
            ));
        }
        for (kind, val) in obj {
            match kind.as_str() {
                // Ruleset metadata: not part of the owned shape.
                "metainfo" => {}
                "table" => {
                    if table_handle.is_some() {
                        return Err(NftablesError::ForeignState(
                            "more than one table object present".to_string(),
                        ));
                    }
                    let ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("name").and_then(|v| v.as_str()) == Some(castle_table());
                    if !ours {
                        return Err(NftablesError::ForeignState(
                            "a table object is not inet/sanctuary-castle".to_string(),
                        ));
                    }
                    let handle = val.get("handle").and_then(|v| v.as_u64()).ok_or_else(|| {
                        NftablesError::ForeignState("owned table has no handle".to_string())
                    })?;
                    // The marker is the ownership proof: a foreign same-named
                    // table cannot carry our random nonce, and its absence means
                    // "not created by this acquisition path."
                    let comment = val.get("comment").and_then(|v| v.as_str()).ok_or_else(|| {
                        NftablesError::ForeignState(
                            "sanctuary-castle table carries no ownership marker comment"
                                .to_string(),
                        )
                    })?;
                    if !comment.starts_with(OWNER_MARKER_PREFIX) {
                        return Err(NftablesError::ForeignState(
                            "table comment is not a sanctuary ownership marker".to_string(),
                        ));
                    }
                    table_handle = Some(handle);
                    marker = Some(comment.to_string());
                }
                "chain" => {
                    let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if name.starts_with(AGENT_CHAIN_PREFIX) {
                        let comment = val.get("comment").and_then(|v| v.as_str()).unwrap_or("");
                        let agent_id = comment
                            .strip_prefix(&format!("{}:agent:", expected_marker))
                            .filter(|id| !id.is_empty())
                            .unwrap_or("");
                        let agent_id_is_typed = agent_id.len() <= 128
                            && agent_id.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            });
                        let is_agent_chain = val.get("family").and_then(|v| v.as_str())
                            == Some(CASTLE_FAMILY)
                            && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                            && agent_chain_name(agent_id) == name
                            && agent_id_is_typed
                            && val.get("hook").is_none()
                            && val.get("policy").is_none();
                        if !is_agent_chain
                            || agent_chains
                                .insert(name.to_string(), agent_id.to_string())
                                .is_some()
                        {
                            return Err(NftablesError::ForeignState(
                                "invalid or duplicate marker-bound agent chain".to_string(),
                            ));
                        }
                        continue;
                    }
                    if base_chain_handle.is_some() {
                        return Err(NftablesError::ForeignState(
                            "more than one base output chain present".to_string(),
                        ));
                    }
                    // Must be EXACTLY our base output chain. A regular (non-base,
                    // hookless) chain, a wrong hook/prio/policy, or a split
                    // family/table all fail here.
                    let is_ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                        && val.get("name").and_then(|v| v.as_str()) == Some("output")
                        && val.get("type").and_then(|v| v.as_str()) == Some("filter")
                        && val.get("hook").and_then(|v| v.as_str()) == Some("output")
                        && val.get("prio").and_then(|v| v.as_i64()) == Some(0)
                        && val.get("policy").and_then(|v| v.as_str()) == Some("accept");
                    if !is_ours {
                        return Err(NftablesError::ForeignState(
                            "the sole chain is not this daemon's exact base output chain"
                                .to_string(),
                        ));
                    }
                    let handle = val.get("handle").and_then(|v| v.as_u64()).ok_or_else(|| {
                        NftablesError::ForeignState("owned base chain has no handle".to_string())
                    })?;
                    base_chain_handle = Some(handle);
                }
                "rule" => {
                    let family_ok =
                        val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY);
                    let table_ok =
                        val.get("table").and_then(|v| v.as_str()) == Some(castle_table());
                    let chain = val.get("chain").and_then(|v| v.as_str()).unwrap_or("");
                    let comment = val.get("comment").and_then(|v| v.as_str()).unwrap_or("");
                    let marker_bound = comment.starts_with(&format!("{}:", expected_marker));
                    let known_chain = chain == "output" || chain.starts_with(AGENT_CHAIN_PREFIX);
                    if !family_ok || !table_ok || !marker_bound || !known_chain {
                        return Err(NftablesError::ForeignState(
                            "unowned or malformed rule in owned table inventory".to_string(),
                        ));
                    }
                    owned_rules.push((
                        chain.to_string(),
                        comment.to_string(),
                        val.get("expr").cloned().unwrap_or(serde_json::Value::Null),
                    ));
                }
                // ANY other object kind (rule, set, map, flowtable, element, …)
                // is foreign to the owned L2 inventory. Table, chain, and rule
                // are handled above; sets/maps/flowtables/elements are never an
                // implicit extension of the authenticated ownership claim.
                other => {
                    return Err(NftablesError::ForeignState(format!(
                        "unexpected nft object `{other}` in sanctuary-castle table \
                         (expected only the marker-bound table/chains/rules inventory)"
                    )));
                }
            }
        }
    }

    let table_handle = table_handle.ok_or_else(|| {
        NftablesError::ForeignState("no owned sanctuary-castle table object present".to_string())
    })?;
    let marker = marker.ok_or_else(|| {
        NftablesError::ForeignState("owned table has no ownership marker".to_string())
    })?;
    let base_chain_handle = base_chain_handle.ok_or_else(|| {
        NftablesError::ForeignState("no owned base output chain present".to_string())
    })?;
    let mut body_counts = std::collections::HashMap::<String, usize>::new();
    let mut jump_counts = std::collections::HashMap::<String, usize>::new();
    let mut cgroup_bindings = std::collections::HashMap::<String, (u32, String)>::new();
    for (chain, comment, expr) in owned_rules {
        let is_jump = chain == "output";
        let fail_closed = !is_jump && comment.contains(":failclosed:");
        // Strip the marker-bound role prefix. The remainder is `{agent_id}` for a
        // fail-closed unconditional-drop body (no cgroup match to seal) or
        // `{agent_id}:cg:{seal}` for any rule carrying a `socket cgroupv2` match
        // (the base-output jump, and the queued per-agent body). See GF2 below.
        let remainder = if is_jump {
            comment.strip_prefix(&format!("{}:jump:", expected_marker))
        } else {
            comment
                .strip_prefix(&format!("{}:queue:", expected_marker))
                .or_else(|| comment.strip_prefix(&format!("{}:failclosed:", expected_marker)))
        }
        .filter(|rest| !rest.is_empty())
        .ok_or_else(|| {
            NftablesError::ForeignState("owned rule comment has wrong role binding".to_string())
        })?;
        // Separate the agent id from the authenticated cgroup-path seal. Agent ids
        // are the typed identifier grammar (ASCII alphanumeric / `-` / `_`, no
        // `:`), so the FIRST `:cg:` is always the seal delimiter and everything
        // before it is the agent id.
        let (agent_id, declared_seal) = match remainder.split_once(":cg:") {
            Some((id, seal)) => (id, Some(seal)),
            None => (remainder, None),
        };
        if agent_id.is_empty() {
            return Err(NftablesError::ForeignState(
                "owned rule comment has an empty agent id".to_string(),
            ));
        }
        let expected_chain = agent_chain_name(agent_id);
        if agent_chains.get(&expected_chain).map(String::as_str) != Some(agent_id)
            || (chain != "output" && chain != expected_chain)
        {
            return Err(NftablesError::ForeignState(
                "owned rule does not bind to its declared agent chain".to_string(),
            ));
        }
        let binding = if is_jump {
            Some(validate_owned_jump_expr(&expr, &expected_chain)?)
        } else {
            validate_owned_body_expr(&expr, agent_id, fail_closed)?
        };
        // GF2 per-agent isolation invariant: bind ownership to the EXACT per-agent
        // cgroup, not merely to an internally-consistent pair of rules. The
        // body/jump agreement below proves the two rules match EACH OTHER; it does
        // NOT prove they match the AGENT they claim. A CAP_NET_ADMIN actor can
        // rewrite BOTH the base jump `goto` and the per-agent body cgroup match to
        // a PARENT scope (e.g. `other.slice/sanctuary-agent-x.service`, same leaf,
        // wrong parent), keep the marker and pristine shape, and read as "owned"
        // while the real agent's traffic misses the goto and hits `policy accept`.
        // The old pin compared only the path LEAF (`scope_unit_name(agent_id)`) and
        // so accepted a same-leaf re-parent. Every rule carrying a cgroup match now
        // seals its EXACT installed path into the marker-bound comment; the live
        // match path must hash to that seal. A mismatch (any re-parent/widening) is
        // refused, which via verify_owned_castle_table / reclaim verification
        // withdraws readiness or re-arms deny-all upstream (GF1).
        if let Some((_level, ref expr_path)) = binding {
            let declared_seal = declared_seal.ok_or_else(|| {
                NftablesError::ForeignState(
                    "a cgroup-matching owned rule carries no authenticated cgroup-path seal"
                        .to_string(),
                )
            })?;
            // GF2 (round-3 re-gate) fail-closed on a numeric match value: an
            // all-digit match is nft's RESOLVED cgroup-id display form, shown when
            // the path no longer resolves (a DESTROYED agent cgroup) OR when an
            // in-place expr mutation replaces the sealed path with a numeric form
            // to DODGE the seal comparison below. Those two are indistinguishable
            // from the dump, and the seal exists precisely to defend against an
            // in-place match mutation, so a numeric match for an owned binding is
            // never trustworthy: it must be refused as ForeignState (fail-closed),
            // NOT skipped past the seal check. Skipping it let the exact attack the
            // seal defends against read as "owned" whenever the mutated match was
            // numeric while body/jump still agreed. Refusing it withdraws readiness
            // / re-arms the GF1 deny-all upstream. The legitimate destroyed-cgroup
            // rule matches no traffic, so failing it closed and re-arming deny-all
            // is safe (nothing escapes); the owned table is re-adopted with a fresh,
            // path-sealed binding on the next restart. INVARIANT: a live owned
            // per-agent binding must always carry a verifiable full-path seal; a
            // numeric-form match value never proves the owned per-agent binding.
            let expr_is_resolved_numeric =
                !expr_path.is_empty() && expr_path.bytes().all(|b| b.is_ascii_digit());
            if expr_is_resolved_numeric {
                return Err(NftablesError::ForeignState(format!(
                    "agent {agent_id:?} cgroup match {expr_path:?} is a numeric resolved-id \
                     form, not a verifiable full-path seal; a live owned per-agent binding \
                     must carry its sealed cgroup path, so a numeric-form match is refused \
                     fail-closed (re-arming deny-all), never adopted as owned"
                )));
            }
            if cgroup_path_seal(expr_path) != declared_seal {
                return Err(NftablesError::ForeignState(format!(
                    "agent {agent_id:?} cgroup match {expr_path:?} does not match its \
                     authenticated cgroup-path seal; a widened or re-parented match is not \
                     the owned per-agent binding"
                )));
            }
        } else if declared_seal.is_some() {
            // A non-cgroup-matching body (the fail-closed unconditional drop) must
            // NOT carry a path seal: a seal there is a malformed/foreign comment.
            return Err(NftablesError::ForeignState(
                "a fail-closed owned rule must not carry a cgroup-path seal".to_string(),
            ));
        }
        if let Some(binding) = binding {
            if let Some(prior) = cgroup_bindings.insert(agent_id.to_string(), binding.clone()) {
                if prior != binding {
                    return Err(NftablesError::ForeignState(
                        "owned body and output jump disagree on cgroup binding".to_string(),
                    ));
                }
            }
        }
        let counts = if is_jump {
            &mut jump_counts
        } else {
            &mut body_counts
        };
        *counts.entry(agent_id.to_string()).or_default() += 1;
    }
    // The marker is an authenticated inventory root: every declared agent
    // chain must have exactly one marker-bound body rule and exactly one
    // marker-bound output jump, and there may be no orphan rule. This makes a
    // complete legitimate multi-agent table reclaimable after restart while
    // refusing partial/crashed or foreign compositions.
    for agent_id in agent_chains.values() {
        if body_counts.get(agent_id) != Some(&1) || jump_counts.get(agent_id) != Some(&1) {
            return Err(NftablesError::ForeignState(format!(
                "agent {agent_id:?} does not have exactly one owned body rule and one owned jump"
            )));
        }
    }
    let mut agent_ids: Vec<String> = agent_chains.into_values().collect();
    agent_ids.sort_unstable();
    Ok(ParsedOwnedTableInventory {
        ownership: CastleTableOwnership {
            table_handle,
            base_chain_handle,
            marker,
        },
        agent_ids,
    })
}

/// Pure parser used by health and ownership checks. Parsing untrusted inventory
/// must never mutate the process-global packet-attribution registry.
pub fn parse_owned_table_identity(json: &str) -> Result<CastleTableOwnership, NftablesError> {
    parse_owned_table_inventory(json).map(|parsed| parsed.ownership)
}

// ---- Public API (platform-dispatching) ------------------------------------

/// Install the dedicated `sanctuary-castle` table if absent.
/// Per scope-lock section 7 E7.2: namespace separation from the operator's
/// existing firewall (ufw, firewalld, etc.).
#[cfg(target_os = "linux")]
pub fn install_castle_table() -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "unowned production table installation is disabled; use the authenticated ownership acquisition path"
                .to_string(),
        ));
    }
    linux::install_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn install_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1 deny-all safety net: force `<castle_table>` to a fail-CLOSED base output
/// chain (`policy drop`, no rules) in one atomic transaction. See
/// [`linux::install_deny_all_safety_net_impl`]. Used by the reclaim/acquire path
/// when the daemon's authenticated ownership journal proves it owned a table
/// this boot but the live table has been LOST or has DRIFTED off its captured
/// identity: deny-all is installed BEFORE the acquisition refuses, so the loop
/// is fail-closed and `policy accept` is never left in force for a live agent.
#[cfg(target_os = "linux")]
pub fn install_deny_all_safety_net() -> Result<(), NftablesError> {
    linux::install_deny_all_safety_net_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn install_deny_all_safety_net() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.1: whether the LIVE table is exactly this daemon's deny-all safety net.
/// See [`linux::live_table_is_deny_all_safety_net_impl`].
#[cfg(target_os = "linux")]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
    linux::live_table_is_deny_all_safety_net_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.1 recovery: atomically reset the deny-all net to a fresh owned table
/// stamped `new_marker`. See [`linux::atomic_reset_deny_all_net_to_fresh_owned_impl`].
#[cfg(target_os = "linux")]
pub fn atomic_reset_deny_all_net_to_fresh_owned(new_marker: &str) -> Result<(), NftablesError> {
    linux::atomic_reset_deny_all_net_to_fresh_owned_impl(new_marker)
}

#[cfg(not(target_os = "linux"))]
pub fn atomic_reset_deny_all_net_to_fresh_owned(_new_marker: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.2 last-resort escalation: delete the `sanctuary-castle` table by name.
/// See [`linux::force_delete_castle_table_by_name_impl`].
#[cfg(target_os = "linux")]
pub fn force_delete_castle_table_by_name() -> Result<(), NftablesError> {
    linux::force_delete_castle_table_by_name_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn force_delete_castle_table_by_name() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Create the `sanctuary-castle` table AND its base output chain in ONE atomic
/// `create` transaction (nft's fail-on-exists verbs), propagating any error.
/// Unlike [`install_castle_table`] (idempotent `add` adopt-or-create), this
/// NEVER touches a pre-existing table: `create` fails the whole transaction if
/// the table already exists, so a `sanctuary-castle` table this acquisition did
/// not create is refused, never mutated or clobbered. `marker` is stamped as the
/// table comment so ownership can later be proven by nonce. (blocker 1)
#[cfg(target_os = "linux")]
pub fn create_castle_table_exclusive(marker: &str) -> Result<(), NftablesError> {
    linux::create_castle_table_exclusive_impl(marker)
}

#[cfg(not(target_os = "linux"))]
pub fn create_castle_table_exclusive(_marker: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Capture the exact owned identity (table + base-chain handles, marker) right
/// after a successful [`create_castle_table_exclusive`], requiring the live
/// marker to equal `expected_marker`. (blocker 3)
#[cfg(target_os = "linux")]
pub fn capture_owned_castle_table(
    expected_marker: &str,
) -> Result<CastleTableOwnership, NftablesError> {
    linux::capture_owned_castle_table_impl(expected_marker)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_owned_castle_table(
    _expected_marker: &str,
) -> Result<CastleTableOwnership, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the live table is STILL exactly the captured owned identity (same
/// handles, marker, and pristine shape). Returns [`NftablesError::ForeignState`]
/// when a same-name replacement, mutation, injected rule, or extra chain has
/// drifted the table off its owned identity, so readiness withdraws. (blocker 2)
#[cfg(target_os = "linux")]
pub fn verify_owned_castle_table(ownership: &CastleTableOwnership) -> Result<(), NftablesError> {
    linux::verify_owned_castle_table_impl(ownership).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_owned_castle_table(_ownership: &CastleTableOwnership) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the exact live inventory and only then rebuild the process-local
/// packet-mark registry needed to reclaim a preserved multi-agent table after
/// restart. This is deliberately separate from the pure health/parser path.
#[cfg(target_os = "linux")]
pub(crate) fn verify_and_register_owned_table_for_reclaim(
    ownership: &CastleTableOwnership,
) -> Result<(), NftablesError> {
    let agent_ids = linux::verify_owned_castle_table_impl(ownership)?;
    for agent_id in agent_ids {
        crate::nfqueue::register_agent_mark(&agent_id);
    }
    Ok(())
}

/// Delete ONLY the exact captured owned table via a handle-qualified delete,
/// after re-verifying the live identity still matches. Refuses (does not delete)
/// if the identity has drifted, so a foreign table squatting the name is never
/// clobbered. (blocker 2/3)
#[cfg(target_os = "linux")]
pub fn remove_owned_castle_table(ownership: &CastleTableOwnership) -> Result<(), NftablesError> {
    linux::remove_owned_castle_table_impl(ownership)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_owned_castle_table(_ownership: &CastleTableOwnership) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Load a ruleset for one agent's cgroup. Atomic replace on the per-agent
/// chain; existing connections preserved per nftables atomic-replace
/// semantics. Also installs (or refreshes) the jump rule in the base
/// `output` chain that gates entry into the per-agent chain on the
/// cgroup-v2 socket match. Without that jump rule the per-agent chain is
/// a dead chain and the kernel never consults it.
///
/// `cgroup_level` is the depth of the agent's cgroup in the cgroup-v2
/// hierarchy (matches `ScopeHandle::cgroup_level`). `cgroup_relative_path`
/// is the path with the `/sys/fs/cgroup/` prefix stripped (matches
/// [`crate::cgroup::cgroup_relative_path`]).
#[cfg(target_os = "linux")]
pub fn load_agent_ruleset(
    id: &AgentRulesetId,
    ruleset: &str,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    linux::load_agent_ruleset_impl(id, ruleset, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_ruleset(
    _id: &AgentRulesetId,
    _ruleset: &str,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Replace an agent ruleset with a fail-closed drop chain and atomically wire
/// the refreshed cgroup jump to that chain. Used during scope recreation
/// before the normal policy ruleset is restored.
#[cfg(target_os = "linux")]
pub fn load_agent_fail_closed_ruleset(
    id: &AgentRulesetId,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    linux::load_agent_fail_closed_ruleset_impl(id, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_fail_closed_ruleset(
    _id: &AgentRulesetId,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove an agent's ruleset (called on agent shutdown / unwrap). Removes
/// the base-chain jump rule first so it does not dangle pointing at a
/// deleted chain, then flushes and deletes the per-agent chain.
#[cfg(target_os = "linux")]
pub fn remove_agent_ruleset(id: &AgentRulesetId) -> Result<(), NftablesError> {
    linux::remove_agent_ruleset_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_ruleset(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Install the jump rule from the base `output` chain into the per-agent
/// chain, gated on the cgroup-v2 socket match. Idempotent: a prior jump
/// rule for the same agent is removed (handle-based delete) before the
/// new one is added.
///
/// Most callers should use [`load_agent_ruleset`], which combines the
/// per-agent chain rules with the jump-rule wiring in one call. This
/// granular surface is exposed for binding code that needs to refresh
/// the jump rule independently (e.g., on a cgroup-id renumbering event
/// where the chain rules have not changed).
#[cfg(target_os = "linux")]
pub fn install_agent_jump_rule(
    id: &AgentRulesetId,
    cgroup_level: u32,
    cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "standalone production jump mutation is disabled; use atomic load_agent_ruleset"
                .to_string(),
        ));
    }
    linux::install_agent_jump_rule_impl(id, cgroup_level, cgroup_relative_path)
}

#[cfg(not(target_os = "linux"))]
pub fn install_agent_jump_rule(
    _id: &AgentRulesetId,
    _cgroup_level: u32,
    _cgroup_relative_path: &str,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the jump rule from the base `output` chain that targets this
/// agent's per-agent chain. Idempotent: zero matching rules returns
/// `Ok(())`.
#[cfg(target_os = "linux")]
pub fn remove_agent_jump_rule(id: &AgentRulesetId) -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "standalone production jump mutation is disabled; use atomic load/remove_agent_ruleset"
                .to_string(),
        ));
    }
    linux::remove_agent_jump_rule_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_jump_rule(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// List current agent rulesets in `sanctuary-castle`.
#[cfg(target_os = "linux")]
pub fn list_agent_rulesets() -> Result<Vec<AgentRulesetId>, NftablesError> {
    linux::list_agent_rulesets_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn list_agent_rulesets() -> Result<Vec<AgentRulesetId>, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the entire `sanctuary-castle` table. Used during daemon shutdown
/// cleanup or in tests.
#[cfg(target_os = "linux")]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "name-only production table removal is disabled; use authenticated --disarm"
                .to_string(),
        ));
    }
    linux::remove_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Check whether the sanctuary-castle table exists.
#[cfg(target_os = "linux")]
pub fn table_exists() -> Result<bool, NftablesError> {
    linux::table_exists_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn table_exists() -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the installed `sanctuary-castle` table has the exact base output-chain
/// shape this daemon installs (`type filter hook output priority 0 ;
/// policy accept ;`). Returns [`NftablesError::ForeignState`] when a table by
/// that name exists but does not match, so the enforcement runtime refuses to
/// adopt or clobber another owner's state rather than reporting ready over it.
/// This is the readiness gate the nftables component uses after install.
#[cfg(target_os = "linux")]
pub fn verify_castle_table_shape() -> Result<(), NftablesError> {
    linux::verify_castle_table_shape_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn verify_castle_table_shape() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Linux L2 deliberately performs no per-rule text lowering.
///
/// Every packet is sent to the typed Rust evaluator, which is the only place
/// where signed rule order, scope, every match axis, prompting, and audit/WAL
/// coupling can be evaluated together.  Emitting even a syntactically safe
/// static accept/drop fragment would allow a later, higher-priority rule to be
/// bypassed and would split first-match semantics across two engines.  Keeping
/// this helper total and inert also removes signed strings from the privileged
/// nft script construction boundary.
pub fn rule_to_nft_expr(_rule: &crate::policy::AllowlistRule) -> Vec<NftRuleFragment> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgroup_match_accepts_absent_level_like_nft_1_0_9() {
        // nft 1.0.9 (Ubuntu 24.04, kernel 6.8) round-trips a rule loaded with
        // `socket cgroupv2 level N "<path>"` WITHOUT the `level` field. Both the
        // level-present shape (newer nft / our own emitter model) and the
        // level-absent shape must parse to the identical owned-binding tuple, or
        // a live daemon on that kernel class fails closed on every adopt.
        let path = "system.slice/sanctuary-agent.scope";
        let with_level = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": 2}}, "right": path}
        });
        let without_level = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv2"}}, "right": path}
        });
        let a = parse_cgroup_match(&with_level).expect("with-level shape parses");
        let b = parse_cgroup_match(&without_level).expect("absent-level shape parses");
        assert_eq!(
            a, b,
            "level-present and level-absent must yield the same owned marker"
        );
        assert_eq!(
            a,
            (2, path.to_string()),
            "depth reconstructed from the 2-component path"
        );

        // Foreign socket matches stay rejected in both shapes: a non-cgroupv2 key,
        // or any extra socket key beyond {key[, level]}, is not our owned rule.
        let wrong_key = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv1"}}, "right": path}
        });
        assert!(
            parse_cgroup_match(&wrong_key).is_none(),
            "non-cgroupv2 key rejected"
        );
        let extra_key = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "foo": 1}}, "right": path}
        });
        assert!(
            parse_cgroup_match(&extra_key).is_none(),
            "extra socket key rejected"
        );
        // An explicit level 0 is still foreign (a real cgroup depth is >= 1).
        let zero_level = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": 0}}, "right": path}
        });
        assert!(
            parse_cgroup_match(&zero_level).is_none(),
            "explicit level 0 rejected"
        );
    }
    use crate::policy::{AllowlistRule, RuleDisposition, RuleMatch, RuleScope};

    // ---- nft binary resolution: absolute-only, no PATH fallback -------------

    #[test]
    fn nft_candidate_paths_are_absolute_with_no_bare_name_fallback() {
        // blocker 9: the candidate list must be absolute-only. A bare `nft`
        // entry would reintroduce PATH resolution for a root daemon's
        // enforcement binary.
        for p in NFT_ABSOLUTE_PATHS {
            assert!(p.starts_with('/'), "nft candidate must be absolute: {p}");
        }
        assert!(
            !NFT_ABSOLUTE_PATHS.contains(&"nft"),
            "no bare-name PATH fallback allowed in the candidate list"
        );
        assert_eq!(
            NFT_ABSOLUTE_PATHS,
            ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        );
    }

    #[test]
    fn resolve_nft_binary_picks_first_executable_and_never_a_bare_name() {
        // None executable -> None (no PATH fallback resurrects a bare `nft`).
        assert_eq!(resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |_| false), None);
        // Only /sbin/nft executable -> picks it, not a PATH search.
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/sbin/nft"),
            Some("/sbin/nft")
        );
        // Arch/Omarchy layout: only /usr/bin/nft present -> resolves it, so the
        // daemon activates on Arch instead of failing to find its enforcement
        // binary. (Arch usr-merges sbin into bin, so nft ships under /usr/bin.)
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/usr/bin/nft"),
            Some("/usr/bin/nft")
        );
        // First candidate wins when several are executable: the sbin path is
        // preferred over the Arch /usr/bin path when both exist.
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |_| true),
            Some("/usr/sbin/nft")
        );
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/sbin/nft"
                || p == "/usr/bin/nft"),
            Some("/sbin/nft"),
            "sbin nft takes precedence over the Arch /usr/bin nft"
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_executable_file_requires_a_regular_file_with_an_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("tool");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let p = f.to_str().unwrap();
        // A non-executable regular file is rejected.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(p));
        // With an exec bit it is accepted.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(p));
        // A directory is not an executable file, and a missing path is rejected.
        assert!(!is_executable_file(dir.path().to_str().unwrap()));
        assert!(!is_executable_file(
            dir.path().join("missing").to_str().unwrap()
        ));
    }

    // ---- foreign-table detection via structured nft -j JSON (no kernel) -----

    /// A realistic `nft -j list table inet sanctuary-castle` document for THIS
    /// daemon's exact base output chain.
    fn ours_json() -> &'static str {
        r#"{"nftables":[
          {"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak","json_schema_version":1}},
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#
    }

    #[test]
    fn our_table_json_is_recognized() {
        assert!(output_chain_shape_is_ours_json(ours_json()));
    }

    #[test]
    fn foreign_drop_policy_json_is_refused() {
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn wrong_hook_json_is_refused() {
        // A base chain hooked on `input` is a foreign base chain, not our egress
        // output hook.
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn wrong_priority_json_is_refused() {
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":10,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn split_family_or_table_json_is_refused() {
        // Right chain name and shape, but a DIFFERENT family — a split/foreign
        // shape the substring scan could not have caught.
        let wrong_family = r#"{"nftables":[
          {"chain":{"family":"ip","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(wrong_family));
        let wrong_table = r#"{"nftables":[
          {"chain":{"family":"inet","table":"someone-else","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(wrong_table));
    }

    #[test]
    fn non_base_chain_only_json_is_refused() {
        // A same-named table whose only chain is a REGULAR (non-base, no hook)
        // chain has no egress hook: foreign state we must not enforce through.
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"somechain","handle":1}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn missing_type_field_json_is_refused() {
        // A base chain (has a hook) missing `type` is not our exact shape.
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn our_chain_plus_a_foreign_base_chain_is_refused() {
        // Our exact output chain PLUS an additional foreign base chain (an
        // `input` hook) is refusable: ANY base chain that is not ours makes the
        // table foreign/incompatible, even when ours is present.
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"intruder","handle":3,
            "type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn empty_or_unparseable_json_is_refused() {
        // Absent, indeterminate, unparseable all read as not-ours (refuse).
        assert!(!output_chain_shape_is_ours_json(""));
        assert!(!output_chain_shape_is_ours_json("not json at all"));
        assert!(!output_chain_shape_is_ours_json("{}"));
        assert!(!output_chain_shape_is_ours_json(r#"{"nftables":[]}"#));
        // A table object with NO chain at all -> no base chain -> refuse.
        assert!(!output_chain_shape_is_ours_json(
            r#"{"nftables":[{"table":{"family":"inet","name":"sanctuary-castle","handle":2}}]}"#
        ));
    }

    // ---- exclusive-create script: `create`, never `add` (blocker 1) --------

    #[test]
    fn exclusive_create_script_uses_create_verbs_never_add() {
        // The acquisition path MUST use nft's fail-on-exists `create` verbs so a
        // raced/foreign same-named table is refused rather than silently adopted.
        // A regression to `add` (idempotent) would reintroduce the adoption hazard.
        let marker = format!("{OWNER_MARKER_PREFIX}deadbeefdeadbeefdeadbeefdeadbeef");
        let script = build_create_castle_table_script(&marker);
        assert!(
            script.contains("create table inet sanctuary-castle"),
            "must create the table with the fail-on-exists `create` verb: {script}"
        );
        assert!(
            script.contains("create chain inet sanctuary-castle output"),
            "must create the base chain with `create`, in the same transaction: {script}"
        );
        // Hard reject `add`: an `add table`/`add chain` here is the exact
        // idempotent-adoption bug this blocker fixes.
        assert!(
            !script.contains("add table") && !script.contains("add chain"),
            "must NEVER use idempotent `add` on the acquisition path: {script}"
        );
        // Exact base output chain shape and the ownership marker comment.
        assert!(script.contains("type filter hook output priority 0 ; policy accept ;"));
        assert!(
            script.contains(&format!("comment \"{marker}\"")),
            "table must carry the ownership marker as its comment: {script}"
        );
    }

    // ---- exact owned-identity parse (blocker 2) ----------------------------

    fn owned_json(table_handle: u64, chain_handle: u64, marker: &str) -> String {
        format!(
            r#"{{"nftables":[
              {{"metainfo":{{"version":"1.0.9","json_schema_version":1}}}},
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":{table_handle},
                "comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "handle":{chain_handle},"type":"filter","hook":"output","prio":0,
                "policy":"accept"}}}}
            ]}}"#
        )
    }

    #[test]
    fn owned_identity_parses_handles_and_marker() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let owned = parse_owned_table_identity(&owned_json(2, 1, &marker)).expect("owned");
        assert_eq!(
            owned,
            CastleTableOwnership {
                table_handle: 2,
                base_chain_handle: 1,
                marker,
            }
        );
    }

    fn owned_agent_json(marker: &str, include_body: bool, include_jump: bool) -> String {
        let chain = agent_chain_name("agent-one");
        let mark = crate::nfqueue::agent_mark("agent-one");
        // GF2: the installed cgroup match must target THIS agent's own scope
        // unit (`scope_unit_name("agent-one")`), not an arbitrary/parent path,
        // and the marker-bound comment carries the authenticated seal of that
        // exact path (`:cg:<seal>`) that the parser recomputes from the live
        // match. The fixture mirrors the exact `cgroup_path_seal` the production
        // emission site writes.
        let cgroup_path = "system.slice/sanctuary-agent-agent-one.service";
        let seal = cgroup_path_seal(cgroup_path);
        let cgroup_match = r#""match":{"op":"==","left":{"socket":{"key":"cgroupv2","level":2}},"right":"system.slice/sanctuary-agent-agent-one.service"}"#;
        let body = if include_body {
            format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"{chain}","handle":10,"comment":"{marker}:queue:agent-one:cg:{seal}","expr":[{{{cgroup_match}}},{{"mangle":{{"key":{{"meta":{{"key":"mark"}}}},"value":{mark}}}}},{{"queue":{{"num":0}}}}]}}}}"#
            )
        } else {
            String::new()
        };
        let jump = if include_jump {
            format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":11,"comment":"{marker}:jump:agent-one:cg:{seal}","expr":[{{{cgroup_match}}},{{"goto":{{"target":"{chain}"}}}}]}}}}"#
            )
        } else {
            String::new()
        };
        format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"{chain}","handle":9,
                "comment":"{marker}:agent:agent-one"}}}}{body}{jump}
            ]}}"#
        )
    }

    #[test]
    fn ordinary_inventory_parsing_is_pure_and_reclaim_metadata_is_complete() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let mark = crate::nfqueue::agent_mark("agent-one");
        let before = crate::nfqueue::resolve_agent_mark(mark);
        let parsed = parse_owned_table_inventory(&owned_agent_json(&marker, true, true))
            .expect("complete inventory");
        assert_eq!(parsed.agent_ids, vec!["agent-one".to_string()]);
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            before,
            "health/parser calls must not mutate global NFQUEUE attribution; only the \
             serialized authenticated reclaim path may restore these IDs"
        );
    }

    #[test]
    fn owned_inventory_refuses_parent_cgroup_path_widening() {
        // GF2 fault injection: a CAP_NET_ADMIN actor rewrites BOTH the base jump
        // and the per-agent body cgroup match to a PARENT scope (`system.slice`),
        // keeping the ownership marker, the pristine shape, and body/jump
        // agreement intact. Pre-GF2 this read as "owned" (over-broad attribution
        // of every process in the parent). The per-agent path pin must now reject
        // it: the match leaf no longer equals the agent's own scope unit.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let widened = owned_agent_json(&marker, true, true).replace(
            "system.slice/sanctuary-agent-agent-one.service",
            "system.slice",
        );
        let err = parse_owned_table_identity(&widened).unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "a widened parent-cgroup match must be refused as foreign, got: {err:?}"
        );
        // The pristine (correct-leaf) inventory still parses: the pin rejects
        // ONLY the widening, never the legitimate per-agent binding.
        parse_owned_table_identity(&owned_agent_json(&marker, true, true))
            .expect("the correct per-agent binding must still parse");
    }

    #[test]
    fn owned_inventory_refuses_same_leaf_wrong_parent_cgroup_path() {
        // GF2 (round-2 re-gate) fault injection: the wrong-PARENT-SAME-LEAF case
        // the leaf-only pin missed. A CAP_NET_ADMIN actor rewrites BOTH the base
        // jump and the per-agent body cgroup match to `other.slice/<same-leaf>`,
        // keeping the marker, pristine shape, body/jump agreement, AND the exact
        // agent scope-unit leaf. The pre-round-2 leaf comparison accepted this
        // (`installed_leaf == expected_leaf`) while the real agent's traffic under
        // `system.slice/<leaf>` missed the goto and hit `policy accept`. The
        // full-path seal must now reject it: the re-parented match hashes to a
        // different seal than the authenticated `:cg:` in the marker-bound comment.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let reparented = owned_agent_json(&marker, true, true).replace(
            "system.slice/sanctuary-agent-agent-one.service",
            "other.slice/sanctuary-agent-agent-one.service",
        );
        // Sanity: the leaf is UNCHANGED, so a leaf-only check would still pass.
        assert!(reparented.contains("other.slice/sanctuary-agent-agent-one.service"));
        let err = parse_owned_table_identity(&reparented).unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "a same-leaf, wrong-parent cgroup match must be refused as foreign, got: {err:?}"
        );
    }

    #[test]
    fn owned_inventory_refuses_missing_or_forged_cgroup_path_seal() {
        // A cgroup-matching rule with its `:cg:` seal stripped is refused (the seal
        // is mandatory), and one whose seal does not match its own path is refused
        // (an in-place expr mutation that forgot to also rewrite the seal).
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let seal = cgroup_path_seal("system.slice/sanctuary-agent-agent-one.service");
        let pristine = owned_agent_json(&marker, true, true);
        // Drop the seal suffix from both cgroup-matching comments.
        let unsealed = pristine.replace(&format!(":cg:{seal}"), "");
        assert!(parse_owned_table_identity(&unsealed).is_err());
        // Replace the seal with a valid-length but wrong digest.
        let wrong = pristine.replace(&seal, "ffffffffffffffff");
        assert!(parse_owned_table_identity(&wrong).is_err());
    }

    #[test]
    fn owned_inventory_refuses_numeric_form_cgroup_match() {
        // GF2 (round-3 re-gate) fault injection: an in-place expr mutation rewrites
        // BOTH the base jump and the per-agent body cgroup match to a numeric
        // resolved-id FORM (nft's display for an unresolvable/destroyed cgroup),
        // keeping the ownership marker, the pristine shape, body/jump agreement, AND
        // the original path's `:cg:` seal in the comment. Pre-round-3 the parser
        // SKIPPED the seal comparison whenever the match was all-digits, so this
        // mutation -- the exact in-place-match attack the seal defends against --
        // read as "owned". The numeric-form match must now be refused as foreign
        // (fail-closed, re-arming GF1 deny-all upstream): a live owned per-agent
        // binding must always carry a verifiable full-path seal.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let numeric = owned_agent_json(&marker, true, true)
            .replace("system.slice/sanctuary-agent-agent-one.service", "12345");
        // Sanity: both match values are now the numeric form, while the sealed
        // comment still carries the original path's seal (the in-place dodge).
        assert!(numeric.contains(r#""right":"12345""#));
        assert!(numeric.contains(":cg:"));
        let err = parse_owned_table_identity(&numeric).unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "a numeric-form cgroup match must be refused as foreign (fail-closed), got: {err:?}"
        );
        // The pristine (real-path, sealed) inventory still parses: the fix rejects
        // ONLY the numeric-form dodge, never the legitimate per-agent binding.
        parse_owned_table_identity(&owned_agent_json(&marker, true, true))
            .expect("the correct per-agent binding must still parse");
    }

    #[test]
    fn deny_all_safety_net_recognizer_accepts_only_the_bare_drop_net() {
        // The exact shape `install_deny_all_safety_net_impl` produces: one unmarked
        // inet/sanctuary-castle table + one base output chain, policy DROP, nothing
        // else. This is the GF1.1 create-failure recovery recognizer.
        let net = r#"{"nftables":[
            {"metainfo":{"version":"1.0.9","json_schema_version":1}},
            {"table":{"family":"inet","name":"sanctuary-castle","handle":7}},
            {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(is_deny_all_safety_net_json(net));

        // A `policy accept` base (the owned shape) is NOT the deny-all net.
        assert!(!is_deny_all_safety_net_json(
            &net.replace("\"drop\"", "\"accept\"")
        ));
        // A table carrying an owner marker is a captured owned table, not the net.
        let marked = net.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"sanctuary-castle-owner:v1:deadbeef\"",
        );
        assert!(!is_deny_all_safety_net_json(&marked));
        // Any extra rule means it is not the BARE net.
        let with_rule = net.replace(
            "\"policy\":\"drop\"}}",
            "\"policy\":\"drop\"}},{\"rule\":{\"family\":\"inet\",\"table\":\"sanctuary-castle\",\"chain\":\"output\",\"handle\":9,\"expr\":[{\"accept\":null}]}}",
        );
        assert!(!is_deny_all_safety_net_json(&with_rule));
        // A wrong family/name table is not ours.
        assert!(!is_deny_all_safety_net_json(
            &net.replace("sanctuary-castle", "sanctuary-castle-test-x")
        ));
        assert!(!is_deny_all_safety_net_json("not json"));
    }

    #[test]
    fn owned_identity_refuses_partial_agent_inventory_after_interrupted_mutation() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        assert!(parse_owned_table_identity(&owned_agent_json(&marker, false, true)).is_err());
        assert!(parse_owned_table_identity(&owned_agent_json(&marker, true, false)).is_err());
        assert!(parse_owned_table_identity(&owned_agent_json(&marker, false, false)).is_err());
    }

    #[test]
    fn owned_identity_refuses_marker_preserving_expression_mutation() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let mut document: serde_json::Value =
            serde_json::from_str(&owned_agent_json(&marker, true, true)).unwrap();
        let items = document["nftables"].as_array_mut().unwrap();
        let body = items
            .iter_mut()
            .find_map(|item| {
                let rule = item.get_mut("rule")?;
                (rule.get("chain")?.as_str()? != "output").then_some(rule)
            })
            .unwrap();
        // Preserve all ownership comments while replacing the cgroup/mark
        // binding with a match-all queue. Comment-only verification would
        // falsely accept this as the owned runtime.
        body["expr"] = serde_json::json!([{ "queue": { "num": 0 } }]);
        assert!(parse_owned_table_identity(&document.to_string()).is_err());
    }

    #[test]
    fn owned_identity_requires_both_table_and_chain_handles() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let missing_table_handle = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "handle":1,"type":"filter","hook":"output","prio":0,"policy":"accept"}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&missing_table_handle).is_err());

        let missing_chain_handle = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,
                "comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&missing_chain_handle).is_err());
    }

    #[test]
    fn owned_identity_refuses_injected_rule() {
        // A rule object in the table is the "injected rule" the weaker shape
        // check ignored; the exact-ownership parser must refuse it.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":9,
                "expr":[{{"accept":null}}]}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json).is_err());
    }

    #[test]
    fn owned_identity_refuses_extra_regular_chain() {
        // A second chain (here a regular, hookless chain) is not the pristine L2
        // slice — refuse even though the base output chain is exactly ours.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"extra","handle":3}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json).is_err());
    }

    #[test]
    fn owned_identity_refuses_foreign_set_object() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"set":{{"family":"inet","table":"sanctuary-castle","name":"s","handle":4}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json).is_err());
    }

    #[test]
    fn owned_identity_refuses_multi_kind_inventory_items() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let mut document: serde_json::Value =
            serde_json::from_str(&owned_json(2, 1, &marker)).unwrap();
        document["nftables"][1]
            .as_object_mut()
            .unwrap()
            .insert("metainfo".to_string(), serde_json::json!({}));
        assert!(parse_owned_table_identity(&document.to_string()).is_err());
    }

    #[test]
    fn owned_identity_refuses_missing_or_foreign_marker() {
        // No comment at all -> not created by us.
        let no_comment = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(parse_owned_table_identity(no_comment).is_err());
        // A comment that is not our marker prefix -> foreign.
        let foreign_comment = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"someone else"}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(parse_owned_table_identity(foreign_comment).is_err());
    }

    #[test]
    fn owned_identity_of_a_same_shape_recreate_differs_by_handle() {
        // The raced/replaced case: a delete+recreate of a same-shaped table gets
        // NEW handles from nft. The parsed identity therefore differs, so a
        // verify against the captured tuple (handle-bound) refuses it. This is
        // what makes "same-shape replacement withdraws readiness" hold.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let first = parse_owned_table_identity(&owned_json(2, 1, &marker)).unwrap();
        let recreated = parse_owned_table_identity(&owned_json(7, 5, &marker)).unwrap();
        assert_ne!(
            first, recreated,
            "a same-shape recreate must not compare equal to the captured identity"
        );
    }

    #[test]
    fn owned_identity_refuses_unparseable_or_empty() {
        assert!(parse_owned_table_identity("").is_err());
        assert!(parse_owned_table_identity("{}").is_err());
        assert!(parse_owned_table_identity(r#"{"nftables":[]}"#).is_err());
    }

    fn make_rule(
        id: &str,
        host: Option<Vec<&str>>,
        port: Option<Vec<u16>>,
        proto: Option<&str>,
        disposition: RuleDisposition,
    ) -> AllowlistRule {
        AllowlistRule {
            id: id.to_string(),
            schema_version: 1,
            created_at: "2026-05-05T00:00:00Z".to_string(),
            description: None,
            match_clause: RuleMatch {
                host: host.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
                host_pattern: None,
                ip: None,
                cidr: None,
                port,
                protocol: proto.map(|s| s.to_string()),
            },
            scope: RuleScope::default(),
            disposition,
            time_window: None,
            derived: None,
        }
    }

    #[test]
    fn agent_chain_name_sanitizes() {
        assert_eq!(agent_chain_name("my-agent"), "agent_my-agent");
        assert_eq!(
            agent_chain_name("agent/with spaces"),
            "agent_agent_x2f_with_x20_spaces"
        );
    }

    #[test]
    fn agent_chain_name_does_not_collapse_colliding_agent_ids() {
        let slash_agent = agent_chain_name("agent/a");
        let underscore_agent = agent_chain_name("agent_a");
        assert_ne!(slash_agent, underscore_agent);
        assert_eq!(slash_agent, "agent_agent_x2f_a");
        assert_eq!(underscore_agent, "agent_agent_a");
    }

    #[test]
    fn agent_chain_name_stays_within_nft_budget() {
        let chain = agent_chain_name(&format!("agent/{}", "x".repeat(400)));
        assert!(chain.len() <= NFT_CHAIN_MAX_LEN);
        assert!(chain.starts_with(AGENT_CHAIN_PREFIX));
    }

    #[test]
    fn build_agent_ruleset_includes_cgroup_queue() {
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "test-agent",
            "system.slice/sanctuary-agent-test.service",
            2,
            &frags,
        );
        assert!(script.contains("flush chain"));
        assert!(!script.contains("tcp dport 443 accept"));
        assert!(script.contains("queue num 0"));
        assert!(script.contains("meta mark set"));
        // Path is quoted, comes after the level, no leading slash. Level 2
        // is the canonical depth for `/system.slice/<unit>`; nested
        // deployments pass higher values, hence the rule encoding the level.
        assert!(
            script.contains("level 2 \"system.slice/sanctuary-agent-test.service\""),
            "rule must emit quoted cgroup-relative path after level: {script}"
        );
    }

    #[test]
    fn build_agent_ruleset_threads_dynamic_level() {
        // In nested environments (CI runners, Docker-in-Docker) the agent's
        // cgroup may be at depth 3 or 4; the rule must reflect that or nft
        // rejects with "cgroupv2 path fails" at load time.
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "nested",
            "system.slice/parent.service/sanctuary-agent-nested.service",
            3,
            &frags,
        );
        assert!(script
            .contains("level 3 \"system.slice/parent.service/sanctuary-agent-nested.service\""));
        assert!(!script.contains("level 2"));
    }

    #[test]
    fn build_agent_ruleset_registers_mark_for_nfqueue_attribution() {
        let script = build_agent_ruleset(
            "attributed-agent",
            "system.slice/sanctuary-agent-attributed-agent.service",
            2,
            &[],
        );
        let mark = crate::nfqueue::agent_mark("attributed-agent");
        assert!(
            script.contains(&format!("meta mark set 0x{mark:08x} queue num 0")),
            "catchall must set a per-agent mark before NFQUEUE: {script}"
        );
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            Some("attributed-agent".to_string())
        );
    }

    #[test]
    fn build_agent_ruleset_emits_quoted_path_not_inode_integer() {
        // Regression guard: earlier production code emitted the post-resolution
        // inode integer where nft expects a quoted cgroup-relative path string.
        // nft 1.x rejects integer input at rule-load time. This test pins the
        // emission to the documented input form.
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset(
            "regression",
            "system.slice/sanctuary-agent-regression.service",
            2,
            &frags,
        );
        // Path must be quoted.
        assert!(
            script.contains("\"system.slice/sanctuary-agent-regression.service\""),
            "cgroup path must be quoted: {script}"
        );
        // Must not emit a bare integer where the path goes (i.e. no
        // `level 2 <digit>` pattern without a quote).
        let lines: Vec<&str> = script.lines().filter(|l| l.contains("cgroupv2")).collect();
        assert_eq!(lines.len(), 1, "exactly one cgroupv2 rule expected");
        let cgroupv2_line = lines[0];
        let post_level = cgroupv2_line
            .split("level 2 ")
            .nth(1)
            .expect("expected 'level 2 ' marker");
        assert!(
            post_level.starts_with('"'),
            "after 'level 2 ' nft requires a quoted path, got: {post_level}"
        );
    }

    #[test]
    fn rule_to_nft_expr_allow_with_host_and_port_stays_on_nfqueue() {
        let r = make_rule(
            "r1",
            Some(vec!["api.anthropic.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host allow rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_deny_no_host_stays_ordered_on_nfqueue() {
        let r = make_rule(
            "r2",
            None,
            Some(vec![80, 8080]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(frags.is_empty());
    }

    #[test]
    fn rule_to_nft_expr_prompt_produces_no_fragments() {
        let r = make_rule(
            "r3",
            Some(vec!["example.com"]),
            None,
            None,
            RuleDisposition::Prompt,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(frags.is_empty());
    }

    #[test]
    fn rule_to_nft_expr_multiple_hosts_stays_on_nfqueue() {
        let r = make_rule(
            "r4",
            Some(vec!["a.com", "b.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "multi-host rules must not emit comment-only static verdicts"
        );
    }

    #[test]
    fn rule_to_nft_expr_host_pattern_stays_on_nfqueue() {
        let mut r = make_rule(
            "r5",
            None,
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        r.match_clause.host_pattern = Some(".example.com".to_string());
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host-pattern rules must not become static port-wide nft drops"
        );
    }

    #[test]
    fn rule_to_nft_expr_ip_axis_stays_on_nfqueue() {
        // An ip-pinned rule (the genuine reserved local distress shape) must
        // NOT lower to a bare `tcp dport 8741 accept` that would grant the port
        // to ANY destination — the loopback constraint would be lost in the
        // kernel (codex round-3). It stays on the evaluator path.
        let mut r = make_rule(
            "r-ip",
            None,
            Some(vec![8741]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        r.match_clause.ip = Some(vec!["127.0.0.1".to_string(), "::1".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "ip-pinned rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_cidr_axis_stays_on_nfqueue() {
        let mut r = make_rule(
            "r-cidr",
            None,
            Some(vec![8741]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        r.match_clause.cidr = Some(vec!["10.0.0.0/8".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "cidr rules must not become static port-wide nft drops"
        );
    }

    // ---- build_agent_jump_rule pure-helper tests --------------------------

    #[test]
    fn build_agent_jump_rule_emits_canonical_shape() {
        // Pin the exact rule string for the canonical case: depth-2 cgroup
        // under system.slice, single-segment agent id. This is what the
        // base output chain needs to route packets from the agent's cgroup
        // into the per-agent chain.
        let rule = build_agent_jump_rule("alpha", 2, "system.slice/sanctuary-agent-alpha.service");
        assert_eq!(
            rule,
            "add rule inet sanctuary-castle output \
             socket cgroupv2 level 2 \"system.slice/sanctuary-agent-alpha.service\" \
             goto agent_alpha"
        );
    }

    #[test]
    fn build_agent_jump_rule_quotes_cgroup_path() {
        // Defense against the integer-bug recurrence pattern PR #130 fixed
        // for build_agent_ruleset: nft 1.x rejects unquoted path strings
        // and unquoted integer-only inputs at rule-load time. The jump
        // rule must always emit a quoted path.
        let rule = build_agent_jump_rule(
            "regression",
            2,
            "system.slice/sanctuary-agent-regression.service",
        );
        assert!(
            rule.contains("\"system.slice/sanctuary-agent-regression.service\""),
            "cgroup path must be quoted: {rule}"
        );
        // No bare integer where the path goes.
        let post_level = rule
            .split("level 2 ")
            .nth(1)
            .expect("expected 'level 2 ' marker");
        assert!(
            post_level.starts_with('"'),
            "after 'level 2 ' nft requires a quoted path, got: {post_level}"
        );
    }

    #[test]
    fn build_agent_jump_rule_threads_dynamic_level() {
        // Mirror the build_agent_ruleset dynamic-depth shape: nested
        // deployments place the agent's cgroup deeper than depth 2, and
        // the jump rule must reflect the actual depth or nft rejects with
        // "cgroupv2 path fails".
        let rule = build_agent_jump_rule(
            "nested",
            3,
            "system.slice/parent.service/sanctuary-agent-nested.service",
        );
        assert!(
            rule.contains("level 3 \"system.slice/parent.service/sanctuary-agent-nested.service\"")
        );
        assert!(!rule.contains("level 2"));
    }

    #[test]
    fn build_agent_jump_rule_chain_name_matches_agent_chain_name() {
        // The goto target must match agent_chain_name(agent_id) exactly so
        // the per-agent chain created by load_agent_ruleset_impl is the
        // chain reached by this jump.
        for agent_id in &["alpha", "my-agent", "team_a.svc1", "weird/id"] {
            let rule = build_agent_jump_rule(agent_id, 2, "system.slice/x.service");
            let chain = agent_chain_name(agent_id);
            assert!(
                rule.ends_with(&format!("goto {chain}")),
                "jump rule must end with goto <chain_name> matching agent_chain_name; \
                 agent={agent_id} chain={chain} rule={rule}"
            );
        }
    }

    #[test]
    fn build_agent_fail_closed_ruleset_drops_everything_in_chain() {
        let script = build_agent_fail_closed_ruleset("refresh-agent");
        assert!(script.contains("flush chain inet sanctuary-castle agent_refresh-agent"));
        assert!(script.contains("add rule inet sanctuary-castle agent_refresh-agent drop"));
        assert!(
            !script.contains("queue"),
            "refresh fail-closed stage must drop rather than queue: {script}"
        );
    }

    // ---- parse_jump_rule_handles tests ------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_matches_target_chain_only() {
        // Synthetic `nft -a list chain` output with three rules: one
        // jumping to our chain, one jumping to a different chain, one
        // doing something else entirely.
        let listing = "\
table inet sanctuary-castle {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tsocket cgroupv2 level 2 \"system.slice/sanctuary-agent-alpha.service\" goto agent_alpha # handle 5
\t\tsocket cgroupv2 level 2 \"system.slice/sanctuary-agent-beta.service\" goto agent_beta # handle 7
\t\tudp dport 53 accept # handle 9
\t}
}";
        let handles = linux::parse_jump_rule_handles(listing, "agent_alpha");
        assert_eq!(handles, vec![5]);
        let handles_beta = linux::parse_jump_rule_handles(listing, "agent_beta");
        assert_eq!(handles_beta, vec![7]);
        let handles_missing = linux::parse_jump_rule_handles(listing, "agent_gamma");
        assert!(handles_missing.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_does_not_substring_match() {
        // Critical correctness invariant: chain names that share a prefix
        // (`agent_foo` and `agent_foo_bar`) must not collide. A naive
        // substring match for `agent_foo` would wrongly hit the line
        // ending in `goto agent_foo_bar`.
        let listing = "\
\t\tsocket cgroupv2 level 2 \"system.slice/foo.service\" goto agent_foo # handle 11
\t\tsocket cgroupv2 level 2 \"system.slice/foo_bar.service\" goto agent_foo_bar # handle 13
";
        let handles_foo = linux::parse_jump_rule_handles(listing, "agent_foo");
        assert_eq!(handles_foo, vec![11], "must not match agent_foo_bar");
        let handles_foo_bar = linux::parse_jump_rule_handles(listing, "agent_foo_bar");
        assert_eq!(handles_foo_bar, vec![13]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_collects_all_duplicates() {
        // If a prior install-and-no-remove path leaked stale jumps for the
        // same agent (the bug shape `install_agent_jump_rule_impl`'s
        // delete-then-add prevents going forward), the parser must surface
        // every handle so a remove call cleans them all out.
        let listing = "\
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 21
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 22
\t\tsocket cgroupv2 level 2 \"x\" goto agent_dup # handle 23
";
        let handles = linux::parse_jump_rule_handles(listing, "agent_dup");
        assert_eq!(handles, vec![21, 22, 23]);
    }
}
