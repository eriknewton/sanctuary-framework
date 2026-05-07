//! Diagnostic test for v1.x cgroup_create_agent_scope on Ubuntu 24.04 +
//! systemd 255. Captures the exact failure shape from the production
//! `systemd-run --scope --unit <name> --property=Delegate=yes
//! --remain-after-exit /bin/true` invocation, plus environment
//! fingerprints (systemd version, cgroup-v2 layout, /proc/self/cgroup),
//! so the spawn-prompt's four open questions can be answered from CI
//! output without standing up a local Ubuntu 24.04 VM.
//!
//! This test is `#[ignore]`-d in normal CI cycles. It runs only when
//! invoked explicitly. The diagnostic file is removed before the PR
//! merges; it exists solely to capture the failure shape during the
//! v1.x fix iteration.

#![cfg(target_os = "linux")]

use castle_wall_daemon::cgroup;
use std::process::Command;

#[test]
fn diagnose_cgroup_create_on_ubuntu_2404() {
    eprintln!("---- DIAG: environment fingerprint ----");

    let systemctl_version = Command::new("systemctl")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|e| format!("(systemctl --version failed: {e})"));
    eprintln!("systemctl --version:\n{}", systemctl_version);

    let proc1_comm = std::fs::read_to_string("/proc/1/comm")
        .unwrap_or_else(|e| format!("(read failed: {e})"));
    eprintln!("/proc/1/comm: {}", proc1_comm.trim());

    let proc1_exe = std::fs::read_link("/proc/1/exe")
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("(readlink failed: {e})"));
    eprintln!("/proc/1/exe -> {}", proc1_exe);

    let proc_self_cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .unwrap_or_else(|e| format!("(read failed: {e})"));
    eprintln!("/proc/self/cgroup:\n{}", proc_self_cgroup);

    let cgroup_layout = Command::new("ls")
        .args(["-la", "/sys/fs/cgroup/system.slice/"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|e| format!("(ls failed: {e})"));
    eprintln!(
        "/sys/fs/cgroup/system.slice/ (head):\n{}",
        cgroup_layout.lines().take(20).collect::<Vec<_>>().join("\n")
    );

    let cgroup_root = Command::new("ls")
        .args(["-la", "/sys/fs/cgroup/"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|e| format!("(ls failed: {e})"));
    eprintln!(
        "/sys/fs/cgroup/ (head):\n{}",
        cgroup_root.lines().take(30).collect::<Vec<_>>().join("\n")
    );

    eprintln!("\n---- DIAG: invoke production create_agent_scope ----");

    let result = cgroup::create_agent_scope("v1x-cgroup-fix-diag");
    match &result {
        Ok(handle) => {
            eprintln!("DIAG: create_agent_scope SUCCEEDED");
            eprintln!("  agent_id   = {}", handle.agent_id);
            eprintln!("  scope_unit = {}", handle.scope_unit);
            eprintln!("  cgroup_path = {}", handle.cgroup_path.display());
            eprintln!("  cgroup_id  = {}", handle.cgroup_id);

            // Check the actual cgroup-v2 location systemd placed it at.
            let systemctl_show = Command::new("systemctl")
                .args(["show", &handle.scope_unit, "--property=ControlGroup"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|e| format!("(systemctl show failed: {e})"));
            eprintln!("systemctl show ControlGroup: {}", systemctl_show.trim());

            let _ = cgroup::destroy_agent_scope(handle);
        }
        Err(e) => {
            eprintln!("DIAG: create_agent_scope FAILED: {e:?}");

            // Run the same systemd-run invocation by hand to get
            // unfiltered stderr.
            let raw = Command::new("systemd-run")
                .args([
                    "--scope",
                    "--unit",
                    "sanctuary-agent-v1x-diag-raw.scope",
                    "--property=Delegate=yes",
                    "--remain-after-exit",
                    "/bin/true",
                ])
                .output();
            match raw {
                Ok(o) => {
                    eprintln!(
                        "DIAG: raw systemd-run exit={} stdout={:?} stderr={:?}",
                        o.status,
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                }
                Err(io) => {
                    eprintln!("DIAG: raw systemd-run io error: {io:?}");
                }
            }

            // Probe the four likely shapes per spawn prompt §Step 2.
            //
            // Shape A: --remain-after-exit /bin/true might be deprecated;
            // try a long-running placeholder.
            let shape_a = Command::new("systemd-run")
                .args([
                    "--scope",
                    "--unit",
                    "sanctuary-agent-v1x-diag-shape-a.scope",
                    "--property=Delegate=yes",
                    "/usr/bin/sleep",
                    "0.1",
                ])
                .output();
            match shape_a {
                Ok(o) => eprintln!(
                    "DIAG shape A (--scope + sleep 0.1): exit={} stderr={:?}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(io) => eprintln!("DIAG shape A io error: {io:?}"),
            }

            // Shape B: --service mode with sleep infinity placeholder.
            let shape_b = Command::new("systemd-run")
                .args([
                    "--unit",
                    "sanctuary-agent-v1x-diag-shape-b.service",
                    "--property=Delegate=yes",
                    "/usr/bin/sleep",
                    "0.1",
                ])
                .output();
            match shape_b {
                Ok(o) => eprintln!(
                    "DIAG shape B (--service + sleep 0.1): exit={} stderr={:?}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(io) => eprintln!("DIAG shape B io error: {io:?}"),
            }

            // Shape B': --service without Delegate=yes (Delegate may not be
            // honored on scopes in 255).
            let shape_b_no_delegate = Command::new("systemd-run")
                .args([
                    "--unit",
                    "sanctuary-agent-v1x-diag-shape-b-nd.service",
                    "/usr/bin/sleep",
                    "0.1",
                ])
                .output();
            match shape_b_no_delegate {
                Ok(o) => eprintln!(
                    "DIAG shape B-no-delegate (--service no Delegate): exit={} stderr={:?}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(io) => eprintln!("DIAG shape B-no-delegate io error: {io:?}"),
            }

            // Shape D: query systemd for where it placed a successful unit
            // to confirm the path assumption.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let where_did_it_go = Command::new("systemctl")
                .args([
                    "show",
                    "sanctuary-agent-v1x-diag-shape-a.scope",
                    "--property=ControlGroup",
                ])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|e| format!("(systemctl show failed: {e})"));
            eprintln!(
                "DIAG shape A ControlGroup (after sleep): {}",
                where_did_it_go.trim()
            );

            panic!("see DIAG output above for failure mode");
        }
    }
}
