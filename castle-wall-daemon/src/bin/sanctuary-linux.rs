//! Root-only installation and lifecycle entry point; no runtime isolation switches.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("sanctuary-linux provision --agent-uid U --service-uid B --fortress-id F --stage-file FILE -- EXEC ARGS...\nsanctuary-linux policy-install --bundle FILE --expected-key-sha256 PIN\nsanctuary-linux start|enable|disable|stop\nsanctuary-linux status --json\nsanctuary-linux evidence --output DIR");
        return std::process::ExitCode::SUCCESS;
    }
    match castle_wall_daemon::linux_install::command::run(&args) {
        Ok(value) => {
            println!("{value}");
            if value.get("complete") == Some(&serde_json::Value::Bool(false)) {
                std::process::ExitCode::FAILURE
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("sanctuary-linux: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("sanctuary-linux requires Linux");
    std::process::ExitCode::FAILURE
}
