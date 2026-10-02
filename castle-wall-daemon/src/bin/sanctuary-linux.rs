//! Root-only installation and lifecycle entry point; no runtime isolation switches.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let Ok(args) = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>()
    else {
        // SAFETY: argument rejection is a fixed CLI diagnostic on stderr.
        eprintln!("sanctuary-linux: non-UTF-8 argument refused");
        return std::process::ExitCode::FAILURE;
    };
    if args == ["--help"] {
        // SAFETY: stdout is the explicit operator help contract for this CLI.
        println!("sanctuary-linux provision --agent-uid U --service-uid B --fortress-id F --stage-file FILE -- EXEC ARGS...\nsanctuary-linux policy-install --bundle FILE --expected-key-sha256 PIN\nsanctuary-linux start|enable|disable|stop\nsanctuary-linux status --json\nsanctuary-linux evidence --output DIR");
        return std::process::ExitCode::SUCCESS;
    }
    match castle_wall_daemon::linux_install::command::run(&args) {
        Ok(value) => {
            // SAFETY: stdout carries the command's machine-readable JSON result.
            println!("{value}");
            if value.get("complete") == Some(&serde_json::Value::Bool(false)) {
                std::process::ExitCode::FAILURE
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(error) => {
            // SAFETY: stderr carries the CLI's command-refusal diagnostic.
            eprintln!("sanctuary-linux: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    // SAFETY: unsupported-platform refusal is this CLI's stderr contract.
    eprintln!("sanctuary-linux requires Linux");
    std::process::ExitCode::FAILURE
}
