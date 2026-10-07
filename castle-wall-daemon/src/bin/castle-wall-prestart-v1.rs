//! Fixed, sandboxed filesystem actions only. No owner IPC or authority.
//!
//! UNREFERENCED IN THIS SLICE: the shipped `sanctuary-castle-wall.service`
//! still runs its own `install -d` prestarts and names this helper nowhere, so
//! building it changes no installed behaviour. It is reviewable source for the
//! slice that also rewrites those unit lines.
#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        // SAFETY: stderr is the operator channel for a prestart refusal. systemd
        // captures it into the unit's journal, and it is the only place an
        // operator can see WHY the daemon never started; no logging facility
        // exists yet at this point in the unit's life.
        eprintln!("castle-wall-prestart-v1: refused: {e}");
        std::process::exit(1)
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(1)
}

#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    use std::{
        fs, io,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::Path,
    };
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 || !matches!(args[1].as_str(), "fortress-runtime" | "locks") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixed action required",
        ));
    }
    // Both actions validate the production fortress grammar before any mutation.
    let fortress = std::env::var("SANCTUARY_FORTRESS_ID")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fortress id absent"))?;
    if fortress.len() < 8
        || fortress.len() > 64
        || !fortress
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid fortress id",
        ));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root required",
        ));
    }
    let group = nix::unistd::Group::from_name("sanctuary")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sanctuary group absent"))?;
    let gid = group.gid.as_raw();
    fn check(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        let m = fs::symlink_metadata(path)?;
        if !m.file_type().is_dir()
            || m.uid() != uid
            || m.gid() != gid
            || (m.mode() & 0o7777) != mode
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path custody mismatch",
            ));
        }
        Ok(())
    }
    check(Path::new("/run"), 0, 0, 0o755)?;
    check(Path::new("/run/sanctuary"), 0, gid, 0o710)?;
    let (path, mode) = if args[1] == "locks" {
        (Path::new("/run/sanctuary/locks").to_path_buf(), 0o700)
    } else {
        (Path::new("/run/sanctuary").join(fortress), 0o750)
    };
    match fs::symlink_metadata(&path) {
        Ok(_) => check(&path, 0, gid, mode)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Only the absent leaf is created. No chown, chmod or repair arm.
            unsafe { libc::umask(0o027) };
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode);
            builder.create(&path)?;
            check(&path, 0, gid, mode)?;
        }
        Err(e) => return Err(e),
    }
    check(Path::new("/run/sanctuary"), 0, gid, 0o710)?;
    Ok(())
}
