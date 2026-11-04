#[cfg(target_os = "macos")]
use crate::cockpit;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
static START_LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_os = "macos")]
static WRAPPER_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
const MAX_WRAPPER_BYTES: u64 = 64 * 1024;

#[cfg(target_os = "macos")]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
fn wrapper_path() -> Result<PathBuf, ()> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or(())?);
    if !home.is_absolute() {
        return Err(());
    }
    Ok(home.join(".config/opencode/bin/oc-rig-v2-terminal"))
}

#[cfg(target_os = "macos")]
fn validate_wrapper(path: &Path) -> Result<(), ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let uid = current_uid();
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component),
            Component::Normal(part) => current.push(part),
            _ => return Err(()),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| ())?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(());
        }
    }
    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o777 != 0o700
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_WRAPPER_BYTES
    {
        return Err(());
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    let after = fs::symlink_metadata(path).map_err(|_| ())?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) || bytes.len() as u64 != before.len()
        || bytes.contains(&0)
    {
        return Err(());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    if !text.starts_with("#!/usr/bin/env bash\n")
        || !text.contains("launcher.py")
        || !text.contains("--terminal")
        || !text.contains("--ownership")
    {
        return Err(());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn reap_later(mut child: std::process::Child) {
    thread::spawn(move || {
        let _ = child.wait();
        WRAPPER_IN_FLIGHT.store(false, Ordering::Release);
    });
}

#[cfg(target_os = "macos")]
pub(crate) fn start() -> Result<(), ()> {
    let _guard = START_LOCK.lock().map_err(|_| ())?;
    if cockpit::load_snapshot().is_ok() {
        return Ok(());
    }
    let mut child = None;
    if WRAPPER_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let wrapper = match wrapper_path() {
            Ok(path) => path,
            Err(()) => {
                WRAPPER_IN_FLIGHT.store(false, Ordering::Release);
                return Err(());
            }
        };
        if validate_wrapper(&wrapper).is_err() {
            WRAPPER_IN_FLIGHT.store(false, Ordering::Release);
            return Err(());
        }
        match Command::new(&wrapper)
            .arg("--mode")
            .arg("app")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(spawned) => child = Some(spawned),
            Err(_) => {
                WRAPPER_IN_FLIGHT.store(false, Ordering::Release);
                return Err(());
            }
        }
    }
    // A cold launch can spend tens of seconds in launchd and OpenCode's own
    // readiness checks before the authenticated cockpit socket appears.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if cockpit::load_snapshot().is_ok() {
            if let Some(spawned) = child.take() {
                reap_later(spawned);
            }
            return Ok(());
        }
        if let Some(spawned) = child.as_mut() {
            match spawned.try_wait() {
                Ok(Some(status)) => {
                    child = None;
                    WRAPPER_IN_FLIGHT.store(false, Ordering::Release);
                    if !status.success() {
                        return Err(());
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    if let Some(spawned) = child.take() {
                        reap_later(spawned);
                    }
                    return Err(());
                }
            }
        }
        if Instant::now() >= deadline {
            // The managed lifecycle owns its own crash recovery and lock. Never
            // SIGKILL it after durable startup may have begun; a later retry
            // will either observe readiness or serialize behind that same lock.
            if let Some(spawned) = child.take() {
                reap_later(spawned);
            }
            return Err(());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn start() -> Result<(), ()> {
    Err(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn wrapper_validation_rejects_writable_or_unrelated_files() {
        // The source checkout may have a group-writable ancestor (for example
        // /Applications). Exercise the owner-only policy in an owned fixture,
        // without weakening production ancestry validation.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".fugue-lifecycle-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let wrapper = root.join("wrapper");
        fs::write(
            &wrapper,
            b"#!/usr/bin/env bash\nlauncher.py --terminal --ownership\n",
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_wrapper(&wrapper).is_ok());
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(validate_wrapper(&wrapper).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn asynchronous_reaper_clears_inflight_launch() {
        WRAPPER_IN_FLIGHT.store(true, Ordering::Release);
        let child = Command::new("/usr/bin/true").spawn().unwrap();
        reap_later(child);
        let deadline = Instant::now() + Duration::from_secs(2);
        while WRAPPER_IN_FLIGHT.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!WRAPPER_IN_FLIGHT.load(Ordering::Acquire));
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod non_macos_tests {
    #[test]
    fn lifecycle_start_is_inert_without_a_verified_platform_transport() {
        assert!(super::start().is_err());
    }
}
