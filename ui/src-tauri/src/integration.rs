use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct IntegrationStatus {
    pub armed: bool,
    pub ready: bool,
    pub trust_mode: &'static str,
    pub backend_ready: bool,
    pub notifier_ready: bool,
    pub codex_cli: bool,
    pub pending_callbacks: u64,
    pub queued_dispatches: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    mode: String,
    ready: bool,
    trust_mode: String,
    backend_ready: bool,
    notifier_ready: bool,
    codex_cli: bool,
    pending_callbacks: u64,
    queued_dispatches: u64,
}

fn decode_status(bytes: &[u8]) -> Result<IntegrationStatus, ()> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(());
    }
    let value: WireStatus = serde_json::from_slice(bytes).map_err(|_| ())?;
    let armed = match value.mode.as_str() {
        "armed" => true,
        "disarmed" => false,
        _ => return Err(()),
    };
    if value.trust_mode != "secure"
        || value.ready != (armed && value.backend_ready && value.notifier_ready && value.codex_cli)
        || (!armed && (value.backend_ready || value.notifier_ready))
    {
        return Err(());
    }
    Ok(IntegrationStatus {
        armed,
        ready: value.ready,
        trust_mode: "secure",
        backend_ready: value.backend_ready,
        notifier_ready: value.notifier_ready,
        codex_cli: value.codex_cli,
        pending_callbacks: value.pending_callbacks,
        queued_dispatches: value.queued_dispatches,
    })
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{decode_status, IntegrationStatus};
    use sha2::{Digest, Sha256};
    use std::ffi::{CStr, OsStr};
    use std::fs;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    const MAX_FILE_BYTES: u64 = 64 * 1024;
    const MAX_OUTPUT_BYTES: usize = 16 * 1024;
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
    const WRAPPER: &[u8] = b"#!/usr/bin/env bash\nset -euo pipefail\nif [ \"$#\" -eq 0 ]; then\n  set -- status\nfi\nexec python3 \"$HOME/.config/opencode/bin/oc-integration.py\" \"$@\"\n";
    const SCRIPT_SHA256: [u8; 32] = [
        0x6a, 0x32, 0x90, 0xd3, 0x2f, 0xcd, 0x05, 0x5e, 0xfd, 0xa4, 0x8f, 0xb1, 0xdb, 0x68, 0x39,
        0xbe, 0x2e, 0x7e, 0x2b, 0xf5, 0x3d, 0xc6, 0xc7, 0xfb, 0x38, 0x71, 0x98, 0xaa, 0x16, 0xc1,
        0xbe, 0xfc,
    ];
    static MUTATION_LOCK: Mutex<()> = Mutex::new(());

    fn current_uid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn owner_home() -> Result<PathBuf, ()> {
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; 16 * 1024];
        // SAFETY: all pointers refer to live writable storage for the duration
        // of this call; failure and an undersized buffer both fail closed.
        let code = unsafe {
            libc::getpwuid_r(
                current_uid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code != 0 || result.is_null() || entry.pw_dir.is_null() {
            return Err(());
        }
        // SAFETY: successful getpwuid_r guarantees a NUL-terminated pw_dir
        // within the caller-owned buffer above.
        let home = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes(),
        ));
        if !home.is_absolute() {
            return Err(());
        }
        Ok(home)
    }

    fn paths() -> Result<(PathBuf, PathBuf), ()> {
        let home = owner_home()?;
        let bin = home.join(".config/opencode/bin");
        Ok((bin.join("oc-integration"), bin.join("oc-integration.py")))
    }

    fn validate_ancestry(path: &Path) -> Result<(), ()> {
        let mut current = PathBuf::new();
        let uid = current_uid();
        for component in path.components() {
            match component {
                Component::RootDir | Component::Prefix(_) => current.push(component),
                Component::Normal(part) => current.push(part),
                _ => return Err(()),
            }
            let details = fs::symlink_metadata(&current).map_err(|_| ())?;
            if details.file_type().is_symlink()
                || (details.uid() != 0 && details.uid() != uid)
                || details.mode() & 0o022 != 0
            {
                return Err(());
            }
        }
        Ok(())
    }

    fn stable_file(path: &Path) -> Result<Vec<u8>, ()> {
        validate_ancestry(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| ())?;
        if !before.is_file()
            || before.uid() != current_uid()
            || before.mode() & 0o022 != 0
            || before.mode() & 0o111 == 0
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > MAX_FILE_BYTES
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
            before.mtime(),
            before.mtime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
            after.mtime(),
            after.mtime_nsec(),
        ) || bytes.len() as u64 != before.len()
            || bytes.contains(&0)
        {
            return Err(());
        }
        Ok(bytes)
    }

    fn validated_script() -> Result<PathBuf, ()> {
        let (wrapper, script) = paths()?;
        if stable_file(&wrapper)? != WRAPPER {
            return Err(());
        }
        let script_bytes = stable_file(&script)?;
        let digest: [u8; 32] = Sha256::digest(&script_bytes).into();
        if digest != SCRIPT_SHA256 {
            return Err(());
        }
        Ok(script)
    }

    fn run(arguments: &[&str]) -> Result<Vec<u8>, ()> {
        if !matches!(arguments, ["status", "--json"] | ["arm"] | ["disarm"]) {
            return Err(());
        }
        let script = validated_script()?;
        let home = owner_home()?;
        let mut child = Command::new("/usr/bin/python3")
            .arg(script)
            .args(arguments)
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ())?;
        let mut stdout = child.stdout.take().ok_or(())?;
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .by_ref()
                .take((MAX_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(result);
        });
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = loop {
            if let Ok(Some(status)) = child.try_wait() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(());
            }
            thread::sleep(Duration::from_millis(20));
        };
        let output = receiver.recv().map_err(|_| ())?.map_err(|_| ())?;
        reader.join().map_err(|_| ())?;
        if !status.success() || output.len() > MAX_OUTPUT_BYTES {
            return Err(());
        }
        Ok(output)
    }

    pub(super) fn status() -> Result<IntegrationStatus, ()> {
        decode_status(&run(&["status", "--json"])?)
    }

    pub(super) fn set_enabled(enabled: bool) -> Result<IntegrationStatus, ()> {
        let _guard = MUTATION_LOCK.lock().map_err(|_| ())?;
        let current = status()?;
        if current.armed == enabled {
            return Ok(current);
        }
        let _ = run(&[if enabled { "arm" } else { "disarm" }])?;
        let changed = status()?;
        if changed.armed != enabled {
            return Err(());
        }
        Ok(changed)
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::IntegrationStatus;

    pub(super) fn status() -> Result<IntegrationStatus, ()> {
        Err(())
    }

    pub(super) fn set_enabled(_enabled: bool) -> Result<IntegrationStatus, ()> {
        Err(())
    }
}

pub(crate) fn status() -> Result<IntegrationStatus, ()> {
    platform::status()
}

pub(crate) fn set_enabled(enabled: bool) -> Result<IntegrationStatus, ()> {
    platform::set_enabled(enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_requires_exact_secure_consistent_shape() {
        let good = br#"{"backend_ready":true,"codex_cli":true,"mode":"armed","notifier_ready":true,"pending_callbacks":0,"queued_dispatches":0,"ready":true,"trust_mode":"secure"}"#;
        let status = decode_status(good).unwrap();
        assert!(status.armed);
        assert!(status.ready);
        assert_eq!(status.trust_mode, "secure");

        for invalid in [
            br#"{"backend_ready":true,"codex_cli":true,"mode":"armed","notifier_ready":true,"pending_callbacks":0,"queued_dispatches":0,"ready":false,"trust_mode":"secure"}"#.as_slice(),
            br#"{"backend_ready":true,"codex_cli":true,"mode":"armed","notifier_ready":true,"pending_callbacks":0,"queued_dispatches":0,"ready":true,"trust_mode":"insecure"}"#.as_slice(),
            br#"{"backend_ready":false,"codex_cli":true,"mode":"disarmed","notifier_ready":false,"pending_callbacks":0,"queued_dispatches":0,"ready":false,"trust_mode":"secure","extra":true}"#.as_slice(),
        ] {
            assert!(decode_status(invalid).is_err());
        }
    }
}
