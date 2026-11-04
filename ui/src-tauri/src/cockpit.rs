use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_FRAME_BYTES: usize = 64 * 1024;
const PROTOCOL_VERSION: u64 = 1;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeError {
    Unavailable,
    Security,
    Protocol,
    Rejected,
    Unsupported,
}

impl BridgeError {
    pub(crate) fn public_message(self) -> &'static str {
        match self {
            Self::Unavailable => "Fugue controller is unavailable",
            Self::Security => "Fugue controller endpoint failed local security validation",
            Self::Protocol => "Fugue controller returned an invalid response",
            Self::Rejected => "Fugue controller rejected the request",
            Self::Unsupported => "Fugue controller does not support this operation",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    version: u64,
    message_type: String,
    request_id: Option<String>,
    idempotency_id: Option<String>,
    ok: bool,
    result: Option<Value>,
    error: Option<WireError>,
}

fn next_identifier(prefix: &str) -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{}-{nanos:x}-{sequence:x}", std::process::id())
}

fn request_bytes(
    operation: &str,
    params: Value,
    request_id: &str,
    idempotency_id: &str,
) -> Result<Vec<u8>, BridgeError> {
    let value = json!({
        "idempotency_id": idempotency_id,
        "message_type": "request",
        "operation": operation,
        "params": params,
        "request_id": request_id,
        "version": PROTOCOL_VERSION,
    });
    let bytes = serde_json::to_vec(&value).map_err(|_| BridgeError::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    Ok(bytes)
}

#[cfg(test)]
fn write_frame(mut writer: impl Write, payload: &[u8]) -> Result<(), BridgeError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let length = u32::try_from(payload.len()).map_err(|_| BridgeError::Protocol)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(payload))
        .map_err(|_| BridgeError::Unavailable)
}

#[cfg(test)]
fn read_frame(mut reader: impl Read) -> Result<Vec<u8>, BridgeError> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| BridgeError::Unavailable)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| BridgeError::Unavailable)?;
    Ok(payload)
}

#[cfg(unix)]
fn remaining(deadline: Instant) -> Result<Duration, BridgeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(BridgeError::Unavailable)
}

#[cfg(unix)]
fn write_all_before(
    stream: &mut std::os::unix::net::UnixStream,
    mut payload: &[u8],
    deadline: Instant,
) -> Result<(), BridgeError> {
    while !payload.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| BridgeError::Unavailable)?;
        match stream.write(payload) {
            Ok(0) => return Err(BridgeError::Unavailable),
            Ok(written) => payload = &payload[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(BridgeError::Unavailable),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_before(
    stream: &mut std::os::unix::net::UnixStream,
    mut target: &mut [u8],
    deadline: Instant,
) -> Result<(), BridgeError> {
    while !target.is_empty() {
        let timeout = remaining(deadline)?;
        let milliseconds = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for this call.
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready <= 0
            || descriptor.revents & libc::POLLNVAL != 0
            || descriptor.revents & libc::POLLIN == 0
        {
            return Err(BridgeError::Unavailable);
        }
        match stream.read(target) {
            Ok(0) => return Err(BridgeError::Unavailable),
            Ok(read) => target = &mut target[read..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(BridgeError::Unavailable),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn exchange_frames(
    stream: &mut std::os::unix::net::UnixStream,
    request: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, BridgeError> {
    if request.is_empty() || request.len() > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let length = u32::try_from(request.len()).map_err(|_| BridgeError::Protocol)?;
    write_all_before(stream, &length.to_be_bytes(), deadline)?;
    write_all_before(stream, request, deadline)?;
    let mut header = [0_u8; 4];
    read_exact_before(stream, &mut header, deadline)?;
    let response_length = u32::from_be_bytes(header) as usize;
    if response_length == 0 || response_length > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let mut response = vec![0_u8; response_length];
    read_exact_before(stream, &mut response, deadline)?;
    Ok(response)
}

#[cfg(unix)]
fn exchange_frames_wait(
    stream: &mut std::os::unix::net::UnixStream,
    request: &[u8],
    write_deadline: Instant,
) -> Result<Vec<u8>, BridgeError> {
    if request.is_empty() || request.len() > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let length = u32::try_from(request.len()).map_err(|_| BridgeError::Protocol)?;
    write_all_before(stream, &length.to_be_bytes(), write_deadline)?;
    write_all_before(stream, request, write_deadline)?;
    stream
        .set_read_timeout(None)
        .map_err(|_| BridgeError::Unavailable)?;
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| BridgeError::Unavailable)?;
    let response_length = u32::from_be_bytes(header) as usize;
    if response_length == 0 || response_length > MAX_FRAME_BYTES {
        return Err(BridgeError::Protocol);
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .map_err(|_| BridgeError::Unavailable)?;
    Ok(response)
}

fn decode_result(
    payload: &[u8],
    request_id: &str,
    idempotency_id: &str,
) -> Result<Value, BridgeError> {
    let value: Value = serde_json::from_slice(payload).map_err(|_| BridgeError::Protocol)?;
    let object = value.as_object().ok_or(BridgeError::Protocol)?;
    let common = [
        "version",
        "message_type",
        "request_id",
        "idempotency_id",
        "ok",
    ];
    let ok = object
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or(BridgeError::Protocol)?;
    let variant = if ok { "result" } else { "error" };
    if object.len() != common.len() + 1
        || common.iter().any(|key| !object.contains_key(*key))
        || !object.contains_key(variant)
    {
        return Err(BridgeError::Protocol);
    }
    let response: WireResponse =
        serde_json::from_value(value).map_err(|_| BridgeError::Protocol)?;
    if response.version != PROTOCOL_VERSION
        || response.message_type != "response"
        || response.request_id.as_deref() != Some(request_id)
        || response.idempotency_id.as_deref() != Some(idempotency_id)
    {
        return Err(BridgeError::Protocol);
    }
    if !response.ok {
        if response.result.is_some() || response.error.is_none() {
            return Err(BridgeError::Protocol);
        }
        let error = response.error.expect("checked non-null error");
        if error.code == "unknown_operation" {
            return Err(BridgeError::Unsupported);
        }
        let _ = error.message;
        return Err(BridgeError::Rejected);
    }
    if response.error.is_some() {
        return Err(BridgeError::Protocol);
    }
    let result = response
        .result
        .and_then(|value| value.as_object().cloned())
        .ok_or(BridgeError::Protocol)?;
    Ok(Value::Object(result))
}

fn decode_snapshot(
    payload: &[u8],
    request_id: &str,
    idempotency_id: &str,
) -> Result<Value, BridgeError> {
    let result = decode_result(payload, request_id, idempotency_id)?;
    let result = result.as_object().ok_or(BridgeError::Protocol)?;
    if result.len() != 1 || !result.contains_key("snapshot") {
        return Err(BridgeError::Protocol);
    }
    let snapshot = result
        .get("snapshot")
        .cloned()
        .ok_or(BridgeError::Protocol)?;
    if !snapshot.is_object() {
        return Err(BridgeError::Protocol);
    }
    Ok(snapshot)
}

#[cfg(unix)]
mod platform {
    use super::{
        exchange_frames, exchange_frames_wait, remaining, request_bytes, BridgeError, Duration,
        Instant, Value,
    };
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::fs;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Component, Path, PathBuf};
    #[cfg(target_os = "macos")]
    use std::process::Command;

    #[derive(Clone, Copy)]
    struct Inode {
        device: u64,
        inode: u64,
    }

    fn current_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        unsafe { libc::geteuid() }
    }

    fn home_directory() -> Result<PathBuf, BridgeError> {
        let value = std::env::var_os("HOME").ok_or(BridgeError::Security)?;
        let home = PathBuf::from(value);
        if !home.is_absolute() {
            return Err(BridgeError::Security);
        }
        Ok(home)
    }

    #[cfg(target_os = "macos")]
    fn endpoint() -> Result<(PathBuf, PathBuf), BridgeError> {
        let root =
            home_directory()?.join("Library/Application Support/oc-rig-v2/runtime/socket-boundary");
        Ok((root.clone(), root.join("socket/rig.sock")))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn endpoint() -> Result<(PathBuf, PathBuf), BridgeError> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or(BridgeError::Unavailable)?;
        let root = runtime.join("fugue/socket-boundary");
        Ok((root.clone(), root.join("socket/rig.sock")))
    }

    fn reject_symlink_ancestry(path: &Path) -> Result<(), BridgeError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::Prefix(_) => current.push(component),
                Component::Normal(part) => current.push(part),
                _ => return Err(BridgeError::Security),
            }
            let details = fs::symlink_metadata(&current).map_err(|_| BridgeError::Unavailable)?;
            if details.file_type().is_symlink() {
                return Err(BridgeError::Security);
            }
        }
        Ok(())
    }

    fn validate_endpoint(root: &Path, path: &Path) -> Result<Inode, BridgeError> {
        if !root.is_absolute() || !path.is_absolute() || !path.starts_with(root) {
            return Err(BridgeError::Security);
        }
        if path.as_os_str().as_encoded_bytes().len() > 100 {
            return Err(BridgeError::Security);
        }
        reject_symlink_ancestry(root)?;
        reject_symlink_ancestry(path)?;

        let uid = current_uid();
        let root_meta = fs::symlink_metadata(root).map_err(|_| BridgeError::Unavailable)?;
        if !root_meta.is_dir() || root_meta.uid() != uid || root_meta.mode() & 0o022 != 0 {
            return Err(BridgeError::Security);
        }
        let parent = path.parent().ok_or(BridgeError::Security)?;
        let parent_meta = fs::symlink_metadata(parent).map_err(|_| BridgeError::Unavailable)?;
        if !parent_meta.is_dir() || parent_meta.uid() != uid || parent_meta.mode() & 0o777 != 0o700
        {
            return Err(BridgeError::Security);
        }
        let socket_meta = fs::symlink_metadata(path).map_err(|_| BridgeError::Unavailable)?;
        if !socket_meta.file_type().is_socket()
            || socket_meta.uid() != uid
            || socket_meta.mode() & 0o777 != 0o600
            || socket_meta.nlink() != 1
        {
            return Err(BridgeError::Security);
        }
        Ok(Inode {
            device: socket_meta.dev(),
            inode: socket_meta.ino(),
        })
    }

    #[cfg(target_os = "macos")]
    fn peer_uid(stream: &UnixStream) -> Result<u32, BridgeError> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both pointers reference initialized storage and the descriptor
        // remains owned by stream for the duration of this call.
        let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if result == 0 {
            Ok(uid)
        } else {
            Err(BridgeError::Security)
        }
    }

    #[cfg(target_os = "linux")]
    fn peer_uid(stream: &UnixStream) -> Result<u32, BridgeError> {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: credentials and length are valid writable storage and the
        // descriptor remains open for the duration of getsockopt.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut _ as *mut libc::c_void,
                &mut length,
            )
        };
        if result == 0 && length as usize == std::mem::size_of::<libc::ucred>() {
            Ok(credentials.uid)
        } else {
            Err(BridgeError::Security)
        }
    }

    #[cfg(target_os = "macos")]
    fn peer_pid(stream: &UnixStream) -> Result<u32, BridgeError> {
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: pid and length are valid writable storage. LOCAL_PEERPID is
        // stable Darwin ABI option 2 at level 0.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                2,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut length,
            )
        };
        if result == 0 && length as usize == std::mem::size_of::<libc::pid_t>() && pid > 0 {
            u32::try_from(pid).map_err(|_| BridgeError::Security)
        } else {
            Err(BridgeError::Security)
        }
    }

    #[cfg(target_os = "macos")]
    fn managed_controller_pid(uid: u32) -> Result<u32, BridgeError> {
        let target = format!("gui/{uid}/com.tensorhost.oc-rig-v2");
        let output = Command::new("/bin/launchctl")
            .args(["print", &target])
            .env_clear()
            .output()
            .map_err(|_| BridgeError::Security)?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(BridgeError::Security);
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|_| BridgeError::Security)?;
        let mut matches = text.lines().filter_map(|line| {
            line.strip_prefix("\tpid = ")
                .and_then(|value| value.parse::<u32>().ok())
        });
        let pid = matches.next().ok_or(BridgeError::Security)?;
        if matches.next().is_some() || pid == 0 {
            return Err(BridgeError::Security);
        }
        Ok(pid)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn peer_uid(_stream: &UnixStream) -> Result<u32, BridgeError> {
        Err(BridgeError::Security)
    }

    fn revalidate(path: &Path, expected: Inode) -> Result<(), BridgeError> {
        let details = fs::symlink_metadata(path).map_err(|_| BridgeError::Security)?;
        if details.dev() != expected.device || details.ino() != expected.inode {
            return Err(BridgeError::Security);
        }
        Ok(())
    }

    fn wait_for_connect(socket: &Socket, deadline: Instant) -> Result<(), BridgeError> {
        let timeout = remaining(deadline)?;
        let milliseconds = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if ready <= 0 || poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(BridgeError::Unavailable);
        }
        if socket
            .take_error()
            .map_err(|_| BridgeError::Unavailable)?
            .is_some()
        {
            return Err(BridgeError::Unavailable);
        }
        Ok(())
    }

    fn connect_before(path: &Path, deadline: Instant) -> Result<UnixStream, BridgeError> {
        let socket =
            Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|_| BridgeError::Unavailable)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| BridgeError::Unavailable)?;
        let address = SockAddr::unix(path).map_err(|_| BridgeError::Security)?;
        match socket.connect(&address) {
            Ok(()) => {}
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    [libc::EINPROGRESS, libc::EAGAIN, libc::EWOULDBLOCK].contains(&code)
                }) =>
            {
                wait_for_connect(&socket, deadline)?;
            }
            Err(_) => return Err(BridgeError::Unavailable),
        }
        socket
            .set_nonblocking(false)
            .map_err(|_| BridgeError::Unavailable)?;
        let descriptor: OwnedFd = socket.into();
        Ok(descriptor.into())
    }

    fn exchange_inner(
        operation: &str,
        params: Value,
        request_id: &str,
        idempotency_id: &str,
        wait_for_change: bool,
    ) -> Result<Value, BridgeError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (root, path) = endpoint()?;
        let inode = validate_endpoint(&root, &path)?;
        let mut stream = connect_before(&path, deadline)?;
        revalidate(&path, inode)?;
        if peer_uid(&stream)? != current_uid() {
            return Err(BridgeError::Security);
        }
        #[cfg(target_os = "macos")]
        if peer_pid(&stream)? != managed_controller_pid(current_uid())? {
            return Err(BridgeError::Security);
        }
        #[cfg(not(target_os = "macos"))]
        return Err(BridgeError::Security);

        #[cfg(target_os = "macos")]
        {
            let request = request_bytes(operation, params, request_id, idempotency_id)?;
            let response = if wait_for_change {
                exchange_frames_wait(&mut stream, &request, deadline)?
            } else {
                exchange_frames(&mut stream, &request, deadline)?
            };
            let value: Value =
                serde_json::from_slice(&response).map_err(|_| BridgeError::Protocol)?;
            if !value.is_object() {
                return Err(BridgeError::Protocol);
            }
            Ok(value)
        }
    }

    pub(super) fn exchange(
        operation: &str,
        params: Value,
        request_id: &str,
        idempotency_id: &str,
    ) -> Result<Value, BridgeError> {
        exchange_inner(operation, params, request_id, idempotency_id, false)
    }

    pub(super) fn exchange_wait(
        operation: &str,
        params: Value,
        request_id: &str,
        idempotency_id: &str,
    ) -> Result<Value, BridgeError> {
        exchange_inner(operation, params, request_id, idempotency_id, true)
    }
}

#[cfg(windows)]
mod platform {
    use super::{BridgeError, Value};

    pub(super) fn exchange(
        _operation: &str,
        _params: Value,
        _request_id: &str,
        _idempotency_id: &str,
    ) -> Result<Value, BridgeError> {
        // The UI compiles on Windows now. The controller's named-pipe transport
        // will implement this same fixed, no-argument boundary in Phase 2.
        Err(BridgeError::Unavailable)
    }

    pub(super) fn exchange_wait(
        _operation: &str,
        _params: Value,
        _request_id: &str,
        _idempotency_id: &str,
    ) -> Result<Value, BridgeError> {
        Err(BridgeError::Unavailable)
    }
}

pub(crate) fn load_snapshot() -> Result<Value, BridgeError> {
    let request_id = next_identifier("fugue-ui");
    let idempotency_id = next_identifier("fugue-ui-read");
    let payload = platform::exchange(
        "cockpit.snapshot.v1",
        json!({}),
        &request_id,
        &idempotency_id,
    )?;
    let bytes = serde_json::to_vec(&payload).map_err(|_| BridgeError::Protocol)?;
    decode_snapshot(&bytes, &request_id, &idempotency_id)
}

pub(crate) fn watch_snapshot(after_event_sequence: i64) -> Result<Value, BridgeError> {
    if after_event_sequence < 0 {
        return Err(BridgeError::Protocol);
    }
    let request_id = next_identifier("fugue-ui");
    let idempotency_id = next_identifier("fugue-ui-watch");
    let payload = platform::exchange_wait(
        "cockpit.watch.v1",
        json!({"after_event_sequence": after_event_sequence}),
        &request_id,
        &idempotency_id,
    )?;
    let bytes = serde_json::to_vec(&payload).map_err(|_| BridgeError::Protocol)?;
    decode_snapshot(&bytes, &request_id, &idempotency_id)
}

pub(crate) fn call_controller(
    operation: &'static str,
    params: Value,
    idempotency_id: String,
) -> Result<Value, BridgeError> {
    let request_id = next_identifier("fugue-ui");
    let payload = platform::exchange(operation, params, &request_id, &idempotency_id)?;
    let bytes = serde_json::to_vec(&payload).map_err(|_| BridgeError::Protocol)?;
    decode_result(&bytes, &request_id, &idempotency_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_is_exact_and_bounded() {
        let bytes = request_bytes(
            "cockpit.snapshot.v1",
            json!({}),
            "request-1",
            "idempotency-1",
        )
        .unwrap();
        assert!(bytes.len() < MAX_FRAME_BYTES);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            json!({
                "idempotency_id": "idempotency-1",
                "message_type": "request",
                "operation": "cockpit.snapshot.v1",
                "params": {},
                "request_id": "request-1",
                "version": 1,
            })
        );
    }

    #[test]
    fn watch_request_carries_only_the_last_validated_sequence() {
        let bytes = request_bytes(
            "cockpit.watch.v1",
            json!({"after_event_sequence": 27}),
            "request-watch",
            "idempotency-watch",
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["operation"], "cockpit.watch.v1");
        assert_eq!(value["params"], json!({"after_event_sequence": 27}));
    }

    #[test]
    fn framing_is_big_endian_and_round_trips() {
        let payload = br#"{"snapshot":true}"#;
        let mut bytes = Vec::new();
        write_frame(&mut bytes, payload).unwrap();
        assert_eq!(&bytes[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(read_frame(Cursor::new(bytes)).unwrap(), payload);
    }

    #[test]
    fn oversized_response_is_rejected_before_allocation() {
        let bytes = ((MAX_FRAME_BYTES as u32) + 1).to_be_bytes();
        assert_eq!(read_frame(Cursor::new(bytes)), Err(BridgeError::Protocol));
    }

    #[test]
    fn response_requires_exact_correlation_and_snapshot() {
        let good = serde_json::to_vec(&json!({
            "version": 1,
            "message_type": "response",
            "request_id": "request-1",
            "idempotency_id": "idempotency-1",
            "ok": true,
            "result": {"snapshot": {"availability": {"status": "available"}}},
        }))
        .unwrap();
        let snapshot = decode_snapshot(&good, "request-1", "idempotency-1").unwrap();
        assert!(snapshot.get("availability").is_some());
        assert_eq!(
            decode_snapshot(&good, "other-request", "idempotency-1"),
            Err(BridgeError::Protocol)
        );
    }

    #[test]
    fn result_decoder_preserves_unknown_operation_as_unsupported() {
        let response = serde_json::to_vec(&json!({
            "version": 1,
            "message_type": "response",
            "request_id": "request-1",
            "idempotency_id": "idempotency-1",
            "ok": false,
            "error": {"code": "unknown_operation", "message": "operation is not recognized"},
        }))
        .unwrap();
        assert_eq!(
            decode_result(&response, "request-1", "idempotency-1"),
            Err(BridgeError::Unsupported)
        );
        let malformed = serde_json::to_vec(&json!({
            "version": 1,
            "message_type": "response",
            "request_id": "request-1",
            "idempotency_id": "idempotency-1",
            "ok": false,
            "result": {"must": "not coexist with failure"},
            "error": {"code": "unknown_operation", "message": "operation is not recognized"},
        }))
        .unwrap();
        assert_eq!(
            decode_result(&malformed, "request-1", "idempotency-1"),
            Err(BridgeError::Protocol)
        );
        let explicit_null_result = serde_json::to_vec(&json!({
            "version": 1,
            "message_type": "response",
            "request_id": "request-1",
            "idempotency_id": "idempotency-1",
            "ok": false,
            "result": null,
            "error": {"code": "unknown_operation", "message": "operation is not recognized"},
        }))
        .unwrap();
        assert_eq!(
            decode_result(&explicit_null_result, "request-1", "idempotency-1"),
            Err(BridgeError::Protocol)
        );
        let missing_error = serde_json::to_vec(&json!({
            "version": 1,
            "message_type": "response",
            "request_id": "request-1",
            "idempotency_id": "idempotency-1",
            "ok": false,
        }))
        .unwrap();
        assert_eq!(
            decode_result(&missing_error, "request-1", "idempotency-1"),
            Err(BridgeError::Protocol)
        );
    }

    #[test]
    fn public_errors_never_expose_paths_or_protocol_details() {
        for error in [
            BridgeError::Unavailable,
            BridgeError::Security,
            BridgeError::Protocol,
            BridgeError::Rejected,
            BridgeError::Unsupported,
        ] {
            let message = error.public_message();
            assert!(!message.contains('/'));
            assert!(!message.contains("rig.sock"));
            assert!(!message.contains("request_id"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn frame_exchange_obeys_one_absolute_deadline() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut request_header = [0_u8; 4];
            server.read_exact(&mut request_header).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(request_header) as usize];
            server.read_exact(&mut request).unwrap();
            thread::sleep(Duration::from_millis(80));
        });
        let deadline = Instant::now() + Duration::from_millis(30);
        assert_eq!(
            exchange_frames(&mut client, b"{}", deadline),
            Err(BridgeError::Unavailable)
        );
        server_thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn change_wait_has_a_bounded_write_and_an_unbounded_read() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut request_header = [0_u8; 4];
            server.read_exact(&mut request_header).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(request_header) as usize];
            server.read_exact(&mut request).unwrap();
            thread::sleep(Duration::from_millis(80));
            let response = br#"{"changed":true}"#;
            server
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            server.write_all(response).unwrap();
        });
        let deadline = Instant::now() + Duration::from_millis(30);
        assert_eq!(
            exchange_frames_wait(&mut client, b"{}", deadline).unwrap(),
            br#"{"changed":true}"#,
        );
        server_thread.join().unwrap();
    }

    #[test]
    #[ignore = "requires a running local Fugue controller"]
    fn live_controller_returns_a_cockpit_snapshot() {
        let snapshot = load_snapshot().expect("running controller should return a snapshot");
        assert!(snapshot.get("availability").is_some());
        assert!(snapshot.get("worker_graph").is_some());
        assert!(snapshot.get("queue").is_some());
        assert!(snapshot.get("attention").is_some());
    }
}
