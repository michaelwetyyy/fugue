use crate::dev_lab;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Number, Value};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fmt::{self, Write as _};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MCP_PATH: &str = "/mcp";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 16;
const MAX_SESSIONS: usize = 32;
const INITIALIZATION_TTL: Duration = Duration::from_secs(30);
const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
const TOOL_CALL_WINDOW: Duration = Duration::from_secs(60);
const TOOL_CALL_LIMIT: usize = 60;
const REQUEST_DEADLINE: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const AUTH_FILE_NAME: &str = "auth-header";

#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
#[cfg(target_os = "macos")]
const ACL_FIRST_ENTRY: libc::c_int = 0;
#[cfg(target_os = "macos")]
const ACL_NEXT_ENTRY: libc::c_int = -1;
#[cfg(target_os = "macos")]
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
#[cfg(target_os = "macos")]
const ACL_EXTENDED_DENY: libc::c_int = 2;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry_p: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag_type: *mut libc::c_int) -> libc::c_int;
    fn acl_free(object: *mut libc::c_void) -> libc::c_int;
}

#[derive(Clone)]
struct ServerState {
    authorization: Arc<str>,
    address: SocketAddr,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    active_connections: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionPhase {
    AwaitingInitialized,
    Ready,
}

struct Session {
    phase: SessionPhase,
    created_at: Instant,
    last_seen: Instant,
    tool_calls: VecDeque<Instant>,
}

impl Session {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            phase: SessionPhase::AwaitingInitialized,
            created_at: now,
            last_seen: now,
            tool_calls: VecDeque::new(),
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        match self.phase {
            SessionPhase::AwaitingInitialized => {
                now.duration_since(self.created_at) >= INITIALIZATION_TTL
            }
            SessionPhase::Ready => now.duration_since(self.last_seen) >= SESSION_TTL,
        }
    }

    fn note_tool_call(&mut self, now: Instant) -> bool {
        while self
            .tool_calls
            .front()
            .is_some_and(|seen| now.duration_since(*seen) >= TOOL_CALL_WINDOW)
        {
            self.tool_calls.pop_front();
        }
        if self.tool_calls.len() >= TOOL_CALL_LIMIT {
            return false;
        }
        self.tool_calls.push_back(now);
        true
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn validate_application_identity(
    identifier: &str,
    product_name: Option<&str>,
) -> Result<(), String> {
    if identifier != dev_lab::APP_IDENTIFIER || product_name != Some("Fugue Dev") {
        return Err("Fugue Dev MCP application identity mismatch".to_owned());
    }
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueJsonVisitor;

        impl<'de> Visitor<'de> for UniqueJsonVisitor {
            type Value = UniqueJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(Number::from(value))))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(Number::from(value))))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(|number| UniqueJsonValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value.to_owned())))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                UniqueJsonValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some(key) = entries.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    let value = entries.next_value::<UniqueJsonValue>()?;
                    values.insert(key, value.0);
                }
                Ok(UniqueJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

fn parse_unique_json(body: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value.0)
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn json(status: u16, reason: &'static str, value: &Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
                .to_vec()
        });
        let body = if body.len() <= MAX_RESPONSE_BYTES {
            body
        } else {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Response too large"}}"#
                .to_vec()
        };
        Self {
            status,
            reason,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body,
        }
    }

    fn with_header(mut self, key: &str, value: String) -> Self {
        self.headers.push((key.to_owned(), value));
        self
    }
}

pub(crate) struct DevMcpServer {
    shutdown: Arc<AtomicBool>,
    address: SocketAddr,
    thread: Option<JoinHandle<()>>,
}

impl DevMcpServer {
    pub(crate) fn start() -> Result<Self, String> {
        let authorization = load_or_create_authorization()?;
        Self::start_with(
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                dev_lab::BACKEND_PORT,
            )),
            authorization,
        )
    }

    fn start_with(address: SocketAddr, authorization: String) -> Result<Self, String> {
        if !address.ip().is_loopback() {
            return Err("Fugue Dev MCP must bind to loopback".to_owned());
        }
        validate_authorization(&authorization)?;
        let listener = TcpListener::bind(address)
            .map_err(|_| "Fugue Dev MCP loopback port is unavailable".to_owned())?;
        let address = listener
            .local_addr()
            .map_err(|_| "Fugue Dev MCP address is unavailable".to_owned())?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let state = ServerState {
            authorization: Arc::from(authorization),
            address,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(AtomicUsize::new(0)),
        };
        let thread_shutdown = shutdown.clone();
        let thread = thread::Builder::new()
            .name("fugue-dev-mcp".to_owned())
            .spawn(move || accept_loop(listener, state, thread_shutdown))
            .map_err(|_| "Fugue Dev MCP server thread could not start".to_owned())?;
        Ok(Self {
            shutdown,
            address,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for DevMcpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(200));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn accept_loop(listener: TcpListener, state: ServerState, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        let Ok((stream, _peer)) = listener.accept() else {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            continue;
        };
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let previous = state.active_connections.fetch_add(1, Ordering::SeqCst);
        if previous >= MAX_CONNECTIONS {
            state.active_connections.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = write_response(&mut stream, HttpResponse::empty(503, "Service Unavailable"));
            continue;
        }
        let child_state = state.clone();
        let counter = state.active_connections.clone();
        if thread::Builder::new()
            .name("fugue-dev-mcp-connection".to_owned())
            .spawn(move || {
                let _guard = ConnectionGuard(child_state.active_connections.clone());
                handle_connection(stream, &child_state);
            })
            .is_err()
        {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn handle_connection(mut stream: TcpStream, state: &ServerState) {
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let response = match read_request(&mut stream, deadline) {
        Ok(request) => handle_http(request, state),
        Err(status) => HttpResponse::empty(status, status_reason(status)),
    };
    let _ = write_response(&mut stream, response);
}

fn status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<HttpRequest, u16> {
    let mut received = Vec::with_capacity(4096);
    let header_end = loop {
        if received.len() > MAX_HEADER_BYTES {
            return Err(413);
        }
        if let Some(position) = find_bytes(&received, b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0_u8; 4096];
        let count = read_before_deadline(stream, &mut chunk, deadline)?;
        if count == 0 {
            return Err(400);
        }
        received.extend_from_slice(&chunk[..count]);
    };
    let header = std::str::from_utf8(&received[..header_end]).map_err(|_| 400_u16)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(400_u16)?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().ok_or(400_u16)?.to_owned();
    let path = request_parts.next().ok_or(400_u16)?.to_owned();
    if request_parts.next() != Some("HTTP/1.1") || request_parts.next().is_some() {
        return Err(400);
    }
    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400_u16)?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(400);
        }
        let value = value.trim().to_owned();
        if value.bytes().any(|byte| byte < 0x20 && byte != b'\t') {
            return Err(400);
        }
        if headers.insert(name, value).is_some() {
            return Err(400);
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(400);
    }
    let content_length = match headers.get("content-length") {
        Some(value) => value.parse::<usize>().map_err(|_| 400_u16)?,
        None if method == "POST" => return Err(400),
        None => 0,
    };
    if content_length > MAX_BODY_BYTES {
        return Err(413);
    }
    let already = received.len().saturating_sub(header_end);
    if already > content_length {
        received.truncate(header_end + content_length);
    }
    while received.len() - header_end < content_length {
        let remaining = content_length - (received.len() - header_end);
        let mut chunk = [0_u8; 4096];
        let amount = remaining.min(chunk.len());
        let count = read_before_deadline(stream, &mut chunk[..amount], deadline)?;
        if count == 0 {
            return Err(400);
        }
        received.extend_from_slice(&chunk[..count]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: received[header_end..header_end + content_length].to_vec(),
    })
}

fn read_before_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, u16> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(408_u16)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| 503_u16)?;
    match stream.read(buffer) {
        Ok(count) => Ok(count),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(408)
        }
        Err(_) => Err(400),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason);
    head.push_str("Cache-Control: no-store\r\n");
    head.push_str("Connection: close\r\n");
    head.push_str("X-Content-Type-Options: nosniff\r\n");
    for (name, value) in response.headers {
        write!(&mut head, "{name}: {value}\r\n").expect("String writes cannot fail");
    }
    write!(&mut head, "Content-Length: {}\r\n\r\n", response.body.len())
        .expect("String writes cannot fail");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn handle_http(request: HttpRequest, state: &ServerState) -> HttpResponse {
    if !host_is_allowed(request.headers.get("host"), state.address) {
        return HttpResponse::empty(403, "Forbidden");
    }
    if !origin_is_allowed(request.headers.get("origin"), state.address) {
        return HttpResponse::empty(403, "Forbidden");
    }
    if !authorization_matches(
        request.headers.get("authorization").map(String::as_str),
        &state.authorization,
    ) {
        return HttpResponse::empty(401, "Unauthorized")
            .with_header("WWW-Authenticate", "Bearer".to_owned());
    }
    if request.path != MCP_PATH {
        return HttpResponse::empty(404, "Not Found");
    }
    match request.method.as_str() {
        "GET" | "DELETE" => {
            HttpResponse::empty(405, "Method Not Allowed").with_header("Allow", "POST".to_owned())
        }
        "POST" => handle_post(request, state),
        _ => HttpResponse::empty(405, "Method Not Allowed").with_header("Allow", "POST".to_owned()),
    }
}

fn host_is_allowed(host: Option<&String>, address: SocketAddr) -> bool {
    let Some(host) = host else {
        return false;
    };
    let port = address.port();
    let host = host.to_ascii_lowercase();
    host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

fn origin_is_allowed(origin: Option<&String>, address: SocketAddr) -> bool {
    match origin.map(String::as_str) {
        None => true,
        Some("https://chatgpt.com") => true,
        Some(value) => {
            let port = address.port();
            value == format!("http://127.0.0.1:{port}")
                || value == format!("http://localhost:{port}")
        }
    }
}

fn authorization_matches(candidate: Option<&str>, expected: &str) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    let candidate = candidate.as_bytes();
    let expected = expected.as_bytes();
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn handle_post(request: HttpRequest, state: &ServerState) -> HttpResponse {
    if !accept_header_is_valid(request.headers.get("accept")) {
        return HttpResponse::empty(400, "Bad Request");
    }
    if !content_type_is_json(request.headers.get("content-type")) {
        return HttpResponse::empty(415, "Unsupported Media Type");
    }
    let message: Value = match parse_unique_json(&request.body) {
        Ok(Value::Array(_)) => {
            return jsonrpc_error(Value::Null, -32600, "JSON-RPC batches are not supported")
        }
        Ok(value) => value,
        Err(error) if error.is_data() => {
            return jsonrpc_error(Value::Null, -32600, "Invalid Request")
        }
        Err(_) => return jsonrpc_error(Value::Null, -32700, "Parse error"),
    };
    let Some(object) = message.as_object() else {
        return jsonrpc_error(Value::Null, -32600, "Invalid Request");
    };
    if object.get("jsonrpc") != Some(&Value::String("2.0".to_owned())) {
        return jsonrpc_error(id_or_null(object), -32600, "Invalid Request");
    }
    let method = match object.get("method").and_then(Value::as_str) {
        Some(value) => value,
        None => return HttpResponse::empty(400, "Bad Request"),
    };
    let has_id = object.contains_key("id");
    if has_id && !valid_request_id(object.get("id")) {
        return jsonrpc_error(Value::Null, -32600, "Invalid Request");
    }
    if method == "initialize" {
        return initialize(object, &request.headers, state);
    }
    let session_id = match validated_session_headers(&request.headers, state) {
        Ok(value) => value,
        Err(status) => return HttpResponse::empty(status, status_reason(status)),
    };
    if !has_id {
        return handle_notification(method, object.get("params"), &session_id, state);
    }
    handle_request(
        method,
        object.get("params"),
        object.get("id").cloned().unwrap_or(Value::Null),
        &session_id,
        state,
    )
}

fn accept_header_is_valid(value: Option<&String>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mut json = false;
    let mut event_stream = false;
    for item in value.split(',') {
        let media = item
            .trim()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        json |= media == "application/json";
        event_stream |= media == "text/event-stream";
    }
    json && event_stream
}

fn content_type_is_json(value: Option<&String>) -> bool {
    value.is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
}

fn valid_request_id(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(_)) | Some(Value::Number(_)))
}

fn id_or_null(object: &Map<String, Value>) -> Value {
    object
        .get("id")
        .filter(|value| matches!(value, Value::String(_) | Value::Number(_)))
        .cloned()
        .unwrap_or(Value::Null)
}

fn initialize(
    object: &Map<String, Value>,
    headers: &HashMap<String, String>,
    state: &ServerState,
) -> HttpResponse {
    if headers.contains_key("mcp-session-id") || headers.contains_key("mcp-protocol-version") {
        return HttpResponse::empty(400, "Bad Request");
    }
    let id = match object.get("id") {
        Some(value) if valid_request_id(Some(value)) => value.clone(),
        _ => return jsonrpc_error(Value::Null, -32600, "Initialize must be a request"),
    };
    let Some(params) = object.get("params").and_then(Value::as_object) else {
        return jsonrpc_error(id, -32602, "Invalid initialize parameters");
    };
    let Some(protocol) = params.get("protocolVersion").and_then(Value::as_str) else {
        return jsonrpc_error(id, -32602, "Invalid initialize parameters");
    };
    if protocol.is_empty() || protocol.len() > 64 || !protocol.is_ascii() {
        return jsonrpc_error(id, -32602, "Invalid initialize parameters");
    }
    if !params.get("capabilities").is_some_and(Value::is_object)
        || !params.get("clientInfo").is_some_and(Value::is_object)
    {
        return jsonrpc_error(id, -32602, "Invalid initialize parameters");
    }
    let session_id = match create_session(state) {
        Ok(value) => value,
        Err(()) => return HttpResponse::empty(503, "Service Unavailable"),
    };
    jsonrpc_result(
        id,
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": dev_lab::MCP_NAME,
                "title": "Fugue Dev",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Isolated read-only synthetic Fugue development MCP server"
            }
        }),
    )
    .with_header("MCP-Session-Id", session_id)
}

fn create_session(state: &ServerState) -> Result<String, ()> {
    let mut sessions = state.sessions.lock().map_err(|_| ())?;
    expire_sessions(&mut sessions);
    if sessions.len() >= MAX_SESSIONS {
        return Err(());
    }
    for _ in 0..4 {
        let id = random_hex(32).map_err(|_| ())?;
        if !sessions.contains_key(&id) {
            sessions.insert(id.clone(), Session::new());
            return Ok(id);
        }
    }
    Err(())
}

fn expire_sessions(sessions: &mut HashMap<String, Session>) {
    let now = Instant::now();
    sessions.retain(|_, session| !session.is_expired(now));
}

fn validated_session_headers(
    headers: &HashMap<String, String>,
    state: &ServerState,
) -> Result<String, u16> {
    if headers.get("mcp-protocol-version").map(String::as_str) != Some(MCP_PROTOCOL_VERSION) {
        return Err(400);
    }
    let session_id = headers.get("mcp-session-id").ok_or(400_u16)?.clone();
    if session_id.is_empty() || !session_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(400);
    }
    let mut sessions = state.sessions.lock().map_err(|_| 503_u16)?;
    expire_sessions(&mut sessions);
    let session = sessions.get_mut(&session_id).ok_or(404_u16)?;
    session.last_seen = Instant::now();
    Ok(session_id)
}

fn handle_notification(
    method: &str,
    params: Option<&Value>,
    session_id: &str,
    state: &ServerState,
) -> HttpResponse {
    if method != "notifications/initialized" || !empty_or_meta_params(params) {
        return HttpResponse::empty(400, "Bad Request");
    }
    let Ok(mut sessions) = state.sessions.lock() else {
        return HttpResponse::empty(503, "Service Unavailable");
    };
    let Some(session) = sessions.get_mut(session_id) else {
        return HttpResponse::empty(404, "Not Found");
    };
    if session.phase != SessionPhase::AwaitingInitialized {
        return HttpResponse::empty(400, "Bad Request");
    }
    session.phase = SessionPhase::Ready;
    session.last_seen = Instant::now();
    HttpResponse::empty(202, "Accepted")
}

fn handle_request(
    method: &str,
    params: Option<&Value>,
    id: Value,
    session_id: &str,
    state: &ServerState,
) -> HttpResponse {
    let phase = match session_phase(session_id, state) {
        Ok(value) => value,
        Err(status) => return HttpResponse::empty(status, status_reason(status)),
    };
    if method == "ping" {
        if !empty_or_meta_params(params) {
            return jsonrpc_error(id, -32602, "Invalid params");
        }
        return jsonrpc_result(id, json!({}));
    }
    if phase != SessionPhase::Ready {
        return jsonrpc_error(id, -32002, "Server initialization is not complete");
    }
    match method {
        "tools/list" => list_tools(params, id),
        "tools/call" => call_tool(params, id, session_id, state),
        _ => jsonrpc_error(id, -32601, "Method not found"),
    }
}

fn session_phase(session_id: &str, state: &ServerState) -> Result<SessionPhase, u16> {
    let sessions = state.sessions.lock().map_err(|_| 503_u16)?;
    sessions
        .get(session_id)
        .map(|value| value.phase)
        .ok_or(404_u16)
}

fn empty_or_meta_params(params: Option<&Value>) -> bool {
    match params {
        None | Some(Value::Null) => true,
        Some(Value::Object(value)) => {
            value.is_empty()
                || (value.len() == 1
                    && value
                        .get("_meta")
                        .is_some_and(|metadata| metadata.is_object()))
        }
        _ => false,
    }
}

fn valid_optional_meta(object: &Map<String, Value>) -> bool {
    object.get("_meta").is_none_or(Value::is_object)
}

fn list_tools(params: Option<&Value>, id: Value) -> HttpResponse {
    if let Some(value) = params {
        let Some(object) = value.as_object() else {
            return jsonrpc_error(id, -32602, "Invalid params");
        };
        if object.keys().any(|key| key != "cursor" && key != "_meta")
            || object.get("cursor").is_some_and(|cursor| !cursor.is_null())
            || !valid_optional_meta(object)
        {
            return jsonrpc_error(id, -32602, "Invalid params");
        }
    }
    jsonrpc_result(
        id,
        json!({
            "tools": [
                tool_definition(
                    "fugue_dev_status",
                    "Fugue Dev Status",
                    "Read the fixed isolation and integration status of the synthetic Fugue development laboratory."
                ),
                tool_definition(
                    "fugue_dev_snapshot",
                    "Fugue Dev Snapshot",
                    "Read the bounded synthetic Fugue cockpit snapshot after fail-closed invariant validation."
                )
            ]
        }),
    )
}

fn tool_definition(name: &str, title: &str, description: &str) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": false
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        },
        "execution": {
            "taskSupport": "forbidden"
        }
    })
}

fn call_tool(
    params: Option<&Value>,
    id: Value,
    session_id: &str,
    state: &ServerState,
) -> HttpResponse {
    let Some(params) = params.and_then(Value::as_object) else {
        return jsonrpc_error(id, -32602, "Invalid params");
    };
    if params
        .keys()
        .any(|key| key != "name" && key != "arguments" && key != "_meta")
    {
        return jsonrpc_error(id, -32602, "Invalid params");
    }
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc_error(id, -32602, "Invalid params");
    };
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    if !matches!(arguments, Value::Null)
        && !arguments
            .as_object()
            .is_some_and(|arguments| arguments.is_empty())
    {
        return jsonrpc_error(id, -32602, "Tool arguments must be an empty object");
    }
    if !valid_optional_meta(params) {
        return jsonrpc_error(id, -32602, "Invalid params");
    }
    if !note_tool_call(session_id, state) {
        return HttpResponse::empty(429, "Too Many Requests");
    }
    let output = match name {
        "fugue_dev_status" => dev_status(),
        "fugue_dev_snapshot" => match validated_snapshot() {
            Ok(value) => value,
            Err(reason) => return tool_error(id, reason),
        },
        _ => return jsonrpc_error(id, -32602, "Unknown tool"),
    };
    let text = match serde_json::to_string(&output) {
        Ok(value) if value.len() <= MAX_RESPONSE_BYTES / 2 => value,
        _ => return tool_error(id, "synthetic_output_invalid"),
    };
    jsonrpc_result(
        id,
        json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": output,
            "isError": false
        }),
    )
}

fn note_tool_call(session_id: &str, state: &ServerState) -> bool {
    let Ok(mut sessions) = state.sessions.lock() else {
        return false;
    };
    let Some(session) = sessions.get_mut(session_id) else {
        return false;
    };
    let now = Instant::now();
    session.last_seen = now;
    session.note_tool_call(now)
}

fn dev_status() -> Value {
    json!({
        "mcp_name": dev_lab::MCP_NAME,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "application_identifier": dev_lab::APP_IDENTIFIER,
        "launchd_label": dev_lab::LAUNCHD_LABEL,
        "development_port": dev_lab::BACKEND_PORT,
        "synthetic": true,
        "callback_mode": dev_lab::CALLBACK_MODE,
        "backend": "disabled",
        "opencode": "disabled",
        "live_controller": "disabled",
        "codex_app_server": "disabled",
        "message_delivery": "disabled",
        "snapshot_source": "dev_lab"
    })
}

fn validated_snapshot() -> Result<Value, &'static str> {
    let snapshot = dev_lab::snapshot();
    if snapshot["snapshot_version"]["migration_version"] != "dev-synthetic-v1"
        || !snapshot["snapshot_version"]["event_sequence"].is_null()
        || snapshot["snapshot_version"]["digest"] != "synthetic-no-provenance"
    {
        return Err("synthetic_snapshot_provenance_invalid");
    }
    if snapshot["topology"]["expected_slots"] != 13
        || snapshot["topology"]["observed_slots"] != 13
        || snapshot["topology"]["observed_status"] != "exact"
        || snapshot["worker_graph"]["workers"].as_array().map(Vec::len) != Some(13)
    {
        return Err("synthetic_snapshot_topology_invalid");
    }
    let integration = dev_lab::integration_status();
    if integration["armed"] != false
        || integration["ready"] != false
        || integration["backend_ready"] != false
        || integration["notifier_ready"] != false
        || integration["codex_cli"] != false
        || integration["pending_callbacks"] != 0
        || integration["queued_dispatches"] != 0
    {
        return Err("synthetic_snapshot_integration_invalid");
    }
    let Some(workers) = snapshot["worker_graph"]["workers"].as_array() else {
        return Err("synthetic_snapshot_workers_invalid");
    };
    if workers.iter().any(|worker| {
        worker["completion"]["callback_adapter"]["status"] != "disabled"
            || worker["recent_turns"]["content_included"] != false
    }) {
        return Err("synthetic_snapshot_live_surface_detected");
    }
    if snapshot["recent_turns"]["content_included"] != false {
        return Err("synthetic_snapshot_content_detected");
    }
    Ok(snapshot)
}

fn tool_error(id: Value, reason: &'static str) -> HttpResponse {
    jsonrpc_result(
        id,
        json!({
            "content": [{"type": "text", "text": reason}],
            "isError": true
        }),
    )
}

fn jsonrpc_result(id: Value, result: Value) -> HttpResponse {
    HttpResponse::json(
        200,
        "OK",
        &json!({"jsonrpc": "2.0", "id": id, "result": result}),
    )
}

fn jsonrpc_error(id: Value, code: i64, message: &'static str) -> HttpResponse {
    HttpResponse::json(
        200,
        "OK",
        &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    )
}

fn validate_authorization(value: &str) -> Result<(), String> {
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err("Fugue Dev MCP authorization format is invalid".to_owned());
    };
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Fugue Dev MCP authorization format is invalid".to_owned());
    }
    Ok(())
}

fn load_or_create_authorization() -> Result<String, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "Fugue Dev MCP requires an absolute HOME".to_owned())?;
    load_or_create_authorization_at(&home)
}

fn load_or_create_authorization_at(home: &Path) -> Result<String, String> {
    if !home.is_absolute() {
        return Err("Fugue Dev MCP requires an absolute HOME".to_owned());
    }

    let home = open_home_directory(home)?;
    let library =
        open_child_directory(&home, "Library", false, DirectoryAclPolicy::DenyOnlyOrNone)?;
    let support = open_child_directory(
        &library,
        "Application Support",
        false,
        DirectoryAclPolicy::DenyOnlyOrNone,
    )?;
    let deployment = open_child_directory(
        &support,
        "oc-rig-v2-dev",
        true,
        DirectoryAclPolicy::NoneOnly,
    )?;
    let directory = open_child_directory(&deployment, "mcp", true, DirectoryAclPolicy::NoneOnly)?;

    match open_authorization_at(&directory, libc::O_RDONLY, 0) {
        Ok(file) => return read_authorization_file(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Fugue Dev MCP auth file is unavailable".to_owned()),
    }

    let authorization = format!("Bearer {}", random_hex(32)?);
    let mut file = match open_authorization_at(
        &directory,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_authorization_at(&directory, libc::O_RDONLY, 0)
                .map_err(|_| "Fugue Dev MCP auth file is unavailable".to_owned())?;
            return read_authorization_file(file);
        }
        Err(_) => return Err("Fugue Dev MCP auth file could not be created".to_owned()),
    };
    verify_private_auth_file(&file)?;
    file.write_all(authorization.as_bytes())
        .map_err(|_| "Fugue Dev MCP auth file could not be written".to_owned())?;
    file.sync_all()
        .map_err(|_| "Fugue Dev MCP auth file could not be synced".to_owned())?;
    Ok(authorization)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryAclPolicy {
    DenyOnlyOrNone,
    NoneOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtendedAclState {
    None,
    DenyOnly,
    GrantsAccess,
}

fn open_home_directory(home: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
    let directory = options
        .open(home)
        .map_err(|_| "Fugue Dev MCP private directory is unavailable".to_owned())?;
    verify_directory_descriptor(&directory, false, DirectoryAclPolicy::DenyOnlyOrNone)?;
    Ok(directory)
}

fn child_name(name: &str) -> Result<CString, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err("Fugue Dev MCP private path component is invalid".to_owned());
    }
    CString::new(name).map_err(|_| "Fugue Dev MCP private path component is invalid".to_owned())
}

fn open_child_directory(
    parent: &File,
    name: &str,
    create: bool,
    acl_policy: DirectoryAclPolicy,
) -> Result<File, String> {
    let name = child_name(name)?;
    if create {
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err("Fugue Dev MCP private directory could not be created".to_owned());
            }
        }
    }

    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err("Fugue Dev MCP private directory is unavailable".to_owned());
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    verify_directory_descriptor(&directory, create, acl_policy)?;
    Ok(directory)
}

fn verify_directory_descriptor(
    directory: &File,
    require_private_mode: bool,
    acl_policy: DirectoryAclPolicy,
) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|_| "Fugue Dev MCP private directory metadata is unavailable".to_owned())?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
        || (require_private_mode && mode != 0o700)
    {
        return Err("Fugue Dev MCP private directory failed identity policy".to_owned());
    }
    let acl_state = descriptor_acl_state(directory)?;
    let acl_ok = match acl_policy {
        DirectoryAclPolicy::DenyOnlyOrNone => acl_state != ExtendedAclState::GrantsAccess,
        DirectoryAclPolicy::NoneOnly => acl_state == ExtendedAclState::None,
    };
    if !acl_ok {
        return Err("Fugue Dev MCP private directory failed identity policy".to_owned());
    }
    Ok(())
}

fn open_authorization_at(
    parent: &File,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    let name = CString::new(AUTH_FILE_NAME).expect("static auth file name cannot contain NUL");
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn descriptor_acl_state(file: &File) -> Result<ExtendedAclState, String> {
    unsafe {
        *libc::__error() = 0;
        let acl = acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return match *libc::__error() {
                libc::ENOENT => Ok(ExtendedAclState::None),
                _ => Err("Fugue Dev MCP ACL inspection failed".to_owned()),
            };
        }

        let mut state = ExtendedAclState::None;
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            let mut entry: *mut libc::c_void = std::ptr::null_mut();
            *libc::__error() = 0;
            let result = acl_get_entry(acl, entry_id, &mut entry);
            if result != 0 {
                let error = *libc::__error();
                if error == libc::EINVAL {
                    break;
                }
                let _ = acl_free(acl);
                return Err("Fugue Dev MCP ACL inspection failed".to_owned());
            }
            if entry.is_null() {
                let _ = acl_free(acl);
                return Err("Fugue Dev MCP ACL inspection failed".to_owned());
            }
            let mut tag_type = 0;
            if acl_get_tag_type(entry, &mut tag_type) != 0 {
                let _ = acl_free(acl);
                return Err("Fugue Dev MCP ACL inspection failed".to_owned());
            }
            match tag_type {
                ACL_EXTENDED_ALLOW => state = ExtendedAclState::GrantsAccess,
                ACL_EXTENDED_DENY if state == ExtendedAclState::None => {
                    state = ExtendedAclState::DenyOnly
                }
                ACL_EXTENDED_DENY => {}
                _ => state = ExtendedAclState::GrantsAccess,
            }
            entry_id = ACL_NEXT_ENTRY;
        }
        if acl_free(acl) != 0 {
            return Err("Fugue Dev MCP ACL inspection failed".to_owned());
        }
        Ok(state)
    }
}

#[cfg(not(target_os = "macos"))]
fn descriptor_acl_state(_file: &File) -> Result<ExtendedAclState, String> {
    Ok(ExtendedAclState::None)
}

fn read_authorization_file(mut file: File) -> Result<String, String> {
    verify_private_auth_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|_| "Fugue Dev MCP auth file metadata is unavailable".to_owned())?;
    if metadata.len() > 80 {
        return Err("Fugue Dev MCP auth file is invalid".to_owned());
    }
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(|_| "Fugue Dev MCP auth file is invalid".to_owned())?;
    validate_authorization(&value)?;
    Ok(value)
}

fn verify_private_auth_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "Fugue Dev MCP auth file metadata is unavailable".to_owned())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || descriptor_acl_state(file)? != ExtendedAclState::None
    {
        return Err("Fugue Dev MCP auth file failed identity policy".to_owned());
    }
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut raw = vec![0_u8; bytes];
    getrandom::fill(&mut raw)
        .map_err(|_| "Fugue Dev MCP secure randomness is unavailable".to_owned())?;
    let mut encoded = String::with_capacity(bytes * 2);
    for byte in raw {
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;

    const TEST_AUTH: &str =
        "Bearer 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn server() -> DevMcpServer {
        DevMcpServer::start_with(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            TEST_AUTH.to_owned(),
        )
        .unwrap()
    }

    fn request(
        server: &DevMcpServer,
        method: &str,
        body: Option<&str>,
        session: Option<&str>,
        authorization: Option<&str>,
        origin: Option<&str>,
        protocol: Option<&str>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        request_to(
            server.address(),
            method,
            body,
            session,
            authorization,
            origin,
            protocol,
        )
    }

    fn request_to(
        address: SocketAddr,
        method: &str,
        body: Option<&str>,
        session: Option<&str>,
        authorization: Option<&str>,
        origin: Option<&str>,
        protocol: Option<&str>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let body = body.unwrap_or("");
        let mut raw = format!(
            "{method} /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            address.port(),
            body.len()
        );
        if let Some(value) = authorization {
            write!(&mut raw, "Authorization: {value}\r\n").unwrap();
        }
        if let Some(value) = origin {
            write!(&mut raw, "Origin: {value}\r\n").unwrap();
        }
        if let Some(value) = session {
            write!(&mut raw, "MCP-Session-Id: {value}\r\n").unwrap();
        }
        if let Some(value) = protocol {
            write!(&mut raw, "MCP-Protocol-Version: {value}\r\n").unwrap();
        }
        raw.push_str("\r\n");
        raw.push_str(body);
        stream.write_all(raw.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let (name, value) = line.trim_end().split_once(':').unwrap();
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut response_body = vec![0_u8; length];
        reader.read_exact(&mut response_body).unwrap();
        (status, headers, response_body)
    }

    fn raw_status(address: SocketAddr, raw: &str) -> u16 {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        status_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap()
    }

    fn initialize(server: &DevMcpServer) -> String {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}
            }
        })
        .to_string();
        let (status, headers, response) = request(
            server,
            "POST",
            Some(&body),
            None,
            Some(TEST_AUTH),
            None,
            None,
        );
        assert_eq!(status, 200);
        let result: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(result["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(result["result"]["serverInfo"]["name"], dev_lab::MCP_NAME);
        assert_eq!(result["result"]["capabilities"], json!({"tools": {}}));
        headers.get("mcp-session-id").unwrap().clone()
    }

    fn initialized(server: &DevMcpServer, session: &str) {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        .to_string();
        let (status, _, response) = request(
            server,
            "POST",
            Some(&body),
            Some(session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(status, 202);
        assert!(response.is_empty());
    }

    #[test]
    fn application_identity_must_match_the_dev_bundle() {
        let dev: Value = serde_json::from_str(include_str!("../tauri.dev.conf.json")).unwrap();
        let live: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert!(validate_application_identity(
            dev["identifier"].as_str().unwrap(),
            dev["productName"].as_str(),
        )
        .is_ok());
        assert!(validate_application_identity(
            live["identifier"].as_str().unwrap(),
            live["productName"].as_str(),
        )
        .is_err());
        assert!(validate_application_identity(dev_lab::APP_IDENTIFIER, Some("Fugue")).is_err());
        assert!(validate_application_identity(dev_lab::APP_IDENTIFIER, None).is_err());
    }

    #[test]
    fn awaiting_initialization_has_a_nonrenewable_deadline() {
        let now = Instant::now();
        let mut awaiting = Session::new();
        awaiting.created_at = now - INITIALIZATION_TTL - Duration::from_millis(1);
        awaiting.last_seen = now;
        assert!(awaiting.is_expired(now));

        let mut ready = Session::new();
        ready.phase = SessionPhase::Ready;
        ready.created_at = now - INITIALIZATION_TTL - Duration::from_millis(1);
        ready.last_seen = now;
        assert!(!ready.is_expired(now));

        let mut sessions = HashMap::from([("stale".to_owned(), awaiting)]);
        expire_sessions(&mut sessions);
        assert!(sessions.is_empty());
    }

    #[test]
    fn initialization_is_session_bound_and_only_advertises_tools() {
        let server = server();
        let session = initialize(&server);
        assert_eq!(session.len(), 64);
        let ping = json!({"jsonrpc":"2.0","id":"p","method":"ping"}).to_string();
        let (status, _, body) = request(
            &server,
            "POST",
            Some(&ping),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["result"],
            json!({})
        );
    }

    #[test]
    fn initialize_negotiates_to_the_single_supported_revision() {
        let server = server();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-06-01",
                "capabilities": {},
                "clientInfo": {"name": "newer-test", "version": "1"}
            }
        })
        .to_string();
        let (status, headers, response) = request(
            &server,
            "POST",
            Some(&body),
            None,
            Some(TEST_AUTH),
            None,
            None,
        );
        assert_eq!(status, 200);
        assert!(headers.contains_key("mcp-session-id"));
        let value: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(value["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    }

    #[test]
    fn standard_request_meta_is_accepted_but_unknown_params_remain_closed() {
        let server = server();
        let session = initialize(&server);
        let initialized_body = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {"_meta": {"trace": "test"}}
        })
        .to_string();
        assert_eq!(
            request(
                &server,
                "POST",
                Some(&initialized_body),
                Some(&session),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION),
            )
            .0,
            202
        );

        for (id, method, params) in [
            (2, "ping", json!({"_meta":{"progressToken":"p"}})),
            (3, "tools/list", json!({"_meta":{"trace":"test"}})),
        ] {
            let body = json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":method,
                "params":params
            })
            .to_string();
            let (status, _, response) = request(
                &server,
                "POST",
                Some(&body),
                Some(&session),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION),
            );
            assert_eq!(status, 200);
            assert!(serde_json::from_slice::<Value>(&response).unwrap()["result"].is_object());
        }

        let invalid = json!({
            "jsonrpc":"2.0",
            "id":4,
            "method":"tools/list",
            "params":{"_meta":"bad"}
        })
        .to_string();
        let (_, _, response) = request(
            &server,
            "POST",
            Some(&invalid),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32602
        );
    }

    #[test]
    fn tools_are_unavailable_before_initialized_notification() {
        let server = server();
        let session = initialize(&server);
        let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string();
        let (_, _, response) = request(
            &server,
            "POST",
            Some(&body),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32002
        );
    }

    #[test]
    fn tool_list_is_exact_read_only_closed_world_and_task_forbidden() {
        let server = server();
        let session = initialize(&server);
        initialized(&server, &session);
        let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string();
        let (_, _, response) = request(
            &server,
            "POST",
            Some(&body),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        let value: Value = serde_json::from_slice(&response).unwrap();
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "fugue_dev_status");
        assert_eq!(tools[1]["name"], "fugue_dev_snapshot");
        for tool in tools {
            assert_eq!(
                tool["inputSchema"],
                json!({"type":"object","additionalProperties":false})
            );
            assert_eq!(tool["annotations"]["readOnlyHint"], true);
            assert_eq!(tool["annotations"]["destructiveHint"], false);
            assert_eq!(tool["annotations"]["idempotentHint"], true);
            assert_eq!(tool["annotations"]["openWorldHint"], false);
            assert_eq!(tool["execution"]["taskSupport"], "forbidden");
        }
    }

    #[test]
    fn status_and_snapshot_return_only_validated_synthetic_objects() {
        let server = server();
        let session = initialize(&server);
        initialized(&server, &session);
        for (index, tool) in ["fugue_dev_status", "fugue_dev_snapshot"]
            .iter()
            .enumerate()
        {
            let body = json!({
                "jsonrpc":"2.0","id":10+index,"method":"tools/call",
                "params":{"name":tool,"arguments":{}}
            })
            .to_string();
            let (_, _, response) = request(
                &server,
                "POST",
                Some(&body),
                Some(&session),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION),
            );
            let value: Value = serde_json::from_slice(&response).unwrap();
            assert_eq!(value["result"]["isError"], false);
            assert!(value["result"]["structuredContent"].is_object());
            let serialized = value["result"]["content"][0]["text"].as_str().unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(serialized).unwrap(),
                value["result"]["structuredContent"]
            );
        }
    }

    #[test]
    fn authentication_origin_host_and_protocol_fail_closed() {
        let server = server();
        let init = json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"t","version":"1"}}
        }).to_string();
        assert_eq!(
            request(&server, "POST", Some(&init), None, None, None, None).0,
            401
        );
        assert_eq!(
            request(
                &server,
                "POST",
                Some(&init),
                None,
                Some(TEST_AUTH),
                Some("https://evil.invalid"),
                None
            )
            .0,
            403
        );
        let session = initialize(&server);
        initialized(&server, &session);
        let ping = json!({"jsonrpc":"2.0","id":2,"method":"ping"}).to_string();
        assert_eq!(
            request(
                &server,
                "POST",
                Some(&ping),
                Some(&session),
                Some(TEST_AUTH),
                None,
                None
            )
            .0,
            400
        );
        assert_eq!(
            request(
                &server,
                "POST",
                Some(&ping),
                Some("missing"),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION)
            )
            .0,
            404
        );
    }

    #[test]
    fn unsolicited_jsonrpc_response_messages_are_rejected_at_http_boundary() {
        let server = server();
        for body in [
            json!({"jsonrpc":"2.0","id":1,"result":{}}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unexpected"}})
                .to_string(),
        ] {
            let (status, _, response) = request(
                &server,
                "POST",
                Some(&body),
                None,
                Some(TEST_AUTH),
                None,
                None,
            );
            assert_eq!(status, 400);
            assert!(response.is_empty());
        }
    }

    #[test]
    fn duplicate_json_object_keys_are_rejected_before_dispatch() {
        let server = server();
        let session = initialize(&server);
        initialized(&server, &session);
        for body in [
            r#"{"jsonrpc":"2.0","id":2,"method":"ping","method":"tools/list","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fugue_dev_status","name":"fugue_dev_snapshot","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fugue_dev_status","arguments":{},"_meta":{"trace":"first","trace":"second"}}}"#,
        ] {
            let (status, _, response) = request(
                &server,
                "POST",
                Some(body),
                Some(&session),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION),
            );
            assert_eq!(status, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
                -32600
            );
        }

        let malformed = r#"{"jsonrpc":"2.0","id":5,"method":"ping"#;
        let (_, _, response) = request(
            &server,
            "POST",
            Some(malformed),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32700
        );
    }

    #[test]
    fn batches_unknown_methods_and_nonempty_tool_arguments_are_rejected() {
        let server = server();
        let session = initialize(&server);
        initialized(&server, &session);
        let batch = "[]";
        let (_, _, response) = request(
            &server,
            "POST",
            Some(batch),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32600
        );
        let unknown = json!({"jsonrpc":"2.0","id":3,"method":"resources/list"}).to_string();
        let (_, _, response) = request(
            &server,
            "POST",
            Some(&unknown),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32601
        );
        let invalid = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fugue_dev_status","arguments":{"extra":true}}}).to_string();
        let (_, _, response) = request(
            &server,
            "POST",
            Some(&invalid),
            Some(&session),
            Some(TEST_AUTH),
            None,
            Some(MCP_PROTOCOL_VERSION),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["error"]["code"],
            -32602
        );
    }

    #[test]
    fn transport_route_host_binding_shutdown_and_port_conflict_fail_closed() {
        assert!(DevMcpServer::start_with(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            TEST_AUTH.to_owned(),
        )
        .is_err());

        let server = server();
        let (status, headers, _) = request(&server, "GET", None, None, Some(TEST_AUTH), None, None);
        assert_eq!(status, 405);
        assert_eq!(headers.get("allow").map(String::as_str), Some("POST"));

        let empty = "{}";
        let wrong_path = format!(
            "POST /wrong HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: {}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            server.address().port(),
            TEST_AUTH,
            empty.len(),
            empty
        );
        assert_eq!(raw_status(server.address(), &wrong_path), 404);

        let wrong_path_bad_origin = format!(
            "POST /wrong HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: https://evil.invalid\r\nAuthorization: {}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            server.address().port(),
            TEST_AUTH,
            empty.len(),
            empty
        );
        assert_eq!(raw_status(server.address(), &wrong_path_bad_origin), 403);

        let wrong_path_unauthorized = format!(
            "POST /wrong HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            server.address().port(),
            empty.len(),
            empty
        );
        assert_eq!(raw_status(server.address(), &wrong_path_unauthorized), 401);

        let wrong_host = format!(
            "POST /mcp HTTP/1.1\r\nHost: evil.invalid\r\nAuthorization: {}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            TEST_AUTH,
            empty.len(),
            empty
        );
        assert_eq!(raw_status(server.address(), &wrong_host), 403);

        let conflict = DevMcpServer::start_with(server.address(), TEST_AUTH.to_owned());
        assert!(conflict.is_err());
        let address = server.address();
        drop(server);
        let rebound =
            TcpListener::bind(address).expect("dropped MCP listener must release its port");
        drop(rebound);
    }

    #[test]
    fn request_and_session_limits_fail_closed() {
        let server = server();
        let mut stream = TcpStream::connect(server.address()).unwrap();
        let oversized = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: {}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            server.address().port(),
            TEST_AUTH,
            MAX_BODY_BYTES + 1
        );
        stream.write_all(oversized.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        assert_eq!(status_line.split_whitespace().nth(1), Some("413"));

        let mut sessions = Vec::new();
        for _ in 0..MAX_SESSIONS {
            sessions.push(initialize(&server));
        }
        let body = json!({
            "jsonrpc":"2.0","id":999,"method":"initialize",
            "params":{"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}
        })
        .to_string();
        let (status, _, _) = request(
            &server,
            "POST",
            Some(&body),
            None,
            Some(TEST_AUTH),
            None,
            None,
        );
        assert_eq!(status, 503);
        assert_eq!(sessions.len(), MAX_SESSIONS);
    }

    #[test]
    fn absolute_request_deadline_recovers_all_slots_from_slowloris_clients() {
        let server = server();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut stream = TcpStream::connect(server.address()).unwrap();
            stream.write_all(b"P").unwrap();
            held.push(stream);
        }
        thread::sleep(Duration::from_millis(1_000));
        for stream in &mut held {
            let _ = stream.write_all(b"O");
        }
        thread::sleep(Duration::from_millis(1_350));

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "deadline-recovery", "version": "1"}
            }
        })
        .to_string();
        let (status, _, response) = request(
            &server,
            "POST",
            Some(&body),
            None,
            Some(TEST_AUTH),
            None,
            None,
        );
        assert_eq!(status, 200);
        let value: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(value["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    }

    #[test]
    fn connection_limit_returns_service_unavailable_without_underflow() {
        let server = server();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let stream = TcpStream::connect(server.address()).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            held.push(stream);
        }
        thread::sleep(Duration::from_millis(75));
        let mut overflow = TcpStream::connect(server.address()).unwrap();
        overflow
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut reader = BufReader::new(&mut overflow);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        assert_eq!(status_line.split_whitespace().nth(1), Some("503"));
        drop(held);
    }

    #[test]
    fn tool_rate_limit_and_concurrent_clients_are_bounded() {
        let server = server();
        let session = initialize(&server);
        initialized(&server, &session);
        let address = server.address();
        let mut handles = Vec::new();
        for index in 0..8 {
            let session = session.clone();
            handles.push(thread::spawn(move || {
                let body = json!({"jsonrpc":"2.0","id":index,"method":"ping"}).to_string();
                request_to(
                    address,
                    "POST",
                    Some(&body),
                    Some(&session),
                    Some(TEST_AUTH),
                    None,
                    Some(MCP_PROTOCOL_VERSION),
                )
                .0
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().unwrap(), 200);
        }

        for index in 0..TOOL_CALL_LIMIT {
            let body = json!({
                "jsonrpc":"2.0","id":1000+index,"method":"tools/call",
                "params":{"name":"fugue_dev_status","arguments":{}}
            })
            .to_string();
            assert_eq!(
                request(
                    &server,
                    "POST",
                    Some(&body),
                    Some(&session),
                    Some(TEST_AUTH),
                    None,
                    Some(MCP_PROTOCOL_VERSION),
                )
                .0,
                200
            );
        }
        let limited = json!({
            "jsonrpc":"2.0","id":9999,"method":"tools/call",
            "params":{"name":"fugue_dev_status","arguments":{}}
        })
        .to_string();
        assert_eq!(
            request(
                &server,
                "POST",
                Some(&limited),
                Some(&session),
                Some(TEST_AUTH),
                None,
                Some(MCP_PROTOCOL_VERSION),
            )
            .0,
            429
        );
    }

    #[test]
    fn authorization_file_is_private_stable_and_tamper_evident() {
        let root = std::env::temp_dir().join(format!("fugue-mcp-auth-{}", random_hex(8).unwrap()));
        let home = root.join("home");
        let library = home.join("Library");
        let support = library.join("Application Support");
        fs::create_dir_all(&support).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&library, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();

        let first = load_or_create_authorization_at(&home).unwrap();
        let second = load_or_create_authorization_at(&home).unwrap();
        assert_eq!(first, second);
        validate_authorization(&first).unwrap();
        let path = support
            .join("oc-rig-v2-dev")
            .join("mcp")
            .join(AUTH_FILE_NAME);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            fs::symlink_metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );

        let hardlink = root.join("auth-hardlink");
        fs::hard_link(&path, &hardlink).unwrap();
        assert!(load_or_create_authorization_at(&home).is_err());
        fs::remove_file(&hardlink).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().nlink(), 1);

        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("chmod")
                .args(["+a", "everyone allow read"])
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
            assert!(load_or_create_authorization_at(&home).is_err());
            let status = std::process::Command::new("chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
        }

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_authorization_at(&home).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn access_granting_acl_on_system_ancestor_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "fugue-mcp-ancestor-allow-{}",
            random_hex(8).unwrap()
        ));
        let home = root.join("home");
        let library = home.join("Library");
        let support = library.join("Application Support");
        fs::create_dir_all(&support).unwrap();
        for path in [&root, &home, &library, &support] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&support)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(load_or_create_authorization_at(&home).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn standard_deny_acl_on_system_ancestors_does_not_weaken_private_leaf_policy() {
        let root =
            std::env::temp_dir().join(format!("fugue-mcp-ancestor-acl-{}", random_hex(8).unwrap()));
        let home = root.join("home");
        let library = home.join("Library");
        let support = library.join("Application Support");
        fs::create_dir_all(&support).unwrap();
        for path in [&root, &home, &library, &support] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone deny delete"])
            .arg(&support)
            .status()
            .unwrap();
        assert!(status.success());

        let authorization = load_or_create_authorization_at(&home).unwrap();
        validate_authorization(&authorization).unwrap();

        let controlled = support.join("oc-rig-v2-dev").join("mcp");
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&controlled)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(load_or_create_authorization_at(&home).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn authorization_path_rejects_symlinked_ancestor() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("fugue-mcp-link-{}", random_hex(8).unwrap()));
        let home = root.join("home");
        let real_library = root.join("real-library");
        fs::create_dir_all(real_library.join("Application Support")).unwrap();
        fs::create_dir_all(&home).unwrap();
        for path in [
            &root,
            &home,
            &real_library,
            &real_library.join("Application Support"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        symlink(&real_library, home.join("Library")).unwrap();
        assert!(load_or_create_authorization_at(&home).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn authorization_format_is_closed() {
        assert!(validate_authorization(TEST_AUTH).is_ok());
        for value in [
            "",
            "Basic abc",
            "Bearer abc",
            "Bearer A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(validate_authorization(value).is_err());
        }
    }
}
