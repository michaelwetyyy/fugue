//! Authenticated, local-only Codex App Server bridge.
//!
//! The bridge deliberately keeps conversation content out of durable Fugue
//! state. Metadata calls return a reduced projection. A full `thread/read` is
//! available only as an explicit inspection result and is never retained by
//! this type.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc, Condvar, Mutex, OnceLock,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(not(test))]
use crate::cockpit::{call_controller, BridgeError};

const LIVE_DEPLOYMENT_ROOT: &str = "Library/Application Support/oc-rig-v2";
const PINNED_CODEX_PATH: &str = "/Applications/ChatGPT.app/Contents/Resources/codex";
const STATE_FORMAT: &str = "oc-rig-local-user-deployment-v1";
const CALLBACK_FORMAT: &str = "oc-rig-local-user-codex-callback-v2";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_MESSAGE_BYTES: usize = 8 * 1024;
const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;
const MAX_THREADS: usize = 200;
// Closed stable ServerNotification method set generated from the deployment-pinned
// Codex executable. A Codex upgrade that adds a method intentionally fails closed
// here until the new protocol surface is reviewed.
const ALLOWED_NOTIFICATION_METHODS: &[&str] = &[
    "error",
    "thread/started",
    "thread/status/changed",
    "thread/archived",
    "thread/deleted",
    "thread/unarchived",
    "thread/closed",
    "thread/reverted",
    "skills/changed",
    "thread/name/updated",
    "thread/goal/updated",
    "thread/goal/cleared",
    "thread/queue/changed",
    "project/changed",
    "thread/project/updated",
    "thread/environment/connected",
    "thread/environment/disconnected",
    "thread/settings/updated",
    "thread/tokenUsage/updated",
    "turn/started",
    "hook/started",
    "turn/completed",
    "hook/completed",
    "turn/diff/updated",
    "turn/plan/updated",
    "item/started",
    "item/autoApprovalReview/started",
    "item/autoApprovalReview/completed",
    "autoApprovalReview/strictReviewRequired",
    "item/completed",
    "rawResponseItem/completed",
    "rawResponse/completed",
    "item/agentMessage/delta",
    "item/plan/delta",
    "command/exec/outputDelta",
    "process/outputDelta",
    "process/exited",
    "item/commandExecution/outputDelta",
    "item/commandExecution/terminalInteraction",
    "item/fileChange/outputDelta",
    "item/fileChange/patchUpdated",
    "serverRequest/resolved",
    "item/mcpToolCall/progress",
    "mcpServer/oauthLogin/completed",
    "mcpServer/startupStatus/updated",
    "mcpServer/event/stream/notification",
    "account/updated",
    "account/rateLimits/updated",
    "app/list/updated",
    "remoteControl/status/changed",
    "externalAgentConfig/import/progress",
    "externalAgentConfig/import/completed",
    "fs/changed",
    "item/reasoning/summaryTextDelta",
    "item/reasoning/summaryPartAdded",
    "item/reasoning/textDelta",
    "thread/compacted",
    "model/rerouted",
    "model/verification",
    "modelProvider/authRecoveryStarted",
    "modelProvider/authRecoveryCompleted",
    "turn/moderationMetadata",
    "model/safetyBuffering/updated",
    "warning",
    "guardianWarning",
    "deprecationNotice",
    "configWarning",
    "fuzzyFileSearch/sessionUpdated",
    "fuzzyFileSearch/sessionCompleted",
    "thread/realtime/started",
    "thread/realtime/itemAdded",
    "thread/realtime/item/started",
    "thread/realtime/item/transcript/delta",
    "thread/realtime/item/completed",
    "thread/realtime/transcript/delta",
    "thread/realtime/transcript/done",
    "thread/realtime/outputAudio/delta",
    "thread/realtime/sdp",
    "thread/realtime/error",
    "thread/realtime/closed",
    "windows/worldWritableWarning",
    "windowsSandbox/setupCompleted",
    "account/login/completed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexSourceError {
    Unavailable,
    Security,
    Protocol,
    Rejected,
    Unsupported,
    DeliveryUnknown,
}

impl CodexSourceError {
    pub(crate) fn public_message(self) -> &'static str {
        match self {
            Self::Unavailable => "Codex source is unavailable",
            Self::Security => "Codex source failed local identity validation",
            Self::Protocol => "Codex source returned an unsupported response",
            Self::Rejected => "Codex source rejected the request",
            Self::Unsupported => "Codex source requires a newer Fugue controller",
            Self::DeliveryUnknown => "Codex message delivery is uncertain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DeliveryState {
    Queued,
    Accepted,
    Committed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeliveryTransition {
    pub message_id: String,
    pub state: DeliveryState,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeliveryReceipt {
    pub message_id: String,
    pub route_id: Option<String>,
    pub state: DeliveryState,
    pub turn_id: Option<String>,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ThreadRuntimeStatus {
    NotLoaded,
    Idle,
    SystemError,
    Active { active_flags: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ThreadMetadata {
    pub id: String,
    pub name: Option<String>,
    pub cwd: String,
    pub source: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: ThreadRuntimeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ThreadPage {
    pub data: Vec<ThreadMetadata>,
    pub next_cursor: Option<String>,
    pub backwards_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SourceChange {
    pub method: &'static str,
}

/// Intentionally has no `Debug` or `Clone`: transcript payloads should not be
/// copied into logs, graph snapshots, preferences, or durable route records.
#[derive(Serialize)]
pub(crate) struct TranscriptInspection {
    pub thread_id: String,
    pub active_turn_id: Option<String>,
    pub thread: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceThreadQuery {
    thread_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceMessageInput {
    thread_id: String,
    expected_turn_id: Option<String>,
    message_id: String,
    text: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SourceDeliveryOutcome {
    endpoint: &'static str,
    thread_id: String,
    transitions: Vec<DeliveryTransition>,
    receipt: DeliveryReceipt,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceInboxItem {
    id: String,
    kind: String,
    origin: String,
    work_id: Option<String>,
    state: String,
    queued_at: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ControllerSourceInbox {
    source_id: String,
    items: Vec<SourceInboxItem>,
    total: Option<u64>,
    total_status: String,
    lower_bound: u64,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct SourceInbox {
    status: &'static str,
    source_id: String,
    runtime_status: &'static str,
    active_turn_id: Option<String>,
    items: Vec<SourceInboxItem>,
    total: Option<u64>,
    total_status: String,
    lower_bound: u64,
    truncated: bool,
}

static CLIENT: OnceLock<Mutex<Option<CodexSourceClient>>> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentState {
    format: String,
    current: String,
    previous: Option<String>,
    opencode: Value,
    codex_callback: Option<CodexCallback>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodexCallback {
    format: String,
    executable: String,
    executable_pin: ExecutablePin,
    home: String,
    codex_home: String,
    timeout_seconds: f64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExecutablePin {
    inode: u64,
    mode: u32,
    sha256: String,
    size: u64,
    uid: u32,
    volume_uuid: String,
}

#[derive(Debug, Clone)]
struct SourceConfiguration {
    executable: PathBuf,
    executable_pin: ExecutablePin,
    home: PathBuf,
    codex_home: PathBuf,
    timeout: Duration,
}

struct SourceNotificationState {
    changes: VecDeque<SourceChange>,
    closed: bool,
}

struct SourceNotificationQueue {
    state: Mutex<SourceNotificationState>,
    ready: Condvar,
}

impl SourceNotificationQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(SourceNotificationState {
                changes: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    fn push(&self, change: SourceChange) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.closed {
            return;
        }
        if state.changes.len() == 32 {
            state.changes.pop_front();
        }
        state.changes.push_back(change);
        self.ready.notify_one();
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            self.ready.notify_all();
        }
    }

    fn wait(&self) -> Result<SourceChange, CodexSourceError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CodexSourceError::Unavailable)?;
        loop {
            if let Some(change) = state.changes.pop_front() {
                return Ok(change);
            }
            if state.closed {
                return Err(CodexSourceError::Unavailable);
            }
            state = self
                .ready
                .wait(state)
                .map_err(|_| CodexSourceError::Unavailable)?;
        }
    }
}

/// An idle turn may only be started after the controller has durably committed
/// this exact route. Callers must construct it from the controller's closed
/// response, not from UI input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedIdleRoute {
    route_id: String,
    message_id: String,
    thread_id: String,
}

impl CommittedIdleRoute {
    pub(crate) fn from_controller_response(
        value: Value,
        expected_thread_id: &str,
        expected_message_id: &str,
    ) -> Result<Self, CodexSourceError> {
        let expected_thread_id = thread_identifier(expected_thread_id)?;
        let expected_message_id = canonical_uuid(expected_message_id)?;
        let object = exact_object(value, &["message_id", "route_id", "state", "thread_id"])?;
        if object.get("state").and_then(Value::as_str) != Some("committed") {
            return Err(CodexSourceError::Rejected);
        }
        let route_id = closed_identifier(value_string(&object, "route_id")?, 256)?;
        let message_id = canonical_uuid(value_string(&object, "message_id")?)?;
        let thread_id = thread_identifier(value_string(&object, "thread_id")?)?;
        if message_id != expected_message_id || thread_id != expected_thread_id {
            return Err(CodexSourceError::Protocol);
        }
        Ok(Self {
            route_id,
            message_id,
            thread_id,
        })
    }
}

pub(crate) struct CodexSourceClient {
    configuration: SourceConfiguration,
    child: Arc<Mutex<Child>>,
    stdin: Arc<Mutex<ChildStdin>>,
    response_rx: Receiver<Result<Value, CodexSourceError>>,
    notification_queue: Arc<SourceNotificationQueue>,
    reader: Option<JoinHandle<()>>,
    next_request_id: u64,
    poisoned: Arc<AtomicBool>,
}

impl CodexSourceClient {
    pub(crate) fn connect_live() -> Result<Self, CodexSourceError> {
        let home = owner_home()?;
        Self::connect_from_deployment(&home.join(LIVE_DEPLOYMENT_ROOT))
    }

    pub(crate) fn connect_from_deployment(
        deployment_root: &Path,
    ) -> Result<Self, CodexSourceError> {
        let configuration = load_configuration(deployment_root)?;
        authenticate_executable(&configuration)?;
        let mut command = Command::new(&configuration.executable);
        command
            .args(["app-server", "--listen", "stdio://", "--strict-config"])
            .current_dir(&configuration.home)
            .env_clear()
            .env("CODEX_HOME", &configuration.codex_home)
            .env("HOME", &configuration.home)
            .env("LANG", "C.UTF-8")
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| CodexSourceError::Unavailable)?;
        let stdin = Arc::new(Mutex::new(
            child.stdin.take().ok_or(CodexSourceError::Unavailable)?,
        ));
        let stdout = child.stdout.take().ok_or(CodexSourceError::Unavailable)?;
        let child = Arc::new(Mutex::new(child));
        let poisoned = Arc::new(AtomicBool::new(false));
        let notification_queue = Arc::new(SourceNotificationQueue::new());
        let (response_tx, response_rx) = mpsc::channel();
        let reader = match thread::Builder::new()
            .name("fugue-codex-source-reader".to_owned())
            .spawn({
                let child = Arc::clone(&child);
                let stdin = Arc::clone(&stdin);
                let poisoned = Arc::clone(&poisoned);
                let notification_queue = Arc::clone(&notification_queue);
                move || {
                    source_reader_loop(
                        stdout,
                        stdin,
                        child,
                        poisoned,
                        response_tx,
                        notification_queue,
                    )
                }
            }) {
            Ok(reader) => reader,
            Err(_) => {
                kill_shared_child(&child);
                return Err(CodexSourceError::Unavailable);
            }
        };
        let mut client = Self {
            configuration,
            child,
            stdin,
            response_rx,
            notification_queue,
            reader: Some(reader),
            next_request_id: 1,
            poisoned,
        };
        if let Err(error) = client.initialize() {
            client.poison();
            return Err(error);
        }
        authenticate_executable_fast(&client.configuration)?;
        Ok(client)
    }

    pub(crate) fn list_threads(
        &mut self,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<ThreadPage, CodexSourceError> {
        if limit == 0 || usize::from(limit) > MAX_THREADS {
            return Err(CodexSourceError::Protocol);
        }
        let cursor = cursor
            .map(|value| safe_text(value, 4096, false))
            .transpose()?;
        let result = self.request(
            "thread/list",
            json!({
                "archived": false,
                "cursor": cursor,
                "limit": limit,
                "sortDirection": "desc",
                "sortKey": "updated_at",
                "sourceKinds": ["cli", "vscode", "appServer"],
                "useStateDbOnly": true,
            }),
        )?;
        decode_thread_page(result)
    }

    pub(crate) fn read_thread_metadata(
        &mut self,
        thread_id: &str,
    ) -> Result<ThreadMetadata, CodexSourceError> {
        let thread_id = thread_identifier(thread_id)?;
        let result = self.request(
            "thread/read",
            json!({"includeTurns": false, "threadId": thread_id}),
        )?;
        let object = exact_object(result, &["thread"])?;
        decode_bound_thread_metadata(
            object
                .get("thread")
                .cloned()
                .ok_or(CodexSourceError::Protocol)?,
            &thread_id,
        )
    }

    pub(crate) fn inspect_thread(
        &mut self,
        thread_id: &str,
    ) -> Result<TranscriptInspection, CodexSourceError> {
        let thread_id = thread_identifier(thread_id)?;
        let result = self.request(
            "thread/read",
            json!({"includeTurns": true, "threadId": thread_id}),
        )?;
        let object = exact_object(result, &["thread"])?;
        let thread = object
            .get("thread")
            .cloned()
            .ok_or(CodexSourceError::Protocol)?;
        validate_thread_shape(&thread, true)?;
        if thread.get("id").and_then(Value::as_str) != Some(thread_id.as_str()) {
            return Err(CodexSourceError::Protocol);
        }
        let active_turn_id = active_turn_id(&thread)?;
        Ok(TranscriptInspection {
            thread_id,
            active_turn_id,
            thread,
        })
    }

    pub(crate) fn steer_active<F>(
        &mut self,
        thread_id: &str,
        expected_turn_id: &str,
        message_id: &str,
        text: &str,
        observer: F,
    ) -> DeliveryReceipt
    where
        F: FnMut(DeliveryTransition),
    {
        let (thread_id, expected_turn_id, message_id, text) = match (
            thread_identifier(thread_id),
            turn_identifier(expected_turn_id),
            canonical_uuid(message_id),
            message_text(text),
        ) {
            (Ok(thread_id), Ok(expected_turn_id), Ok(message_id), Ok(text)) => {
                (thread_id, expected_turn_id, message_id, text)
            }
            _ => return failed_receipt("invalid".to_owned(), None, "request_invalid", observer),
        };
        self.deliver(
            "turn/steer",
            json!({
                "clientUserMessageId": message_id,
                "expectedTurnId": expected_turn_id,
                "input": [{"text": text, "type": "text"}],
                "threadId": thread_id,
            }),
            message_id,
            None,
            Some(expected_turn_id),
            observer,
        )
    }

    pub(crate) fn start_idle_turn<F>(
        &mut self,
        route: CommittedIdleRoute,
        text: &str,
        observer: F,
    ) -> DeliveryReceipt
    where
        F: FnMut(DeliveryTransition),
    {
        let text = match message_text(text) {
            Ok(text) => text,
            Err(_) => {
                return failed_receipt(
                    route.message_id,
                    Some(route.route_id),
                    "request_invalid",
                    observer,
                )
            }
        };
        self.deliver(
            "turn/start",
            json!({
                "approvalPolicy": "never",
                "clientUserMessageId": route.message_id,
                "input": [{"text": text, "type": "text"}],
                "threadId": route.thread_id,
            }),
            route.message_id,
            Some(route.route_id),
            None,
            observer,
        )
    }

    fn initialize(&mut self) -> Result<(), CodexSourceError> {
        let result = self.request_uninitialized(
            "initialize",
            json!({
                "capabilities": {
                    "optOutNotificationMethods": ALLOWED_NOTIFICATION_METHODS
                        .iter()
                        .copied()
                        .filter(|method| source_change_method(method).is_none())
                        .collect::<Vec<_>>()
                },
                "clientInfo": {"name": "fugue", "title": "Fugue", "version": "0.1.0"},
            }),
        )?;
        let object = exact_object(
            result,
            &["codexHome", "platformFamily", "platformOs", "userAgent"],
        )?;
        if object.get("codexHome").and_then(Value::as_str)
            != Some(self.configuration.codex_home.to_string_lossy().as_ref())
            || object
                .get("platformFamily")
                .and_then(Value::as_str)
                .is_none()
            || object.get("platformOs").and_then(Value::as_str).is_none()
            || object.get("userAgent").and_then(Value::as_str).is_none()
        {
            return Err(CodexSourceError::Protocol);
        }
        self.write_message(&json!({"method": "initialized", "params": {}}))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, CodexSourceError> {
        if self.is_poisoned() {
            return Err(CodexSourceError::Unavailable);
        }
        authenticate_executable_fast(&self.configuration)?;
        let result = self.request_uninitialized(method, params);
        if matches!(
            result,
            Err(CodexSourceError::Unavailable
                | CodexSourceError::Protocol
                | CodexSourceError::DeliveryUnknown)
        ) {
            self.poison();
        }
        result
    }

    fn request_uninitialized(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, CodexSourceError> {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(CodexSourceError::Protocol)?;
        self.write_message(&json!({"id": request_id, "method": method, "params": params}))?;
        self.await_response(request_id)
    }

    fn deliver<F>(
        &mut self,
        method: &str,
        params: Value,
        message_id: String,
        route_id: Option<String>,
        expected_turn_id: Option<String>,
        mut observer: F,
    ) -> DeliveryReceipt
    where
        F: FnMut(DeliveryTransition),
    {
        transition(&mut observer, &message_id, DeliveryState::Queued, "queued");
        if self.is_poisoned() || authenticate_executable_fast(&self.configuration).is_err() {
            transition(
                &mut observer,
                &message_id,
                DeliveryState::Failed,
                "source_unavailable",
            );
            return DeliveryReceipt {
                message_id,
                route_id,
                state: DeliveryState::Failed,
                turn_id: None,
                reason: "source_unavailable",
            };
        }
        let request_id = self.next_request_id;
        let Some(next_id) = self.next_request_id.checked_add(1) else {
            return failed_receipt(message_id, route_id, "request_id_exhausted", observer);
        };
        self.next_request_id = next_id;
        if self
            .write_message(&json!({"id": request_id, "method": method, "params": params}))
            .is_err()
        {
            self.poison();
            transition(
                &mut observer,
                &message_id,
                DeliveryState::Unknown,
                "write_uncertain",
            );
            return DeliveryReceipt {
                message_id,
                route_id,
                state: DeliveryState::Unknown,
                turn_id: None,
                reason: "write_uncertain",
            };
        }
        transition(
            &mut observer,
            &message_id,
            DeliveryState::Accepted,
            "request_written",
        );
        let result = match self.await_response(request_id) {
            Ok(value) => value,
            Err(CodexSourceError::Rejected) => {
                transition(
                    &mut observer,
                    &message_id,
                    DeliveryState::Failed,
                    "server_rejected",
                );
                return DeliveryReceipt {
                    message_id,
                    route_id,
                    state: DeliveryState::Failed,
                    turn_id: None,
                    reason: "server_rejected",
                };
            }
            Err(_) => {
                self.poison();
                transition(
                    &mut observer,
                    &message_id,
                    DeliveryState::Unknown,
                    "outcome_uncertain",
                );
                return DeliveryReceipt {
                    message_id,
                    route_id,
                    state: DeliveryState::Unknown,
                    turn_id: None,
                    reason: "outcome_uncertain",
                };
            }
        };
        let turn_id = if method == "turn/steer" {
            exact_object(result, &["turnId"])
                .and_then(|object| value_string(&object, "turnId").and_then(turn_identifier))
                .and_then(|turn_id| {
                    if expected_turn_id.as_deref() == Some(turn_id.as_str()) {
                        Ok(turn_id)
                    } else {
                        Err(CodexSourceError::Protocol)
                    }
                })
        } else {
            decode_started_turn(result)
        };
        let turn_id = match turn_id {
            Ok(turn_id) => turn_id,
            Err(_) => {
                self.poison();
                transition(
                    &mut observer,
                    &message_id,
                    DeliveryState::Unknown,
                    "receipt_invalid",
                );
                return DeliveryReceipt {
                    message_id,
                    route_id,
                    state: DeliveryState::Unknown,
                    turn_id: None,
                    reason: "receipt_invalid",
                };
            }
        };
        transition(
            &mut observer,
            &message_id,
            DeliveryState::Committed,
            "server_committed",
        );
        DeliveryReceipt {
            message_id,
            route_id,
            state: DeliveryState::Committed,
            turn_id: Some(turn_id),
            reason: "server_committed",
        }
    }

    fn write_message(&mut self, value: &Value) -> Result<(), CodexSourceError> {
        if self.is_poisoned() {
            return Err(CodexSourceError::Unavailable);
        }
        write_shared_message(&self.stdin, value)
    }

    fn await_response(&mut self, request_id: u64) -> Result<Value, CodexSourceError> {
        let message = match self.response_rx.recv_timeout(self.configuration.timeout) {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(CodexSourceError::Unavailable),
        };
        let object = message.as_object().ok_or(CodexSourceError::Protocol)?;
        decode_response(object, request_id)
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison(&mut self) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            self.notification_queue.close();
            kill_shared_child(&self.child);
        }
    }
}

fn synchronized_client() -> &'static Mutex<Option<CodexSourceClient>> {
    CLIENT.get_or_init(|| Mutex::new(None))
}

fn with_client<T>(
    operation: impl FnOnce(&mut CodexSourceClient) -> Result<T, CodexSourceError>,
) -> Result<T, CodexSourceError> {
    let mut guard = synchronized_client()
        .lock()
        .map_err(|_| CodexSourceError::Unavailable)?;
    if guard.as_ref().is_some_and(CodexSourceClient::is_poisoned) {
        *guard = None;
    }
    if guard.is_none() {
        *guard = Some(CodexSourceClient::connect_live()?);
    }
    let result = operation(guard.as_mut().ok_or(CodexSourceError::Unavailable)?);
    if guard.as_ref().is_some_and(CodexSourceClient::is_poisoned) {
        *guard = None;
    }
    result
}

pub(crate) fn recent_threads() -> Result<ThreadPage, CodexSourceError> {
    with_client(|client| client.list_threads(None, 24))
}

pub(crate) fn wait_for_source_change() -> Result<SourceChange, CodexSourceError> {
    let queue = with_client(|client| Ok(Arc::clone(&client.notification_queue)))?;
    queue.wait()
}

pub(crate) fn inspect(input: SourceThreadQuery) -> Result<TranscriptInspection, CodexSourceError> {
    with_client(|client| client.inspect_thread(&input.thread_id))
}

pub(crate) fn inbox(input: SourceThreadQuery) -> Result<SourceInbox, CodexSourceError> {
    let thread_id = thread_identifier(&input.thread_id)?;
    let durable = controller_source_inbox(&thread_id)?;
    let durable = decode_controller_source_inbox(durable, &thread_id)?;
    let runtime_status = match with_client(|client| client.read_thread_metadata(&thread_id)) {
        Ok(metadata) => match metadata.status {
            ThreadRuntimeStatus::Active { .. } => "active",
            ThreadRuntimeStatus::Idle | ThreadRuntimeStatus::NotLoaded => "idle",
            ThreadRuntimeStatus::SystemError => "unavailable",
        },
        Err(_) => "unavailable",
    };
    Ok(SourceInbox {
        status: "available",
        source_id: durable.source_id,
        runtime_status,
        active_turn_id: None,
        items: durable.items,
        total: durable.total,
        total_status: durable.total_status,
        lower_bound: durable.lower_bound,
        truncated: durable.truncated,
    })
}

pub(crate) fn send(input: SourceMessageInput) -> Result<SourceDeliveryOutcome, CodexSourceError> {
    let thread_id = thread_identifier(&input.thread_id)?;
    let message_id = canonical_uuid(&input.message_id)?;
    let text = message_text(&input.text)?;
    let expected_turn_id = input
        .expected_turn_id
        .as_deref()
        .map(turn_identifier)
        .transpose()?;
    let endpoint;
    let mut transitions = Vec::new();
    let receipt = if let Some(expected_turn_id) = expected_turn_id.as_deref() {
        endpoint = "turn/steer";
        with_client(|client| {
            Ok(client.steer_active(
                &thread_id,
                expected_turn_id,
                &message_id,
                &text,
                |transition| transitions.push(transition),
            ))
        })?
    } else {
        endpoint = "turn/start";
        with_client(|client| {
            let metadata = client.read_thread_metadata(&thread_id)?;
            if !matches!(
                metadata.status,
                ThreadRuntimeStatus::Idle | ThreadRuntimeStatus::NotLoaded
            ) {
                return Err(CodexSourceError::Rejected);
            }
            let controller = commit_idle_route(&thread_id, &message_id)?;
            let route =
                CommittedIdleRoute::from_controller_response(controller, &thread_id, &message_id)?;
            Ok(client.start_idle_turn(route, &text, |transition| transitions.push(transition)))
        })?
    };
    Ok(SourceDeliveryOutcome {
        endpoint,
        thread_id,
        transitions,
        receipt,
    })
}

fn decode_controller_source_inbox(
    value: Value,
    expected_thread_id: &str,
) -> Result<ControllerSourceInbox, CodexSourceError> {
    let object = exact_object(
        value.clone(),
        &[
            "source_id",
            "items",
            "total",
            "total_status",
            "lower_bound",
            "truncated",
        ],
    )?;
    let raw_items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or(CodexSourceError::Protocol)?;
    for raw_item in raw_items {
        exact_object(
            raw_item.clone(),
            &[
                "id",
                "kind",
                "origin",
                "work_id",
                "state",
                "queued_at",
                "reason",
            ],
        )?;
    }
    let inbox: ControllerSourceInbox =
        serde_json::from_value(value).map_err(|_| CodexSourceError::Protocol)?;
    if inbox.source_id != expected_thread_id
        || inbox.items.len() > 12
        || !matches!(inbox.total_status.as_str(), "exact" | "capped")
        || (inbox.total_status == "exact"
            && (inbox.total != Some(inbox.items.len() as u64)
                || inbox.lower_bound != inbox.items.len() as u64))
        || (inbox.total_status == "capped"
            && (inbox.total.is_some() || inbox.items.len() != 12 || inbox.lower_bound != 13))
        || inbox.truncated != (inbox.total_status == "capped")
    {
        return Err(CodexSourceError::Protocol);
    }
    for item in &inbox.items {
        closed_identifier(&item.id, 256)?;
        if item.kind != "completion_nudge" {
            return Err(CodexSourceError::Protocol);
        }
        closed_identifier(&item.origin, 256)?;
        if let Some(work_id) = item.work_id.as_deref() {
            durable_identifier(work_id, 256)?;
        }
        if !matches!(
            item.state.as_str(),
            "queued" | "delivering" | "accepted" | "attention"
        ) {
            return Err(CodexSourceError::Protocol);
        }
        safe_text(&item.queued_at, 64, false)?;
        if !item.queued_at.ends_with('Z') {
            return Err(CodexSourceError::Protocol);
        }
        match (item.state.as_str(), item.reason.as_deref()) {
            ("attention", Some(reason)) => {
                safe_text(reason, 1024, false)?;
            }
            ("attention", None) => return Err(CodexSourceError::Protocol),
            (_, None) => {}
            (_, Some(_)) => return Err(CodexSourceError::Protocol),
        }
    }
    Ok(inbox)
}

#[cfg(not(test))]
fn controller_source_inbox(thread_id: &str) -> Result<Value, CodexSourceError> {
    call_controller(
        "codex.source.inbox.v1",
        json!({"thread_id": thread_id}),
        format!("source-inbox-{thread_id}"),
    )
    .map_err(source_controller_error)
}

#[cfg(test)]
fn controller_source_inbox(_thread_id: &str) -> Result<Value, CodexSourceError> {
    Err(CodexSourceError::Unavailable)
}

#[cfg(not(test))]
fn commit_idle_route(thread_id: &str, message_id: &str) -> Result<Value, CodexSourceError> {
    call_controller(
        "codex.source.route.commit.v1",
        json!({"message_id": message_id, "thread_id": thread_id}),
        message_id.to_owned(),
    )
    .map_err(source_controller_error)
}

#[cfg(test)]
fn commit_idle_route(_thread_id: &str, _message_id: &str) -> Result<Value, CodexSourceError> {
    Err(CodexSourceError::Unavailable)
}

#[cfg(not(test))]
fn source_controller_error(error: BridgeError) -> CodexSourceError {
    match error {
        BridgeError::Unavailable => CodexSourceError::Unavailable,
        BridgeError::Security => CodexSourceError::Security,
        BridgeError::Protocol => CodexSourceError::Protocol,
        BridgeError::Rejected => CodexSourceError::Rejected,
        BridgeError::Unsupported => CodexSourceError::Unsupported,
    }
}

fn write_shared_message(
    stdin: &Arc<Mutex<ChildStdin>>,
    value: &Value,
) -> Result<(), CodexSourceError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| CodexSourceError::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(CodexSourceError::Protocol);
    }
    bytes.push(b'\n');
    let mut writer = stdin.lock().map_err(|_| CodexSourceError::Unavailable)?;
    writer
        .write_all(&bytes)
        .and_then(|_| writer.flush())
        .map_err(|_| CodexSourceError::DeliveryUnknown)
}

fn read_source_message(
    stdout: &mut ChildStdout,
    read_buffer: &mut Vec<u8>,
) -> Result<Value, CodexSourceError> {
    loop {
        if let Some(index) = read_buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = read_buffer.drain(..=index).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                return Err(CodexSourceError::Protocol);
            }
            return serde_json::from_slice(&line).map_err(|_| CodexSourceError::Protocol);
        }
        if read_buffer.len() >= MAX_WIRE_BYTES {
            return Err(CodexSourceError::Protocol);
        }
        let mut chunk = [0_u8; 8192];
        let read = match stdout.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(CodexSourceError::Unavailable),
        };
        if read == 0 {
            return Err(CodexSourceError::Unavailable);
        }
        if read_buffer.len().saturating_add(read) > MAX_WIRE_BYTES {
            return Err(CodexSourceError::Protocol);
        }
        read_buffer.extend_from_slice(&chunk[..read]);
    }
}

fn kill_shared_child(child: &Arc<Mutex<Child>>) {
    if let Ok(mut process) = child.lock() {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn source_reader_loop(
    mut stdout: ChildStdout,
    stdin: Arc<Mutex<ChildStdin>>,
    child: Arc<Mutex<Child>>,
    poisoned: Arc<AtomicBool>,
    response_tx: Sender<Result<Value, CodexSourceError>>,
    notification_queue: Arc<SourceNotificationQueue>,
) {
    let mut read_buffer = Vec::new();
    let failure = loop {
        let message = match read_source_message(&mut stdout, &mut read_buffer) {
            Ok(message) => message,
            Err(error) => break error,
        };
        let Some(object) = message.as_object() else {
            break CodexSourceError::Protocol;
        };
        if object.contains_key("method") && object.contains_key("id") {
            if let Some(id) = object.get("id") {
                let _ = write_shared_message(
                    &stdin,
                    &json!({
                        "error": {"code": -32601, "message": "Fugue refuses server requests"},
                        "id": id,
                    }),
                );
            }
            break CodexSourceError::Protocol;
        }
        if object.contains_key("method") {
            if validate_notification(object).is_err() {
                break CodexSourceError::Protocol;
            }
            match source_change_notification(object) {
                Ok(Some(change)) => notification_queue.push(change),
                Ok(None) => {}
                Err(error) => break error,
            }
            continue;
        }
        if response_tx.send(Ok(message)).is_err() {
            break CodexSourceError::Unavailable;
        }
    };
    poisoned.store(true, Ordering::Release);
    notification_queue.close();
    let _ = response_tx.send(Err(failure));
    kill_shared_child(&child);
}

fn active_turn_id(thread: &Value) -> Result<Option<String>, CodexSourceError> {
    let turns = thread
        .get("turns")
        .and_then(Value::as_array)
        .ok_or(CodexSourceError::Protocol)?;
    let mut active = None;
    for turn in turns {
        let object = turn.as_object().ok_or(CodexSourceError::Protocol)?;
        if object.get("status").and_then(Value::as_str) == Some("inProgress") {
            if active.is_some() {
                return Err(CodexSourceError::Protocol);
            }
            active = Some(turn_identifier(value_string(object, "id")?)?);
        }
    }
    Ok(active)
}

impl Drop for CodexSourceClient {
    fn drop(&mut self) {
        self.poison();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn transition<F>(observer: &mut F, message_id: &str, state: DeliveryState, reason: &'static str)
where
    F: FnMut(DeliveryTransition),
{
    observer(DeliveryTransition {
        message_id: message_id.to_owned(),
        state,
        reason,
    });
}

fn failed_receipt<F>(
    message_id: String,
    route_id: Option<String>,
    reason: &'static str,
    mut observer: F,
) -> DeliveryReceipt
where
    F: FnMut(DeliveryTransition),
{
    transition(&mut observer, &message_id, DeliveryState::Queued, "queued");
    transition(&mut observer, &message_id, DeliveryState::Failed, reason);
    DeliveryReceipt {
        message_id,
        route_id,
        state: DeliveryState::Failed,
        turn_id: None,
        reason,
    }
}

fn decode_response(
    object: &Map<String, Value>,
    request_id: u64,
) -> Result<Value, CodexSourceError> {
    if object.get("id").and_then(Value::as_u64) != Some(request_id) {
        return Err(CodexSourceError::Protocol);
    }
    match (object.get("result"), object.get("error")) {
        (Some(result), None) if object.len() == 2 => Ok(result.clone()),
        (None, Some(error)) if object.len() == 2 && valid_rpc_error(error) => {
            Err(CodexSourceError::Rejected)
        }
        _ => Err(CodexSourceError::Protocol),
    }
}

fn valid_rpc_error(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .keys()
        .all(|key| matches!(key.as_str(), "code" | "data" | "message"))
        && object.contains_key("code")
        && object.contains_key("message")
        && object.get("code").is_some_and(Value::is_i64)
        && object.get("message").and_then(Value::as_str).is_some()
}

fn source_change_method(method: &str) -> Option<&'static str> {
    match method {
        "thread/status/changed" => Some("thread/status/changed"),
        "turn/started" => Some("turn/started"),
        "turn/completed" => Some("turn/completed"),
        _ => None,
    }
}

fn source_change_notification(
    object: &Map<String, Value>,
) -> Result<Option<SourceChange>, CodexSourceError> {
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or(CodexSourceError::Protocol)?;
    let Some(method) = source_change_method(method) else {
        return Ok(None);
    };
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or(CodexSourceError::Protocol)?;
    let thread_id = thread_identifier(value_string(params, "threadId")?)?;
    match method {
        "thread/status/changed" => {
            if params.len() != 2 || !params.contains_key("status") {
                return Err(CodexSourceError::Protocol);
            }
            let _ = thread_id;
            let _ = decode_status(params.get("status").ok_or(CodexSourceError::Protocol)?)?;
            Ok(Some(SourceChange { method }))
        }
        "turn/started" | "turn/completed" => {
            if params.len() != 2 || !params.get("turn").is_some_and(Value::is_object) {
                return Err(CodexSourceError::Protocol);
            }
            // The turn object can contain transcript/tool material. Only its parent
            // thread ID crosses this boundary; the turn payload is discarded here.
            let _ = thread_id;
            Ok(Some(SourceChange { method }))
        }
        _ => Err(CodexSourceError::Protocol),
    }
}

fn validate_notification(object: &Map<String, Value>) -> Result<(), CodexSourceError> {
    if !object.contains_key("method")
        || !object.contains_key("params")
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "emittedAtMs" | "method" | "params"))
        || object
            .get("emittedAtMs")
            .is_some_and(|value| !value.is_u64() && !value.is_i64())
    {
        return Err(CodexSourceError::Protocol);
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or(CodexSourceError::Protocol)?;
    if !ALLOWED_NOTIFICATION_METHODS.contains(&method)
        || !object.get("params").is_some_and(Value::is_object)
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(())
}

fn decode_thread_page(value: Value) -> Result<ThreadPage, CodexSourceError> {
    let object = optional_exact_object(value, &["data"], &["backwardsCursor", "nextCursor"])?;
    let data = object
        .get("data")
        .and_then(Value::as_array)
        .ok_or(CodexSourceError::Protocol)?;
    if data.len() > MAX_THREADS {
        return Err(CodexSourceError::Protocol);
    }
    let threads = data
        .iter()
        .cloned()
        .map(decode_thread_metadata)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ThreadPage {
        data: threads,
        next_cursor: optional_string(&object, "nextCursor", 4096)?,
        backwards_cursor: optional_string(&object, "backwardsCursor", 4096)?,
    })
}

fn decode_thread_metadata(value: Value) -> Result<ThreadMetadata, CodexSourceError> {
    validate_thread_shape(&value, false)?;
    let object = value.as_object().ok_or(CodexSourceError::Protocol)?;
    let id = thread_identifier(value_string(object, "id")?)?;
    let name = optional_string(object, "name", 1024)?;
    let cwd = safe_text(value_string(object, "cwd")?, 16 * 1024, false)?;
    let source = safe_text(value_string(object, "source")?, 128, false)?;
    let created_at = object
        .get("createdAt")
        .and_then(Value::as_i64)
        .ok_or(CodexSourceError::Protocol)?;
    let updated_at = object
        .get("updatedAt")
        .and_then(Value::as_i64)
        .ok_or(CodexSourceError::Protocol)?;
    let status = decode_status(object.get("status").ok_or(CodexSourceError::Protocol)?)?;
    Ok(ThreadMetadata {
        id,
        name,
        cwd,
        source,
        created_at,
        updated_at,
        status,
    })
}

fn decode_bound_thread_metadata(
    value: Value,
    expected_thread_id: &str,
) -> Result<ThreadMetadata, CodexSourceError> {
    let expected_thread_id = thread_identifier(expected_thread_id)?;
    let metadata = decode_thread_metadata(value)?;
    if metadata.id != expected_thread_id {
        return Err(CodexSourceError::Protocol);
    }
    Ok(metadata)
}

fn validate_thread_shape(value: &Value, include_turns: bool) -> Result<(), CodexSourceError> {
    const REQUIRED: &[&str] = &[
        "cliVersion",
        "createdAt",
        "cwd",
        "ephemeral",
        "id",
        "modelProvider",
        "preview",
        "projectId",
        "sessionId",
        "source",
        "status",
        "turns",
        "updatedAt",
    ];
    const OPTIONAL: &[&str] = &[
        "agentNickname",
        "agentRole",
        "canAcceptDirectInput",
        "extra",
        "forkedFromId",
        "gitInfo",
        "historyMode",
        "model",
        "name",
        "parentThreadId",
        "path",
        "reasoningEffort",
        "recencyAt",
        "section",
        "sectionEnteredAt",
        "threadSource",
    ];
    let object = value.as_object().ok_or(CodexSourceError::Protocol)?;
    if REQUIRED.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !REQUIRED.contains(&key.as_str()) && !OPTIONAL.contains(&key.as_str()))
        || !object.get("turns").is_some_and(Value::is_array)
        || (!include_turns
            && !object
                .get("turns")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty))
        || object
            .get("canAcceptDirectInput")
            .is_some_and(|value| !value.is_null() && !value.is_boolean())
        || object
            .get("extra")
            .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(())
}

fn decode_status(value: &Value) -> Result<ThreadRuntimeStatus, CodexSourceError> {
    let object = value.as_object().ok_or(CodexSourceError::Protocol)?;
    match object.get("type").and_then(Value::as_str) {
        Some("notLoaded") if object.len() == 1 => Ok(ThreadRuntimeStatus::NotLoaded),
        Some("idle") if object.len() == 1 => Ok(ThreadRuntimeStatus::Idle),
        Some("systemError") if object.len() == 1 => Ok(ThreadRuntimeStatus::SystemError),
        Some("active") if object.len() == 2 => {
            let flags = object
                .get("activeFlags")
                .and_then(Value::as_array)
                .ok_or(CodexSourceError::Protocol)?
                .iter()
                .map(|value| {
                    safe_text(
                        value.as_str().ok_or(CodexSourceError::Protocol)?,
                        128,
                        false,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ThreadRuntimeStatus::Active {
                active_flags: flags,
            })
        }
        _ => Err(CodexSourceError::Protocol),
    }
}

fn decode_started_turn(value: Value) -> Result<String, CodexSourceError> {
    let object = exact_object(value, &["turn"])?;
    let turn = object
        .get("turn")
        .and_then(Value::as_object)
        .ok_or(CodexSourceError::Protocol)?;
    if !turn.contains_key("id")
        || !turn.contains_key("items")
        || !turn.contains_key("status")
        || turn.keys().any(|key| {
            !matches!(
                key.as_str(),
                "completedAt"
                    | "durationMs"
                    | "error"
                    | "id"
                    | "items"
                    | "itemsView"
                    | "startedAt"
                    | "status"
            )
        })
        || turn.get("status").and_then(Value::as_str) != Some("inProgress")
        || !turn.get("items").is_some_and(Value::is_array)
    {
        return Err(CodexSourceError::Protocol);
    }
    turn_identifier(value_string(turn, "id")?)
}

fn load_configuration(deployment_root: &Path) -> Result<SourceConfiguration, CodexSourceError> {
    validate_private_directory(deployment_root, true)?;
    let state_path = deployment_root.join("deployment-state.json");
    let bytes = stable_private_file(&state_path, 0o600, MAX_STATE_BYTES)?;
    let state: DeploymentState =
        serde_json::from_slice(&bytes).map_err(|_| CodexSourceError::Protocol)?;
    if state.format != STATE_FORMAT
        || !closed_identifier(&state.current, 256).is_ok()
        || state
            .previous
            .as_deref()
            .is_some_and(|value| closed_identifier(value, 256).is_err())
        || !state.opencode.is_object()
    {
        return Err(CodexSourceError::Protocol);
    }
    let callback = state.codex_callback.ok_or(CodexSourceError::Security)?;
    if callback.format != CALLBACK_FORMAT
        || callback.executable != PINNED_CODEX_PATH
        || !(0.0 < callback.timeout_seconds && callback.timeout_seconds <= 60.0)
    {
        return Err(CodexSourceError::Security);
    }
    let executable = canonical_absolute_path(&callback.executable)?;
    let home = canonical_absolute_path(&callback.home)?;
    let codex_home = canonical_absolute_path(&callback.codex_home)?;
    validate_private_directory(&home, false)?;
    validate_private_directory(&codex_home, false)?;
    Ok(SourceConfiguration {
        executable,
        executable_pin: callback.executable_pin,
        home,
        codex_home,
        timeout: Duration::from_secs_f64(callback.timeout_seconds),
    })
}

fn authenticate_executable(configuration: &SourceConfiguration) -> Result<(), CodexSourceError> {
    validate_ancestry(&configuration.executable)?;
    let before =
        fs::symlink_metadata(&configuration.executable).map_err(|_| CodexSourceError::Security)?;
    validate_executable_metadata(&before, &configuration.executable_pin)?;
    if !valid_digest(&configuration.executable_pin.sha256)
        || !canonical_uuid_shape(&configuration.executable_pin.volume_uuid)
    {
        return Err(CodexSourceError::Security);
    }
    let mut file =
        fs::File::open(&configuration.executable).map_err(|_| CodexSourceError::Security)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| CodexSourceError::Security)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    let after =
        fs::symlink_metadata(&configuration.executable).map_err(|_| CodexSourceError::Security)?;
    if actual != configuration.executable_pin.sha256 || !same_file_identity(&before, &after) {
        return Err(CodexSourceError::Security);
    }
    Ok(())
}

fn authenticate_executable_fast(
    configuration: &SourceConfiguration,
) -> Result<(), CodexSourceError> {
    validate_ancestry(&configuration.executable)?;
    let metadata =
        fs::symlink_metadata(&configuration.executable).map_err(|_| CodexSourceError::Security)?;
    validate_executable_metadata(&metadata, &configuration.executable_pin)
}

fn validate_executable_metadata(
    metadata: &fs::Metadata,
    pin: &ExecutablePin,
) -> Result<(), CodexSourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || (metadata.uid() != 0 && metadata.uid() != current_uid())
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o100 == 0
            || metadata.ino() != pin.inode
            || (metadata.mode() & 0o7777) != pin.mode
            || metadata.size() != pin.size
            || metadata.uid() != pin.uid
        {
            return Err(CodexSourceError::Security);
        }
    }
    if !valid_digest(&pin.sha256) || !canonical_uuid_shape(&pin.volume_uuid) {
        return Err(CodexSourceError::Security);
    }
    Ok(())
}

fn exact_object(value: Value, keys: &[&str]) -> Result<Map<String, Value>, CodexSourceError> {
    optional_exact_object(value, keys, &[])
}

fn optional_exact_object(
    value: Value,
    required: &[&str],
    optional: &[&str],
) -> Result<Map<String, Value>, CodexSourceError> {
    let object = value.as_object().ok_or(CodexSourceError::Protocol)?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(object.clone())
}

fn value_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, CodexSourceError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(CodexSourceError::Protocol)
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<Option<String>, CodexSourceError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => safe_text(value, maximum, true).map(Some),
        _ => Err(CodexSourceError::Protocol),
    }
}

fn thread_identifier(value: &str) -> Result<String, CodexSourceError> {
    closed_identifier(value, 128)
}

fn turn_identifier(value: &str) -> Result<String, CodexSourceError> {
    closed_identifier(value, 128)
}

fn closed_identifier(value: &str, maximum: usize) -> Result<String, CodexSourceError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(value.to_owned())
}

fn durable_identifier(value: &str, maximum: usize) -> Result<String, CodexSourceError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0
                    && matches!(
                        byte,
                        b'.' | b'_' | b':' | b'/' | b'@' | b'*' | b'?' | b'+' | b'-'
                    ))
        })
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(value.to_owned())
}

fn canonical_uuid(value: &str) -> Result<String, CodexSourceError> {
    if canonical_uuid_shape(value) {
        Ok(value.to_owned())
    } else {
        Err(CodexSourceError::Protocol)
    }
}

fn canonical_uuid_shape(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn message_text(value: &str) -> Result<String, CodexSourceError> {
    safe_text(value, MAX_MESSAGE_BYTES, true).and_then(|text| {
        if text.trim().is_empty() || text.matches('\n').count() > 40 {
            Err(CodexSourceError::Protocol)
        } else {
            Ok(text)
        }
    })
}

fn safe_text(value: &str, maximum: usize, allow_layout: bool) -> Result<String, CodexSourceError> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(|character| {
            (character.is_control() && !(allow_layout && matches!(character, '\n' | '\r' | '\t')))
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
    {
        return Err(CodexSourceError::Protocol);
    }
    Ok(value.to_owned())
}

fn canonical_absolute_path(value: &str) -> Result<PathBuf, CodexSourceError> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.to_string_lossy() != value
    {
        return Err(CodexSourceError::Security);
    }
    Ok(path)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

fn owner_home() -> Result<PathBuf, CodexSourceError> {
    let home = std::env::var_os("HOME").ok_or(CodexSourceError::Security)?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(CodexSourceError::Security);
    }
    Ok(home)
}

fn validate_ancestry(path: &Path) -> Result<(), CodexSourceError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component),
            Component::Normal(part) => current.push(part),
            _ => return Err(CodexSourceError::Security),
        }
        let details = fs::symlink_metadata(&current).map_err(|_| CodexSourceError::Security)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // `/Applications` is root-owned `0775` on supported macOS
            // installations. The selected app and executable are still pinned
            // by owner, inode, mode, size and digest below, so reject foreign
            // owners and links here without incorrectly rejecting that system
            // ancestor.
            if details.file_type().is_symlink()
                || (details.uid() != 0 && details.uid() != current_uid())
            {
                return Err(CodexSourceError::Security);
            }
        }
    }
    Ok(())
}

fn validate_private_directory(
    path: &Path,
    require_owner_only: bool,
) -> Result<(), CodexSourceError> {
    validate_ancestry(path)?;
    let details = fs::symlink_metadata(path).map_err(|_| CodexSourceError::Security)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !details.is_dir()
            || details.uid() != current_uid()
            || details.mode() & 0o022 != 0
            || (require_owner_only && details.mode() & 0o077 != 0)
        {
            return Err(CodexSourceError::Security);
        }
    }
    Ok(())
}

fn stable_private_file(
    path: &Path,
    required_mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, CodexSourceError> {
    validate_ancestry(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| CodexSourceError::Security)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !before.is_file()
            || before.uid() != current_uid()
            || before.nlink() != 1
            || before.mode() & 0o777 != required_mode
            || before.len() == 0
            || before.len() > maximum
        {
            return Err(CodexSourceError::Security);
        }
    }
    let bytes = fs::read(path).map_err(|_| CodexSourceError::Security)?;
    let after = fs::symlink_metadata(path).map_err(|_| CodexSourceError::Security)?;
    if bytes.len() as u64 != before.len() || !same_file_identity(&before, &after) {
        return Err(CodexSourceError::Security);
    }
    Ok(bytes)
}

fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            before.dev(),
            before.ino(),
            before.uid(),
            before.mode(),
            before.size(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.uid(),
            after.mode(),
            after.size(),
            after.ctime(),
            after.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(turns: Value, status: Value) -> Value {
        json!({
            "cliVersion": "0.153.0-alpha.5",
            "createdAt": 1,
            "cwd": "/tmp/project",
            "ephemeral": false,
            "id": "123e4567-e89b-42d3-a456-426614174000",
            "modelProvider": "openai",
            "name": "Example",
            "preview": "never projected",
            "projectId": null,
            "sessionId": "123e4567-e89b-42d3-a456-426614174000",
            "source": "appServer",
            "status": status,
            "turns": turns,
            "updatedAt": 2
        })
    }

    #[test]
    fn metadata_projection_rejects_turn_content() {
        assert!(decode_thread_metadata(thread(json!([]), json!({"type": "idle"}))).is_ok());
        assert_eq!(
            decode_thread_metadata(thread(json!([{"id": "secret"}]), json!({"type": "idle"}))),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn controller_source_inbox_is_exact_metadata_only_and_preserves_accepted() {
        let value = json!({
            "source_id": "thread-1",
            "items": [{
                "id": "callback-1",
                "kind": "completion_nudge",
                "origin": "control-1",
                "work_id": "team/job+1@example?x*",
                "state": "accepted",
                "queued_at": "2026-09-10T20:00:00.123456Z",
                "reason": null
            }],
            "total": 1,
            "total_status": "exact",
            "lower_bound": 1,
            "truncated": false
        });
        let decoded = decode_controller_source_inbox(value.clone(), "thread-1").unwrap();
        assert_eq!(decoded.source_id, "thread-1");
        assert_eq!(decoded.items[0].state, "accepted");

        let mut wrong_thread = value.clone();
        wrong_thread["source_id"] = json!("thread-2");
        assert_eq!(
            decode_controller_source_inbox(wrong_thread, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut content = value.clone();
        content["items"][0]["content"] = json!("must not cross");
        assert_eq!(
            decode_controller_source_inbox(content, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut inconsistent_count = value.clone();
        inconsistent_count["total_status"] = json!("capped");
        inconsistent_count["total"] = Value::Null;
        inconsistent_count["truncated"] = json!(true);
        assert_eq!(
            decode_controller_source_inbox(inconsistent_count, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let empty_capped = json!({
            "source_id": "thread-1",
            "items": [],
            "total": null,
            "total_status": "capped",
            "lower_bound": 13,
            "truncated": true
        });
        assert_eq!(
            decode_controller_source_inbox(empty_capped, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut missing_total = value.clone();
        missing_total.as_object_mut().unwrap().remove("total");
        assert_eq!(
            decode_controller_source_inbox(missing_total, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut missing_work_id = value.clone();
        missing_work_id["items"][0]
            .as_object_mut()
            .unwrap()
            .remove("work_id");
        assert_eq!(
            decode_controller_source_inbox(missing_work_id, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut missing_reason_field = value.clone();
        missing_reason_field["items"][0]
            .as_object_mut()
            .unwrap()
            .remove("reason");
        assert_eq!(
            decode_controller_source_inbox(missing_reason_field, "thread-1"),
            Err(CodexSourceError::Protocol)
        );

        let mut overclaim = value.clone();
        overclaim["items"][0]["state"] = json!("committed");
        assert_eq!(
            decode_controller_source_inbox(overclaim, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
        let mut missing_reason = value;
        missing_reason["items"][0]["state"] = json!("attention");
        assert_eq!(
            decode_controller_source_inbox(missing_reason, "thread-1"),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn thread_metadata_is_bound_to_the_requested_thread() {
        let matching = thread(json!([]), json!({"type": "idle"}));
        assert!(decode_bound_thread_metadata(
            matching.clone(),
            "123e4567-e89b-42d3-a456-426614174000"
        )
        .is_ok());
        assert_eq!(
            decode_bound_thread_metadata(matching, "123e4567-e89b-42d3-a456-426614174001"),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn unsupported_controller_error_has_a_closed_public_message() {
        assert_eq!(
            CodexSourceError::Unsupported.public_message(),
            "Codex source requires a newer Fugue controller"
        );
    }

    #[test]
    fn runtime_status_is_closed() {
        assert!(decode_status(&json!({"type": "active", "activeFlags": ["waiting"]})).is_ok());
        assert_eq!(
            serde_json::to_value(ThreadRuntimeStatus::Active {
                active_flags: vec!["waiting".to_owned()]
            })
            .unwrap(),
            json!({"type": "active", "active_flags": ["waiting"]})
        );
        assert_eq!(
            decode_status(&json!({"type": "future"})),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn idle_route_requires_closed_committed_receipt() {
        let route = CommittedIdleRoute::from_controller_response(
            json!({
                "message_id": "123e4567-e89b-42d3-a456-426614174000",
                "route_id": "source-route-1",
                "state": "committed",
                "thread_id": "123e4567-e89b-42d3-a456-426614174000"
            }),
            "123e4567-e89b-42d3-a456-426614174000",
            "123e4567-e89b-42d3-a456-426614174000",
        );
        assert!(route.is_ok());
        assert_eq!(
            CommittedIdleRoute::from_controller_response(
                json!({
                    "message_id": "123e4567-e89b-42d3-a456-426614174000",
                    "route_id": "source-route-1",
                    "state": "accepted",
                    "thread_id": "123e4567-e89b-42d3-a456-426614174000"
                }),
                "123e4567-e89b-42d3-a456-426614174000",
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            Err(CodexSourceError::Rejected)
        );
        assert_eq!(
            CommittedIdleRoute::from_controller_response(
                json!({
                    "message_id": "123e4567-e89b-42d3-a456-426614174001",
                    "route_id": "source-route-1",
                    "state": "committed",
                    "thread_id": "123e4567-e89b-42d3-a456-426614174000"
                }),
                "123e4567-e89b-42d3-a456-426614174000",
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            Err(CodexSourceError::Protocol)
        );
        assert_eq!(
            CommittedIdleRoute::from_controller_response(
                json!({
                    "message_id": "123e4567-e89b-42d3-a456-426614174000",
                    "route_id": "source-route-1",
                    "state": "committed",
                    "thread_id": "123e4567-e89b-42d3-a456-426614174001"
                }),
                "123e4567-e89b-42d3-a456-426614174000",
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn source_change_notifications_are_closed_to_status_metadata() {
        assert_eq!(
            source_change_method("thread/status/changed"),
            Some("thread/status/changed")
        );
        assert_eq!(source_change_method("turn/started"), Some("turn/started"));
        assert_eq!(
            source_change_method("turn/completed"),
            Some("turn/completed")
        );
        assert_eq!(source_change_method("item/agentMessage/delta"), None);
        assert_eq!(source_change_method("future/event"), None);

        let status = json!({
            "method": "thread/status/changed",
            "params": {"threadId": "thread-1", "status": {"type": "active", "activeFlags": ["waiting"]}}
        });
        assert_eq!(
            source_change_notification(status.as_object().unwrap()),
            Ok(Some(SourceChange {
                method: "thread/status/changed",
            }))
        );
        assert_eq!(
            serde_json::to_value(SourceChange {
                method: "thread/status/changed",
            })
            .unwrap(),
            json!({"method": "thread/status/changed"})
        );
        let turn = json!({
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": {"private": "discarded"}}
        });
        assert_eq!(
            source_change_notification(turn.as_object().unwrap()),
            Ok(Some(SourceChange {
                method: "turn/started",
            }))
        );
        assert!(validate_notification(
            json!({"method": "thread/queue/changed", "params": {"private": "discarded"}})
                .as_object()
                .unwrap()
        )
        .is_ok());
        assert_eq!(
            validate_notification(
                json!({"method": "future/event", "params": {}})
                    .as_object()
                    .unwrap()
            ),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn response_envelope_rejects_unknown_fields() {
        let good = json!({"id": 7, "result": {}});
        assert_eq!(decode_response(good.as_object().unwrap(), 7), Ok(json!({})));
        let extra = json!({"id": 7, "result": {}, "future": true});
        assert_eq!(
            decode_response(extra.as_object().unwrap(), 7),
            Err(CodexSourceError::Protocol)
        );
    }

    #[test]
    fn transcript_is_explicit_and_may_contain_turns() {
        assert!(validate_thread_shape(
            &thread(json!([{"id": "turn-1"}]), json!({"type": "idle"})),
            true
        )
        .is_ok());
    }

    #[test]
    fn inspection_finds_one_exact_active_turn() {
        let value = thread(
            json!([
                {"id": "turn-old", "status": "completed"},
                {"id": "turn-active", "status": "inProgress"}
            ]),
            json!({"type": "active", "activeFlags": []}),
        );
        assert_eq!(active_turn_id(&value), Ok(Some("turn-active".to_owned())));
        let ambiguous = thread(
            json!([
                {"id": "turn-a", "status": "inProgress"},
                {"id": "turn-b", "status": "inProgress"}
            ]),
            json!({"type": "active", "activeFlags": []}),
        );
        assert_eq!(active_turn_id(&ambiguous), Err(CodexSourceError::Protocol));
    }
}
