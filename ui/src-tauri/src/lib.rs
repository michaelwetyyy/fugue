#[cfg(not(feature = "dev-lab"))]
mod cockpit;
#[cfg(not(feature = "dev-lab"))]
mod codex_source;
#[cfg(feature = "dev-lab")]
mod dev_lab;
#[cfg(not(feature = "dev-lab"))]
mod integration;
#[cfg(not(feature = "dev-lab"))]
mod lifecycle;
#[cfg(not(feature = "dev-lab"))]
mod llm_behaviour;
#[cfg(feature = "dev-lab")]
mod mcp_dev;
#[cfg(not(feature = "dev-lab"))]
mod submission;
#[cfg(not(feature = "dev-lab"))]
mod transcript;

#[cfg(target_os = "macos")]
const EXPLICIT_QUIT_MENU_ID: &str = "fugue.explicit-quit";

#[cfg(target_os = "macos")]
fn macos_application_menu(
    handle: &tauri::AppHandle,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem};

    let menu = Menu::default(handle)?;
    let app_submenu = menu
        .items()?
        .into_iter()
        .next()
        .and_then(|item| item.as_submenu().cloned())
        .expect("Tauri default macOS menu must begin with the application submenu");
    let app_items = app_submenu.items()?;
    let quit_index = app_items
        .len()
        .checked_sub(1)
        .expect("Tauri default macOS application menu must contain Quit");
    let native_quit = app_items[quit_index]
        .as_predefined_menuitem()
        .expect("Tauri default macOS application menu must end with predefined Quit");
    let native_quit_text = native_quit.text()?;
    if !native_quit_text.starts_with("Quit") {
        panic!("Tauri default macOS application menu no longer ends with Quit");
    }
    app_submenu.remove_at(quit_index)?;

    let product_name = handle
        .config()
        .product_name
        .as_deref()
        .unwrap_or(handle.package_info().name.as_str())
        .to_owned();
    let explicit_quit = MenuItem::with_id(
        handle,
        EXPLICIT_QUIT_MENU_ID,
        format!("Quit {product_name}"),
        true,
        Some("CmdOrCtrl+Q"),
    )?;
    app_submenu.append(&explicit_quit)?;
    Ok(menu)
}

#[derive(Debug, serde::Serialize)]
struct SourceInboxCommandError {
    code: &'static str,
    message: &'static str,
}

impl SourceInboxCommandError {
    #[cfg(not(feature = "dev-lab"))]
    fn unavailable(message: &'static str) -> Self {
        Self {
            code: "source_inbox_unavailable",
            message,
        }
    }
}

#[cfg(not(feature = "dev-lab"))]
fn source_inbox_command_error(error: codex_source::CodexSourceError) -> SourceInboxCommandError {
    let code = match error {
        codex_source::CodexSourceError::Unsupported => "unsupported_operation",
        codex_source::CodexSourceError::Security => "source_inbox_security",
        codex_source::CodexSourceError::Protocol => "source_inbox_protocol",
        codex_source::CodexSourceError::Rejected => "source_inbox_rejected",
        codex_source::CodexSourceError::Unavailable
        | codex_source::CodexSourceError::DeliveryUnknown => "source_inbox_unavailable",
    };
    SourceInboxCommandError {
        code,
        message: error.public_message(),
    }
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn cockpit_snapshot() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(cockpit::load_snapshot)
        .await
        .map_err(|_| "Fugue controller is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn cockpit_snapshot() -> Result<serde_json::Value, String> {
    Ok(dev_lab::snapshot())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn cockpit_watch(after_event_sequence: i64) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || cockpit::watch_snapshot(after_event_sequence))
        .await
        .map_err(|_| "Fugue controller is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn cockpit_watch(after_event_sequence: i64) -> Result<serde_json::Value, String> {
    dev_lab::watch(after_event_sequence)
        .map_err(|_| "Fugue Dev synthetic feed has no live events".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn integration_status() -> Result<integration::IntegrationStatus, String> {
    tauri::async_runtime::spawn_blocking(integration::status)
        .await
        .map_err(|_| "Fugue integration status is unavailable".to_owned())?
        .map_err(|_| "Fugue integration status is unavailable".to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn integration_status() -> Result<serde_json::Value, String> {
    Ok(dev_lab::integration_status())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn integration_set_enabled(enabled: bool) -> Result<integration::IntegrationStatus, String> {
    tauri::async_runtime::spawn_blocking(move || integration::set_enabled(enabled))
        .await
        .map_err(|_| "Fugue could not change the integration state".to_owned())?
        .map_err(|_| "Fugue could not change the integration state".to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn integration_set_enabled(enabled: bool) -> Result<serde_json::Value, String> {
    if enabled {
        Err("Live offload is disabled in Fugue Dev".to_owned())
    } else {
        Ok(dev_lab::integration_status())
    }
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn llm_behaviour_status() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(llm_behaviour::status)
        .await
        .map_err(|_| "Fugue LLM behaviour control is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn llm_behaviour_status() -> Result<serde_json::Value, String> {
    Ok(dev_lab::llm_behaviour_status())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn llm_behaviour_apply(model: String, effort: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || llm_behaviour::apply(&model, &effort))
        .await
        .map_err(|_| "Fugue could not apply the LLM behaviour".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn llm_behaviour_apply(model: String, effort: String) -> Result<serde_json::Value, String> {
    dev_lab::apply_llm_behaviour(&model, &effort)
        .map_err(|_| "Fugue Dev rejected the synthetic LLM target".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn task_submit(input: submission::TaskSubmission) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || submission::submit(input))
        .await
        .map_err(|_| "Fugue controller is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn task_submit(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Task submission is disabled in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn task_result(input: submission::TaskResultQuery) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || submission::result(input))
        .await
        .map_err(|_| "Fugue controller is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn task_close(input: submission::TaskResultQuery) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || submission::close(input))
        .await
        .map_err(|_| "Fugue controller is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn task_close(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Persistent task close is disabled in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn worker_transcript(
    input: transcript::TranscriptQuery,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || transcript::load(input))
        .await
        .map_err(|_| "Worker transcript is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn worker_transcript(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Worker transcripts are unavailable in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn worker_transcript_archive(
    input: transcript::ArchiveTranscriptQuery,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || transcript::load_archive(input))
        .await
        .map_err(|_| "Archived worker transcript is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn worker_transcript_archive(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Archived worker transcripts are unavailable in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn worker_compose(input: transcript::ComposerInput) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || transcript::send(input))
        .await
        .map_err(|_| "Worker message delivery is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn source_threads() -> Result<codex_source::ThreadPage, String> {
    tauri::async_runtime::spawn_blocking(codex_source::recent_threads)
        .await
        .map_err(|_| "Codex source is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn source_threads() -> Result<serde_json::Value, String> {
    Err("Live Codex sources are unavailable in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn source_watch() -> Result<codex_source::SourceChange, String> {
    tauri::async_runtime::spawn_blocking(codex_source::wait_for_source_change)
        .await
        .map_err(|_| "Codex source updates are unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn source_watch() -> Result<serde_json::Value, String> {
    Err("Live Codex source updates are unavailable in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn source_inbox(
    input: codex_source::SourceThreadQuery,
) -> Result<codex_source::SourceInbox, SourceInboxCommandError> {
    tauri::async_runtime::spawn_blocking(move || codex_source::inbox(input))
        .await
        .map_err(|_| SourceInboxCommandError::unavailable("Codex source inbox is unavailable"))?
        .map_err(source_inbox_command_error)
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn source_inbox(
    _input: serde_json::Value,
) -> Result<serde_json::Value, SourceInboxCommandError> {
    Err(SourceInboxCommandError {
        code: "unsupported_operation",
        message: "Live Codex source inbox is unavailable in Fugue Dev",
    })
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn source_inspect(
    input: codex_source::SourceThreadQuery,
) -> Result<codex_source::TranscriptInspection, String> {
    tauri::async_runtime::spawn_blocking(move || codex_source::inspect(input))
        .await
        .map_err(|_| "Codex source inspection is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn source_inspect(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Live Codex source inspection is unavailable in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn source_compose(
    input: codex_source::SourceMessageInput,
) -> Result<codex_source::SourceDeliveryOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || codex_source::send(input))
        .await
        .map_err(|_| "Codex source delivery is unavailable".to_owned())?
        .map_err(|error| error.public_message().to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn source_compose(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Live Codex source messaging is unavailable in Fugue Dev".to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn worker_compose(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Worker messaging is unavailable in Fugue Dev".to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn task_result(_input: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("Task results are synthetic in Fugue Dev".to_owned())
}

#[cfg(not(feature = "dev-lab"))]
#[tauri::command]
async fn app_lifecycle_start() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(lifecycle::start)
        .await
        .map_err(|_| "Fugue could not start its controller".to_owned())?
        .map_err(|_| "Fugue could not start its controller".to_owned())
}

#[cfg(feature = "dev-lab")]
#[tauri::command]
async fn app_lifecycle_start() -> Result<(), String> {
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let context = tauri::generate_context!();
    #[cfg(feature = "dev-lab")]
    mcp_dev::validate_application_identity(
        &context.config().identifier,
        context.config().product_name.as_deref(),
    )
    .expect("Fugue Dev MCP application identity mismatch");
    #[cfg(feature = "dev-lab")]
    let _dev_mcp_server =
        mcp_dev::DevMcpServer::start().expect("Fugue Dev MCP server failed to start");

    #[cfg(target_os = "macos")]
    use tauri::Manager;

    let builder = tauri::Builder::default().invoke_handler(tauri::generate_handler![
        cockpit_snapshot,
        cockpit_watch,
        integration_status,
        integration_set_enabled,
        llm_behaviour_status,
        llm_behaviour_apply,
        task_submit,
        task_result,
        task_close,
        worker_transcript,
        worker_transcript_archive,
        worker_compose,
        source_threads,
        source_watch,
        source_inbox,
        source_inspect,
        source_compose,
        app_lifecycle_start
    ]);
    #[cfg(target_os = "macos")]
    let builder = builder
        .menu(macos_application_menu)
        .on_menu_event(|app, event| {
            if event.id() == EXPLICIT_QUIT_MENU_ID {
                app.exit(0);
            }
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        });
    let app = builder
        .build(context)
        .expect("Fugue desktop failed to build");
    app.run(|handle, event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen {
            has_visible_windows: false,
            ..
        } = event
        {
            if let Some(window) = handle.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
    });
}
