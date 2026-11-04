use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cockpit::{call_controller, BridgeError};

const MAX_TEXT_BYTES: usize = 2_000;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TranscriptQuery {
    slot_id: String,
    work_id: String,
    generation: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchiveTranscriptQuery {
    archive_id: String,
    slot_id: String,
    work_id: String,
    generation: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComposerInput {
    thread_id: String,
    slot_id: String,
    work_id: String,
    generation: i64,
    idempotency_key: String,
    text: String,
    anchor_item_id: Option<String>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn uuid4(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
        && bytes[14].to_ascii_lowercase() == b'4'
        && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

fn transient_id() -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "fugue-transcript-{}-{nanos:x}-{sequence:x}",
        std::process::id()
    )
}

fn exact_binding(
    value: &Value,
    slot_id: &str,
    work_id: &str,
    generation: i64,
    session_id: Option<&str>,
) -> bool {
    let object = match value.as_object() {
        Some(object) => object,
        None => return false,
    };
    object.get("slot_id").and_then(Value::as_str) == Some(slot_id)
        && object.get("work_id").and_then(Value::as_str) == Some(work_id)
        && object.get("generation").and_then(Value::as_i64) == Some(generation)
        && session_id.is_none_or(|expected| {
            object.get("thread_id").and_then(Value::as_str) == Some(expected)
        })
}

pub(crate) fn load(input: TranscriptQuery) -> Result<Value, BridgeError> {
    if !identifier(&input.slot_id)
        || !identifier(&input.work_id)
        || !(1..=i64::from(i32::MAX)).contains(&input.generation)
    {
        return Err(BridgeError::Protocol);
    }
    let result = call_controller(
        "worker.transcript.v1",
        json!({
            "slot_id": input.slot_id,
            "work_id": input.work_id,
            "generation": input.generation,
        }),
        transient_id(),
    )?;
    if !exact_binding(
        &result,
        &input.slot_id,
        &input.work_id,
        input.generation,
        None,
    ) {
        return Err(BridgeError::Protocol);
    }
    Ok(result)
}

pub(crate) fn load_archive(input: ArchiveTranscriptQuery) -> Result<Value, BridgeError> {
    if !identifier(&input.archive_id)
        || !identifier(&input.slot_id)
        || !identifier(&input.work_id)
        || !(1..=i64::from(i32::MAX)).contains(&input.generation)
    {
        return Err(BridgeError::Protocol);
    }
    let result = call_controller(
        "worker.transcript.archive.v1",
        json!({
            "archive_id": input.archive_id,
            "slot_id": input.slot_id,
            "work_id": input.work_id,
            "generation": input.generation,
        }),
        transient_id(),
    )?;
    if !exact_binding(
        &result,
        &input.slot_id,
        &input.work_id,
        input.generation,
        None,
    ) || result.get("archive_id").and_then(Value::as_str) != Some(input.archive_id.as_str())
        || result.get("read_only").and_then(Value::as_bool) != Some(true)
    {
        return Err(BridgeError::Protocol);
    }
    Ok(result)
}

pub(crate) fn send(input: ComposerInput) -> Result<Value, BridgeError> {
    if !identifier(&input.thread_id)
        || !identifier(&input.slot_id)
        || !identifier(&input.work_id)
        || !(1..=i64::from(i32::MAX)).contains(&input.generation)
        || !uuid4(&input.idempotency_key)
        || input.text.trim().is_empty()
        || input.text.len() > MAX_TEXT_BYTES
        || input.text.matches('\n').count() > 20
        || input
            .anchor_item_id
            .as_deref()
            .is_some_and(|value| !identifier(value))
    {
        return Err(BridgeError::Protocol);
    }
    let result = call_controller(
        "worker.compose.v1",
        json!({
            "slot_id": input.slot_id,
            "work_id": input.work_id,
            "generation": input.generation,
            "session_id": input.thread_id,
            "text": input.text,
        }),
        input.idempotency_key.to_ascii_lowercase(),
    )?;
    if !exact_binding(
        &result,
        &input.slot_id,
        &input.work_id,
        input.generation,
        Some(&input.thread_id),
    ) {
        return Err(BridgeError::Protocol);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_requires_v4_and_rfc_variant() {
        assert!(uuid4("123e4567-e89b-42d3-a456-426614174000"));
        assert!(!uuid4("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!uuid4("123e4567-e89b-42d3-c456-426614174000"));
    }

    #[test]
    fn identifiers_are_closed_ascii_values() {
        assert!(identifier("homelab-1"));
        assert!(!identifier("homelab/1"));
        assert!(!identifier("-homelab"));
        assert!(!identifier("homelab\u{200b}-1"));
    }

    #[test]
    #[ignore = "requires an exact active worker binding and the configured controller"]
    fn configured_controller_returns_exact_worker_transcript() {
        let input = TranscriptQuery {
            slot_id: std::env::var("FUGUE_TEST_SLOT_ID").unwrap(),
            work_id: std::env::var("FUGUE_TEST_WORK_ID").unwrap(),
            generation: std::env::var("FUGUE_TEST_GENERATION")
                .unwrap()
                .parse()
                .unwrap(),
        };
        let result = load(input).unwrap();
        assert!(result.get("turns").and_then(Value::as_array).is_some());
    }
}
