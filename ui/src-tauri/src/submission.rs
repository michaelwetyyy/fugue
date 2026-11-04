use crate::cockpit::{call_controller, BridgeError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

const MAX_OBJECTIVE_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_SCOPE_ITEMS: usize = 32;
const MAX_SCOPE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AgentLifecycle {
    Disposable,
    Persistent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskSubmission {
    submission_id: String,
    lane: String,
    repository: String,
    scope: Vec<String>,
    objective: String,
    agent_lifecycle: AgentLifecycle,
    reservation_attempt: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskResultQuery {
    submission_id: String,
    reservation_attempt: u8,
}

fn safe_text(value: &str, maximum: usize, allow_layout: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| {
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
}

fn valid_submission_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_scope(value: &str) -> bool {
    safe_text(value, MAX_SCOPE_BYTES, false)
        && !Path::new(value).is_absolute()
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !value
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))
}

impl TaskSubmission {
    fn validate(&self) -> Result<(), BridgeError> {
        if !valid_submission_id(&self.submission_id)
            || !matches!(
                self.lane.as_str(),
                "tensorhost" | "homelab" | "personal" | "control" | "hands-off"
            )
            || !safe_text(&self.repository, MAX_PATH_BYTES, false)
            || !Path::new(&self.repository).is_absolute()
            || !safe_text(&self.objective, MAX_OBJECTIVE_BYTES, true)
            || !(1..=32).contains(&self.reservation_attempt)
            || self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE_ITEMS
            || self.scope.iter().any(|item| !valid_scope(item))
        {
            return Err(BridgeError::Protocol);
        }
        let mut canonical = self.scope.clone();
        canonical.sort();
        canonical.dedup();
        if canonical.len() != self.scope.len() {
            return Err(BridgeError::Protocol);
        }
        Ok(())
    }

    fn params(&self) -> Value {
        json!({
            "agent_lifecycle": self.agent_lifecycle,
            "allow_child_agents": true,
            "classification": "PUBLIC",
            "lane": self.lane,
            "objective": self.objective,
            "repository": self.repository,
            "reservation_attempt": self.reservation_attempt,
            "scope": self.scope,
            "submission_id": self.submission_id,
            "trust": "secure",
        })
    }
}

fn validate_result(input: &TaskSubmission, result: Value) -> Result<Value, BridgeError> {
    let item = result.as_object().ok_or(BridgeError::Protocol)?;
    let expected = [
        "submission_id",
        "work_id",
        "lane",
        "state",
        "agent_lifecycle",
        "child_agents",
        "reservation_attempt",
    ];
    if item.len() != expected.len()
        || expected.iter().any(|key| !item.contains_key(*key))
        || item.get("submission_id").and_then(Value::as_str) != Some(input.submission_id.as_str())
        || item.get("lane").and_then(Value::as_str) != Some(input.lane.as_str())
        || item.get("agent_lifecycle")
            != Some(&Value::String(match input.agent_lifecycle {
                AgentLifecycle::Disposable => "disposable".to_owned(),
                AgentLifecycle::Persistent => "persistent".to_owned(),
            }))
        || item.get("child_agents") != Some(&Value::String("allowed".to_owned()))
        || item.get("reservation_attempt").and_then(Value::as_u64)
            != Some(u64::from(input.reservation_attempt))
        || !matches!(
            item.get("state").and_then(Value::as_str),
            Some("accepted" | "busy" | "rejected")
        )
        || !item
            .get("work_id")
            .and_then(Value::as_str)
            .is_some_and(|value| safe_text(value, 256, false))
    {
        return Err(BridgeError::Protocol);
    }
    Ok(result)
}

pub(crate) fn submit(input: TaskSubmission) -> Result<Value, BridgeError> {
    input.validate()?;
    let idempotency_id = format!(
        "gui-submit-{}-attempt-{}",
        input.submission_id, input.reservation_attempt
    );
    let result = call_controller("submission.submit.v1", input.params(), idempotency_id)?;
    validate_result(&input, result)
}

pub(crate) fn result(input: TaskResultQuery) -> Result<Value, BridgeError> {
    if !valid_submission_id(&input.submission_id) || !(1..=32).contains(&input.reservation_attempt)
    {
        return Err(BridgeError::Protocol);
    }
    let value = call_controller(
        "submission.result.v1",
        json!({
            "submission_id": input.submission_id,
            "reservation_attempt": input.reservation_attempt,
        }),
        format!(
            "gui-result-{}-attempt-{}",
            input.submission_id, input.reservation_attempt
        ),
    )?;
    let item = value.as_object().ok_or(BridgeError::Protocol)?;
    let expected = [
        "submission_id",
        "reservation_attempt",
        "state",
        "outcome",
        "result_ref",
        "text",
        "persistent_session_state",
    ];
    let state = item.get("state").and_then(Value::as_str);
    let nullable_text = |key: &str, maximum: usize| {
        item.get(key).is_some_and(|value| {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|text| safe_text(text, maximum, true))
        })
    };
    if item.len() != expected.len()
        || expected.iter().any(|key| !item.contains_key(*key))
        || item.get("submission_id").and_then(Value::as_str) != Some(input.submission_id.as_str())
        || item.get("reservation_attempt").and_then(Value::as_u64)
            != Some(u64::from(input.reservation_attempt))
        || !matches!(state, Some("waiting" | "completed" | "not_started"))
        || !nullable_text("outcome", 32)
        || !nullable_text("result_ref", 256)
        || !nullable_text("text", 49_152)
        || !item.get("persistent_session_state").is_some_and(|value| {
            value.is_null()
                || matches!(
                    value.as_str(),
                    Some("active" | "closed" | "attention" | "unavailable")
                )
        })
        || (state == Some("completed")
            && (item.get("outcome").is_none_or(Value::is_null)
                || item.get("result_ref").is_none_or(Value::is_null)))
        || (state != Some("completed")
            && (!item.get("outcome").is_some_and(Value::is_null)
                || !item.get("result_ref").is_some_and(Value::is_null)
                || !item.get("text").is_some_and(Value::is_null)))
    {
        return Err(BridgeError::Protocol);
    }
    Ok(value)
}

pub(crate) fn close(input: TaskResultQuery) -> Result<Value, BridgeError> {
    if !valid_submission_id(&input.submission_id) || !(1..=32).contains(&input.reservation_attempt)
    {
        return Err(BridgeError::Protocol);
    }
    let value = call_controller(
        "submission.close.v1",
        json!({
            "submission_id": input.submission_id,
            "reservation_attempt": input.reservation_attempt,
        }),
        format!(
            "gui-close-{}-attempt-{}",
            input.submission_id, input.reservation_attempt
        ),
    )?;
    let item = value.as_object().ok_or(BridgeError::Protocol)?;
    let expected = ["submission_id", "reservation_attempt", "state", "reason"];
    let state = item.get("state").and_then(Value::as_str);
    if item.len() != expected.len()
        || expected.iter().any(|key| !item.contains_key(*key))
        || item.get("submission_id").and_then(Value::as_str) != Some(input.submission_id.as_str())
        || item.get("reservation_attempt").and_then(Value::as_u64)
            != Some(u64::from(input.reservation_attempt))
        || !matches!(state, Some("closed" | "attention"))
        || !match state {
            Some("closed") => item.get("reason").is_some_and(Value::is_null),
            Some("attention") => {
                item.get("reason").and_then(Value::as_str) == Some("persistent_session_attention")
            }
            _ => false,
        }
    {
        return Err(BridgeError::Protocol);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission() -> TaskSubmission {
        TaskSubmission {
            submission_id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
            lane: "homelab".to_owned(),
            repository: "/Users/example/project".to_owned(),
            scope: vec!["src/main.rs".to_owned()],
            objective: "Review the task boundary".to_owned(),
            agent_lifecycle: AgentLifecycle::Disposable,
            reservation_attempt: 1,
        }
    }

    #[test]
    fn exact_submission_is_bounded_and_child_delegation_is_controller_derived() {
        let input = submission();
        input.validate().unwrap();
        assert_eq!(
            input.params(),
            json!({
                "agent_lifecycle": "disposable",
                "allow_child_agents": true,
                "classification": "PUBLIC",
                "lane": "homelab",
                "objective": "Review the task boundary",
                "repository": "/Users/example/project",
                "reservation_attempt": 1,
                "scope": ["src/main.rs"],
                "submission_id": "123e4567-e89b-12d3-a456-426614174000",
                "trust": "secure",
            })
        );
    }

    #[test]
    fn traversal_duplicates_controls_and_unknown_lifecycle_are_rejected() {
        let mut input = submission();
        input.scope = vec!["../escape".to_owned()];
        assert_eq!(input.validate(), Err(BridgeError::Protocol));
        input.scope = vec!["src/main.rs".to_owned(), "src/main.rs".to_owned()];
        assert_eq!(input.validate(), Err(BridgeError::Protocol));
        input.scope = vec!["src/main.rs".to_owned()];
        input.objective = "unsafe\0objective".to_owned();
        assert_eq!(input.validate(), Err(BridgeError::Protocol));
        assert!(serde_json::from_value::<TaskSubmission>(json!({
            "submission_id": "123e4567-e89b-12d3-a456-426614174000",
            "lane": "homelab",
            "repository": "/tmp/project",
            "scope": ["src/main.rs"],
            "objective": "Review",
            "agent_lifecycle": "forever"
            ,"reservation_attempt": 1
        }))
        .is_err());
    }

    #[test]
    fn response_must_match_the_submitted_identity_and_closed_shape() {
        let input = submission();
        let good = json!({
            "submission_id": input.submission_id,
            "work_id": "gui-work-1",
            "lane": input.lane,
            "state": "accepted",
            "agent_lifecycle": "disposable",
            "child_agents": "allowed",
            "reservation_attempt": 1,
        });
        assert!(validate_result(&input, good.clone()).is_ok());
        let mut bad = good;
        bad.as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), json!(true));
        assert_eq!(validate_result(&input, bad), Err(BridgeError::Protocol));
    }
}
