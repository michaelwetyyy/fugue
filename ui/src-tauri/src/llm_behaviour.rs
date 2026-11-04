use crate::cockpit::{call_controller, BridgeError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MUSE_13: &str = "opencode/muse-spark-1.3-contributor-free";
const MUSE_12: &str = "opencode/muse-spark-1.2-contributor-free";
const LING_30: &str = "opencode/ling-3.0-flash-fin-free";
const MODELS: [&str; 3] = [MUSE_13, MUSE_12, LING_30];
const MUSE_13_EFFORTS: [&str; 6] = ["minimal", "low", "medium", "high", "xhigh", "max"];
const MUSE_12_EFFORTS: [&str; 5] = ["minimal", "low", "medium", "high", "xhigh"];
const LING_30_EFFORTS: [&str; 3] = ["low", "medium", "high"];
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmBehaviourStatus {
    available: bool,
    supported_models: Vec<String>,
    supported_efforts_by_model: BTreeMap<String, Vec<String>>,
    current_model: String,
    current_effort: String,
    effective_model: String,
    effective_effort: String,
}

fn efforts(model: &str) -> Option<&'static [&'static str]> {
    match model {
        MUSE_13 => Some(&MUSE_13_EFFORTS),
        MUSE_12 => Some(&MUSE_12_EFFORTS),
        LING_30 => Some(&LING_30_EFFORTS),
        _ => None,
    }
}

fn valid_pair(model: &str, effort: &str) -> bool {
    efforts(model).is_some_and(|values| values.contains(&effort))
}

fn validate(value: Value) -> Result<Value, BridgeError> {
    let status: LlmBehaviourStatus =
        serde_json::from_value(value.clone()).map_err(|_| BridgeError::Protocol)?;
    if !status.available
        || status.supported_models != MODELS
        || status.supported_efforts_by_model.len() != MODELS.len()
        || MODELS.iter().any(|model| {
            status.supported_efforts_by_model.get(*model)
                != efforts(model)
                    .map(|items| {
                        items
                            .iter()
                            .map(|item| (*item).to_owned())
                            .collect::<Vec<_>>()
                    })
                    .as_ref()
        })
        || !valid_pair(&status.current_model, &status.current_effort)
        || !valid_pair(&status.effective_model, &status.effective_effort)
    {
        return Err(BridgeError::Protocol);
    }
    Ok(value)
}

fn request_id(label: &str) -> String {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "fugue-llm-{label}-{}-{nanos:x}-{sequence:x}",
        std::process::id()
    )
}

pub(crate) fn status() -> Result<Value, BridgeError> {
    validate(call_controller(
        "llm.behaviour.status.v1",
        json!({}),
        request_id("status"),
    )?)
}

pub(crate) fn apply(model: &str, effort: &str) -> Result<Value, BridgeError> {
    if !valid_pair(model, effort) {
        return Err(BridgeError::Protocol);
    }
    let value = validate(call_controller(
        "llm.behaviour.apply.v1",
        json!({"model": model, "effort": effort}),
        request_id("apply"),
    )?)?;
    let status: LlmBehaviourStatus =
        serde_json::from_value(value.clone()).map_err(|_| BridgeError::Protocol)?;
    if status.current_model != model
        || status.current_effort != effort
        || status.effective_model != model
        || status.effective_effort != effort
    {
        return Err(BridgeError::Protocol);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_is_closed_and_preserves_muse_13_max() {
        assert!(valid_pair(MUSE_13, "max"));
        assert!(!valid_pair(MUSE_12, "max"));
        assert!(!valid_pair("opencode/paid", "max"));
        assert!(!valid_pair(MUSE_13, "ultra"));
    }

    #[test]
    fn response_rejects_unknown_or_incomplete_rosters() {
        let supported_efforts_by_model = BTreeMap::from([
            (
                MUSE_13.to_owned(),
                MUSE_13_EFFORTS
                    .iter()
                    .map(|item| (*item).to_owned())
                    .collect::<Vec<_>>(),
            ),
            (
                MUSE_12.to_owned(),
                MUSE_12_EFFORTS
                    .iter()
                    .map(|item| (*item).to_owned())
                    .collect::<Vec<_>>(),
            ),
            (
                LING_30.to_owned(),
                LING_30_EFFORTS
                    .iter()
                    .map(|item| (*item).to_owned())
                    .collect::<Vec<_>>(),
            ),
        ]);
        let value = json!({
            "available": true,
            "supported_models": MODELS,
            "supported_efforts_by_model": supported_efforts_by_model,
            "current_model": MUSE_13,
            "current_effort": "max",
            "effective_model": MUSE_13,
            "effective_effort": "max",
        });
        assert!(validate(value.clone()).is_ok());
        let mut changed = value;
        changed["supported_models"] = json!([MUSE_13, "opencode/paid"]);
        assert!(validate(changed).is_err());
    }
}
