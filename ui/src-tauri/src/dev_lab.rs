use serde_json::{json, Value};
use std::sync::atomic::{AtomicU8, Ordering};

pub(crate) const APP_IDENTIFIER: &str = "com.tensorhost.fugue.dev";
pub(crate) const LAUNCHD_LABEL: &str = "com.tensorhost.oc-rig-v2.dev";
pub(crate) const DEPLOYMENT_ROOT: &str = "Library/Application Support/oc-rig-v2-dev";
pub(crate) const BACKEND_WORK_ROOT: &str = "Library/Application Support/oc-rig-v2-dev-backend-work";
pub(crate) const OPENCODE_CONFIG_ROOT: &str = ".config/opencode-dev";
pub(crate) const BACKEND_PORT: u16 = 4197;
pub(crate) const MCP_NAME: &str = "fugue-dev";
pub(crate) const CALLBACK_MODE: &str = "shadow";

const LIVE_APP_IDENTIFIER: &str = "com.tensorhost.fugue";
const LIVE_LAUNCHD_LABEL: &str = "com.tensorhost.oc-rig-v2";
const LIVE_DEPLOYMENT_ROOT: &str = "Library/Application Support/oc-rig-v2";
const LIVE_BACKEND_WORK_ROOT: &str = "Library/Application Support/oc-rig-v2-backend-work";
const LIVE_OPENCODE_CONFIG_ROOT: &str = ".config/opencode";
const LIVE_BACKEND_PORT: u16 = 4096;
static LLM_SELECTION: AtomicU8 = AtomicU8::new(3);

fn assert_isolated_profile() {
    assert_ne!(APP_IDENTIFIER, LIVE_APP_IDENTIFIER);
    assert_ne!(LAUNCHD_LABEL, LIVE_LAUNCHD_LABEL);
    assert_ne!(DEPLOYMENT_ROOT, LIVE_DEPLOYMENT_ROOT);
    assert_ne!(BACKEND_WORK_ROOT, LIVE_BACKEND_WORK_ROOT);
    assert_ne!(OPENCODE_CONFIG_ROOT, LIVE_OPENCODE_CONFIG_ROOT);
    assert_ne!(BACKEND_PORT, LIVE_BACKEND_PORT);
    assert_eq!(MCP_NAME, "fugue-dev");
    assert_eq!(CALLBACK_MODE, "shadow");
}

fn collection() -> Value {
    json!({
        "status": "available",
        "items": [],
        "total": 0,
        "total_status": "exact",
        "lower_bound": 0,
        "truncated": false
    })
}

fn recent_turns() -> Value {
    json!({
        "status": "unavailable",
        "reason": "synthetic_dev_metadata_only",
        "limit": 2,
        "items": [],
        "content_included": false
    })
}

fn worker(lane: &str, position: u8, assigned: bool) -> Value {
    let slot_id = format!("{lane}-{position}");
    let work_id = assigned.then_some("dev-shadow-work-1");
    let assignment_id = assigned.then_some("dev-shadow-assignment-1");
    json!({
        "slot_id": slot_id,
        "lane": lane,
        "position": position,
        "slot_state": if assigned { "assigned" } else { "clear" },
        "display_name": format!("synthetic · {slot_id}"),
        "session": { "status": "available", "ref": format!("dev-session-{slot_id}") },
        "pane": { "status": "disabled", "ref": null },
        "work_id": work_id,
        "agent_lifecycle": if assigned { Value::String("persistent".to_owned()) } else { Value::Null },
        "owner_id": assigned.then_some("fugue-dev-shadow"),
        "assignment_id": assignment_id,
        "attempt": assigned.then_some(1),
        "transport": {
            "status": if assigned { "available" } else { "disabled" },
            "reason": if assigned { Value::Null } else { Value::String("synthetic_dev_adapter".to_owned()) },
            "id": assigned.then_some("dev-shadow-transport-1"),
            "state": if assigned { "accepted" } else { "idle" },
            "generation": assigned.then_some(1),
            "acknowledgement_id": assigned.then_some("dev-shadow-ack-1"),
            "error_code": Value::Null,
            "adapter": {
                "status": "disabled",
                "kind": "synthetic-shadow-v1",
                "reason": "no_live_delivery"
            }
        },
        "completion": {
            "status": "disabled",
            "reason": "synthetic_dev_result",
            "id": Value::Null,
            "registration_state": "not-applicable",
            "route_state": "not-applicable",
            "callback_state": "not-applicable",
            "callback_adapter": { "status": "disabled", "reason": "shadow_only" }
        },
        "recovery": {
            "status": "disabled",
            "reason": "synthetic_dev_target",
            "target_id": Value::Null,
            "phase": if assigned { "handed_off" } else { "not-applicable" },
            "circuit_state": "not-applicable",
            "episode_state": "not-applicable",
            "timer_state": "not-applicable"
        },
        "recent_turns": recent_turns()
    })
}

fn synthetic_snapshot() -> Value {
    let lanes = [
        ("tensorhost", 3_u8),
        ("homelab", 3_u8),
        ("personal", 3_u8),
        ("control", 3_u8),
        ("hands-off", 1_u8),
    ];
    let mut workers = Vec::new();
    let mut slots = Vec::new();
    for (lane, capacity) in lanes {
        for position in 1..=capacity {
            let assigned = lane == "control" && position == 1;
            let slot_id = format!("{lane}-{position}");
            workers.push(worker(lane, position, assigned));
            slots.push(json!({
                "slot_id": slot_id,
                "lane": lane,
                "position": position,
                "state": if assigned { "assigned" } else { "clear" },
                "assignment_id": assigned.then_some("dev-shadow-assignment-1"),
                "work_id": assigned.then_some("dev-shadow-work-1")
            }));
        }
    }
    json!({
        "projection_version": 1,
        "snapshot_version": {
            "event_sequence": null,
            "migration_version": "dev-synthetic-v1",
            "digest": "synthetic-no-provenance"
        },
        "availability": { "status": "available", "errors": [] },
        "topology": {
            "lanes": ["tensorhost", "homelab", "personal", "control", "hands-off"],
            "expected_slots": 13,
            "observed_slots": 13,
            "observed_status": "exact"
        },
        "slots": slots,
        "worker_graph": {
            "workers": workers,
            "edges": [
                { "from": "control-1", "to": "dev-shadow-work-1", "kind": "runs" },
                { "from": "control-1", "to": "dev-shadow-transport-1", "kind": "transport" }
            ]
        },
        "queue": collection(),
        "attention": {
            "automatic_recovery": collection(),
            "delivery_attention": collection(),
            "operator_required": collection()
        },
        "metrics": {
            "token_total": { "status": "unavailable", "reason": "synthetic_dev_samples" },
            "token_rate_5m": { "status": "unavailable", "reason": "synthetic_dev_samples" }
        },
        "recent_turns": recent_turns(),
        "source_inbox": {
            "status": "available",
            "source_id": "codex",
            "runtime_status": "active",
            "active_turn_id": "dev-active-turn-1",
            "items": [
                {
                    "id": "dev-inbox-completion-1",
                    "kind": "completion_nudge",
                    "origin": "control-1",
                    "work_id": "dev-shadow-work-1",
                    "state": "queued",
                    "queued_at": "2026-09-06T00:00:00Z",
                    "reason": null
                },
                {
                    "id": "dev-inbox-message-1",
                    "kind": "message",
                    "origin": "personal-2",
                    "work_id": null,
                    "state": "delivering",
                    "queued_at": "2026-09-06T00:00:01Z",
                    "reason": null
                }
            ],
            "total": 2,
            "total_status": "exact",
            "lower_bound": 2,
            "truncated": false
        },
        "refresh": { "mode": "explicit", "polling": "disabled" }
    })
}

pub(crate) fn snapshot() -> Value {
    assert_isolated_profile();
    synthetic_snapshot()
}

pub(crate) fn watch(_after_event_sequence: i64) -> Result<Value, &'static str> {
    Err("synthetic_feed_has_no_live_events")
}

pub(crate) fn integration_status() -> Value {
    assert_isolated_profile();
    json!({
        "armed": false,
        "ready": false,
        "trust_mode": "secure",
        "backend_ready": false,
        "notifier_ready": false,
        "codex_cli": false,
        "pending_callbacks": 0,
        "queued_dispatches": 0
    })
}

pub(crate) fn llm_behaviour_status() -> Value {
    assert_isolated_profile();
    let (model, effort) = match LLM_SELECTION.load(Ordering::Relaxed) {
        0 => ("dev/muse-spark-1.3-free", "low"),
        1 => ("dev/muse-spark-1.3-free", "medium"),
        2 => ("dev/muse-spark-1.3-free", "high"),
        3 => ("dev/muse-spark-1.3-free", "max"),
        4 => ("dev/alternate-model", "low"),
        _ => ("dev/alternate-model", "medium"),
    };
    json!({
        "available": true,
        "supported_models": ["dev/muse-spark-1.3-free", "dev/alternate-model"],
        "supported_efforts_by_model": {
            "dev/muse-spark-1.3-free": ["low", "medium", "high", "max"],
            "dev/alternate-model": ["low", "medium"]
        },
        "current_model": model,
        "current_effort": effort,
        "effective_model": model,
        "effective_effort": effort
    })
}

pub(crate) fn apply_llm_behaviour(model: &str, effort: &str) -> Result<Value, &'static str> {
    assert_isolated_profile();
    let selection = match (model, effort) {
        ("dev/muse-spark-1.3-free", "low") => 0,
        ("dev/muse-spark-1.3-free", "medium") => 1,
        ("dev/muse-spark-1.3-free", "high") => 2,
        ("dev/muse-spark-1.3-free", "max") => 3,
        ("dev/alternate-model", "low") => 4,
        ("dev/alternate-model", "medium") => 5,
        _ => return Err("unsupported_dev_llm_pair"),
    };
    LLM_SELECTION.store(selection, Ordering::Relaxed);
    Ok(llm_behaviour_status())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_profile_rejects_every_live_namespace() {
        assert_isolated_profile();
    }

    #[test]
    fn synthetic_profile_has_no_attention_or_live_integration() {
        let state = snapshot();
        assert_eq!(state["availability"]["status"], "available");
        assert_eq!(state["attention"]["operator_required"]["total"], 0);
        assert_eq!(state["source_inbox"]["runtime_status"], "active");
        assert_eq!(state["source_inbox"]["total"], 2);
        assert!(state["snapshot_version"]["event_sequence"].is_null());
        assert_eq!(
            state["snapshot_version"]["digest"],
            "synthetic-no-provenance"
        );
        assert_eq!(integration_status()["armed"], false);
        assert_eq!(integration_status()["ready"], false);
        assert!(watch(1).is_err());
    }

    #[test]
    fn synthetic_llm_behaviour_is_bounded_and_non_persistent() {
        let initial = llm_behaviour_status();
        assert_eq!(initial["available"], true);
        assert!(apply_llm_behaviour("dev/alternate-model", "medium").is_ok());
        assert!(apply_llm_behaviour("dev/alternate-model", "max").is_err());
        assert!(apply_llm_behaviour("live/model", "low").is_err());
        apply_llm_behaviour("dev/muse-spark-1.3-free", "max").unwrap();
    }

    #[test]
    fn dev_bundle_config_uses_the_isolated_identity() {
        let config: Value = serde_json::from_str(include_str!("../tauri.dev.conf.json")).unwrap();
        assert_eq!(config["productName"], "Fugue Dev");
        assert_eq!(config["identifier"], APP_IDENTIFIER);
        assert_eq!(config["app"]["windows"][0]["title"], "Fugue Dev");
        assert_ne!(config["identifier"], LIVE_APP_IDENTIFIER);
    }
}
