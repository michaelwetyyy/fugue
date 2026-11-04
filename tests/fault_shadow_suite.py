"""Focused deterministic milestone-nine fault/shadow acceptance suite."""

from __future__ import annotations

import unittest


_FAULT_SHADOW_CASES = (
    # Daemon/controller crash, restart, persistence, socket/process replacement.
    "tests.test_fault_shadow.FaultShadowDaemonExercises.test_hard_crash_replaces_process_and_socket_without_losing_state",
    "tests.test_fault_shadow.NestedHarnessCleanupExercises.test_status_read_failure_clears_child_before_temp_cleanup",
    "tests.test_fault_shadow.NestedHarnessCleanupExercises.test_post_readiness_failure_stops_child_before_removing_temp_root",
    "tests.test_transport_delivery.TransportDaemonTests.test_restart_reconciles_committed_send_intent_without_resend_or_pid_signal",
    "tests.test_scheduler_lanes.SchedulerDaemonTests.test_durable_success_and_failure_idempotency_survive_restart",
    "tests.test_scheduler_lanes.SchedulerDaemonTests.test_exact_topology_is_verified_and_immutable",
    # Same-database concurrency and stale lease/fence/epoch rejection.
    "tests.test_fault_shadow.SameDatabaseRestartExercises.test_concurrent_claim_then_restart_preserves_one_fenced_owner",
    "tests.test_recovery_events.RecoveryEventTests.test_new_generation_cancels_old_timer_and_rejects_late_event",
    "tests.test_recovery_events.RecoveryEventTests.test_blocked_persistent_open_is_refused_after_authority_close_starts",
    "tests.test_transport_delivery.TransportDaemonTests.test_stale_fence_policy_denial_and_slot_injection_never_send",
    # Duplicate dispatch, delivery, completion, and callback recovery.
    "tests.test_transport_delivery.TransportDaemonTests.test_duplicate_and_concurrent_dispatch_calls_disabled_adapter_once",
    "tests.test_transport_delivery.TransportDaemonTests.test_post_intent_disconnect_is_unknown_and_never_retried",
    "tests.test_completion_join.CompletionJoinTests.test_release_before_completion_joins_and_duplicate_is_exactly_once",
    "tests.test_completion_join.CompletionJoinTests.test_interrupted_delivery_becomes_terminal_unknown_exactly_once",
    # Synthetic process containment and timeout/parent-death cleanup.
    "tests.test_adapter_process.SyntheticProcessAdapterTests.test_timeout_kills_the_process_group_and_is_delivery_unknown",
    "tests.test_adapter_process.SyntheticProcessAdapterTests.test_parent_death_before_identity_persist_kills_the_entire_target_group",
    # Monotonic clock authority despite wall-clock skew, including restart epoch.
    "tests.test_recovery_events.RecoveryEventTests.test_same_epoch_wall_rollback_and_forward_do_not_fire_timer",
    "tests.test_recovery_events.RecoveryEventTests.test_restart_uses_trusted_wall_and_persisted_timer",
    # Snapshot degradation and every packaged migration restart.
    "tests.test_fault_shadow.CorruptedSnapshotExercises.test_missing_and_corrupted_sections_degrade_visibly_with_exact_topology",
    "tests.test_fault_shadow.MigrationRestartExercises.test_migrations_001_through_009_restart_cleanly_and_preserve_state",
    # Shipped boundaries remain disabled and isolated from live integrations.
    "tests.test_transport_delivery.TransportDaemonTests.test_production_endpoint_exposes_no_transport_authority_or_arming_surface",
    "tests.test_completion_join.CompletionJoinTests.test_shipped_protocol_rejects_callback_worker_mutations",
    "tests.test_source_runtime_separation.SourceRuntimeSeparationTests.test_tracked_tree_contains_no_runtime_artifacts",
)


def load_tests(
    _loader: unittest.TestLoader,
    _tests: unittest.TestSuite,
    _pattern: str | None,
) -> unittest.TestSuite:
    return unittest.defaultTestLoader.loadTestsFromNames(_FAULT_SHADOW_CASES)


if __name__ == "__main__":
    unittest.main()
