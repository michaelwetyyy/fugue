CREATE INDEX ix_local_codex_return_routes_thread_route
    ON local_codex_return_routes(thread_id, return_route_id);

CREATE INDEX ix_completion_results_work_generation
    ON completion_results(work_id, generation);
