# Child-agent topology working input

## Requested outcome

When a Fugue orchestrator delegates bounded work to child agents, the live
cockpit must show each child as a real node and the parent-to-child handoff as a
typed edge. Nodes and edges must come from durable, authoritative controller
state rather than frontend inference.

## Current boundary

The v1 cockpit snapshot exposes eleven configured worker slots and typed graph
edges. It deliberately excludes prompts, outputs, reasoning and transcripts.
The UI receives new snapshots through the blocking `cockpit.watch.v1` change
feed; no polling may be introduced.

## Required design work

Define the smallest additive controller projection for bounded child identity,
parent identity, lifecycle, state and handoff events. Specify privacy limits,
normalization, compatibility rollout, caps/truncation, deterministic tests and
the exact source files that implementation should change. Preserve one Codex
owner, existing secure-mode policy and truthful unavailable states.
