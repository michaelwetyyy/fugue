# Callback delivery attention

This document is PUBLIC and contains no runtime identifiers or private data.

## Problem

A completed worker result and its callback delivery are different facts. A
callback process can fail or return an ambiguous outcome after the durable
result has already been committed. Presenting that condition as “operator
required” implies the work itself needs a decision even when only transport
delivery needs reconciliation.

## Required behavior

- Durable worker completion remains authoritative and readable by result
  reference regardless of callback state.
- Recovery incidents and actions that genuinely require a person remain under
  `operator_required`.
- Callback/outbox states `attention` or a missing local route appear under a
  separate `delivery_attention` collection with a non-operator visual state.
- The collection exposes only stable identifiers, typed state and a bounded
  privacy-safe reason. It never exposes callback messages or result content.
- A non-zero Codex child exit records its numeric exit status as a bounded
  diagnostic reason. Raw standard error is never persisted.
- A zero exit from the local `codex queue` command proves only that Codex
  accepted the message into its queue. Activity therefore records
  `callback.queued_for_codex`; it must not claim that the destination task
  rendered or consumed the message. The internal callback transport may be
  terminal even though this stronger destination fact remains unproved.
- Ambiguous deliveries are never retried automatically. The explicit
  `callback.delivery.reconcile.v1` operation performs no send. It reconstructs
  the exact original callback from Fugue's durable state and asks the pinned
  local Codex adapter for positive proof. The proof is accepted only when
  owner-controlled Codex `thread_history_1.sqlite` contains exactly one
  `userMessage` on the bound thread whose sole text part equals the reconstructed
  callback byte-for-byte, including the original random delivery key, and that
  item is the first user item of a started turn. Ordinary later thread activity,
  a human assertion, or a delivery-key substring alone is not proof.
- Positive reconciliation preserves the original delivery key and attempt, adds
  one immutable `callback_delivery_reconciliations` record, moves only the exact
  `delivery_unknown` attention attempt/callback/outbox to delivered, and consumes
  its ready route. The resulting `delivered` state still means only that Codex
  accepted/recorded the callback message; it does not claim the destination model
  rendered or consumed it.
- If the proof is absent, ambiguous, malformed, or its local file/executable
  identity changed, reconciliation leaves delivery attention unchanged and never
  retries the callback.
- Projection and rendering remain read-only. They never repair callback state.

## Validation

Tests must distinguish recovery attention from delivery attention, preserve
exact collection totals through normalization and rendering, and prove that a
non-zero exit code is recorded without stderr or message content.
