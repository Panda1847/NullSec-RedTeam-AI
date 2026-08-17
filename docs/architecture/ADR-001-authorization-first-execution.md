# ADR-001: Authorization-first execution control plane

**Status:** Accepted  
**Date:** 2026-08-17

## Context

The original prototype validated command syntax and used a shared token, but it did not model operator identity, campaign authorization, target scope, policy decisions, approval, or evidence provenance. Security-sensitive behavior therefore depended on operator judgment and README guidance rather than enforced application state.

## Decision

The platform will require a campaign context and an explicit policy decision before a job can be queued. Jobs retain immutable identifiers for campaign, task, caller, policy decision, trace, and idempotency key. Execution adapters receive typed requests rather than generic command strings. A runner marked as sandbox-required fails closed if the sandbox cannot start.

A local development mode remains available for mocked and loopback testing, but it is explicit and cannot silently substitute for a sandbox-required job.

## Consequences

This introduces additional models, validation, tests, and migration work. It reduces unsupported “quick start” paths, but makes scope enforcement, auditability, recovery, and future multi-agent orchestration possible. OAuth/OIDC and a multi-tenant policy service remain future adapters; the first implementation persists local campaign and policy state in the existing database boundary.
