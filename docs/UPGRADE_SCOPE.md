# Discovery — NullSec-RedTeam-AI Defensive Modernization

## Requirements

The upgrade will convert the reviewed prototype into a safer and more maintainable **MCP-governed security execution platform**. The implementation will establish repository governance and CI, correct product claims, harden execution boundaries, introduce durable job state and audit records, and add the foundations for typed AURA workflow handoffs.

The work will preserve a local, single-host development mode while making privileged or containment-sensitive behavior explicit. Changes will be implemented in the isolated worktree at `/home/ubuntu/nullsec_upgrade` and validated with mocked, local tests only.

## Exclusions

No security tooling will be installed or invoked against a network, host, or third-party service. The upgrade will not include credentials, OAuth provider setup, a live LLM provider integration, or an externally reachable deployment. Those operations need an organization-specific identity provider, secrets-management choice, and written authorization model.

A full distributed scheduler, web frontend, and multi-tenant authorization service are intentionally deferred. The code will instead expose typed, testable contracts that allow those components to be added without replacing the core execution model.

## Success criteria

- The repository contains an explicit license, security disclosure policy, contribution path, code of conduct, issue/PR templates, responsible-use statement, architecture documentation, and CI workflow.
- The core execution service has strict deployment configuration, constant-time shared-secret verification, campaign-scoped policy validation, audit events, idempotent submission, durable state transitions, leases, heartbeats, cancellation, and requeue controls.
- A sandbox-required job never falls back to local execution; local execution is development-only and explicit.
- Tool requests use typed command specifications for the initial safe adapters rather than generic free-form command strings.
- The AI Security Lab labels deterministic output as simulation, persists no fabricated claim as real evidence, and exposes an extensible provider/evaluator interface.
- Typed plan, policy, execution, and evidence events form the first bounded AURA workflow layer; only approved execution requests can reach the job queue.
- Unit and integration-style tests pass without running security tools, and the project’s command-line/test configuration is repeatable.

## Minimal implementation

The first implementation slice will affect Python service modules, tests, packaging, CI, governance, installer documentation, and public project documentation. Existing users retain a local development path through an explicit `NULLSEC_EXECUTION_MODE=development` configuration, while deployment defaults are fail-closed.

## Alternative considered

Replacing the entire prototype with a distributed service mesh or a new web application was rejected. It would delay the security controls that the existing queue and MCP boundary require, and would not be proportionate to the present codebase.

## Root-cause framing

The most consequential issues share a common root: product-critical policies currently exist as README prose, installation-side configuration, and ad hoc validation rather than as enforced domain state. The upgrade therefore moves policy, identity context, task state, and evidence into explicit models and verifies them at the API, queue, and runner boundaries.
