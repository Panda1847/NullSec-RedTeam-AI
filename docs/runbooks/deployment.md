# Deployment Runbook

## Scope

This runbook covers the project’s current **single-host** deployment model. It does not establish a multi-tenant service, a public API, external identity integration, or a managed security operation. Use a non-production environment first.

## Choose an Installation Mode

Use `./install.sh --user` for development and local tests. It installs project files below the invoking user’s data directory and does not require root. Use `./install.sh --system` only after reviewing service ownership, storage paths, secrets handling, and systemd units. The installer does not download security tools, start services, or enable units automatically.

The installer is offline by default. `--allow-network` permits dependency resolution, but it does not prove artifact provenance. For production, use a vetted internal package source or verified release artifact with an approved dependency-lock strategy.

## Required Configuration Review

Before enabling a server or worker, review the following settings.

| Setting | Required posture |
|---|---|
| API binding | Loopback by default; external binding requires an approved authenticated reverse proxy and network policy |
| `API_TOKEN` | Unique secret from protected storage; never committed, printed, or included in process lists |
| `NULLSEC_LOCAL_ACTOR_ID` | Stable local operator identity for the single-host adapter |
| `NULLSEC_LOCAL_ACTOR_ROLES` | Least-privilege role set; do not add `elevated_operator` by default |
| `NULLSEC_JOB_DIR` | Worker-owned persistent directory with backup and retention plan |
| `TOOL_IMAGE` | Reviewed immutable digest, not a mutable tag |
| `NULLSEC_SANDBOX_NETWORK` | `none` unless campaign-specific review approves a constrained alternative |
| `NULLSEC_EXECUTION_MODE` | Unset in normal operation; `development` only for mocked local work |

## Readiness Review

Run the test suite before deployment. Use `guardian --report` to collect read-only diagnostic observations. Address high-severity findings through reviewed change control; Guardian intentionally does not repair hosts or start services.

Enable one component at a time. Validate the health endpoint, authenticated campaign creation, policy denial for an out-of-scope target, job idempotency, worker lease recovery, sandbox failure-closed behavior, and audit-event retention. Do not enable an MCP client until API and worker behavior are independently verified.

## Rollback

If a deployment behaves unexpectedly, stop scheduling new work, preserve logs and SQLite state, revoke the local token, and restore the previous known-good deployment artifact. Do not delete state before collecting required evidence. A rollback must be documented with the affected image digest, application version, configuration revision, and trace identifiers.
