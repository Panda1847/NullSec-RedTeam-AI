# Runner Hardening Runbook

## Purpose

This runbook describes the minimum review required before enabling `sandbox_required` execution. It is an operational checklist, not a command generator. The operator remains responsible for obtaining written authorization and validating the configuration in an isolated environment.

## Preconditions

Confirm that the campaign scope, allowed capability tier, operational window, rate limits, and stop contact are recorded. Confirm that the worker identity has access only to the intended job state, log, and workspace directories. The worker must not run as root.

Use a rootless container runtime where operationally feasible. Do not grant untrusted users access to a Docker daemon socket. Do not mount the host root filesystem, home directories, credentials, SSH agents, or runtime socket into a task container.

## Image and Runtime Controls

The `TOOL_IMAGE` value must be an OCI image reference pinned with an `@sha256:` digest. Record the image origin, digest, SBOM, build provenance, and approval date with the campaign or deployment record. Mutable tags such as `latest` are intentionally rejected by the worker.

The default network profile is `none`. Any network profile change must be approved as part of the campaign and must not use host networking. Configure an explicit task workspace mount. The runner applies a non-root user, read-only root filesystem, dropped capabilities, no-new-privileges, process limit, memory limit, CPU limit, temporary filesystem, and process-group cleanup.

## Validation

Before enabling an execution environment, use a disposable mock task to prove the following conditions:

| Check | Expected result |
|---|---|
| Missing container runtime | Job fails closed; no host command runs |
| Mutable image reference | Job fails validation before launch |
| Host network request | Profile creation fails before launch |
| Cancellation request | Runner terminates the sandbox process group and job becomes `cancelled` |
| Worker restart | Lease expiry recovers or fails the job according to attempt policy |
| Log review | Trace, campaign, job, and policy references are present without secrets |

## Incident Response

If containment is suspected to have failed, immediately stop worker scheduling, preserve relevant audit events and logs, revoke affected tokens, record the image digest and runtime version, and escalate through the organization’s incident-response process. Do not restart or clean up the affected environment until evidence-preservation requirements are understood.
