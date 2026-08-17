# Credential Rotation Runbook

## Scope

The current local adapter authenticates API requests with a bearer token sourced from `API_TOKEN` or a protected system token file. This is a transitional single-host mechanism. It does not replace an organization’s identity provider, short-lived credential policy, or secrets-management system.

## Rotation Procedure

First pause new submissions and let authorized in-flight work reach a documented terminal state, unless incident response requires immediate shutdown. Record the change window, campaign impact, responsible operator, and rollback point. Generate a new high-entropy token through an approved secrets-management process and restrict read access to the server or approved service identity.

Update the server configuration, restart only the server component through approved change control, and verify that the old token is rejected while the new token works. Update dependent MCP or local client configuration through protected secret injection; never paste the token into issues, documentation examples, shell history, process arguments, screenshots, or build logs. Resume scheduling only after an authenticated campaign creation and policy-denial check succeeds.

## Suspected Exposure

Treat a suspected token exposure as a security event. Revoke the token promptly, stop accepting new requests until the replacement configuration is verified, preserve relevant access logs and trace identifiers, and assess whether submitted jobs or audit records require further investigation. Report repository-secret exposure through the process in `SECURITY.md`.

## Logging Rule

Tokens, authorization headers, raw provider credentials, and unredacted sensitive evidence must never be written to application logs or audit event details. Errors should include a trace identifier and a stable reason code, not credential material.
