# Evidence and Retention Runbook

## Evidence Model

A credible finding must be traceable to a campaign, task, policy decision, tool and image version, execution time, parser or reviewer revision, and evidence reference. Model-generated prose is not evidence by itself. Clearly distinguish observed data, inference, hypothesis, and pending validation in every report.

The current job store records campaign, actor, policy decision, trace ID, idempotency key, lifecycle events, result metadata, and log path. Keep raw artifacts outside source control. Store them in an access-controlled location with a documented retention period, integrity strategy, and deletion procedure.

## Retention Controls

Set retention periods based on engagement scope, contractual requirements, organizational policy, and applicable law. Restrict access to the minimum personnel required. Redact or separate credentials, personal data, sensitive system configuration, and protected target details before copying evidence into tickets or reports.

Before pruning jobs or logs, confirm that related finding reports, incident records, and customer deliverables no longer require them. Maintain an immutable record of the decision to delete evidence and the identity of the approving owner.

## Incident Preservation

For a suspected containment failure, policy bypass, credential exposure, or unauthorized job submission, stop new work, preserve SQLite state and logs, capture relevant image digests and runtime information, and record trace/job/campaign IDs. Do not edit, rotate away, or delete the relevant artifacts until incident-response evidence requirements have been established.
