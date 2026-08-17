# Responsible Use

NullSec-RedTeam-AI is designed for **authorized security validation** in environments where the operator has clear permission to act. It is not a substitute for legal authorization, change control, professional judgment, or human accountability.

## Required Conditions

Before using any execution feature, the operator must define the authorized assets, excluded assets, approved time window, permitted techniques, rate limits, data-handling constraints, and an emergency stop contact. Every execution should be associated with a campaign record that captures this information.

Use isolated virtual machines, dedicated runners, or an approved test environment whenever possible. Do not expose the service to an untrusted network, run it with unnecessary privileges, or configure it to fall back from a required sandbox to the host system.

## Prohibited Use

Do not use this project to access, disrupt, degrade, evade controls on, or collect data from a system without explicit authorization. Do not use it to create, distribute, or operationalize malware; obtain credentials; perform denial-of-service activity; or conceal unauthorized activity.

## Operator Responsibility

The user is solely responsible for verifying authorization and complying with applicable law, contractual obligations, organizational policy, and engagement rules. Maintainers and contributors do not accept responsibility for misuse of this software. The project’s safeguards reduce risk but cannot establish authorization or make an unsafe operation appropriate.
