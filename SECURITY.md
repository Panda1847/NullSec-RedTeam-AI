# Security Policy

## Supported Versions

| Version | Supported |
|---|---:|
| 7.1.x | Yes |
| 7.0.x and earlier | No |

## Reporting a Vulnerability

Please **do not open a public issue** for a suspected security vulnerability, unsafe execution path, authorization bypass, secret exposure, containment failure, or vulnerability in a bundled dependency.

Report privately through the repository’s GitHub Security Advisory reporting flow. If that flow is unavailable, contact the maintainers through the repository owner’s verified GitHub contact channel and include `SECURITY REPORT: NullSec-RedTeam-AI` in the subject.

A useful report includes a clear description, affected version or commit, safe reproduction steps, expected and observed behavior, impact assessment, and suggested remediation. Do not include live credentials, unredacted target data, or payloads that could harm third parties.

## Response Targets

Maintainers aim to acknowledge a valid report within **five business days**, provide a status update within **fourteen business days**, and coordinate a fix and disclosure timeline with the reporter. These are targets rather than contractual commitments.

## Scope

This policy covers the source repository, official releases, documentation, and reference deployment files. Third-party security tools, external model providers, operating systems, and user-operated targets are outside this policy’s direct control, although reports of unsafe integration behavior are welcome.

## Safe Testing

Only test against systems you own or are explicitly authorized to assess. Prefer isolated virtual machines and simulated environments. Never use a report to access, disrupt, degrade, or exfiltrate data from third-party systems.
