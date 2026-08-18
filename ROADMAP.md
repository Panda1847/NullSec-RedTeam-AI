# Roadmap

## Direction

NullSec-RedTeam-AI is being developed as an **authorization-first execution control plane**, not a tool launcher or an autonomous engagement platform. Milestones are ordered by the controls needed to make the next capability trustworthy.

| Milestone | Objective | Completion evidence |
|---|---|---|
| **7.1 — Control-plane foundation** | Establish campaign policy, durable jobs, fail-closed runner contracts, bounded AURA workflow, and repository quality gates. | Implemented in the current release worktree with focused tests, linting, type checks, security checks, and package build verification. |
| **7.2 — Deployment assurance** | Publish a reviewed rootless runner profile, signed immutable image process, and deployment configuration validator. | A documented image provenance flow, sandbox integration tests, and a repeatable operator readiness checklist. |
| **7.3 — Identity and policy services** | Replace the local actor adapter with a deployment-specific identity integration and persistent approval records. | Least-privilege role mapping, expiration, revocation tests, and auditable approval state. |
| **7.4 — Evidence operations** | Add managed evidence storage, retention policy enforcement, integrity metadata, and finding/report schemas. | Controlled retention tests, access controls, and traceable evidence-to-report links. |
| **7.5 — Bounded provider evaluation** | Add consented AI-provider adapters and versioned evaluation datasets behind policy and evidence controls. | Provider adapters that record dataset version, authorization, limitations, and evidence—not synthetic findings. |
| **8.0 — Operated platform readiness** | Evaluate distributed work queues, multi-operator governance, release signing, and supportability. | Design review, threat model, migration plan, and operational ownership before any production claim. |

## Contribution Opportunities

The most useful contributions are small, testable, and security-relevant. Good candidates include policy unit tests, runner profile validation, non-sensitive documentation examples, package/release automation, evidence parser contracts, and accessibility or clarity improvements to the docs.

The project does not currently accept features that bypass campaign policy, create arbitrary host shell execution, use unbounded target or option inputs, generate live-target test traffic in automated checks, or present simulated AI-evaluation output as a verified finding.

## How We Prioritize

A proposed change is prioritized when it improves authorization, containment, evidence quality, reliability, interoperability, or contributor safety without weakening an earlier control. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a proposal, and use the issue templates to include a safety case and validation plan.
