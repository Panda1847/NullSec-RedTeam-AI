# Visual Asset Validation Notes

The control-plane architecture diagram was rendered from `control-plane-architecture.mmd` and reviewed on 2026-08-18. The vertical hierarchy is legible at repository-page scale, preserves the intended separation between the AURA planning lane, policy enforcement, durable job control plane, fail-closed sandbox execution, and evidence review, and is suitable for the README.

The quality-gates diagram was rendered from `quality-gates.mmd`. It is designed to accompany the contributor and release sections, explaining that tests, linting and focused type checks, static security analysis and dependency auditing, and package verification all precede maintainer review and a protected release branch.
