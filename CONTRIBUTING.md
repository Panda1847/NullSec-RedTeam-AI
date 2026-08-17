# Contributing to NullSec-RedTeam-AI

Thank you for improving NullSec-RedTeam-AI. This project treats authorization, containment, evidence quality, and safe defaults as product features. Contributions must improve or preserve those properties.

## Development Setup

Use Python 3.10 or newer in an isolated virtual environment. Install the development extra with `python -m pip install -e '.[dev]'`, then run `pytest`, `ruff check .`, and `mypy modules` before opening a pull request. Tests must use mocks, fixtures, local loopback services, or explicitly simulated runners; they must not invoke security tools against a live target.

## Change Design

Open an issue or discussion before proposing a large feature, a runner integration, a new tool adapter, an identity model change, or a workflow that can perform an externally visible action. Explain the user need, proposed design, alternatives, threat model, safe defaults, migration plan, and validation strategy. Record consequential architectural choices in `docs/architecture/`.

Tool integrations must use typed request models and a versioned adapter. A contribution may not add a generic shell command or pass arbitrary option strings to an execution backend. Each adapter needs a risk tier, required capability scope, bounded resource profile, deterministic test fixture, and evidence parser or documented limitation.

## Pull Requests

Keep pull requests narrowly scoped and include tests for new behavior and regressions. Describe security implications, configuration changes, and documentation updates. Never commit credentials, raw target data, vulnerability details that require coordinated disclosure, generated scans, or binary security-tool artifacts.

Maintainers will prioritize correctness, safety, testability, and documentation over tool count or feature breadth. Pull requests that reduce containment, bypass policy controls, or make unsafe behavior easier to trigger will not be accepted.

## Code Style

Use type annotations for public functions and data models, explicit exception types, structured logs, and small modules with single responsibilities. Prefer dependency injection and interfaces at external boundaries. Do not hide failed safety controls behind broad fallbacks; either use a documented safe mode or fail closed with an actionable error.

## Code of Conduct and Security Reports

Participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md). Please follow [SECURITY.md](SECURITY.md) rather than public issues for suspected vulnerabilities.
