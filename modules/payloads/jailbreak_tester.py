#!/usr/bin/env python3
"""AI Security Lab: consented evaluation contracts and transparent simulations.

The module does not claim to evaluate a provider unless an explicitly configured,
organization-approved provider adapter returns evidence. Its default mode is a
simulation suitable only for interface demonstrations and tests.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", str(Path.home() / ".local/state/nullsec/logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_DIR / "ai_lab.log")],
)
logger = logging.getLogger("ai_security_lab")

try:
    from fastmcp import FastMCP  # type: ignore[import-untyped]
except ImportError:
    try:  # Compatibility with the earlier MCP-provided FastMCP location.
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        class FastMCP:  # type: ignore[no-redef]
            """Import-safe local fallback; it never exposes a long-running dummy service."""

            def __init__(self, name: str):
                self.name = name

            def tool(self, *args, **kwargs):
                def decorator(function):
                    return function
                return decorator

            def run(self) -> None:
                raise RuntimeError("MCP support requires the fastmcp dependency")


mcp = FastMCP("AI Security Lab")


class EvaluationMode(str, Enum):
    SIMULATION = "simulation"
    PROVIDER = "provider"


class EvaluationStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    COMPLETED = "completed"
    CONFIGURATION_REQUIRED = "configuration_required"


@dataclass(frozen=True)
class EvaluationCase:
    """Versioned, non-operational test metadata for a consented evaluation suite."""

    technique_id: str
    name: str
    category: str
    severity: str
    description: str
    revision: str = "2026.08"


@dataclass(frozen=True)
class EvaluationResult:
    """Evidence-aware result that distinguishes simulation from provider execution."""

    evaluation_id: str
    mode: EvaluationMode
    status: EvaluationStatus
    model: str
    technique_id: str
    case_revision: str
    evaluated_at: str
    evidence_ref: str | None
    limitations: Sequence[str]
    summary: str
    provider_metadata: Mapping[str, str] = field(default_factory=dict)


class ProviderEvaluator(Protocol):
    """Adapter contract for an organization-approved, consented provider evaluator."""

    def evaluate(self, model: str, case: EvaluationCase, prompt: str) -> EvaluationResult:
        """Return provider-backed evidence for one approved case."""


EVALUATION_CASES: dict[str, EvaluationCase] = {
    "PROMPT_INJECTION": EvaluationCase(
        "PROMPT_INJECTION",
        "Untrusted instruction handling",
        "instruction_isolation",
        "high",
        "Checks whether a model distinguishes untrusted content from governing instructions.",
    ),
    "DATA_BOUNDARY": EvaluationCase(
        "DATA_BOUNDARY",
        "Sensitive-data boundary handling",
        "data_protection",
        "high",
        "Checks whether a model follows approved data-handling constraints in a consented test suite.",
    ),
    "ENCODING_ROBUSTNESS": EvaluationCase(
        "ENCODING_ROBUSTNESS",
        "Obfuscated-input handling",
        "input_normalization",
        "medium",
        "Checks whether a model applies policy consistently when input representation varies.",
    ),
    "ROLE_BOUNDARY": EvaluationCase(
        "ROLE_BOUNDARY",
        "Role and authority handling",
        "authorization",
        "medium",
        "Checks whether a model respects role boundaries in a controlled evaluation.",
    ),
}


def _case(technique: str) -> EvaluationCase:
    identifier = (technique or "").upper().strip()
    if identifier not in EVALUATION_CASES:
        raise ValueError(f"Unknown evaluation case '{identifier}'")
    return EVALUATION_CASES[identifier]


def _simulation_result(model: str, case: EvaluationCase) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        mode=EvaluationMode.SIMULATION,
        status=EvaluationStatus.NOT_EVALUATED,
        model=model,
        technique_id=case.technique_id,
        case_revision=case.revision,
        evaluated_at=datetime.now(timezone.utc).isoformat(),
        evidence_ref=None,
        limitations=(
            "This is a deterministic interface simulation, not a provider call.",
            "No security conclusion, score, or finding may be inferred from this record.",
        ),
        summary="Simulation created for workflow demonstration; provider behavior was not evaluated.",
    )


def run_evaluation(
    model: str,
    technique: str,
    *,
    mode: EvaluationMode = EvaluationMode.SIMULATION,
    target_prompt: str = "",
    provider: ProviderEvaluator | None = None,
) -> EvaluationResult:
    """Evaluate one consented case or return an explicit non-evaluation simulation."""
    if not isinstance(model, str) or not model.strip():
        raise ValueError("model must be a non-empty identifier")
    case = _case(technique)
    if mode is EvaluationMode.SIMULATION:
        return _simulation_result(model.strip(), case)
    if provider is None:
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            mode=EvaluationMode.PROVIDER,
            status=EvaluationStatus.CONFIGURATION_REQUIRED,
            model=model.strip(),
            technique_id=case.technique_id,
            case_revision=case.revision,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            evidence_ref=None,
            limitations=(
                "No provider adapter was configured.",
                "A provider call requires written authorization, dataset versioning, and protected credentials.",
            ),
            summary="Provider evaluation was not executed.",
        )
    return provider.evaluate(model.strip(), case, target_prompt)


def _render_result(result: EvaluationResult) -> str:
    payload = asdict(result)
    payload["mode"] = result.mode.value
    payload["status"] = result.status.value
    return json.dumps(payload, indent=2, sort_keys=True)


@mcp.tool()
def list_evaluation_cases() -> str:
    """List non-operational evaluation-case metadata and revisions."""
    return json.dumps([asdict(case) for case in EVALUATION_CASES.values()], indent=2, sort_keys=True)


@mcp.tool()
def get_evaluation_case(technique: str) -> str:
    """Return metadata for one versioned evaluation case without returning attack payloads."""
    try:
        return json.dumps(asdict(_case(technique)), indent=2, sort_keys=True)
    except ValueError as error:
        return json.dumps({"error": str(error)})


@mcp.tool()
def run_jailbreak_test(model: str, technique: str, target_prompt: str = "", mode: str = "simulation") -> str:
    """Run a transparent simulation or report that provider configuration is required."""
    try:
        evaluation_mode = EvaluationMode(mode)
        return _render_result(run_evaluation(model, technique, mode=evaluation_mode, target_prompt=target_prompt))
    except ValueError as error:
        return json.dumps({"error": str(error)})


@mcp.tool()
def scan_llm_vulnerabilities(model: str, scan_type: str = "standard") -> str:
    """Create a simulation-only scan manifest; it never reports fabricated findings."""
    if scan_type not in {"quick", "standard", "full"}:
        return json.dumps({"error": "scan_type must be quick, standard, or full"})
    selected = list(EVALUATION_CASES.values())
    if scan_type == "quick":
        selected = selected[:1]
    elif scan_type == "standard":
        selected = selected[:3]
    return json.dumps(
        {
            "mode": EvaluationMode.SIMULATION.value,
            "status": EvaluationStatus.NOT_EVALUATED.value,
            "model": model,
            "scan_type": scan_type,
            "case_revisions": [{"technique_id": case.technique_id, "revision": case.revision} for case in selected],
            "limitations": ["No provider endpoints were contacted.", "No risk findings were produced."],
        },
        indent=2,
        sort_keys=True,
    )


@mcp.tool()
def generate_test_payload(technique: str, target_topic: str = "general") -> str:
    """Return a non-operational test-plan stub rather than an executable bypass payload."""
    try:
        case = _case(technique)
        return json.dumps(
            {
                "technique_id": case.technique_id,
                "target_topic": target_topic,
                "status": "test_plan_required",
                "guidance": "Use an organization-approved, versioned test dataset in an isolated evaluation environment.",
                "limitations": "This endpoint deliberately does not generate bypass payloads.",
            },
            indent=2,
            sort_keys=True,
        )
    except ValueError as error:
        return json.dumps({"error": str(error)})


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Security Lab — transparent evaluator")
    parser.add_argument("--mcp", action="store_true", help="Run as an MCP server")
    parser.add_argument("--model", help="Model identifier")
    parser.add_argument("--technique", help="Evaluation case identifier")
    parser.add_argument("--list", action="store_true", help="List evaluation cases")
    parser.add_argument("--scan", action="store_true", help="Create a simulation scan manifest")
    parser.add_argument("--mode", choices=[item.value for item in EvaluationMode], default="simulation")
    args = parser.parse_args()
    if args.mcp:
        mcp.run()
    elif args.list:
        print(list_evaluation_cases())
    elif args.model and args.technique:
        print(run_jailbreak_test(args.model, args.technique, mode=args.mode))
    elif args.model and args.scan:
        print(scan_llm_vulnerabilities(args.model))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
