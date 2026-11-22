"""CIS-03-03B independence and frozen-contract architecture proofs."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import get_args

from event_switch_manager.planning.layer2_cli_grammar import FORMS as L2_FORMS
from event_switch_manager.planning.layer3_cli_candidates import (
    Candidate,
    L3CandidateDocument,
)
from event_switch_manager.planning.layer3_cli_validation import (
    CandidateValidation,
    L3ValidationReport,
    ValidationSafety,
)

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "event_switch_manager"
PLANNING = PACKAGE / "planning"
GRAMMAR = PLANNING / "layer3_cli_grammar.py"
PARSER = PLANNING / "layer3_cli_parser.py"
VALIDATION = PLANNING / "layer3_cli_validation.py"
NEW_MODULES = (GRAMMAR, PARSER, VALIDATION)
FORBIDDEN_MODULES = {
    "layer2_cli_candidates",
    "layer2_cli_validation",
    "subprocess",
    "socket",
    "paramiko",
    "telnetlib",
    "os",
}
ALLOWED_CANDIDATE_IMPORTS = {
    "Candidate",
    "CandidateCategory",
    "CandidateStatus",
    "L3CandidateDocument",
    "RiskClass",
}
FORBIDDEN_CALL_NAMES = {
    "eval", "exec", "compile", "__import__", "system", "popen", "run",
    "check_output", "call", "Popen", "spawn",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.extend((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = "." * node.level + module
            values.extend((module.lstrip("."), alias.name) for alias in node.names)
    return values


def _module_names(tree: ast.Module) -> set[str]:
    return {module for module, _ in _imports(tree)}


def test_grammar_has_no_renderer_evidence_or_l2_dependency() -> None:
    imports = _module_names(_tree(GRAMMAR))
    assert "layer3_cli_candidates" not in imports
    assert "layer3_command_evidence" not in imports
    assert "layer3_cli_parser" not in imports
    assert "layer3_cli_validation" not in imports
    for forbidden in FORBIDDEN_MODULES:
        assert all(not item.endswith(forbidden) for item in imports)
    assert "layer2_cli_grammar" not in imports
    assert "layer2_cli_parser" not in imports


def test_parser_only_uses_lexer_and_grammar() -> None:
    imports = _module_names(_tree(PARSER))
    assert "layer3_cli_candidates" not in imports
    assert "layer3_command_evidence" not in imports
    assert "layer3_cli_validation" not in imports
    assert "layer2_cli_parser" not in imports
    assert "layer2_cli_grammar" not in imports
    assert {"layer2_cli_lexer", "layer3_cli_grammar"} <= imports
    for forbidden in FORBIDDEN_MODULES:
        assert all(not item.endswith(forbidden) for item in imports)


def test_validator_reads_only_public_candidate_models() -> None:
    rows = _imports(_tree(VALIDATION))
    imports = {module for module, _ in rows}
    assert "layer3_cli_candidates" in imports
    assert "layer3_cli_parser" in imports
    assert "layer3_cli_grammar" in imports
    candidate_names = {
        name for module, name in rows
        if module == "layer3_cli_candidates"
    }
    assert candidate_names <= ALLOWED_CANDIDATE_IMPORTS
    assert "build_l3_cli_candidates" not in candidate_names
    assert "candidate_fingerprint" not in candidate_names
    assert "render_fingerprint" not in candidate_names
    assert "intent_fingerprint" not in candidate_names
    for forbidden in FORBIDDEN_MODULES:
        assert all(not item.endswith(forbidden) for item in imports)


def test_new_modules_have_no_dynamic_execution_or_device_calls() -> None:
    for path in NEW_MODULES:
        tree = _tree(path)
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert calls.isdisjoint(FORBIDDEN_CALL_NAMES)
        assert "subprocess" not in _module_names(tree)
        assert "socket" not in _module_names(tree)


def test_report_contract_has_no_command_sequence_or_configuration_fields() -> None:
    fields = set(L3ValidationReport.model_fields)
    assert {
        "commands", "command_lines", "configuration", "config", "script",
        "execution_order", "sequence", "candidate_text", "paste_ready",
        "deployment_script",
    }.isdisjoint(fields)
    annotation = L3ValidationReport.model_fields["candidates"].annotation
    assert annotation is not None
    args = get_args(annotation)
    assert args == (CandidateValidation, Ellipsis)
    candidate_model = CandidateValidation
    candidate_fields = set(candidate_model.model_fields)
    assert "candidate_text" not in candidate_fields
    assert "parse" in candidate_fields
    assert "evidence" in candidate_fields
    assert "independent_verdict" in candidate_fields
    assert L3ValidationReport.model_fields["validation_contract_id"].default == (
        "cis-03-03-independent-cli-validation-v1"
    )
    assert L3ValidationReport.model_fields["validation_schema_version"].default == 1


def test_candidate_contract_remains_parser_unverified_and_safety_false() -> None:
    assert "candidate_text" in Candidate.model_fields
    assert "syntax_validation" in Candidate.model_fields
    assert L3CandidateDocument.model_fields["contract_id"].default == (
        "cis-03-cisco-l3-cli-candidate-v1"
    )
    safety = ValidationSafety()
    assert safety.candidate_only is True
    assert safety.executable is False
    assert safety.deployable is False
    assert safety.deployment_allowed is False
    assert safety.hardware_verified is False
    assert safety.device_connection == "none"
    assert safety.running_config_read is False
    assert safety.device_writes_enabled is False
    assert safety.cli is None
    assert safety.deployment_artifact is None
    assert safety.deployment_authorized is False


def test_l2_grammar_keeps_twenty_two_forms() -> None:
    assert len(L2_FORMS) == 22
