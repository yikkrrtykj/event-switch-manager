"""CIS-02B2-03 architecture-independence proofs.

These tests prove that the independent parser core does not import, reuse or
call the frozen B2-02 renderer, and that only the report adapter may read the
typed renderer document read-only. They also prove the parser works when the
renderer's own validation helpers are monkeypatched to fail, so a renderer
conclusion can never decide the parser verdict.
"""

from __future__ import annotations

import ast
import importlib
import sys
import uuid
from collections.abc import Sequence
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from b203_corpus import deterministic_plan, render_plan
from test_l2_cli_candidates import full_plan

from event_switch_manager.planning import layer2_cli_grammar
from event_switch_manager.planning.layer2_cli_validation import (
    Verdict,
    validate_candidate_document,
)

PACKAGE_DIR = Path(layer2_cli_grammar.__file__).resolve().parent
PARSER_CORE: dict[str, Path] = {
    "layer2_cli_grammar": PACKAGE_DIR / "layer2_cli_grammar.py",
    "layer2_cli_lexer": PACKAGE_DIR / "layer2_cli_lexer.py",
    "layer2_cli_parser": PACKAGE_DIR / "layer2_cli_parser.py",
}
VALIDATION_MODULE = PACKAGE_DIR / "layer2_cli_validation.py"
RENDERER_MODULE = PACKAGE_DIR / "layer2_cli_candidates.py"

FORBIDDEN_MODULES: frozenset[str] = frozenset({
    "layer2_cli_candidates",
    "subprocess",
    "os",
    "importlib",
    "ctypes",
    "socket",
    "http",
    "urllib",
    "requests",
    "paramiko",
    "telnetlib",
})

FORBIDDEN_RENDERER_IDENTIFIERS: frozenset[str] = frozenset({
    "VLAN_NAME_PATTERN",
    "DESCRIPTION_PATTERN",
    "PORT_CHANNEL_NAME_PATTERN",
    "validate_parameters",
    "vlan_name_reason",
    "description_reason",
    "port_channel_name_reason",
    "interface_name_reason",
    "_rule_violation",
    "_text_policy_violations",
    "_mode_header",
    "_mode_for",
    "_single_line",
    "_GRAMMAR",
    "_build_candidate",
    "_candidate_id",
    "build_l2_cli_candidates",
    "verify_render_binding",
    "candidate_fingerprint(",
    "render_fingerprint(",
})

ALLOWED_RENDERER_IMPORTS: frozenset[str] = frozenset({
    "Candidate",
    "CandidateStatus",
    "L2CliCandidateDocument",
    "RenderDevice",
    "RiskClass",
    "SyntaxValidationLevel",
    "TargetKind",
})


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = "." * node.level + module
            modules.add(module)
    return modules


def _imported_names(tree: ast.Module, module: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def _project_module(import_name: str) -> str:
    return import_name.lstrip(".")


def _call_names(tree: ast.Module) -> set[str]:
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
    return calls


def _loaded_names(tree: ast.Module) -> set[str]:
    return {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def _attribute_names(tree: ast.Module) -> set[str]:
    return {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }


@pytest.mark.parametrize("name", sorted(PARSER_CORE))
def test_parser_core_does_not_import_the_renderer_or_process_modules(
    name: str,
) -> None:
    tree = _tree(PARSER_CORE[name])
    imports = _imports(tree)
    for forbidden in FORBIDDEN_MODULES:
        assert all(
            _project_module(module) != forbidden for module in imports
        ), (name, imports)
        assert not any(
            _project_module(module).endswith(forbidden) for module in imports
        ), (name, imports)
    assert "re" not in imports


@pytest.mark.parametrize("name", sorted(PARSER_CORE))
def test_parser_core_has_no_dynamic_execution_or_shell_calls(name: str) -> None:
    tree = _tree(PARSER_CORE[name])
    calls = _call_names(tree)
    assert calls.isdisjoint({
        "eval", "exec", "compile", "__import__", "system", "popen", "run",
        "check_output", "call", "Popen", "spawn",
    })
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"system", "popen"}
        for node in ast.walk(tree)
    )


@pytest.mark.parametrize("name", sorted(PARSER_CORE))
def test_parser_core_does_not_reference_renderer_internals(name: str) -> None:
    source = PARSER_CORE[name].read_text(encoding="utf-8")
    for identifier in FORBIDDEN_RENDERER_IDENTIFIERS:
        assert identifier not in source, (name, identifier)


def test_grammar_and_parser_share_only_the_pure_command_vocabulary() -> None:
    grammar_tree = _tree(PARSER_CORE["layer2_cli_grammar"])
    parser_tree = _tree(PARSER_CORE["layer2_cli_parser"])
    assert _imported_names(grammar_tree, "command_evidence") == {
        "CommandMode", "CommandTopic",
    }
    assert _imported_names(parser_tree, "command_evidence") == {
        "CommandMode", "CommandTopic",
    }
    lexer_tree = _tree(PARSER_CORE["layer2_cli_lexer"])
    assert not any(
        module.startswith(".") for module in _imports(lexer_tree)
    )


def test_grammar_is_an_independent_production_table_not_renderer_output() -> None:
    tree = _tree(PARSER_CORE["layer2_cli_grammar"])
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"build_l2_cli_candidates", "parse_command"}
        for node in ast.walk(tree)
    )
    form_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "GrammarForm"
    ]
    assert len(form_calls) == 22


def test_validation_adapter_imports_only_public_renderer_types() -> None:
    tree = _tree(VALIDATION_MODULE)
    imported = _imported_names(tree, "layer2_cli_candidates")
    assert imported == set(ALLOWED_RENDERER_IMPORTS)
    assert any(
        _project_module(module) == "layer2_cli_candidates"
        for module in _imports(tree)
    )


def test_validation_adapter_never_calls_renderer_validation_helpers() -> None:
    tree = _tree(VALIDATION_MODULE)
    calls = _call_names(tree)
    loaded = _loaded_names(tree)
    attributes = _attribute_names(tree)
    for identifier in FORBIDDEN_RENDERER_IDENTIFIERS:
        if identifier.endswith("("):
            continue
        assert identifier not in calls, identifier
        assert identifier not in loaded, identifier
    assert "verify_render_binding" not in attributes
    assert "validate_parameters" not in attributes


def test_renderer_and_api_do_not_import_the_b203_layer() -> None:
    renderer_imports = _imports(_tree(RENDERER_MODULE))
    new_modules = {
        ".layer2_cli_grammar", ".layer2_cli_lexer",
        ".layer2_cli_parser", ".layer2_cli_validation",
    }
    assert renderer_imports.isdisjoint(new_modules)
    plan_api = PACKAGE_DIR.parent / "plan_api.py"
    assert _imports(_tree(plan_api)).isdisjoint(new_modules)


class _RendererBlocker(MetaPathFinder):
    """Meta-path finder that makes the renderer module un-importable."""

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        if fullname.endswith("layer2_cli_candidates"):
            raise ImportError("renderer must not be imported by the parser core")
        return None


def test_parser_core_imports_without_the_renderer_module() -> None:
    names = [
        "event_switch_manager.planning.layer2_cli_grammar",
        "event_switch_manager.planning.layer2_cli_lexer",
        "event_switch_manager.planning.layer2_cli_parser",
    ]
    saved = {name: sys.modules.get(name) for name in names}
    for name in names:
        sys.modules.pop(name, None)
    blocker = _RendererBlocker()
    sys.meta_path.insert(0, blocker)
    try:
        for name in names:
            module = importlib.import_module(name)
            assert isinstance(module, ModuleType)
    finally:
        sys.meta_path.remove(blocker)
        for name in names:
            sys.modules.pop(name, None)
        for name, saved_module in saved.items():
            if saved_module is not None:
                sys.modules[name] = saved_module


def test_renderer_validation_helpers_cannot_decide_parser_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from event_switch_manager.planning import layer2_cli_candidates as renderer

    document = render_plan(deterministic_plan(full_plan(str(uuid.uuid4()), "9300")))
    baseline = validate_candidate_document(document)
    assert baseline.summary.overall_status is Verdict.PASS

    def _explode(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("renderer validation helper must not be called")

    for helper in (
        "validate_parameters",
        "vlan_name_reason",
        "description_reason",
        "port_channel_name_reason",
        "interface_name_reason",
        "_rule_violation",
        "_text_policy_violations",
        "_mode_header",
        "_mode_for",
        "_single_line",
        "candidate_fingerprint",
        "render_fingerprint",
        "evidence_fingerprint",
        "verify_render_binding",
        "build_l2_cli_candidates",
    ):
        monkeypatch.setattr(renderer, helper, _explode)

    patched = validate_candidate_document(document)
    assert patched.summary.overall_status is Verdict.PASS
    assert patched.report_fingerprint == baseline.report_fingerprint


def test_independent_parser_verdict_is_not_derived_from_candidate_text_equality() -> None:
    from event_switch_manager.planning.layer2_cli_parser import parse_command

    result = parse_command("vlan 10")
    assert result.ok
    command = result.command
    assert command is not None
    assert command.topic.value == "vlan"
    assert command.parameter("vlan-id") == 10
    # A string equality shortcut would only know the text; the structured value
    # is what the scope validator consumes.
    assert isinstance(command.parameter("vlan-id"), int)
