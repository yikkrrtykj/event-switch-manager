"""CIS-03-02A architecture-independence proofs."""

from __future__ import annotations

import ast
from pathlib import Path

from event_switch_manager.planning.layer3_intent import Layer3Intent

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "event_switch_manager"
MODULES = (
    PACKAGE / "planning" / "layer3_capability.py",
    PACKAGE / "planning" / "layer3_intent.py",
    PACKAGE / "layer3_api.py",
)
FORBIDDEN_MODULES = {
    "layer2_cli_candidates",
    "layer2_cli_parser",
    "layer2_cli_validation",
    "layer2_config_preview",
    "subprocess",
    "socket",
    "paramiko",
    "telnetlib",
    "os",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = "." * node.level + module
            names.add(module.lstrip("."))
    return names


def test_l3_modules_do_not_import_l2_renderer_or_device_libraries() -> None:
    for path in MODULES:
        imports = _imports(_tree(path))
        for forbidden in FORBIDDEN_MODULES:
            assert all(not item.endswith(forbidden) for item in imports), (path, imports)


def test_l3_modules_do_not_call_dynamic_execution_or_shells() -> None:
    for path in MODULES:
        tree = _tree(path)
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert calls.isdisjoint({
            "eval", "exec", "compile", "__import__", "system", "popen",
            "run", "check_output", "call", "Popen", "spawn",
        })


def test_layer3_intent_has_no_cli_or_execution_fields() -> None:
    fields = set(Layer3Intent.model_fields)
    assert {
        "commands", "command_lines", "configuration", "config", "script",
        "execution_order", "sequence", "paste_ready", "deployment_script",
    }.isdisjoint(fields)
    assert "cli" in fields
    assert "executable" in fields
    assert "device_writes_enabled" in fields
