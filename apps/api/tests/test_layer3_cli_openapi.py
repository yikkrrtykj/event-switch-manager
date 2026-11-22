"""CIS-03-03C OpenAPI namespace isolation and Python type stability."""

from __future__ import annotations

import json
import os
import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any

from event_switch_manager.app import create_app
from event_switch_manager.settings import Settings

API_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = API_ROOT / "src"
CANDIDATE_PATH = (
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}"
    "/assignments/{assignment_id}/l3-cli-candidates"
)
VALIDATION_PATH = (
    "/api/v1/events/{event_id}/plan-revisions/{revision_id}"
    "/assignments/{assignment_id}/l3-cli-validation"
)


def _app_schema(tmp_path: Path) -> dict[str, Any]:
    app = create_app(Settings(database_path=tmp_path / "r42-openapi.sqlite3"))
    return app.openapi()


def test_importing_app_does_not_mutate_frozen_type_metadata() -> None:
    script = r"""
import json
import pickle
from event_switch_manager.planning.layer3_cli_candidates import (
    Candidate,
    CandidateStatus,
    RenderBindingError,
)
from event_switch_manager.planning.layer3_cli_validation import (
    CandidateValidation,
    IndependentVerdict,
    ValidationSafety,
)

items = [
    Candidate,
    CandidateStatus,
    RenderBindingError,
    ValidationSafety,
    IndependentVerdict,
    CandidateValidation,
]
before = {
    item.__name__: {
        "name": item.__name__,
        "qualname": item.__qualname__,
        "module": item.__module__,
    }
    for item in items
}
import event_switch_manager.app  # noqa: F401
after = {
    item.__name__: {
        "name": item.__name__,
        "qualname": item.__qualname__,
        "module": item.__module__,
    }
    for item in items
}
assert before == after, (before, after)
instances = [
    CandidateStatus.CANDIDATE,
    RenderBindingError("r42-pickle"),
    ValidationSafety(),
    IndependentVerdict.PASS,
]
for instance in instances:
    restored = pickle.loads(pickle.dumps(instance))
    assert type(restored) is type(instance)
print(json.dumps({"ok": True, "before": before}))
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SOURCE_ROOT)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=API_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["before"]["Candidate"]["qualname"] == "Candidate"
    assert payload["before"]["ValidationSafety"]["qualname"] == "ValidationSafety"


def test_openapi_components_and_refs_are_isolated_and_resolvable(
    tmp_path: Path,
) -> None:
    schema = _app_schema(tmp_path)
    components = schema["components"]["schemas"]
    assert "ValidationReport" in components
    assert "ValidationSafety" in components
    assert "ExpectedSource" not in components
    assert "Candidate" in components
    assert "CandidateValidation" in components
    assert "CandidateCategory" in components
    assert "SourceBinding" in components
    assert "SyntaxValidation" in components
    assert not any(
        key.startswith("event_switch_manager__planning__layer3_")
        for key in components
    )
    assert "L3CandidateDocument" in components
    assert "L3ValidationReport" in components
    for path, model in (
        (CANDIDATE_PATH, "L3CandidateDocument"),
        (VALIDATION_PATH, "L3ValidationReport"),
    ):
        operation = schema["paths"][path]["get"]
        assert operation["responses"]["200"]["content"]["application/json"][
            "schema"
        ] == {"$ref": f"#/components/schemas/{model}"}
        assert set(schema["paths"][path]) == {"get"}
        parameters = operation.get("parameters", [])
        assert [(item["name"], item["in"]) for item in parameters] == [
            ("event_id", "path"),
            ("revision_id", "path"),
            ("assignment_id", "path"),
        ]

    refs: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str):
                    refs.append(item)
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(schema)
    local_refs = [
        ref for ref in refs if ref.startswith("#/components/schemas/")
    ]
    assert local_refs
    for ref in local_refs:
        target = ref.removeprefix("#/components/schemas/")
        assert target in components, ref
    assert len(components) == len(set(components))


def test_openapi_generation_is_stable_and_idempotent(tmp_path: Path) -> None:
    app = create_app(Settings(database_path=tmp_path / "r42-stable.sqlite3"))
    first = app.openapi()
    second = app.openapi()
    assert first == second
    assert app.openapi_schema == first
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_l3_model_and_enum_pickle_roundtrip_after_app_import() -> None:
    from event_switch_manager.planning.layer3_cli_candidates import (
        Candidate,
        CandidateStatus,
        RenderBindingError,
    )
    from event_switch_manager.planning.layer3_cli_validation import (
        CandidateValidation,
        IndependentVerdict,
        ValidationSafety,
    )

    objects = (
        CandidateStatus.CANDIDATE,
        RenderBindingError("r42-pickle"),
        ValidationSafety(),
        IndependentVerdict.PASS,
    )
    for obj in objects:
        restored = pickle.loads(pickle.dumps(obj))
        assert type(restored) is type(obj)
    assert Candidate.__name__ == "Candidate"
    assert CandidateValidation.__name__ == "CandidateValidation"
