"""Controlled Windows live-console lab runner.

This package is isolated from the product runtime.  It is only imported by the
standalone ConsoleLab executable and tests; the product launcher never imports
it and the product serial adapter remains hard-disabled.
"""

from .authorization import (
    LAB_AUTHORIZATION_TTL_LIMIT_SECONDS,
    LabAuthorization,
    LabAuthorizationError,
    issue_authorization,
)
from .completion import LiveCompletionPolicy
from .reporting import LabBuildMetadata, LabReportWriter
from .targets import LAB_TARGETS, LabTarget, get_target

__all__ = [
    "LAB_AUTHORIZATION_TTL_LIMIT_SECONDS",
    "LAB_TARGETS",
    "LabAuthorization",
    "LabAuthorizationError",
    "LabBuildMetadata",
    "LabReportWriter",
    "LabTarget",
    "LiveCompletionPolicy",
    "get_target",
    "issue_authorization",
]
