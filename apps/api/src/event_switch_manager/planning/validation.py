from __future__ import annotations

from collections.abc import Callable, Iterable
from itertools import combinations
from typing import TYPE_CHECKING, Literal, TypeVar

from .types import Record

if TYPE_CHECKING:
    from .plan import EventPlan

T = TypeVar("T")
K = TypeVar("K")


class PlanIssue(Record):
    path: str
    code: str
    message: str
    severity: Literal["ERROR", "WARNING"] = "ERROR"


class Validation:
    def __init__(self, plan: EventPlan) -> None:
        self.plan = plan
        self.issues: list[PlanIssue] = []

    def error(self, path: str, code: str, message: str) -> None:
        self.issues.append(PlanIssue(path=path, code=code, message=message))

    def warning(self, path: str, code: str, message: str) -> None:
        self.issues.append(PlanIssue(path=path, code=code, message=message, severity="WARNING"))

    def index(self, path: str, records: Iterable[T], key: Callable[[T], K]) -> dict[K, T]:
        result: dict[K, T] = {}
        for i, record in enumerate(records):
            value = key(record)
            if value in result:
                self.error(f"{path}.{i}", "duplicate", f"Duplicate value {value}")
            result[value] = record
        return result

    def require(self, condition: object, path: str, code: str, message: str) -> None:
        if not condition:
            self.error(path, code, message)


def pairs(count: int) -> Iterable[tuple[int, int]]:
    return combinations(range(count), 2)
