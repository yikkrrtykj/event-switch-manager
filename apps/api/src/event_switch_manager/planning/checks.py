from .plan import EventPlan
from .validate_addressing import check_addressing
from .validate_inventory import check_inventory
from .validate_routing import check_routes, check_transit
from .validation import PlanIssue, Validation


def validate_plan(plan: EventPlan) -> tuple[PlanIssue, ...]:
    validation = Validation(plan)
    check_inventory(validation)
    check_addressing(validation)
    check_routes(validation)
    check_transit(validation)
    return tuple(validation.issues)
