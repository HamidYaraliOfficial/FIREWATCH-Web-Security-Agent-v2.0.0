# Extending FIREWATCH v2

## Add a deterministic check

Create a module under `backend/app/checks/` and return `FindingCandidate` objects from a function that accepts a `PageSnapshot` and context. Register the function in `checks/registry.py` when it should run for every discovered page.

Example:

```python
from app.models import Severity
from app.checks.base import FindingCandidate

def run_example(page, context):
    if "needle" not in page.observation.body:
        return []
    return [FindingCandidate(
        rule_id="FW-CUSTOM-001",
        category="custom",
        title="Example observation",
        severity=Severity.LOW,
        confidence=0.90,
        endpoint=page.url,
        description="...",
        impact="...",
        remediation="...",
        evidence_summary="The expected marker was observed.",
        evidence={"marker":"needle"},
    )]
```

Keep checks deterministic, bounded, scope-aware and honest about confidence. Never silently add destructive requests.

## Add a discovery phase

Prefer a dedicated module such as `api_discovery.py`, then call it from `ScanOrchestrator`. Persist discovered objects through the `Asset` model rather than hiding them inside findings.

## Add an LLM planner

Use the `PlannerProtocol` boundary for future reasoning. The planner should produce structured, constrained decisions only. Request execution must continue to pass through `ScopePolicy`, the safe HTTP client and explicit policy controls.
