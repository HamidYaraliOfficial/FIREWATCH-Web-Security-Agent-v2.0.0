from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import urllib.request


@dataclass(frozen=True)
class ZAPPlan:
    target_url: str
    plan_path: str


class ZAPAdapter:
    """Small adapter boundary for OWASP ZAP Automation Framework.

    FIREWATCH does not require ZAP for the core scan. This adapter generates a
    plan and optionally checks reachability of a remote ZAP API. It does not
    execute arbitrary commands from target content.
    """

    def __init__(self, base_url: str, workdir: str = "./reports/zap"):
        self.base_url = base_url.rstrip("/")
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    def write_plan(self, target_url: str) -> ZAPPlan:
        path = self.workdir / "automation.yaml"
        body = f"""env:\n  contexts:\n    - name: FIREWATCH\n      urls:\n        - {target_url}\n      includePaths:\n        - {target_url}.*\n      excludePaths: []\n\njobs:\n  - type: passiveScan-wait\n    parameters:\n      maxDuration: 10\n"""
        path.write_text(body, encoding="utf-8")
        return ZAPPlan(target_url, str(path))

    def health(self) -> bool:
        try:
            with urllib.request.urlopen(self.base_url + "/JSON/core/view/version/", timeout=3) as resp:
                payload = json.load(resp)
                return bool(payload.get("version"))
        except Exception:
            return False
