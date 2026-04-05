"""Secret discovery agent for HTML, JS, and API responses."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class SecretFindAgent(BaseAgent):
    """Looks for exposed secrets with defensive confidence scoring."""

    PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "generic_api_key": re.compile(r"(?i)api[_-]?key[^A-Za-z0-9]{0,6}([A-Za-z0-9_-]{16,})"),
    }

    async def _scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Fetch one URL and run secret regex checks."""
        findings: List[Dict[str, Any]] = []
        if not self.check_scope(url):
            return findings

        resp = await self.request("GET", url)
        body = resp.get("body", "")
        for name, pattern in self.PATTERNS.items():
            for match in pattern.finditer(body):
                findings.append(
                    {
                        "vuln_type": "secret_exposure",
                        "severity": "medium",
                        "endpoint": url,
                        "parameter": name,
                        "evidence": {"match": match.group(0)[:60]},
                        "confidence": 0.7,
                        "requires_human_review": True,
                    }
                )
        return findings

    async def run(self) -> Dict[str, Any]:
        """Scan likely endpoints for accidentally exposed secrets."""
        base = self.target if self.target.startswith("http") else f"https://{self.target}"
        candidates = [base, f"{base.rstrip('/')}/robots.txt", f"{base.rstrip('/')}/.env"]

        findings: List[Dict[str, Any]] = []
        for url in candidates:
            for finding in await self._scan_url(url):
                findings.append(finding)
                await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.78 if findings else 0.2,
            requires_human_review=bool(findings),
        )
