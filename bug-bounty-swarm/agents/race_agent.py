"""Race condition agent using concurrent request bursts."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class RaceAgent(BaseAgent):
    """Detects race conditions in critical state-changing endpoints."""

    async def _burst(self, method: str, url: str, body: Dict[str, Any], count: int = 8) -> List[Dict[str, Any]]:
        """Execute a burst of concurrent requests."""
        tasks = [self.request(method, url, json_body=body) for _ in range(count)]
        return await asyncio.gather(*tasks)

    def _analyze(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze response set for inconsistent state behavior."""
        statuses = [r.get("status", 0) for r in responses]
        bodies = [r.get("body", "") for r in responses]
        unique_statuses = set(statuses)
        unique_bodies = len(set(bodies))
        suspect = len(unique_statuses) > 1 or unique_bodies > 2
        return {
            "suspect": suspect,
            "statuses": statuses,
            "unique_body_count": unique_bodies,
        }

    async def run(self) -> Dict[str, Any]:
        """Run race probes on coupon, transfer, and voting endpoints."""
        base = self.target if self.target.startswith("http") else f"https://{self.target}"
        probes = [
            ("POST", f"{base.rstrip('/')}/api/coupon/redeem", {"coupon": "WELCOME100"}),
            ("POST", f"{base.rstrip('/')}/api/wallet/transfer", {"to": "attacker", "amount": 1}),
            ("POST", f"{base.rstrip('/')}/api/vote", {"poll_id": 1, "option": "A"}),
        ]

        findings: List[Dict[str, Any]] = []
        for method, url, body in probes:
            if not self.check_scope(url):
                continue
            responses = await self._burst(method, url, body)
            analysis = self._analyze(responses)
            if not analysis["suspect"]:
                continue
            first_resp = responses[0] if responses else {}
            finding = {
                "vuln_type": "race_condition",
                "severity": "high",
                "endpoint": url,
                "parameter": "concurrency",
                "evidence": self.build_evidence(
                    response=first_resp,
                    method=method,
                    request_url=url,
                    extra=analysis,
                ),
                "confidence": 0.74,
                "requires_human_review": True,
            }
            findings.append(finding)
            await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.73 if findings else 0.22,
            requires_human_review=bool(findings),
        )
