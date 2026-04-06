"""Business logic testing agent."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class LogicBugAgent(BaseAgent):
    """Probes non-technical flaws in business workflows and authorization logic."""

    async def _probe_negative_quantity(self, endpoint: str) -> Dict[str, Any]:
        """Test negative quantity and price manipulation controls."""
        resp = await self.request("POST", endpoint, json_body={"product_id": 1, "quantity": -5, "price": 0.01})
        vulnerable = resp.get("status") in {200, 201}
        return {
            "vuln_type": "business_logic",
            "severity": "high" if vulnerable else "info",
            "endpoint": endpoint,
            "parameter": "quantity",
            "evidence": self.build_evidence(
                response=resp,
                method="POST",
                request_url=endpoint,
                extra={"accepted_negative_quantity": vulnerable},
            ),
            "confidence": 0.72 if vulnerable else 0.2,
            "requires_human_review": vulnerable,
        }

    async def _probe_workflow_skip(self, endpoint: str) -> Dict[str, Any]:
        """Test direct transition to a privileged workflow step."""
        resp = await self.request("POST", endpoint, json_body={"step": "complete", "order_id": "123"})
        vulnerable = resp.get("status") in {200, 202}
        return {
            "vuln_type": "workflow_bypass",
            "severity": "medium" if vulnerable else "info",
            "endpoint": endpoint,
            "parameter": "step",
            "evidence": self.build_evidence(
                response=resp,
                method="POST",
                request_url=endpoint,
                extra={"workflow_skipped": vulnerable},
            ),
            "confidence": 0.66 if vulnerable else 0.2,
            "requires_human_review": vulnerable,
        }

    async def _probe_role_escalation(self, endpoint: str) -> Dict[str, Any]:
        """Test role parameter tampering for privilege escalation."""
        resp = await self.request("POST", endpoint, json_body={"role": "admin"})
        vulnerable = resp.get("status") in {200, 204}
        return {
            "vuln_type": "privilege_escalation",
            "severity": "high" if vulnerable else "info",
            "endpoint": endpoint,
            "parameter": "role",
            "evidence": self.build_evidence(
                response=resp,
                method="POST",
                request_url=endpoint,
                extra={"accepted_admin_role": vulnerable},
            ),
            "confidence": 0.75 if vulnerable else 0.18,
            "requires_human_review": vulnerable,
        }

    async def run(self) -> Dict[str, Any]:
        """Run core business logic abuse tests."""
        base = self.target if self.target.startswith("http") else f"https://{self.target}"
        tests = [
            await self._probe_negative_quantity(f"{base.rstrip('/')}/api/cart/update"),
            await self._probe_workflow_skip(f"{base.rstrip('/')}/api/checkout/transition"),
            await self._probe_role_escalation(f"{base.rstrip('/')}/api/account/update-role"),
        ]

        findings = [item for item in tests if item.get("severity") != "info"]
        for finding in findings:
            await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.76 if findings else 0.21,
            requires_human_review=any(f.get("requires_human_review") for f in findings),
        )
