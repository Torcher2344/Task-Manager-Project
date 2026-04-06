"""XSS testing agent for reflected/stored/DOM contexts."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode

from agents.base_agent import BaseAgent


class XSSAgent(BaseAgent):
    """Inject payload polyglots and detect reflection/execution hints."""

    PAYLOADS = [
        '"><svg/onload=alert(1337)>',
        "</script><img src=x onerror=alert(document.domain)>",
        "'--><svg/onload=confirm(1)>",
    ]

    async def _probe(self, endpoint: str, param: str, payload: str) -> Dict[str, Any]:
        """Send one XSS probe and return classification details."""
        url = f"{endpoint}?{urlencode({param: payload})}"
        resp = await self.request("GET", url)
        body = resp.get("body", "")
        reflected = payload in body
        escaped = payload.replace("<", "&lt;") in body
        dom_hint = "location.search" in body or "innerHTML" in body

        severity = "medium"
        if reflected and not escaped:
            severity = "high"
        elif dom_hint:
            severity = "medium"

        return {
            "vuln_type": "xss",
            "severity": severity,
            "endpoint": endpoint,
            "parameter": param,
            "payload": payload,
            "evidence": self.build_evidence(
                response=resp,
                method="GET",
                request_url=url,
                extra={
                    "reflected": reflected,
                    "escaped": escaped,
                    "dom_hint": dom_hint,
                },
            ),
            "confidence": 0.8 if reflected and not escaped else 0.55,
            "requires_human_review": severity == "high",
        }

    async def _probe_stored(self, endpoint: str, param: str, payload: str) -> Dict[str, Any]:
        """Attempt stored-XSS by posting payload then retrieving page."""
        submit = await self.request("POST", endpoint, data={param: payload})
        review = await self.request("GET", endpoint)
        body = review.get("body", "")
        reflected_later = payload in body
        escaped = payload.replace("<", "&lt;") in body
        suspected = submit.get("status", 0) in {200, 201, 202} and reflected_later and not escaped

        return {
            "vuln_type": "xss_stored",
            "severity": "high" if suspected else "info",
            "endpoint": endpoint,
            "parameter": param,
            "payload": payload,
            "evidence": self.build_evidence(
                response=review,
                method="POST",
                request_url=endpoint,
                extra={
                    "submit_status": submit.get("status"),
                    "review_status": review.get("status"),
                    "reflected_after_store": reflected_later,
                    "escaped": escaped,
                },
            ),
            "confidence": 0.77 if suspected else 0.2,
            "requires_human_review": suspected,
        }

    async def run(self) -> Dict[str, Any]:
        """Run reflected and DOM XSS heuristics against common endpoints."""
        base = self.target if self.target.startswith("http") else f"https://{self.target}"
        endpoints = [
            (f"{base.rstrip('/')}/search", "q"),
            (f"{base.rstrip('/')}/profile", "name"),
            (f"{base.rstrip('/')}/feedback", "message"),
        ]

        findings: List[Dict[str, Any]] = []
        for endpoint, param in endpoints:
            if not self.check_scope(endpoint):
                continue
            for payload in self.PAYLOADS:
                finding = await self._probe(endpoint, param, payload)
                if finding["evidence"]["reflected"] or finding["evidence"]["dom_hint"]:
                    findings.append(finding)
                    await self.save_finding(finding)
                stored_finding = await self._probe_stored(endpoint, param, payload)
                if stored_finding["severity"] != "info":
                    findings.append(stored_finding)
                    await self.save_finding(stored_finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.79 if findings else 0.28,
            requires_human_review=any(f.get("requires_human_review") for f in findings),
        )
