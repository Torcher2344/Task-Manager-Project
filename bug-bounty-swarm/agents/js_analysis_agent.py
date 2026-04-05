"""JavaScript analysis agent for endpoints and secret-like patterns."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from bs4 import BeautifulSoup

from agents.base_agent import BaseAgent


class JSAnalysisAgent(BaseAgent):
    """Discovers JavaScript files and extracts endpoints/keys using regexes."""

    JS_ENDPOINT_RE = re.compile(r"""(?:fetch|axios\.|XMLHttpRequest).*?['"](https?://[^'"]+|/[^'"\s]+)""")
    KEY_RE = re.compile(r"""(?i)(api[_-]?key|token|secret)['"\s:=]+([A-Za-z0-9_\-]{12,})""")

    async def _discover_js_urls(self, base_url: str) -> Set[str]:
        """Collect JavaScript file URLs from HTML script tags."""
        urls: Set[str] = set()
        if not self.check_scope(base_url):
            return urls

        resp = await self.request("GET", base_url)
        if resp.get("status", 0) <= 0:
            return urls

        soup = BeautifulSoup(resp.get("body", ""), "lxml")
        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue
            if src.startswith("http"):
                url = src
            else:
                url = f"{base_url.rstrip('/')}/{src.lstrip('/')}"
            if self.check_scope(url):
                urls.add(url)
        return urls

    def _extract_from_js(self, content: str) -> Dict[str, List[str]]:
        """Extract likely endpoints and key-like values from JS text."""
        endpoints = [m.group(1) for m in self.JS_ENDPOINT_RE.finditer(content)]
        keys = [m.group(2) for m in self.KEY_RE.finditer(content)]
        return {
            "endpoints": sorted(set(endpoints)),
            "keys": sorted(set(keys)),
        }

    async def run(self) -> Dict[str, Any]:
        """Execute JS discovery and analysis."""
        base_url = self.target if self.target.startswith("http") else f"https://{self.target}"
        js_urls = await self._discover_js_urls(base_url)
        findings: List[Dict[str, Any]] = []

        for js_url in sorted(js_urls):
            resp = await self.request("GET", js_url)
            if resp.get("status", 0) <= 0:
                continue
            extracted = self._extract_from_js(resp.get("body", ""))
            if not extracted["endpoints"] and not extracted["keys"]:
                continue

            finding = {
                "vuln_type": "js_analysis",
                "severity": "info",
                "endpoint": js_url,
                "parameter": "script",
                "evidence": extracted,
                "confidence": 0.6,
                "requires_human_review": False,
            }
            findings.append(finding)
            await self.save_finding(finding)

        return self.handoff(phase="hunt", findings=findings, confidence=0.62 if findings else 0.25)
