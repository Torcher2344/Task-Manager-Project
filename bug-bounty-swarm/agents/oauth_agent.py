"""OAuth flow security testing agent."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode

from agents.base_agent import BaseAgent


class OAuthAgent(BaseAgent):
    """Tests OAuth implementation for common misconfigurations."""

    async def _test_state_missing(self, endpoint: str) -> Dict[str, Any]:
        """Check if authorization flow accepts missing state parameter."""
        if not self.check_scope(endpoint):
            return {
                "vuln_type": "oauth_misconfig",
                "severity": "info",
                "endpoint": endpoint,
                "parameter": "state",
                "evidence": self.build_evidence(
                    method="GET",
                    request_url=endpoint,
                    response_snippet="out_of_scope",
                    extra={"skipped": "out_of_scope"},
                ),
                "confidence": 0.0,
                "requires_human_review": False,
            }
        url = f"{endpoint}?{urlencode({'client_id': 'public', 'redirect_uri': 'https://example.org/cb', 'response_type': 'code'})}"
        resp = await self.request("GET", url, allow_redirects=False)
        vulnerable = resp.get("status") in {200, 302} and "state" not in resp.get("body", "").lower()
        return {
            "vuln_type": "oauth_misconfig",
            "severity": "high" if vulnerable else "info",
            "endpoint": endpoint,
            "parameter": "state",
            "evidence": self.build_evidence(
                response=resp,
                method="GET",
                request_url=url,
                extra={"state_required": not vulnerable},
            ),
            "confidence": 0.76 if vulnerable else 0.2,
            "requires_human_review": vulnerable,
        }

    async def _test_redirect_bypass(self, endpoint: str) -> Dict[str, Any]:
        """Check open redirect style bypass in redirect_uri checks."""
        if not self.check_scope(endpoint):
            return {
                "vuln_type": "oauth_redirect_uri_bypass",
                "severity": "info",
                "endpoint": endpoint,
                "parameter": "redirect_uri",
                "evidence": self.build_evidence(
                    method="GET",
                    request_url=endpoint,
                    response_snippet="out_of_scope",
                    extra={"skipped": "out_of_scope"},
                ),
                "confidence": 0.0,
                "requires_human_review": False,
            }
        bad_redirect = "https://trusted.example.com.evil.tld/callback"
        url = f"{endpoint}?{urlencode({'client_id': 'public', 'redirect_uri': bad_redirect, 'response_type': 'code', 'state': 'abc'})}"
        resp = await self.request("GET", url, allow_redirects=False)
        location = resp.get("headers", {}).get("Location", "")
        vulnerable = bad_redirect in location
        return {
            "vuln_type": "oauth_redirect_uri_bypass",
            "severity": "high" if vulnerable else "info",
            "endpoint": endpoint,
            "parameter": "redirect_uri",
            "evidence": self.build_evidence(
                response=resp,
                method="GET",
                request_url=url,
                response_snippet=location,
                extra={"location": location[:180]},
            ),
            "confidence": 0.82 if vulnerable else 0.22,
            "requires_human_review": vulnerable,
        }

    async def _test_pkce_bypass(self, token_endpoint: str) -> Dict[str, Any]:
        """Check whether token exchange works without required PKCE fields."""
        if not self.check_scope(token_endpoint):
            return {
                "vuln_type": "oauth_pkce_bypass",
                "severity": "info",
                "endpoint": token_endpoint,
                "parameter": "code_verifier",
                "evidence": self.build_evidence(
                    method="POST",
                    request_url=token_endpoint,
                    response_snippet="out_of_scope",
                    extra={"skipped": "out_of_scope"},
                ),
                "confidence": 0.0,
                "requires_human_review": False,
            }
        data = {
            "grant_type": "authorization_code",
            "code": "fake-code",
            "redirect_uri": "https://example.org/cb",
            "client_id": "public-client",
        }
        resp = await self.request("POST", token_endpoint, data=data)
        body = resp.get("body", "").lower()
        vulnerable = "access_token" in body and "code_verifier" not in body
        return {
            "vuln_type": "oauth_pkce_bypass",
            "severity": "high" if vulnerable else "info",
            "endpoint": token_endpoint,
            "parameter": "code_verifier",
            "evidence": self.build_evidence(
                response=resp,
                method="POST",
                request_url=token_endpoint,
                response_snippet=body,
                extra={"body_snippet": body[:180]},
            ),
            "confidence": 0.79 if vulnerable else 0.2,
            "requires_human_review": vulnerable,
        }

    async def _test_referrer_token_leak(self, callback_url: str) -> Dict[str, Any]:
        """Test token leakage through URL fragment or query in redirects."""
        if not self.check_scope(callback_url):
            return {
                "vuln_type": "oauth_token_leakage",
                "severity": "info",
                "endpoint": callback_url,
                "parameter": "access_token",
                "evidence": self.build_evidence(
                    method="GET",
                    request_url=callback_url,
                    response_snippet="out_of_scope",
                    extra={"skipped": "out_of_scope"},
                ),
                "confidence": 0.0,
                "requires_human_review": False,
            }
        leak_url = f"{callback_url}?{urlencode({'access_token': 'testtoken', 'token_type': 'bearer'})}"
        resp = await self.request(
            "GET",
            leak_url,
            headers={"Referer": leak_url},
            allow_redirects=False,
        )
        location = str(resp.get("headers", {}).get("Location", ""))
        body = str(resp.get("body", ""))
        leaked = "access_token=" in location or "access_token=" in body
        return {
            "vuln_type": "oauth_token_leakage",
            "severity": "high" if leaked else "info",
            "endpoint": callback_url,
            "parameter": "access_token",
            "evidence": self.build_evidence(
                response=resp,
                method="GET",
                request_url=leak_url,
                response_snippet=f"{location}\n{body}",
                extra={
                    "location_snippet": location[:180],
                    "body_snippet": body[:180],
                },
            ),
            "confidence": 0.74 if leaked else 0.2,
            "requires_human_review": leaked,
        }

    async def run(self) -> Dict[str, Any]:
        """Execute OAuth test battery against common auth endpoints."""
        discovered_urls = self.discovered_urls()
        auth_endpoint = next(
            (url for url in discovered_urls if url.lower().endswith("/bank/login.aspx")),
            discovered_urls[0],
        )
        token_endpoint = next(
            (url for url in discovered_urls if url.lower().endswith("/bank/main.aspx")),
            discovered_urls[0],
        )
        callback_endpoint = next(
            (url for url in discovered_urls if url.lower().endswith("/search.aspx")),
            discovered_urls[0],
        )

        candidates = [
            await self._test_state_missing(auth_endpoint),
            await self._test_redirect_bypass(auth_endpoint),
            await self._test_pkce_bypass(token_endpoint),
            await self._test_referrer_token_leak(callback_endpoint),
        ]

        findings = [f for f in candidates if f.get("severity") != "info"]
        for finding in findings:
            await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.8 if findings else 0.24,
            requires_human_review=any(f.get("requires_human_review") for f in findings),
        )
