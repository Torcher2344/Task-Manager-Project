"""Validation agent implementing the 4-gate triage pipeline."""

from __future__ import annotations

from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class ValidatorAgent(BaseAgent):
    """Validates findings for reproducibility, scope, deduplication, and severity."""

    CVSS_BASE = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 6.0,
        "low": 3.5,
        "info": 0.0,
        "p1": 9.7,
        "p2": 8.2,
        "p3": 6.4,
        "p4": 3.4,
    }

    def _normalize_existing_findings(self, raw_findings: Any) -> List[Dict[str, Any]]:
        """Coerce persisted notes into a safe list[dict] structure."""
        if not isinstance(raw_findings, list):
            self.log(f"validator_notes_unexpected_type: {type(raw_findings).__name__}")
            return []

        normalized: List[Dict[str, Any]] = []
        dropped = 0
        for item in raw_findings:
            if isinstance(item, dict):
                normalized.append(item)
            else:
                dropped += 1

        if dropped:
            self.log(f"validator_notes_invalid_entries_dropped: {dropped}")
        return normalized

    async def _reproduce(self, finding: Dict[str, Any]) -> bool:
        """Gate 1: ensure PoC succeeds consistently (3/3)."""
        endpoint = finding.get("endpoint")
        if not endpoint or not self.check_scope(str(endpoint)):
            return False

        success = 0
        for _ in range(3):
            resp = await self.request("GET", str(endpoint))
            if resp.get("status", 0) > 0:
                success += 1
        return success == 3

    def _scope_gate(self, finding: Dict[str, Any]) -> bool:
        """Gate 2: enforce in-scope endpoint requirement."""
        endpoint = str(finding.get("endpoint", ""))
        return self.check_scope(endpoint)

    async def _dedup_gate(self, finding: Dict[str, Any], existing: List[Dict[str, Any]]) -> bool:
        """Gate 3: reject findings that match prior vuln+endpoint+parameter tuple."""
        key = (
            finding.get("vuln_type", ""),
            finding.get("endpoint", ""),
            finding.get("parameter", ""),
        )
        for prev in existing:
            prev_key = (prev.get("vuln_type", ""), prev.get("endpoint", ""), prev.get("parameter", ""))
            if key == prev_key:
                return False
        return True

    def _cvss_gate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Gate 4: attach CVSS base score based on severity mapping."""
        severity = str(finding.get("severity", "info")).lower()
        score = self.CVSS_BASE.get(severity, 0.0)
        finding["cvss_base"] = score
        finding["validated_severity"] = severity
        return finding

    async def run_with_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate provided findings through all gates."""
        validated: List[Dict[str, Any]] = []
        existing = self._normalize_existing_findings(await self.read_findings())
        if self.run_id:
            prior = [item for item in existing if str(item.get("run_id", "")) != self.run_id]
        else:
            prior = existing

        for finding in findings:
            if not await self._reproduce(finding):
                continue
            if not self._scope_gate(finding):
                continue
            if not await self._dedup_gate(finding, prior):
                continue
            enriched = self._cvss_gate(dict(finding))
            validated.append(enriched)

        return self.handoff(
            phase="validate",
            findings=validated,
            confidence=0.9 if validated else 0.3,
            requires_human_review=any(
                f.get("validated_severity") in {"critical", "high", "p1", "p2"} for f in validated
            ),
            meta={
                "gates": [
                    "reproducibility_3_of_3",
                    "scope_confirmation",
                    "deduplication",
                    "cvss_scoring",
                ],
                "prior_findings_considered": len(prior),
            },
        )

    async def run(self) -> Dict[str, Any]:
        """Validate findings currently stored in loot/notes.json."""
        findings = await self.read_findings()
        return await self.run_with_findings(findings)
