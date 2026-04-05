"""Deduplication agent for candidate findings."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from agents.base_agent import BaseAgent


class DeduplicatorAgent(BaseAgent):
    """Flags duplicates by vulnerability class, endpoint, and parameter."""

    def _key(self, finding: Dict[str, Any]) -> Tuple[str, str, str]:
        """Build dedup key for a finding."""
        return (
            str(finding.get("vuln_type", "")).lower(),
            str(finding.get("endpoint", "")).lower(),
            str(finding.get("parameter", "")).lower(),
        )

    async def run_with_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Return only unique findings compared to prior notes and current batch."""
        existing = await self.read_findings()
        seen: Set[Tuple[str, str, str]] = {self._key(item) for item in existing}
        deduped: List[Dict[str, Any]] = []
        duplicates: List[Dict[str, Any]] = []

        for finding in findings:
            key = self._key(finding)
            if key in seen:
                duplicates.append(finding)
                continue
            seen.add(key)
            deduped.append(finding)

        return self.handoff(
            phase="validate",
            findings=deduped,
            confidence=0.95,
            meta={
                "input_count": len(findings),
                "deduped_count": len(deduped),
                "duplicate_count": len(duplicates),
            },
        )

    async def run(self) -> Dict[str, Any]:
        """Deduplicate findings already present in notes store."""
        findings = await self.read_findings()
        return await self.run_with_findings(findings)
