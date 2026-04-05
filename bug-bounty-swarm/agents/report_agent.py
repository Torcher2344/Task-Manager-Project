"""Platform-specific report generation agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    """Creates markdown reports tailored for common bounty platforms."""

    PLATFORM_HEADERS = {
        "h1": "# HackerOne Report",
        "bugcrowd": "# Bugcrowd Submission",
        "intigriti": "# Intigriti Report",
    }

    def _title(self, finding: Dict[str, Any]) -> str:
        """Apply required title formula for report entries."""
        vuln = str(finding.get("vuln_type", "UNKNOWN")).upper()
        impact = str(finding.get("severity", "IMPACT")).upper()
        component = str(finding.get("endpoint", "component")).split("?")[0]
        return f"[{vuln}] [{impact}] in [{component}]"

    def _section(self, finding: Dict[str, Any]) -> str:
        """Render one finding into markdown."""
        evidence = finding.get("evidence", {})
        steps = finding.get("repro_steps", [])
        steps_md = "\n".join(f"1. {step}" for step in steps) if steps else "1. Reproduce with provided payload"
        return (
            f"## {self._title(finding)}\n\n"
            f"- Severity: **{finding.get('severity', 'unknown')}**\n"
            f"- CVSS Base: **{finding.get('cvss_base', 'n/a')}**\n"
            f"- Endpoint: `{finding.get('endpoint', 'n/a')}`\n"
            f"- Parameter: `{finding.get('parameter', 'n/a')}`\n"
            f"- Payload: `{finding.get('payload', 'n/a')}`\n\n"
            f"### Evidence\n\n```\n{evidence}\n```\n\n"
            f"### Steps to Reproduce\n\n{steps_md}\n\n"
            "### Impact\n\n"
            "The issue may allow unauthorized actions, data exposure, or workflow compromise depending on execution context.\n"
        )

    def _build_report(self, findings: List[Dict[str, Any]]) -> str:
        """Build full markdown report body."""
        platform = self.config.get("platform", "h1")
        header = self.PLATFORM_HEADERS.get(platform, "# Bug Bounty Report")
        disclaimer = (
            "> Generated in CTF/read-only mode. High-severity findings require human validation before submission.\n\n"
        )
        if not findings:
            return f"{header}\n\n{disclaimer}No validated findings were produced.\n"

        sections = [self._section(finding) for finding in findings]
        return f"{header}\n\n{disclaimer}" + "\n\n---\n\n".join(sections)

    async def run_with_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate and store report markdown from validated findings."""
        reports_dir = self.root_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        platform = self.config.get("platform", "h1")
        output = reports_dir / f"report_{platform}.md"

        report = self._build_report(findings)
        output.write_text(report, encoding="utf-8")

        return self.handoff(
            phase="report",
            findings=findings,
            confidence=0.97,
            requires_human_review=any(
                str(finding.get("severity", "")).lower() in {"critical", "high", "p1", "p2"}
                for finding in findings
            ),
            meta={"report_path": str(output)},
        )

    async def run(self) -> Dict[str, Any]:
        """Generate report from notes store findings."""
        findings = await self.read_findings()
        return await self.run_with_findings(findings)
