"""Planner/orchestrator for the Bug Bounty Hunter Swarm."""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List

from agents.base_agent import BaseAgent
from agents.deduplicator_agent import DeduplicatorAgent
from agents.idor_agent import IDORAgent
from agents.js_analysis_agent import JSAnalysisAgent
from agents.logic_bug_agent import LogicBugAgent
from agents.oauth_agent import OAuthAgent
from agents.race_agent import RaceAgent
from agents.recon_agent import ReconAgent
from agents.report_agent import ReportAgent
from agents.secret_find_agent import SecretFindAgent
from agents.ssrf_agent import SSRFAgent
from agents.validator_agent import ValidatorAgent
from agents.xss_agent import XSSAgent


class QueenAgent(BaseAgent):
    """Top-level planner that coordinates recon, hunting, validation, and reporting."""

    def _selected_agents(self) -> List[type[BaseAgent]]:
        """Resolve hunter agent list by mode and vuln filters."""
        mode = self.config.get("mode", "full")
        filters = set(self.config.get("vuln_filters", []))

        if mode == "recon":
            return [ReconAgent, JSAnalysisAgent, SecretFindAgent]

        hunters: List[type[BaseAgent]] = [
            IDORAgent,
            SSRFAgent,
            XSSAgent,
            OAuthAgent,
            RaceAgent,
            LogicBugAgent,
            JSAnalysisAgent,
            SecretFindAgent,
        ]

        if not filters:
            return hunters

        mapping = {
            "idor": IDORAgent,
            "ssrf": SSRFAgent,
            "xss": XSSAgent,
            "oauth": OAuthAgent,
            "race": RaceAgent,
            "logic": LogicBugAgent,
            "js": JSAnalysisAgent,
            "secrets": SecretFindAgent,
        }
        return [mapping[key] for key in filters if key in mapping]

    async def _run_agent(self, agent_cls: type[BaseAgent]) -> Dict[str, Any]:
        """Run one agent safely and never let failures stop the swarm."""
        try:
            async with agent_cls(self.target, self.config) as agent:
                return await agent.run()
        except Exception as exc:
            self.log(f"agent_failure {agent_cls.__name__}: {exc}")
            return {
                "agent": agent_cls.__name__,
                "target": self.target,
                "phase": "error",
                "findings": [],
                "confidence": 0.0,
                "requires_human_review": False,
                "meta": {"error": str(exc)},
            }

    def _extract_discovered_urls(self, blocks: List[Dict[str, Any]]) -> List[str]:
        """Collect recon-discovered URL candidates for downstream hunt agents."""
        discovered: set[str] = set()
        for block in blocks:
            meta = block.get("meta", {})
            for url in meta.get("discovered_urls", []) if isinstance(meta, dict) else []:
                value = str(url).strip()
                if value:
                    discovered.add(value)

            findings = block.get("findings", [])
            for finding in findings if isinstance(findings, list) else []:
                evidence = finding.get("evidence", {})
                if not isinstance(evidence, dict):
                    continue
                for url in evidence.get("discovered_urls", []):
                    value = str(url).strip()
                    if value:
                        discovered.add(value)
        return sorted(discovered)

    async def _anthropic_chain_hint(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Optional Anthropic-assisted vuln chaining hints."""
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return {"chained_paths": [], "note": "Anthropic disabled: no API key"}

        try:
            from anthropic import Anthropic

            client = Anthropic(api_key=api_key)
            prompt = (
                "You are a security triage planner. Analyze these findings and suggest "
                "possible vulnerability chains in concise JSON. Findings:\n"
                f"{findings!r}"
            )
            message = client.messages.create(
                model="claude-3-5-sonnet-latest",
                max_tokens=500,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
            )
            return {"chained_paths": [], "llm_hint": str(message.content)}
        except Exception as exc:
            self.log(f"anthropic_hint_error: {exc}")
            return {"chained_paths": [], "note": f"Anthropic error: {exc}"}

    async def run(self) -> Dict[str, Any]:
        """Execute planner workflow across all swarm phases."""
        recon_results: List[Dict[str, Any]] = []
        hunt_results: List[Dict[str, Any]] = []

        if self.config.get("mode", "full") in {"recon", "full"}:
            for agent_cls in [ReconAgent, JSAnalysisAgent, SecretFindAgent]:
                recon_results.append(await self._run_agent(agent_cls))

        discovered_urls = self._extract_discovered_urls(recon_results)
        if discovered_urls:
            self.config["discovered_urls"] = discovered_urls

        if self.config.get("mode", "full") in {"hunt", "full"}:
            tasks = [self._run_agent(agent_cls) for agent_cls in self._selected_agents()]
            hunt_results = await asyncio.gather(*tasks)

        combined_findings: List[Dict[str, Any]] = []
        for block in [*recon_results, *hunt_results]:
            combined_findings.extend(block.get("findings", []))

        chain_hints = await self._anthropic_chain_hint(combined_findings)

        async with DeduplicatorAgent(self.target, self.config) as dedup_agent:
            deduped = await dedup_agent.run_with_findings(combined_findings)

        async with ValidatorAgent(self.target, self.config) as validator_agent:
            validated = await validator_agent.run_with_findings(deduped.get("findings", []))

        async with ReportAgent(self.target, self.config) as report_agent:
            report_result = await report_agent.run_with_findings(validated.get("findings", []))

        high_sev = [
            finding
            for finding in validated.get("findings", [])
            if str(finding.get("severity", "")).upper() in {"P1", "P2", "HIGH", "CRITICAL"}
        ]

        return self.handoff(
            phase="report",
            findings=validated.get("findings", []),
            confidence=0.92 if validated.get("findings") else 0.4,
            requires_human_review=bool(high_sev),
            meta={
                "recon_results": recon_results,
                "hunt_results": hunt_results,
                "deduplicated": deduped,
                "report": report_result,
                "chain_hints": chain_hints,
                "discovered_urls": discovered_urls,
                "ctf_mode": bool(self.config.get("ctf", False)),
                "no_submit": bool(self.config.get("no_submit", True)),
            },
        )
