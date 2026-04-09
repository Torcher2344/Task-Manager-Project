"""Planner/orchestrator for the Bug Bounty Hunter Swarm."""

from __future__ import annotations

import asyncio
import json
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

try:
    from anthropic import AsyncAnthropic
except Exception:  # pragma: no cover - exercised in environments without SDK
    AsyncAnthropic = None  # type: ignore[assignment]


class QueenAgent(BaseAgent):
    """Top-level planner that coordinates recon, hunting, validation, and reporting."""
    DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"

    @staticmethod
    def _safe_float(value: Any, default: float) -> float:
        """Convert config-like value to float with fallback."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_int(value: Any, default: int) -> int:
        """Convert config-like value to int with fallback."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _resolve_anthropic_api_key(self) -> str:
        """Resolve Anthropic API key from config, .env, or process env."""
        configured = str(self.config.get("anthropic_api_key", "")).strip()
        if configured:
            return configured

        env_path = self.root_dir / "config" / ".env"
        if env_path.exists():
            try:
                from dotenv import load_dotenv

                load_dotenv(dotenv_path=env_path, override=False)
            except Exception as exc:
                self.log(f"anthropic_dotenv_load_error: {exc}")

        return str(os.getenv("ANTHROPIC_API_KEY", "")).strip()

    def _extract_anthropic_text(self, content: Any) -> str:
        """Extract human-readable text from Anthropic message content blocks."""
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            chunks: List[str] = []
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text")
                else:
                    text = getattr(block, "text", None)
                if text:
                    chunks.append(str(text))
            if chunks:
                return "\n".join(chunks).strip()
        return str(content).strip()

    def _parse_chain_hints(self, llm_text: str) -> Dict[str, Any]:
        """Parse JSON-like chain hints while tolerating plain-text responses."""
        cleaned = self.clean_json_response(llm_text)
        if not cleaned:
            return {"chained_paths": [], "llm_hint": ""}

        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError:
            return {"chained_paths": [], "llm_hint": llm_text}

        if isinstance(payload, dict):
            chains = payload.get("chained_paths", [])
            if not isinstance(chains, list):
                chains = []
            result: Dict[str, Any] = {"chained_paths": chains}
            note = payload.get("note")
            if note:
                result["note"] = str(note)
            llm_hint = payload.get("llm_hint", "")
            if llm_hint:
                result["llm_hint"] = str(llm_hint)
            return result

        return {"chained_paths": [], "llm_hint": llm_text}

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

    async def _anthropic_chain_hint(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Optional Anthropic-assisted vuln chaining hints."""
        api_key = self._resolve_anthropic_api_key()
        if not api_key:
            return {"chained_paths": [], "note": "Anthropic disabled: no API key"}

        if AsyncAnthropic is None:
            self.log("anthropic_sdk_unavailable: import failed")
            return {"chained_paths": [], "note": "Anthropic disabled: SDK unavailable"}

        client = AsyncAnthropic(
            api_key=api_key,
            timeout=self._safe_float(self.config.get("anthropic_timeout", 20), 20.0),
            max_retries=max(0, self._safe_int(self.config.get("anthropic_max_retries", 1), 1)),
        )
        try:
            prompt = (
                "You are a security triage planner. Analyze these findings and suggest "
                "possible vulnerability chains in concise JSON. Findings:\n"
                f"{findings!r}"
            )
            message = await client.messages.create(
                model=str(self.config.get("anthropic_model", self.DEFAULT_ANTHROPIC_MODEL)),
                max_tokens=500,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
            )
            llm_text = self._extract_anthropic_text(getattr(message, "content", ""))
            parsed = self._parse_chain_hints(llm_text)
            if not parsed.get("llm_hint"):
                parsed["llm_hint"] = llm_text
            return parsed
        except Exception as exc:
            self.log(f"anthropic_hint_error: {exc.__class__.__name__}: {exc}")
            return {"chained_paths": [], "note": f"Anthropic connection error: {exc}"}
        finally:
            try:
                await client.close()
            except Exception:
                pass

    async def run(self) -> Dict[str, Any]:
        """Execute planner workflow across all swarm phases."""
        recon_results: List[Dict[str, Any]] = []
        hunt_results: List[Dict[str, Any]] = []

        if self.config.get("mode", "full") in {"recon", "full"}:
            for agent_cls in [ReconAgent, JSAnalysisAgent, SecretFindAgent]:
                recon_results.append(await self._run_agent(agent_cls))

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
                "ctf_mode": bool(self.config.get("ctf", False)),
                "no_submit": bool(self.config.get("no_submit", True)),
            },
        )
