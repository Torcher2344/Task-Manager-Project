"""Regression tests for run_id-aware dedup/validation pipeline behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agents.base_agent import BaseAgent
from agents.deduplicator_agent import DeduplicatorAgent
from agents.validator_agent import ValidatorAgent
from swarm import build_config


class DummyDedupAgent(DeduplicatorAgent):
    """Concrete dedup agent for unit testing."""

    async def run(self):  # pragma: no cover - not used in these tests
        return await self.run_with_findings([])


class DummyValidatorAgent(ValidatorAgent):
    """Validator agent that bypasses network reproducibility in tests."""

    async def _reproduce(self, finding):  # type: ignore[override]
        return True


def _agent_config(root_dir: Path, run_id: str) -> dict:
    """Build minimal config for test agents."""
    return {
        "root_dir": root_dir,
        "scope": [],
        "debug": False,
        "run_id": run_id,
    }


class DummyArgs:
    """Simple args object for build_config tests."""

    def __init__(self) -> None:
        self.mode = "full"
        self.platform = "h1"
        self.debug = False
        self.ctf = True
        self.no_submit = True
        self.vuln = None
        self.scope_file = None


class RunIdPipelineTests(unittest.IsolatedAsyncioTestCase):
    """Ensure pipeline gates ignore same-run persisted findings."""

    async def test_deduplicator_ignores_same_run_existing_finding(self) -> None:
        """Current run findings should not self-deduplicate."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loot = root / "loot"
            loot.mkdir(parents=True, exist_ok=True)
            notes_path = loot / "notes.json"

            same_run_finding = {
                "vuln_type": "xss",
                "endpoint": "https://target.tld/search",
                "parameter": "q",
                "run_id": "run-123",
            }
            notes_path.write_text(json.dumps([same_run_finding]), encoding="utf-8")

            agent = DummyDedupAgent(target="target.tld", config=_agent_config(root, "run-123"))
            result = await agent.run_with_findings(
                [{"vuln_type": "xss", "endpoint": "https://target.tld/search", "parameter": "q"}]
            )
            self.assertEqual(len(result["findings"]), 1)

    async def test_validator_ignores_same_run_existing_finding(self) -> None:
        """Validation dedup gate should compare only against prior runs."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loot = root / "loot"
            loot.mkdir(parents=True, exist_ok=True)
            notes_path = loot / "notes.json"

            same_run_finding = {
                "vuln_type": "idor",
                "endpoint": "https://target.tld/api/user/2",
                "parameter": "path_or_query_id",
                "run_id": "run-456",
            }
            notes_path.write_text(json.dumps([same_run_finding]), encoding="utf-8")

            finding = {
                "vuln_type": "idor",
                "severity": "high",
                "endpoint": "https://target.tld/api/user/2",
                "parameter": "path_or_query_id",
                "evidence": {"status_code": 200, "response_snippet": "ok", "request_url": "https://target.tld/api/user/2"},
            }
            agent = DummyValidatorAgent(target="target.tld", config=_agent_config(root, "run-456"))
            result = await agent.run_with_findings([finding])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["cvss_base"], 8.0)

    async def test_validator_blocks_out_of_scope_endpoint(self) -> None:
        """Scope gate should reject findings whose endpoints are not in scope."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loot = root / "loot"
            loot.mkdir(parents=True, exist_ok=True)
            (loot / "notes.json").write_text("[]", encoding="utf-8")

            finding = {
                "vuln_type": "idor",
                "severity": "high",
                "endpoint": "https://evil.example/api/user/2",
                "parameter": "path_or_query_id",
                "evidence": {"status_code": 200, "response_snippet": "ok", "request_url": "https://evil.example/api/user/2"},
            }
            config = _agent_config(root, "run-789")
            config["scope"] = ["target.tld"]
            agent = DummyValidatorAgent(target="target.tld", config=config)
            result = await agent.run_with_findings([finding])
            self.assertEqual(result["findings"], [])

    async def test_deduplicator_handles_non_list_notes_payload(self) -> None:
        """Deduplicator should not crash when notes.json contains a JSON object."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loot = root / "loot"
            loot.mkdir(parents=True, exist_ok=True)
            notes_path = loot / "notes.json"
            notes_path.write_text('{"unexpected": "shape"}', encoding="utf-8")

            agent = DummyDedupAgent(target="target.tld", config=_agent_config(root, "run-900"))
            result = await agent.run_with_findings(
                [{"vuln_type": "xss", "endpoint": "https://target.tld/search", "parameter": "q"}]
            )
            self.assertEqual(len(result["findings"]), 1)

    async def test_validator_handles_non_list_notes_payload(self) -> None:
        """Validator should not crash when notes.json contains a JSON object."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            loot = root / "loot"
            loot.mkdir(parents=True, exist_ok=True)
            notes_path = loot / "notes.json"
            notes_path.write_text('{"unexpected": "shape"}', encoding="utf-8")

            finding = {
                "vuln_type": "idor",
                "severity": "high",
                "endpoint": "https://target.tld/api/user/2",
                "parameter": "path_or_query_id",
                "evidence": {"status_code": 200, "response_snippet": "ok", "request_url": "https://target.tld/api/user/2"},
            }
            agent = DummyValidatorAgent(target="target.tld", config=_agent_config(root, "run-901"))
            result = await agent.run_with_findings([finding])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["cvss_base"], 8.0)


class RunIdConfigTests(unittest.TestCase):
    """Configuration tests for run-id generation and persistence."""

    def test_build_config_sets_non_empty_run_id(self) -> None:
        """CLI config should always include a run UUID."""
        config = build_config(DummyArgs())
        self.assertIn("run_id", config)
        self.assertTrue(str(config["run_id"]).strip())


class SessionLogPathTests(unittest.TestCase):
    """Ensure agent logs stay in a single file per instance."""

    def test_base_agent_uses_stable_session_log_path(self) -> None:
        """Multiple log calls should append to one file."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = BaseAgent(
                target="target.tld",
                config={
                    "root_dir": root,
                    "scope": [],
                    "run_id": "run-stable",
                    "debug": False,
                },
            )
            first_path = agent._session_log_file
            agent.log("first")
            second_path = agent._session_log_file
            agent.log("second")

            self.assertEqual(first_path, second_path)
            content = first_path.read_text(encoding="utf-8")
            self.assertIn("first", content)
            self.assertIn("second", content)


if __name__ == "__main__":
    unittest.main()
