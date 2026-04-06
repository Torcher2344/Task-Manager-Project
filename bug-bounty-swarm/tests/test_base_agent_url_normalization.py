"""Regression tests for BaseAgent URL normalization behavior."""

from __future__ import annotations

import unittest
from pathlib import Path

from agents.base_agent import BaseAgent


class DummyAgent(BaseAgent):
    """Minimal concrete agent for BaseAgent unit tests."""

    async def run(self):  # pragma: no cover - not used by these tests
        return self.handoff(phase="noop")


def build_agent(scope: list[str] | None = None) -> DummyAgent:
    """Construct a dummy agent with isolated temp-like config."""
    return DummyAgent(
        target="example.com",
        config={
            "root_dir": Path(__file__).resolve().parents[1],
            "scope": scope or [],
            "debug": False,
        },
    )


class BaseAgentUrlNormalizationTests(unittest.TestCase):
    """Validate URL handling and scope checks for host-only values."""

    def test_normalize_request_url_adds_https_for_host_only_values(self) -> None:
        """Host-only request targets should become valid HTTPS URLs."""
        agent = build_agent()
        self.assertEqual(
            agent._normalize_request_url("example.com/path?q=1"),
            "https://example.com/path?q=1",
        )

    def test_host_from_target_handles_urls_with_auth_and_ports(self) -> None:
        """Host extraction should ignore credentials and ports."""
        agent = build_agent()
        self.assertEqual(
            agent._host_from_target("https://user:pass@api.example.com:8443/v1"),
            "api.example.com",
        )

    def test_check_scope_accepts_host_only_candidate_against_host_scope(self) -> None:
        """Scope matching should work for host-only values."""
        agent = build_agent(scope=["example.com"])
        self.assertTrue(agent.check_scope("api.example.com/v1"))

    def test_check_scope_rejects_out_of_scope_host_only_candidate(self) -> None:
        """Scope matching should still block unrelated domains."""
        agent = build_agent(scope=["example.com"])
        self.assertFalse(agent.check_scope("evil-example.net"))


if __name__ == "__main__":
    unittest.main()
