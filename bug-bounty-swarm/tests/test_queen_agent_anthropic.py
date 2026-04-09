"""Unit tests for QueenAgent Anthropic integration behavior."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.queen_agent import QueenAgent


def _build_agent(root_dir: Path, *, extra_config: dict | None = None) -> QueenAgent:
    """Create a QueenAgent with isolated config for Anthropic tests."""
    config = {
        "root_dir": root_dir,
        "scope": [],
        "debug": False,
        "mode": "recon",
    }
    if extra_config:
        config.update(extra_config)
    return QueenAgent(target="example.com", config=config)


class QueenAgentAnthropicTests(unittest.IsolatedAsyncioTestCase):
    """Verify key-loading and response parsing for Anthropic hinting."""

    async def test_resolves_api_key_from_config_env_file(self) -> None:
        """Anthropic key should load from config/.env when env var is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / ".env").write_text("ANTHROPIC_API_KEY=from-dotenv\n", encoding="utf-8")

            prior = os.environ.pop("ANTHROPIC_API_KEY", None)
            try:
                agent = _build_agent(root)
                self.assertEqual(agent._resolve_anthropic_api_key(), "from-dotenv")
            finally:
                if prior is not None:
                    os.environ["ANTHROPIC_API_KEY"] = prior
                else:
                    os.environ.pop("ANTHROPIC_API_KEY", None)

    async def test_prefers_config_key_over_environment(self) -> None:
        """Explicit config key should win over process environment value."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.environ["ANTHROPIC_API_KEY"] = "from-env"
            agent = _build_agent(root, extra_config={"anthropic_api_key": "from-config"})
            self.assertEqual(agent._resolve_anthropic_api_key(), "from-config")

    async def test_chain_hint_uses_async_client_and_extracts_text(self) -> None:
        """Chain hint call should await AsyncAnthropic and preserve text output."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = _build_agent(root, extra_config={"anthropic_api_key": "test-key"})

            class _FakeBlock:
                def __init__(self, text: str) -> None:
                    self.text = text

            class _FakeMessage:
                def __init__(self) -> None:
                    self.content = [_FakeBlock('{"chained_paths": ["a->b"]}')]

            class _FakeMessages:
                async def create(self, **_: object) -> _FakeMessage:
                    return _FakeMessage()

            class _FakeClient:
                def __init__(self, **_: object) -> None:
                    self.messages = _FakeMessages()

                async def close(self) -> None:
                    return None

            with patch("agents.queen_agent.AsyncAnthropic", _FakeClient):
                result = await agent._anthropic_chain_hint([{"vuln_type": "xss"}])

            self.assertEqual(result.get("chained_paths"), ["a->b"])
            self.assertIn("llm_hint", result)

    async def test_chain_hint_handles_connection_error(self) -> None:
        """Connection failures should not crash swarm orchestration."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = _build_agent(root, extra_config={"anthropic_api_key": "test-key"})

            class _FakeMessages:
                async def create(self, **_: object) -> object:
                    raise RuntimeError("network down")

            class _FakeClient:
                def __init__(self, **_: object) -> None:
                    self.messages = _FakeMessages()

                async def close(self) -> None:
                    return None

            with patch("agents.queen_agent.AsyncAnthropic", _FakeClient):
                result = await agent._anthropic_chain_hint([{"vuln_type": "ssrf"}])

            self.assertEqual(result.get("chained_paths"), [])
            self.assertIn("connection error", str(result.get("note", "")).lower())

    async def test_chain_hint_handles_missing_api_key_gracefully(self) -> None:
        """Missing API key should return empty chains with explanatory note."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = _build_agent(root)
            prior = os.environ.pop("ANTHROPIC_API_KEY", None)
            try:
                result = await agent._anthropic_chain_hint([{"vuln_type": "idor"}])
            finally:
                if prior is not None:
                    os.environ["ANTHROPIC_API_KEY"] = prior
                else:
                    os.environ.pop("ANTHROPIC_API_KEY", None)

            self.assertEqual(result.get("chained_paths"), [])
            self.assertIn("no api key", str(result.get("note", "")).lower())

    async def test_chain_hint_uses_expected_anthropic_call_format(self) -> None:
        """Anthropic call should use configured model and expected payload keys."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = _build_agent(root, extra_config={"anthropic_api_key": "test-key"})
            captured: dict[str, object] = {}

            class _FakeMessage:
                def __init__(self) -> None:
                    self.content = [{"type": "text", "text": '{"chained_paths": []}'}]

            class _FakeMessages:
                async def create(self, **kwargs: object) -> _FakeMessage:
                    captured.update(kwargs)
                    return _FakeMessage()

            class _FakeClient:
                def __init__(self, **_: object) -> None:
                    self.messages = _FakeMessages()

                async def close(self) -> None:
                    return None

            with patch("agents.queen_agent.AsyncAnthropic", _FakeClient):
                _ = await agent._anthropic_chain_hint([{"vuln_type": "xss", "endpoint": "/search"}])

            self.assertEqual(captured.get("model"), QueenAgent.DEFAULT_ANTHROPIC_MODEL)
            self.assertEqual(captured.get("max_tokens"), 500)
            self.assertEqual(captured.get("temperature"), 0)
            self.assertIsInstance(captured.get("messages"), list)
            self.assertTrue(captured.get("messages"))


if __name__ == "__main__":
    unittest.main()
