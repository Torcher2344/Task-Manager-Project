"""Main CLI entrypoint for Bug Bounty Hunter Swarm."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict

from config.settings import DEFAULT_CONFIG


def clean_json_response(raw: str) -> str:
    """Strip markdown code fences before JSON parsing."""
    cleaned = str(raw or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", cleaned, count=1)
        cleaned = re.sub(r"\s*```$", "", cleaned, count=1)
    return cleaned.strip()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the swarm runner."""
    parser = argparse.ArgumentParser(description="Bug Bounty Hunter Swarm")
    parser.add_argument("--target", required=True, help="Target domain or URL")
    parser.add_argument(
        "--mode",
        default="full",
        choices=["recon", "hunt", "full"],
        help="Execution mode",
    )
    parser.add_argument(
        "--platform",
        default="h1",
        choices=["h1", "bugcrowd", "intigriti"],
        help="Bug bounty platform output profile",
    )
    parser.add_argument(
        "--vuln",
        action="append",
        choices=["idor", "ssrf", "xss", "oauth", "race", "logic", "secrets", "js"],
        help="Run only specific vuln classes (can be repeated)",
    )
    parser.add_argument(
        "--ctf",
        action="store_true",
        help="Enable CTF mode; no submissions and safe testing defaults",
    )
    parser.add_argument(
        "--no-submit",
        action="store_true",
        default=True,
        help="Never auto-submit findings (default: enabled)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--scope-file",
        type=Path,
        help="Path to scope definition file (.txt/.json)",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Dict[str, Any]:
    """Build runtime config from defaults and CLI flags."""
    # Warn if Anthropic API key is not configured
    if not os.getenv("ANTHROPIC_API_KEY", ""):
        print(
            "[WARN][swarm] ANTHROPIC_API_KEY is not set. "
            "LLM-assisted vulnerability chaining will be disabled. "
            "Set the env var or add anthropic_api_key to config to enable it.",
            file=sys.stderr,
        )
    config: Dict[str, Any] = dict(DEFAULT_CONFIG)
    config["run_id"] = str(uuid.uuid4())
    config["mode"] = args.mode
    config["platform"] = args.platform
    config["debug"] = bool(args.debug)
    config["ctf"] = bool(args.ctf)
    config["no_submit"] = True if args.no_submit else bool(DEFAULT_CONFIG["no_submit"])
    config["vuln_filters"] = args.vuln or []

    if args.scope_file:
        if not args.scope_file.exists():
            raise FileNotFoundError(f"Scope file not found: {args.scope_file}")
        raw = args.scope_file.read_text(encoding="utf-8").strip()
        if args.scope_file.suffix.lower() == ".json":
            config["scope"] = json.loads(clean_json_response(raw))
        else:
            config["scope"] = [line.strip() for line in raw.splitlines() if line.strip()]

    return config


async def run_swarm(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the swarm orchestration flow."""
    from agents.queen_agent import QueenAgent

    queen = QueenAgent(target=target, config=config)
    return await queen.run()


def main() -> int:
    """CLI main wrapper."""
    args = parse_args()

    try:
        config = build_config(args)
        result = asyncio.run(run_swarm(args.target, config))
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"[FAIL][swarm] fatal error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
