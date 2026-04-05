"""Global settings for Bug Bounty Hunter Swarm."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parents[1]

DEFAULT_CONFIG: Dict[str, Any] = {
    "root_dir": ROOT_DIR,
    "rate_limit_per_host": 10,
    "http_timeout": 30,
    "platform": "h1",
    "mode": "full",
    "scope": [],
    "severity_thresholds": {
        "h1": {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"},
        "bugcrowd": {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"},
        "intigriti": {"critical": "High", "high": "Medium", "medium": "Low", "low": "Low"},
    },
    "platform_urls": {
        "h1": "https://hackerone.com",
        "bugcrowd": "https://bugcrowd.com",
        "intigriti": "https://app.intigriti.com",
    },
    "ctf": False,
    "no_submit": True,
    "debug": False,
    "callback_domain": "",
    "vuln_filters": [],
}
