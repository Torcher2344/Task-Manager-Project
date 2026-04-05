"""Base agent implementation shared by all swarm agents."""

from __future__ import annotations

import asyncio
import json
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp


class BaseAgent:
    """Common functionality for all bug bounty swarm agents."""

    _notes_lock = asyncio.Lock()

    def __init__(self, target: str, config: Dict[str, Any]) -> None:
        """Initialize the shared agent state."""
        self.target = target
        self.config = config
        self.agent_name = self.__class__.__name__
        self.root_dir = Path(config.get("root_dir", Path(__file__).resolve().parents[1]))
        self.loot_dir = self.root_dir / "loot"
        self.sessions_dir = self.loot_dir / "sessions"
        self.notes_path = self.loot_dir / "notes.json"
        self.rate_limit_per_host = float(config.get("rate_limit_per_host", 10))
        self.timeout = float(config.get("http_timeout", 30))
        self.scope = config.get("scope", [])
        self._last_request_time: Dict[str, float] = {}
        self._session: Optional[aiohttp.ClientSession] = None

        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        if not self.notes_path.exists():
            self.notes_path.write_text("[]", encoding="utf-8")

    async def __aenter__(self) -> "BaseAgent":
        """Open async HTTP session for this agent."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Close async HTTP session cleanly."""
        if self._session and not self._session.closed:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        """Expose HTTP session with safety checks."""
        if self._session is None:
            raise RuntimeError(f"{self.agent_name} session not initialized")
        return self._session

    async def run(self) -> Dict[str, Any]:
        """Execute the agent and return handoff payload."""
        raise NotImplementedError("Subclasses must implement run()")

    def _session_log_path(self) -> Path:
        """Build a timestamped session log path for the agent."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self.sessions_dir / f"{ts}_{self.agent_name}.log"

    def log(self, message: str) -> None:
        """Append a log line to the session log and print when debugging."""
        log_line = f"[{datetime.now(tz=timezone.utc).isoformat()}] {message}\n"
        with self._session_log_path().open("a", encoding="utf-8") as handle:
            handle.write(log_line)
        if self.config.get("debug"):
            print(f"[{self.agent_name}] {message}")

    def _host_from_target(self, value: str) -> str:
        """Extract host from URL-like or host-only values."""
        host = re.sub(r"^https?://", "", value.strip(), flags=re.IGNORECASE)
        return host.split("/")[0].lower()

    def check_scope(self, candidate: str) -> bool:
        """Validate target candidate against in-scope definitions."""
        if not candidate:
            return False
        if not self.scope:
            return True

        candidate_host = self._host_from_target(candidate)
        for entry in self.scope:
            allowed = self._host_from_target(str(entry))
            if candidate_host == allowed or candidate_host.endswith(f".{allowed}"):
                return True

        self.log(f"scope_block: {candidate}")
        return False

    async def rate_limit(self, host: str) -> None:
        """Apply per-host request throttling."""
        now = time.monotonic()
        min_interval = 1.0 / max(self.rate_limit_per_host, 1.0)
        previous = self._last_request_time.get(host)
        if previous is not None:
            elapsed = now - previous
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
        self._last_request_time[host] = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        allow_redirects: bool = True,
    ) -> Dict[str, Any]:
        """Send a scoped, rate-limited HTTP request and return normalized response."""
        if not self.check_scope(url):
            raise PermissionError(f"Out-of-scope request blocked: {url}")

        host = self._host_from_target(url)
        await self.rate_limit(host)

        try:
            async with self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=data,
                allow_redirects=allow_redirects,
            ) as resp:
                text = await resp.text(errors="ignore")
                payload = {
                    "url": str(resp.url),
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": text,
                    "content_length": len(text),
                }
                self.log(f"http {method.upper()} {url} -> {resp.status} len={len(text)}")
                return payload
        except Exception as exc:
            self.log(f"http_error {method.upper()} {url} :: {exc}")
            return {
                "url": url,
                "status": 0,
                "headers": {},
                "body": "",
                "content_length": 0,
                "error": str(exc),
            }

    @contextmanager
    def _file_lock(self, lock_path: Path):
        """Cross-platform advisory lock for file writes."""
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+") as lock_file:
            if __import__("os").name == "nt":
                import msvcrt

                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    async def read_findings(self) -> List[Dict[str, Any]]:
        """Read the central findings store safely."""
        async with self._notes_lock:
            lock_path = self.notes_path.with_suffix(".lock")
            with self._file_lock(lock_path):
                raw = self.notes_path.read_text(encoding="utf-8").strip() or "[]"
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    self.log("notes_json_decode_error: resetting corrupted notes file")
                    return []

    async def save_finding(self, finding: Dict[str, Any]) -> None:
        """Persist a new finding to loot/notes.json with locking."""
        normalized = {
            "agent": self.agent_name,
            "target": self.target,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            **finding,
        }

        async with self._notes_lock:
            lock_path = self.notes_path.with_suffix(".lock")
            with self._file_lock(lock_path):
                raw = self.notes_path.read_text(encoding="utf-8").strip() or "[]"
                try:
                    existing = json.loads(raw)
                    if not isinstance(existing, list):
                        existing = []
                except json.JSONDecodeError:
                    existing = []

                existing.append(normalized)
                self.notes_path.write_text(
                    json.dumps(existing, indent=2, ensure_ascii=True),
                    encoding="utf-8",
                )

        self.log(
            f"finding_saved: {normalized.get('vuln_type', 'unknown')} @ "
            f"{normalized.get('endpoint', 'n/a')}"
        )

    def handoff(
        self,
        *,
        phase: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.0,
        requires_human_review: bool = False,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build consistent handoff payload for inter-agent communication."""
        return {
            "agent": self.agent_name,
            "target": self.target,
            "phase": phase,
            "findings": findings or [],
            "confidence": max(0.0, min(1.0, confidence)),
            "requires_human_review": requires_human_review,
            "meta": meta or {},
        }
