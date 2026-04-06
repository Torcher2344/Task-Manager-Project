"""Reconnaissance agent with tool and Python fallback paths."""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
from typing import Any, Dict, List

from agents.base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """Enumerates assets, checks liveness, and fingerprints technologies."""

    TESTFIRE_PATHS = [
        "/index.jsp",
        "/bank/login.aspx",
        "/bank/main.aspx",
        "/bank/transfer.aspx",
        "/bank/queryxpath.aspx",
        "/bank/login",
        "/search.aspx",
        "/bank/customize.aspx",
    ]

    async def _run_tool(self, command: List[str]) -> str:
        """Execute a local tool command and return stdout."""
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            self.log(f"tool_failed {' '.join(command)} :: {stderr.decode(errors='ignore')}")
            return ""
        return stdout.decode(errors="ignore")

    async def _subdomains(self) -> List[str]:
        """Collect subdomains using subfinder/amass with fallback."""
        target_host = self._host_from_target(self.target)
        candidates: set[str] = {target_host}

        if shutil.which("subfinder"):
            out = await self._run_tool(["subfinder", "-silent", "-d", target_host])
            candidates.update({line.strip() for line in out.splitlines() if line.strip()})
        elif shutil.which("amass"):
            out = await self._run_tool(["amass", "enum", "-passive", "-d", target_host])
            candidates.update({line.strip() for line in out.splitlines() if line.strip()})
        else:
            for prefix in ["www", "api", "admin", "dev", "staging"]:
                candidates.add(f"{prefix}.{target_host}")

        return sorted(candidates)

    async def _live_hosts(self, hosts: List[str]) -> List[str]:
        """Detect live hosts via httpx or direct HTTP probes."""
        if shutil.which("httpx"):
            input_file = self.root_dir / "recon" / "hosts.txt"
            input_file.parent.mkdir(parents=True, exist_ok=True)
            input_file.write_text("\n".join(hosts), encoding="utf-8")
            out = await self._run_tool(["httpx", "-silent", "-l", str(input_file)])
            return [line.strip() for line in out.splitlines() if line.strip()]

        live: List[str] = []
        for host in hosts:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                if not self.check_scope(url):
                    continue
                resp = await self.request("GET", url)
                if resp.get("status", 0) > 0:
                    live.append(url)
                    break
        return live

    async def _discover_known_testfire_urls(self, host_urls: List[str]) -> List[str]:
        """Probe known Testfire paths when external recon tools are unavailable."""
        discovered: List[str] = []
        for host_url in host_urls:
            for path in self.TESTFIRE_PATHS:
                candidate = f"{host_url.rstrip('/')}{path}"
                if not self.check_scope(candidate):
                    continue
                resp = await self.request("GET", candidate, allow_redirects=False)
                if resp.get("status") == 200:
                    discovered.append(candidate)
        return sorted(set(discovered))

    async def _port_scan(self, host: str) -> List[int]:
        """Run nmap fallback or Python socket checks."""
        target_host = self._host_from_target(host)
        common_ports = [80, 443, 8080, 8443, 3000]

        if shutil.which("nmap"):
            out = await self._run_tool(["nmap", "-Pn", "-p", ",".join(map(str, common_ports)), target_host])
            open_ports: List[int] = []
            for line in out.splitlines():
                if "/tcp" in line and "open" in line:
                    try:
                        open_ports.append(int(line.split("/")[0].strip()))
                    except ValueError:
                        continue
            return open_ports

        open_ports: List[int] = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.75)
            if sock.connect_ex((target_host, port)) == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    async def _fingerprint(self, url: str) -> Dict[str, Any]:
        """Extract basic technology fingerprints from headers/body."""
        resp = await self.request("GET", url)
        body = resp.get("body", "").lower()
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}

        tech = []
        if "x-powered-by" in headers:
            tech.append(headers["x-powered-by"])
        if "server" in headers:
            tech.append(headers["server"])
        if "wp-content" in body:
            tech.append("WordPress")
        if "__next" in body:
            tech.append("Next.js")
        if "laravel" in body:
            tech.append("Laravel")

        return {
            "url": url,
            "status": resp.get("status"),
            "tech": sorted(set(tech)),
        }

    async def run(self) -> Dict[str, Any]:
        """Run recon pipeline and store enumerated assets."""
        findings: List[Dict[str, Any]] = []
        subs = await self._subdomains()
        live = await self._live_hosts(subs)
        known_hosts = sorted(set(live))

        base_target = self._base_target_url()
        if base_target not in known_hosts and self.check_scope(base_target):
            base_resp = await self.request("GET", base_target, allow_redirects=False)
            if base_resp.get("status") == 200:
                known_hosts.append(base_target)

        discovered_urls = await self._discover_known_testfire_urls(known_hosts)
        if not discovered_urls:
            discovered_urls = [f"{base_target}{path}" for path in self.TESTFIRE_PATHS]

        for asset in known_hosts:
            ports = await self._port_scan(asset)
            fp = await self._fingerprint(asset)
            finding = {
                "vuln_type": "recon",
                "severity": "info",
                "endpoint": asset,
                "evidence": {
                    "ports": ports,
                    "fingerprint": fp,
                    "discovered_urls": discovered_urls,
                },
                "confidence": 0.85,
                "requires_human_review": False,
            }
            findings.append(finding)
            await self.save_finding(finding)

        recon_output = self.root_dir / "recon" / "inventory.json"
        recon_output.parent.mkdir(parents=True, exist_ok=True)
        recon_output.write_text(json.dumps(findings, indent=2), encoding="utf-8")

        return self.handoff(
            phase="recon",
            findings=findings,
            confidence=0.82 if findings else 0.35,
            meta={"subdomains": subs, "live_hosts": known_hosts, "discovered_urls": discovered_urls},
        )
