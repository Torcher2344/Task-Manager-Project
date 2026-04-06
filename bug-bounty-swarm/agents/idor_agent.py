"""IDOR testing agent with full async mutation strategies."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents.base_agent import BaseAgent


class IDORAgent(BaseAgent):
    """Tests object-level authorization weaknesses across common ID vectors."""

    ID_RE = re.compile(r"(?P<id>\b\d{1,10}\b)")
    UUID_RE = re.compile(
        r"(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})"
    )

    async def _baseline(self, url: str) -> Dict[str, Any]:
        """Collect baseline response characteristics for a candidate endpoint."""
        return await self.request("GET", url)

    def _mutate_numeric_ids(self, value: str) -> List[str]:
        """Generate numeric ID mutations (enum and edge values)."""
        values: set[str] = set()
        for match in self.ID_RE.finditer(value):
            raw = match.group("id")
            try:
                number = int(raw)
            except ValueError:
                continue
            for delta in (-5, -1, 1, 2, 10, 100):
                cand = number + delta
                if cand > 0:
                    values.add(value.replace(raw, str(cand), 1))
            values.add(value.replace(raw, "1", 1))
            values.add(value.replace(raw, "999999", 1))
        return sorted(values)

    def _mutate_uuid(self, value: str) -> List[str]:
        """Generate UUID prediction mutations by tweaking segments."""
        mutations: set[str] = set()
        for match in self.UUID_RE.finditer(value):
            uuid = match.group("uuid")
            parts = uuid.split("-")
            if len(parts) != 5:
                continue
            tail = parts[-1]
            for suffix in ("0", "1", "a", "f"):
                mutated_tail = (tail[:-1] + suffix) if len(tail) > 1 else tail
                mutated = "-".join([parts[0], parts[1], parts[2], parts[3], mutated_tail])
                mutations.add(value.replace(uuid, mutated, 1))
            mutations.add(value.replace(uuid, "00000000-0000-4000-8000-000000000001", 1))
        return sorted(mutations)

    def _pollute_params(self, url: str) -> List[str]:
        """Create parameter pollution permutations for object identifiers."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return []

        polluted: List[str] = []
        for key, values in qs.items():
            for value in values:
                if not (self.ID_RE.search(value) or self.UUID_RE.search(value)):
                    continue

                variants = self._mutate_numeric_ids(value) + self._mutate_uuid(value)
                for variant in variants[:8]:
                    expanded = dict(qs)
                    expanded[key] = [value, variant]
                    query = urlencode(expanded, doseq=True)
                    polluted.append(urlunparse(parsed._replace(query=query)))
        return polluted

    def _derive_candidates(self, base_url: str) -> List[str]:
        """Derive IDOR candidate URLs from path/query segments."""
        candidates: set[str] = {base_url}
        parsed = urlparse(base_url)

        path_variants = self._mutate_numeric_ids(parsed.path) + self._mutate_uuid(parsed.path)
        for path in path_variants:
            candidates.add(urlunparse(parsed._replace(path=path)))

        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        if query_dict:
            for key, values in query_dict.items():
                for value in values:
                    for variant in self._mutate_numeric_ids(value) + self._mutate_uuid(value):
                        q = dict(query_dict)
                        q[key] = [variant]
                        candidates.add(urlunparse(parsed._replace(query=urlencode(q, doseq=True))))

        candidates.update(self._pollute_params(base_url))
        return sorted(candidates)

    def _interesting_diff(self, baseline: Dict[str, Any], probe: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Compare baseline and probe response to detect authorization anomalies."""
        b_status = baseline.get("status", 0)
        p_status = probe.get("status", 0)
        b_len = baseline.get("content_length", 0)
        p_len = probe.get("content_length", 0)

        status_changed = b_status != p_status
        len_delta = abs(p_len - b_len)
        similarity_hint = 0.0
        if max(b_len, p_len) > 0:
            similarity_hint = 1 - (len_delta / max(b_len, p_len))

        signals = {
            "baseline_status": b_status,
            "probe_status": p_status,
            "baseline_length": b_len,
            "probe_length": p_len,
            "length_delta": len_delta,
            "body_similarity_hint": round(similarity_hint, 4),
        }

        if p_status in {200, 201} and b_status in {401, 403, 404}:
            return True, {**signals, "reason": "Unauthorized baseline became authorized"}
        if p_status == b_status == 200 and len_delta > max(60, int(0.1 * max(b_len, 1))):
            return True, {**signals, "reason": "Same status but materially different object response"}
        if status_changed and p_status in {200, 302}:
            return True, {**signals, "reason": "Status changed to potentially authorized response"}
        return False, signals

    async def _test_candidate(self, baseline_url: str, candidate_url: str) -> Optional[Dict[str, Any]]:
        """Run one mutated IDOR probe against baseline URL."""
        if not self.check_scope(candidate_url):
            return None

        baseline = await self._baseline(baseline_url)
        probe = await self.request("GET", candidate_url, allow_redirects=False)
        hit, evidence = self._interesting_diff(baseline, probe)
        if not hit:
            return None

        severity = "high" if evidence.get("probe_status") == 200 else "medium"
        finding = {
            "vuln_type": "idor",
            "severity": severity,
            "endpoint": baseline_url,
            "parameter": "path_or_query_id",
            "payload": candidate_url,
            "evidence": self.build_evidence(
                response=probe,
                method="GET",
                request_url=candidate_url,
                extra=evidence,
            ),
            "confidence": 0.82 if severity == "high" else 0.68,
            "requires_human_review": severity == "high",
            "repro_steps": [
                f"GET baseline: {baseline_url}",
                f"GET mutated: {candidate_url}",
                "Compare HTTP status and body length differences",
            ],
        }
        return finding

    async def run(self) -> Dict[str, Any]:
        """Run IDOR checks over curated endpoint seeds and mutations."""
        seeds = self.discovered_urls()

        findings: List[Dict[str, Any]] = []
        for seed in seeds:
            if not self.check_scope(seed):
                continue
            candidates = self._derive_candidates(seed)
            for candidate in candidates[:35]:
                finding = await self._test_candidate(seed, candidate)
                if finding is None:
                    continue
                findings.append(finding)
                await self.save_finding(finding)

        return self.handoff(
            phase="hunt",
            findings=findings,
            confidence=0.88 if findings else 0.32,
            requires_human_review=any(f.get("requires_human_review") for f in findings),
            meta={"tested_seeds": seeds, "tested_mutations_per_seed": 35},
        )
