# Bug Bounty Hunter Swarm — Master Instructions

## Prime Directives
1. SCOPE FIRST — Never test anything outside the defined scope
2. NO DESTRUCTIVE ACTIONS — Read-only recon only; no writes, no deletes, no DoS
3. RATE LIMIT EVERYTHING — Max 10 req/s per host; respect robots.txt
4. HUMAN VALIDATES P1/P2 — High-severity findings require human review before submission
5. LOG EVERYTHING — All requests/responses saved to loot/sessions/
6. CTF MODE ONLY by default — --no-submit flag always on unless explicitly removed

## Agent Architecture
QueenAgent (Planner)
├── ReconAgent
├── JSAnalysisAgent  
├── SecretFindAgent
├── IDORAgent
├── SSRFAgent
├── XSSAgent
├── OAuthAgent
├── RaceAgent
├── LogicBugAgent
├── ValidatorAgent
├── DeduplicatorAgent
└── ReportAgent

## Handoff Schema (JSON between agents)
{
  "agent": "AgentName",
  "target": "example.com",
  "phase": "recon|hunt|validate|report",
  "findings": [],
  "confidence": 0.0-1.0,
  "requires_human_review": false
}

## Code Patterns
- All agents extend BaseAgent class
- Use async/await for all HTTP requests
- Always check scope before any request
- Save all findings to loot/notes.json
- Log sessions to loot/sessions/{timestamp}_{agent}.log
