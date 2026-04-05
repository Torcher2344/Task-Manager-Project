# Bug Bounty Hunter Swarm

A multi-agent AI system for identifying and validating bug bounty opportunities with a **Planner → Workers → Judges** architecture and mandatory HITL for high-severity findings.

## Architecture

```text
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
```

## Quick Start (Windows / PowerShell)

```powershell
cd bug-bounty-swarm
.\scripts\setup.ps1
.\.venv\Scripts\Activate.ps1
python swarm.py --target https://example.com --mode full --platform h1 --ctf --no-submit --debug
```

Optional tooling install:

```powershell
.\scripts\install_tools.ps1
```

## Quick Start (Linux/macOS)

```bash
cd bug-bounty-swarm
bash scripts/setup.sh
source .venv/bin/activate
python swarm.py --target https://example.com --mode full --platform h1 --ctf --no-submit --debug
```

Optional tooling install:

```bash
bash scripts/install_tools.sh
```

## Usage Examples

### Full swarm run
```bash
python swarm.py --target https://target.tld --mode full --platform h1 --ctf --no-submit
```

### Recon only
```bash
python swarm.py --target target.tld --mode recon --scope-file scope.txt
```

### Focus only on IDOR + SSRF
```bash
python swarm.py --target https://target.tld --mode hunt --vuln idor --vuln ssrf --platform bugcrowd
```

## CLI Options

- `--target` (required): target domain or URL
- `--mode`: `recon`, `hunt`, or `full`
- `--platform`: `h1`, `bugcrowd`, `intigriti`
- `--vuln`: filter vuln classes (`idor`, `ssrf`, `xss`, `oauth`, `race`, `logic`, `secrets`, `js`)
- `--ctf`: enable safe CTF mode defaults
- `--no-submit`: keep auto-submission disabled
- `--debug`: verbose runtime logging
- `--scope-file`: scope file path (`.txt` or `.json`)

## Data Layout

- Findings store: `loot/notes.json`
- Session logs: `loot/sessions/{timestamp}_{agent}.log`
- Reports: `reports/report_<platform>.md`
- Recon output: `recon/inventory.json`

## Legal Disclaimer

This framework is for **authorized security testing only**. You are responsible for ensuring written permission and compliance with target program policies, laws, and platform rules. The default mode is safety-first (`--no-submit`) and high-severity findings require human validation before submission.
