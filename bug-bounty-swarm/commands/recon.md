# /recon Command

## Purpose
Run read-only reconnaissance pipeline and generate `recon/inventory.json`.

## Usage
`/recon target=<domain_or_url> scope=<scope_file_optional>`

## Steps
1. Confirm scope.
2. Enumerate subdomains.
3. Probe live hosts.
4. Fingerprint stack and exposed services.
5. Save notes to `loot/notes.json`.
