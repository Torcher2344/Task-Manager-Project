# /hunt Commands

## Purpose
Launch focused vulnerability hunts.

## Commands
- `/hunt-idor target=<url>`
- `/hunt-ssrf target=<url>`
- `/hunt-xss target=<url>`

## Safety
- Scope check before each request.
- Respect 10 req/s host rate limit.
- Read-only testing only.
