#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-$(pwd)}"
echo "[setup] Initializing Bug Bounty Swarm on Linux/macOS"
cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
  python -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [ ! -f "config/.env" ]; then
  cp config/.env.example config/.env
  echo "[setup] Created config/.env from template"
fi

mkdir -p loot loot/sessions reports tools knowledge recon
echo "[setup] Done. Activate with source .venv/bin/activate"
