#!/bin/bash
# Start the full honeypot system (Windows: run from Git Bash)

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$PROJECT_DIR/venv/Scripts/python.exe"

echo "=============================================="
echo "  KIU Honeypot System — Starting"
echo "  Dashboard : http://localhost:5000"
echo "  Login     : admin / Admin@2026!"
echo "=============================================="

cd "$PROJECT_DIR"
"$PYTHON" run.py
