#!/bin/bash
# Run all unit tests with coverage report
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$PROJECT_DIR/venv/Scripts/python.exe"

cd "$PROJECT_DIR"
echo "Running tests..."
"$PYTHON" -m pytest tests/unit/ -v --cov=honeypot --cov=dashboard --cov-report=term-missing
