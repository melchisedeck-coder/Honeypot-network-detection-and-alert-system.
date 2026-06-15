#!/bin/bash
# Stop the honeypot system — kills all Python processes in the venv
echo "Stopping honeypot processes..."
taskkill //F //IM python.exe 2>/dev/null || pkill -f "run.py"
echo "Stopped."
