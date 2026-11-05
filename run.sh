#!/usr/bin/env bash
# WordPress Security Scanner - launcher
# Usage: ./run.sh   (or: bash run.sh)

set -e

# Navigate to the project directory (works from anywhere, handles spaces in path)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON=""

# Prefer the project virtualenv if it exists
if [ -x "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
    # Expose bundled shared libraries (e.g. libxcb-cursor for Qt on older distros)
    if [ -d "venv/lib" ]; then
        export LD_LIBRARY_PATH="$SCRIPT_DIR/venv/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
elif [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
    if [ -d ".venv/lib" ]; then
        export LD_LIBRARY_PATH="$SCRIPT_DIR/.venv/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
else
    PYTHON="$(command -v python3 || command -v python)"
fi

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3 not found. Install python3 first." >&2
    exit 1
fi

# Auto-install dependencies if the venv exists but is missing packages
if [ -x "venv/bin/python" ]; then
    if ! venv/bin/python -c "import PySide6, requests, aiohttp" 2>/dev/null; then
        echo "Installing dependencies into venv ..."
        venv/bin/python -m pip install --upgrade pip
        venv/bin/python -m pip install -r requirements.txt
    fi
fi

exec "$PYTHON" src/main.py "$@"