#!/bin/bash
# Start ACS Server with Auto SN Configuration
#
# Usage:
#   ./start_server.sh              # Start with defaults
#   ./start_server.sh -v           # Verbose mode
#   ./start_server.sh --port 8080  # Custom port
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default settings
PORT="${ACS_PORT:-10302}"
HOST="${ACS_HOST:-0.0.0.0}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required"
    exit 1
fi

# Check dependencies
python3 -c "import fastapi, uvicorn, defusedxml" 2>/dev/null || {
    echo "Installing dependencies..."
    pip install -r requirements.txt
}

# Start server
echo "Starting ACS Server with Auto SN Configuration"
echo "================================================"
echo "CWMP Endpoint: http://${HOST}:${PORT}/acs"
echo "Web Dashboard: http://${HOST}:${PORT}/"
echo "================================================"

exec python3 acs_server_auto_sn.py --host "$HOST" --port "$PORT" "$@"
