#!/bin/bash
# SecIntel — Quick Start
# Usage: ./start.sh [port]

PORT=${1:-5000}

echo "╔══════════════════════════════════════════╗"
echo "║  SecIntel — Security Intelligence        ║"
echo "║  Team 6 Research                         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check dependencies
for pkg in flask requests feedparser apscheduler; do
    python3 -c "import ${pkg}" 2>/dev/null || {
        echo "[*] Installing missing dependency: ${pkg}"
        pip install ${pkg} --quiet
    }
done

echo "[+] Starting SecIntel on port ${PORT}..."
echo "[+] Dashboard: http://127.0.0.1:${PORT}"
echo "[+] API:       http://127.0.0.1:${PORT}/api/dashboard"
echo ""
echo "[*] Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")"
python3 app.py
