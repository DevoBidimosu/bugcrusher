#!/usr/bin/env bash
# start.sh — bugcrusher: browser (left 3/4) | Django dev server (top-right 1/4) | test runner (bottom-right 1/4)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate venv if not already active
if [[ -z "$VIRTUAL_ENV" ]] && [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

ACTIVATE="source \"$SCRIPT_DIR/venv/bin/activate\" 2>/dev/null"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Dependency check ──────────────────────────────────────────────────────────
if [ ! -d "$SCRIPT_DIR/venv" ] && [ ! -d "$SCRIPT_DIR/.venv" ]; then
    echo -e "${YELLOW}⚠️  No venv found. Run ./expand.sh first.${NC}"
    exit 1
fi

if ! command -v wmctrl &>/dev/null; then
    echo "◆ Installing wmctrl..."
    sudo apt-get install -y wmctrl -qq
fi

# Screen size
SCREEN_W=$(xdpyinfo 2>/dev/null | awk '/dimensions/{print $2}' | cut -dx -f1)
SCREEN_H=$(xdpyinfo 2>/dev/null | awk '/dimensions/{print $2}' | cut -dx -f2)
SCREEN_W=${SCREEN_W:-1920}
SCREEN_H=${SCREEN_H:-1080}

# Layout math
MAIN_W=$(( SCREEN_W * 3 / 4 ))  # left 3/4  — browser
QTR_W=$(( SCREEN_W / 4 ))        # right 1/4 — terminals
HALF_H=$(( SCREEN_H / 2 ))       # top/bottom split on right

echo "◆ Starting bugcrusher...  (${SCREEN_W}x${SCREEN_H})"
echo "  Browser  → left 3/4     (0,0  ${MAIN_W}x${SCREEN_H})"
echo "  Server   → top-right    (${MAIN_W},0  ${QTR_W}x${HALF_H})"
echo "  Tests    → bot-right    (${MAIN_W},${HALF_H}  ${QTR_W}x${HALF_H})"

# ── 1. Launch Django dev server ───────────────────────────────────────────────
gnome-terminal \
    --title="bugcrusher — Server" \
    -- bash --login -c "
        $ACTIVATE
        cd \"$SCRIPT_DIR\"
        echo '════════════════════════════════════════'
        echo '  bugcrusher — Django Development Server'
        echo '════════════════════════════════════════'
        python manage.py runserver 2>&1
        exec bash
    " &

sleep 1.2

# ── 2. Launch test runner terminal ───────────────────────────────────────────
gnome-terminal \
    --title="bugcrusher — Tests" \
    -- bash --login -c "
        $ACTIVATE
        cd \"$SCRIPT_DIR\"
        echo '════════════════════════════════════════'
        echo '  bugcrusher — Test Runner'
        echo '  Commands:'
        echo '    python run_tests.py        (all tests)'
        echo '    bash test_all.sh           (full suite)'
        echo '    python manage.py test scanner'
        echo '    python manage.py test users'
        echo '════════════════════════════════════════'
        echo ''
        exec bash
    " &

sleep 1.5

# ── 3. Open browser to app ───────────────────────────────────────────────────
if command -v firefox &>/dev/null; then
    firefox "http://127.0.0.1:8000" &
elif command -v google-chrome &>/dev/null; then
    google-chrome "http://127.0.0.1:8000" &
elif command -v chromium-browser &>/dev/null; then
    chromium-browser "http://127.0.0.1:8000" &
else
    xdg-open "http://127.0.0.1:8000" &
fi

sleep 2.0

# ── 4. Position all three windows ────────────────────────────────────────────
# Browser — left 3/4, full height
wmctrl -r "Mozilla Firefox" -b remove,maximized_vert,maximized_horz 2>/dev/null
wmctrl -r "Mozilla Firefox" -e 0,0,0,$MAIN_W,$SCREEN_H 2>/dev/null
wmctrl -r "Google Chrome" -b remove,maximized_vert,maximized_horz 2>/dev/null
wmctrl -r "Google Chrome" -e 0,0,0,$MAIN_W,$SCREEN_H 2>/dev/null

# Django server — top-right 1/4
wmctrl -r "bugcrusher — Server" -b remove,maximized_vert,maximized_horz
wmctrl -r "bugcrusher — Server" -e 0,$MAIN_W,0,$QTR_W,$HALF_H

# Test terminal — bottom-right 1/4
wmctrl -r "bugcrusher — Tests" -b remove,maximized_vert,maximized_horz
wmctrl -r "bugcrusher — Tests" -e 0,$MAIN_W,$HALF_H,$QTR_W,$HALF_H

echo ""
echo -e "${GREEN}◆ Done.${NC}"
echo "  App → http://127.0.0.1:8000"
echo "  Admin → http://127.0.0.1:8000/admin"
