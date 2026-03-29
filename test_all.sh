#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# BugCrusher AI — Full Test Runner
# Runs both the static checker AND the Django test suite.
#
# Usage (from inside the bugcrusher/ project folder):
#   chmod +x test_all.sh
#   ./test_all.sh
# ─────────────────────────────────────────────────────────────

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       BugCrusher AI — Full Test Suite Runner         ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: static checker ────────────────────────────────────
echo -e "${BOLD}[ 1/2 ] Running static checks (run_tests.py)...${NC}"
echo ""
python3 run_tests.py
STATIC_EXIT=$?

echo ""

# ── Step 2: Django test suite ─────────────────────────────────
echo -e "${BOLD}[ 2/2 ] Running Django test suite (100 tests)...${NC}"
echo ""

# Make sure migrations are applied before running tests
python3 manage.py migrate --run-syncdb -v 0 2>/dev/null || true

python3 manage.py test scanner --verbosity=2
DJANGO_EXIT=$?

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}FINAL RESULT${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"

if [ $STATIC_EXIT -eq 0 ] && [ $DJANGO_EXIT -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓ All checks passed — static + Django tests green!${NC}"
    exit 0
else
    [ $STATIC_EXIT -ne 0 ] && echo -e "${RED}  ✗ Static checks had failures (see above)${NC}"
    [ $DJANGO_EXIT -ne 0 ] && echo -e "${RED}  ✗ Django tests had failures (see above)${NC}"
    exit 1
fi
