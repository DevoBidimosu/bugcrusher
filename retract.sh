#!/usr/bin/env bash

# bugcrusher - Project Retraction Script
# Removes venv and all build artifacts — leaves core source code intact

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📉 Retracting bugcrusher Project${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Detect what's present ─────────────────────────────────────────────────────
HAS_DEPENDENCIES=false
TOTAL_TO_REMOVE=0

VENV_DIRS=()
if [ -d "venv" ]; then
    VENV_DIRS+=("venv")
    HAS_DEPENDENCIES=true
fi
if [ -d ".venv" ]; then
    VENV_DIRS+=(".venv")
    HAS_DEPENDENCIES=true
fi

HAS_PYCACHE=false
HAS_PYTEST_CACHE=false

if find . -type d -name "__pycache__" -not -path "*/venv/*" -not -path "*/.venv/*" 2>/dev/null | grep -q .; then
    HAS_PYCACHE=true
    HAS_DEPENDENCIES=true
fi
if [ -d ".pytest_cache" ]; then
    HAS_PYTEST_CACHE=true
    HAS_DEPENDENCIES=true
fi

# ── Guard: already retracted? ─────────────────────────────────────────────────
if [ "$HAS_DEPENDENCIES" = false ]; then
    echo -e "${YELLOW}⚠️  Project is already RETRACTED${NC}"
    echo ""
    echo "No dependencies or build artifacts found."
    echo ""

    CURRENT_LINES=$(find . -type f \
        -not -path "*/.git/*" \
        -not -path "*/__pycache__/*" \
        -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')
    CURRENT_FILES=$(find . -type f \
        -not -path "*/.git/*" \
        -not -path "*/__pycache__/*" \
        2>/dev/null | wc -l)

    echo -e "${CYAN}Current state (core only):${NC}"
    echo -e "  Lines: ${GREEN}${CURRENT_LINES}${NC}"
    echo -e "  Files: ${GREEN}${CURRENT_FILES}${NC}"
    echo ""
    echo "To expand: ./expand.sh"
    exit 0
fi

# ── Capture EXPANDED stats before removal ────────────────────────────────────
echo -e "${YELLOW}📊 Current state (EXPANDED — with dependencies):${NC}"

INITIAL_LINES=$(find . -type f \
    -not -path "*/.git/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

INITIAL_FILES=$(find . -type f \
    -not -path "*/.git/*" \
    2>/dev/null | wc -l)

INITIAL_PY=$(find . -name "*.py" 2>/dev/null | wc -l)

echo -e "  Lines:        ${GREEN}${INITIAL_LINES}${NC}"
echo -e "  Files:        ${GREEN}${INITIAL_FILES}${NC}"
echo -e "  Python files: ${GREEN}${INITIAL_PY}${NC}"
echo ""

# ── Show what will be removed ─────────────────────────────────────────────────
echo -e "${YELLOW}📦 About to remove:${NC}"

for venv_dir in "${VENV_DIRS[@]}"; do
    VENV_SIZE=$(du -sh "$venv_dir" 2>/dev/null | awk '{print $1}')
    VENV_FILES=$(find "$venv_dir" -type f 2>/dev/null | wc -l)
    echo -e "  • ${venv_dir}/        ${CYAN}${VENV_SIZE}${NC}  (${VENV_FILES} files)"
    TOTAL_TO_REMOVE=$((TOTAL_TO_REMOVE + VENV_FILES))
done

if [ "$HAS_PYCACHE" = true ]; then
    CACHE_FILES=$(find . -type d -name "__pycache__" -not -path "*/venv/*" -not -path "*/.venv/*" \
        -exec find {} -type f \; 2>/dev/null | wc -l)
    echo -e "  • __pycache__/   compiled .pyc files  (${CACHE_FILES} files)"
    TOTAL_TO_REMOVE=$((TOTAL_TO_REMOVE + CACHE_FILES))
fi
if [ "$HAS_PYTEST_CACHE" = true ]; then
    echo -e "  • .pytest_cache/  test cache"
fi

echo -e "  ${BOLD}Total to remove: ~${TOTAL_TO_REMOVE} files${NC}"
echo ""
echo -e "  ${CYAN}Note: db.sqlite3 is preserved (your development database)${NC}"
echo -e "  ${CYAN}Note: .env is preserved (your local environment config)${NC}"
echo ""

# ── Remove venv(s) ────────────────────────────────────────────────────────────
if [ ${#VENV_DIRS[@]} -gt 0 ]; then
    echo -e "${YELLOW}━━━ Python Virtual Environment ━━━${NC}"
    for venv_dir in "${VENV_DIRS[@]}"; do
        VENV_SIZE=$(du -sh "$venv_dir" 2>/dev/null | awk '{print $1}')
        echo "🗑️  Removing ${venv_dir}/ ..."
        rm -rf "$venv_dir"
        echo -e "${GREEN}✓ Removed ${venv_dir}/ ${NC}(was ${VENV_SIZE})"
    done
    echo ""
fi

# ── Remove build artifacts ────────────────────────────────────────────────────
echo -e "${YELLOW}━━━ Cleaning Build Artifacts ━━━${NC}"
CLEANED=0

# __pycache__ everywhere (outside venv)
if find . -type d -name "__pycache__" 2>/dev/null | grep -q .; then
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    echo -e "${GREEN}✓ Removed __pycache__ directories${NC}"
    CLEANED=$((CLEANED + 1))
fi

# .pyc / .pyo compiled files
if find . -type f \( -name "*.pyc" -o -name "*.pyo" \) 2>/dev/null | grep -q .; then
    find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true
    echo -e "${GREEN}✓ Removed compiled .pyc/.pyo files${NC}"
    CLEANED=$((CLEANED + 1))
fi

# .pytest_cache
if [ -d ".pytest_cache" ]; then
    rm -rf .pytest_cache
    echo -e "${GREEN}✓ Removed .pytest_cache/${NC}"
    CLEANED=$((CLEANED + 1))
fi

if [ "$CLEANED" -eq 0 ]; then
    echo -e "${YELLOW}–  No build artifacts found${NC}"
fi

echo ""

# ── Final stats (retracted state) ────────────────────────────────────────────
FINAL_LINES=$(find . -type f \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.git/*" \
    -not -path "*/.pytest_cache/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

FINAL_FILES=$(find . -type f \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.git/*" \
    -not -path "*/.pytest_cache/*" \
    2>/dev/null | wc -l)

FINAL_PY=$(find . -name "*.py" \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    2>/dev/null | wc -l)

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ bugcrusher RETRACTED Successfully${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}📊 Final state (RETRACTED — core code only):${NC}"
echo -e "  Lines:        ${GREEN}${FINAL_LINES}${NC}"
echo -e "  Files:        ${GREEN}${FINAL_FILES}${NC}"
echo -e "  Python files: ${GREEN}${FINAL_PY}${NC}"
echo ""

# Reduction analysis
if [ -n "$INITIAL_LINES" ] && [ -n "$FINAL_LINES" ] && [ "$INITIAL_LINES" -gt 0 ] 2>/dev/null; then
    REMOVED=$((INITIAL_LINES - FINAL_LINES))
    if [ "$REMOVED" -gt 0 ]; then
        PERCENT=$(echo "scale=1; ($REMOVED * 100) / $INITIAL_LINES" | bc 2>/dev/null || echo "?")
        RATIO=$(echo "scale=1; $INITIAL_LINES / $FINAL_LINES" | bc 2>/dev/null || echo "?")
        echo -e "${YELLOW}📉 Reduction Analysis:${NC}"
        echo -e "  Lines removed:  ${GREEN}${REMOVED}${NC}"
        echo -e "  Files removed:  ${GREEN}$((INITIAL_FILES - FINAL_FILES))${NC}"
        echo -e "  Size reduction: ${GREEN}${PERCENT}%${NC}"
        echo -e "  Compression:    ${GREEN}${RATIO}x smaller${NC}"
        echo ""
    fi
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Project is now RETRACTED — core source only."
echo ""
echo "Core files preserved:"
echo "  bugcrusher/               ← Django settings package"
echo "    settings.py             ← project settings"
echo "    urls.py                 ← root URL configuration"
echo "    wsgi.py / asgi.py       ← WSGI/ASGI entry points"
echo "  scanner/                  ← vulnerability scanner Django app"
echo "    models.py               ← Scan, Vulnerability models"
echo "    views.py                ← scan management views"
echo "    ai_engine.py            ← AI-powered vulnerability analysis"
echo "    urls.py                 ← scanner URL patterns"
echo "    tests.py                ← scanner test suite"
echo "    migrations/             ← database migrations"
echo "  users/                    ← user authentication app"
echo "    models.py               ← user models"
echo "    views.py                ← login, register, profile views"
echo "    urls.py                 ← auth URL patterns"
echo "    tests.py                ← user test suite"
echo "    migrations/             ← user migrations"
echo "  static/css/main.css       ← stylesheet"
echo "  static/js/                ← index.js, scan_detail.js"
echo "  templates/                ← HTML templates"
echo "  manage.py                 ← Django management CLI"
echo "  create_demo.py            ← demo data seeder"
echo "  run_tests.py              ← test runner"
echo "  test_all.sh               ← full test suite runner"
echo "  requirements.txt"
echo "  .env / .env.example"
echo "  db.sqlite3                ← development database (preserved)"
echo ""
echo "To expand again: ./expand.sh"
echo ""
