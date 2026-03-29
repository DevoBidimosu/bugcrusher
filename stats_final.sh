#!/usr/bin/env bash

# bugcrusher - Accurate Project Statistics
# Uses both `find` and `cloc` for a complete picture of core vs. expanded size

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

clear

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${YELLOW}                 bugcrusher — ACCURATE PROJECT STATISTICS                   ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── cloc check ────────────────────────────────────────────────────────────────
if ! command -v cloc &> /dev/null; then
    echo -e "${RED}Error: cloc is not installed.${NC}"
    echo "Install it:  sudo apt-get install cloc"
    echo "             brew install cloc"
    exit 1
fi

# ── Helper: format numbers with commas ────────────────────────────────────────
format_num() {
    echo "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

# ── Detect current state ──────────────────────────────────────────────────────
CURRENT_STATE="RETRACTED"
VENV_DIR=""

if [ -d "venv" ]; then
    CURRENT_STATE="EXPANDED"
    VENV_DIR="venv"
elif [ -d ".venv" ]; then
    CURRENT_STATE="EXPANDED"
    VENV_DIR=".venv"
fi

echo -e "${CYAN}Current State:  ${BOLD}${CURRENT_STATE}${NC}"
if [ "$CURRENT_STATE" = "EXPANDED" ]; then
    VENV_SIZE=$(du -sh "$VENV_DIR" 2>/dev/null | awk '{print $1}')
    echo -e "${DIM}  (venv at ${VENV_DIR}/ — ${VENV_SIZE})${NC}"
fi

# Django check — only meaningful when venv is present and Django is importable
if [ "$CURRENT_STATE" = "EXPANDED" ] && command -v python &>/dev/null && python -c "import django" 2>/dev/null; then
    if python manage.py check --quiet 2>/dev/null; then
        echo -e "${DIM}  Django system check: ${GREEN}OK${NC}"
    else
        echo -e "${DIM}  Django system check: ${YELLOW}issues present${NC}"
    fi
elif [ "$CURRENT_STATE" = "RETRACTED" ]; then
    echo -e "${DIM}  Django system check: ${YELLOW}N/A (no venv)${NC}"
else
    echo -e "${DIM}  Django system check: ${YELLOW}Django not importable${NC}"
fi
echo ""

echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📊 ANALYZING PROJECT...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Method 1: Raw find (core source files only) ───────────────────────────────
echo -e "${DIM}  Counting raw lines (find)...${NC}"

TOTAL_LINES_ALL=$(find . -type f \
    -not -path "*/.git/*" \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.pytest_cache/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

TOTAL_FILES_ALL=$(find . -type f \
    -not -path "*/.git/*" \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.pytest_cache/*" \
    2>/dev/null | wc -l)

# ── Method 2: cloc — core only (no venv, no pycache) ─────────────────────────
echo -e "${DIM}  Running cloc on core source...${NC}"

CLOC_CORE=$(cloc . \
    --exclude-dir=venv,.venv,__pycache__,.git,.pytest_cache \
    --not-match-f='\.txt$' \
    --quiet 2>/dev/null)

CORE_CODE=$(echo    "$CLOC_CORE" | grep "^SUM:"    | awk '{print $5}')
CORE_BLANK=$(echo   "$CLOC_CORE" | grep "^SUM:"    | awk '{print $3}')
CORE_COMMENT=$(echo "$CLOC_CORE" | grep "^SUM:"    | awk '{print $4}')
CORE_FILES=$(echo   "$CLOC_CORE" | grep "^SUM:"    | awk '{print $2}')

# Per-language breakdown
PY_CODE=$(echo    "$CLOC_CORE" | grep "^Python "      | awk '{print $NF}')
HTML_CODE=$(echo  "$CLOC_CORE" | grep "^HTML "        | awk '{print $NF}')
CSS_CODE=$(echo   "$CLOC_CORE" | grep "^CSS "         | awk '{print $NF}')
JS_CODE=$(echo    "$CLOC_CORE" | grep "^JavaScript "  | awk '{print $NF}')
SH_CODE=$(echo    "$CLOC_CORE" | grep "^Bourne Shell" | awk '{print $NF}')
MD_CODE=$(echo    "$CLOC_CORE" | grep "^Markdown "    | awk '{print $NF}')

[ -z "$PY_CODE" ]   && PY_CODE=0
[ -z "$HTML_CODE" ] && HTML_CODE=0
[ -z "$CSS_CODE" ]  && CSS_CODE=0
[ -z "$JS_CODE" ]   && JS_CODE=0
[ -z "$SH_CODE" ]   && SH_CODE=0
[ -z "$MD_CODE" ]   && MD_CODE=0
[ -z "$CORE_CODE" ] && CORE_CODE=0

# ── Method 3: cloc — full project (with venv) ────────────────────────────────
FULL_CODE=0
FULL_FILES=0
DEPS_ONLY=0
TRUE_RATIO="N/A"
LEVERAGE="N/A"
if [ "$CURRENT_STATE" = "EXPANDED" ]; then
    echo -e "${DIM}  Running cloc on full project including venv (may take a moment)...${NC}"
    CLOC_FULL=$(cloc . --exclude-dir=.git --quiet 2>/dev/null)
    FULL_CODE=$(echo  "$CLOC_FULL" | grep "^SUM:" | awk '{print $5}')
    FULL_FILES=$(echo "$CLOC_FULL" | grep "^SUM:" | awk '{print $2}')
    [ -z "$FULL_CODE" ]  && FULL_CODE=0
    [ -z "$FULL_FILES" ] && FULL_FILES=0
fi

# ── Per-file line counts ──────────────────────────────────────────────────────
echo -e "${DIM}  Counting per-file lines...${NC}"

count_lines() {
    [ -f "$1" ] && wc -l < "$1" 2>/dev/null || echo 0
}

MANAGE_LINES=$(count_lines          "manage.py")
SETTINGS_LINES=$(count_lines        "bugcrusher/settings.py")
ROOT_URLS_LINES=$(count_lines       "bugcrusher/urls.py")
SCANNER_MODELS_LINES=$(count_lines  "scanner/models.py")
SCANNER_VIEWS_LINES=$(count_lines   "scanner/views.py")
AI_ENGINE_LINES=$(count_lines       "scanner/ai_engine.py")
SCANNER_URLS_LINES=$(count_lines    "scanner/urls.py")
SCANNER_TESTS_LINES=$(count_lines   "scanner/tests.py")
USERS_MODELS_LINES=$(count_lines    "users/models.py")
USERS_VIEWS_LINES=$(count_lines     "users/views.py")
USERS_URLS_LINES=$(count_lines      "users/urls.py")
USERS_TESTS_LINES=$(count_lines     "users/tests.py")
CREATE_DEMO_LINES=$(count_lines     "create_demo.py")
RUN_TESTS_LINES=$(count_lines       "run_tests.py")
MAIN_CSS_LINES=$(count_lines        "static/css/main.css")
INDEX_JS_LINES=$(count_lines        "static/js/index.js")
SCAN_DETAIL_JS_LINES=$(count_lines  "static/js/scan_detail.js")

echo ""

# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}📈 CORE PROJECT (source code only — no venv)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Raw file count (find — all source files):${NC}"
printf "  %-28s  %8s lines\n" "All source lines:"  "$(format_num $TOTAL_LINES_ALL)"
printf "  %-28s  %8s files\n" "All source files:"  "$(format_num $TOTAL_FILES_ALL)"
echo ""

echo -e "${YELLOW}cloc analysis (code only — blanks/comments excluded):${NC}"
printf "  %-28s  %8s lines\n" "Total code lines:"    "$(format_num $CORE_CODE)"
printf "  %-28s  %8s lines\n" "Blank lines:"         "$(format_num $CORE_BLANK)"
printf "  %-28s  %8s lines\n" "Comment lines:"       "$(format_num $CORE_COMMENT)"
printf "  %-28s  %8s files\n" "Total code files:"    "$(format_num $CORE_FILES)"
echo ""

echo -e "${CYAN}By language:${NC}"
printf "  %-20s  %6s lines\n"  "Python:"      "$PY_CODE"
printf "  %-20s  %6s lines\n"  "HTML:"        "$HTML_CODE"
printf "  %-20s  %6s lines\n"  "CSS:"         "$CSS_CODE"
printf "  %-20s  %6s lines\n"  "JavaScript:"  "$JS_CODE"
printf "  %-20s  %6s lines\n"  "Shell:"       "$SH_CODE"
printf "  %-20s  %6s lines\n"  "Markdown:"    "$MD_CODE"
echo ""

echo -e "${CYAN}Key file breakdown:${NC}"
printf "  %-42s  %5s lines\n"  "manage.py"                              "$MANAGE_LINES"
printf "  %-42s  %5s lines\n"  "bugcrusher/settings.py"                 "$SETTINGS_LINES"
printf "  %-42s  %5s lines\n"  "bugcrusher/urls.py"                     "$ROOT_URLS_LINES"
printf "  %-42s  %5s lines\n"  "scanner/models.py"                      "$SCANNER_MODELS_LINES"
printf "  %-42s  %5s lines\n"  "scanner/views.py"                       "$SCANNER_VIEWS_LINES"
printf "  %-42s  %5s lines\n"  "scanner/ai_engine.py (AI analysis)"     "$AI_ENGINE_LINES"
printf "  %-42s  %5s lines\n"  "scanner/urls.py"                        "$SCANNER_URLS_LINES"
printf "  %-42s  %5s lines\n"  "scanner/tests.py"                       "$SCANNER_TESTS_LINES"
printf "  %-42s  %5s lines\n"  "users/models.py"                        "$USERS_MODELS_LINES"
printf "  %-42s  %5s lines\n"  "users/views.py"                         "$USERS_VIEWS_LINES"
printf "  %-42s  %5s lines\n"  "users/urls.py"                          "$USERS_URLS_LINES"
printf "  %-42s  %5s lines\n"  "users/tests.py"                         "$USERS_TESTS_LINES"
printf "  %-42s  %5s lines\n"  "create_demo.py"                         "$CREATE_DEMO_LINES"
printf "  %-42s  %5s lines\n"  "run_tests.py"                           "$RUN_TESTS_LINES"
printf "  %-42s  %5s lines\n"  "static/css/main.css"                    "$MAIN_CSS_LINES"
printf "  %-42s  %5s lines\n"  "static/js/index.js"                     "$INDEX_JS_LINES"
printf "  %-42s  %5s lines\n"  "static/js/scan_detail.js"               "$SCAN_DETAIL_JS_LINES"
echo ""

# ── Expanded analysis ─────────────────────────────────────────────────────────
if [ "$CURRENT_STATE" = "EXPANDED" ]; then
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}📦 EXPANDED STATE (with all venv dependencies)${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${YELLOW}Full project (cloc including venv):${NC}"
    if [ "$FULL_CODE" != "0" ]; then
        echo -e "  Total code lines: ${BOLD}$(format_num $FULL_CODE)${NC}"
        echo -e "  Total code files: ${BOLD}$(format_num $FULL_FILES)${NC}"
    else
        echo -e "  ${RED}cloc parse failed${NC}"
    fi
    echo ""

    if [ "$PY_CODE" -gt 0 ] && [ "$FULL_CODE" -gt 0 ] 2>/dev/null; then
        DEPS_ONLY=$((FULL_CODE - PY_CODE))
        TRUE_RATIO=$(echo "scale=1; $FULL_CODE / $PY_CODE" | bc 2>/dev/null || echo "?")
        LEVERAGE=$(echo "scale=0; $DEPS_ONLY / $PY_CODE" | bc 2>/dev/null || echo "?")

        echo -e "${CYAN}Expansion Analysis:${NC}"
        printf "  %-28s  %8s lines\n" "Your Python code:"     "$(format_num $PY_CODE)"
        printf "  %-28s  %8s lines\n" "Library dependencies:" "$(format_num $DEPS_ONLY)"
        printf "  %-28s  %8s lines\n" "Full expanded total:"  "$(format_num $FULL_CODE)"
        echo -e "  ${BOLD}──────────────────────────────────────────${NC}"
        echo -e "  ${MAGENTA}Expansion ratio:  ${BOLD}${TRUE_RATIO}x${NC}  ${DIM}(your code × leverage)${NC}"
        echo -e "  ${MAGENTA}Library leverage: ${BOLD}${LEVERAGE}x${NC}  ${DIM}(lines of libs per line of yours)${NC}"
    fi
    echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🎯 THE TRUTH ABOUT bugcrusher${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "When someone asks ${BOLD}\"How big is bugcrusher?\"${NC}"
echo ""
echo -e "  Answer: ${GREEN}${BOLD}$(format_num $PY_CODE) lines of Python${NC} written by hand."
OTHER_LINES=$((HTML_CODE + CSS_CODE + JS_CODE + SH_CODE + MD_CODE))
echo -e "  ${DIM}(Plus $(format_num $OTHER_LINES) lines of HTML/CSS/JS/shell/docs)${NC}"
echo ""

echo -e "  What that code does:"
echo -e "    • Django web app — vulnerability scanner with full CRUD"
echo -e "    • AI engine (ai_engine.py) — AI-powered scan analysis & fix suggestions"
echo -e "    • Scan management — create, view, import, and track scan jobs"
echo -e "    • Vulnerability tracking — per-finding severity, CVE IDs, fix status"
echo -e "    • User authentication — register, login, logout, profile"
echo -e "    • Dashboard — severity charts, scan stats, at-a-glance overview"
echo -e "    • Import reports — ingest external scan results"
echo -e "    • SQLite database — migrations-managed schema"
echo -e "    • Demo data seeder — populate dev environment instantly"
echo ""

if [ "$CURRENT_STATE" = "EXPANDED" ] && [ "$FULL_CODE" != "0" ] 2>/dev/null; then
    echo -e "  When expanded with libraries: ${MAGENTA}${BOLD}$(format_num $FULL_CODE) total lines${NC}"
    echo -e "  ${DIM}($(format_num $DEPS_ONLY) lines of libraries riding on $(format_num $PY_CODE) lines of yours)${NC}"
    echo ""
    echo -e "${CYAN}  The leverage of modern development:${NC}"
    echo -e "${DIM}  You wrote ~$(format_num $PY_CODE) lines. You're wielding ~$(format_num $FULL_CODE) lines of capability.${NC}"
fi

echo ""

# ── Django app breakdown ──────────────────────────────────────────────────────
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🏗️  DJANGO APP BREAKDOWN${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

for app in bugcrusher scanner users; do
    APP_PY=$(find "${app}" -name "*.py" \
        -not -path "*/__pycache__/*" \
        -not -name "__init__.py" \
        2>/dev/null | wc -l)
    APP_LINES=$(find "${app}" -name "*.py" \
        -not -path "*/__pycache__/*" \
        -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')
    [ -z "$APP_LINES" ] && APP_LINES=0
    printf "  %-12s  %3s Python files   %6s lines\n" "${app}/" "$APP_PY" "$(format_num $APP_LINES)"
done

TMPL_COUNT=$(find templates -name "*.html" 2>/dev/null | wc -l)
printf "  %-12s  %3s HTML templates\n" "templates/" "$TMPL_COUNT"

echo ""

# ── Test coverage ──────────────────────────────────────────────────────────────
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🧪 TEST COVERAGE${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

TEST_SCANNER=$(grep -c "def test_" scanner/tests.py 2>/dev/null | tr -d '[:space:]'); [ -z "$TEST_SCANNER" ] && TEST_SCANNER=0
TEST_USERS=$(grep -c "def test_" users/tests.py 2>/dev/null | tr -d '[:space:]'); [ -z "$TEST_USERS" ] && TEST_USERS=0
# run_tests.py is a static analysis runner (no def test_ functions) — count check() calls instead
STATIC_CHECKS=$(grep -c "^check(" run_tests.py 2>/dev/null | tr -d '[:space:]'); [ -z "$STATIC_CHECKS" ] && STATIC_CHECKS=0
TEST_TOTAL=$(( ${TEST_SCANNER:-0} + ${TEST_USERS:-0} ))

echo -e "  Scanner tests:  ${GREEN}${BOLD}${TEST_SCANNER}${NC}  (scanner/tests.py)"
echo -e "  User tests:     ${GREEN}${BOLD}${TEST_USERS}${NC}  (users/tests.py)"
echo -e "  Total Django:   ${GREEN}${BOLD}${TEST_TOTAL} defined${NC}"
echo ""
echo -e "  Static checks:  ${GREEN}${BOLD}${STATIC_CHECKS}${NC}  across 10 phases (run_tests.py — no venv needed)"
echo ""
echo -e "  ${DIM}Run scanner tests:  python manage.py test scanner${NC}"
echo -e "  ${DIM}Run user tests:     python manage.py test users${NC}"
echo -e "  ${DIM}Run static checks:  python run_tests.py${NC}"
echo -e "  ${DIM}Full suite:         bash test_all.sh${NC}"
echo ""

# ── Environment check ─────────────────────────────────────────────────────────
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}⚙️  ENVIRONMENT STATUS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ -f ".env" ]; then
    echo -e "  ${GREEN}✓${NC}  .env file found"
else
    echo -e "  ${YELLOW}–${NC}  .env not found — copy from .env.example"
fi

if [ -f "db.sqlite3" ]; then
    DB_SIZE=$(du -sh db.sqlite3 2>/dev/null | awk '{print $1}')
    echo -e "  ${GREEN}✓${NC}  db.sqlite3 exists (${DB_SIZE})"
else
    echo -e "  ${YELLOW}–${NC}  db.sqlite3 not found — run: python manage.py migrate"
fi

if [ "$CURRENT_STATE" = "EXPANDED" ]; then
    echo -e "  ${GREEN}✓${NC}  venv present at ${VENV_DIR}/ (${VENV_SIZE})"
else
    echo -e "  ${YELLOW}–${NC}  venv not present — run: ./expand.sh"
fi

echo ""

# ── Debug mode ────────────────────────────────────────────────────────────────
if [ "$1" = "--debug" ]; then
    echo ""
    echo -e "${DIM}━━━ Debug Variables ━━━${NC}"
    echo -e "${DIM}PY_CODE:         $PY_CODE${NC}"
    echo -e "${DIM}CORE_CODE:       $CORE_CODE${NC}"
    echo -e "${DIM}CORE_FILES:      $CORE_FILES${NC}"
    echo -e "${DIM}FULL_CODE:       $FULL_CODE${NC}"
    echo -e "${DIM}FULL_FILES:      $FULL_FILES${NC}"
    echo -e "${DIM}DEPS_ONLY:       $DEPS_ONLY${NC}"
    echo -e "${DIM}TRUE_RATIO:      $TRUE_RATIO${NC}"
    echo -e "${DIM}LEVERAGE:        $LEVERAGE${NC}"
    echo -e "${DIM}TEST_TOTAL:      $TEST_TOTAL${NC}"
    echo ""
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
