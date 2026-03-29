#!/usr/bin/env bash

# bugcrusher - Project Expansion Script
# Creates venv and installs ALL Python dependencies

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🚀 Expanding bugcrusher Project${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Guard: already expanded? ──────────────────────────────────────────────────
ALREADY_EXPANDED=false
VENV_DIR=""

if [ -d "venv" ]; then
    ALREADY_EXPANDED=true
    VENV_DIR="venv"
elif [ -d ".venv" ]; then
    ALREADY_EXPANDED=true
    VENV_DIR=".venv"
fi

if [ "$ALREADY_EXPANDED" = true ]; then
    echo -e "${YELLOW}⚠️  Project is already EXPANDED${NC}"
    echo ""
    echo "Virtual environment already exists at: ${VENV_DIR}/"
    echo ""

    CURRENT_LINES=$(find . -type f \
        -not -path "*/.git/*" \
        -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')
    CURRENT_FILES=$(find . -type f \
        -not -path "*/.git/*" \
        2>/dev/null | wc -l)

    echo -e "${CYAN}Current state:${NC}"
    echo -e "  Total lines: ${GREEN}${CURRENT_LINES}${NC}"
    echo -e "  Total files: ${GREEN}${CURRENT_FILES}${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Activate venv:      source ${VENV_DIR}/bin/activate"
    echo "  2. Apply migrations:   python manage.py migrate"
    echo "  3. Create demo data:   python create_demo.py"
    echo "  4. Run server:         python manage.py runserver"
    echo "  5. Run tests:          python run_tests.py"
    echo "  6. Run all tests:      bash test_all.sh"
    echo ""
    echo "To retract: ./retract.sh"
    exit 0
fi

# ── Sanity check ──────────────────────────────────────────────────────────────
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}✗ requirements.txt not found.${NC}"
    echo "  Are you in the bugcrusher project root? Expected layout:"
    echo "    bugcrusher/   ← Django settings package"
    echo "    scanner/      ← vulnerability scanner app"
    echo "    users/        ← user auth app"
    echo "    requirements.txt"
    echo "    manage.py"
    exit 1
fi

if [ ! -f "manage.py" ]; then
    echo -e "${RED}✗ manage.py not found.${NC}"
    echo "  Are you in the bugcrusher project root?"
    exit 1
fi

# ── Initial stats (retracted state) ──────────────────────────────────────────
echo -e "${YELLOW}📊 Initial state (RETRACTED — core code only):${NC}"

INITIAL_LINES=$(find . -type f \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.git/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

INITIAL_FILES=$(find . -type f \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.git/*" \
    2>/dev/null | wc -l)

INITIAL_PY=$(find . -name "*.py" \
    -not -path "*/venv/*" \
    -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    2>/dev/null | wc -l)

echo -e "  Lines:        ${GREEN}${INITIAL_LINES}${NC}"
echo -e "  Files:        ${GREEN}${INITIAL_FILES}${NC}"
echo -e "  Python files: ${GREEN}${INITIAL_PY}${NC}"
echo ""

# ── Create virtual environment ────────────────────────────────────────────────
echo -e "${YELLOW}━━━ Python Virtual Environment ━━━${NC}"

echo "📦 Creating virtual environment (venv)..."
python3 -m venv venv
VENV_DIR="venv"

echo "📦 Activating..."
source venv/bin/activate

echo "📦 Upgrading pip..."
pip install --upgrade pip --quiet

echo "📦 Installing dependencies from requirements.txt..."
pip install -r requirements.txt --quiet

echo -e "${GREEN}✓ All Python dependencies installed${NC}"
echo ""

# ── Verify required packages ──────────────────────────────────────────────────
echo -e "${YELLOW}━━━ Verifying Core Packages ━━━${NC}"

CORE_PKGS=(
    "django|Django|Web framework"
    "dotenv|python-dotenv|Environment variable loader"
)

ALL_OK=true
for entry in "${CORE_PKGS[@]}"; do
    IMP="${entry%%|*}"
    REST="${entry#*|}"
    PKG="${REST%%|*}"
    DESC="${REST#*|}"
    if python -c "import ${IMP}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${PKG} — ${DESC}"
    else
        echo -e "  ${RED}✗${NC} ${PKG} — ${DESC} — MISSING"
        ALL_OK=false
    fi
done

echo ""
echo -e "${CYAN}  Optional / AI packages:${NC}"

OPT_PKGS=(
    "openai|openai|OpenAI API client (AI engine)"
    "anthropic|anthropic|Anthropic Claude client (AI engine)"
    "requests|requests|HTTP library"
    "sqlparse|sqlparse|SQL formatting"
    "httpx|httpx|Async HTTP client"
)

for entry in "${OPT_PKGS[@]}"; do
    IMP="${entry%%|*}"
    REST="${entry#*|}"
    PKG="${REST%%|*}"
    DESC="${REST#*|}"
    if python -c "import ${IMP}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${PKG} — ${DESC}"
    else
        echo -e "  ${YELLOW}–${NC} ${PKG} — ${DESC} (not installed)"
    fi
done

echo ""

if [ "$ALL_OK" = false ]; then
    echo -e "${RED}⚠️  Some core packages failed to install. Try:${NC}"
    echo "     pip install -r requirements.txt"
    echo ""
fi

# ── Verify Django apps load ───────────────────────────────────────────────────
# NOTE: Django app modules (models, views, urls) require a fully initialised
# Django environment — bare `python -c "import X"` won't work for them.
# We use `manage.py shell` to run imports inside a live Django context instead,
# and rely on `manage.py check` as the authoritative health signal.
echo -e "${YELLOW}━━━ Verifying Django Project ━━━${NC}"

IMPORT_ERRORS=0

# These pure-config modules are safe to import without django.setup()
SAFE_MODULES=(
    "bugcrusher"
    "bugcrusher.settings"
)
for mod in "${SAFE_MODULES[@]}"; do
    if DJANGO_SETTINGS_MODULE=bugcrusher.settings python -c "import ${mod}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${mod}"
    else
        echo -e "  ${RED}✗${NC} ${mod} — import failed"
        IMPORT_ERRORS=$((IMPORT_ERRORS + 1))
    fi
done

# App modules need django.setup() — run through manage.py shell
DJANGO_MODULES=(
    "bugcrusher.urls"
    "scanner"
    "scanner.models"
    "scanner.views"
    "scanner.urls"
    "scanner.ai_engine"
    "users"
    "users.models"
    "users.views"
    "users.urls"
)
for mod in "${DJANGO_MODULES[@]}"; do
    # Redirect stdout+stderr — we only care about exit code, not shell banner output
    if python manage.py shell -c "import ${mod}" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} ${mod}"
    else
        echo -e "  ${RED}✗${NC} ${mod} — import failed"
        IMPORT_ERRORS=$((IMPORT_ERRORS + 1))
    fi
done

echo ""
if [ "$IMPORT_ERRORS" -gt 0 ]; then
    echo -e "${RED}⚠️  ${IMPORT_ERRORS} module(s) failed to import.${NC}"
    echo "     Check your .env file and run: python manage.py check"
else
    echo -e "${GREEN}✓ All bugcrusher modules import cleanly${NC}"
fi

echo ""
echo -e "${CYAN}  Django system check:${NC}"
CHECK_OUTPUT=$(python manage.py check 2>&1)
CHECK_EXIT=$?
if [ "$CHECK_EXIT" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} manage.py check passed — no issues"
else
    echo -e "  ${YELLOW}⚠${NC} manage.py check reported issues:"
    # Indent each line of the check output for readability
    echo "$CHECK_OUTPUT" | grep -v "^$" | while IFS= read -r line; do
        echo -e "      ${YELLOW}${line}${NC}"
    done
fi

echo ""

# ── Apply migrations ──────────────────────────────────────────────────────────
echo -e "${YELLOW}━━━ Database Migrations ━━━${NC}"
if python manage.py migrate --run-syncdb; then
    echo -e "${GREEN}✓ Migrations applied${NC}"
else
    echo -e "${YELLOW}⚠️  Migrations may need attention — run: python manage.py migrate${NC}"
fi
echo ""

# ── Final stats ───────────────────────────────────────────────────────────────
FINAL_LINES=$(find . -type f \
    -not -path "*/.git/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.pytest_cache/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

FINAL_FILES=$(find . -type f \
    -not -path "*/.git/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/.pytest_cache/*" \
    2>/dev/null | wc -l)

FINAL_PY=$(find . -name "*.py" 2>/dev/null | wc -l)

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ bugcrusher EXPANDED Successfully${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}📊 Final state (EXPANDED):${NC}"
echo -e "  Total lines:  ${GREEN}${FINAL_LINES}${NC}"
echo -e "  Total files:  ${GREEN}${FINAL_FILES}${NC}"
echo -e "  Python files: ${GREEN}${FINAL_PY}${NC}"
echo ""

if [ -n "$INITIAL_LINES" ] && [ "$INITIAL_LINES" -gt 0 ] 2>/dev/null; then
    ADDED=$((FINAL_LINES - INITIAL_LINES))
    if [ "$ADDED" -gt 0 ]; then
        RATIO=$(echo "scale=1; $FINAL_LINES / $INITIAL_LINES" | bc 2>/dev/null || echo "?")
        PERCENT=$(echo "scale=1; ($ADDED * 100) / $INITIAL_LINES" | bc 2>/dev/null || echo "?")
        echo -e "${YELLOW}📈 Expansion Analysis:${NC}"
        echo -e "  Lines added:     ${GREEN}${ADDED}${NC}"
        echo -e "  Files added:     ${GREEN}$((FINAL_FILES - INITIAL_FILES))${NC}"
        echo -e "  Size increase:   ${GREEN}${PERCENT}%${NC}"
        echo -e "  Expansion ratio: ${GREEN}${RATIO}x${NC}"
        echo ""
    fi
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate venv:      source venv/bin/activate"
echo "  2. Copy env file:      cp .env.example .env  (if not done)"
echo "  3. Create demo data:   python create_demo.py"
echo "  4. Run dev server:     python manage.py runserver"
echo "  5. Run tests:          python run_tests.py"
echo "  6. Run all tests:      bash test_all.sh"
echo ""
echo "  Access at: http://127.0.0.1:8000"
echo ""
echo "To retract: ./retract.sh"
echo ""
