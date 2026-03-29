#!/usr/bin/env bash

# bugcrusher - Project Structure Mapper
# Generates a comprehensive PROJECT_MAP.txt describing every module

OUTPUT_FILE="PROJECT_MAP.txt"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Colors (terminal output only)
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Generating bugcrusher structure map...${NC}"

# ── Check for cloc ────────────────────────────────────────────────────────────
HAS_CLOC=false
if command -v cloc &>/dev/null; then
    HAS_CLOC=true
fi

# ── Dynamic codebase stats ────────────────────────────────────────────────────
PY_FILES_COUNT=$(find . -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" 2>/dev/null | wc -l | tr -d ' ')

PY_LINE_COUNT="unknown"
if [ "$HAS_CLOC" = true ]; then
    PY_LINE_COUNT=$(cloc . \
        --exclude-dir=venv,.venv,__pycache__,.git,.pytest_cache \
        --quiet 2>/dev/null | grep "^Python " | awk '{print $5}')
    [ -z "$PY_LINE_COUNT" ] && PY_LINE_COUNT="unknown"
fi

# Format with commas (e.g. 1234 → 1,234)
PY_LINE_COUNT_FMT=$(echo "$PY_LINE_COUNT" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')

# ── Header ────────────────────────────────────────────────────────────────────
cat > "$OUTPUT_FILE" << EOF
================================================================================
bugcrusher — PROJECT STRUCTURE MAP
Generated: $DATE
================================================================================

bugcrusher is a Django-based vulnerability scanner web application with AI-powered
analysis, user authentication, scan management, and a detailed vulnerability
dashboard. Built on Django with SQLite, it features an AI engine for interpreting
scan results, user registration/login, and a clean scan detail UI.

Framework:   Django
Entry point: python manage.py runserver
Dev server:  http://127.0.0.1:8000
Codebase:    $PY_LINE_COUNT_FMT lines of Python (cloc, $PY_FILES_COUNT files)

================================================================================
FULL PROJECT TREE (core source only — no venv / pycache)
================================================================================

EOF

tree -I 'venv|.venv|__pycache__|*.pyc|.git|*.egg-info|.pytest_cache' \
    --dirsfirst -a >> "$OUTPUT_FILE" 2>/dev/null || \
    find . -not -path "*/venv/*" -not -path "*/.venv/*" \
           -not -path "*/__pycache__/*" -not -path "*/.git/*" \
           -not -path "*/.pytest_cache/*" \
           | sort >> "$OUTPUT_FILE"

cat >> "$OUTPUT_FILE" << 'EOF'

================================================================================
MODULE REFERENCE — WHAT EACH FILE DOES
================================================================================

ROOT
────
  manage.py             ← Django management utility entry point
                           Runs: runserver, migrate, test, shell, etc.
  create_demo.py        ← Demo data seeder — populates db with sample scans
                           and vulnerabilities for development/preview
  run_tests.py          ← Static analysis runner — 104 checks across 10 phases
                           (file existence, model fields, prompts, views, URLs,
                           JS, templates, migrations, CSS, test completeness)
                           Does NOT use Django test runner — runs without venv
  test_all.sh           ← Shell script running the full test suite
  requirements.txt      ← Python dependency list (Django, dotenv, etc.)
  .env.example          ← Template for required environment variables
  db.sqlite3            ← SQLite development database (not committed to git)

BUGCRUSHER/ (Django project package)
─────────────────────────────────────
  settings.py           ← Project-wide Django settings
                           • INSTALLED_APPS: scanner, users
                           • DATABASE: SQLite (db.sqlite3)
                           • SECRET_KEY, DEBUG, ALLOWED_HOSTS from .env
                           • Static files, templates, auth backends
  urls.py               ← Root URL dispatcher
                           • Routes: / → scanner.urls
                           •         /users/ → users.urls
                           •         /admin/ → Django admin
  wsgi.py               ← WSGI entry point (production deployment)
  asgi.py               ← ASGI entry point (async production deployment)

SCANNER/ (Vulnerability Scanner App)
──────────────────────────────────────
  models.py             ← Core data models
                           • Scan — represents a single scan job
                             Fields: target, scan_type, status, created_at,
                                     completed_at, user (FK)
                           • Vulnerability — individual finding within a scan
                             Fields: scan (FK), title, severity, description,
                                     fix_suggestion, cve_id, fix_status
  views.py              ← Scanner views (all login-required)
                           • index() — scan list / dashboard
                           • scan_detail() — single scan + vulnerability list
                           • dashboard() — stats overview
                           • import_report() — import external scan report
  ai_engine.py          ← AI-powered vulnerability analysis engine
                           • Analyzes raw scan output with AI
                           • Generates fix suggestions per vulnerability
                           • Summarizes severity and risk posture
  urls.py               ← Scanner URL patterns
                           • /              → index (scan list)
                           • /scan/<id>/    → scan detail
                           • /dashboard/    → stats dashboard
                           • /import/       → import report
  admin.py              ← Django admin registration for Scan + Vulnerability
  apps.py               ← ScannerConfig app configuration
  tests.py              ← Scanner test suite
                           • Model creation tests
                           • View response tests (auth required)
                           • AI engine unit tests
  migrations/
    0001_initial.py     ← Initial schema: Scan + Vulnerability tables
    0002_vulnerability_fix_fields.py  ← Adds fix_suggestion, fix_status fields

USERS/ (Authentication App)
─────────────────────────────
  models.py             ← Custom user model extensions (if any)
  views.py              ← Auth views
                           • register() — new user registration
                           • login_view() — user login
                           • logout_view() — session logout
                           • profile() — user profile page
  urls.py               ← Auth URL patterns
                           • /users/register/  → registration
                           • /users/login/     → login
                           • /users/logout/    → logout
                           • /users/profile/   → profile
  admin.py              ← Admin registration for user models
  apps.py               ← UsersConfig app configuration
  tests.py              ← User auth test suite
                           • Registration flow tests
                           • Login/logout tests
                           • Auth redirect tests
  migrations/
    __init__.py         ← Users migrations package

TEMPLATES/
──────────
  base.html             ← Base layout — navbar, auth status, static includes
  scanner/
    index.html          ← Scan list page — shows all scans with status badges
    scan_detail.html    ← Single scan view — vulnerability table + AI summary
    dashboard.html      ← Statistics overview — severity charts, counts
    import_report.html  ← Import external scan report form
  users/
    login.html          ← Login form
    register.html       ← Registration form

STATIC/
───────
  css/main.css          ← Application stylesheet
  js/index.js           ← Scan list page JS (filtering, sorting)
  js/scan_detail.js     ← Scan detail page JS (expand/collapse, fix tracking)

EOF

# ── Statistics ────────────────────────────────────────────────────────────────
echo "" >> "$OUTPUT_FILE"
echo "================================================================================" >> "$OUTPUT_FILE"
echo "FILE STATISTICS" >> "$OUTPUT_FILE"
echo "================================================================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

PY_FILES=$(find . -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" 2>/dev/null | wc -l)

PY_LINES=$(find . -name "*.py" \
    -not -path "*/venv/*" -not -path "*/.venv/*" \
    -not -path "*/__pycache__/*" \
    -exec wc -l {} + 2>/dev/null | tail -n 1 | awk '{print $1}')

printf "  %-30s %6s files\n" "Total Python files:" "$PY_FILES" >> "$OUTPUT_FILE"
printf "  %-30s %6s lines\n" "Total Python lines:" "$PY_LINES" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "  Per-module line counts:" >> "$OUTPUT_FILE"

for f in \
    "manage.py" \
    "create_demo.py" \
    "run_tests.py" \
    "bugcrusher/settings.py" \
    "bugcrusher/urls.py" \
    "bugcrusher/wsgi.py" \
    "bugcrusher/asgi.py" \
    "scanner/models.py" \
    "scanner/views.py" \
    "scanner/ai_engine.py" \
    "scanner/urls.py" \
    "scanner/admin.py" \
    "scanner/tests.py" \
    "scanner/migrations/0001_initial.py" \
    "scanner/migrations/0002_vulnerability_fix_fields.py" \
    "users/models.py" \
    "users/views.py" \
    "users/urls.py" \
    "users/admin.py" \
    "users/tests.py"; do
    if [ -f "$f" ]; then
        LINES=$(wc -l < "$f" 2>/dev/null || echo "0")
        printf "    %-45s %5s lines\n" "$f" "$LINES" >> "$OUTPUT_FILE"
    fi
done

echo "" >> "$OUTPUT_FILE"

# Test count — only Django test files (run_tests.py is a static check runner, not a test file)
DJANGO_TESTS=$(grep -c "def test_" \
    scanner/tests.py \
    users/tests.py \
    2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')

STATIC_CHECKS=$(grep -c "^check(" run_tests.py 2>/dev/null || echo "0")

echo "  Django tests: ${DJANGO_TESTS} defined (scanner + users)" >> "$OUTPUT_FILE"
echo "  Static checks: ${STATIC_CHECKS} checks across 10 phases (run_tests.py)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "================================================================================" >> "$OUTPUT_FILE"
echo "End of bugcrusher PROJECT_MAP.txt" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# ── Terminal summary ──────────────────────────────────────────────────────────
echo -e "${GREEN}✓ Structure map written to: ${OUTPUT_FILE}${NC}"
echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  Python files (core): ${GREEN}${PY_FILES}${NC}"
echo -e "  Python lines (core): ${GREEN}${PY_LINES}${NC}"
echo ""
echo -e "  Apps:"
for app in scanner users bugcrusher; do
    COUNT=$(find "${app}" -name "*.py" -not -name "__init__.py" \
        -not -path "*/__pycache__/*" -not -path "*/migrations/*" 2>/dev/null | wc -l)
    printf "    %-14s %s files\n" "${app}/" "${COUNT}"
done
echo ""
echo -e "  Tests: ${GREEN}${DJANGO_TESTS} Django tests${NC} + ${GREEN}${STATIC_CHECKS} static checks${NC}"
echo ""
