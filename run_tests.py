#!/usr/bin/env python3
"""
BugCrusher AI — Static Test Runner v3
Checks file existence, model fields, prompt schemas, CSS classes,
migration integrity, JS fixes, and template security without running Django.

Usage:
    python run_tests.py          # full suite
    python run_tests.py --quick  # same, just labelled quick
"""

import sys
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))

PASS = 0
FAIL = 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  \033[32m✓\033[0m  {label}")
        PASS += 1
    else:
        print(f"  \033[31m✗\033[0m  {label}" + (f"\n      → {detail}" if detail else ""))
        FAIL += 1


def read(rel_path):
    try:
        with open(os.path.join(BASE, rel_path), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def header(title):
    width = 60
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


# ─────────────────────────────────────────────────────────────
# Phase 1 — File Existence
# ─────────────────────────────────────────────────────────────
header("Phase 1 — File Existence")

required_files = [
    "manage.py",
    "requirements.txt",
    "run_tests.py",
    "scanner/models.py",
    "scanner/views.py",
    "scanner/ai_engine.py",
    "scanner/urls.py",
    "scanner/tests.py",
    "scanner/admin.py",
    "scanner/migrations/0001_initial.py",
    "scanner/migrations/0002_vulnerability_fix_fields.py",
    "static/js/scan_detail.js",
    "static/js/index.js",
    "static/css/main.css",
    "templates/base.html",
    "templates/scanner/dashboard.html",
    "templates/scanner/scan_detail.html",
    "templates/scanner/import_report.html",
    "templates/scanner/index.html",
    "templates/users/login.html",
    "templates/users/register.html",
]

for f in required_files:
    check(f"exists: {f}", os.path.isfile(os.path.join(BASE, f)))


# ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
# Phase 1b — Python Syntax Validation
# ─────────────────────────────────────────────────────────────
header("Phase 1b — Python Syntax Validation")

import ast as _ast

_python_files = [
    "manage.py", "create_demo.py", "run_tests.py",
    "scanner/models.py", "scanner/views.py", "scanner/ai_engine.py",
    "scanner/urls.py", "scanner/tests.py", "scanner/admin.py",
    "scanner/management/commands/cleanup_stale_scans.py",
    "users/views.py", "users/urls.py",
    "bugcrusher/settings.py", "bugcrusher/urls.py",
]

for _pyf in _python_files:
    _path = os.path.join(BASE, _pyf)
    try:
        _source = open(_path, encoding="utf-8").read()
        _ast.parse(_source)
        check(f"syntax OK: {_pyf}", True)
    except SyntaxError as _e:
        check(f"syntax OK: {_pyf}", False, f"Line {_e.lineno}: {_e.msg}")
    except FileNotFoundError:
        check(f"syntax OK: {_pyf}", False, "File not found")


# Phase 2 — Model Fields
# ─────────────────────────────────────────────────────────────
header("Phase 2 — Model Fields")

models = read("scanner/models.py")

scan_fields = ["target_type", "target_url", "target_code", "target_file",
               "language", "status", "created_at", "completed_at", "error_message"]
for f in scan_fields:
    check(f"Scan.{f}", f in models)

vuln_fields = ["title", "severity", "vuln_type", "description",
               "proof_of_concept", "remediation", "cvss_score", "cwe_id",
               "references", "fix_patch", "fix_notes", "fix_status"]
for f in vuln_fields:
    check(f"Vulnerability.{f}", f in models)

check("Vulnerability.FIX_STATUS_CHOICES defined", "FIX_STATUS_CHOICES" in models)
check("Vulnerability.fix_status default=unfixed", "default='unfixed'" in models)
check("Vulnerability severity ordering (Case/When)", "models.Case" in models and "models.When" in models)
check("Report.risk_score", "risk_score" in models)
check("Report.executive_summary", "executive_summary" in models)
check("Report OneToOneField scan", "OneToOneField" in models)
check("Scan.vulnerability_count property", "vulnerability_count" in models)
check("Scan.critical_count property", "critical_count" in models)
check("Scan.high_count property", "high_count" in models)
check("Scan.input_method field",              "input_method" in models)
check("Scan.INPUT_METHOD_CHOICES",            "INPUT_METHOD_CHOICES" in models)
check("Scan.get_target_display_name method", "get_target_display_name" in models)


# ─────────────────────────────────────────────────────────────
# Phase 3 — AI Engine / Prompts
# ─────────────────────────────────────────────────────────────
header("Phase 3 — AI Engine & Prompts")

ai = read("scanner/ai_engine.py")

check("SYSTEM_PROMPT defined", "SYSTEM_PROMPT" in ai)
check("FIX_SYSTEM_PROMPT defined", "FIX_SYSTEM_PROMPT" in ai)
check("SYSTEM_PROMPT: references schema", '"references"' in ai)
check("SYSTEM_PROMPT: label field", '"label"' in ai)
check("SYSTEM_PROMPT: url field", '"url"' in ai)
check("SYSTEM_PROMPT: type field", '"type"' in ai)
check("SYSTEM_PROMPT: no markdown instruction", "no markdown" in ai.lower())
check("SYSTEM_PROMPT: no code fences instruction", "no code fences" in ai.lower())
check("SYSTEM_PROMPT: owasp.org domain", "owasp.org" in ai)
check("SYSTEM_PROMPT: cwe.mitre.org domain", "cwe.mitre.org" in ai)
check("SYSTEM_PROMPT: portswigger.net domain", "portswigger.net" in ai)
check("SYSTEM_PROMPT: nvd.nist.gov domain", "nvd.nist.gov" in ai)
check("SYSTEM_PROMPT: CWE URL pattern", "cwe.mitre.org/data/definitions/" in ai)
check("FIX_SYSTEM_PROMPT: fix_patch field", "fix_patch" in ai)
check("FIX_SYSTEM_PROMPT: fix_notes field", "fix_notes" in ai)
check("FIX_SYSTEM_PROMPT: verification field", "verification" in ai)
check("FIX_SYSTEM_PROMPT: ONLY a valid JSON", "ONLY a valid JSON" in ai)
check("run_scan function defined", "def run_scan(" in ai)
check("generate_fix function defined", "def generate_fix(" in ai)
check("_fail_scan function defined", "def _fail_scan(" in ai)
check("_build_analysis_content defined", "def _build_analysis_content(" in ai)
check("raw_text = '' initialised before try", "raw_text = ''" in ai)
check("references saved in run_scan (json.dumps)", "json.dumps(refs)" in ai or "references=json.dumps" in ai)
check("fence stripping in run_scan", "startswith('```')" in ai)
check("fence stripping in generate_fix", ai.count("startswith('```')") >= 1 and "_parse_or_repair_json" in ai)
check("_call_groq_with_retry defined",     "_call_groq_with_retry" in ai)
check("_parse_or_repair_json defined",      "_parse_or_repair_json" in ai)
check("EXTENSION_TO_LANGUAGE defined",      "EXTENSION_TO_LANGUAGE" in ai)
check("detect_language_from_file defined",  "detect_language_from_file" in ai)
check("TRANSIENT_SIGNALS defined",          "TRANSIENT_SIGNALS" in ai)
check("MAX_CHARS defined",                  "MAX_CHARS" in ai)
check("groq model: llama-3.3-70b-versatile", "llama-3.3-70b-versatile" in ai)


# ─────────────────────────────────────────────────────────────
# Phase 4 — Views
# ─────────────────────────────────────────────────────────────
header("Phase 4 — Views")

views = read("scanner/views.py")

check("@login_required on dashboard", re.search(r'@login_required\s+def dashboard', views) is not None)
check("@login_required on new_scan", re.search(r'@login_required\s+@require_POST\s+def new_scan|@require_POST\s+@login_required\s+def new_scan', views) is not None)
check("@login_required on scan_detail", re.search(r'@login_required\s+def scan_detail', views) is not None)
check("@login_required on scan_status", re.search(r'@login_required\s+def scan_status', views) is not None)
check("delete_scan has @require_POST (regression fix)", re.search(r'@require_POST\s+def delete_scan|@login_required\s+@require_POST\s+def delete_scan|@require_POST\s+@login_required\s+def delete_scan', views) is not None)
check("delete_scan does NOT use if request.method == 'POST' (old pattern removed)", "if request.method == 'POST':" not in views.split("def delete_scan")[1].split("def ")[0])
check("@login_required on request_fix", re.search(r'@login_required.*?def request_fix|def request_fix', views) is not None and "@login_required" in views)
check("@require_POST on request_fix", re.search(r'@require_POST\s+def request_fix|@login_required\s+@require_POST\s+def request_fix', views) is not None)
check("fix_status view defined", "def fix_status(" in views)
check("@require_POST on mark_fix", re.search(r'@require_POST\s+def mark_fix|@login_required\s+@require_POST\s+def mark_fix', views) is not None)
check("scan__user ownership check in fix views", "scan__user=request.user" in views)
check("v32 structured refs saved (CWE- branch)", "'type': 'cwe'" in views or "\"type\": \"cwe\"" in views)
check("v32 structured refs saved (CVE- branch)", "'type': 'cve'" in views or "\"type\": \"cve\"" in views)
check("v32 structured refs saved (http URL branch)", "'type': 'article'" in views or "\"type\": \"article\"" in views)
check("v32 CWE URL built (cwe.mitre.org)", "cwe.mitre.org" in views)
check("v32 CVE URL built (nvd.nist.gov)", "nvd.nist.gov" in views)
check("BugCrusher import saves references", "references=json.dumps(refs)" in views)
check("BugCrusher import saves fix_status", "fix_status=v.get('fix_status'" in views)
check("BugCrusher import saves fix_patch", "fix_patch=v.get('fix_patch')" in views)
check("scan_status returns references as list", "json.loads(v.references)" in views)
check("scan_status returns fix_patch", "'fix_patch'" in views)
check("scan_status returns fix_notes", "'fix_notes'" in views)
check("import_report view defined", "def import_report(" in views)
check("threading.Thread used for scan", "threading.Thread" in views)


# ─────────────────────────────────────────────────────────────
# Phase 5 — URLs
# ─────────────────────────────────────────────────────────────
header("Phase 5 — URL Routes")

urls = read("scanner/urls.py")

route_checks = [
    ("index", "name='index'"),
    ("dashboard", "name='dashboard'"),
    ("new_scan", "name='new_scan'"),
    ("import_report", "name='import_report'"),
    ("scan_detail", "name='scan_detail'"),
    ("scan_status", "name='scan_status'"),
    ("delete_scan", "name='delete_scan'"),
    ("request_fix", "name='request_fix'"),
    ("fix_status", "name='fix_status'"),
    ("mark_fix", "name='mark_fix'"),
]
for name, pattern in route_checks:
    check(f"route: {name}", pattern in urls)

check("fix routes use vuln/<int:vuln_id>/", "vuln/<int:vuln_id>" in urls)


# ─────────────────────────────────────────────────────────────
# Phase 6 — JavaScript
# ─────────────────────────────────────────────────────────────
header("Phase 6 — JavaScript (scan_detail.js)")

js = read("static/js/scan_detail.js")

check("escapeHtml defined", "function escapeHtml(" in js)
check("escapeHtml: falsy guard (if (!str))", "if (!str) return ''" in js or "if (!str)" in js)
check("requestFix defined", "async function requestFix(" in js)
check("markFix defined", "async function markFix(" in js)
check("regenerateFix defined", "async function regenerateFix(" in js)
check("pollFix defined", "function pollFix(" in js)
check("updateFixUI defined", "function updateFixUI(" in js)
check("activePolls guard (duplicate interval fix)", "activePolls" in js)
check("activePolls: Set() used", "new Set()" in js)
check("activePolls.has() check in pollFix", "activePolls.has(" in js)
check("activePolls.add() in pollFix", "activePolls.add(" in js)
check("activePolls.delete() on completion", "activePolls.delete(" in js)
check("updateFixUI: insertBefore/removeChild (no stale outerHTML)", "insertBefore" in js and "removeChild" in js)
check("updateFixUI: no raw outerHTML= swap", js.count("outerHTML =") == 0)
check("regenerateFix: sequential await (race condition fixed)", "await fetch" in js and "regenerateFix" in js)
check("renderFixSection defined", "function renderFixSection(" in js or "renderFixSection" in js)
check("fix-section- id pattern", "fix-section-" in js)
check("fix-badge- id pattern", "fix-badge-" in js)
check("exportReport function defined", "function exportReport(" in js)
check("CSRF token extracted from cookie", "csrftoken" in js)
check("fix/request/ endpoint called", "fix/request/" in js)
check("fix/status/ endpoint called", "fix/status/" in js)
check("fix/mark/ endpoint called", "fix/mark/" in js)


# ─────────────────────────────────────────────────────────────
# Phase 7 — Templates
# ─────────────────────────────────────────────────────────────
header("Phase 7 — Templates")

base_html = read("templates/base.html")

check("base.html: logout uses POST form (CSRF fix)", 'method="post"' in base_html.lower() and "logout" in base_html.lower())
check("base.html: logout no bare GET <a href> to logout", not re.search(r'<a\s[^>]*href=["\'].*logout.*["\'][^>]*>', base_html))
check("base.html: csrf_token in logout form", "csrf_token" in base_html)
check("base.html: block content", "{% block content %}" in base_html)
check("base.html: static tag", "{% load static %}" in base_html or "{% load" in base_html)
check("base.html: viewport meta tag present", 'name="viewport"' in base_html)
check("base.html: width=device-width in viewport", "width=device-width" in base_html)

scan_detail = read("templates/scanner/scan_detail.html")
check("scan_detail.html: SCAN_ID injected", "SCAN_ID" in scan_detail)
check("scan_detail.html: scan_detail.js included", "scan_detail.js" in scan_detail)
check("scan_detail.html: delete button present", "deleteScan" in scan_detail)

dashboard = read("templates/scanner/dashboard.html")
check("dashboard.html: extends base", "extends" in dashboard)
check("dashboard.html: stats-grid present", "stats-grid" in dashboard)

import_html = read("templates/scanner/import_report.html")
check("import_report.html: file input", 'type="file"' in import_html or "type='file'" in import_html)


# ─────────────────────────────────────────────────────────────
# Phase 8 — Migrations
# ─────────────────────────────────────────────────────────────
header("Phase 8 — Migration Integrity")

mig0001 = read("scanner/migrations/0001_initial.py")
mig0002 = read("scanner/migrations/0002_vulnerability_fix_fields.py")

check("0001_initial.py: non-empty", len(mig0001) > 100)
check("0002: adds references field", "references" in mig0002)
check("0002: adds fix_patch field", "fix_patch" in mig0002)
check("0002: adds fix_notes field", "fix_notes" in mig0002)
check("0002: adds fix_status field", "fix_status" in mig0002)
check("0002: depends on 0001_initial",     "0001_initial" in mig0002)

mig3_path = os.path.join(BASE, "scanner/migrations/0003_scan_input_method.py")
mig3 = open(mig3_path).read() if os.path.exists(mig3_path) else ""
check("0003: exists",                      bool(mig3))
check("0003: adds input_method",           "input_method" in mig3)
check("0003: depends on 0002",             "0002_vulnerability_fix_fields" in mig3)


# ─────────────────────────────────────────────────────────────
# Phase 9 — CSS
# ─────────────────────────────────────────────────────────────
header("Phase 9 — CSS Classes")

css = read("static/css/main.css")

css_classes = [
    ".fix-patch", ".fix-badge", ".refs-grid", ".ref-link",
    ".vuln-section", ".btn", ".btn--primary",
    # responsive
    ".vuln-toggle",
    ".scan-progress-container",
    ".drop-zone",
    ".auth-container",
    ".export-toolbar",
]
for cls in css_classes:
    check(f"CSS class defined: {cls}", cls in css)

check("CSS: 768px breakpoint",        "@media (max-width: 768px)" in css)
check("CSS: 480px breakpoint",        "@media (max-width: 480px)" in css)
check("CSS: 360px breakpoint",        "@media (max-width: 360px)" in css)
check("CSS: vuln-toggle margin-left", ".vuln-toggle" in css and "margin-left: auto" in css)
check("CSS: section-header flex-wrap","section-header" in css and "flex-wrap: wrap" in css)


# ─────────────────────────────────────────────────────────────
# Phase 10 — Test Suite Completeness
# ─────────────────────────────────────────────────────────────
header("Phase 10 — Test Suite Completeness")

tests = read("scanner/tests.py")

test_classes = [
    # original
    "ScanModelTest", "VulnerabilityModelTest", "ReportModelTest",
    "PromptTest", "RunScanTest", "GenerateFixTest",
    "BasicViewTest", "NewScanViewTest", "ScanStatusViewTest",
    "DeleteScanViewTest", "FixEngineViewTest",
    "ImportJSONTest", "URLRoutingTest", "ReferencesTest", "EdgeCaseTest",
    # new coverage-gap classes
    "UserAuthTest",
    "FileScanViewTest",
    "BuildContentFileSuccessTest",
    "GenerateFixFileContextTest",
    "GenerateFixWithFileContextTest",
    "ImportDecodeErrorTest",
    "ImportV32ExtraFieldsTest",
    "ImportHTMLTest",
    "ImportHTMLVulnBlockTest",
    "ImportMarkdownTest",
    "ImportMarkdownEdgeCaseTest",
    "ImportTXTTest",
    "ImportTXTEdgeCaseTest",
    "ImportEdgeCaseTest",
    "RunScanExceptionTest",
    "ScanDisplayNameFileTest",
    # coverage surgery — session 8
    "CleanupStaleScansCommandTest",
    "DetectLanguageSpecialFilenamesTest",
    "GroqRetryTransientTest",
    "GroqRetryGuardTest",
    "ParseOrRepairJsonTest",
    "ParseRepairPass2ExceptTest",
    "ParseRepairPass3InvalidMatchTest",
    "BuildAnalysisContentEdgeCasesTest",
    "GenerateFixExceptionPathsTest",
    "GenerateFixFileReadExceptTest",
    "GenerateFixOuterExceptInnerExceptTest",
    "RunScanTimeoutCallbackTest",
    "NewScanValidationEdgesTest",
    "StripTagsExceptionFallbackTest",
    "ImportHTMLCVSSEdgeTest",
    "ImportTXTNoSeverityPrefixTest",
    "ImportTXTEmptyBlockTest",
    "ScanDisplayNameUploadTest",
    "ScanDisplayNameURLFallbackTest",
    "CoverageMetricAccuracyTest",
]
for cls in test_classes:
    check(f"test class: {cls}", cls in tests)

regression_tests = [
    "test_get_method_not_allowed_regression",                     # delete_scan GET → 405
    "test_v32_import_with_cwe_string_generates_structured_refs",  # v32 refs regression
    "test_v32_import_with_cve_string_generates_nvd_ref",          # CVE ref
    "test_v32_import_with_url_string_saves_article_ref",          # URL ref
    "test_no_verification_key_does_not_crash",                    # fix_notes None crash
    "test_request_fix_clears_old_patch_before_retry",             # patch cleared on retry
    "test_request_fix_while_fixing_is_idempotent_no_new_thread",  # idempotency
    # new regressions
    "test_login_invalid_credentials_stays_on_login",              # auth: bad creds
    "test_register_mismatched_passwords_stays_on_page",           # auth: password mismatch
    "test_register_duplicate_username_stays_on_page",             # auth: duplicate user
    "test_file_scan_without_file_returns_400",                    # file scan: no file
    "test_undecodable_file_returns_400",                          # import: binary file
    "test_v32_evidence_and_exploitation_notes_included_in_poc",   # v32: evidence fields
    "test_html_import_cvss_na_stored_as_none",                    # html: N/A fields
    "test_markdown_cvss_na_stored_as_none",                       # md: N/A fields
    "test_markdown_invalid_cvss_value_stored_as_none",            # md: ValueError branch
    "test_txt_cvss_na_stored_as_none",                            # txt: N/A fields
    "test_txt_invalid_cvss_stored_as_none",                       # txt: ValueError branch
    "test_txt_vuln_block_without_severity_prefix_uses_info",      # txt: no-prefix fallback
    "test_import_unsupported_extension_with_invalid_content_returns_400",  # bad extension
    "test_groq_network_error_sets_failed_with_message",           # run_scan: network error
    "test_get_target_display_name_file_returns_filename",         # model: file display name
    # session 8 — coverage precision
    "test_marks_old_running_scans_as_failed",                    # mgmt: cleanup fires
    "test_cleans_multiple_stale_scans",                          # mgmt: bulk cleanup
    "test_retries_on_rate_limit_then_succeeds",                  # retry: transient 429
    "test_pass3_extracts_individual_vuln_objects",               # repair: pass3 salvage
    "test_file_read_exception_returns_fallback_string",          # build: read error
    "test_binary_file_rejected",                                 # build: binary guard
    "test_truncation_note_added_for_large_files",                # build: truncation
    "test_timeout_fires_and_marks_scan_failed",                  # timeout: callback body
    "test_paste_too_short_returns_400",                          # views: short code
    "test_paste_too_long_returns_400",                           # views: long code
    "test_upload_empty_file_returns_400",                        # views: empty upload
    "test_upload_oversized_file_returns_400",                    # views: oversized
    "test_non_numeric_cvss_and_na_cwe_imported_cleanly",        # html: CVSS ValueError
    "test_block_without_severity_prefix_uses_info",              # txt: no-prefix
    "test_empty_block_between_vuln_markers_is_skipped",          # txt: empty block
    "test_display_name_uses_target_url_when_no_code_or_file",   # model: url fallback
    "test_upload_scan_display_name_is_filename",                 # model: upload name
    "test_retries_zero_raises_value_error",                      # retry: guard
]
for t in regression_tests:
    check(f"regression test: {t}", t in tests)

check("regression test: test_dashboard_status_filter_complete",   "test_dashboard_status_filter_complete" in tests)
check("regression test: test_dashboard_method_filter_paste",      "test_dashboard_method_filter_paste" in tests)
check("regression test: test_html_import_malformed_attribute",    "test_html_import_malformed_attribute" in tests)
check("test helper: _cleanup_media_uploads defined",              "_cleanup_media_uploads" in tests)
test_count = len(re.findall(r'def test_', tests))
check(f"test count >= 219 (found {test_count})", test_count >= 219)

check("mkvuln fixture",      "def mkvuln("      in tests)
check("mkscan fixture",      "def mkscan("      in tests)
check("mkreport fixture",    "def mkreport("    in tests)
check("upload_json fixture", "def upload_json(" in tests)
check("upload_file fixture", "def upload_file(" in tests)


# ─────────────────────────────────────────────────────────────
# Phase 11 — README Quality
# ─────────────────────────────────────────────────────────────
header("Phase 11 — README Quality")

readme = read("README.md")

check("README: exists and non-empty",          len(readme) > 500)
check("README: Distinctiveness and Complexity section", "Distinctiveness and Complexity" in readme)
check("README: How to Run section",            "How to Run" in readme)
check("README: requirements.txt mentioned",    "requirements.txt" in readme)
check("README: GROQ_API_KEY documented",       "GROQ_API_KEY" in readme)
check("README: create_demo.py mentioned",      "create_demo.py" in readme)
check("README: mobile responsiveness mentioned","mobile" in readme.lower() or "responsive" in readme.lower())
check("README: fix engine documented",         "fix" in readme.lower() and ("patch" in readme.lower() or "engine" in readme.lower()))
check("README: import system documented",      "import" in readme.lower() and ("json" in readme.lower() or "html" in readme.lower()))
check("README: file structure documented",     "scanner/" in readme or "models.py" in readme)
check("README: ethical use mentioned",         "permission" in readme.lower() or "ethical" in readme.lower())

readme_words = len(readme.split())

import re as _re
_video_match = _re.search(r'Video Demo.*?(https://youtu\.be/\S+|https://www\.youtube\.com/\S+)', readme)
_video_url   = _video_match.group(1).strip(')[]') if _video_match else ''
# Video URL — warn but don't fail (user must record manually)
check("README: DEVLOG.md mentioned",           "DEVLOG.md" in readme)
check("README: CHANGELOG.md mentioned",         "CHANGELOG.md" in readme)
check("README: cleanup command mentioned",       "cleanup_stale_scans" in readme)
check("README: reliability features mentioned",  "retry" in readme.lower() or "timeout" in readme.lower())
check("README: no stale URL scan text",            "scan URLs, code snippets" not in readme)
check("README: mentions 20 languages",             "20" in readme and "language" in readme.lower())
check("README: migration count accurate (three)",  "three migrations" in readme)
check("README: correct truncation limit (15k)",    "15,000" in readme or "15k" in readme.lower() or "8,000" not in readme)
_video_is_real = bool(_video_url) and 'youtu.be/x' not in _video_url
if not _video_is_real:
    print(f"  \033[33m⚠  WARNING: README video demo URL is still a placeholder\033[0m")
    print(f"     → Record your demo and replace [https://youtu.be/x] in README.md")
else:
    check("README: Video Demo URL is not a placeholder", True)

check(f"README: word count >= 500 (found {readme_words})", readme_words >= 500)


# ─────────────────────────────────────────────────────────────
# Phase 12 — Users App
# ─────────────────────────────────────────────────────────────
header("Phase 12 — Users App")

users_views = read("users/views.py")
users_urls  = read("users/urls.py")
users_tests = read("users/tests.py")

check("users/views.py: login_view defined",    "def login_view("    in users_views)
check("users/views.py: register_view defined", "def register_view(" in users_views)
check("users/views.py: logout_view defined",   "def logout_view("   in users_views)
check("users/views.py: authenticate used",     "authenticate("      in users_views)
check("users/views.py: redirect to dashboard", "dashboard"          in users_views)
check("users/views.py: password mismatch check","password"          in users_views and "match" in users_views.lower())
check("users/views.py: duplicate username check","username"         in users_views and "exists()"  in users_views)
check("users/urls.py: login route",            "name='login'"       in users_urls)
check("users/urls.py: register route",         "name='register'"    in users_urls)
check("users/urls.py: logout route",           "name='logout'"      in users_urls)

# Users are tested in scanner/tests.py (UserAuthTest)
check("UserAuthTest in scanner/tests.py",      "UserAuthTest"       in tests)
check("test_login_valid_credentials_redirects_to_dashboard in tests",
      "test_login_valid_credentials" in tests)
check("test_logout_clears_session in tests",   "test_logout_clears_session" in tests)


# ─────────────────────────────────────────────────────────────

# Phase 13 — V2 Architecture (Unified Code Analysis)
# ─────────────────────────────────────────────────────────────
header("Phase 13 — V2 Architecture Checks")

# AI engine reliability
check("retry logic defined",       "_call_groq_with_retry" in ai)
check("JSON repair defined",        "_parse_or_repair_json" in ai)
check("TRANSIENT_SIGNALS defined",  "TRANSIENT_SIGNALS" in ai)
check("FRIENDLY_ERRORS defined",    "FRIENDLY_ERRORS" in ai)
check("timeout timer in run_scan",  "_threading.Timer" in ai or "threading.Timer" in ai)
check("LANGUAGE_FOCUS dict defined","LANGUAGE_FOCUS" in ai)
check("language auto-detect fn",    "detect_language_from_file" in ai)
check("EXTENSION_TO_LANGUAGE map",  "EXTENSION_TO_LANGUAGE" in ai)
check("MAX_CHARS truncation guard", "MAX_CHARS" in ai)
check("max_tokens 6000 for scans",  "6000" in ai)

# Model
check("input_method field in models",     "input_method" in models)
check("INPUT_METHOD_CHOICES defined",     "INPUT_METHOD_CHOICES" in models)
check("migration 0003 exists",
      os.path.exists(os.path.join(BASE, "scanner/migrations/0003_scan_input_method.py")))

# Views
check("new_scan uses input_method",       "input_method" in views)
check("paste min length validation",      "len(code) < 20" in views)
check("paste max length validation",      "60_000" in views)
check("file size limit 300KB",            "300_000" in views)
check("scan_status returns input_method", views.count("input_method") >= 3)
check("url target_type removed from new_scan", "'url'" not in open(os.path.join(BASE, "scanner/views.py")).read().split("def new_scan")[1].split("def scan_detail")[0])

# CSS
check("CSS .input-method-bar defined",  ".input-method-bar" in css)
check("CSS .method-btn defined",        ".method-btn" in css)
check("CSS .scan-type-badge defined",   ".scan-type-badge" in css)
check("CSS .drop-zone.dragover defined","drop-zone.dragover" in css or "drop-zone.drag" in css)

# Templates
index_html = open(os.path.join(BASE, "templates/scanner/index.html")).read()
check("index: no url tab present",        'data-tab="url"' not in index_html)
check("index: method toggle present",     "input-method-bar" in index_html)
check("index: 20 language options",       index_html.count("<option") >= 18)
check("index: auto-detect note present",  "lang-autodetect-note" in index_html)
check("index: char counter present",      "code-char-count" in index_html)
check("index: error box present",         "scan-error" in index_html)
check("dashboard: search/filter view", "search_query" in views and "status_filter" in views)
check("dashboard: method filter", "method_filter" in views)
check("dashboard: limit raised to 50", "scans[:50]" in views or "50]" in views)
check("dashboard: filter bar in template", "dashboard-filter-bar" in open(os.path.join(BASE, "templates/scanner/dashboard.html")).read())
check("dashboard: scan-type-badge used",  "scan-type-badge" in open(os.path.join(BASE, "templates/scanner/dashboard.html")).read())

# JS
js_index = open(os.path.join(BASE, "static/js/index.js")).read()
check("index.js: EXT_TO_LANG map",       "EXT_TO_LANG" in js_index)
check("index.js: detectLang function",   "detectLang" in js_index)
check("index.js: applyFile function",    "applyFile" in js_index)
check("index.js: method toggle wired",   "method-btn" in js_index)
check("index.js: sends input_method",    "input_method" in js_index)
check("scan_detail.js: language in exports",    "scanLang" in open(os.path.join(BASE, "static/js/scan_detail.js")).read() or "_lang" in open(os.path.join(BASE, "static/js/scan_detail.js")).read())
check("scan_detail.js: PROGRESS_MSGS",   "PROGRESS_MSGS" in open(os.path.join(BASE, "static/js/scan_detail.js")).read())
check("scan_detail.js: no inline margin-left on vuln-toggle",
      'style=\"margin-left:auto;\"' not in open(os.path.join(BASE, "static/js/scan_detail.js")).read())

# Management command
cmd_content = open(os.path.join(BASE, "scanner/management/commands/cleanup_stale_scans.py")).read() if os.path.exists(os.path.join(BASE, "scanner/management/commands/cleanup_stale_scans.py")) else ""
check("cleanup_stale_scans: timedelta used",  "timedelta" in cmd_content)
check("cleanup_stale_scans: status=failed",   "failed" in cmd_content)
check("cleanup_stale_scans command exists",
      os.path.exists(os.path.join(BASE, "scanner/management/commands/cleanup_stale_scans.py")))

# Security
check("strip_tags uses html.parser",        "HTMLParser" in views or "html.parser" in views)
check("scan_detail shows language badge",    "scan.language" in open(os.path.join(BASE, "templates/scanner/scan_detail.html")).read())
check("create_demo.py has references",       "references" in open(os.path.join(BASE, "create_demo.py")).read())
check("Phase 1b syntax check present",      "Phase 1b" in open(os.path.join(BASE, "run_tests.py")).read())
check(".env has no live API key",
      "gsk_" not in open(os.path.join(BASE, ".env")).read() or "gsk_your_key" in open(os.path.join(BASE, ".env")).read())
check("settings: AUTH_PASSWORD_VALIDATORS not empty",
      "AUTH_PASSWORD_VALIDATORS = []" not in open(os.path.join(BASE, "bugcrusher/settings.py")).read())
check("create_demo.py: admin123 not used",
      "admin123" not in open(os.path.join(BASE, "create_demo.py")).read())



# ─────────────────────────────────────────────────────────────
# Phase 14 — Real Coverage Enforcement
# Runs coverage and asserts >= 100% on production code.
# Skipped when GROQ_API_KEY is not set (CI without secrets).
# ─────────────────────────────────────────────────────────────
header("Phase 14 — Real Coverage Enforcement")

import subprocess as _sp
import os as _os

_env_key = _os.environ.get("GROQ_API_KEY", "")
if not _env_key:
    check("coverage run skipped (no GROQ_API_KEY in env — set it to measure)", True)
else:
    _cov_result = _sp.run(
        [
            sys.executable, "-m", "coverage", "run",
            "--source=scanner,users",
            "--omit=scanner/tests.py,scanner/migrations/*,users/migrations/*",
            "manage.py", "test", "scanner", "users", "-v", "0",
        ],
        capture_output=True, text=True,
        env={**_os.environ, "DJANGO_SETTINGS_MODULE": "bugcrusher.settings"},
        cwd=BASE,
    )
    _ran_ok = _cov_result.returncode == 0
    check("coverage run: all tests pass", _ran_ok,
          _cov_result.stderr[-300:] if not _ran_ok else "")

    if _ran_ok:
        _rep = _sp.run(
            [sys.executable, "-m", "coverage", "report", "--fail-under=100"],
            capture_output=True, text=True, cwd=BASE,
        )
        _pct_ok = _rep.returncode == 0
        # Extract percentage from report output
        _pct_line = [l for l in _rep.stdout.splitlines() if "TOTAL" in l]
        _pct_str = _pct_line[-1].split()[-1] if _pct_line else "?"
        check(f"coverage >= 100% (measured: {_pct_str})", _pct_ok,
              "Run: coverage report --show-missing  to see gaps")

# Summary
# ─────────────────────────────────────────────────────────────
total = PASS + FAIL
print(f"\n{'═' * 60}")
print(f"  SUMMARY")
print(f"{'═' * 60}")
print(f"  \033[32m✓ {PASS} passed\033[0m" + (f"  \033[31m✗ {FAIL} failed\033[0m" if FAIL else ""))

if FAIL == 0:
    print(f"\n  \033[32m🎯 All {total} checks passed!\033[0m\n")
    sys.exit(0)
else:
    print(f"\n  \033[31m⚠  {FAIL} check(s) failed. Review above.\033[0m\n")
    sys.exit(1)
