import threading
import json
import re
from collections import Counter
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.middleware.csrf import get_token
from django.utils import timezone
from .models import Scan, Vulnerability, Report
from .ai_engine import run_scan, generate_fix, detect_language_from_file


# ── INDEX ─────────────────────────────────────────────────────────────────────

def index(request):
    get_token(request)
    features = [
        {'icon': '💻', 'title': 'Deep Code Review', 'desc': '20 languages. Language-specific vulnerability patterns — not generic checklists.'},
        {'icon': '📁', 'title': 'File Analysis', 'desc': 'Upload source files, configs, .env, Dockerfiles, Terraform, Kubernetes YAML.'},
        {'icon': '⚡', 'title': 'AI Fix Engine', 'desc': 'Request a code patch for any finding. Targeted before/after diff, exact vulnerable lines.'},
        {'icon': '📋', 'title': 'Bounty Reports', 'desc': 'CVSS scoring, CWE tagging, PoC with line references, export to JSON/MD/HTML/TXT.'},
    ]
    return render(request, 'scanner/index.html', {'features': features})


# ── DASHBOARD ─────────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    all_scans = Scan.objects.filter(user=request.user).prefetch_related('vulnerabilities', 'report')

    # Search and filter
    search_query  = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    method_filter = request.GET.get('method', '').strip()

    scans = all_scans
    if search_query:
        scans = scans.filter(target_code__icontains=search_query) |                 scans.filter(target_file__icontains=search_query) |                 scans.filter(language__icontains=search_query)
    if status_filter in ('pending', 'running', 'complete', 'failed'):
        scans = scans.filter(status=status_filter)
    if method_filter in ('paste', 'upload'):
        scans = scans.filter(input_method=method_filter)

    # Stats always computed from all scans (unfiltered)
    total_scans     = all_scans.count()
    completed_scans = all_scans.filter(status='complete').count()
    total_vulns     = sum(s.vulnerability_count for s in all_scans[:200])
    critical_vulns  = sum(s.critical_count for s in all_scans[:200])

    context = {
        'scans': scans.order_by('-created_at')[:50],
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'critical_vulns': critical_vulns,
        'completed_scans': completed_scans,
        'search_query': search_query,
        'status_filter': status_filter,
        'method_filter': method_filter,
    }
    return render(request, 'scanner/dashboard.html', context)


# ── NEW SCAN ──────────────────────────────────────────────────────────────────

@login_required
@require_POST
def new_scan(request):
    """Accept pasted code or uploaded file. Both route to the unified analysis pipeline."""
    input_method = request.POST.get('input_method', 'paste')

    if input_method not in ('paste', 'upload'):
        return JsonResponse({'error': 'Invalid input method.'}, status=400)

    scan = Scan(user=request.user, target_type='code', input_method=input_method)

    if input_method == 'paste':
        code = request.POST.get('target_code', '').strip()
        language = request.POST.get('language', 'unknown').strip().lower()

        if not code:
            return JsonResponse({'error': 'No code provided.'}, status=400)
        if len(code) < 20:
            return JsonResponse({'error': 'Too short to analyze — paste at least 20 characters of meaningful code.'}, status=400)
        if len(code) > 60_000:
            return JsonResponse({'error': 'Code exceeds 60,000 character limit. Paste the most security-relevant section.'}, status=400)

        scan.target_code = code
        scan.language = language or 'unknown'

    else:  # upload
        uploaded_file = request.FILES.get('target_file')
        if not uploaded_file:
            return JsonResponse({'error': 'No file selected.'}, status=400)
        if uploaded_file.size == 0:
            return JsonResponse({'error': 'Uploaded file is empty.'}, status=400)
        if uploaded_file.size > 300_000:
            return JsonResponse({'error': 'File exceeds 300 KB. Upload a smaller file or paste the key section.'}, status=400)

        # Auto-detect language; allow override from form
        detected = detect_language_from_file(uploaded_file.name)
        language = request.POST.get('language', '').strip().lower() or detected
        scan.target_file = uploaded_file
        scan.language = language or 'unknown'

    scan.save()
    thread = threading.Thread(target=run_scan, args=(scan.id,))
    thread.daemon = True
    thread.start()
    return JsonResponse({'scan_id': scan.id})


# ── SCAN DETAIL / STATUS ──────────────────────────────────────────────────────

@login_required
def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    return render(request, 'scanner/scan_detail.html', {'scan': scan})


@login_required
def scan_status(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    data = {
        'status': scan.status,
        'error_message': scan.error_message,
        'target_type': scan.target_type,
        'input_method': scan.input_method,
        'language': scan.language or 'unknown',
    }

    if scan.status == 'complete':
        vulns = scan.vulnerabilities.all()
        report = getattr(scan, 'report', None)
        data['report'] = {
            'executive_summary': report.executive_summary if report else '',
            'risk_score': report.risk_score if report else 0,
        }
        data['vulnerabilities'] = [
            {
                'id': v.id,
                'title': v.title,
                'severity': v.severity,
                'vuln_type': v.vuln_type,
                'description': v.description,
                'proof_of_concept': v.proof_of_concept,
                'remediation': v.remediation,
                'cvss_score': v.cvss_score,
                'cwe_id': v.cwe_id,
                'references': json.loads(v.references) if v.references else [],
                'fix_status': v.fix_status,
                'fix_patch': v.fix_patch,
                'fix_notes': v.fix_notes,
            }
            for v in vulns
        ]
    return JsonResponse(data)


@login_required
@require_POST
def delete_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    scan.delete()
    return JsonResponse({'success': True})


# ── FIX ENGINE ────────────────────────────────────────────────────────────────

@login_required
@require_POST
def request_fix(request, vuln_id):
    vuln = get_object_or_404(Vulnerability, id=vuln_id, scan__user=request.user)
    if vuln.fix_status == 'fixing':
        return JsonResponse({'status': 'fixing', 'message': 'Fix already in progress.'})
    vuln.fix_status = 'fixing'
    vuln.fix_patch = None
    vuln.fix_notes = None
    vuln.save()
    thread = threading.Thread(target=generate_fix, args=(vuln.id,))
    thread.daemon = True
    thread.start()
    return JsonResponse({'status': 'fixing'})


@login_required
def fix_status(request, vuln_id):
    vuln = get_object_or_404(Vulnerability, id=vuln_id, scan__user=request.user)
    return JsonResponse({
        'fix_status': vuln.fix_status,
        'fix_patch': vuln.fix_patch,
        'fix_notes': vuln.fix_notes,
    })


@login_required
@require_POST
def mark_fix(request, vuln_id):
    vuln = get_object_or_404(Vulnerability, id=vuln_id, scan__user=request.user)
    new_status = request.POST.get('status', 'fixed')
    if new_status not in ('fixed', 'wontfix', 'unfixed'):
        return JsonResponse({'error': 'Invalid status'}, status=400)
    vuln.fix_status = new_status
    vuln.save()
    return JsonResponse({'fix_status': vuln.fix_status})


# ── IMPORT ────────────────────────────────────────────────────────────────────

@login_required
def import_report(request):
    if request.method == 'GET':
        return render(request, 'scanner/import_report.html')

    uploaded = request.FILES.get('report_file')
    if not uploaded:
        return JsonResponse({'error': 'No file uploaded'}, status=400)

    try:
        raw = uploaded.read().decode('utf-8')
    except Exception as e:
        return JsonResponse({'error': f'Could not read file: {e}'}, status=400)

    fname = uploaded.name.lower()

    try:
        if fname.endswith('.json'):
            scan = _ingest_json(request.user, json.loads(raw))
        elif fname.endswith(('.html', '.htm')):
            scan = _ingest_html(request.user, raw)
        elif fname.endswith(('.md', '.markdown')):
            scan = _ingest_markdown(request.user, raw)
        elif fname.endswith('.txt'):
            scan = _ingest_txt(request.user, raw)
        else:
            try:
                scan = _ingest_json(request.user, json.loads(raw))
            except Exception:
                return JsonResponse({'error': 'Unsupported file type. Use .json, .html, .md, or .txt'}, status=400)

        return JsonResponse({'scan_id': scan.id})
    except Exception as e:
        return JsonResponse({'error': f'Import failed: {e}'}, status=400)


# ── INGEST: JSON ──────────────────────────────────────────────────────────────

def _ingest_json(user, data):
    is_v32 = 'scan_info' in data or (
        bool(data.get('vulnerabilities')) and
        'type' in (data['vulnerabilities'][0] if data['vulnerabilities'] else {})
    )

    if is_v32:
        scan_info = data.get('scan_info', {})
        target_url = scan_info.get('target', 'imported')
        raw_vulns = data.get('vulnerabilities', [])

        scan = Scan.objects.create(
            user=user, target_type='code', input_method='paste',
            target_url=target_url if target_url.startswith('http') else 'https://imported',
            status='complete', completed_at=timezone.now(),
        )

        sev_counts = Counter(v.get('severity', 'info').lower() for v in raw_vulns)
        summary = (
            f"Imported scan of {target_url}. "
            f"Discovered {len(raw_vulns)} vulnerabilities: "
            f"{sev_counts.get('critical',0)} critical, {sev_counts.get('high',0)} high, "
            f"{sev_counts.get('medium',0)} medium, {sev_counts.get('low',0)} low. "
            f"Scanned {scan_info.get('urls_scanned','?')} URLs with {scan_info.get('requests','?')} requests."
        )
        risk = min(100, sev_counts.get('critical',0)*10 + sev_counts.get('high',0)*5 +
                   sev_counts.get('medium',0)*2 + sev_counts.get('low',0))

        Report.objects.create(scan=scan, executive_summary=summary,
                               risk_score=risk, raw_ai_response=json.dumps(scan_info))

        sev_map = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}
        for v in raw_vulns:
            refs = v.get('references', [])
            cwe = next((r for r in refs if r.startswith('CWE-')), None)
            structured_refs = []
            for ref in refs:
                if ref.startswith('CWE-'):
                    structured_refs.append({'label': ref, 'url': f'https://cwe.mitre.org/data/definitions/{ref[4:]}.html', 'type': 'cwe'})
                elif ref.startswith('CVE-'):
                    structured_refs.append({'label': ref, 'url': f'https://nvd.nist.gov/vuln/detail/{ref}', 'type': 'cve'})
                elif ref.startswith('http'):
                    structured_refs.append({'label': ref, 'url': ref, 'type': 'article'})
            poc = v.get('payload', '')
            if v.get('evidence'):
                poc = f"Payload: {poc}\nEvidence: {v['evidence']}"
            if v.get('exploitation_notes'):
                poc += f"\nNotes: {v['exploitation_notes']}"
            Vulnerability.objects.create(
                scan=scan,
                title=v.get('type', 'Unknown'),
                severity=sev_map.get(v.get('severity','info').lower(), 'info'),
                vuln_type=v.get('type', 'Unknown'),
                description=(
                    f"{v.get('evidence','')}\n\nURL: {v.get('url','')}\n"
                    f"Parameter: {v.get('parameter','')}\nMethod: {v.get('method','')}\n"
                    f"Detection: {v.get('detection_method','')}\n"
                    f"Confidence: {v.get('confidence','')} ({v.get('confidence_pct','')}%)"
                ).strip(),
                proof_of_concept=poc,
                remediation=v.get('remediation', ''),
                cvss_score=v.get('cvss_score'),
                cwe_id=cwe,
                references=json.dumps(structured_refs) if structured_refs else None,
            )
    else:
        target = data.get('target_url', 'imported')
        raw_vulns = data.get('vulnerabilities', [])

        scan = Scan.objects.create(
            user=user, target_type='code', input_method='paste',
            target_url=target if target.startswith('http') else 'https://imported',
            status='complete', completed_at=timezone.now(),
        )
        Report.objects.create(
            scan=scan,
            executive_summary=data.get('executive_summary', 'Imported report.'),
            risk_score=data.get('risk_score', 0),
            raw_ai_response='imported',
        )
        for v in raw_vulns:
            refs = v.get('references', [])
            Vulnerability.objects.create(
                scan=scan,
                title=v.get('title', 'Unknown'),
                severity=v.get('severity', 'info'),
                vuln_type=v.get('vuln_type', 'Unknown'),
                description=v.get('description', ''),
                proof_of_concept=v.get('proof_of_concept', ''),
                remediation=v.get('remediation', ''),
                cvss_score=v.get('cvss_score'),
                cwe_id=v.get('cwe_id'),
                references=json.dumps(refs) if refs else None,
                fix_status=v.get('fix_status', 'unfixed'),
                fix_patch=v.get('fix_patch'),
                fix_notes=v.get('fix_notes'),
            )
    return scan


# ── INGEST: HTML ──────────────────────────────────────────────────────────────

def _ingest_html(user, raw):
    def strip_tags(s):
        """Strip HTML tags using stdlib html.parser — handles malformed HTML."""
        from html.parser import HTMLParser
        class _Stripper(HTMLParser):
            def __init__(self):
                super().__init__()
                self._parts = []
            def handle_data(self, data):
                self._parts.append(data)
            def get_text(self):
                return ' '.join(self._parts).strip()
        p = _Stripper()
        try:
            p.feed(s)
            return p.get_text()
        except Exception:
            return re.sub(r'<[^>]+>', ' ', s).strip()

    def get_between(text, start_marker, end_marker):
        try:
            s = text.index(start_marker) + len(start_marker)
            e = text.index(end_marker, s)
            return strip_tags(text[s:e]).strip()
        except ValueError:
            return ''

    scan_id_match = re.search(r'Scan #(\d+)', raw)
    risk_match = re.search(r'<div class="score-value"[^>]*>(\d+)<', raw)
    risk_score = int(risk_match.group(1)) if risk_match else 0

    summary = get_between(raw, '# executive_summary', '</p>')
    if not summary:
        summary = get_between(raw, 'Executive Summary</h2>', '</div>')
    if not summary:
        summary = 'Imported from HTML report.'

    scan = Scan.objects.create(
        user=user, target_type='code', input_method='paste',
        target_url='https://imported-html-report',
        status='complete', completed_at=timezone.now(),
    )
    Report.objects.create(scan=scan, executive_summary=summary,
                           risk_score=risk_score, raw_ai_response='html-import')

    vuln_blocks = re.findall(
        r'<div class="vuln"[^>]*>(.*?)</div>\s*(?=<div class="vuln"|<footer|$)',
        raw, re.DOTALL
    )
    sev_map = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}

    for block in vuln_blocks:
        title_m = re.search(r'<h3[^>]*>.*?</span>\s*(.*?)</h3>', block, re.DOTALL)
        title = strip_tags(title_m.group(1)).strip() if title_m else 'Unknown'
        sev_m = re.search(r'class="badge badge--(\w+)"', block)
        sev = sev_map.get(sev_m.group(1) if sev_m else 'info', 'info')

        def get_td(label):
            m = re.search(rf'<th>{label}</th>\s*<td>(.*?)</td>', block, re.DOTALL)
            return strip_tags(m.group(1)).strip() if m else ''

        vuln_type = get_td('Type') or title
        cvss_raw = get_td('CVSS Score')
        try:
            cvss = float(cvss_raw) if cvss_raw and cvss_raw != 'N/A' else None
        except ValueError:
            cvss = None
        cwe = get_td('CWE') or None
        if cwe == 'N/A':
            cwe = None

        desc_m = re.search(r'# Description</strong><br>(.*?)</p>', block, re.DOTALL)
        desc = strip_tags(desc_m.group(1)).strip() if desc_m else ''
        poc_m = re.search(r'# Proof of Concept</strong></p>\s*<pre>(.*?)</pre>', block, re.DOTALL)
        poc = strip_tags(poc_m.group(1)).strip() if poc_m else ''
        rem_m = re.search(r'# Remediation</strong><br>(.*?)</p>', block, re.DOTALL)
        rem = strip_tags(rem_m.group(1)).strip() if rem_m else ''

        Vulnerability.objects.create(
            scan=scan, title=title, severity=sev, vuln_type=vuln_type,
            description=desc, proof_of_concept=poc, remediation=rem,
            cvss_score=cvss, cwe_id=cwe,
        )

    return scan


# ── INGEST: MARKDOWN ──────────────────────────────────────────────────────────

def _ingest_markdown(user, raw):
    lines = raw.split('\n')
    risk_m = re.search(r'\*\*Risk Score:\*\*\s*(\d+)', raw)
    risk_score = int(risk_m.group(1)) if risk_m else 0

    summary = ''
    in_summary = False
    for line in lines:
        if line.strip() == '## Executive Summary':
            in_summary = True
            continue
        if in_summary:
            if line.startswith('##') or line.strip() == '---':
                break
            if line.strip():
                summary += line.strip() + ' '
    summary = summary.strip() or 'Imported from Markdown report.'

    scan = Scan.objects.create(
        user=user, target_type='code', input_method='paste',
        target_url='https://imported-markdown-report',
        status='complete', completed_at=timezone.now(),
    )
    Report.objects.create(scan=scan, executive_summary=summary,
                           risk_score=risk_score, raw_ai_response='md-import')

    vuln_sections = re.split(r'\n### \d+\.', raw)
    sev_map = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}

    for section in vuln_sections[1:]:
        section_lines = section.strip().split('\n')
        title = section_lines[0].strip() if section_lines else 'Unknown'

        def get_table_val(label):
            m = re.search(rf'\|\s*\*\*{label}\*\*\s*\|\s*(.*?)\s*\|', section)
            return m.group(1).strip() if m else ''

        sev_raw = get_table_val('Severity')
        sev_clean = re.sub(r'[🔴🟠🟡🔵⚪]\s*', '', sev_raw).strip().lower()
        sev = sev_map.get(sev_clean, 'info')
        vuln_type = get_table_val('Type') or title
        cvss_raw = get_table_val('CVSS Score')
        try:
            cvss = float(cvss_raw) if cvss_raw and cvss_raw != 'N/A' else None
        except ValueError:
            cvss = None
        cwe = get_table_val('CWE') or None
        if cwe == 'N/A':
            cwe = None

        def get_section_text(label):
            m = re.search(rf'\*\*{label}\*\*\n\n(.*?)(?=\n\*\*|\n---|\Z)', section, re.DOTALL)
            return m.group(1).strip() if m else ''

        desc = get_section_text('Description')
        rem  = get_section_text('Remediation')
        poc_m = re.search(r'\*\*Proof of Concept\*\*\n\n```\n?(.*?)```', section, re.DOTALL)
        poc = poc_m.group(1).strip() if poc_m else ''

        if title:
            Vulnerability.objects.create(
                scan=scan, title=title, severity=sev, vuln_type=vuln_type,
                description=desc, proof_of_concept=poc, remediation=rem,
                cvss_score=cvss, cwe_id=cwe,
            )

    return scan


# ── INGEST: TXT ───────────────────────────────────────────────────────────────

def _ingest_txt(user, raw):
    lines = raw.split('\n')
    risk_m = re.search(r'Risk Score\s*:\s*(\d+)', raw)
    risk_score = int(risk_m.group(1)) if risk_m else 0

    summary = ''
    in_summary = False
    for line in lines:
        if 'EXECUTIVE SUMMARY' in line:
            in_summary = True
            continue
        if in_summary:
            if re.match(r'^[=\-]{10,}', line) or 'VULNERABILITY FINDINGS' in line:
                break
            if line.strip():
                summary += line.strip() + ' '
    summary = summary.strip() or 'Imported from TXT report.'

    scan = Scan.objects.create(
        user=user, target_type='code', input_method='paste',
        target_url='https://imported-txt-report',
        status='complete', completed_at=timezone.now(),
    )
    Report.objects.create(scan=scan, executive_summary=summary,
                           risk_score=risk_score, raw_ai_response='txt-import')

    vuln_blocks = re.split(r'\n\[\d+\]', raw)
    sev_map = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}

    for block in vuln_blocks[1:]:
        block = block.strip()
        if not block:
            continue
        first_line = block.split('\n')[0].strip()
        sev_title_m = re.match(r'(\w+)\s+[—\-]+\s+(.*)', first_line)
        if sev_title_m:
            sev = sev_map.get(sev_title_m.group(1).lower(), 'info')
            title = sev_title_m.group(2).strip()
        else:
            sev = 'info'
            title = first_line

        def get_field(label):
            m = re.search(rf'{label}\s*:\s*(.*)', block)
            return m.group(1).strip() if m else ''

        vuln_type = get_field('Type') or title
        cvss_raw = get_field('CVSS Score')
        try:
            cvss = float(cvss_raw) if cvss_raw and cvss_raw != 'N/A' else None
        except ValueError:
            cvss = None
        cwe = get_field('CWE') or None
        if cwe == 'N/A':
            cwe = None

        def get_block_text(label):
            m = re.search(rf'{label}:\n(.*?)(?=\n[A-Z]+:|$)', block, re.DOTALL)
            return m.group(1).strip() if m else ''

        desc = get_block_text('DESCRIPTION')
        poc  = get_block_text('PROOF OF CONCEPT')
        rem  = get_block_text('REMEDIATION')

        if title:
            Vulnerability.objects.create(
                scan=scan, title=title, severity=sev, vuln_type=vuln_type,
                description=desc, proof_of_concept=poc, remediation=rem,
                cvss_score=cvss, cwe_id=cwe,
            )

    return scan
