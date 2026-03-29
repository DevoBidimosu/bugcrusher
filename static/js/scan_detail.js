// BugCrusher AI — scan detail: polling + results renderer + export

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_COLORS = {
  critical: 'var(--severity-critical)',
  high:     'var(--severity-high)',
  medium:   'var(--severity-medium)',
  low:      'var(--severity-low)',
  info:     'var(--severity-info)',
};

let pollInterval = null;
let stageIndex = 0;
const stages = ['stage-submit', 'stage-parse', 'stage-analyze', 'stage-report', 'stage-done'];

// Store results globally for export
let _reportData = null;

function advanceStage() {
  stageIndex = Math.min(stageIndex + 1, stages.length - 1);
  stages.forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (i < stageIndex) el.classList.add('done');
    else if (i === stageIndex) el.classList.add('active');
  });
}

function addTerminalLine(text, cls = '') {
  const terminal = document.getElementById('terminal-output');
  if (!terminal) return;
  const line = document.createElement('div');
  line.className = `terminal-line ${cls}`;
  line.style.animationDelay = '0s';
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

const PROGRESS_MSGS = {
  upload: [
    'reading uploaded file...',
    'identifying language and security context...',
    'running deep static analysis...',
    'generating vulnerability report...',
  ],
  paste: [
    'parsing code structure...',
    'cross-referencing CVE/CWE patterns...',
    'running deep static analysis...',
    'generating vulnerability report...',
  ],
};

async function pollStatus() {
  try {
    const res = await fetch(`/scan/${SCAN_ID}/status/`);
    const data = await res.json();

    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (dot) dot.className = `status-dot status-dot--${data.status}`;
    if (txt) txt.textContent = data.status.toUpperCase();

    if (data.status === 'running' && stageIndex < 3) {
      advanceStage();
      const method = data.input_method || 'paste';
      const msgs = PROGRESS_MSGS[method] || PROGRESS_MSGS.paste;
      addTerminalLine(msgs[Math.min(stageIndex - 1, msgs.length - 1)]);
    }

    if (data.status === 'complete') {
      clearInterval(pollInterval);
      advanceStage(); advanceStage();
      addTerminalLine('scan complete. rendering findings...', 'info');
      setTimeout(() => renderResults(data), 600);
    }

    if (data.status === 'failed') {
      clearInterval(pollInterval);
      addTerminalLine(`SCAN FAILED: ${data.error_message || 'unknown error'}`, 'err');
    }
  } catch (err) {
    console.error('Poll error:', err);
  }
}

function getRiskColor(score) {
  if (score >= 80) return 'var(--severity-critical)';
  if (score >= 60) return 'var(--severity-high)';
  if (score >= 40) return 'var(--severity-medium)';
  if (score >= 20) return 'var(--severity-low)';
  return 'var(--severity-info)';
}

function renderResults(data) {
  const container = document.getElementById('results-container');
  if (!container) { window.location.reload(); return; }

  _reportData = data; // store for export
  const { report, vulnerabilities } = data;
  const riskColor = getRiskColor(report.risk_score);
  const _scanLang   = data.language    || '';
  const _scanMethod = data.input_method || '';

  const counts = {};
  SEVERITY_ORDER.forEach(s => counts[s] = 0);
  vulnerabilities.forEach(v => counts[v.severity] = (counts[v.severity] || 0) + 1);

  container.innerHTML = `
    <!-- Export toolbar -->
    <div class="export-toolbar">
      <span class="export-toolbar-label">// export_report:</span>
      <button class="export-btn export-btn--json" onclick="exportReport('json')">JSON</button>
      <button class="export-btn export-btn--md"   onclick="exportReport('md')">Markdown</button>
      <button class="export-btn export-btn--html" onclick="exportReport('html')">HTML</button>
      <button class="export-btn export-btn--txt"  onclick="exportReport('txt')">TXT</button>
    </div>

    <div class="report-header">
      <div>
        ${_scanLang ? `<div style="font-size:0.68rem; color:var(--dim); margin-bottom:0.5rem;">// language: <span style="color:var(--green);">${escapeHtml(_scanLang)}</span>${_scanMethod ? ` &nbsp;|&nbsp; ${escapeHtml(_scanMethod)}` : ''}</div>` : ''}
        <div style="font-size:0.7rem; color:var(--dim); letter-spacing:0.2em; text-transform:uppercase; margin-bottom:0.5rem;">
          # executive_summary
        </div>
        <p style="color:#aaccaa; font-size:0.82rem; line-height:1.8; user-select:text; cursor:text;">${escapeHtml(report.executive_summary)}</p>

        <div class="risk-meter" style="margin-top:1.2rem;">
          <div class="risk-label">
            <span>risk_score</span>
            <span style="color:${riskColor};">${report.risk_score}/100</span>
          </div>
          <div class="risk-bar-track">
            <div class="risk-bar-fill" id="risk-bar" style="width:0%; background:${riskColor};"></div>
          </div>
        </div>

        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:1rem;">
          ${SEVERITY_ORDER.map(s => counts[s] > 0 ? `
            <span style="font-size:0.75rem; color:${SEVERITY_COLORS[s]}; user-select:text;">${counts[s]}x <span class="badge badge--${s}">${s}</span></span>
          ` : '').join('')}
          ${vulnerabilities.length === 0 ? '<span style="color:var(--green); font-size:0.78rem;">[+] no vulnerabilities detected</span>' : ''}
        </div>
      </div>

      <div class="report-score">
        <div class="score-ring" style="border-color:${riskColor}; box-shadow:0 0 15px ${riskColor}44;">
          <div class="score-value" style="color:${riskColor};">${report.risk_score}</div>
          <div class="score-text">risk</div>
        </div>
        <div style="font-size:0.7rem; color:var(--dim); margin-top:0.3rem;">${vulnerabilities.length} finding${vulnerabilities.length !== 1 ? 's' : ''}</div>
      </div>
    </div>

    <div class="section-header" style="margin-top:1.5rem;">
      <div class="section-title"><span>vulnerability</span>_findings</div>
      <div class="section-line"></div>
    </div>

    <div id="vuln-list">
      ${vulnerabilities.length === 0
        ? `<div class="terminal-loader" style="text-align:center; padding:2rem;">
             <span style="color:var(--green);">[+] clean — no vulnerabilities found in this target</span>
           </div>`
        : vulnerabilities.map((v, i) => renderVuln(v, i)).join('')
      }
    </div>
  `;

  setTimeout(() => {
    const bar = document.getElementById('risk-bar');
    if (bar) bar.style.width = `${report.risk_score}%`;
  }, 100);

  document.querySelectorAll('.vuln-header').forEach(header => {
    header.addEventListener('click', () => {
      const body = header.nextElementSibling;
      body.classList.toggle('open');
      header.querySelector('.vuln-toggle').textContent = body.classList.contains('open') ? '[-]' : '[+]';
    });
  });
}

function renderVuln(v, i) {
  const color = SEVERITY_COLORS[v.severity] || 'var(--dim)';
  const fixBadge = renderFixBadge(v.fix_status);
  const refsHtml = renderReferences(v.references || []);
  const fixSectionHtml = renderFixSection(v);

  return `
    <div class="vuln-card" id="vuln-card-${v.id}" style="border-left-color:${color}; animation:fadeInLine 0.3s forwards; animation-delay:${i*0.06}s; opacity:0;">
      <div class="vuln-header">
        <span class="badge badge--${v.severity}">${v.severity}</span>
        <span class="vuln-title">${escapeHtml(v.title)}</span>
        <span class="vuln-type">${escapeHtml(v.vuln_type)}</span>
        ${v.cvss_score != null ? `<span style="font-size:0.72rem; color:${color};">cvss:${v.cvss_score}</span>` : ''}
        ${v.cwe_id ? `<span style="font-size:0.7rem; color:var(--dim);">${escapeHtml(v.cwe_id)}</span>` : ''}
        <span class="fix-badge fix-badge--${v.fix_status}" id="fix-badge-${v.id}">${fixBadge}</span>
        <span class="vuln-toggle">[+]</span>
      </div>
      <div class="vuln-body">
        <div class="vuln-section">
          <div class="vuln-section-title">description</div>
          <p>${escapeHtml(v.description)}</p>
        </div>
        ${v.proof_of_concept ? `
        <div class="vuln-section">
          <div class="vuln-section-title">proof_of_concept</div>
          <pre>${escapeHtml(v.proof_of_concept)}</pre>
        </div>` : ''}
        <div class="vuln-section">
          <div class="vuln-section-title">remediation</div>
          <p style="color:var(--green2);">${escapeHtml(v.remediation)}</p>
        </div>
        ${refsHtml}
        ${fixSectionHtml}
      </div>
    </div>
  `;
}

function renderFixBadge(status) {
  const labels = { unfixed: 'unfixed', fixing: 'fixing…', fixed: '✓ fixed', wontfix: 'wontfix' };
  return labels[status] || status;
}

function renderReferences(refs) {
  if (!refs || refs.length === 0) return '';
  const typeIcons = { owasp: '🛡', cwe: '📋', nvd: '🔎', cve: '⚠', docs: '📖', tool: '🔧', article: '📰' };
  const items = refs.map(r => `
    <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" class="ref-link ref-link--${escapeHtml(r.type || 'article')}">
      <span class="ref-icon">${typeIcons[r.type] || '🔗'}</span>
      <span class="ref-label">${escapeHtml(r.label)}</span>
      <span class="ref-type">[${escapeHtml(r.type || '?')}]</span>
    </a>
  `).join('');
  return `
    <div class="vuln-section vuln-section--refs">
      <div class="vuln-section-title">// trusted_sources &amp; references</div>
      <div class="refs-grid">${items}</div>
    </div>
  `;
}

function renderFixSection(v) {
  if (v.fix_status === 'fixed' && v.fix_patch) {
    return `
      <div class="vuln-section vuln-section--fix" id="fix-section-${v.id}">
        <div class="vuln-section-title" style="color:var(--green);">// ai_generated_fix</div>
        ${v.fix_notes ? `<p style="color:var(--green2); font-size:0.8rem; margin-bottom:0.6rem;">${escapeHtml(v.fix_notes)}</p>` : ''}
        <pre class="fix-patch">${escapeHtml(v.fix_patch)}</pre>
        <div style="display:flex; gap:0.5rem; margin-top:0.6rem; flex-wrap:wrap;">
          <button class="btn btn--ghost fix-action-btn" style="font-size:0.7rem;" onclick="markFix(${v.id}, 'wontfix')">mark_wontfix</button>
          <button class="btn btn--ghost fix-action-btn" style="font-size:0.7rem;" onclick="regenerateFix(${v.id})">regenerate_fix</button>
        </div>
      </div>
    `;
  }
  if (v.fix_status === 'fixing') {
    return `
      <div class="vuln-section vuln-section--fix" id="fix-section-${v.id}">
        <div class="vuln-section-title" style="color:var(--yellow);">// ai_fix_generating <span class="terminal-cursor"></span></div>
        <p style="color:var(--dim); font-size:0.78rem;">AI is writing a code fix… polling…</p>
      </div>
    `;
  }
  if (v.fix_status === 'wontfix') {
    return `
      <div class="vuln-section vuln-section--fix" id="fix-section-${v.id}">
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
          <span style="color:var(--dim); font-size:0.75rem;">marked as won't fix</span>
          <button class="btn btn--ghost fix-action-btn" style="font-size:0.7rem;" onclick="requestFix(${v.id})">request_ai_fix</button>
        </div>
      </div>
    `;
  }
  // unfixed
  return `
    <div class="vuln-section vuln-section--fix" id="fix-section-${v.id}">
      <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
        <button class="btn btn--primary fix-action-btn" style="font-size:0.75rem;" onclick="requestFix(${v.id})">⚡ request_ai_fix</button>
        <button class="btn btn--ghost fix-action-btn" style="font-size:0.7rem;" onclick="markFix(${v.id}, 'wontfix')">mark_wontfix</button>
        <button class="btn btn--ghost fix-action-btn" style="font-size:0.7rem; color:var(--green);" onclick="markFix(${v.id}, 'fixed')">mark_fixed</button>
      </div>
    </div>
  `;
}

// ── FIX ACTIONS ──────────────────────────────────────────────

async function requestFix(vulnId) {
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
  const btn = document.querySelector(`#fix-section-${vulnId} .fix-action-btn`);
  if (btn) { btn.disabled = true; btn.textContent = 'requesting…'; }

  try {
    const res = await fetch(`/vuln/${vulnId}/fix/request/`, {
      method: 'POST', headers: { 'X-CSRFToken': csrf },
    });
    const data = await res.json();
    if (data.status === 'fixing') {
      updateFixUI(vulnId, 'fixing', null, null);
      pollFix(vulnId);
    }
  } catch (err) {
    console.error('Fix request error:', err);
    if (btn) { btn.disabled = false; btn.textContent = '⚡ request_ai_fix'; }
  }
}

async function markFix(vulnId, status) {
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
  const body = new URLSearchParams({ status });
  try {
    const res = await fetch(`/vuln/${vulnId}/fix/mark/`, {
      method: 'POST', headers: { 'X-CSRFToken': csrf }, body,
    });
    const data = await res.json();
    updateFixUI(vulnId, data.fix_status, null, null);
  } catch (err) {
    console.error('Mark fix error:', err);
  }
}

async function regenerateFix(vulnId) {
  // Sequentially: mark unfixed first, then request new fix
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
  const body = new URLSearchParams({ status: 'unfixed' });
  try {
    await fetch(`/vuln/${vulnId}/fix/mark/`, {
      method: 'POST', headers: { 'X-CSRFToken': csrf }, body,
    });
  } catch (err) { /* proceed anyway */ }
  await requestFix(vulnId);
}

const activePolls = new Set();

function pollFix(vulnId) {
  if (activePolls.has(vulnId)) return;  // already polling this vuln
  activePolls.add(vulnId);
  const interval = setInterval(async () => {
    try {
      const res = await fetch(`/vuln/${vulnId}/fix/status/`);
      const data = await res.json();
      if (data.fix_status !== 'fixing') {
        clearInterval(interval);
        activePolls.delete(vulnId);
        updateFixUI(vulnId, data.fix_status, data.fix_patch, data.fix_notes);
      }
    } catch (err) {
      clearInterval(interval);
      activePolls.delete(vulnId);
    }
  }, 2000);
}

function updateFixUI(vulnId, fixStatus, fixPatch, fixNotes) {
  // Update badge
  const badge = document.getElementById(`fix-badge-${vulnId}`);
  if (badge) {
    badge.className = `fix-badge fix-badge--${fixStatus}`;
    badge.textContent = renderFixBadge(fixStatus);
  }
  // Update fix section via a wrapper so outerHTML swap is safe
  const section = document.getElementById(`fix-section-${vulnId}`);
  if (!section) return;

  const v = { id: vulnId, fix_status: fixStatus, fix_patch: fixPatch, fix_notes: fixNotes };
  // Insert new element before the old one, then remove old
  const tmp = document.createElement('div');
  tmp.innerHTML = renderFixSection(v);
  const newSection = tmp.firstElementChild;
  if (newSection) {
    section.parentNode.insertBefore(newSection, section);
    section.parentNode.removeChild(section);
  }
}

// ── EXPORT ENGINE ──────────────────────────────────────────────

function exportReport(format) {
  if (!_reportData) return;
  const { report, vulnerabilities } = _reportData;
  const scanId = SCAN_ID;
  const ts = new Date().toISOString();

  let content, filename, mime;

  if (format === 'json') {
    const scanLang    = _reportData.language    || 'unknown';
    const scanMethod  = _reportData.input_method || 'paste';
    content = JSON.stringify({
      scan_id: scanId,
      exported_at: ts,
      language: scanLang,
      input_method: scanMethod,
      risk_score: report.risk_score,
      executive_summary: report.executive_summary,
      vulnerability_count: vulnerabilities.length,
      vulnerabilities: vulnerabilities.map(v => ({
        title: v.title,
        severity: v.severity,
        vuln_type: v.vuln_type,
        cvss_score: v.cvss_score,
        cwe_id: v.cwe_id,
        description: v.description,
        proof_of_concept: v.proof_of_concept,
        remediation: v.remediation,
        references: v.references || [],
        fix_status: v.fix_status,
        fix_patch: v.fix_patch || null,
        fix_notes: v.fix_notes || null,
      }))
    }, null, 2);
    filename = `bugcrusher_scan_${scanId}.json`;
    mime = 'application/json';

  } else if (format === 'md') {
    const severityEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
    const _lang   = _reportData.language    || 'unknown';
    const _method = _reportData.input_method || 'paste';
    content = `# BugCrusher AI — Security Report
**Scan ID:** ${scanId}  
**Language:** ${_lang}  
**Input:** ${_method}  
**Exported:** ${ts}  
**Risk Score:** ${report.risk_score}/100  
**Findings:** ${vulnerabilities.length}

---

## Executive Summary

${report.executive_summary}

---

## Vulnerability Findings

${vulnerabilities.length === 0 ? '_No vulnerabilities found._' : vulnerabilities.map((v, i) => `
### ${i+1}. ${v.title}

| Field | Value |
|-------|-------|
| **Severity** | ${(severityEmoji[v.severity] || '') + ' ' + v.severity.toUpperCase()} |
| **Type** | ${v.vuln_type} |
| **CVSS Score** | ${v.cvss_score != null ? v.cvss_score : 'N/A'} |
| **CWE** | ${v.cwe_id || 'N/A'} |

**Description**

${v.description}
${v.proof_of_concept ? `
**Proof of Concept**

\`\`\`
${v.proof_of_concept}
\`\`\`` : ''}

**Remediation**

${v.remediation}

---`).join('\n')}

_Generated by BugCrusher AI_
`;
    filename = `bugcrusher_scan_${scanId}.md`;
    mime = 'text/markdown';

  } else if (format === 'html') {
    const severityColor = { critical: '#ff0040', high: '#ff4400', medium: '#ff8000', low: '#ffff00', info: '#00ffff' };
    content = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugCrusher AI Report — Scan #${scanId}</title>
<style>
  body { background: #0a0a0a; color: #ccffcc; font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 2rem; }
  h1 { color: #00ff41; border-bottom: 1px solid #00ff4133; padding-bottom: 0.5rem; }
  h2 { color: #00ff41; font-size: 1rem; letter-spacing: 0.2em; text-transform: uppercase; margin-top: 2rem; }
  h3 { color: #aaffaa; font-size: 0.95rem; margin-top: 1.5rem; }
  .meta { color: #336633; font-size: 0.8rem; margin-bottom: 2rem; }
  .summary { background: #0d0d0d; border-left: 2px solid #00ff41; padding: 1rem; margin: 1rem 0; color: #aaccaa; }
  .risk-score { font-size: 3rem; color: #ff0040; font-weight: bold; }
  .vuln { background: #0d0d0d; border-left: 3px solid #444; padding: 1rem; margin: 1rem 0; }
  .badge { display: inline-block; padding: 0.15rem 0.4rem; border: 1px solid currentColor; font-size: 0.72rem; text-transform: uppercase; margin-right: 0.5rem; }
  table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.85rem; }
  td, th { border: 1px solid #1a331a; padding: 0.4rem 0.6rem; text-align: left; }
  th { color: #336633; background: #050505; }
  pre { background: #050505; border: 1px solid #1a331a; padding: 0.8rem; overflow-x: auto; color: #00ffff; white-space: pre-wrap; word-break: break-word; }
  .remediation { color: #00cc33; }
  footer { margin-top: 3rem; border-top: 1px solid #1a331a; padding-top: 1rem; color: #1a331a; font-size: 0.75rem; }
</style>
</head>
<body>
<h1>⬡ BugCrusher AI — Security Report</h1>
<div class="meta">
  Scan ID: #${scanId} &nbsp;|&nbsp; Exported: ${ts} &nbsp;|&nbsp; Findings: ${vulnerabilities.length}
</div>

<h2>Risk Score</h2>
<div class="risk-score">${report.risk_score}<span style="font-size:1.2rem; color:#336633;">/100</span></div>

<h2>Executive Summary</h2>
<div class="summary">${report.executive_summary}</div>

<h2>Vulnerability Findings</h2>
${vulnerabilities.length === 0 ? '<p style="color:#00ff41;">[+] No vulnerabilities found.</p>' :
  vulnerabilities.map((v, i) => {
    const c = severityColor[v.severity] || '#888';
    return `
<div class="vuln" style="border-left-color:${c}">
  <h3>
    <span class="badge" style="color:${c}">${v.severity}</span>
    ${v.title}
  </h3>
  <table>
    <tr><th>Type</th><td>${v.vuln_type}</td></tr>
    <tr><th>CVSS Score</th><td>${v.cvss_score != null ? v.cvss_score : 'N/A'}</td></tr>
    <tr><th>CWE</th><td>${v.cwe_id || 'N/A'}</td></tr>
  </table>
  <p><strong style="color:#336633"># Description</strong><br>${v.description}</p>
  ${v.proof_of_concept ? `<p><strong style="color:#336633"># Proof of Concept</strong></p><pre>${v.proof_of_concept}</pre>` : ''}
  <p class="remediation"><strong># Remediation</strong><br>${v.remediation}</p>
</div>`;
  }).join('\n')}

<footer>Generated by BugCrusher AI &nbsp;|&nbsp; ${ts}</footer>
</body>
</html>`;
    filename = `bugcrusher_scan_${scanId}.html`;
    mime = 'text/html';

  } else if (format === 'txt') {
    const line = '='.repeat(60);
    const dline = '-'.repeat(60);
    content = `${line}
BUGCRUSHER AI — SECURITY ANALYSIS REPORT
${line}
Scan ID  : ${scanId}
Exported : ${ts}
Risk Score: ${report.risk_score}/100
Findings : ${vulnerabilities.length}
${line}

EXECUTIVE SUMMARY
${dline}
${report.executive_summary}

${line}
VULNERABILITY FINDINGS
${line}
${vulnerabilities.length === 0 ? '[+] No vulnerabilities found.\n' :
  vulnerabilities.map((v, i) => `
[${i+1}] ${v.severity.toUpperCase()} — ${v.title}
${dline}
Type       : ${v.vuln_type}
CVSS Score : ${v.cvss_score != null ? v.cvss_score : 'N/A'}
CWE        : ${v.cwe_id || 'N/A'}

DESCRIPTION:
${v.description}
${v.proof_of_concept ? `\nPROOF OF CONCEPT:\n${v.proof_of_concept}\n` : ''}
REMEDIATION:
${v.remediation}
`).join('\n' + dline + '\n')}
${line}
Generated by BugCrusher AI
${line}`;
    filename = `bugcrusher_scan_${scanId}.txt`;
    mime = 'text/plain';
  }

  // Trigger download
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── UTIL ──────────────────────────────────────────────────────

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function deleteScan(id) {
  if (!confirm(`rm -rf scan::${id} — this cannot be undone. continue?`)) return;
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
  const res = await fetch(`/scan/${id}/delete/`, {
    method: 'POST', headers: { 'X-CSRFToken': csrf },
  });
  const data = await res.json();
  if (data.success) window.location.href = '/dashboard/';
  else alert('delete failed.');
}

// ── INIT ──────────────────────────────────────────────────────

if (INITIAL_STATUS === 'pending' || INITIAL_STATUS === 'running') {
  pollInterval = setInterval(pollStatus, 2500);
  pollStatus();
} else if (INITIAL_STATUS === 'complete') {
  fetch(`/scan/${SCAN_ID}/status/`).then(r => r.json()).then(renderResults);
}
