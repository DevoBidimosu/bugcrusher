// BugCrusher AI — Index page: unified code/file scan submission

// ── Extension → language map (mirrors server-side detect_language_from_file) ──
const EXT_TO_LANG = {
  py: 'python', pyw: 'python',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'javascript', tsx: 'javascript',
  php: 'php', java: 'java', kt: 'java',
  go: 'go', rb: 'ruby', rs: 'rust',
  c: 'c', h: 'c', cpp: 'c', cc: 'c', hpp: 'c',
  cs: 'csharp', swift: 'swift',
  sh: 'bash', bash: 'bash', zsh: 'bash', ps1: 'powershell',
  sql: 'sql', tf: 'terraform', tfvars: 'terraform',
  yml: 'yaml', yaml: 'yaml', json: 'json', toml: 'json', xml: 'yaml',
  env: 'dotenv', ini: 'ini', cfg: 'ini', conf: 'ini', config: 'ini',
};
const SPECIAL_NAMES = {
  'dockerfile': 'dockerfile', 'dockerfile.prod': 'dockerfile',
  'dockerfile.dev': 'dockerfile', 'dockerfile.staging': 'dockerfile',
  'makefile': 'bash', 'gemfile': 'ruby', 'rakefile': 'ruby',
  '.env': 'dotenv', '.env.local': 'dotenv',
  '.env.production': 'dotenv', '.env.staging': 'dotenv',
};

function detectLang(filename) {
  const lower = filename.toLowerCase();
  const base  = lower.split('/').pop();
  if (SPECIAL_NAMES[lower] || SPECIAL_NAMES[base]) return SPECIAL_NAMES[lower] || SPECIAL_NAMES[base];
  const ext = base.includes('.') ? base.split('.').pop() : '';
  return EXT_TO_LANG[ext] || 'unknown';
}

// ── DOM refs ──────────────────────────────────────────────────
const langSelect    = document.getElementById('input-lang');
const autoDetNote   = document.getElementById('lang-autodetect-note');
const codeInput     = document.getElementById('input-code');
const charCount     = document.getElementById('code-char-count');
const dropZone      = document.getElementById('drop-zone');
const fileInput     = document.getElementById('input-file');
const fileNameEl    = document.getElementById('file-name');
const submitBtn     = document.getElementById('submit-scan');
const errorBox      = document.getElementById('scan-error');
const panelPaste    = document.getElementById('panel-paste');
const panelUpload   = document.getElementById('panel-upload');

if (!submitBtn) {
  // Not authenticated — nothing to wire up
} else {

// ── Input method toggle ───────────────────────────────────────
document.querySelectorAll('.method-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.method-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (btn.dataset.method === 'paste') {
      panelPaste.style.display = 'block';
      panelUpload.style.display = 'none';
    } else {
      panelPaste.style.display = 'none';
      panelUpload.style.display = 'block';
    }
    clearError();
  });
});

// ── Character counter ─────────────────────────────────────────
codeInput.addEventListener('input', () => {
  const len = codeInput.value.length;
  if (len === 0) { charCount.textContent = ''; return; }
  const color = len > 55000
    ? 'var(--severity-critical)'
    : len > 40000 ? 'var(--severity-high)' : 'var(--dimmer)';
  charCount.style.color = color;
  charCount.textContent = `${len.toLocaleString()} / 60,000 chars`;
});

// ── File handling ─────────────────────────────────────────────
function applyFile(file) {
  if (!file) return;
  const size = (file.size / 1024).toFixed(1);
  fileNameEl.textContent = `${file.name}  (${size} KB)`;
  fileNameEl.style.display = 'block';
  dropZone.style.borderColor = 'var(--green)';

  const detected = detectLang(file.name);
  const optionExists = langSelect.querySelector(`option[value="${detected}"]`);
  if (optionExists) {
    langSelect.value = detected;
    autoDetNote.style.display = 'block';
  } else {
    langSelect.value = 'unknown';
    autoDetNote.style.display = 'none';
  }
  clearError();
}

fileInput.addEventListener('change', () => { if (fileInput.files[0]) applyFile(fileInput.files[0]); });
dropZone.addEventListener('click',   () => fileInput.click());

dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (!file) return;
  try {
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
  } catch (_) { /* Safari fallback — file still usable via e.dataTransfer */ }
  applyFile(file);
});

// ── Error helpers ─────────────────────────────────────────────
function showError(msg) {
  errorBox.textContent = `// error: ${msg}`;
  errorBox.style.display = 'block';
}
function clearError() {
  errorBox.style.display = 'none';
  errorBox.textContent = '';
}

// ── Submit ────────────────────────────────────────────────────
submitBtn.addEventListener('click', async () => {
  clearError();
  const activeMethod = document.querySelector('.method-btn.active').dataset.method;
  const lang   = langSelect.value;
  const csrf   = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
  const fd     = new FormData();

  fd.append('input_method', activeMethod);
  fd.append('language', lang);

  if (activeMethod === 'paste') {
    const code = codeInput.value.trim();
    if (!code)       { showError('Please paste some code before scanning.'); return; }
    if (code.length < 20) { showError('Too short — paste at least 20 characters of meaningful code.'); return; }
    fd.append('target_code', code);
  } else {
    const file = fileInput.files[0];
    if (!file) { showError('Please select or drop a file before scanning.'); return; }
    fd.append('target_file', file);
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'initializing scan...';

  try {
    const res  = await fetch('/scan/new/', { method: 'POST', headers: { 'X-CSRFToken': csrf }, body: fd });
    const data = await res.json();
    if (data.scan_id) {
      window.location.href = `/scan/${data.scan_id}/`;
    } else {
      showError(data.error || 'Submission failed. Please try again.');
      submitBtn.disabled = false;
      submitBtn.textContent = 'execute_scan --type=code_analysis';
    }
  } catch (err) {
    showError('Network error. Please try again.');
    submitBtn.disabled = false;
    submitBtn.textContent = 'execute_scan --type=code_analysis';
  }
});

} // end if submitBtn
