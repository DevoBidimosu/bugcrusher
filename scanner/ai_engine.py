import json
import os
import re
import time
import threading as _threading
from groq import Groq
from django.conf import settings
from django.utils import timezone
from .models import Scan, Vulnerability, Report


# ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert security researcher and bug bounty hunter with 15+ years of experience.
Your task is to analyze the provided code or file and identify real security vulnerabilities.

You MUST respond with ONLY a valid JSON object — no markdown, no code fences, no extra text — in this exact format:
{
  "executive_summary": "2-3 sentence overview of the security posture",
  "risk_score": <integer 0-100>,
  "vulnerabilities": [
    {
      "title": "Vulnerability name",
      "severity": "<critical|high|medium|low|info>",
      "vuln_type": "e.g. SQL Injection, Command Injection, Hardcoded Secret, etc.",
      "description": "Detailed technical description of the vulnerability",
      "proof_of_concept": "Line N: [exact vulnerable code]\\nExplanation of why this is exploitable",
      "remediation": "The corrected version of the vulnerable lines + explanation of the fix",
      "cvss_score": <float 0.0-10.0 or null>,
      "cwe_id": "CWE-XXX or null",
      "references": [
        {
          "label": "Human-readable title",
          "url": "https://exact-url",
          "type": "owasp|cwe|nvd|cve|docs|tool|article"
        }
      ]
    }
  ]
}

CRITICAL RULES:
- Only report vulnerabilities ACTUALLY PRESENT in the submitted code — never invent generic findings
- Quote the exact vulnerable line(s) in proof_of_concept using "Line N: [code]" format
- Provide the corrected version of those specific lines in remediation
- If no vulnerabilities exist, return an empty vulnerabilities array
- Include 3-5 highly reliable references per finding (OWASP owasp.org, CWE cwe.mitre.org/data/definitions/, NVD nvd.nist.gov, PortSwigger portswigger.net/web-security, official docs)
- Only include URLs you are highly confident actually exist
- Return ONLY the JSON object. No markdown. No explanation. No code fences."""


# ── LANGUAGE-SPECIFIC FOCUS PROMPTS ───────────────────────────────────────────

LANGUAGE_FOCUS = {
    'python': """
PYTHON-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: f-string or % formatting in raw SQL / ORM .raw() / .extra()
- Command injection: subprocess with shell=True, os.system(), os.popen() with user input
- Insecure deserialization: pickle.loads(), yaml.load() without Loader=yaml.SafeLoader, marshal
- Path traversal: open(), os.path.join() with unsanitized user input
- SSTI: Jinja2/Mako Template(user_input) rendering user-controlled strings
- Hardcoded secrets: API keys, passwords, tokens, private keys in source or config
- Weak crypto: MD5/SHA1 for passwords, random.random() for tokens, DES
- SSRF: requests.get(user_url) without URL allowlist
- XXE: xml.etree with external entity resolution on user-supplied XML
- Django: missing @login_required, @csrf_exempt, DEBUG=True, AUTH_PASSWORD_VALIDATORS=[], raw QuerySet with format strings
- Flask: app.run(debug=True), missing SECRET_KEY, open redirect via redirect(request.args.get('next'))
- Code execution: eval(user_input), exec(user_input), __import__() with user data""",

    'javascript': """
JAVASCRIPT/NODE.JS-SPECIFIC VULNERABILITIES TO HUNT:
- Prototype pollution: recursive merge / lodash.merge() with __proto__ or constructor keys
- eval() / new Function() / setTimeout(string) with user-controlled data
- DOM XSS: innerHTML, outerHTML, document.write(), dangerouslySetInnerHTML with user data
- Node.js RCE: child_process.exec/execSync with shell:true and user input
- Path traversal: fs.readFile/writeFile with user path segments
- ReDoS: nested quantifiers or alternation in regex applied to user input
- JWT: algorithm:none, symmetric/asymmetric key confusion, missing expiry check
- SSRF: axios/fetch/http.request with user-controlled URL and no allowlist
- Hardcoded secrets: API keys, JWT secrets, database passwords in source
- require() with user-controlled module path
- Template literals: `<div>${userInput}</div>` without sanitization""",

    'typescript': """
TYPESCRIPT-SPECIFIC VULNERABILITIES TO HUNT:
- All JavaScript/Node.js vulnerabilities above
- Type assertion abuse: (userInput as any) bypassing type safety on security-critical paths
- Unsafe casting defeating input validation: 'as unknown as SafeType'
- Missing type guards before using external API data in security-sensitive operations""",

    'php': """
PHP-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: string interpolation in mysqli_query/PDO without prepared statements
- RCE: eval(), system(), exec(), passthru(), shell_exec(), preg_replace(/e), assert(string)
- File inclusion: include/require with user-controlled path (LFI/RFI)
- Deserialization: unserialize() with user input — PHP object injection via __wakeup/__destruct
- XSS: echo/print without htmlspecialchars(); missing ENT_QUOTES
- Type juggling: loose == with user input (0 == "0abc", "" == false) enabling auth bypass
- SSRF: file_get_contents(user_url), curl_exec with user URL
- Path traversal: fopen/file_get_contents with user-controlled path
- Hardcoded credentials in config files
- extract() with user input — variable injection
- register_globals, allow_url_include=On in php.ini""",

    'java': """
JAVA-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: Statement.executeQuery() with string concatenation
- XXE: DocumentBuilderFactory/SAXParserFactory without disabling external entities
- Deserialization gadget chains: ObjectInputStream.readObject() with user-supplied bytes
- SSRF: URL.openConnection() / HttpClient with user-controlled URL
- Path traversal: new File(baseDir, userInput) without canonical path validation
- LDAP injection: DirContext.search() with unsanitized input
- EL injection: EL expressions evaluated from user input (Spring/JSF/Struts)
- Log4j JNDI: logger.info(userInput) without sanitization (CVE-2021-44228)
- Spring: @RequestMapping without CSRF; mass assignment via @ModelAttribute
- Hardcoded credentials in .properties files or source
- java.util.Random for security tokens (use SecureRandom)""",

    'go': """
GO-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: fmt.Sprintf() in db.Query/db.Exec
- Command injection: exec.Command() with user-controlled arguments
- Path traversal: os.Open/os.ReadFile with filepath.Join() not validated against base dir
- SSRF: http.Get(userURL) with no host allowlist
- Template injection: text/template (not html/template) rendering user-controlled data
- Hardcoded credentials in source or config structs
- Race conditions: shared mutable state accessed from goroutines without sync.Mutex
- Integer overflow: unchecked arithmetic on user-supplied integers for buffer sizing
- Goroutine leaks: blocking on channels that are never closed
- math/rand instead of crypto/rand for security-sensitive values
- InsecureSkipVerify: true in tls.Config""",

    'rust': """
RUST-SPECIFIC VULNERABILITIES TO HUNT:
- Unsafe blocks: raw pointer dereference, pointer arithmetic — audit every unsafe{} block
- FFI safety: C function calls without input validation
- Integer overflow: wrapping arithmetic in release builds, unchecked index operations
- Hardcoded secrets in source or config files
- SSRF: reqwest/hyper with user-controlled URL
- Path traversal: std::fs operations with user-controlled path components
- DoS: catastrophic regex, unbounded recursion with user-controlled depth
- unwrap()/expect() on untrusted data in security-critical paths
- Lifetime violations and use-after-free patterns in unsafe blocks""",

    'c': """
C-SPECIFIC VULNERABILITIES TO HUNT:
- Buffer overflow: strcpy/strcat/sprintf/gets/scanf without bounds (always flag these)
- Format string: printf(user_input) — use printf("%s", user_input)
- Integer overflow/underflow: arithmetic before malloc/calloc without overflow check
- Use-after-free: pointer used after free(); double-free patterns
- Off-by-one: loop condition <=len instead of <len
- Null pointer dereference: unchecked return from malloc/calloc/fopen
- Hardcoded credentials and cryptographic keys
- Deprecated insecure functions: gets(), mktemp(), tmpnam()
- rand() for security randomness (use /dev/urandom or getrandom())
- TOCTOU race: check-use gap in file operations""",

    'cpp': """
C++-SPECIFIC VULNERABILITIES TO HUNT:
- All C vulnerabilities above, plus:
- Iterator invalidation after container mutation (erase, push_back, resize)
- Type confusion: reinterpret_cast / C-style casts in security-critical code
- Missing virtual destructor on polymorphic base class
- Using moved-from objects after std::move
- Resource leaks when exceptions thrown without RAII
- Smart pointer misuse: shared_ptr cycles, raw pointer aliasing with smart pointers""",

    'csharp': """
C#-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: SqlCommand with string concatenation
- XSS: HtmlHelper.Raw() / Response.Write() with user input
- Deserialization: BinaryFormatter.Deserialize(), TypeNameHandling.All in Json.NET
- XXE: XmlTextReader/XmlDocument without ProhibitDtd=true
- Path traversal: Server.MapPath / Path.Combine with user input
- Open redirect: Response.Redirect with user-controlled URL
- SSRF: HttpClient/WebClient with user-controlled URL
- Hardcoded credentials in connection strings or source
- ASP.NET: missing ValidateAntiForgeryToken, VIEWSTATE without MAC
- Insecure crypto: MD5/SHA1, hardcoded IV""",

    'ruby': """
RUBY-SPECIFIC VULNERABILITIES TO HUNT:
- SQL injection: string interpolation in ActiveRecord where()/find_by_sql()
- Command injection: system(), exec(), backticks with user input
- Mass assignment: Rails strong parameters bypass
- SSTI: ERB with user-controlled template strings
- Insecure deserialization: Marshal.load() with user-controlled data
- ReDoS: Ruby regex catastrophic backtracking with user input
- Path traversal: File.read/File.open with unsanitized user paths
- Hardcoded credentials in database.yml or initializers
- Rails: protect_from_forgery disabled, force_ssl missing, secret_key_base exposed
- Symbol DoS: converting user input to symbols (params.to_sym)""",

    'kotlin': """
KOTLIN-SPECIFIC VULNERABILITIES TO HUNT:
- All Java vulnerabilities above
- !! operator on untrusted data causing NullPointerException in security-critical paths
- Coroutine misuse: shared mutable state across Dispatchers.IO without synchronization
- Reflection: KClass.createInstance() with user-controlled class names""",

    'swift': """
SWIFT-SPECIFIC VULNERABILITIES TO HUNT:
- Hardcoded credentials: API keys in source, keys in Info.plist
- Insecure data storage: NSUserDefaults or unencrypted SQLite for sensitive data
- Weak crypto: CommonCrypto MD5/SHA1, predictable key derivation
- Transport security: NSAllowsArbitraryLoads in Info.plist
- Logging sensitive data: print()/NSLog() with tokens, passwords, PII
- Path traversal: FileManager with user-controlled path components
- Force unwrap (!) on untrusted optional data in security-critical paths""",

    'bash': """
BASH/SHELL-SPECIFIC VULNERABILITIES TO HUNT:
- Command injection: unquoted variables in command substitution — use "${var}" not $var
- Hardcoded passwords, API keys, tokens in scripts
- World-writable files: chmod 777/666 on sensitive files
- Insecure temporary files: predictable names in /tmp; TOCTOU race (use mktemp)
- curl/wget piped to bash: curl http://... | bash
- Missing error handling: no set -e, set -o pipefail, set -u
- Path injection: $PATH manipulation via user-controlled directory
- sudo with NOPASSWD or wildcard in sudoers""",

    'powershell': """
POWERSHELL-SPECIFIC VULNERABILITIES TO HUNT:
- Command injection: Invoke-Expression with user input
- Hardcoded credentials: ConvertTo-SecureString with plaintext, hardcoded PSCredential
- Download-and-execute: IEX(New-Object Net.WebClient).DownloadString() from user URL
- -ExecutionPolicy Bypass used in production scripts
- Sensitive data in clear-text log/transcript output""",

    'sql': """
SQL-SPECIFIC VULNERABILITIES TO HUNT:
- Stored procedure injection: EXEC/EXECUTE with string concatenation
- Dynamic SQL: sp_executesql with unsanitized parameters
- Overly permissive GRANT: wildcard (*) permissions on sensitive objects
- Hardcoded credentials in stored procedures or linked server definitions
- Sensitive PII/financial data in unencrypted columns
- Users with blank passwords or sa account enabled
- OPENROWSET, BULK INSERT, or LINKED SERVERS with public access""",

    'terraform': """
TERRAFORM-SPECIFIC VULNERABILITIES TO HUNT:
- Hardcoded credentials: AWS access keys, passwords in resource blocks or variable defaults
- Overly permissive IAM: Action:* or Resource:*, wildcard Principal in S3 bucket policy
- Public S3 buckets: acl="public-read", block_public_acls=false
- Unencrypted storage: EBS/RDS/S3 without encryption=true
- Open security groups: cidr_blocks=["0.0.0.0/0"] on port 22, 3389, or database ports
- Missing TLS: load balancers with HTTP-only listeners
- IMDSv2 not enforced on EC2 instances
- Missing CloudTrail, VPC flow logs, S3 access logging""",

    'yaml': """
YAML/CONFIG-SPECIFIC VULNERABILITIES TO HUNT:
- Hardcoded credentials: passwords, API keys, tokens, connection strings in any field
- Kubernetes: privileged:true containers, hostPath mounts, missing securityContext, containers running as root, missing resource limits, automountServiceAccountToken:true
- Docker Compose: privileged:true, ports binding 0.0.0.0 for sensitive services, volumes mounting /etc or /var/run/docker.sock
- GitHub Actions: secrets echoed in run: steps, third-party actions not pinned to commit hash, pull_request_target with code checkout
- Missing TLS/HTTPS in service configuration""",

    'json': """
JSON-SPECIFIC VULNERABILITIES TO HUNT:
- Hardcoded API keys, tokens, passwords, connection strings
- package.json: wildcard dependency versions, scripts.postinstall running arbitrary commands
- AWS/cloud policies: Action:*, Resource:*, Principal:* overly permissive
- Public access configuration: S3 bucket policies with public read/write
- Non-HTTPS registry sources in package-lock.json""",

    'dotenv': """
.ENV FILE-SPECIFIC VULNERABILITIES TO HUNT:
- Any real API key, token, password, secret, or credential present (should never be committed)
- Weak secret values: DEBUG=True, SECRET_KEY=django-insecure-, JWT_SECRET=secret
- Database connection strings with embedded credentials
- Third-party service credentials: Stripe, Twilio, SendGrid, AWS, GCP keys
- Predictable or default values that should be randomized per-deployment""",

    'dockerfile': """
DOCKERFILE-SPECIFIC VULNERABILITIES TO HUNT:
- Running as root: no USER instruction before CMD/ENTRYPOINT
- Unpinned base images: FROM ubuntu:latest
- Secrets in build args or ENV: ARG API_KEY= or ENV PASSWORD=
- Sensitive files copied: COPY . . including .env, .git, credentials
- Exposed sensitive ports: EXPOSE 22, 3306, 5432, 6379
- curl | bash patterns: RUN curl http://... | bash
- Missing HEALTHCHECK
- Unnecessary packages installed in production image""",

    'ini': """
INI/CONFIG-SPECIFIC VULNERABILITIES TO HUNT:
- Hardcoded credentials: passwords, API keys, tokens
- Debug/development settings in production: debug=true, display_errors=On
- Default credentials: admin/admin, root with empty password
- Insecure PHP settings: allow_url_include=On, allow_url_fopen=On, expose_php=On
- Missing security headers in web server configs
- Overly permissive CORS: Access-Control-Allow-Origin: *""",

    'unknown': """
GENERAL SECURITY ANALYSIS — look for all of the following:
- Injection vulnerabilities: SQL, command, template, LDAP, XML
- Authentication and authorization flaws
- Hardcoded secrets, credentials, API keys, tokens
- Sensitive data exposure and insecure data handling
- Security misconfigurations
- Insecure cryptography and randomness
- Input validation and sanitization failures
- Path traversal and file operation vulnerabilities
- Insecure deserialization
- OWASP Top 10 considerations appropriate to the language/framework""",
}


# ── FILE EXTENSION → LANGUAGE MAPPING ────────────────────────────────────────

EXTENSION_TO_LANGUAGE = {
    'py': 'python', 'pyw': 'python',
    'js': 'javascript', 'mjs': 'javascript', 'cjs': 'javascript', 'jsx': 'javascript',
    'ts': 'typescript', 'tsx': 'typescript',
    'php': 'php', 'php3': 'php', 'php4': 'php', 'php5': 'php',
    'java': 'java', 'kt': 'kotlin', 'kts': 'kotlin',
    'go': 'go',
    'rb': 'ruby', 'rake': 'ruby',
    'rs': 'rust',
    'c': 'c', 'h': 'c',
    'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp',
    'cs': 'csharp',
    'swift': 'swift',
    'sh': 'bash', 'bash': 'bash', 'zsh': 'bash',
    'ps1': 'powershell', 'psm1': 'powershell',
    'sql': 'sql',
    'tf': 'terraform', 'tfvars': 'terraform',
    'yml': 'yaml', 'yaml': 'yaml',
    'json': 'json',
    'toml': 'json',
    'xml': 'yaml',
    'env': 'dotenv',
    'ini': 'ini', 'cfg': 'ini', 'conf': 'ini', 'config': 'ini',
    'dockerfile': 'dockerfile',
    'lua': 'unknown',
    'r': 'unknown',
    'dart': 'unknown',
    'gradle': 'unknown',
}

SPECIAL_FILENAMES = {
    'dockerfile': 'dockerfile',
    'dockerfile.prod': 'dockerfile',
    'dockerfile.dev': 'dockerfile',
    'dockerfile.staging': 'dockerfile',
    'makefile': 'bash',
    'gemfile': 'ruby',
    'rakefile': 'ruby',
    'procfile': 'bash',
    'brewfile': 'ruby',
    '.env': 'dotenv',
    '.env.local': 'dotenv',
    '.env.production': 'dotenv',
    '.env.staging': 'dotenv',
}


def detect_language_from_file(filename):
    """Detect language from filename or extension."""
    fname = filename.lower().strip('/')
    # check special full filenames first
    if fname in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[fname]
    basename = fname.split('/')[-1]
    if basename in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[basename]
    ext = basename.rsplit('.', 1)[-1] if '.' in basename else ''
    return EXTENSION_TO_LANGUAGE.get(ext, 'unknown')


# ── TRANSIENT ERROR DETECTION ─────────────────────────────────────────────────

TRANSIENT_SIGNALS = [
    'rate limit', '429', '503', '502', '500',
    'timeout', 'connection', 'temporarily unavailable',
    'service unavailable', 'overloaded',
]

FRIENDLY_ERRORS = [
    (['rate limit', '429'], 'API rate limit reached. Please wait 60 seconds and try again.'),
    (['GROQ_API_KEY not set', 'api key'], 'API key not configured. Add GROQ_API_KEY to your .env file.'),
    (['timed out', 'timeout'], 'The scan timed out. Try with a shorter code sample.'),
    (['connection', 'network'], 'Could not connect to the AI service. Check your internet connection.'),
    (['JSONDecodeError', 'could not parse', 'repair'], 'The AI returned an unexpected response. Please try again.'),
    (['token', 'context length', 'too long'], 'Input is too large for the AI model. Paste a smaller section.'),
]


def _translate_error(error_msg):
    for signals, friendly in FRIENDLY_ERRORS:
        if any(s.lower() in error_msg.lower() for s in signals):
            return friendly
    return error_msg


def _fail_scan(scan_id, error_msg):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'failed'
        scan.error_message = _translate_error(error_msg)
        scan.save()
    except Exception:
        pass


# ── GROQ RETRY WRAPPER ────────────────────────────────────────────────────────

def _call_groq_with_retry(client, messages, max_tokens, temperature, retries=3):
    """Call Groq API with exponential backoff for transient failures."""
    if retries < 1:
        raise ValueError('retries must be >= 1')
    for attempt in range(retries):
        try:
            return client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        except Exception as e:
            err_str = str(e).lower()
            is_transient = any(sig in err_str for sig in TRANSIENT_SIGNALS)
            if is_transient and attempt < retries - 1:
                time.sleep(2 ** attempt)   # 1s → 2s → 4s
                continue
            raise


# ── JSON REPAIR ───────────────────────────────────────────────────────────────

def _parse_or_repair_json(raw):
    """Parse AI response JSON, attempting repair if truncated."""
    text = raw.strip()

    # Strip markdown fences
    if text.startswith('```'):
        text = text.split('\n', 1)[-1] if '\n' in text else text[3:]
    if text.endswith('```'):
        text = text.rsplit('```', 1)[0]
    text = text.strip()

    # Pass 1: parse as-is
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Pass 2: close unclosed brackets/braces — try both closing orderings
    open_braces = text.count('{') - text.count('}')
    open_brackets = text.count('[') - text.count(']')
    for suffix in [
        (']' * open_brackets) + ('}' * open_braces),   # close inner arrays first
        ('}' * open_braces) + (']' * open_brackets),   # close inner objects first
    ]:
        if not suffix:
            break
        try:
            return json.loads(text + suffix)
        except json.JSONDecodeError:
            pass

    # Pass 3: extract individually-valid vulnerability objects
    pattern = re.compile(
        r'\{[^{}]*"title"\s*:\s*"[^"]+?"[^{}]*"severity"\s*:\s*"[^"]+?"[^{}]*\}',
        re.DOTALL
    )
    valid_vulns = []
    for match in pattern.findall(text):
        try:
            v = json.loads(match)
            if 'title' in v and 'severity' in v:
                valid_vulns.append(v)
        except json.JSONDecodeError:
            continue

    if valid_vulns:
        return {
            'executive_summary': 'Analysis was partially truncated. Results may be incomplete.',
            'risk_score': 50,
            'vulnerabilities': valid_vulns,
        }

    raise json.JSONDecodeError(
        f'Could not parse or repair AI response (length: {len(text)})', text, 0
    )


# ── CONTENT BUILDER ───────────────────────────────────────────────────────────

MAX_CHARS = 15_000   # ~3,750 tokens — leaves 6k for output


def _build_analysis_content(scan):
    """Build unified analysis prompt for both pasted code and uploaded files."""

    # ── Get the code content ──────────────────────────────────
    filename = None
    if scan.target_file and not scan.target_code:
        # Uploaded file path
        try:
            scan.target_file.open('rb')
            raw_bytes = scan.target_file.read()
            scan.target_file.close()
        except Exception as e:
            return f'File could not be read: {e}. Provide a general security assessment.'

        # Reject obviously binary files
        null_count = raw_bytes.count(b'\x00')
        if null_count > 20 or (len(raw_bytes) > 100 and null_count / len(raw_bytes) > 0.05):
            return (
                'The uploaded file appears to be binary (compiled executable, image, archive, etc). '
                'Security analysis requires readable source code or configuration text. '
                'Please upload a source file or paste its contents.'
            )

        try:
            content = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # latin-1 maps all 256 byte values — always succeeds as a fallback
            content = raw_bytes.decode('latin-1', errors='replace')

        filename = scan.target_file.name.split('/')[-1]
        source_label = f'uploaded file: {filename}'
    else:
        content = scan.target_code or ''
        source_label = f'pasted {scan.language or "code"} snippet'

    if not content.strip():
        return 'No content provided for analysis.'

    # ── Truncation ───────────────────────────────────────────
    truncation_note = ''
    if len(content) > MAX_CHARS:
        truncation_note = (
            f'\n\n[NOTE: Input was {len(content):,} characters. '
            f'Analysis covers the first {MAX_CHARS:,} characters only. '
            f'Upload a smaller file or paste the most security-relevant section for complete coverage.]'
        )
        content = content[:MAX_CHARS]

    # ── Select focus prompt ──────────────────────────────────
    lang = (scan.language or 'unknown').lower()
    # Auto-detect from filename if language wasn't set or is unknown
    if (lang == 'unknown' or not lang) and filename:
        lang = detect_language_from_file(filename)
    focus = LANGUAGE_FOCUS.get(lang, LANGUAGE_FOCUS['unknown'])

    line_count = len(content.split('\n'))

    return f"""Perform a deep, precise security vulnerability analysis on this {source_label}.

Statistics: {line_count} lines, {len(content):,} characters, language: {lang}

```{lang if lang not in ('unknown', 'dotenv') else ''}
{content}
```

{focus}

ANALYSIS REQUIREMENTS:
1. Only report vulnerabilities ACTUALLY PRESENT in the code above — do not generate generic findings
2. For each finding, quote the EXACT vulnerable line(s): "Line N: [exact code]"
3. Provide the CORRECTED version of those specific lines in the remediation field
4. If no vulnerabilities exist, return an empty vulnerabilities array
5. Assign CVSS scores based on realistic exploitability in context
6. Include 3-5 highly reliable reference URLs per finding{truncation_note}"""


# ── MAIN SCAN RUNNER ──────────────────────────────────────────────────────────

def run_scan(scan_id):
    timeout_timer = None
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'running'
        scan.save()

        groq_key = os.environ.get('GROQ_API_KEY', getattr(settings, 'GROQ_API_KEY', ''))
        if not groq_key:
            raise ValueError('GROQ_API_KEY not set. Get a free key at https://console.groq.com')

        # 120-second hard timeout — extracted so it can be exercised by tests
        def _on_timeout():
            _fail_scan(scan_id, 'Scan timed out after 120 seconds. Try with a smaller input.')

        _SCAN_TIMEOUT_SECONDS = getattr(settings, 'SCAN_TIMEOUT_SECONDS', 120)
        timeout_timer = _threading.Timer(_SCAN_TIMEOUT_SECONDS, _on_timeout)
        timeout_timer.start()

        client = Groq(api_key=groq_key)
        content = _build_analysis_content(scan)

        response = _call_groq_with_retry(
            client=client,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': content},
            ],
            max_tokens=6000,
            temperature=0.15,
        )

        raw_text = response.choices[0].message.content.strip()
        data = _parse_or_repair_json(raw_text)

        Report.objects.create(
            scan=scan,
            executive_summary=data.get('executive_summary', ''),
            risk_score=min(100, max(0, int(data.get('risk_score', 0)))),
            raw_ai_response=raw_text,
        )

        for v in data.get('vulnerabilities', []):
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
            )

        scan.status = 'complete'
        scan.completed_at = timezone.now()
        scan.save()

    except json.JSONDecodeError as e:
        _fail_scan(scan_id, f'JSONDecodeError: {e}')
    except Exception as e:
        _fail_scan(scan_id, str(e))
    finally:
        if timeout_timer:
            timeout_timer.cancel()


# ── FIX ENGINE ────────────────────────────────────────────────────────────────

FIX_SYSTEM_PROMPT = """You are an expert security engineer. Your task is to generate a concrete, working code fix for a specific vulnerability.

Respond with ONLY a valid JSON object — no markdown, no code fences, no extra text:
{
  "fix_patch": "Clear before/after diff showing exactly what lines change, plus the complete corrected code block",
  "fix_notes": "1-2 sentences explaining what was changed and why it closes the vulnerability",
  "verification": "Specific test case or proof that confirms the vulnerability is now closed"
}

Be precise and minimal — only change what is necessary to fix this specific vulnerability."""


def generate_fix(vuln_id):
    """Generate an AI code fix for a specific vulnerability. Runs in a background thread."""
    raw_text = ''
    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
        vuln.fix_status = 'fixing'
        vuln.save()

        groq_key = os.environ.get('GROQ_API_KEY', getattr(settings, 'GROQ_API_KEY', ''))
        if not groq_key:
            raise ValueError('GROQ_API_KEY not set.')

        client = Groq(api_key=groq_key)
        scan = vuln.scan

        # Build code context — try file first, then pasted code
        context_code = ''
        if scan.target_file:
            try:
                scan.target_file.open('rb')
                raw = scan.target_file.read(5000)
                scan.target_file.close()
                decoded = raw.decode('utf-8', errors='replace')
                context_code = (
                    f'\n\n## Full File Context\n'
                    f'```{scan.language or ""}\n{decoded}\n```'
                )
            except Exception:
                pass
        elif scan.target_code:
            context_code = (
                f'\n\n## Full Code Context\n'
                f'```{scan.language or ""}\n{scan.target_code[:5000]}\n```'
            )

        user_content = f"""Generate a precise, minimal code fix for the following vulnerability.

## Vulnerability Details
- **Title:** {vuln.title}
- **Type:** {vuln.vuln_type}
- **Severity:** {vuln.severity.upper()}
- **CVSS:** {vuln.cvss_score if vuln.cvss_score is not None else 'N/A'}
- **CWE:** {vuln.cwe_id or 'N/A'}

## Description
{vuln.description}

## Vulnerable Code
{vuln.proof_of_concept or 'See description above — exact line not captured.'}

## Remediation Guidance
{vuln.remediation}
{context_code}

Provide a minimal, targeted patch — only change the lines needed to fix this vulnerability.
Show a clear before/after diff."""

        response = _call_groq_with_retry(
            client=client,
            messages=[
                {'role': 'system', 'content': FIX_SYSTEM_PROMPT},
                {'role': 'user', 'content': user_content},
            ],
            max_tokens=2500,
            temperature=0.1,
        )

        raw_text = response.choices[0].message.content.strip()
        fix_data = _parse_or_repair_json(raw_text)

        verification = fix_data.get('verification', '')
        fix_notes = fix_data.get('fix_notes', '')
        if verification:
            fix_notes += '\n\nVerification: ' + verification

        vuln.fix_patch = fix_data.get('fix_patch', '')
        vuln.fix_notes = fix_notes
        vuln.fix_status = 'fixed'
        vuln.save()

    except json.JSONDecodeError:
        # Store raw response — still useful even if not JSON
        try:
            vuln = Vulnerability.objects.get(id=vuln_id)
            vuln.fix_patch = raw_text or 'AI returned an unparseable response.'
            vuln.fix_notes = 'Fix generated (raw format — JSON parse failed).'
            vuln.fix_status = 'fixed'
            vuln.save()
        except Exception:
            pass
    except Exception as e:
        try:
            vuln = Vulnerability.objects.get(id=vuln_id)
            vuln.fix_status = 'unfixed'
            vuln.fix_notes = f'Fix generation failed: {_translate_error(str(e))}'
            vuln.save()
        except Exception:
            pass
