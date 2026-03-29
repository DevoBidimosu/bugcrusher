"""
Run with: python create_demo.py
Creates a superuser + demo scan with fake vulnerability data for UI testing.
"""
import os, json, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bugcrusher.settings')
django.setup()

from django.contrib.auth.models import User
from scanner.models import Scan, Vulnerability, Report
from django.utils import timezone

# Create superuser
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@bugcrusher.local', 'BugCrusher@2026!')
    print("✓ Superuser created: admin / BugCrusher@2026!")
else:
    print("- Superuser already exists")

# Create demo user
user, created = User.objects.get_or_create(username='hunter')
if created:
    user.set_password('hunter123')
    user.save()
    print("✓ Demo user created: hunter / hunter123")

# Create a completed demo scan
scan = Scan.objects.create(
    user=user,
    target_type='url',
    target_url='https://demo.example.com/api/v1/users?id=1',
    status='complete',
    completed_at=timezone.now(),
)

Report.objects.create(
    scan=scan,
    executive_summary=(
        "The target endpoint exhibits multiple critical security vulnerabilities that pose "
        "significant risk to the application and its users. SQL injection and reflected XSS "
        "were identified as the most severe issues requiring immediate remediation."
    ),
    risk_score=78,
)

vulns = [
    {
        'title': 'SQL Injection via id Parameter',
        'severity': 'critical',
        'vuln_type': 'SQL Injection',
        'description': 'The id query parameter is directly interpolated into a SQL query without parameterization, allowing an attacker to manipulate database queries and extract sensitive data.',
        'proof_of_concept': "GET /api/v1/users?id=1' OR '1'='1\n# Returns all users instead of one",
        'remediation': 'Use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
        'cvss_score': 9.8,
        'cwe_id': 'CWE-89',
        'references': json.dumps([
            {'label': 'CWE-89: SQL Injection', 'url': 'https://cwe.mitre.org/data/definitions/89.html', 'type': 'cwe'},
            {'label': 'OWASP: SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection', 'type': 'owasp'},
            {'label': 'PortSwigger: SQL Injection', 'url': 'https://portswigger.net/web-security/sql-injection', 'type': 'article'},
        ]),
    },
    {
        'title': 'Reflected Cross-Site Scripting (XSS)',
        'severity': 'high',
        'vuln_type': 'XSS',
        'description': 'User-supplied input from the id parameter is reflected in the error response without HTML encoding, allowing script injection into the page context.',
        'proof_of_concept': "GET /api/v1/users?id=<script>alert(document.cookie)</script>",
        'remediation': 'Encode all user-controlled data before rendering in HTML. Use Content-Security-Policy headers.',
        'cvss_score': 7.2,
        'cwe_id': 'CWE-79',
        'references': json.dumps([
            {'label': 'CWE-79: Cross-site Scripting', 'url': 'https://cwe.mitre.org/data/definitions/79.html', 'type': 'cwe'},
            {'label': 'OWASP: XSS Prevention', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', 'type': 'owasp'},
        ]),
    },
    {
        'title': 'Missing Security Headers',
        'severity': 'medium',
        'vuln_type': 'Security Misconfiguration',
        'description': 'The response is missing several important security headers: X-Content-Type-Options, X-Frame-Options, and Strict-Transport-Security.',
        'proof_of_concept': "curl -I https://demo.example.com/api/v1/users?id=1\n# Headers absent from response",
        'remediation': 'Add security headers via middleware: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security: max-age=31536000.',
        'cvss_score': 5.3,
        'cwe_id': 'CWE-693',
        'references': json.dumps([
            {'label': 'CWE-693: Protection Mechanism Failure', 'url': 'https://cwe.mitre.org/data/definitions/693.html', 'type': 'cwe'},
            {'label': 'OWASP: Security Headers', 'url': 'https://owasp.org/www-project-secure-headers/', 'type': 'owasp'},
        ]),
    },
    {
        'title': 'Verbose Error Messages',
        'severity': 'low',
        'vuln_type': 'Information Disclosure',
        'description': 'SQL error messages are returned directly to the client, revealing database engine, table structure, and query details.',
        'proof_of_concept': "Error: You have an error in your SQL syntax near 'users WHERE id='",
        'remediation': 'Implement generic error pages in production. Log detailed errors server-side only.',
        'cvss_score': 3.1,
        'cwe_id': 'CWE-209',
        'references': json.dumps([
            {'label': 'CWE-209: Error Message Information Exposure', 'url': 'https://cwe.mitre.org/data/definitions/209.html', 'type': 'cwe'},
        ]),
    },
    {
        'title': 'No Rate Limiting on API Endpoint',
        'severity': 'info',
        'vuln_type': 'Brute Force',
        'description': 'The endpoint has no rate limiting, allowing automated enumeration of user IDs and brute force attacks.',
        'proof_of_concept': "for i in range(1, 10000): requests.get(f'/api/v1/users?id={i}')",
        'remediation': 'Implement rate limiting (e.g., 100 requests/minute per IP). Consider authentication requirements.',
        'cvss_score': None,
        'cwe_id': 'CWE-307',
        'references': json.dumps([
            {'label': 'CWE-307: Improper Restriction of Excessive Auth Attempts', 'url': 'https://cwe.mitre.org/data/definitions/307.html', 'type': 'cwe'},
            {'label': 'OWASP: Brute Force Attack', 'url': 'https://owasp.org/www-community/attacks/Brute_force_attack', 'type': 'owasp'},
        ]),
    },
]

for v in vulns:
    Vulnerability.objects.create(scan=scan, **v)

print(f"✓ Demo scan created: Scan #{scan.id} with {len(vulns)} vulnerabilities")
print("\nReady! Run: python manage.py runserver")
print("Need a free API key? Get Groq at https://console.groq.com")
print("Login at http://127.0.0.1:8000/login/ with: hunter / hunter123")
print(f"View demo scan: http://127.0.0.1:8000/scan/{scan.id}/")
