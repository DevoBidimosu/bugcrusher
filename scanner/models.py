from django.db import models
from django.contrib.auth.models import User


class Scan(models.Model):
    TARGET_TYPES = [
        ('code', 'Code / File Analysis'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('complete', 'Complete'),
        ('failed', 'Failed'),
    ]
    INPUT_METHOD_CHOICES = [
        ('paste', 'Pasted Code'),
        ('upload', 'Uploaded File'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    target_type = models.CharField(max_length=10, choices=TARGET_TYPES, default='code')
    target_url = models.URLField(blank=True, null=True)          # kept for imported reports
    target_code = models.TextField(blank=True, null=True)
    target_file = models.FileField(upload_to='uploads/', blank=True, null=True)
    language = models.CharField(max_length=50, blank=True, null=True)
    input_method = models.CharField(
        max_length=10, choices=INPUT_METHOD_CHOICES, default='paste', blank=True
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan #{self.id} - {self.input_method} - {self.status}"

    def get_target_display_name(self):
        if self.input_method == 'upload' and self.target_file:
            return self.target_file.name.split('/')[-1]
        elif self.target_code:
            snippet = (self.target_code or '')[:50]
            lang = f"[{self.language}] " if self.language and self.language != 'unknown' else ''
            return f"{lang}{snippet}..." if len(self.target_code or '') > 50 else f"{lang}{snippet}"
        elif self.target_url:
            return self.target_url
        return 'Code Analysis'

    @property
    def vulnerability_count(self):
        return self.vulnerabilities.count()

    @property
    def critical_count(self):
        return self.vulnerabilities.filter(severity='critical').count()

    @property
    def high_count(self):
        return self.vulnerabilities.filter(severity='high').count()


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    FIX_STATUS_CHOICES = [
        ('unfixed', 'Unfixed'),
        ('fixing', 'Fixing...'),
        ('fixed', 'Fixed'),
        ('wontfix', "Won't Fix"),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    vuln_type = models.CharField(max_length=100)
    description = models.TextField()
    proof_of_concept = models.TextField(blank=True, null=True)
    remediation = models.TextField()
    cvss_score = models.FloatField(blank=True, null=True)
    cwe_id = models.CharField(max_length=20, blank=True, null=True)
    references = models.TextField(blank=True, null=True)
    fix_patch = models.TextField(blank=True, null=True)
    fix_notes = models.TextField(blank=True, null=True)
    fix_status = models.CharField(max_length=10, choices=FIX_STATUS_CHOICES, default='unfixed')

    class Meta:
        ordering = [
            models.Case(
                models.When(severity='critical', then=0),
                models.When(severity='high',     then=1),
                models.When(severity='medium',   then=2),
                models.When(severity='low',      then=3),
                models.When(severity='info',     then=4),
                default=5,
            )
        ]

    def __str__(self):
        return f"{self.severity.upper()}: {self.title}"


class Report(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='report')
    executive_summary = models.TextField()
    risk_score = models.IntegerField(default=0)
    generated_at = models.DateTimeField(auto_now_add=True)
    raw_ai_response = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Report for Scan #{self.scan.id}"
