from django.contrib import admin
from .models import Scan, Vulnerability, Report


class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    readonly_fields = ('title', 'severity', 'vuln_type', 'cvss_score', 'cwe_id', 'fix_status')


class ReportInline(admin.StackedInline):
    model = Report
    extra = 0
    readonly_fields = ('executive_summary', 'risk_score', 'generated_at')


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'input_method', 'language', 'status', 'vulnerability_count', 'created_at')
    list_filter = ('status', 'input_method', 'language')
    readonly_fields = ('created_at', 'completed_at')
    inlines = [ReportInline, VulnerabilityInline]


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'vuln_type', 'cvss_score', 'fix_status', 'scan')
    list_filter = ('severity', 'vuln_type', 'fix_status')
    readonly_fields = ('fix_patch', 'fix_notes', 'references')
    search_fields = ('title', 'vuln_type', 'cwe_id')


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('scan', 'risk_score', 'generated_at')
    readonly_fields = ('generated_at', 'raw_ai_response')
