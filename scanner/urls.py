from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/new/', views.new_scan, name='new_scan'),
    path('scan/import/', views.import_report, name='import_report'),
    path('scan/<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scan/<int:scan_id>/status/', views.scan_status, name='scan_status'),
    path('scan/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),
    # Fix engine
    path('vuln/<int:vuln_id>/fix/request/', views.request_fix, name='request_fix'),
    path('vuln/<int:vuln_id>/fix/status/', views.fix_status, name='fix_status'),
    path('vuln/<int:vuln_id>/fix/mark/', views.mark_fix, name='mark_fix'),
]
