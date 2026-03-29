from django.urls import path
from .views import (
    dashboard, statistics_view, download_logs, export_alerts_csv,
    alerts_list_view, resolve_alert, manage_rules_view, toggle_rule, 
    update_rule_params
)
from .api_views import dashboard_stats_api, user_statistics_api

urlpatterns = [
    path('dashboard/', dashboard, name='security_dashboard'),
    path('statistics/', statistics_view, name='statistics'),
    path('download-logs/', download_logs, name='download_logs'),
    path('export-alerts-csv/', export_alerts_csv, name='export_alerts_csv'),
    path('alerts/', alerts_list_view, name='alerts_list'),
    path('alerts/resolve/<int:alert_id>/', resolve_alert, name='resolve_alert'),
    path('manage-rules/', manage_rules_view, name='manage_rules'),
    path('rules/toggle/<int:rule_id>/', toggle_rule, name='toggle_rule'),
    path('rules/update/<int:rule_id>/', update_rule_params, name='update_rule_params'),
    
    # API Endpoints
    path('api/v1/dashboard/stats/', dashboard_stats_api, name='api_dashboard_stats'),
    path('api/v1/user/stats/', user_statistics_api, name='api_user_stats'),
]