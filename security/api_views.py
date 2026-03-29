from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from core.models import SecurityEvent, Alert, CompteBancaire
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import timedelta

@login_required
def dashboard_stats_api(request):
    """API endpoint for real-time dashboard updates"""
    if request.user.role not in ['admin', 'analyste'] and not request.user.is_superuser:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    # 1. Total events and severity breakdown
    total_events = SecurityEvent.objects.count()
    severity_breakdown = dict(SecurityEvent.objects.values('severity').annotate(count=Count('id')).values_list('severity', 'count'))
    
    # 2. Latest alerts
    latest_alerts = list(Alert.objects.order_by('-timestamp')[:5].values('message', 'alert_level', 'timestamp'))

    # 3. Events in the last 24 hours (for charts)
    last_24h = timezone.now() - timedelta(hours=24)
    chart_data = list(SecurityEvent.objects.filter(timestamp__gte=last_24h)
                      .extra({'hour': "EXTRACT(hour FROM timestamp)"})
                      .values('hour')
                      .annotate(count=Count('id'))
                      .order_by('hour'))

    return JsonResponse({
        'total_events': total_events,
        'severity': severity_breakdown,
        'latest_alerts': latest_alerts,
        'chart_data': chart_data,
        'timestamp': timezone.now().isoformat()
    })

@login_required
def user_statistics_api(request):
    """API endpoint for personal user statistics"""
    user = request.user
    
    # 1. Account summary
    comptes = CompteBancaire.objects.filter(owner=user)
    total_solde = comptes.aggregate(Sum('solde'))['solde__sum'] or 0
    
    # 2. Activity summary (if user is not admin)
    recent_activity = list(SecurityEvent.objects.filter(username=user.username).order_by('-timestamp')[:10].values('event_type', 'timestamp', 'description'))

    return JsonResponse({
        'username': user.username,
        'total_accounts': comptes.count(),
        'total_solde': float(total_solde),
        'recent_activity': recent_activity,
    })
