
import os
import csv
from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Count, Sum, Avg
from django.utils import timezone
from django.contrib import messages
from core.models import SecurityEvent, Alert, CompteBancaire
from .models import SecurityRule
from django.core.cache import cache

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role in ['admin', 'analyste'])
def dashboard(request):
    """Vue principale avec statistiques dynamiques et graphiques"""
    severity = request.GET.get('severity')
    date_from = request.GET.get('from')
    date_to = request.GET.get('to')
    event_type = request.GET.get('event_type')
    
    events_qs = SecurityEvent.objects.all()
    alerts_qs = Alert.objects.all()
    
    # Filtrage dynamique
    if severity:
        events_qs = events_qs.filter(severity=severity)
        alerts_qs = alerts_qs.filter(alert_level=severity)
    if date_from:
        events_qs = events_qs.filter(timestamp__date__gte=date_from)
        alerts_qs = alerts_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        events_qs = events_qs.filter(timestamp__date__lte=date_to)
        alerts_qs = alerts_qs.filter(timestamp__date__lte=date_to)
    if event_type:
        events_qs = events_qs.filter(event_type=event_type)

    # Statistiques avancées (Top IPs, Users)
    top_ips = list(SecurityEvent.objects.values('ip_address').annotate(count=Count('id')).order_by('-count')[:10])
    # Calcul des pourcentages pour la barre de progression
    max_ip_count = top_ips[0]['count'] if top_ips else 1
    for ip in top_ips:
        ip['percentage'] = (ip['count'] / max_ip_count) * 100
        
    top_users = list(SecurityEvent.objects.values('username').annotate(count=Count('id')).order_by('-count')[:5])
    
    # Évolution journalière (7j) - Alertes non résolues uniquement
    alert_trends = []
    for i in range(6, -1, -1):
        day = timezone.now().date() - timezone.timedelta(days=i)
        count = Alert.objects.filter(timestamp__date=day, resolved=False).count()
        alert_trends.append({'day': day.strftime("%d/%m"), 'count': count})

    # Distribution par type d'événement
    event_type_dist = list(SecurityEvent.objects.values('event_type')
                           .annotate(count=Count('id'))
                           .order_by('-count')[:10])
    # Formatter pour le JS
    event_type_distribution = [{'name': d['event_type'], 'count': d['count']} for d in event_type_dist]

    # Activité par heure (dernières 24h)
    last_24h = timezone.now() - timezone.timedelta(hours=23)
    hourly_activity = []
    for i in range(24):
        time_slot = last_24h + timezone.timedelta(hours=i)
        count = SecurityEvent.objects.filter(timestamp__hour=time_slot.hour, timestamp__date=time_slot.date()).count()
        hourly_activity.append({'hour': time_slot.hour, 'count': count})

    # Trend Mensuel (Simplifié: ce mois vs mois dernier)
    this_month = timezone.now().month
    last_month = (timezone.now().replace(day=1) - timezone.timedelta(days=1)).month
    count_this = SecurityEvent.objects.filter(timestamp__month=this_month).count()
    count_last = SecurityEvent.objects.filter(timestamp__month=last_month).count()
    total_trend = round(((count_this - count_last) / count_last * 100), 1) if count_last > 0 else 0

    total_alerts = Alert.objects.count()
    resolved_alerts = Alert.objects.filter(resolved=True).count()
    detection_rate = round((resolved_alerts / total_alerts * 100), 1) if total_alerts > 0 else 100.0

    # Liste des types d'événements pour le filtre
    event_types_list = [{'value': t, 'label': t.replace('_', ' ').title()} 
                       for t in SecurityEvent.objects.values_list('event_type', flat=True).distinct()]

    today = timezone.now().date()

    stats = {
        'total_events': SecurityEvent.objects.count(),
        'critical': Alert.objects.filter(alert_level='critical', resolved=False).count(),
        'high': Alert.objects.filter(alert_level='high', resolved=False).count(),
        'medium': Alert.objects.filter(alert_level='medium', resolved=False).count(),
        'low': Alert.objects.filter(alert_level='low', resolved=False).count(),
        'critical_today': Alert.objects.filter(alert_level='critical', timestamp__date=today).count(),
        'total_trend': total_trend,
        'detection_rate': detection_rate,
        'alert_trends': alert_trends,
        'top_ips': top_ips,
        'top_users': top_users,
        'event_type_distribution': event_type_distribution,
        'hourly_activity': hourly_activity,
        'event_types_list': event_types_list,
        'active_alerts_count': Alert.objects.filter(resolved=False).count()
    }
    
    return render(request, 'security/dashboard.html', {
        'events': events_qs[:50], 
        'alerts': alerts_qs.filter(resolved=False)[:50], 
        'stats': stats,
        'current_severity': severity,
        'current_event_type': event_type
    })

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role in ['admin', 'analyste'])
def resolve_all_alerts(request):
    """Marque TOUTES les alertes comme résolues"""
    if request.method == 'POST':
        Alert.objects.filter(resolved=False).update(resolved=True)
        messages.success(request, "Toutes les alertes ont été marquées comme résolues.")
    return redirect('security_dashboard')

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role in ['admin', 'analyste'])
def export_filtered_results(request):
    """Exporte les résultats filtrés en CSV"""
    severity = request.GET.get('severity')
    date_from = request.GET.get('from')
    date_to = request.GET.get('to')
    
    events = SecurityEvent.objects.all()
    if severity: events = events.filter(severity=severity)
    if date_from: events = events.filter(timestamp__date__gte=date_from)
    if date_to: events = events.filter(timestamp__date__lte=date_to)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="filtered_security_events.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'IP', 'Type', 'Severity', 'Description'])
    for e in events[:1000]:
        writer.writerow([e.timestamp, e.username, e.ip_address, e.event_type, e.severity, e.description])
    
    return response

@login_required
def statistics_view(request):
    """Vue des statistiques adaptée au rôle"""
    
    if request.user.role in ['admin', 'analyste'] or request.user.is_superuser:
        # Données globales pour les superviseurs
        comptes = CompteBancaire.objects.all()
        active_alerts = Alert.objects.filter(resolved=False)
        
        # Historique des 7 derniers jours (Alertes actives uniquement)
        history_data = []
        for i in range(6, -1, -1):
            day = timezone.now().date() - timezone.timedelta(days=i)
            count = Alert.objects.filter(timestamp__date=day, resolved=False).count()
            history_data.append({'day': day.strftime("%d/%m"), 'count': count})

        # Top IPs Sources
        top_ips = list(SecurityEvent.objects.values('ip_address').annotate(count=Count('id')).order_by('-count')[:10])
        max_ip_count = top_ips[0]['count'] if top_ips else 1
        for ip in top_ips:
            ip['percentage'] = (ip['count'] / max_ip_count) * 100

        # Activité par heure (dernières 24h)
        last_24h = timezone.now() - timezone.timedelta(hours=23)
        hourly_activity = []
        for i in range(24):
            time_slot = last_24h + timezone.timedelta(hours=i)
            count = SecurityEvent.objects.filter(timestamp__hour=time_slot.hour, timestamp__date=time_slot.date()).count()
            hourly_activity.append({'hour': f"{time_slot.hour:02d}", 'count': count})
        
        # Heure de pointe
        peak_hour_data = max(hourly_activity, key=lambda x: x['count']) if hourly_activity else {'hour': '--'}
        peak_hour = peak_hour_data['hour']

        # Calcul de la tendance (ce mois vs mois dernier)
        this_month = timezone.now().month
        last_month = (timezone.now().replace(day=1) - timezone.timedelta(days=1)).month
        count_this = Alert.objects.filter(timestamp__month=this_month).count()
        count_last = Alert.objects.filter(timestamp__month=last_month).count()
        trend_percentage = round(((count_this - count_last) / count_last * 100), 1) if count_last > 0 else 0

        stats = {
            'by_type': list(SecurityEvent.objects.values('event_type').annotate(count=Count('id'))),
            'by_severity': list(active_alerts.values('alert_level').annotate(count=Count('id'))),
            'history': history_data,
            'total_liquidity': comptes.aggregate(Sum('solde'))['solde__sum'] or 0,
            'avg_balance': comptes.aggregate(Avg('solde'))['solde__avg'] or 0,
            'role_dist': list(comptes.values('owner__role').annotate(count=Count('id'))),
            'total_accounts': comptes.count(),
            'total_events': SecurityEvent.objects.count(),
            'active_alerts': active_alerts.count(),
            'critical_alerts': active_alerts.filter(alert_level='critical').count(),
            'top_ips': top_ips,
            'hourly_activity': hourly_activity,
            'peak_hour': peak_hour,
            'recent_alerts': active_alerts.order_by('-timestamp')[:5],
            'trend_percentage': trend_percentage,
            'liquidity_trend': trend_percentage # Utilisé comme alias dans certains cards
        }
        template = 'security/statistics.html'
    else:
        # Données personnelles pour les clients
        comptes = CompteBancaire.objects.filter(owner=request.user)
        total_solde = comptes.aggregate(Sum('solde'))['solde__sum'] or 0
        
        # Dernière activité
        last_event = SecurityEvent.objects.filter(username=request.user.username).order_by('-timestamp').first()
        last_activity = last_event.timestamp.strftime("%d/%m/%Y %H:%M") if last_event else "Aucune"

        # Simulation d'historique de solde sur 12 mois
        balance_history = []
        current_date = timezone.now()
        for i in range(11, -1, -1):
            month_date = current_date - timezone.timedelta(days=i*30)
            variation = (i * 5000) - 25000 
            balance_history.append({
                'month': month_date.strftime("%b"),
                'balance': float(total_solde) + variation if total_solde else 0
            })

        stats = {
            'total_accounts': comptes.count(),
            'total_solde': total_solde,
            'recent_activity': SecurityEvent.objects.filter(username=request.user.username)[:10],
            'accounts': comptes.all(),
            'last_activity': last_activity,
            'balance_history': balance_history
        }
        template = 'security/statistics.html'
        
    return render(request, template, {'stats': stats})

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role in ['admin', 'analyste'])
def alerts_list_view(request):
    """Vue détaillée de toutes les alertes"""
    # Filtrage par niveau si demandé
    level = request.GET.get('level')
    if level:
        alerts = Alert.objects.filter(alert_level=level).order_by('-timestamp')
    else:
        alerts = Alert.objects.all().order_by('-timestamp')
        
    # Statistiques pour l'en-tête et les filtres
    stats = {
        'total': Alert.objects.count(),
        'active': Alert.objects.filter(resolved=False).count(),
        'critical': Alert.objects.filter(alert_level='critical', resolved=False).count(),
        'high': Alert.objects.filter(alert_level='high', resolved=False).count(),
        'medium': Alert.objects.filter(alert_level='medium', resolved=False).count(),
        'low': Alert.objects.filter(alert_level='low', resolved=False).count(),
    }
        
    return render(request, 'security/alerts.html', {
        'alerts': alerts, 
        'current_level': level,
        'stats': stats
    })

from django.shortcuts import get_object_or_404, redirect

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role in ['admin', 'analyste'])
def resolve_alert(request, alert_id):
    """Marque une alerte comme résolue"""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.resolved = True
    alert.save()
    
    # Rediriger vers la page précédente (Dashboard ou Liste)
    referer = request.META.get('HTTP_REFERER')
    if referer:
        return redirect(referer)
    return redirect('alerts_list')


@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def export_alerts_csv(request):
    """Exporte la liste des alertes en CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="security_alerts_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Date', 'Utilisateur', 'Type Event', 'Sévérité', 'Message', 'Résolue'])
    
    alerts = Alert.objects.all().select_related('source_event').order_by('-timestamp')
    for alert in alerts:
        writer.writerow([
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            alert.source_event.username if alert.source_event else 'N/A',
            alert.source_event.event_type if alert.source_event else 'Manual',
            alert.alert_level.upper(),
            alert.message,
            "Oui" if alert.resolved else "Non"
        ])
    
    return response

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def download_logs(request):
    """Permet aux admins de télécharger le fichier de logs"""
    log_path = os.path.join(settings.BASE_DIR, 'logs', 'security.log')
    if os.path.exists(log_path):
        return FileResponse(open(log_path, 'rb'), as_attachment=True, filename='security_monitor.log')
    raise Http404("Fichier de logs introuvable.")

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def manage_rules_view(request):
    """Affiche la liste des règles de sécurité pour gestion"""
    rules = SecurityRule.objects.all().order_by('name')
    stats = {
        'total': rules.count(),
        'active': rules.filter(is_active=True).count(),
        'inactive': rules.filter(is_active=False).count(),
    }
    return render(request, 'security/manage_rules.html', {'rules': rules, 'stats': stats})

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def toggle_rule(request, rule_id):
    """Active ou désactive une règle"""
    rule = get_object_or_404(SecurityRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save()
    
    # Invalider le cache pour que le middleware voie le changement
    cache.delete(f"rule_status_{rule.code}")
    
    status = "activée" if rule.is_active else "désactivée"
    messages.success(request, f"La règle '{rule.name}' a été {status}.")
    return redirect('manage_rules')

@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def update_rule_params(request, rule_id):
    """Met à jour les paramètres spécifiques d'une règle"""
    if request.method == 'POST':
        rule = get_object_or_404(SecurityRule, id=rule_id)
        params = rule.parameters or {}
        
        if rule.code == 'transaction_limit':
            params['threshold'] = int(request.POST.get('threshold', 1000000))
        elif rule.code == 'off_hours':
            params['start'] = int(request.POST.get('start', 22))
            params['end'] = int(request.POST.get('end', 6))
        elif rule.code == 'mass_access' or rule.code == 'repeated_reading':
            params['limit'] = int(request.POST.get('limit', 20 if rule.code == 'mass_access' else 5))
            if rule.code == 'repeated_reading':
                params['window'] = int(request.POST.get('window', 180))
        elif rule.code == 'global_rate_limit':
            params['threshold'] = int(request.POST.get('threshold', 40))
            
        rule.parameters = params
        rule.save()
        cache.delete(f"rule_status_{rule.code}")
        messages.success(request, f"Paramètres de '{rule.name}' mis à jour.")
        
    return redirect('manage_rules')