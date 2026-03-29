from django.dispatch import Signal, receiver
from django.contrib.auth.signals import user_login_failed
from django.core.cache import cache
from django.utils import timezone
from core.models import SecurityEvent, Alert
from .models import BlacklistedIP
import logging
import re

# ====================== CONFIGURATION DU LOGGER FICHIER ======================
logger = logging.getLogger('security')

def check_and_blacklist(ip, reason):
    """Vérifie si une IP doit être blacklistée automatiquement (3 alertes critiques)"""
    if not ip or ip == '127.0.0.1': return
    
    critical_count = Alert.objects.filter(source_event__ip_address=ip, alert_level='critical').count()
    if critical_count >= 3:
        BlacklistedIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': f"Automatique: {critical_count} alertes critiques détectées. Raison: {reason}"}
        )

def log_to_file(event_type, username, ip, severity, description, action="journalisé"):
    """Écrit dans logs/security.log + dans la console"""
    extra = {
        'user': username,
        'ip': ip or 'N/A',
        'event_type': event_type,
    }
    logger.info(
        f"{description} | Action: {action} | Sévérité: {severity}",
        extra=extra
    )

# ====================== SIGNAUX PERSONNALISÉS ======================
sql_injection_detected = Signal()
access_denied = Signal()
mass_access_detected = Signal()
enumeration_attempt = Signal()
off_hours_access = Signal()
privilege_escalation = Signal()
repeated_sensitive_access = Signal()
transaction_threshold_exceeded = Signal()
abnormal_navigation_speed = Signal()
repeated_account_consultation = Signal()
unauthorized_modification = Signal()

# ====================== HANDLERS (RÈGLES DU SUJET) ======================

@receiver(user_login_failed)
def handle_failed_login(sender, credentials, request, **kwargs):
    username = credentials.get('username', 'inconnu')
    ip = request.META.get('REMOTE_ADDR') if request else None
    
    # Règle 1 : 3 échecs en < 2 minutes
    key = f'failed_login_{ip}'
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, 120)

    severity = 'medium' if attempts >= 3 else 'low'
    event = SecurityEvent.objects.create(
        username=username,
        ip_address=ip,
        event_type='login_failed',
        severity=severity,
        description=f'Échec de connexion (tentative {attempts})'
    )
    if attempts >= 3:
        Alert.objects.create(alert_level='medium', source_event=event,
                           message=f'3 échecs de connexion en < 2 min - IP {ip}')
    log_to_file('login_failed', username, ip, severity, event.description)
    check_and_blacklist(ip, "Échecs de connexion répétés")


@receiver(sql_injection_detected)
def handle_sql_injection(sender, username, ip, payload, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='sql_injection',
        severity='high', description=f'Tentative SQLi : {payload[:80]}'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message='Injection SQL détectée et bloquée')
    log_to_file('sql_injection', username, ip, 'high', event.description)
    check_and_blacklist(ip, "Tentative d'injection SQL")


@receiver(mass_access_detected)
def handle_mass_access(sender, username, ip, count, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='mass_access',
        severity='critical', description=f'Consultation massive ({count} en 1 min)'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message='Risque d’exfiltration massive détecté')
    log_to_file('mass_access', username, ip, 'critical', event.description)
    check_and_blacklist(ip, "Exfiltration massive suspectée")


@receiver(access_denied)
def handle_access_denied(sender, username, ip, requested_url, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='access_denied',
        severity='high', description=f'Accès interdit à {requested_url}'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message=f'Tentative d’accès à une ressource interdite ({requested_url})')
    log_to_file('access_denied', username, ip, 'high', event.description)


@receiver(enumeration_attempt)
def handle_enumeration(sender, ip, tried_usernames, **kwargs):
    event = SecurityEvent.objects.create(
        username='anonymous', ip_address=ip, event_type='enumeration_attempt',
        severity='medium', description=f'Énumération de {len(tried_usernames)} comptes'
    )
    Alert.objects.create(alert_level='medium', source_event=event,
                       message=f'Tentative d’énumération d’identifiants depuis IP {ip}')
    log_to_file('enumeration_attempt', 'anonymous', ip, 'medium', event.description)


@receiver(off_hours_access)
def handle_off_hours(sender, username, ip, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='off_hours_access',
        severity='medium', description='Accès en dehors de la plage horaire autorisée'
    )
    Alert.objects.create(alert_level='medium', source_event=event,
                       message='Accès SIEM hors horaires de travail détecté')
    log_to_file('off_hours_access', username, ip, 'medium', event.description)

@receiver(transaction_threshold_exceeded)
def handle_transaction_threshold(sender, username, amount, threshold, ip, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='transaction_threshold',
        severity='high', description=f'Seuil de transaction dépassé : {amount} FCFA (Limite: {threshold})'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message=f'Virement suspect de {amount} FCFA détecté')
    log_to_file('transaction_threshold', username, ip, 'high', event.description)


@receiver(privilege_escalation)
def handle_privilege_escalation(sender, username, ip, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='privilege_escalation',
        severity='high', description='Tentative d’élévation de privilèges'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message='Tentative d’élévation de privilèges détectée')
    log_to_file('privilege_escalation', username, ip, 'high', event.description)


@receiver(repeated_sensitive_access)
def handle_repeated_access(sender, username, ip, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='repeated_sensitive_access',
        severity='high', description='Lecture répétée de données sensibles'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message='Consultation répétée de données sensibles')
    log_to_file('repeated_sensitive_access', username, ip, 'high', event.description)

@receiver(abnormal_navigation_speed)
def handle_navigation_speed(sender, username, ip, count, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='abnormal_navigation_speed',
        severity='high', description=f'Vitesse de navigation suspecte ({count} req/min)'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message=f'Navigation trop rapide ({count} req/min) - Suspection de bot')
    log_to_file('abnormal_navigation_speed', username, ip, 'high', event.description)

@receiver(repeated_account_consultation)
def handle_repeated_account(sender, username, ip, account_id, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='repeated_account_consultation',
        severity='high', description=f'Consultation répétée du compte {account_id}'
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message=f'Le même compte ({account_id}) a été consulté à répétition')
    log_to_file('repeated_account_consultation', username, ip, 'high', event.description)

@receiver(unauthorized_modification)
def handle_unauthorized_mod(sender, username, ip, target_account, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='unauthorized_modification',
        severity='critical', description=f'Tentative de modification illégale du compte {target_account}'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message='Tentative de modification de capital par un non-admin bloquée')
    log_to_file('unauthorized_modification', username, ip, 'critical', event.description)
    check_and_blacklist(ip, "Tentative de modification illégale de capital")