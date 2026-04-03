from django.dispatch import Signal, receiver
from django.contrib.auth.signals import user_login_failed, user_logged_in
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
login_success = Signal()
multiple_login_detected = Signal()
web_scan_detected = Signal()
suspicious_url_detected = Signal()
suspicious_chars_detected = Signal()
account_locked_attempt = Signal()

# ====================== HANDLERS (RÈGLES DU SUJET) ======================

@receiver(user_login_failed)
def handle_failed_login(sender, credentials, request, **kwargs):
    username = credentials.get('username', 'inconnu')
    ip = request.META.get('REMOTE_ADDR') if request else None
    
    # Règle 1 : 3 échecs en < 2 minutes
    key = f'failed_login_{ip}'
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, 120)

    # Détection utilisateur inexistant ou verrouillé
    from core.models import CustomUser
    user_info = "inconnu"
    is_existent = False
    is_locked_account = False
    
    try:
        user_obj = CustomUser.objects.get(username=username)
        is_existent = True
        if user_obj.is_locked:
            is_locked_account = True
            user_info = f"{username} (DÉJÀ VERROUILLÉ)"
        else:
            user_info = username
    except CustomUser.DoesNotExist:
        user_info = f"{username} (INEXISTANT)"

    severity = 'medium' if (attempts >= 3 or not is_existent or is_locked_account) else 'low'
    
    event_type = 'login_failed'
    if is_locked_account:
        event_type = 'locked_account_attempt'
        description = f"Tentative de connexion sur compte déjà verrouillé : {username}"
    elif not is_existent:
        event_type = 'non_existent_user'
        description = f"Tentative avec utilisateur inexistant : {username}"
    else:
        description = f"Échec de connexion pour {username} (tentative {attempts})"

    event = SecurityEvent.objects.create(
        username=username,
        ip_address=ip,
        event_type=event_type,
        severity=severity,
        description=description
    )

    # Création systématique de l'alerte pour assurer la visibilité sur le dashboard
    Alert.objects.create(
        alert_level=severity,
        source_event=event,
        message=description
    )

    if attempts >= 3:
        # Verrouillage du compte utilisateur s'il existe et n'est pas admin
        if is_existent and not user_obj.is_superuser and user_obj.role != 'admin':
            user_obj.is_locked = True
            user_obj.save()
            event.action_taken = "Compte verrouillé"
            event.save()

    log_to_file(event_type, username, ip, severity, event.description)
    check_and_blacklist(ip, "Échecs de connexion répétés ou suspects")


@receiver(sql_injection_detected)
def handle_sql_injection(sender, username, ip, payload, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='sql_injection',
        severity='critical', description=f'Tentative SQLi : {payload[:80]}'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message='Injection SQL détectée et bloquée')
    log_to_file('sql_injection', username, ip, 'critical', event.description)
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
        severity='critical', description=f'Accès interdit à {requested_url}'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message=f'Tentative d’accès à une ressource interdite ({requested_url})')
    log_to_file('access_denied', username, ip, 'critical', event.description)


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
        severity='critical', description='Tentative d’élévation de privilèges'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message='Tentative d’élévation de privilèges détectée')
    log_to_file('privilege_escalation', username, ip, 'critical', event.description)


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
        severity='critical', description=f'Vitesse de navigation suspecte ({count} req/min)'
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message=f'Navigation trop rapide ({count} req/min) - Suspection de bot')
    log_to_file('abnormal_navigation_speed', username, ip, 'critical', event.description)

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

from django.contrib.auth.signals import user_login_failed, user_logged_in, user_logged_out

@receiver(user_logged_in)
def handle_login_success(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    
    # Règle : Détection de logins multiples
    key_ip = f"logins_from_ip_{ip}"
    users_from_ip = cache.get(key_ip, set())
    users_from_ip.add(user.username)
    cache.set(key_ip, users_from_ip, 600) # 10 minutes

    if len(users_from_ip) > 3:
        multiple_login_detected.send(sender=None, ip=ip, usernames=list(users_from_ip))

    event = SecurityEvent.objects.create(
        username=user.username, ip_address=ip, event_type='login_success',
        severity='low', description=f"Connexion réussie : {user.username}"
    )
    # Créer une alerte de faible priorité pour la visibilité sur le dashboard
    Alert.objects.create(
        alert_level='low',
        source_event=event,
        message=f"Session ouverte pour l'utilisateur {user.username}"
    )
    log_to_file('login_success', user.username, ip, 'low', event.description)

@receiver(user_logged_out)
def handle_logout(sender, request, user, **kwargs):
    if user:
        ip = request.META.get('REMOTE_ADDR')
        event = SecurityEvent.objects.create(
            username=user.username, ip_address=ip, event_type='logout',
            severity='low', description=f"Déconnexion de l'utilisateur : {user.username}"
        )
        # Créer une alerte de faible priorité pour la visibilité sur le dashboard
        Alert.objects.create(
            alert_level='low',
            source_event=event,
            message=f"Session fermée pour l'utilisateur {user.username}"
        )
        log_to_file('logout', user.username, ip, 'low', event.description)

@receiver(multiple_login_detected)
def handle_multiple_login(sender, ip, usernames, **kwargs):
    event = SecurityEvent.objects.create(
        username='multi-user', ip_address=ip, event_type='multiple_login',
        severity='medium', description=f"Connexion de {len(usernames)} comptes via cette IP : {', '.join(usernames)}"
    )
    Alert.objects.create(alert_level='medium', source_event=event,
                       message=f"IP partagée par {len(usernames)} comptes - Suspection de bot/proxy")
    log_to_file('multiple_login', 'multi-user', ip, 'medium', event.description)

@receiver(web_scan_detected)
def handle_web_scan(sender, ip, count, **kwargs):
    event = SecurityEvent.objects.create(
        username='anonymous', ip_address=ip, event_type='web_scan',
        severity='high', description=f"Scan Web détecté ({count} erreurs 404/min)"
    )
    Alert.objects.create(alert_level='high', source_event=event,
                       message=f"Scan de vulnérabilités suspecté depuis IP {ip}")
    log_to_file('web_scan', 'anonymous', ip, 'high', event.description)
    check_and_blacklist(ip, "Scan de fichiers détecté")

@receiver(suspicious_url_detected)
def handle_suspicious_url(sender, username, ip, url, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='suspicious_url',
        severity='critical', description=f"Manipulation d'URL détectée : {url}"
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message=f"Tentative de manipulation d'URL ({url})")
    log_to_file('suspicious_url', username, ip, 'critical', event.description)

@receiver(suspicious_chars_detected)
def handle_suspicious_chars(sender, username, ip, payload, **kwargs):
    event = SecurityEvent.objects.create(
        username=username, ip_address=ip, event_type='suspicious_chars',
        severity='critical', description=f"Caractères suspects / XSS détectés : {payload[:50]}"
    )
    Alert.objects.create(alert_level='critical', source_event=event,
                       message="Tentative d'injection de scripts (XSS/Payload)")
    log_to_file('suspicious_chars', username, ip, 'critical', event.description)
