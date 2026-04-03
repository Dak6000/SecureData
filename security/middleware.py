# security/middleware.py
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone
from .signals import (
    access_denied, sql_injection_detected, mass_access_detected, 
    off_hours_access, enumeration_attempt, privilege_escalation,
    abnormal_navigation_speed, repeated_account_consultation,
    unauthorized_modification, transaction_threshold_exceeded,
    suspicious_url_detected, suspicious_chars_detected, web_scan_detected
)
import re

from django.shortcuts import render
from .models import SecurityRule, BlacklistedIP

class SecurityAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def is_rule_active(self, code):
        """Vérifie si une règle est activée avec mise en cache courte"""
        key = f"rule_status_{code}"
        status = cache.get(key)
        if status is None:
            try:
                rule = SecurityRule.objects.get(code=code)
                status = rule.is_active
            except:
                status = True # Par défaut actif si règle manquante
            cache.set(key, status, 30) # Cache de 30 secondes
        return status

    def __call__(self, request):
        # 0. Ignorer le favicon pour éviter les faux positifs de scan
        if 'favicon.ico' in request.path:
            return self.get_response(request)

        ip = request.META.get('REMOTE_ADDR')
        
        # 0. Vérification Blacklist
        if BlacklistedIP.objects.filter(ip_address=ip).exists():
            return render(request, 'core/blocked.html', status=403)

        user = request.user

        # 0. Règle 9 : Vitesse de navigation globale (Rate Limit)
        if self.is_rule_active('global_rate_limit'):
            rate_key = f"global_rate_{ip}" if not user.is_authenticated else f"global_rate_{user.id}"
            try:
                from .models import SecurityRule
                rule_r9 = SecurityRule.objects.get(code='global_rate_limit')
                threshold = rule_r9.parameters.get('threshold', 40)
            except:
                threshold = 40
            
            requests_count = cache.get(rate_key, 0) + 1
            cache.set(rate_key, requests_count, 60)
            if requests_count > threshold:
                abnormal_navigation_speed.send(
                    sender=None, 
                    username=user.username if user.is_authenticated else 'anonymous', 
                    ip=ip, 
                    count=requests_count
                )

        # 1. Détection SQL Injection & Caractères Suspects (XSS)
        sql_active = self.is_rule_active('sql_injection')
        xss_active = self.is_rule_active('suspicious_chars')
        
        if sql_active or xss_active:
            for key, value in list(request.GET.items()) + list(request.POST.items()):
                val_str = str(value)
                # SQLi
                if sql_active and re.search(r"(?i)(\b(SELECT|UNION|DROP|OR 1=1|--|;)\b)", val_str):
                    sql_injection_detected.send(
                        sender=None, username=user.username if user.is_authenticated else 'anonymous',
                        ip=ip, payload=val_str
                    )
                # XSS / Caractères suspects
                if xss_active and re.search(r"(?i)(<script|alert\(|onload=|onerror=|javascript:)", val_str):
                    suspicious_chars_detected.send(
                        sender=None, username=user.username if user.is_authenticated else 'anonymous',
                        ip=ip, payload=val_str
                    )

        # 1.bis Détection Manipulation d'URL (Path Traversal / Fichiers sensibles)
        if self.is_rule_active('suspicious_url'):
            url_path = request.path.lower()
            if re.search(r"(\.\.\/|\.\.\\|/etc/passwd|\.env|\.git|\.php|wp-admin|cmd\.exe)", url_path):
                suspicious_url_detected.send(
                    sender=None, username=user.username if user.is_authenticated else 'anonymous',
                    ip=ip, url=request.path
                )

        # 2. Détection Énumération
        if self.is_rule_active('enumeration'):
            if not request.user.is_authenticated and 'login' in request.path:
                username_tried = request.POST.get('username')
                if username_tried:
                    key_enum = f"enum_{ip}"
                    tried_list = cache.get(key_enum, set())
                    tried_list.add(username_tried)
                    cache.set(key_enum, tried_list, 300) # 5 minutes
                    if len(tried_list) > 5:
                        enumeration_attempt.send(sender=None, ip=ip, tried_usernames=list(tried_list))

        # --- Suite du traitement (Post-Response) ---
        response = self.get_response(request)

        # 6. Détection Scan Web (Surveillance globale des 404)
        if response.status_code == 404 and self.is_rule_active('web_scan_404'):
            key_404 = f"scan_404_{ip}"
            count_404 = cache.get(key_404, 0) + 1
            cache.set(key_404, count_404, 60)
            
            try:
                rule_scan = SecurityRule.objects.get(code='web_scan_404')
                limit_404 = rule_scan.parameters.get('limit', 10)
            except:
                limit_404 = 10
                
            if count_404 > limit_404:
                web_scan_detected.send(sender=None, ip=ip, count=count_404)

        if not user.is_authenticated:
            return response

        path = request.path.lower()

        # 3. Règle 7 : Tentative d'élévation & Accès restreint
        if self.is_rule_active('restricted_access'):
            forbidden_patterns = ['/admin/', '/security/', '/users/manage/', '/manage-rules/', '/rules/']
            is_forbidden = any(path.startswith(pattern) for pattern in forbidden_patterns)
            
            # Exception : la page statistics est autorisée pour tous (vue filtrée par rôle)
            if '/security/statistics/' in path:
                is_forbidden = False
                
            if is_forbidden and user.role == 'utilisateur':
                privilege_escalation.send(sender=None, username=user.username, ip=ip)
                access_denied.send(
                    sender=None, username=user.username, ip=ip, requested_url=request.path
                )

        # 4. Règle 4 : Consultation massive
        if '/data/' in path and self.is_rule_active('mass_access'):
            key_mass = f"mass_{user.username}"
            count = cache.get(key_mass, 0) + 1
            cache.set(key_mass, count, 60)
            if count > 20:
                mass_access_detected.send(sender=None, username=user.username, ip=ip, count=count)

        # 5. Règle 7 : Accès hors horaires
        if self.is_rule_active('off_hours'):
            current_hour = timezone.now().hour
            from .models import SecurityRule
            try:
                rule = SecurityRule.objects.get(code='off_hours')
                start = rule.parameters.get('start', 22)
                end = rule.parameters.get('end', 6)
            except:
                start, end = 22, 6

            is_off_hours = False
            if start > end: # 22h à 6h
                if current_hour >= start or current_hour <= end:
                    is_off_hours = True
            else:
                if current_hour >= start and current_hour <= end:
                    is_off_hours = True

            if is_off_hours:
                off_hours_access.send(sender=None, username=user.username, ip=ip)

        return response