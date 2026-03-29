# security/middleware.py
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone
from .signals import (
    access_denied, sql_injection_detected, mass_access_detected, 
    off_hours_access, enumeration_attempt, privilege_escalation,
    abnormal_navigation_speed, repeated_account_consultation,
    unauthorized_modification, transaction_threshold_exceeded
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

        # 1. Détection SQL Injection
        if self.is_rule_active('sql_injection'):
            for key, value in list(request.GET.items()) + list(request.POST.items()):
                if re.search(r"(?i)(\b(SELECT|UNION|DROP|OR 1=1|--|;)\b)", str(value)):
                    if request.user.is_authenticated:
                        sql_injection_detected.send(
                            sender=None, username=request.user.username,
                            ip=request.META.get('REMOTE_ADDR'), payload=str(value)
                        )
                    # return HttpResponseForbidden("Requête bloquée.")

        # 2. Détection Énumération
        ip = request.META.get('REMOTE_ADDR')
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

        # --- Suite du traitement ---
        response = self.get_response(request)

        if not user.is_authenticated:
            return response

        path = request.path.lower()

        # 3. Règle 7 : Tentative d'élévation & Accès restreint
        if self.is_rule_active('restricted_access'):
            forbidden_patterns = ['/admin/', '/security/', '/users/manage/', '/manage-rules/', '/rules/']
            is_forbidden = any(path.startswith(pattern) for pattern in forbidden_patterns)
            
            if is_forbidden and user.role == 'utilisateur':
                # Alerte Elévation de privilèges
                privilege_escalation.send(sender=None, username=user.username, ip=ip)
                
                # Alerte Accès refusé
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
            
            # Récupération des paramètres dynamiques
            from .models import SecurityRule
            try:
                rule = SecurityRule.objects.get(code='off_hours')
                start = rule.parameters.get('start', 22)
                end = rule.parameters.get('end', 6)
            except:
                start, end = 22, 6

            # Logique de détection de plage horaire (gère le passage à minuit)
            is_off_hours = False
            if start > end: # Ex: 22h à 6h
                if current_hour >= start or current_hour <= end:
                    is_off_hours = True
            else: # Ex: 9h à 17h (inverse)
                if current_hour >= start and current_hour <= end:
                    is_off_hours = True

            if is_off_hours:
                off_hours_access.send(sender=None, username=user.username, ip=ip)

        return response