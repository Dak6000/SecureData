from django.db import models

class SecurityRule(models.Model):
    name = models.CharField(max_length=100, verbose_name="Nom de la règle")
    code = models.SlugField(max_length=50, unique=True, verbose_name="Code technique")
    is_active = models.BooleanField(default=True, verbose_name="Activée")
    description = models.TextField(blank=True, verbose_name="Description")
    parameters = models.JSONField(default=dict, blank=True, verbose_name="Paramètres")
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        status = "ACTIF" if self.is_active else "INACTIF"
        return f"{self.name} [{status}]"

    class Meta:
        verbose_name = "Règle de Sécurité"
        verbose_name_plural = "Règles de Sécurité"

class BlacklistedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, verbose_name="Adresse IP")
    reason = models.TextField(blank=True, verbose_name="Raison du blocage")
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} (Bloqué le {self.timestamp.strftime('%d/%m/%Y')})"

    class Meta:
        verbose_name = "IP Blacklistée"
        verbose_name_plural = "IP Blacklistées"
