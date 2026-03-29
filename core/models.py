from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrateur'),
        ('analyste', 'Analyste'),
        ('utilisateur', 'Utilisateur'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='utilisateur')
    is_locked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

class CompteBancaire(models.Model):
    id_compte = models.CharField(max_length=20, unique=True, verbose_name="N° Compte")
    titulaire = models.CharField(max_length=150, verbose_name="Titulaire")
    solde = models.DecimalField(max_digits=15, decimal_places=2, verbose_name="Solde actuel")
    historique = models.TextField(blank=True, verbose_name="Historique des transactions")
    classification = models.CharField(max_length=50, choices=[
        ('confidentiel', 'Confidentiel'),
        ('secret', 'Secret'),
        ('top_secret', 'Top Secret')
    ], default='confidentiel')
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='comptes')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.id_compte} - {self.titulaire}"

class SecurityEvent(models.Model):
    SEVERITY_CHOICES = [('low', 'Faible'), ('medium', 'Moyenne'), ('high', 'Élevée'), ('critical', 'Critique')]
    timestamp = models.DateTimeField(auto_now_add=True)
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    event_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    action_taken = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=50, default='détecté')

    class Meta:
        ordering = ['-timestamp']

class Alert(models.Model):
    ALERT_LEVEL_CHOICES = [('low', 'Faible'), ('medium', 'Moyenne'), ('high', 'Élevée'), ('critical', 'Critique')]
    timestamp = models.DateTimeField(auto_now_add=True)
    alert_level = models.CharField(max_length=20, choices=ALERT_LEVEL_CHOICES)
    source_event = models.ForeignKey(SecurityEvent, on_delete=models.CASCADE, null=True, blank=True)
    message = models.TextField()
    resolved = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('transfert', 'Transfert P2P'),
        ('ajustement', 'Ajustement Admin'),
    ]
    sender_acc = models.ForeignKey(CompteBancaire, on_delete=models.SET_NULL, null=True, related_name='sent_transactions', verbose_name="Source")
    receiver_acc = models.ForeignKey(CompteBancaire, on_delete=models.CASCADE, related_name='received_transactions', verbose_name="Destination")
    amount = models.DecimalField(max_digits=15, decimal_places=2, verbose_name="Montant")
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES, default='transfert')
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"

    def __str__(self):
        return f"{self.transaction_type} | {self.amount} FCFA"