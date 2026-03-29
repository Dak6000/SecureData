from django.core.management.base import BaseCommand
from security.models import SecurityRule

class Command(BaseCommand):
    help = 'Initialise les règles de sécurité par défaut'

    def handle(self, *args, **kwargs):
        rules = [
            {
                'name': 'Détection SQL Injection',
                'code': 'sql_injection',
                'description': 'Analyse les paramètres GET/POST pour détecter des payloads SQL suspects.',
                'is_active': True
            },
            {
                'name': 'Détection Énumération',
                'code': 'enumeration',
                'description': 'Surveille les tentatives de connexion avec plusieurs pseudos depuis une même IP.',
                'is_active': False  # Désactivé par défaut comme demandé précédemment pour les tests
            },
            {
                'name': 'Consultation Massive',
                'code': 'mass_access',
                'description': 'Détecte plus de 20 requêtes par minute sur les données sensibles.',
                'is_active': True,
                'parameters': {'limit': 20}
            },
            {
                'name': 'Accès Hors Horaires',
                'code': 'off_hours',
                'description': 'Alerte lors d\'un accès au système en dehors des heures définies.',
                'is_active': True,
                'parameters': {'start': 22, 'end': 6}
            },
            {
                'name': 'Seuil de Transaction',
                'code': 'transaction_limit',
                'description': 'Déclenche une alerte si un virement dépasse le montant autorisé.',
                'is_active': True,
                'parameters': {'threshold': 1000000}
            },
            {
                'name': 'Élévation de Privilèges',
                'code': 'restricted_access',
                'description': 'Surveille les tentatives d\'accès aux pages administratives par des non-admins.',
                'is_active': True
            },
            {
                'name': 'Lecture Répétée',
                'code': 'repeated_reading',
                'description': 'Alerte si un utilisateur consulte plus de 5 fois le même compte en moins de 3 minutes.',
                'is_active': True,
                'parameters': {'limit': 5, 'window': 180}
            },
            {
                'name': 'Vitesse de Navigation',
                'code': 'global_rate_limit',
                'description': 'Détecte une activité suspecte si plus de 40 requêtes sont effectuées par minute.',
                'is_active': True,
                'parameters': {'threshold': 40}
            },
            {
                'name': 'Modification Non Autorisée',
                'code': 'unauthorized_mod',
                'description': 'Alerte critique lors d\'une tentative de modification de compte par un utilisateur simple.',
                'is_active': True
            },
        ]

        for r in rules:
            rule, created = SecurityRule.objects.get_or_create(
                code=r['code'],
                defaults={
                    'name': r['name'],
                    'description': r['description'],
                    'is_active': r['is_active'],
                    'parameters': r.get('parameters', {})
                }
            )
            if not created:
                # Mise à jour des champs si la règle existe déjà
                rule.name = r['name']
                rule.description = r['description']
                if not rule.parameters: # On n'écrase pas si déjà personnalisé par l'user
                    rule.parameters = r.get('parameters', {})
                rule.save()
                self.stdout.write(self.style.WARNING(f'Règle "{rule.name}" mise à jour.'))
            else:
                self.stdout.write(self.style.SUCCESS(f'Règle "{rule.name}" créée.'))
