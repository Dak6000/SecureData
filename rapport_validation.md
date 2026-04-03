# Évaluation du Projet SecureData Monitor

Ce rapport présente l'analyse de votre projet actuel (`SecureData Monitor`) par rapport au cahier des charges de votre cours "Programmation événementielle avec Python".

## 1. Ce qui est parfaitement réussi (Validé ✅)

- **Technologies Respectées** : 
  - Backend en **Python (Django)**.
  - Base de données **PostgreSQL** correctement configurée (`settings.py`).
- **Fonctionnalités Métier & Authentification** :
  - L'authentification par défaut est modifiée pour inclure des `roles` (Administrateur, Analyste, Utilisateur).
  - L'entité métier correspond à l'Option B (Comptes Bancaires), avec les champs demandés (id_compte, titulaire, solde, historique).
- **Architecture Événementielle (Le coeur du sujet)** :
  - **Excellente séparation** : Vous utilisez un middleware (`SecurityAccessMiddleware`) et le système des *Signals* de Django pour la détection et la réaction. C'est l'essence même de la programmation événementielle dans Django.
  - **Journalisation Complète** : Double persistence. Les logs s'écrivent à la fois dans fichier et dans PostgreSQL via la table `SecurityEvent`.
- **Règles de détection majeures (Validées)** :
  - **Règle 2 (SQL Injection)** : Détectée par regex dans le middleware et remonte une alerte *high*.
  - **Règle 3 (Accès admin par simple user)** : Gérée. L'élévation de privilèges est interceptée et déclenche l'événement `privilege_escalation`.
  - **Règle 4 (20 req / min)** : Implémentée dans le middleware avec un système de cache robuste (`global_rate_limit` et `mass_access`).
  - **Règle 5 (Énumération)** : Protégée au niveau du middleware de login par le comptage d'identifiants essayés via la même IP.
- **Tableau de Bord** : Le Dashboard (`views.py`) présente correctement les KPIs de sécurité, les statistiques et le suivi des alertes.

## 2. Ce qu'il manquait ou qui était incomplet ⚠️

Il manquait principalement la stricte application de la sanction pour la **Règle 1** et les éléments annexes de rendu (livrables textuels et tests).

### Défaut technique (Règle 1)
- **Ce que disait le sujet** : "3 échecs login < 2 min → alerte moyenne + **lock** (verrouillage de compte)".
- **Votre code initial** : S'il y avait 3 échecs, l'alerte était bien créée, mais le compte de l'utilisateur visé n'était jamais verrouillé (`user.is_locked = True`). La fonctionnalité de verrouillage était codée pour l'administration manuelle, mais pas déclenchée **automatiquement** en approche événementielle lors des 3 échecs.

## 3. Ce qu'il vous reste à faire maintenant 🚀

Pour boucler définitivement votre projet, voici vos prochaines étapes :

### A. Livrables Documentaires ("Le Rapport" et "Scripts SQL")
Conformément au "Travail demandé (Partie 1 et 14)", vous devez fournir un rapport écrit comprenant au minimum :
1. Le **Cahier des charges**, les objectifs et le contexte.
2. L'**Architecture** explicitée (Dites bien que vous avez utilisé les signaux de Django `dispatch.Signal` et un *Middleware* métier pour l'interception asynchrone des événements).
3. Les **règles implémentées** et leurs niveaux de gravité.
4. Les **Screenshots** (captures d'écrans du terminal de logs, de la base de données PostgreSQL, du dashboard SIEM).
5. **Scripts SQL** : Vous utilisez l'ORM de Django, mais le prof veut les scripts SQL. Générez votre schéma de création des tables comme ceci et mettez tout dans un fichier `init_schema.sql` pour votre rendu final :
   ```bash
   python manage.py sqlmigrate core 0001
   python manage.py sqlmigrate security 0001
   ```

### B. Mener les Scénarios de Démonstration (Livrables 3 & 4)
Votre professeur demandera sans doute une démo ou consultera vos données en base lors de sa validation. Vous devez simuler (par script ou à la main) :
1. **Un login normal** (Capture la connexion réussite).
2. **Une attaque par force brute (Login échoué)** : Entrez un vrai nom d'utilisateur avec de faux mots de passe. Il faut que le compte soit verrouillé automatiquement.
3. **Une attaque par Injection SQL** : En tant qu'utilisateur, tapez `' OR 1=1 --` ou `UNION SELECT` dans la barre d'adresse pour déclencher le log et l'alerte élevée.
4. **Accès interdit** : En tant que simple `utilisateur`, essayez d'aller sur `/security/dashboard/`.
5. Prenez **preuve par capture d'écran** des journaux de logs console, fichier, et dashboard après chacune de ces attaques.
