# UNIVERSITÉ DE KARA – FAST-LPSIC S6

## EXAMEN : PROGRAMMATION ÉVÉNEMENTIELLE & CYBERSÉCURITÉ

**Année académique :** 2025 - 2026

**Niveau :** Licence 3

**Durée :** Deux semaines

## Projet d’examen

**Conception d’une application Web événementielle de détection et de journalisation des tentatives d’accès non autorisé à une base de données sécurisée**

# 1. Contexte

Une institution sensible dispose d’une application Web permettant l’accès à des données confidentielles stockées dans une base PostgreSQL.

### Types de données :

* Dossiers clients
* Relevés financiers
* Dossiers médicaux
* Documents administratifs sensibles
* Secrets industriels

### Types d’attaques possibles :

* Multiples essais de connexion avec mots de passe erronés
* Injection SQL
* Accès à des URL interdites
* Élévation de privilèges
* Exfiltration massive de données
* Utilisation d’identifiants volés
* Accès à des heures inhabituelles
* Consultation répétée de données sensibles

### Objectifs de sécurité :

* Détecter les comportements suspects
* Générer des alertes en temps réel
* Journaliser tous les événements
* Distinguer actions normales / malveillantes
* Assurer une traçabilité complète

---

# 2. Objectif général

Développer une application Web avec PostgreSQL intégrant une API événementielle permettant de :

* Intercepter les événements sensibles
* Analyser les actions utilisateur
* Détecter les attaques
* Journaliser les opérations
* Générer des alertes

---

# 3. Objectifs spécifiques

## Partie A

1. Concevoir une application Web avec authentification
2. Connecter à PostgreSQL

## Partie B

3. Modéliser les événements critiques
4. Implémenter la logique événementielle
5. Détecter les attaques
6. Journaliser les événements
7. Générer des alertes

## Partie C

8. Créer un tableau de bord
9. Documenter l’architecture

---

# 4. Technologies suggérées

### Obligatoire :

* Backend : **Python**
* Base : **PostgreSQL**

### Frameworks possibles :

* Flask
* FastAPI
* Django

### Outils :

* SQLAlchemy / psycopg2 / asyncpg
* JavaScript
* Bootstrap / Tailwind
* WebSocket / polling
* logging Python
* asyncio

---

# 5. Sujet proposé

API : **SecureData Monitor**

---

# 6. Fonctionnalités minimales

## 6.1 Fonctionnalités métier

* Page de connexion
* Gestion des rôles (admin, analyste, utilisateur)
* Consultation de données sensibles
* Tableau de bord sécurité
* Base PostgreSQL

## 6.2 Données sensibles

### Option A : Dossiers médicaux

* id_patient
* nom
* diagnostic
* traitement
* niveau_confidentialite

### Option B : Comptes bancaires

* id_compte
* titulaire
* solde
* historique
* classification

### Option C : Documents administratifs

* id_document
* titre
* categorie
* contenu
* classification

---

# 7. Dimension événementielle

### Événements à détecter :

* Tentative de connexion
* Échec d’authentification
* Requête suspecte
* Accès interdit
* Lecture répétée
* Pic de requêtes
* Injection SQL
* Modification non autorisée
* Accès admin
* Consultation massive

---

# 8. Types d’événements

## 8.1 Authentification

* login réussi
* login échoué
* login multiple
* compte verrouillé
* utilisateur inexistant

## 8.2 Autorisation

* accès refusé
* accès hors périmètre
* élévation de privilège

## 8.3 Applicatifs

* trop de requêtes
* téléchargement massif
* accès répété
* accès hors horaires

## 8.4 Attaques

* SQL injection
* caractères suspects
* énumération
* manipulation URL
* scan Web

---

# 9. Travail demandé

## Partie 1 : Conception

* Cahier des charges
* Architecture
* Événements
* Schéma PostgreSQL

## Partie 2 : Développement

* Application Web
* Base de données
* Authentification
* Affichage données
* Gestion rôles

## Partie 3 : Événementiel

* Détection événements
* Handlers
* Analyse attaques
* Alertes

## Partie 4 : Journalisation

Logs obligatoires :

* date/heure
* utilisateur
* IP
* type
* gravité
* détail
* action
* statut

Stockage :

* fichier
* base PostgreSQL

## Partie 5 : Alertes

* Faible : 1 accès refusé
* Moyenne : 3 échecs login
* Élevée : injection SQL
* Critique : exfiltration

## Partie 6 : Tableau de bord

* événements récents
* alertes
* sévérité
* fréquence
* statistiques

---

# 10. Contraintes techniques

* Python obligatoire
* PostgreSQL obligatoire
* Architecture Web
* Journalisation complète
* ≥ 5 événements détectés
* ≥ 4 niveaux d’alerte
* Séparation :
* logique métier
* logique événementielle
* persistance
* interface

---

# 11. Base de données

## Table users

* id
* username
* password_hash
* role
* is_locked
* created_at

## Table sensitive_data

* id
* title
* content
* sensitivity_level
* owner
* created_at

## Table security_events

* id
* timestamp
* username
* ip_address
* event_type
* severity
* description
* status
* action_taken

## Table alerts

* id
* timestamp
* alert_level
* source_event_id
* message
* resolved

---

# 12. Règles de détection

### Règle 1

3 échecs login < 2 min

→ alerte moyenne + lock

### Règle 2

Motifs SQL :

* `' OR 1=1 --`
* `UNION SELECT`
* `DROP TABLE`

  → alerte élevée

### Règle 3

Accès `/admin` par user simple

→ alerte élevée

### Règle 4

> 20 consultations / minute
>
> → alerte critique

### Règle 5

Même IP → plusieurs comptes

→ énumération

---

# 13. Programmation événementielle

### Exemple :

* Événement : `login_failed`
* Handler : `handle_failed_login`
* Actions :
* incrément compteur
* log
* alerte si seuil

---

# 14. Livrables

## 1. Code source

* Application complète
* Scripts SQL
* Config

## 2. Rapport

* Contexte
* Objectifs
* Architecture
* Données
* Événements
* Règles
* Screenshots
* Tests
* Limites

## 3. Tests

* login normal
* login échoué
* SQL injection
* accès interdit
* requêtes massives
* exfiltration

## 4. Démo

* fonctionnement normal
* attaque détectée
* alerte générée
* logs visibles

---

# Consignes générales

* Python (Flask / FastAPI / Django)
* PostgreSQL
* Logique événementielle
* Journalisation complète
* Alertes par gravité
