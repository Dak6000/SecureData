# 🛡️ SecureData SIEM Monitor

![SIEM Banner](https://img.shields.io/badge/Status-Project--Ready-success?style=for-the-badge&logo=django)
![UI Style](https://img.shields.io/badge/Design-GlassAdmin-violet?style=for-the-badge)

**SecureData SIEM Monitor** est une plateforme de surveillance de sécurité avancée (SIEM) intégrée à un système bancaire simulé. Elle permet de détecter, d'analyser et de répondre aux menaces en temps réel tout en gérant les actifs financiers des utilisateurs de manière sécurisée.

---

## ✨ Points Forts & Fonctionnalités

### 🖥️ Interface Utilisateur Premium (Glassmorphism)
- **Thèmes Adaptatifs** : Basculement fluide entre le mode **Frosted Quartz** (Jour) et **Deep Navy** (Nuit).
- **Design SIEM Moderne** : Tableaux de bord interactifs propulsés par **Chart.js**.
- **Visualisations Dynamiques** : Graphiques de sévérité, répartition des comptes par rôle et évolution temporelle des incidents.

### 🔍 Moteur SIEM & Détection
- **Moteur de Règles Dynamique** : Gestion en temps réel de 10 règles de sécurité critiques (SQLi, Brute-force, Exfiltration, etc.).
- **Alertes en Temps Réel** : Système de notifications visuelles pour les incidents critiques.
- **Réponse Automatisée** : Blacklisting IP automatique après plusieurs violations graves.

### 🏦 Système Bancaire Multi-Rôles
- **Admins** : Surveillance totale, gestion des règles et des utilisateurs.
- **Analystes** : Monitoring des incidents et accès à leurs comptes personnels.
- **Utilisateurs** : Gestion de portefeuille, historique des transactions et sécurité du profil.

---

## 🛠️ Architecture de Sécurité (Règles R1-R10)

Le système implémente les règles de détection suivantes :
1.  **R1 (Brute-force)** : 3 échecs de connexion en moins de 2 minutes.
2.  **R2 (SQL Injection)** : Détection de patterns malveillants dans les requêtes.
3.  **R3 (Sensitive Access)** : Alertes sur les accès aux dossiers racines.
4.  **R4 (Exfiltration)** : Consultation massive de données en peu de temps.
5.  **R7 (Off-hours)** : Accès détecté en dehors des plages horaires autorisées.
6.  **R8 (Reconnaissance)** : Consultations répétées d'un même compte bancaire.
7.  **R9 (Navigation Speed)** : Détection de robots via la vitesse de navigation.
8.  ... et bien d'autres (Élévation de privilèges, modifications illégales).

---

## 🚀 Guide de Lancement (Projet Cloné)

Suivez ces étapes pour mettre en place le projet localement après l'avoir cloné depuis GitHub.

### 1. Clonage du Projet
```bash
git clone https://github.com/Dak6000/SecureData.git
cd SecureData
```

### 2. Configuration de l'Environnement
Il est fortement recommandé d'utiliser un environnement virtuel pour isoler les dépendances.
```bash
# Création de l'env (Windows)
python -m venv venv
.\venv\Scripts\activate

# Création de l'env (Linux/macOS)
python3 -m venv venv
source venv/bin/activate
```

### 3. Installation des Dépendances
```bash
pip install -r requirements.txt
```

### 4. Initialisation de la Base de Données
Cette étape prépare les tables et configure le moteur SIEM.
```bash
# Appliquer les migrations
python manage.py migrate

# Initialiser les règles SIEM (OBLIGATOIRE pour voir les règles s'afficher)
python manage.py init_rules

# Créer votre compte Administrateur
python manage.py createsuperuser
```

### 5. Lancement du Serveur
```bash
python manage.py runserver
```
L'application sera disponible sur [http://127.0.0.1:8000/](http://127.0.0.1:8000/).

---

## 💡 Notes Importantes
- **Règles SIEM** : Si vous ne voyez pas les règles dans le dashboard, relancez `python manage.py init_rules`.
- **Compte de Test** : Après avoir créé un super-utilisateur, vous pouvez accéder au panneau d'administration (`/admin`) pour créer des utilisateurs avec les rôles `analyste` ou `utilisateur`.

---

## 🎨 Technologies Utilisées
- **Backend** : Django 5.1.7, Python-dotenv
- **Frontend** : Tailwind CSS (Custom), Chart.js 4.x
- **Base de données** : SQLite (par défaut) / Support PostgreSQL inclus

---

## 👨‍💻 Auteu
Projet réalisé dans le cadre du cours de **Programmation Événementielle avec Python**.
