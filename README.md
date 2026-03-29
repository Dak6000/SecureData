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

## 🚀 Installation & Lancement

### 1. Pré-requis
- Python 3.12+
- Django 5.1.7

### 2. Configuration
```bash
# Cloner le dépôt
git clone <url-du-depot>
cd secure-data-monitor

# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

### 3. Initialisation
```bash
# Appliquer les migrations
python manage.py migrate

# Initialiser les règles SIEM (Crucial)
python manage.py init_rules

# Créer un super-utilisateur
python manage.py createsuperuser
```

### 4. Lancement
```bash
python manage.py runserver
```
Accédez à l'application via `http://127.0.0.1:8000/`.

---

## 🎨 Technologies Utilisées
- **Framework** : Django 5.1.7
- **Frontend** : Tailwind CSS, Javascript (Vanilla)
- **Graphiques** : Chart.js
- **Sécurité** : Signaux Django, Middleware personnalisé, Rate Limiting
- **Base de données** : SQLite / PostgreSQL

---

## 👨‍💻 Auteu
Projet réalisé dans le cadre du cours de **Programmation Événementielle avec Python**.
