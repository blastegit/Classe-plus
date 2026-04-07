# 🎓 Classe+ — Plateforme de Gestion Académique Sécurisée

Projet DevSecOps — UE7-2 GCS2 | Guardia Cybersecurity School

## Description

Classe+ est une application web de gestion académique permettant de gérer les notes, les emplois du temps, les absences et la messagerie interne d'un campus. L'application implémente un système RBAC (Role-Based Access Control) avec trois rôles : Administrateur, Professeur et Étudiant.

## Stack technique

- **Backend** : Python / Flask
- **Base de données** : SQLite (via SQLAlchemy)
- **Sécurité** : Bcrypt, CSRF (Flask-WTF), headers HTTP sécurisés
- **Conteneurisation** : Docker & Docker Compose
- **CI/CD** : GitHub Actions (Flake8, SonarCloud, pip-audit, OWASP ZAP)

## Installation

### En local

```bash
# cloner le repo
git clone https://github.com/votre-repo/classe-plus.git
cd classe-plus

# installer les dependances
pip install -r requirements.txt

# lancer l'application
python app.py
```

L'application sera accessible sur `http://localhost:5000`

### Avec Docker

```bash
docker-compose up --build
```

## Compte par défaut

Au premier lancement, un compte admin est créé automatiquement :
- **Identifiant** : `admin`
- **Mot de passe** : `admin`

## Fonctionnalités

### Administrateur
- Créer et gérer les utilisateurs
- Créer des classes
- Assigner les étudiants aux classes
- Programmer les cours (emplois du temps)

### Professeur
- Consulter son emploi du temps
- Attribuer des notes aux étudiants
- Faire l'appel (absences et retards)
- Envoyer des messages

### Étudiant
- Consulter ses notes et sa moyenne
- Consulter son emploi du temps
- Voir ses absences et retards
- Recevoir et envoyer des messages

## Sécurité implémentée

- Hachage des mots de passe avec Bcrypt
- Protection CSRF sur tous les formulaires
- Headers HTTP de sécurité (CSP, X-Frame-Options, X-XSS-Protection, etc.)
- Contrôle d'accès RBAC côté serveur
- Validation des entrées utilisateur
- Requêtes paramétrées (SQLAlchemy ORM)
- Gestion sécurisée des sessions (durée limitée, invalidation)
- Logging des événements de sécurité

## Pipeline CI/CD

La pipeline GitHub Actions exécute les étapes suivantes à chaque push :
1. **Flake8** — Lint du code Python
2. **SonarCloud** — Analyse statique de sécurité (SAST)
3. **pip-audit** — Scan des dépendances vulnérables
4. **OWASP ZAP** — Scan dynamique (DAST)
5. **Docker Build** — Construction et test de l'image

## Arborescence du projet

```
CLASSE-PLUS/
├── .github/workflows/ci-cd.yml
├── instance/campus.db
├── static/style.css
├── templates/
│   ├── admin/
│   │   ├── home.html
│   │   └── users.html
│   ├── etudiant/
│   │   ├── absences.html
│   │   ├── edt.html
│   │   ├── home.html
│   │   └── notes.html
│   ├── prof/
│   │   ├── appel.html
│   │   ├── edt.html
│   │   ├── home.html
│   │   └── notes.html
│   ├── shared/
│   │   └── messages.html
│   ├── 403.html
│   ├── base.html
│   └── login.html
├── .dockerignore
├── app.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── security.log
└── sonar-project.properties
```