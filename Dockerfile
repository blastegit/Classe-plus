# Utiliser une image Python officielle legere
FROM python:3.11-slim

# Repertoire de travail
WORKDIR /app

# Copie des dependances en premier (pour le cache Docker)
COPY requirements.txt .

# Installation des dependances
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste de l'application
COPY . .

# Exposer le port
EXPOSE 5000

# Lancement en production avec Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
