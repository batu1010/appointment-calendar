# Basisimage für Python verwenden
FROM python:3.10-slim

# Arbeitsverzeichnis erstellen
WORKDIR /app

# Anforderungen kopieren und installieren
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Anwendungscode kopieren
COPY . .

# Port für die Anwendung öffnen
EXPOSE 8080

# Flask starten
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
