FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Utilisateur non-root
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --create-home app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY wsgi.py .
COPY app ./app

# Dossier d'upload (le volume nommé hérite de ces droits à sa création)
RUN mkdir -p /app/uploads && chown -R app:app /app

USER app
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "wsgi:app"]
