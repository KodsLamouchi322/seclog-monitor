#!/usr/bin/env python3
"""Crée les comptes de test (un par rôle) dans MongoDB.

Usage (dans le conteneur web, qui connaît MONGO_URI) :
    docker compose exec web python /scripts/seed_users.py
    docker compose exec web python /scripts/seed_users.py --reset   # régénère les mots de passe

Les mots de passe sont générés au hasard et affichés UNE SEULE FOIS. Pour imposer un mot de passe,
définir SEED_ADMIN_PASSWORD, SEED_ANALYSTE_PASSWORD ou SEED_LECTEUR_PASSWORD.
Un compte déjà présent n'est pas modifié (sauf avec --reset).
"""
import argparse
import os
import secrets
from datetime import datetime, timezone

from pymongo import MongoClient
from werkzeug.security import generate_password_hash

# (nom d'utilisateur, rôle, e-mail) ; l'e-mail est obligatoire : index unique créé par mongo/init
ACCOUNTS = [
    ("admin", "admin", "admin@seclog.local"),
    ("analyste", "analyste", "analyste@seclog.local"),
    ("lecteur", "lecteur", "lecteur@seclog.local"),
]


def seed(db, reset=False, env=None):
    env = os.environ if env is None else env
    users = db["users"]
    users.create_index("username", unique=True)
    report = []
    for username, role, email in ACCOUNTS:
        existing = users.find_one({"username": username})
        if existing and not reset:
            report.append((username, role, None, "déjà présent"))
            continue
        password = env.get(f"SEED_{username.upper()}_PASSWORD") or secrets.token_urlsafe(12)
        fields = {"role": role, "email": email, "active": True,
                  "password_hash": generate_password_hash(password)}
        if existing:
            users.update_one({"username": username}, {"$set": fields})
            report.append((username, role, password, "mot de passe régénéré"))
        else:
            users.insert_one({"username": username, **fields, "created_at": datetime.now(timezone.utc)})
            report.append((username, role, password, "créé"))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="régénère le mot de passe des comptes existants")
    args = parser.parse_args()
    client = MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=5000)
    db = client[os.environ.get("MONGO_DB", "seclog")]
    print("Comptes SecLog Monitor :")
    for username, role, password, status in seed(db, reset=args.reset):
        shown = f"mot de passe : {password}" if password else "(inchangé)"
        print(f"  - {username:<9} rôle {role:<9} {status:<22} {shown}")
    print("Note ces mots de passe maintenant : ils ne seront plus affichés.")


if __name__ == "__main__":
    main()
