import json
import os
import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from .db import get_db
from .validation import ValidationError, validate_file

bp = Blueprint("upload", __name__)


@bp.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    mb = current_app.config["MAX_UPLOAD_MB"]
    return jsonify(error=f"Fichier trop volumineux (max {mb} Mo)."), 413


@bp.post("/upload")
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify(error="Aucun fichier envoyé (champ 'file' attendu)."), 400

    original = secure_filename(f.filename)
    raw = f.read()
    cfg = current_app.config
    try:
        info = validate_file(
            original, raw, cfg["ALLOWED_EXTENSIONS"], cfg["PREVIEW_LINES"]
        )
    except ValidationError as exc:
        return jsonify(error=str(exc)), 400

    stored = f"{int(time.time())}_{original}"
    folder = cfg["UPLOAD_FOLDER"]
    os.makedirs(folder, exist_ok=True)
    final_path = os.path.join(folder, stored)
    tmp_path = final_path + ".tmp"

    # Tableau JSON : conversion en NDJSON (un objet par ligne) pour Logstash
    if info.get("was_array"):
        content = "\n".join(json.dumps(e, ensure_ascii=False) for e in info["events"])
        data = (content + "\n").encode("utf-8")
    else:
        data = raw
    with open(tmp_path, "wb") as out:
        out.write(data)
    os.replace(tmp_path, final_path)

    doc = {
        "original_name": original,
        "stored_name": stored,
        "format": info["format"],
        "size_bytes": len(raw),
        "total_lines": info["total_lines"],
        "invalid_lines": info["invalid_lines"],
        "status": "pending",
        "uploaded_at": datetime.now(timezone.utc),
    }
    res = get_db().files.insert_one(doc)

    return jsonify(
        id=str(res.inserted_id),
        stored_name=stored,
        format=info["format"],
        total_lines=info["total_lines"],
        invalid_lines=info["invalid_lines"],
        status="pending",
        preview=info["preview"],
    ), 201


@bp.get("/upload")
def upload_page():
    return render_template("upload.html")
