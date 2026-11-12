import csv
import io
import json

REQUIRED_CSV_COLUMNS = {"timestamp", "source_ip", "event_type", "result", "severity"}


class ValidationError(Exception):
    """Fichier refusé, avec un message clair pour l'utilisateur (RM11)."""


def get_extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def decode_content(raw: bytes) -> str:
    if not raw.strip():
        raise ValidationError("Fichier vide.")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValidationError("Encodage non supporté (UTF-8 requis).")


def validate_csv(text: str, preview_lines: int = 10) -> dict:
    reader = csv.reader(io.StringIO(text))
    try:
        header = [h.strip() for h in next(reader)]
    except StopIteration:
        raise ValidationError("Fichier vide.")
    missing = sorted(REQUIRED_CSV_COLUMNS - set(header))
    if missing:
        raise ValidationError("Colonnes manquantes : " + ", ".join(missing))
    preview, total, invalid = [], 0, 0
    for row in reader:
        if not row:
            continue
        total += 1
        if len(row) != len(header):
            invalid += 1
        if len(preview) < preview_lines:
            preview.append(dict(zip(header, row)))
    return {"total_lines": total, "invalid_lines": invalid, "preview": preview}


def validate_json(text: str, preview_lines: int = 10) -> dict:
    """Accepte NDJSON (un objet par ligne) ou un tableau [ ... ]."""
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"JSON invalide : {exc.msg} (ligne {exc.lineno}).")
        events = [e for e in data if isinstance(e, dict)]
        if not events:
            raise ValidationError("Le tableau JSON ne contient aucun objet.")
        return {
            "total_lines": len(data),
            "invalid_lines": len(data) - len(events),
            "preview": events[:preview_lines],
            "was_array": True,
            "events": events,
        }
    preview, total, invalid = [], 0, 0
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        total += 1
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError
            if len(preview) < preview_lines:
                preview.append(obj)
        except ValueError:
            invalid += 1
            if total == 1:
                raise ValidationError(f"JSON invalide ligne {n}.")
    if total == invalid:
        raise ValidationError("Aucun objet JSON valide.")
    return {"total_lines": total, "invalid_lines": invalid, "preview": preview, "was_array": False}


def validate_txt(text: str, preview_lines: int = 10) -> dict:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValidationError("Fichier vide.")
    return {"total_lines": len(lines), "invalid_lines": 0, "preview": lines[:preview_lines]}


def validate_file(filename: str, raw: bytes, allowed: set, preview_lines: int = 10) -> dict:
    ext = get_extension(filename)
    if ext not in allowed:
        raise ValidationError(
            "Format non autorisé (" + ", ".join(sorted(allowed)) + " uniquement)."
        )
    text = decode_content(raw)
    result = {"csv": validate_csv, "json": validate_json, "txt": validate_txt}[ext](
        text, preview_lines
    )
    result["format"] = ext
    return result
