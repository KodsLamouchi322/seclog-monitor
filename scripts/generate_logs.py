#!/usr/bin/env python3
"""Générateur de logs de sécurité synthétiques pour SecLog Monitor (sprint 2, phase 5).

Scénarios : authentifications réussies/échouées, brute force, injections SQL,
pare-feu/IDS (dont scans de ports), accès sensibles, audit administrateur.

Les champs correspondent à l'index template elasticsearch/index-template.json.
Les adresses IP et les pays sont fictifs (aucune géolocalisation réelle).

Exemples :
  python generate_logs.py --count 5000                      # écrit data/samples/security_logs.json
  python generate_logs.py --count 5000 --format both        # JSON (une ligne par événement) + CSV
  python generate_logs.py --count 5000 --load --reset       # génère, puis indexe dans Elasticsearch
                                                            # et crée la data view Kibana
"""
import argparse
import csv
import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "data" / "samples"
TEMPLATE_PATH = ROOT / "elasticsearch" / "index-template.json"

SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORY = {
    "authentication": "authentication",
    "intrusion": "web",
    "firewall": "network",
    "sensitive_access": "file",
    "audit": "configuration",
}

# iso -> (pays, ville, latitude, longitude)
COUNTRIES = {
    "TN": ("Tunisia", "Tunis", 36.8065, 10.1815),
    "FR": ("France", "Paris", 48.8566, 2.3522),
    "DE": ("Germany", "Berlin", 52.52, 13.405),
    "RU": ("Russia", "Moscow", 55.7558, 37.6173),
    "CN": ("China", "Beijing", 39.9042, 116.4074),
    "US": ("United States", "Ashburn", 39.0438, -77.4874),
    "BR": ("Brazil", "Sao Paulo", -23.5505, -46.6333),
    "IN": ("India", "Mumbai", 19.076, 72.8777),
    "NL": ("Netherlands", "Amsterdam", 52.3676, 4.9041),
    "VN": ("Vietnam", "Hanoi", 21.0285, 105.8542),
    "IR": ("Iran", "Tehran", 35.6892, 51.389),
    "NG": ("Nigeria", "Lagos", 6.5244, 3.3792),
}
AUTHORIZED = ("TN", "FR")
HOSTILE = [c for c in COUNTRIES if c not in AUTHORIZED]

AUTH_HOSTS = ["vpn-gateway-01", "auth-server-01", "bastion-01"]
SQLI_PAYLOADS = [
    "' OR '1'='1", "admin'--", "1; DROP TABLE users;--",
    "' UNION SELECT username,password FROM users--", "1' AND SLEEP(5)--",
    "' OR 1=1 #", "%27%20OR%20%271%27%3D%271", "1 UNION ALL SELECT NULL,NULL,version()--",
]
SQLI_ENDPOINTS = ["/login?user=", "/search?q=", "/products?id=", "/api/v1/users?id=", "/admin/report?date="]
IDS_SIGNATURES = [
    "Nmap scan detected", "Possible SSH brute force", "Suspicious outbound connection (synthetic C2)",
    "SQL injection pattern in HTTP request", "Malformed packet, possible exploit attempt",
]
SENSITIVE_RESOURCES = [
    "/etc/shadow", "/var/backups/db_dump.sql", "/srv/hr/payroll_2026.xlsx",
    "/admin/export/users.csv", "vault/secrets/prod-api-keys",
]
AUDIT_ACTIONS = [
    ("user_created", "low", "User {target} created"),
    ("user_deleted", "medium", "User {target} deleted"),
    ("role_changed", "medium", "Role of {target} changed to admin"),
    ("password_reset", "low", "Password reset for {target}"),
    ("alert_rule_updated", "info", "Alert rule 'Brute force' updated"),
    ("ip_unblocked", "low", "IP {ip} removed from the blocklist"),
    ("config_changed", "medium", "Security configuration changed"),
]

CSV_COLUMNS = [
    "timestamp", "source_ip", "source_port", "user", "role", "event_type", "event_action",
    "result", "severity", "country", "city", "latitude", "longitude", "host", "message",
    "http_method", "http_uri", "http_status", "tags",
]


def iso_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class Generator:
    def __init__(self, seed: int, days: int, file_id: str):
        self.rnd = random.Random(seed)
        self.fake = Faker()
        self.fake.seed_instance(seed)
        self.days = days
        self.file_id = file_id
        self.now = datetime.now(timezone.utc)
        self.end = self.now - timedelta(seconds=30)
        self._build_pools()

    # ------------------------------------------------------------------ pools
    def _build_pools(self):
        names = {"admin", "svc-backup"}
        while len(names) < 16:
            names.add(self.fake.user_name())
        roles = ["admin", "admin", "analyste_soc", "analyste_soc", "analyste_soc", "lecteur", "lecteur", "utilisateur"]
        self.users = []
        for i, name in enumerate(sorted(names)):
            role = "admin" if name == "admin" else ("utilisateur" if name == "svc-backup" else roles[i % len(roles)])
            remote = self.rnd.random() < 0.3
            iso = self.rnd.choice(AUTHORIZED) if remote else "TN"
            ip = self.fake.ipv4_public() if remote else f"10.10.{self.rnd.randint(0, 20)}.{self.rnd.randint(2, 250)}"
            self.users.append({"name": name, "role": role, "ip": ip, "iso": iso})
        self.admins = [u for u in self.users if u["role"] == "admin"]
        # IP d'attaquants : une par pays hostile, plus l'IP citée dans le document d'architecture
        self.attackers = [{"ip": "185.220.101.45", "iso": "DE"}]
        for iso in HOSTILE:
            self.attackers.append({"ip": self.fake.ipv4_public(), "iso": iso})

    # ---------------------------------------------------------------- helpers
    def ts_random(self, business=False) -> datetime:
        t = self.end - timedelta(seconds=self.rnd.uniform(0, self.days * 86400))
        if business:
            t = t.replace(hour=self.rnd.randint(7, 16), minute=self.rnd.randint(0, 59),
                          second=self.rnd.randint(0, 59), microsecond=self.rnd.randint(0, 999999))
            if t > self.end:
                t -= timedelta(days=1)
        return t

    def event(self, ts, etype, action, result, severity, ip, iso, host, message,
              user=None, role=None, port=None, http=None, tags=None):
        country, city, lat, lon = COUNTRIES[iso]
        doc = {
            "@timestamp": iso_ts(ts),
            "ingested_at": iso_ts(self.now),
            "event": {"type": etype, "category": CATEGORY[etype], "action": action},
            "result": result,
            "severity": severity,
            "severity_score": SEVERITY_SCORE[severity],
            "source": {
                "ip": ip,
                "port": port or self.rnd.randint(1024, 65535),
                "geo": {"country_name": country, "country_iso_code": iso, "city_name": city,
                        "location": {"lat": lat, "lon": lon}},
            },
            "host": {"name": host},
            "message": message,
            "log_type": etype,
            "file_id": self.file_id,
            "tags": tags or [],
        }
        if user:
            doc["user"] = {"name": user}
            if role:
                doc["user"]["role"] = role
        if http:
            doc["http"] = http
        return doc

    # -------------------------------------------------------------- scénarios
    def normal_auth(self, n):
        out = []
        for _ in range(n):
            u = self.rnd.choice(self.users)
            ts = self.ts_random(business=True)
            ip, iso, port = u["ip"], u["iso"], self.rnd.randint(1024, 65535)
            r = self.rnd.random()
            tags = []
            if r < 0.03:  # connexion réussie depuis un pays non autorisé
                att = self.rnd.choice(self.attackers)
                ip, iso = att["ip"], att["iso"]
                action, result, sev, tags = "login_success", "success", "high", ["unauthorized_country"]
            elif r < 0.11:
                action, result, sev = "login_failed", "failure", "low"
            else:
                action, result, sev = "login_success", "success", "info"
            if self.rnd.random() < 0.3:  # connexion web
                host = "web-prod-01"
                status = 200 if result == "success" else 401
                http = {"method": "POST", "uri": "/login", "status_code": status}
                msg = f"Web login {'success' if result == 'success' else 'failed'} for {u['name']} from {ip}"
            else:
                host, http = self.rnd.choice(AUTH_HOSTS), None
                verb = "Accepted" if result == "success" else "Failed"
                msg = f"{verb} password for {u['name']} from {ip} port {port} ssh2"
            out.append(self.event(ts, "authentication", action, result, sev, ip, iso, host, msg,
                                  user=u["name"], role=u["role"], port=port, http=http, tags=tags))
        return out

    def brute_force(self, target):
        out = []
        known = {u["name"]: u["role"] for u in self.users}
        while len(out) < target:
            att = self.rnd.choice(self.attackers)
            victim = self.rnd.choice(["admin", "root", "administrator"] + [u["name"] for u in self.admins])
            role = known.get(victim)
            host = self.rnd.choice(AUTH_HOSTS)
            n = self.rnd.randint(8, 40)
            t = min(self.ts_random(), self.end - timedelta(minutes=3))
            for i in range(n):
                t += timedelta(seconds=self.rnd.uniform(0.5, 4))
                sev = "medium" if i < 4 else ("high" if i < 20 else "critical")
                port = self.rnd.randint(1024, 65535)
                out.append(self.event(t, "authentication", "login_failed", "failure", sev, att["ip"], att["iso"], host,
                                      f"Failed password for {victim} from {att['ip']} port {port} ssh2",
                                      user=victim, role=role, port=port,
                                      tags=["brute_force"] if i >= 4 else []))
            if self.rnd.random() < 0.15:  # le brute force finit par réussir
                t += timedelta(seconds=self.rnd.uniform(1, 5))
                port = self.rnd.randint(1024, 65535)
                out.append(self.event(t, "authentication", "login_success", "success", "critical", att["ip"], att["iso"],
                                      host, f"Accepted password for {victim} from {att['ip']} port {port} ssh2",
                                      user=victim, role=role, port=port, tags=["brute_force", "possible_compromise"]))
        return out

    def sql_injection(self, target):
        out = []
        while len(out) < target:
            att = self.rnd.choice(self.attackers)
            t = min(self.ts_random(), self.end - timedelta(minutes=2))
            for _ in range(self.rnd.randint(1, 6)):
                t += timedelta(seconds=self.rnd.uniform(1, 12))
                status = self.rnd.choices([403, 500, 200], weights=[60, 20, 20])[0]
                uri = self.rnd.choice(SQLI_ENDPOINTS) + self.rnd.choice(SQLI_PAYLOADS)
                blocked = status == 403
                http = {"method": self.rnd.choice(["GET", "POST"]), "uri": uri, "status_code": status}
                out.append(self.event(t, "intrusion", "sql_injection_attempt", "failure" if blocked else "success",
                                      "high" if blocked else "critical", att["ip"], att["iso"], "web-prod-01",
                                      f"WAF: SQL injection pattern detected in {uri} from {att['ip']}",
                                      http=http, tags=["sql_injection_suspect"]))
        return out

    def firewall_ids(self, target):
        out = []
        while len(out) < target:
            dst = f"10.10.0.{self.rnd.randint(2, 50)}"
            if self.rnd.random() < 0.12:  # scan de ports
                att = self.rnd.choice(self.attackers)
                t = min(self.ts_random(), self.end - timedelta(minutes=2))
                for dport in self.rnd.sample(range(20, 9000), self.rnd.randint(10, 30)):
                    t += timedelta(seconds=self.rnd.uniform(0.1, 1.5))
                    sport = self.rnd.randint(1024, 65535)
                    out.append(self.event(t, "firewall", "fw_deny", "failure", "medium", att["ip"], att["iso"],
                                          "fw-edge-01", f"DENY tcp {att['ip']}:{sport} -> {dst}:{dport}",
                                          port=sport, tags=["port_scan"]))
                continue
            ts = self.ts_random()
            att = self.rnd.choice(self.attackers)
            kind = self.rnd.choices(["allow", "deny", "ids"], weights=[40, 40, 20])[0]
            sport, dport = self.rnd.randint(1024, 65535), self.rnd.choice([22, 80, 443, 3306, 8080])
            if kind == "allow":
                out.append(self.event(ts, "firewall", "fw_allow", "success", "info", "10.10.0.5", "TN", "fw-edge-01",
                                      f"ALLOW tcp 10.10.0.5:{sport} -> {dst}:{dport}", port=sport))
            elif kind == "deny":
                out.append(self.event(ts, "firewall", "fw_deny", "failure", "low", att["ip"], att["iso"], "fw-edge-01",
                                      f"DENY tcp {att['ip']}:{sport} -> {dst}:{dport}", port=sport))
            else:
                sig = self.rnd.choice(IDS_SIGNATURES)
                out.append(self.event(ts, "firewall", "ids_alert", "failure", self.rnd.choice(["medium", "high"]),
                                      att["ip"], att["iso"], "ids-sensor-01",
                                      f"IDS alert: {sig} from {att['ip']} to {dst}:{dport}", port=sport,
                                      tags=["ids_alert"]))
        return out

    def sensitive_access(self, n):
        out = []
        for _ in range(n):
            u = self.rnd.choice(self.users)
            res = self.rnd.choice(SENSITIVE_RESOURCES)
            ts = self.ts_random(business=True)
            tags = []
            if self.rnd.random() < 0.25:  # accès hors heures de bureau
                ts = ts.replace(hour=self.rnd.randint(0, 5))
                if ts > self.end:
                    ts -= timedelta(days=1)
                tags.append("off_hours")
            denied = u["role"] in ("lecteur", "utilisateur") and res == "/etc/shadow" or self.rnd.random() < 0.15
            if denied:
                action, result, sev = "permission_denied", "failure", "high" if tags else "medium"
                tags.append("access_denied")
                msg = f"Access denied: {u['name']} tried to read {res}"
            else:
                action = self.rnd.choice(["file_read", "file_download", "db_query"])
                result, sev = "success", "high" if tags else ("medium" if action == "file_download" else "low")
                msg = f"{u['name']} {action.replace('_', ' ')} {res}"
            out.append(self.event(ts, "sensitive_access", action, result, sev, u["ip"], u["iso"],
                                  self.rnd.choice(["db-prod-01", "web-prod-01", "bastion-01"]), msg,
                                  user=u["name"], role=u["role"], tags=tags))
        return out

    def admin_audit(self, n):
        out = []
        for _ in range(n):
            adm = self.rnd.choice(self.admins)
            action, sev, tpl = self.rnd.choice(AUDIT_ACTIONS)
            msg = tpl.format(target=self.fake.user_name(), ip=self.rnd.choice(self.attackers)["ip"])
            out.append(self.event(self.ts_random(business=True), "audit", action, "success", sev, adm["ip"], adm["iso"],
                                  "web-prod-01", f"AUDIT {adm['name']}: {msg}", user=adm["name"], role=adm["role"],
                                  tags=["audit"]))
        return out

    def generate(self, total):
        mix = {"auth": 0.46, "brute": 0.14, "sqli": 0.08, "fw": 0.18, "sens": 0.08, "audit": 0.06}
        events = []
        events += self.normal_auth(int(total * mix["auth"]))
        events += self.brute_force(int(total * mix["brute"]))
        events += self.sql_injection(int(total * mix["sqli"]))
        events += self.firewall_ids(int(total * mix["fw"]))
        events += self.sensitive_access(int(total * mix["sens"]))
        events += self.admin_audit(int(total * mix["audit"]))
        events.sort(key=lambda e: e["@timestamp"])
        return events


# ------------------------------------------------------------------- écriture
def write_json(events, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def flatten(e):
    http = e.get("http", {})
    geo = e["source"]["geo"]
    return {
        "timestamp": e["@timestamp"], "source_ip": e["source"]["ip"], "source_port": e["source"]["port"],
        "user": e.get("user", {}).get("name", ""), "role": e.get("user", {}).get("role", ""),
        "event_type": e["event"]["type"], "event_action": e["event"]["action"], "result": e["result"],
        "severity": e["severity"], "country": geo["country_name"], "city": geo["city_name"],
        "latitude": geo["location"]["lat"], "longitude": geo["location"]["lon"], "host": e["host"]["name"],
        "message": e["message"], "http_method": http.get("method", ""), "http_uri": http.get("uri", ""),
        "http_status": http.get("status_code", ""), "tags": "|".join(e["tags"]),
    }


def write_csv(events, path: Path):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for e in events:
            w.writerow(flatten(e))


# ---------------------------------------------------------- Elasticsearch/Kibana
def wait_for(url, check, label, timeout):
    import requests
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and check(r):
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    print(f"[!] {label} injoignable ({url}) après {timeout}s", file=sys.stderr)
    return False


def load_elasticsearch(events, es_url, reset):
    import requests
    es_url = es_url.rstrip("/")
    if not wait_for(f"{es_url}/_cluster/health", lambda r: True, "Elasticsearch", 180):
        sys.exit(1)
    if reset:
        r = requests.get(f"{es_url}/_cat/indices/logs-security-*", params={"h": "index", "format": "json"}, timeout=30)
        for item in r.json() if r.status_code == 200 else []:
            requests.delete(f"{es_url}/{item['index']}", timeout=30)
            print(f"  index supprimé : {item['index']}")
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        template = json.load(f)
    r = requests.put(f"{es_url}/_index_template/logs-security-template", json=template, timeout=30)
    r.raise_for_status()
    print("Index template logs-security-template : OK")

    indexed, chunk = 0, 1000
    for i in range(0, len(events), chunk):
        lines = []
        for e in events[i:i + chunk]:
            index = "logs-security-" + e["@timestamp"][:10].replace("-", ".")
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(e, ensure_ascii=False))
        r = requests.post(f"{es_url}/_bulk", data=("\n".join(lines) + "\n").encode("utf-8"),
                          headers={"Content-Type": "application/x-ndjson"}, timeout=120)
        r.raise_for_status()
        body = r.json()
        if body.get("errors"):
            first = next(it for it in body["items"] if "error" in it["index"])
            print("[!] Erreur d'indexation :", json.dumps(first["index"]["error"]), file=sys.stderr)
            sys.exit(1)
        indexed += len(body["items"])
    requests.post(f"{es_url}/logs-security-*/_refresh", timeout=30)
    count = requests.get(f"{es_url}/logs-security-*/_count", timeout=30).json().get("count")
    print(f"{indexed} événements envoyés, {count} documents dans logs-security-*")


def create_data_view(kibana_url):
    import requests
    kibana_url = kibana_url.rstrip("/")
    ready = wait_for(f"{kibana_url}/api/status",
                     lambda r: r.json().get("status", {}).get("overall", {}).get("level") == "available",
                     "Kibana", 240)
    if not ready:
        print("[!] Data view non créée : crée-la à la main (voir README)", file=sys.stderr)
        return
    body = {"data_view": {"id": "logs-security", "title": "logs-security-*", "name": "logs-security",
                          "timeFieldName": "@timestamp"}, "override": True}
    r = requests.post(f"{kibana_url}/api/data_views/data_view", json=body,
                      headers={"kbn-xsrf": "true"}, timeout=30)
    if r.status_code in (200, 201):
        print("Data view Kibana « logs-security-* » : OK")
    else:
        print(f"[!] Data view : HTTP {r.status_code} {r.text[:200]}", file=sys.stderr)


# ----------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Générateur de logs de sécurité synthétiques")
    p.add_argument("--count", type=int, default=5000, help="nombre approximatif d'événements (défaut 5000)")
    p.add_argument("--days", type=int, default=7, help="période couverte en jours (défaut 7)")
    p.add_argument("--seed", type=int, default=42, help="graine aléatoire (défaut 42)")
    p.add_argument("--format", choices=["json", "csv", "both"], default="json")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="dossier de sortie")
    p.add_argument("--load", action="store_true", help="indexer dans Elasticsearch et créer la data view Kibana")
    p.add_argument("--reset", action="store_true", help="avec --load : supprimer d'abord les index logs-security-*")
    p.add_argument("--no-kibana", action="store_true", help="avec --load : ne pas créer la data view")
    p.add_argument("--es-url", default=os.getenv("ES_HOST", "http://localhost:9200"))
    p.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", "http://localhost:5601"))
    args = p.parse_args()

    file_id = "".join(random.Random(args.seed).choice("0123456789abcdef") for _ in range(24))
    events = Generator(args.seed, args.days, file_id).generate(args.count)

    args.out.mkdir(parents=True, exist_ok=True)
    if args.format in ("json", "both"):
        write_json(events, args.out / "security_logs.json")
        print(f"Écrit : {args.out / 'security_logs.json'}")
    if args.format in ("csv", "both"):
        write_csv(events, args.out / "security_logs.csv")
        print(f"Écrit : {args.out / 'security_logs.csv'}")

    print(f"{len(events)} événements générés")
    for label, key in (("par type", lambda e: e["event"]["type"]), ("par gravité", lambda e: e["severity"])):
        print(f"  {label} :", dict(Counter(key(e) for e in events).most_common()))

    if args.load:
        load_elasticsearch(events, args.es_url, args.reset)
        if not args.no_kibana:
            create_data_view(args.kibana_url)


if __name__ == "__main__":
    main()
