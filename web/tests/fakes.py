"""Doublures simples de MongoDB et de Redis pour les tests (aucun serveur nécessaire)."""
from bson import ObjectId


class FakeCursor(list):
    def sort(self, key=None, direction=1):
        return FakeCursor(sorted(self, key=lambda d: d.get(key), reverse=direction == -1)) if key else self

    def limit(self, n):
        return FakeCursor(self[:n])


class FakeCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        doc = dict(doc)
        doc.setdefault("_id", ObjectId())
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    @staticmethod
    def _match(doc, query):
        for key, value in query.items():
            if isinstance(value, dict) and "$gte" in value:
                if not doc.get(key) or doc[key] < value["$gte"]:
                    return False
            elif doc.get(key) != value:
                return False
        return True

    def find_one(self, query):
        found = next((d for d in self.docs if self._match(d, query)), None)
        return dict(found) if found else None

    def find(self, query=None):
        # comme MongoDB : chaque lecture renvoie des copies (le code appelant peut modifier les documents)
        return FakeCursor(dict(d) for d in self.docs if self._match(d, query or {}))

    def update_one(self, query, update):
        doc = next((d for d in self.docs if self._match(d, query)), None)
        if doc is not None:
            doc.update(update["$set"])

    def delete_one(self, query):
        doc = next((d for d in self.docs if self._match(d, query)), None)
        if doc is not None:
            self.docs.remove(doc)
        return type("R", (), {"deleted_count": 1 if doc is not None else 0})()


class FakeDb(dict):
    def __getitem__(self, name):
        return self.setdefault(name, FakeCollection())

    @property
    def files(self):
        return self["files"]


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, _ttl, value):
        self.store[key] = value
