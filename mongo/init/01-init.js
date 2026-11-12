// Exécuté une seule fois, à la première création du volume mongodata.
const seclog = db.getSiblingDB("seclog");

["users", "files", "search_history", "alert_rules", "alerts"].forEach((name) => {
  if (!seclog.getCollectionNames().includes(name)) {
    seclog.createCollection(name);
  }
});

seclog.users.createIndex({ email: 1 }, { unique: true });
seclog.files.createIndex({ uploaded_at: -1 });
seclog.files.createIndex({ status: 1 });
seclog.search_history.createIndex({ user_id: 1, executed_at: -1 });
seclog.alert_rules.createIndex({ enabled: 1 });
seclog.alerts.createIndex({ status: 1, triggered_at: -1 });
seclog.alerts.createIndex({ source_ip: 1 });

print("SecLog : collections et index créés");
