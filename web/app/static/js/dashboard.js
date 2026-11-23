// Tableau de bord : 4 indicateurs + 4 graphiques, alimentés par /api/v1/stats et /api/v1/files.
Chart.defaults.maintainAspectRatio = false;
const SINCE = { "24h": "now-24h", "7j": "now-7d", "30j": "now-30d" };
const SEVERITY_COLORS = {
  critical: "#dc3545", high: "#fd7e14", medium: "#ffc107", low: "#0dcaf0", info: "#6c757d",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const charts = {};

const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n).toLocaleString("fr-FR");

async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (r.status === 401) { window.location.href = "/login?next=/"; throw new Error("session expirée"); }
  if (r.status === 429) throw new Error("Trop de requêtes, réessaie dans quelques secondes.");
  if (!r.ok) throw new Error("Le serveur a répondu " + r.status + " sur " + url.split("?")[0]);
  return r.json();
}

function draw(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), config);
}

function render(stats) {
  const hasData = stats.total > 0;
  $("dash-empty").classList.toggle("d-none", hasData);

  draw("chart-per-day", {
    type: "line",
    data: {
      labels: stats.per_day.map((b) => b.key),
      datasets: [{ label: "Événements", data: stats.per_day.map((b) => b.count),
                   borderColor: "#0d6efd", backgroundColor: "rgba(13,110,253,.15)", fill: true, tension: .25 }],
    },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } },
  });

  const sev = SEVERITY_ORDER.map((k) => ({ k, c: (stats.by_severity.find((b) => b.key === k) || {}).count || 0 }))
    .filter((s) => s.c > 0);
  draw("chart-severity", {
    type: "doughnut",
    data: { labels: sev.map((s) => s.k), datasets: [{ data: sev.map((s) => s.c),
            backgroundColor: sev.map((s) => SEVERITY_COLORS[s.k]) }] },
    options: { plugins: { legend: { position: "bottom" } } },
  });

  draw("chart-top-ips", {
    type: "bar",
    data: { labels: stats.top_ips.map((b) => b.key),
            datasets: [{ label: "Événements", data: stats.top_ips.map((b) => b.count), backgroundColor: "#6610f2" }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } },
  });

  draw("chart-event-type", {
    type: "bar",
    data: { labels: stats.by_event_type.map((b) => b.key),
            datasets: [{ label: "Événements", data: stats.by_event_type.map((b) => b.count), backgroundColor: "#20c997" }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } },
  });
}

async function load() {
  const since = "date_from=" + encodeURIComponent(SINCE[$("period").value]);
  $("dash-error").classList.add("d-none");
  try {
    const [stats, failures, critical, files] = await Promise.all([
      getJSON("/api/v1/stats?" + since),
      getJSON("/api/v1/stats?event_type=authentication&result=failure&" + since),
      getJSON("/api/v1/stats?severity=critical&" + since),
      getJSON("/api/v1/files?size=1"),
    ]);
    $("kpi-events").textContent = fmt(stats.total);
    $("kpi-failures").textContent = fmt(failures.total);
    $("kpi-critical").textContent = fmt(critical.total);
    $("kpi-files").textContent = fmt(files.total);
    render(stats);
  } catch (err) {
    $("dash-error").textContent = err.message;
    $("dash-error").classList.remove("d-none");
  }
}

$("period").addEventListener("change", load);
load();
