// Page de recherche : filtres, tableau DataTables (pagination côté serveur, 50 par page),
// détail d'un événement, export CSV et historique des recherches.
const FIELDS = ["q", "event_type", "result", "severity", "country", "ip", "date_from", "date_to"];
const LABELS = { q: "texte", event_type: "type", result: "résultat", severity: "gravité",
                 country: "pays", ip: "IP", date_from: "du", date_to: "au" };
const SEVERITY_CLASS = { critical: "danger", high: "warning", medium: "warning", low: "info", info: "secondary" };
const PAGE_SIZE = 50;

const $$ = (id) => document.getElementById(id);
let table;
let historyTimer = null;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function el(tag, props = {}, text) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  if (text !== undefined) node.textContent = text;
  return node;
}
function notify(kind, text) {
  const box = $$("search-error");
  box.className = "alert alert-" + kind;
  box.textContent = text;
}
function clearNotice() { $$("search-error").className = "alert alert-danger d-none"; }

function fmtDate(iso, seconds = true) {
  const d = new Date(iso);
  if (isNaN(d)) return iso || "";
  return d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: seconds ? "medium" : "short" });
}
function toLocalInput(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes());
}

// ---------- filtres ----------
function criteria() {
  const out = {};
  FIELDS.forEach((f) => {
    let v = $$("f-" + f).value.trim();
    if (!v) return;
    if (f === "country") v = v.toUpperCase();
    if (f === "date_from" || f === "date_to") v = new Date(v).toISOString();
    out[f] = v;
  });
  return out;
}
function fillForm(values) {
  FIELDS.forEach((f) => {
    let v = values[f] || "";
    if ((f === "date_from" || f === "date_to") && v) v = toLocalInput(v);
    $$("f-" + f).value = v;
  });
}
function qs(obj) {
  const p = new URLSearchParams();
  Object.entries(obj).forEach(([k, v]) => { if (v !== "" && v !== undefined) p.set(k, v); });
  return p.toString();
}

// ---------- tableau ----------
function badge(kind, text) { return '<span class="badge text-bg-' + kind + '">' + esc(text) + "</span>"; }

function initTable() {
  table = $("#logs").DataTable({
    serverSide: true,
    processing: true,
    searching: false,
    lengthChange: false,
    pageLength: PAGE_SIZE,
    order: [[0, "desc"]],
    columnDefs: [{ orderable: false, targets: [1, 2, 3, 5, 6, 7, 8] }],
    language: {
      processing: "Chargement...", emptyTable: "Aucun événement ne correspond aux filtres.",
      zeroRecords: "Aucun événement ne correspond aux filtres.",
      info: "Événements _START_ à _END_ sur _TOTAL_", infoEmpty: "0 événement", infoFiltered: "",
      paginate: { first: "«", previous: "Précédent", next: "Suivant", last: "»" },
    },
    columns: [
      { data: null, render: (d, t, r) => esc(fmtDate(r["@timestamp"])) },
      { data: null, render: (d, t, r) => esc(r.event && r.event.type) },
      { data: null, render: (d, t, r) => esc(r.event && r.event.action) },
      { data: null, render: (d, t, r) => badge(r.result === "failure" ? "danger" : "success", r.result) },
      { data: null, render: (d, t, r) => badge(SEVERITY_CLASS[r.severity] || "secondary", r.severity) },
      { data: null, render: (d, t, r) => esc(r.source && r.source.ip) },
      { data: null, render: (d, t, r) => esc(r.source && r.source.geo && r.source.geo.country_iso_code) },
      { data: null, render: (d, t, r) => esc(r.user && r.user.name) },
      { data: null, render: (d, t, r) => '<span class="msg-cell" title="' + esc(r.message) + '">' + esc(r.message) + "</span>" },
    ],
    ajax: async (dt, callback) => {
      const order = dt.order && dt.order[0] ? dt.order[0] : { column: 0, dir: "desc" };
      const params = { ...criteria(), page: Math.floor(dt.start / dt.length) + 1, size: dt.length,
                       sort: order.column === 4 ? "severity" : "date", order: order.dir };
      const empty = { draw: dt.draw, recordsTotal: 0, recordsFiltered: 0, data: [] };
      try {
        const r = await fetch("/api/v1/logs?" + qs(params), { headers: { Accept: "application/json" } });
        if (r.status === 401) { window.location.href = "/login?next=/search"; return; }
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          notify("danger", r.status === 429 ? "Trop de requêtes, réessaie dans quelques secondes."
                                            : (d.error || "Erreur " + r.status));
          callback(empty);
          return;
        }
        clearNotice();
        callback({ draw: dt.draw, recordsTotal: d.total, recordsFiltered: d.total, data: d.results });
        if (Object.keys(criteria()).length) scheduleHistory();
      } catch (err) {
        notify("danger", "Erreur réseau.");
        callback(empty);
      }
    },
  });

  $("#logs tbody").on("click", "tr", function () {
    const row = table.row(this).data();
    if (row) showDetail(row);
  });
}

// ---------- détail d'un événement ----------
function flat(obj, prefix, out) {
  Object.entries(obj).forEach(([k, v]) => {
    const key = prefix ? prefix + "." + k : k;
    if (Array.isArray(v)) out[key] = v.join(", ");
    else if (v && typeof v === "object") flat(v, key, out);
    else out[key] = v;
  });
  return out;
}
function showDetail(row) {
  const body = $$("log-detail");
  body.replaceChildren();
  Object.entries(flat(row, "", {})).forEach(([k, v]) => {
    const tr = el("tr");
    tr.append(el("th", { className: "text-nowrap w-25" }, k), el("td", { className: "text-break" }, String(v ?? "")));
    body.append(tr);
  });
  bootstrap.Modal.getOrCreateInstance($$("log-modal")).show();
}

// ---------- export CSV ----------
async function exportCsv() {
  clearNotice();
  try {
    const r = await fetch("/api/v1/logs/export?" + qs(criteria()));
    if (r.status === 401) { window.location.href = "/login?next=/search"; return; }
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      notify("danger", d.error || "Export impossible (code " + r.status + ").");
      return;
    }
    const blob = await r.blob();
    const m = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const a = el("a", { href: URL.createObjectURL(blob), download: m ? m[1] : "export.csv" });
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    if (r.headers.get("X-Export-Truncated")) notify("warning", "Export limité aux 10 000 premiers résultats : affine tes filtres.");
  } catch (err) {
    notify("danger", "Erreur réseau pendant l'export.");
  }
}

// ---------- historique ----------
function scheduleHistory() {
  clearTimeout(historyTimer);
  historyTimer = setTimeout(loadHistory, 800);
}
async function loadHistory() {
  const list = $$("history");
  try {
    const r = await fetch("/api/v1/searches?size=10", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    list.replaceChildren();
    if (!d.results.length) {
      list.append(el("li", { className: "list-group-item text-muted" }, "Aucune recherche enregistrée."));
      return;
    }
    d.results.forEach((s) => {
      const li = el("li", { className: "list-group-item d-flex justify-content-between align-items-center gap-2 flex-wrap" });
      const left = el("div");
      Object.entries(s.criteria).forEach(([k, v]) => {
        const shown = (k === "date_from" || k === "date_to") && !isNaN(new Date(v)) ? fmtDate(v, false) : v;
        left.append(el("span", { className: "badge text-bg-light border me-1" }, (LABELS[k] || k) + " : " + shown));
      });
      left.append(el("span", { className: "small text-muted" }, s.total + " résultat(s) - " + fmtDate(s.at, false)));
      const again = el("button", { className: "btn btn-outline-primary btn-sm", type: "button" }, "Relancer");
      again.addEventListener("click", () => { fillForm(s.criteria); table.ajax.reload(); });
      li.append(left, again);
      list.append(li);
    });
  } catch (err) {
    list.replaceChildren(el("li", { className: "list-group-item text-danger" }, "Historique indisponible."));
  }
}

// ---------- démarrage ----------
$$("search-form").addEventListener("submit", (e) => { e.preventDefault(); table.ajax.reload(); });
$$("reset").addEventListener("click", () => { fillForm({}); table.ajax.reload(); });
$$("export").addEventListener("click", exportCsv);
$$("history-refresh").addEventListener("click", loadHistory);

// Filtres préremplis par l'adresse, ex. /search?severity=critical&result=failure
const initial = {};
new URLSearchParams(window.location.search).forEach((v, k) => { if (FIELDS.includes(k)) initial[k] = v; });
fillForm(initial);
initTable();
loadHistory();
