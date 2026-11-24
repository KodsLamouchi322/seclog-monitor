// Page d'import : glisser-déposer, barre de progression, liste des fichiers avec statut.
const app = document.getElementById("upload-app");
const MAX_BYTES = Number(app.dataset.maxMb) * 1024 * 1024;
const ALLOWED = ["csv", "json", "txt"];
const PAGE_SIZE = 10;
const POLL_MS = 5000;
const POLL_MAX = 3; // au plus 3 fichiers vérifiés par cycle (limite de débit de l'API)

const $ = (id) => document.getElementById(id);
let selected = null;
let page = 1;
let pollTimer = null;

// ---------- utilitaires ----------
function el(tag, props = {}, text) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  if (text !== undefined) node.textContent = text;
  return node;
}
function fmtSize(b) {
  if (b >= 1048576) return (b / 1048576).toFixed(1).replace(".", ",") + " Mo";
  if (b >= 1024) return Math.round(b / 1024) + " Ko";
  return b + " o";
}
function fmtDate(s) {
  if (!s) return "-";
  // MongoDB renvoie des dates UTC sans fuseau : on ajoute Z pour un affichage à l'heure locale
  const d = new Date(/(Z|[+-]\d\d:\d\d)$/.test(s) ? s : s + "Z");
  return d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}
function alertBox(kind, text) {
  const box = el("div", { className: "alert alert-" + kind }, text);
  $("result").replaceChildren(box);
  return box;
}
const STATUS = {
  pending: ["warning", "En cours d'ingestion"],
  ingested: ["success", "Ingéré"],
};
function badge(status) {
  const [kind, label] = STATUS[status] || ["secondary", status];
  return el("span", { className: "badge text-bg-" + kind }, label);
}

// ---------- sélection et envoi ----------
function choose(file) {
  const ext = (file.name.split(".").pop() || "").toLowerCase();
  $("chosen").textContent = "";
  selected = null;
  $("send").disabled = true;
  if (!ALLOWED.includes(ext)) { alertBox("warning", "Format non accepté : choisis un fichier .csv, .json ou .txt."); return; }
  if (file.size > MAX_BYTES) { alertBox("warning", "Fichier trop volumineux (max " + app.dataset.maxMb + " Mo)."); return; }
  $("result").replaceChildren();
  selected = file;
  $("chosen").textContent = file.name + " (" + fmtSize(file.size) + ")";
  $("send").disabled = false;
}

const dz = $("dropzone");
dz.addEventListener("click", () => $("file").click());
dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } });
["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("dragover"); }));
["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("dragover"); }));
dz.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) choose(e.dataTransfer.files[0]); });
$("file").addEventListener("change", (e) => { if (e.target.files.length) choose(e.target.files[0]); });

function setProgress(pct) {
  const bar = $("progress-bar");
  bar.style.width = pct + "%";
  bar.textContent = pct + " %";
}

function showPreview(d) {
  const box = el("div");
  box.append(el("div", { className: "alert alert-success" },
    "Fichier accepté : " + d.total_lines + " lignes, " + d.invalid_lines + " invalides. Statut : " + d.status + "."));
  if (d.preview && d.preview.length) {
    const rows = d.preview;
    const isObj = typeof rows[0] === "object" && rows[0] !== null;
    const table = el("table", { className: "table table-sm table-striped bg-white" });
    if (isObj) {
      const tr = el("tr");
      Object.keys(rows[0]).forEach((k) => tr.append(el("th", {}, k)));
      table.append(el("thead")).firstChild.append(tr);
    }
    const tbody = el("tbody");
    rows.forEach((row) => {
      const tr = el("tr");
      if (isObj) {
        Object.values(row).forEach((v) => tr.append(el("td", {}, typeof v === "object" ? JSON.stringify(v) : String(v ?? ""))));
      } else {
        tr.append(el("td", {}, String(row)));
      }
      tbody.append(tr);
    });
    table.append(tbody);
    const wrap = el("div", { className: "table-responsive" });
    wrap.append(el("div", { className: "small text-muted mb-1" }, "Prévisualisation (10 premières lignes)"), table);
    box.append(wrap);
  }
  $("result").replaceChildren(box);
}

$("send").addEventListener("click", () => {
  if (!selected) return;
  const fd = new FormData();
  fd.append("file", selected);
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/upload");
  $("send").disabled = true;
  $("progress-wrap").classList.remove("d-none");
  setProgress(0);
  $("result").replaceChildren();
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) setProgress(Math.round((e.loaded / e.total) * 100)); };
  xhr.onload = () => {
    $("progress-wrap").classList.add("d-none");
    let d = {};
    try { d = JSON.parse(xhr.responseText); } catch (err) { /* réponse non JSON */ }
    if (xhr.status === 401) { window.location.href = "/login?next=/upload"; return; }
    if (xhr.status === 201) {
      showPreview(d);
      selected = null;
      $("chosen").textContent = "";
      $("file").value = "";
      page = 1;
      loadFiles();
      return;
    }
    $("send").disabled = false;
    alertBox("danger", d.message || d.error || "Échec de l'envoi (code " + xhr.status + ").");
  };
  xhr.onerror = () => {
    $("progress-wrap").classList.add("d-none");
    $("send").disabled = false;
    alertBox("danger", "Erreur réseau pendant l'envoi.");
  };
  xhr.send(fd);
});

// ---------- liste des fichiers ----------
function row(f) {
  const tr = el("tr", { id: "file-" + f.id });
  tr.dataset.status = f.status;
  tr.append(el("td", {}, f.original_name), el("td", {}, (f.format || "").toUpperCase()),
    el("td", { className: "text-end" }, fmtSize(f.size_bytes || 0)),
    el("td", { className: "text-end" }, (f.total_lines ?? "-") + " (" + (f.invalid_lines ?? 0) + ")"));
  const st = el("td", { className: "status-cell" });
  st.append(badge(f.status));
  tr.append(st, el("td", {}, fmtDate(f.uploaded_at)));
  return tr;
}

async function loadFiles() {
  clearTimeout(pollTimer);
  $("files-error").classList.add("d-none");
  const status = $("status-filter").value;
  const qs = "page=" + page + "&size=" + PAGE_SIZE + (status ? "&status=" + encodeURIComponent(status) : "");
  try {
    const r = await fetch("/api/v1/files?" + qs, { headers: { Accept: "application/json" } });
    if (r.status === 401) { window.location.href = "/login?next=/upload"; return; }
    if (!r.ok) throw new Error("Le serveur a répondu " + r.status);
    const d = await r.json();
    const body = $("files-body");
    body.replaceChildren();
    if (!d.results.length) {
      const tr = el("tr"); const td = el("td", { colSpan: 6, className: "text-center text-muted py-3" }, "Aucun fichier.");
      tr.append(td); body.append(tr);
    } else {
      d.results.forEach((f) => body.append(row(f)));
    }
    const pages = Math.max(1, Math.ceil(d.total / PAGE_SIZE));
    $("files-info").textContent = d.total + " fichier(s) - page " + d.page + " / " + pages;
    $("prev").disabled = d.page <= 1;
    $("next").disabled = d.page >= pages;
    schedulePoll();
  } catch (err) {
    $("files-error").textContent = "Impossible de charger la liste : " + err.message;
    $("files-error").classList.remove("d-none");
  }
}

// Les fichiers « pending » passent à « ingested » quand Elasticsearch contient toutes leurs lignes
function schedulePoll() {
  const pending = [...document.querySelectorAll('#files-body tr[data-status="pending"]')];
  if (!pending.length) return;
  pollTimer = setTimeout(async () => {
    for (const tr of pending.slice(0, POLL_MAX)) {
      try {
        const r = await fetch("/api/v1/files/" + tr.id.replace("file-", ""), { headers: { Accept: "application/json" } });
        if (!r.ok) continue;
        const f = await r.json();
        if (f.status !== tr.dataset.status) {
          tr.dataset.status = f.status;
          tr.querySelector(".status-cell").replaceChildren(badge(f.status));
        }
      } catch (err) { /* on réessaie au cycle suivant */ }
    }
    schedulePoll();
  }, POLL_MS);
}

$("status-filter").addEventListener("change", () => { page = 1; loadFiles(); });
$("refresh").addEventListener("click", loadFiles);
$("prev").addEventListener("click", () => { if (page > 1) { page -= 1; loadFiles(); } });
$("next").addEventListener("click", () => { page += 1; loadFiles(); });
loadFiles();
