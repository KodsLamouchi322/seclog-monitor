// Gestion des règles d'alerte : liste, création, modification, activation, suppression et test.
const app = document.getElementById("rules-app");
const IS_ADMIN = app.dataset.admin === "true";
const $ = (id) => document.getElementById(id);
const SEVERITY_CLASS = { critical: "danger", high: "warning", medium: "warning", low: "info" };

let meta = { types: [], severities: [] };
let rules = [];
let editingId = null;
let modal = null;

function el(tag, props = {}, text) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  if (text !== undefined) node.textContent = text;
  return node;
}
function typeLabel(id) { return (meta.types.find((t) => t.id === id) || {}).label || id; }
function windowText(m) { return m >= 60 && m % 60 === 0 ? (m / 60) + " h" : m + " min"; }
function paramsText(r) {
  const p = r.params || {};
  if (r.type === "silent_host") return "équipement : " + p.host;
  if (r.type === "unauthorized_country") return "autorisés : " + (p.allowed_countries || []).join(", ");
  return "seuil : " + p.threshold + (r.block_ip ? " + blocage d'IP" : "");
}

async function api(url, options = {}) {
  const r = await fetch(url, { headers: { Accept: "application/json", "Content-Type": "application/json" }, ...options });
  if (r.status === 401) { window.location.href = "/login?next=/rules"; throw new Error("session expirée"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || data.message || "Erreur " + r.status);
  return data;
}
function showError(text) {
  const box = $("rules-error");
  box.textContent = text;
  box.classList.toggle("d-none", !text);
}

// ---------- affichage du résultat d'un test ----------
function renderTest(target, result, name) {
  const box = el("div", { className: "alert alert-" + (result.matched ? "warning" : "success") });
  const head = result.matched
    ? "La règle « " + name + " » aurait déclenché une alerte : " + result.findings.length + " correspondance(s), " + result.total + " événement(s) sur " + windowText(result.window_minutes) + "."
    : "La règle « " + name + " » ne se déclencherait pas sur les " + windowText(result.window_minutes) + " écoulées.";
  box.append(el("div", { className: "fw-semibold" }, head));
  if (result.matched) {
    const ul = el("ul", { className: "mb-0 mt-1" });
    result.findings.slice(0, 10).forEach((f) => {
      ul.append(el("li", {}, f.key + " : " + f.count + " événement(s)" + (f.detail ? " (" + f.detail + ")" : "")));
    });
    box.append(ul);
  }
  target.replaceChildren(box);
}

// ---------- liste ----------
function render() {
  const body = $("rules-body");
  body.replaceChildren();
  if (!rules.length) {
    const tr = el("tr");
    tr.append(el("td", { colSpan: 7, className: "text-center text-muted py-3" }, "Aucune règle pour l'instant."));
    body.append(tr);
    return;
  }
  rules.forEach((r) => {
    const tr = el("tr");
    const sw = el("input", { type: "checkbox", className: "form-check-input", checked: !!r.enabled, disabled: !IS_ADMIN });
    sw.setAttribute("aria-label", "Activer la règle " + r.name);
    sw.addEventListener("change", () => toggle(r, sw));
    const swWrap = el("div", { className: "form-check form-switch" });
    swWrap.append(sw);
    const sev = el("span", { className: "badge text-bg-" + (SEVERITY_CLASS[r.severity] || "secondary") }, r.severity);
    const actions = el("td", { className: "text-nowrap text-end" });
    if (IS_ADMIN) {
      const test = el("button", { className: "btn btn-outline-secondary btn-sm me-1", type: "button" }, "Tester");
      test.addEventListener("click", () => testSaved(r));
      const edit = el("button", { className: "btn btn-outline-primary btn-sm me-1", type: "button" }, "Modifier");
      edit.addEventListener("click", () => openForm(r));
      const del = el("button", { className: "btn btn-outline-danger btn-sm", type: "button" }, "Supprimer");
      del.addEventListener("click", () => remove(r));
      actions.append(test, edit, del);
    }
    tr.append(el("td", { className: "fw-semibold" }, r.name), el("td", {}, typeLabel(r.type)));
    const sevTd = el("td"); sevTd.append(sev);
    const swTd = el("td"); swTd.append(swWrap);
    tr.append(sevTd, el("td", {}, windowText(r.window_minutes)), el("td", {}, paramsText(r)), swTd, actions);
    body.append(tr);
  });
}

async function load() {
  try {
    showError("");
    [meta, rules] = await Promise.all([api("/api/v1/rules/types"), api("/api/v1/rules").then((d) => d.results)]);
    const sel = $("r-severity");
    if (!sel.options.length) meta.severities.forEach((s) => sel.append(new Option(s, s)));
    const typeSel = $("r-type");
    if (!typeSel.options.length) meta.types.forEach((t) => typeSel.append(new Option(t.label, t.id)));
    render();
  } catch (err) {
    showError("Impossible de charger les règles : " + err.message);
  }
}

// ---------- actions ----------
async function toggle(rule, checkbox) {
  try {
    showError("");
    const updated = await api("/api/v1/rules/" + rule.id, { method: "PATCH", body: JSON.stringify({ enabled: checkbox.checked }) });
    rule.enabled = updated.enabled;
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    showError(err.message);
  }
}
async function remove(rule) {
  if (!window.confirm("Supprimer la règle « " + rule.name + " » ?")) return;
  try {
    showError("");
    await api("/api/v1/rules/" + rule.id, { method: "DELETE" });
    await load();
  } catch (err) { showError(err.message); }
}
function payload(rule) {
  return { name: rule.name, type: rule.type, severity: rule.severity, window_minutes: rule.window_minutes,
           cooldown_minutes: rule.cooldown_minutes, enabled: rule.enabled, block_ip: rule.block_ip, params: rule.params };
}
async function testSaved(rule) {
  try {
    showError("");
    renderTest($("test-result"), await api("/api/v1/rules/test", { method: "POST", body: JSON.stringify(payload(rule)) }), rule.name);
  } catch (err) { showError(err.message); }
}

// ---------- formulaire ----------
function syncParams() {
  const type = $("r-type").value;
  document.querySelectorAll(".param").forEach((n) => n.classList.add("d-none"));
  if (type === "silent_host") document.querySelector(".param-host").classList.remove("d-none");
  else if (type === "unauthorized_country") document.querySelector(".param-countries").classList.remove("d-none");
  else document.querySelector(".param-threshold").classList.remove("d-none");
  const canBlock = (meta.types.find((t) => t.id === type) || {}).can_block;
  $("block-wrap").classList.toggle("d-none", !canBlock);
  if (!canBlock) $("r-block").checked = false;
}
function openForm(rule) {
  editingId = rule ? rule.id : null;
  $("rule-modal-title").textContent = rule ? "Modifier la règle" : "Nouvelle règle";
  const r = rule || { name: "", type: meta.types[0].id, severity: "medium", window_minutes: 15, cooldown_minutes: 15,
                      enabled: true, block_ip: false, params: { threshold: 5 } };
  $("r-name").value = r.name;
  $("r-type").value = r.type;
  $("r-severity").value = r.severity;
  $("r-window").value = r.window_minutes;
  $("r-cooldown").value = r.cooldown_minutes;
  $("r-enabled").checked = !!r.enabled;
  $("r-block").checked = !!r.block_ip;
  $("r-threshold").value = (r.params || {}).threshold || 5;
  $("r-host").value = (r.params || {}).host || "";
  $("r-countries").value = ((r.params || {}).allowed_countries || []).join(", ");
  $("form-error").classList.add("d-none");
  $("modal-test").replaceChildren();
  syncParams();
  modal = bootstrap.Modal.getOrCreateInstance($("rule-modal"));
  modal.show();
}
function formRule() {
  const type = $("r-type").value;
  let params;
  if (type === "silent_host") params = { host: $("r-host").value.trim() };
  else if (type === "unauthorized_country") params = { allowed_countries: $("r-countries").value.split(",").map((c) => c.trim()).filter(Boolean) };
  else params = { threshold: Number($("r-threshold").value) };
  return { name: $("r-name").value.trim(), type, severity: $("r-severity").value,
           window_minutes: Number($("r-window").value), cooldown_minutes: Number($("r-cooldown").value),
           enabled: $("r-enabled").checked, block_ip: $("r-block").checked, params };
}
function formError(text) {
  const box = $("form-error");
  box.textContent = text;
  box.classList.toggle("d-none", !text);
}

$("r-type").addEventListener("change", syncParams);
$("rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    formError("");
    const url = editingId ? "/api/v1/rules/" + editingId : "/api/v1/rules";
    await api(url, { method: editingId ? "PUT" : "POST", body: JSON.stringify(formRule()) });
    modal.hide();
    await load();
  } catch (err) { formError(err.message); }
});
$("modal-test-btn").addEventListener("click", async () => {
  try {
    formError("");
    const rule = formRule();
    renderTest($("modal-test"), await api("/api/v1/rules/test", { method: "POST", body: JSON.stringify(rule) }), rule.name || "sans nom");
  } catch (err) { formError(err.message); }
});
if (IS_ADMIN) $("new-rule").addEventListener("click", () => openForm(null));

load();
