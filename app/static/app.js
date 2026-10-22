"use strict";
const MASK = "*REDACTED*";
const STORE = "scrubber.prefs.v2";
const LIST_IDS = ["keys", "terms", "allowlist"];
const $ = (id) => document.getElementById(id);
let defaults = null;
let lastResult = null;
let dirty = false;

const lines = (s) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

function loadSaved() {
  try { return JSON.parse(localStorage.getItem(STORE)) || {}; } catch { return {}; }
}
function save() {
  const s = {
    categories: [...document.querySelectorAll("#categories input:checked")].map((i) => i.value),
    auto: $("auto").checked,
  };
  try { localStorage.setItem(STORE, JSON.stringify(s)); } catch { /* storage unavailable */ }
}

function setDirty(value, message) {
  dirty = value;
  const el = $("settings-status");
  el.classList.toggle("dirty", value);
  el.textContent = message ?? (value ? "Unsaved changes" : "");
}

function applyLists() {
  $("allowlist").value = defaults.allowlist.join("\n");
  $("terms").value = defaults.custom_terms.join("\n");
  $("keys").value = defaults.custom_keys.join("\n");
  setDirty(false);
}

async function saveSettings() {
  try {
    const res = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        custom_keys: lines($("keys").value),
        custom_terms: lines($("terms").value),
        allowlist: lines($("allowlist").value),
      }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    defaults = body;
    applyLists();
    setDirty(false, "Saved to the config folder");
  } catch (e) {
    setDirty(true, `Not saved: ${e.message}`);
  }
}

async function discardChanges() {
  defaults = await (await fetch("/api/defaults")).json();
  applyLists();
}

function applySettings(s) {
  const enabled = new Set(s.categories || defaults.categories.map((c) => c.id));
  const box = $("categories");
  box.replaceChildren();
  for (const c of defaults.categories) {
    const label = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = c.id; cb.checked = enabled.has(c.id);
    label.append(cb, c.label);
    box.append(label);
  }
  $("auto").checked = !!s.auto;
  applyLists();
}

function renderOutput(text) {
  const out = $("output");
  out.replaceChildren();
  const parts = text.split(MASK);
  parts.forEach((p, i) => {
    out.append(document.createTextNode(p));
    if (i < parts.length - 1) {
      const m = document.createElement("mark");
      m.textContent = MASK;
      out.append(m);
    }
  });
}

function renderFindings(r) {
  const total = Object.values(r.counts).reduce((a, b) => a + b, 0);
  $("findings-box").hidden = false;
  $("total").textContent = `(${total} redacted)`;
  const labels = Object.fromEntries(defaults.categories.map((c) => [c.id, c.label]));
  $("counts").replaceChildren(...Object.entries(r.counts).map(([k, n]) => {
    const s = document.createElement("span");
    s.className = "chip";
    s.textContent = `${labels[k] || k}: ${n}`;
    return s;
  }));
  const body = $("findings").querySelector("tbody");
  body.replaceChildren(...r.findings.map((f) => {
    const tr = document.createElement("tr");
    const td = (t, cls) => { const d = document.createElement("td"); d.textContent = t; if (cls) d.className = cls; return d; };
    tr.append(td(f.label), td(f.value, "val"), td(String(f.count)));
    return tr;
  }));
  $("findings").hidden = !$("show-values").checked;
}

async function doScrub() {
  const text = $("input").value;
  if (!text) return;
  $("status").textContent = "Scrubbing...";
  const t0 = performance.now();
  try {
    const res = await fetch("/api/scrub", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        categories: [...document.querySelectorAll("#categories input:checked")].map((i) => i.value),
        allowlist: lines($("allowlist").value),
        custom_terms: lines($("terms").value),
        custom_keys: lines($("keys").value),
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    lastResult = await res.json();
    renderOutput(lastResult.text);
    renderFindings(lastResult);
    $("copy").disabled = false;
    $("status").textContent = `Done in ${Math.round(performance.now() - t0)} ms`;
  } catch (e) {
    $("status").textContent = `Error: ${e.message}`;
  }
}

async function copyResult() {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(lastResult.text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = lastResult.text; document.body.append(ta); ta.select();
    document.execCommand("copy"); ta.remove();
  }
  $("status").textContent = "Copied to clipboard";
}

function clearAll() {
  $("input").value = "";
  $("output").replaceChildren();
  $("findings-box").hidden = true;
  $("copy").disabled = true;
  $("status").textContent = "";
  lastResult = null;
  $("input").focus();
}

async function init() {
  defaults = await (await fetch("/api/defaults")).json();
  applySettings(loadSaved());
  $("scrub").addEventListener("click", doScrub);
  $("copy").addEventListener("click", copyResult);
  $("clear").addEventListener("click", clearAll);
  $("show-values").addEventListener("change", () => { $("findings").hidden = !$("show-values").checked; });
  $("save-settings").addEventListener("click", saveSettings);
  $("reset").addEventListener("click", discardChanges);
  for (const id of ["categories", "auto"]) $(id).addEventListener("change", save);
  for (const id of LIST_IDS) $(id).addEventListener("input", () => setDirty(true));
  window.addEventListener("beforeunload", (e) => { if (dirty) e.preventDefault(); });
  $("input").addEventListener("paste", () => { if ($("auto").checked) setTimeout(doScrub, 0); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); doScrub(); }
    if (e.key === "s" && (e.ctrlKey || e.metaKey) && dirty) { e.preventDefault(); saveSettings(); }
  });
  $("input").focus();
}

init();
