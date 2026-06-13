/* =========================================================
   WebDev Software Catalog — frontend
   ========================================================= */

/* ---- Seguridad: helpers de CSRF, URLs seguras y autenticación ----------- */

/** Lee el token CSRF del cookie emitido por el servidor. */
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

/**
 * Devuelve la URL sólo si el esquema es http(s) o relativo.
 * Bloquea javascript:, data:, vbscript: y esquemas desconocidos.
 */
function safeUrl(u) {
  if (!u) return "#";
  const lower = String(u).trim().toLowerCase().replace(/\s/g, "");
  if (/^(javascript|data|vbscript):/.test(lower)) return "#";
  return u;
}

/**
 * Parche global de fetch: añade automáticamente el token CSRF y, si la
 * instancia requiere autenticación, el token de acceso almacenado en
 * sessionStorage. También gestiona respuestas 401 (solicita el token).
 */
(function patchFetch() {
  const _orig = window.fetch.bind(window);
  window.fetch = function(url, opts = {}) {
    if (typeof url !== "string" || !url.startsWith("/api/")) {
      return _orig(url, opts);
    }
    const token = sessionStorage.getItem("webdev_auth_token") || "";
    const h = {};
    if (token) h["X-Auth-Token"] = token;
    h["X-CSRF-Token"] = getCsrfToken();
    const merged = { ...h, ...(opts.headers || {}) };
    return _orig(url, { ...opts, headers: merged }).then(async r => {
      if (r.status === 401) {
        const newToken = window.prompt(
          "⚠ Esta instancia requiere autenticación.\nIngresa el valor de WEBDEV_AUTH_TOKEN:", "");
        if (newToken !== null) {
          sessionStorage.setItem("webdev_auth_token", newToken.trim());
          return window.fetch(url, opts);   // reintento con token actualizado
        }
      }
      return r;
    });
  };
})();

/* ---- Verificar si la instancia requiere autenticación al cargar ---------- */
(async function checkAuth() {
  try {
    const d = await fetch("/api/auth-info").then(r => r.json());
    if (d.auth_required && !sessionStorage.getItem("webdev_auth_token")) {
      const t = window.prompt(
        "Esta instancia requiere autenticación.\nIngresa el token de acceso (WEBDEV_AUTH_TOKEN):", "");
      if (t) sessionStorage.setItem("webdev_auth_token", t.trim());
    }
  } catch {}
})();

const $ = (s) => document.querySelector(s);
let all = [];
let refreshTimer = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function eolField(v) {
  if (v === true)  return `<span class="vuln-bad">terminado</span>`;
  if (v === false) return `<span class="vuln-ok">activo</span>`;
  if (!v)          return `<span class="muted">—</span>`;
  const d = new Date(String(v) + "T00:00:00Z");
  const past = !isNaN(d) && d.getTime() <= Date.now();
  return `<span class="${past ? "vuln-bad" : ""}">${esc(String(v))}</span>`;
}

function statusCell(st) {
  const map = { eol: ["bad", "EOL"], obsolete: ["warn", "OBSOLETO"],
                ok: ["ok", "OK"], unknown: ["unknown", "—"] };
  const [cls, label] = map[st] || ["unknown", "—"];
  return `<span class="dot dot-${cls}"></span> ${label}`;
}

/* ---- load + render ---- */
async function load() {
  try {
    all = await fetch("/api/catalog").then(r => r.json());
  } catch (e) {
    $("#catBody").innerHTML = `<tr><td colspan="8" class="loading">Error: ${esc(e.message)}</td></tr>`;
    return;
  }
  // poblar el filtro de categorías solo si cambió el conjunto (evita rehacer el
  // <select> y perder el foco/selección innecesariamente)
  const cats = [...new Set(all.map(r => r.category).filter(Boolean))].sort();
  const sel = $("#fCategory");
  const sig = cats.join("|");
  if (sel.dataset.sig !== sig) {
    const cur = sel.value;
    sel.innerHTML = `<option value="">todas</option>` +
      cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
    sel.value = cur;
    sel.dataset.sig = sig;
  }
  render();
}

function render() {
  const q = ($("#search").value || "").trim().toLowerCase();
  const fc = $("#fCategory").value;
  const fs = $("#fStatus").value;
  const fv = $("#fVuln").value;

  let rows = all.filter(r => {
    if (fc && r.category !== fc) return false;
    if (fs && r.status !== fs) return false;
    if (fv === "vulnerable" && !(r.vuln_count > 0)) return false;
    if (fv === "clean" && r.vuln_status !== "clean") return false;
    if (q) {
      const hay = [r.slug, r.name, r.cycle, r.latest, (r.vuln_ids || []).join(" "), r.category]
        .join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  $("#rowCount").textContent = rows.length;
  if (!rows.length) {
    $("#catBody").innerHTML = `<tr><td colspan="8" class="loading">sin coincidencias</td></tr>`;
    return;
  }

  let html = "";
  let lastCat = null;
  rows.forEach((r, i) => {
    if (r.category !== lastCat) {
      html += `<tr class="cat-group-head"><td colspan="8">${esc(r.category || "otros")}</td></tr>`;
      lastCat = r.category;
    }
    const cve = r.vuln_status === "no-map" ? `<span class="muted" title="sin mapeo a OSV">n/d</span>`
      : r.vuln_status === "neterror" ? `<span class="vuln-bad">error</span>`
      : (r.vuln_count > 0
          ? `<span class="vuln-bad cve-toggle" data-i="${i}">${r.vuln_count} CVE ▸</span>`
          : r.vuln_status === "clean" ? `<span class="vuln-ok">sin CVE</span>`
          : `<span class="muted">—</span>`);
    const detail = (r.vuln_details && r.vuln_details.length)
      ? `<tr class="cve-detail-row" id="cve-${i}" hidden><td colspan="8"><div class="cve-detail-wrap">${
          r.vuln_details.map(d => `
            <div class="cve-detail">
              <div class="cve-detail-head"><strong>${esc(d.id || d.osv_id || "—")}</strong>
              ${d.severity ? `<span class="cve-sev">${esc(String(d.severity))}</span>` : ""}</div>
              ${d.summary ? `<div class="cve-summary">${esc(d.summary)}</div>` : ""}
              ${d.details ? `<div class="cve-body">${esc(d.details)}</div>` : ""}
              ${(d.references || []).slice(0,4).map(u => `<a class="cve-ref" href="${safeUrl(u)}" target="_blank" rel="noopener">${esc(u.length>72?u.slice(0,72)+'…':u)}</a>`).join("")}
            </div>`).join("")
        }</div></td></tr>`
      : "";
    html += `
      <tr class="row status-${r.status === 'eol' ? 'bad' : r.status === 'obsolete' ? 'warn' : r.status === 'ok' ? 'ok' : 'unknown'}">
        <td>${statusCell(r.status)}</td>
        <td><strong>${esc(r.name || r.slug)}</strong>${(r.name && r.name !== r.slug) ? `<div class="cat-slug">${esc(r.slug)}</div>` : ""}</td>
        <td>${esc(r.cycle)}${r.lts ? `<span class="lts-badge">LTS</span>` : ""}</td>
        <td>${r.latest ? esc(r.latest) : '<span class="muted">—</span>'}</td>
        <td>${r.release_date ? esc(r.release_date) : '<span class="muted">—</span>'}</td>
        <td>${eolField(r.support)}</td>
        <td>${eolField(r.eol)}</td>
        <td>${cve}</td>
      </tr>${detail}`;
  });
  $("#catBody").innerHTML = html;
  $("#catBody").querySelectorAll(".cve-toggle").forEach(el =>
    el.addEventListener("click", () => {
      const row = document.getElementById("cve-" + el.dataset.i);
      if (row) row.hidden = !row.hidden;
    }));
}

/* ---- status / refresh polling ---- */
async function pollStatus() {
  let st;
  try { st = await fetch("/api/status").then(r => r.json()); } catch { return; }
  const rf = st.refresh || {};
  const prog = $("#progress");
  if (rf.running) {
    prog.hidden = false;
    const pct = rf.total ? Math.round(rf.done / rf.total * 100) : 0;
    prog.querySelector("span").style.width = pct + "%";
    $("#summary").textContent = `actualizando ${rf.done}/${rf.total}…`;
    $("#refreshBtn").disabled = true;
    if (!refreshTimer) refreshTimer = setInterval(pollStatus, 1500);
  } else {
    prog.hidden = true;
    $("#refreshBtn").disabled = false;
    $("#summary").textContent = `${st.products} productos · ${st.cycles} versiones`;
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; load(); }
    if (rf.error) {
      $("#summary").textContent = "error al actualizar";
      $("#diagLog").hidden = false;
      $("#diagLog").textContent = "✗ " + rf.error + "\nRevisa la conexión/proxy y vuelve a intentar.";
    }
  }
}

/* ---- wiring ---- */
// Debounce del texto (evita re-renderizar toda la tabla en cada tecla);
// los <select> filtran al instante.
function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
const renderDebounced = debounce(render, 140);
$("#search").addEventListener("input", renderDebounced);
["fCategory", "fStatus", "fVuln"].forEach(id =>
  $("#" + id).addEventListener("change", render));

$("#refreshBtn").addEventListener("click", async () => {
  $("#refreshBtn").disabled = true;
  $("#summary").textContent = "iniciando actualización…";
  await fetch("/api/refresh", { method: "POST" });
  if (!refreshTimer) refreshTimer = setInterval(pollStatus, 1500);
  pollStatus();
});

$("#diagBtn").addEventListener("click", async () => {
  const log = $("#diagLog");
  log.hidden = false; log.textContent = "probando endoflife.date y osv.dev…";
  try {
    const d = await fetch("/api/diag").then(r => r.json());
    const lines = [`truststore (CA del SO): ${d.truststore ? "activo ✓" : "no disponible"}`,
                   `proxy en uso: ${d.proxy}`];
    for (const [n, t] of Object.entries(d.targets || {}))
      lines.push(`${n}: ${t.ok ? "OK ✓ (200)" : "FALLA — " + (t.error || ("HTTP " + t.status)) + (t.detail ? " · " + t.detail : "")}`);
    log.textContent = lines.join("\n");
  } catch (e) { log.textContent = "✗ " + e.message; }
});

$("#proxySave").addEventListener("click", async () => {
  const msg = $("#proxyMsg");
  msg.className = "proxy-status"; msg.textContent = "guardando…";
  try {
    const d = await fetch("/api/proxy", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proxy_url: $("#proxyUrl").value })
    }).then(r => r.json());
    msg.className = "proxy-status ok"; msg.textContent = "✓ guardado · usando: " + d.resolved;
  } catch (e) { msg.className = "proxy-status bad"; msg.textContent = "✗ " + e.message; }
});

$("#exportBtn").addEventListener("click", () => {
  const rows = all;
  const header = ["categoria","producto","ciclo","ultima_version","release","soporte","eol","lts","estado","cve_count","cve_ids"];
  const csv = [header.join(",")].concat(rows.map(r => [
    r.category, r.name || r.slug, r.cycle, r.latest || "", r.release_date || "",
    r.support === true ? "activo" : r.support === false ? "terminado" : (r.support || ""),
    r.eol === true ? "terminado" : r.eol === false ? "activo" : (r.eol || ""),
    r.lts ? "si" : "no", r.status, r.vuln_count ?? "", (r.vuln_ids || []).join(" ")
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(","))).join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "webdev_catalogo.csv"; a.click();
});

(async function initProxy() {
  try {
    const d = await fetch("/api/proxy").then(r => r.json());
    $("#proxyUrl").value = d.proxy_url || "";
  } catch {}
})();

function tick() { const e = $("#footClock"); if (e) e.textContent = new Date().toLocaleTimeString(); }
setInterval(tick, 1000); tick();

load();
pollStatus();

/* ============================================================ QA: auditar package.json */
let qaLast = [];
let lastPkgContent = "";
let lastFilename = "";
let lastToml = "";
let lastExtra = "";

function qaGap(d) {
  if (d.note === "neterror") return `<span class="vuln-bad">sin conexión</span>`;
  if (d.note) return `<span class="muted" title="${esc(d.note)}">${esc(d.note)}</span>`;
  if (d.outdated === false) return `<span class="vuln-ok">al día</span>`;
  if (d.gap === "major") return `<span class="vuln-bad">major ▲</span>`;
  if (d.gap === "minor") return `<span class="gap-minor">minor</span>`;
  if (d.gap === "patch") return `<span class="gap-patch">patch</span>`;
  return `<span class="muted">—</span>`;
}
function qaState(d) {
  const c = d.compliance;
  if (c && c.nivel === "crítico") return ["bad", "⚖ GRAVÍSIMO"];
  if (c && c.nivel === "alto") return ["bad", "⚖ GRAVE"];
  if ((d.vuln_count || 0) > 0) return ["bad", "VULNERABLE"];
  if (c && c.nivel === "medio") return ["warn", "⚖ REVISAR"];
  if (d.gap === "major") return ["warn", "MAJOR"];
  if (d.note === "neterror") return ["unknown", "?"];
  if (d.outdated) return ["warn", "DESACTUAL."];
  if (d.outdated === false) return ["ok", "OK"];
  return ["unknown", "—"];
}

async function runAudit() {
  const content = $("#pkgInput").value.trim();
  lastPkgContent = content;
  const file = $("#pkgFile").files[0];
  const toml = $("#tomlFile") && $("#tomlFile").files[0];
  const extra = $("#extraFile") && $("#extraFile").files[0];
  lastFilename = file ? file.name : "";
  if (!content && !file) { alert("Pega el contenido o sube un package.json / build.gradle.kts."); return; }
  $("#auditBtn").disabled = true;
  $("#auditBtn").textContent = "auditando…";
  try {
    let res;
    if (file) {
      const fd = new FormData(); fd.append("file", file);
      if (toml) fd.append("toml", toml);
      if (extra) fd.append("extra", extra);
      res = await fetch("/api/audit", { method: "POST", body: fd }).then(r => r.json());
    } else {
      res = await fetch("/api/audit", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content })
      }).then(r => r.json());
    }
    if (!res.ok) { alert(res.error || "Error al auditar"); return; }
    renderAudit(res);
  } catch (e) {
    alert("Error: " + e.message);
  } finally {
    $("#auditBtn").disabled = false;
    $("#auditBtn").textContent = "▶ auditar";
  }
}

function renderAudit(res) {
  qaLast = res.deps || [];
  const s = res.summary || {};
  const proj = res.project || {};
  // Veredicto
  let verdictCls = "ok", verdictTxt = "Sin observaciones críticas";
  if (s.compliance_critico > 0) { verdictCls = "bad"; verdictTxt = `⚖ ${s.compliance_critico} riesgo legal GRAVÍSIMO`; }
  else if (s.compliance_alto > 0) { verdictCls = "bad"; verdictTxt = `⚖ ${s.compliance_alto} riesgo legal GRAVE`; }
  else if (s.vulnerable > 0) { verdictCls = "bad"; verdictTxt = `${s.vulnerable} con CVE`; }
  else if (s.major_behind > 0) { verdictCls = "warn"; verdictTxt = `${s.major_behind} con versión major atrasada`; }
  else if (s.outdated > 0) { verdictCls = "warn"; verdictTxt = `${s.outdated} desactualizadas`; }
  const v = $("#qaVerdict");
  v.hidden = false;
  v.className = "qa-verdict " + verdictCls;
  v.innerHTML = `<strong>${esc(proj.name || "proyecto")}</strong> ${proj.version ? "v" + esc(proj.version) : ""}
    — ${esc(verdictTxt)}
    <span class="qa-counts">${s.total} deps · ${s.outdated} desactualizadas · ${s.major_behind} major · ${s.vulnerable} con CVE${s.compliance_flags ? ` · ⚖ ${s.compliance_flags} hallazgo(s) legal(es)` : ""}${s.neterror ? ` · ${s.neterror} sin conexión` : ""}</span>`;

  // Orden: vulnerables → major → minor → patch → al día
  const rank = d => (d.vuln_count > 0 ? 0 : d.gap === "major" ? 1 : d.gap === "minor" ? 2 : d.gap === "patch" ? 3 : d.outdated === false ? 5 : 4);
  const rows = [...qaLast].sort((a, b) => rank(a) - rank(b) || a.package.localeCompare(b.package));

  $("#qaBody").innerHTML = rows.map(d => {
    const [cls, label] = qaState(d);
    const cve = (d.vuln_count || 0) > 0
      ? `<span class="vuln-bad" title="${esc((d.vuln_ids || []).join(', '))}">${d.vuln_count} CVE</span>`
      : d.note === "neterror" ? `<span class="muted">?</span>`
      : d.installed ? `<span class="vuln-ok">sin CVE</span>` : `<span class="muted">—</span>`;
    return `<tr class="row">
      <td><span class="dot dot-${cls}"></span> ${label}</td>
      <td><strong>${esc(d.package)}</strong></td>
      <td class="muted">${esc(d.section)}</td>
      <td><code>${esc(d.range)}</code></td>
      <td>${d.installed ? esc(d.installed) : '<span class="muted">—</span>'}</td>
      <td>${d.latest ? esc(d.latest) : '<span class="muted">—</span>'}${d.latest_release ? `<div class="cat-slug">${esc(d.latest_release)}</div>` : ""}</td>
      <td>${qaGap(d)}</td>
      <td>${cve}</td>
    </tr>`;
  }).join("");
  $("#qaResultWrap").hidden = false;
  $("#auditExport").hidden = false;
  $("#reportBtn").hidden = false;
}

function exportAudit() {
  if (!qaLast.length) return;
  const header = ["paquete","seccion","declarada","instalada","ultima_npm","ultima_release","desfase","outdated","cve_count","cve_ids","nota"];
  const csv = [header.join(",")].concat(qaLast.map(d => [
    d.package, d.section, d.range, d.installed || "", d.latest || "", d.latest_release || "",
    d.gap || "", d.outdated, d.vuln_count ?? "", (d.vuln_ids || []).join(" "), d.note || ""
  ].map(x => `"${String(x).replace(/"/g, '""')}"`).join(","))).join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "auditoria_dependencias.csv"; a.click();
}

$("#auditBtn").addEventListener("click", runAudit);
$("#auditExport").addEventListener("click", exportAudit);
$("#pkgFile").addEventListener("change", () => {
  const f = $("#pkgFile").files[0];
  if (f) { const r = new FileReader(); r.onload = e => { $("#pkgInput").value = e.target.result; }; r.readAsText(f); }
});
if ($("#tomlFile")) $("#tomlFile").addEventListener("change", () => {
  const f = $("#tomlFile").files[0];
  if (f) { const r = new FileReader(); r.onload = e => { lastToml = e.target.result; }; r.readAsText(f); }
});
if ($("#extraFile")) $("#extraFile").addEventListener("change", () => {
  const f = $("#extraFile").files[0];
  if (f) { const r = new FileReader(); r.onload = e => { lastExtra = e.target.result; }; r.readAsText(f); }
});

/* ============================================================ Reporte IA */

function escMd(s){return esc(s);}

async function generateReport() {
  const content = lastPkgContent || $("#pkgInput").value.trim();
  if (!content) { alert("Primero audita un manifiesto."); return; }
  $("#reportBtn").disabled = true;
  $("#reportBtn").textContent = "generando…";
  const out = $("#reportOut");
  out.hidden = false;
  out.innerHTML = `<div class="cve-loading">Analizando con la base de conocimiento y generando el reporte…</div>`;
  try {
    const rep = await fetch("/api/report", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, filename: lastFilename, toml: lastToml, extra: lastExtra })
    }).then(r => r.json());
    if (!rep.ok) { out.innerHTML = `<div class="cve-loading bad">${esc(rep.error || "error")}</div>`; return; }
    renderReport(rep);
  } catch (e) {
    out.innerHTML = `<div class="cve-loading bad">Error: ${esc(e.message)}</div>`;
  } finally {
    $("#reportBtn").disabled = false;
    $("#reportBtn").textContent = "📄 generar reporte IA";
  }
}

function reportSectionsHtml(rep) {
  const ov = rep.overall || {};
  const vcls = {"crítico":"bad","alto":"bad","medio":"warn","bajo":"warn","ok":"ok"}[ov.verdict_level] || "warn";
  const tech = (rep.tecnico || []).map(t => {
    const lvlCls = {"crítico":"bad","alto":"bad","medio":"warn","bajo":"warn","ok":"ok","desconocido":"unknown"}[t.nivel] || "unknown";
    const links = [];
    if (t.homepage) links.push(`<a href="${safeUrl(t.homepage)}" target="_blank" rel="noopener">sitio oficial</a>`);
    if (t.repository) links.push(`<a href="${safeUrl(t.repository)}" target="_blank" rel="noopener">repositorio</a>`);
    if (t.npm_url) links.push(`<a href="${safeUrl(t.npm_url)}" target="_blank" rel="noopener">npm</a>`);
    if (t.eol_url) links.push(`<a href="${safeUrl(t.eol_url)}" target="_blank" rel="noopener">EOL</a>`);
    const cves = (t.cve_detalle || []).length ? `
        <div class="rep-block"><span class="rep-k">Detalle de CVE</span>
          <ul>${t.cve_detalle.map(d => `<li><strong>${esc(d.id||"")}</strong> (sev. ${esc(d.severity||"n/d")})${d.summary ? " — "+esc(d.summary) : ""}${(d.references||[]).slice(0,3).map(u=>`<br><a href="${safeUrl(u)}" target="_blank" rel="noopener" class="cve-ref">${esc(u)}</a>`).join("")}</li>`).join("")}</ul></div>` : "";
    return `
      <div class="rep-tech">
        <div class="rep-tech-head">
          <span class="dot dot-${lvlCls}"></span>
          <strong>${esc(t.package)}</strong> <span class="muted">${esc(t.installed || "—")}</span>
          <span class="rep-sev rep-sev-${lvlCls}">${esc(t.severidad)}</span>
        </div>
        ${links.length ? `<div class="rep-links">${links.join(" · ")}</div>` : ""}
        <div class="rep-block"><span class="rep-k">Riesgos conocidos</span>
          <ul>${(t.riesgos_conocidos||[]).map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>
        ${cves}
        <div class="rep-block"><span class="rep-k">Precisión técnica</span>
          <p>${esc(t.precision_tecnica)}</p></div>
        <div class="rep-block"><span class="rep-k">Medidas de mitigación recomendadas</span>
          <ul>${(t.mitigaciones||[]).map(m => `<li>${esc(m)}</li>`).join("")}</ul></div>
      </div>`;
  }).join("");
  const leg = (rep.cumplimiento_legal || []).map(h => {
    const lc = {"crítico":"bad","alto":"bad","medio":"warn"}[h.nivel] || "warn";
    return `
      <div class="rep-tech rep-legal">
        <div class="rep-tech-head">
          <span class="dot dot-${lc}"></span>
          <strong>⚖ ${esc(h.package)}</strong>
          <span class="rep-sev rep-sev-${lc}">${esc(h.nivel.toUpperCase())} · ${esc(h.categoria)}</span>
        </div>
        <div class="rep-block"><p>${esc(h.rationale)}</p></div>
        <div class="rep-block"><span class="rep-k">Disposiciones legales potencialmente aplicables</span>
          <ul>${(h.articulos||[]).map(a => `<li><strong>${esc(a.art)}:</strong> ${esc(a.texto)}</li>`).join("")}</ul></div>
        <div class="rep-block"><span class="rep-k">Recomendación</span><p>${esc(h.recomendacion||"")}</p></div>
        <div class="rep-disclaimer">${esc(h.disclaimer||"")}</div>
      </div>`;
  }).join("");
  const legalBlock = leg ? `
      <h3 class="rep-h">Análisis de Cumplimiento Legal</h3>
      <p class="rep-prose muted">Evaluación frente a la Ley 21.459 (delitos informáticos) y la Ley 19.628 (protección de datos personales).</p>
      ${leg}` : "";

  return `
      <div class="rep-verdict ${vcls}">Recomendación sobre el inventario: <strong>${esc(ov.verdict || "—")}</strong>
        · puntaje de riesgo promedio ${ov.avg_score}
        <div class="rep-note">Insumo para la evaluación final de QA (no es el veredicto único de QA).</div></div>
      <h3 class="rep-h">Análisis General</h3>
      <div class="rep-prose">${esc(rep.general || "").replace(/\n/g,"<br>")}</div>
      <h3 class="rep-h">Análisis Técnico</h3>
      ${tech}
      ${legalBlock}
      <h3 class="rep-h">Conclusión General</h3>
      <div class="rep-prose">${esc(rep.conclusion || "").replace(/\n/g,"<br>")}</div>`;
}

function renderReport(rep) {
  const ov = rep.overall || {};
  const proj = rep.project || {};
  const badge = rep.ai_used
    ? `<span class="ai-badge">✦ redactado con IA (Claude)</span>`
    : `<span class="ai-badge local">modelo de riesgo local${rep.ai_error ? " · IA: " + esc(rep.ai_error) : ""}</span>`;

  $("#reportOut").innerHTML = `
    <div class="rep-card">
      <div class="rep-title">
        <h2>Informe de inventario de software — ${esc(proj.name || "proyecto")} ${proj.version ? "v"+esc(proj.version) : ""}</h2>
        ${badge}
        <span class="rep-export">
          <span class="rep-export-lbl">exportar:</span>
          <button class="btn-ghost rep-exp" data-fmt="docx">DOCX</button>
          <button class="btn-ghost rep-exp" data-fmt="pdf">PDF</button>
          <button class="btn-ghost rep-exp" data-fmt="md">MD</button>
          <button class="btn-ghost rep-exp" data-fmt="txt">TXT</button>
          <button class="btn-ghost rep-exp" data-fmt="csv">CSV</button>
        </span>
      </div>
      <div class="rep-meta">Fecha y hora: ${esc(rep.generated_at || "")}${rep.author && rep.author !== "no indicado" ? " · Generado por: " + esc(rep.author) : ""}</div>
      ${reportSectionsHtml(rep)}
    </div>`;

  const content = lastPkgContent || $("#pkgInput").value.trim();
  $("#reportOut").querySelectorAll(".rep-exp").forEach(btn => {
    btn.addEventListener("click", async () => {
      const fmt = btn.dataset.fmt;
      const author = askAuthor();
      if (author === null) return;  // canceló
      const old = btn.textContent;
      btn.disabled = true; btn.textContent = "…";
      try {
        const resp = await fetch(`/api/report/export?format=${fmt}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content, author, filename: lastFilename, toml: lastToml, extra: lastExtra })
        });
        if (!resp.ok) { const e = await resp.json().catch(() => ({})); alert(e.error || "Error al exportar"); return; }
        const blob = await resp.blob();
        const cd = resp.headers.get("Content-Disposition") || "";
        const m = cd.match(/filename=([^;]+)/);
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = (m ? m[1].trim() : `reporte.${fmt}`);
        a.click(); URL.revokeObjectURL(a.href);
      } catch (e) { alert("Error: " + e.message); }
      finally { btn.disabled = false; btn.textContent = old; }
    });
  });
}

// Obtiene el nombre de quien genera el informe desde el campo fijo en pantalla.
// Si está vacío, lo pregunta una vez y lo deja escrito en el campo.
let lastAuthor = "";
function askAuthor() {
  const input = $("#authorInput");
  let v = (input && input.value || "").trim();
  if (!v) {
    const r = window.prompt("Nombre de quien genera el informe (aparecerá en el documento):", lastAuthor || "");
    if (r === null) return null;            // canceló
    v = r.trim();
    if (input) input.value = v;
  }
  lastAuthor = v;
  if (v) { try { fetch("/api/author", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({author: v}) }); } catch (e) {} }
  return v || "no indicado";
}

$("#reportBtn").addEventListener("click", generateReport);

/* ---- configuración IA ---- */
$("#aiSave").addEventListener("click", async () => {
  const msg = $("#aiMsg"); msg.className = "proxy-status"; msg.textContent = "guardando…";
  try {
    const d = await fetch("/api/ai-config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: $("#aiKey").value, model: $("#aiModel").value })
    }).then(r => r.json());
    msg.className = "proxy-status ok";
    msg.textContent = d.configured ? `✓ IA activa · modelo ${d.model}` : "✓ guardado (IA desactivada, solo modelo local)";
  } catch (e) { msg.className = "proxy-status bad"; msg.textContent = "✗ " + e.message; }
});

(async function initAi() {
  try {
    const d = await fetch("/api/ai-config").then(r => r.json());
    $("#aiModel").value = d.model || "";
    if (d.configured) $("#aiKey").placeholder = "•••• (ya configurada; deja vacío para mantener)";
    if (d.author && $("#authorInput")) { $("#authorInput").value = d.author; lastAuthor = d.author; }
  } catch {}
})();

/* ============================================================ Pestañas */
let histLoaded = false;
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    const view = tab.dataset.view;
    document.querySelectorAll(".view").forEach(v => v.hidden = (v.id !== "view-" + view));
    if (view === "historial") { loadHistory(); }
  });
});

/* ============================================================ Historial */
let histData = [];

function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

async function loadHistory() {
  const body = $("#histBody");
  body.innerHTML = `<tr><td colspan="9" class="loading">cargando historial…</td></tr>`;
  try {
    histData = await fetch("/api/audits").then(r => r.json());
  } catch (e) {
    body.innerHTML = `<tr><td colspan="9" class="loading">Error: ${esc(e.message)}</td></tr>`;
    return;
  }
  histLoaded = true;
  renderHistory();
}

function renderHistory() {
  const q = ($("#histSearch").value || "").trim().toLowerCase();
  const rows = histData.filter(a => !q ||
    [a.filename, a.app_name, a.app_version, a.sha256].join(" ").toLowerCase().includes(q));
  if (!rows.length) {
    $("#histBody").innerHTML = `<tr><td colspan="9" class="loading">${histData.length ? "sin coincidencias" : "aún no hay auditorías — genera un reporte en la pestaña catálogo"}</td></tr>`;
    return;
  }
  const vcls = v => /RECHAZ/i.test(v||"") ? "bad" : /OBSERV/i.test(v||"") ? "warn" : "ok";
  $("#histBody").innerHTML = rows.map(a => {
    const s = a.summary || {};
    const fmts = ["pdf","docx","md","txt","csv"];
    const dl = fmts.map(f => `<a class="hist-dl" href="/api/audits/${a.id}/export?format=${f}" title="descargar ${f.toUpperCase()}">${f}</a>`).join("");
    return `<tr class="row">
      <td class="muted" title="${esc(fmtDate(a.created_at))}">${esc((a.created_at||"").slice(0,10))}</td>
      <td><strong>${esc(a.filename || "—")}</strong></td>
      <td>${esc(a.app_name || "—")}</td>
      <td>${esc(a.app_version || "—")}</td>
      <td><span class="dot dot-${vcls(a.verdict)}"></span> ${esc(a.verdict || "—")}</td>
      <td><code class="hist-hash" title="${esc(a.sha256||"")}">${esc((a.sha256||"").slice(0,16))}…</code>
          <button class="hist-copy" data-hash="${esc(a.sha256||"")}" title="copiar hash">⧉</button></td>
      <td><button class="btn-ghost hist-view" data-id="${a.id}">👁 ver</button></td>
      <td class="hist-dls">${dl}</td>
      <td><button class="hist-del" data-id="${a.id}" title="eliminar">✖</button></td>
    </tr>`;
  }).join("");

  $("#histBody").querySelectorAll(".hist-view").forEach(b =>
    b.addEventListener("click", () => openAuditModal(b.dataset.id)));
  $("#histBody").querySelectorAll(".hist-copy").forEach(b =>
    b.addEventListener("click", () => { navigator.clipboard?.writeText(b.dataset.hash); b.textContent = "✓"; setTimeout(()=>b.textContent="⧉",1200); }));
  $("#histBody").querySelectorAll(".hist-del").forEach(b =>
    b.addEventListener("click", async () => {
      if (!confirm("¿Eliminar esta auditoría del historial?")) return;
      await fetch("/api/audits/" + b.dataset.id, { method: "DELETE" });
      loadHistory();
    }));
}

$("#histSearch").addEventListener("input", debounce(renderHistory, 140));
$("#histReload").addEventListener("click", loadHistory);

/* ============================================================ Modal de auditoría */
let modalAuditId = null;
async function openAuditModal(id) {
  modalAuditId = id;
  const ov = $("#auditModal"); const body = $("#modalBody");
  ov.hidden = false;
  body.innerHTML = `<div class="cve-loading">cargando auditoría…</div>`;
  try {
    const rep = await fetch("/api/audits/" + id).then(r => r.json());
    if (!rep.ok) { body.innerHTML = `<div class="cve-loading bad">${esc(rep.error||"error")}</div>`; return; }
    const proj = rep.project || {};
    $("#modalTitle").textContent = `Informe — ${proj.name || "proyecto"} ${proj.version ? "v"+proj.version : ""}`;
    const meta = `<div class="rep-meta">Fecha y hora: ${esc(rep.generated_at || "")}${rep.author && rep.author !== "no indicado" ? " · Generado por: " + esc(rep.author) : ""}</div>`;
    body.innerHTML = `<div class="rep-card">${meta}${reportSectionsHtml(rep)}</div>`;
  } catch (e) {
    body.innerHTML = `<div class="cve-loading bad">Error: ${esc(e.message)}</div>`;
  }
}
function closeModal() { $("#auditModal").hidden = true; modalAuditId = null; }
$("#modalClose").addEventListener("click", closeModal);
$("#auditModal").addEventListener("click", e => { if (e.target.id === "auditModal") closeModal(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });
$("#auditModal").querySelectorAll(".rep-exp-modal").forEach(btn =>
  btn.addEventListener("click", () => {
    if (modalAuditId == null) return;
    window.location.href = `/api/audits/${modalAuditId}/export?format=${btn.dataset.fmt}`;
  }));

/* ============================================================ análisis de código */
(function initCodeScan() {
  const btn = document.getElementById("codeScanBtn");
  if (!btn) return;
  const out = document.getElementById("codeScanOut");
  let lastReport = null;

  const SEV_ORDER = { "crítico": 4, "alto": 3, "medio": 2, "bajo": 1, "info": 0 };
  const SEV_CLASS = { "crítico": "sev-crit", "alto": "sev-high", "medio": "sev-med", "bajo": "sev-low", "info": "sev-info" };

  function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

  btn.addEventListener("click", async () => {
    const f = document.getElementById("codeFile").files[0];
    if (!f) { alert("Selecciona un archivo .zip, .7z o .rar."); return; }
    btn.disabled = true; const old = btn.textContent; btn.textContent = "analizando…";
    out.hidden = false;
    out.innerHTML = `<div class="loading">extrayendo y analizando en entorno aislado…</div>`;
    try {
      const fd = new FormData(); fd.append("file", f);
      const r = await fetch("/api/codescan", { method: "POST", body: fd });
      const data = await r.json();
      if (!data.ok) { out.innerHTML = `<div class="loading bad">${esc(data.error || "error")}</div>`; return; }
      lastReport = data;
      renderCodeScan(data);
    } catch (e) {
      out.innerHTML = `<div class="loading bad">Error: ${esc(e.message)}</div>`;
    } finally { btn.disabled = false; btn.textContent = old; }
  });

  function renderCodeScan(R) {
    const rs = R.resumen || {}, st = R.stats || {}, arch = R.archive || {};
    const sev = rs.por_severidad || {}, cat = rs.por_categoria || {};
    const findings = (R.findings || []).slice().sort((a, b) =>
      (SEV_ORDER[b.severidad] - SEV_ORDER[a.severidad]) || a.categoria.localeCompare(b.categoria));

    const sevChips = Object.keys(sev).sort((a, b) => SEV_ORDER[b] - SEV_ORDER[a])
      .map(k => `<span class="chip ${SEV_CLASS[k]}">${k}: ${sev[k]}</span>`).join(" ");
    const catChips = Object.entries(cat).map(([k, v]) => `<span class="chip">${esc(k)}: ${v}</span>`).join(" ");
    const langs = Object.entries(st.lenguajes || {}).map(([k, v]) => `${esc(k)} (${v})`).join(", ") || "—";
    const perms = (st.permisos_android || []).map(p => p.split(".").pop());
    const an = R.analisis || {};
    const cmp = R.cumplimiento || null;

    // Bloque de cumplimiento normativo (veredicto + matriz por instrumento).
    const ESTADO_CLS = { cumple: "ok", no_cumple: "crit", observado: "warn", no_evaluable: "info" };
    let cmpHtml = "";
    if (cmp) {
      const co = cmp.conteos || {};
      const vClass = cmp.veredicto === "CONFORME" ? "ok"
        : (cmp.veredicto === "NO CONFORME" ? "crit" : "warn");
      const instRows = (cmp.instrumentos || []).map(inst => {
        const d = (cmp.por_instrumento || {})[inst.id] || {};
        return `<tr>
          <td>${esc(inst.id)} — ${esc(inst.titulo)}</td>
          <td class="num ok">${d.cumple || 0}</td>
          <td class="num crit">${d.no_cumple || 0}</td>
          <td class="num warn">${d.observado || 0}</td>
          <td class="num">${d.no_evaluable || 0}</td></tr>`;
      }).join("");
      const noConf = (cmp.controles || []).filter(c => c.estado === "no_cumple").map(c => `
        <details class="cs-finding ${SEV_CLASS[c.severidad] || ""}">
          <summary>
            <span class="chip ${SEV_CLASS[c.severidad] || ""}">${(c.severidad || "").toUpperCase()}</span>
            <span class="cs-rule">${esc(c.instrumento)} ${esc(c.referencia)}</span>
            <span class="cs-title">${esc(c.titulo)}</span>
          </summary>
          <div class="cs-body">
            <p><strong>Exigencia:</strong> ${esc(c.exigencia)}</p>
            ${c.hallazgos && c.hallazgos.length ? `<p><strong>Evidencia (${c.n_hallazgos}):</strong> ${
              c.hallazgos.slice(0, 6).map(h => `<code>${esc(h.rule_id)}</code> en ${esc((h.archivo || "").split("/").pop())}${h.linea ? ":" + h.linea : ""}`).join("; ")}</p>` : ""}
          </div>
        </details>`).join("");
      cmpHtml = `
        <div class="cs-compliance">
          <h3>Conformidad con el marco normativo</h3>
          <p class="cs-verdict ${vClass}">Veredicto: <strong>${esc(cmp.veredicto)}</strong>
            · ${cmp.pct_cumplimiento}% de controles evaluables conformes</p>
          <p class="cs-note">${esc(cmp.veredicto_detalle || "")}</p>
          <p>${cmp.total_controles} controles evaluados ·
            <span class="chip cs-ok-chip">cumple: ${co.cumple || 0}</span>
            <span class="chip crit">no cumple: ${co.no_cumple || 0}</span>
            <span class="chip warn">observado: ${co.observado || 0}</span>
            <span class="chip">no evaluable: ${co.no_evaluable || 0}</span></p>
          <table class="cs-matrix">
            <thead><tr><th>Instrumento</th><th>Cumple</th><th>No cumple</th><th>Observado</th><th>No eval.</th></tr></thead>
            <tbody>${instRows}</tbody>
          </table>
          ${noConf ? `<h4>Controles no conformes (${(cmp.controles || []).filter(c => c.estado === "no_cumple").length})</h4>${noConf}` : ""}
        </div>`;
    }

    const NR_CLASS = { "Crítico": "sev-crit", "Alto": "sev-high", "Medio": "sev-med",
                       "Bajo": "sev-low", "Informativo": "sev-info" };
    const fragHtml = (ctx) => {
      const fr = (ctx && ctx.fragmento) || [];
      if (!fr.length) return "";
      const rows = fr.map(([ln, txt, es]) =>
        `<div class="cs-codeline${es ? " hit" : ""}">${es ? "▶" : "&nbsp;"} ${String(ln).padStart(4)} | ${esc(txt)}</div>`).join("");
      return `<div class="cs-frag">${rows}</div>`;
    };

    const rows = findings.map((f, i) => {
      const ctx = f.contexto || {};
      const nr = f.nivel_riesgo || f.severidad;
      const nrcls = NR_CLASS[nr] || SEV_CLASS[f.severidad] || "";
      return `
      <details class="cs-finding ${nrcls}">
        <summary>
          <span class="chip ${nrcls}">${esc(String(nr).toUpperCase())}</span>
          <span class="cs-rule">${esc(f.rule_id)}${f.cwe ? " · " + esc(f.cwe) : ""}</span>
          <span class="cs-title">${esc(f.titulo)}</span>
          <span class="cs-loc">${esc(f.archivo)}${f.linea ? ":" + f.linea : ""}</span>
        </summary>
        <div class="cs-body">
          ${f.descripcion_contextual ? `<p><strong>Descripción (contexto detectado):</strong> ${esc(f.descripcion_contextual)}</p>` : ""}
          ${f.explicacion_no_tecnica ? `<p><strong>Qué significa, en simple:</strong> ${esc(f.explicacion_no_tecnica)}</p>` : ""}
          <p><strong>Ubicación:</strong> <code>${esc(f.archivo)}${f.linea ? ":" + f.linea : ""}</code>
             · rol: ${esc(ctx.rol_archivo || "—")}${ctx.constructo ? " · " + esc(ctx.constructo) : ""}
             · exposición: ${esc(f.exposicion || "—")}</p>
          <p><strong>Procedencia y verificación:</strong> motor: ${esc(f.motor || "interno")}${
            f.corroborado_por && f.corroborado_por.length ? "; corroborado por: " + esc(f.corroborado_por.join(", ")) : ""}${
            (f.secreto_prob != null) ? "; verosimilitud de secreto (ML): " + Math.round(f.secreto_prob * 100) + "%" + (f.posible_falso_positivo ? " — posible falso positivo" : "") : ""}</p>
          ${f.alcanzable_taint && f.ruta_flujo ? `<p class="cs-taint"><strong>Explotabilidad (flujo de datos):</strong> ${esc(f.ruta_flujo.fuente)} (L${f.ruta_flujo.fuente_linea}) → ${esc(f.ruta_flujo.sumidero)} (L${f.ruta_flujo.sumidero_linea}) vía <code>${esc(f.ruta_flujo.var)}</code>; el dato no confiable alcanza la operación sensible.</p>` : ""}
          ${fragHtml(ctx)}
          <p class="cs-risk"><strong>Cálculo del nivel de riesgo</strong> (severidad de regla: ${esc(f.severidad)}):</p>
          <ul class="cs-risk-list">
            <li><strong>Impacto:</strong> ${esc(f.impacto_nivel || "—")} (${f.impacto || "?"}/5). ${esc(f.impacto_just || "")}</li>
            <li><strong>Probabilidad:</strong> ${esc(f.probabilidad_nivel || "—")} (${f.probabilidad || "?"}/5). ${esc(f.probabilidad_just || "")}</li>
            <li><strong>Resultado:</strong> ${f.impacto || "?"} × ${f.probabilidad || "?"} = ${f.riesgo_valor || "?"} (sobre 25) → <strong>${esc(nr)}</strong></li>
          </ul>
          ${f.impacto_contexto ? `<p><strong>Impacto en el contexto del código:</strong> ${esc(f.impacto_contexto)}</p>` : ""}
          <p><strong>Mitigación puntual:</strong> ${esc(f.mitigacion_puntual || f.mitigacion)}</p>
          ${f.controles && f.controles.length ? `<p class="cs-trace"><em>Trazabilidad de cumplimiento (ver conformidad normativa): ${esc(f.controles.join(", "))}</em></p>` : ""}
        </div>
      </details>`;
    }).join("");

    out.innerHTML = `
      <div class="cs-report">
        <div class="cs-head">
          <h2>Informe de cumplimiento — ${esc(arch.nombre || "código")}</h2>
          <span class="cs-export">
            exportar:
            <button class="btn-ghost cs-exp" data-fmt="docx">DOCX</button>
            <button class="btn-ghost cs-exp" data-fmt="pdf">PDF</button>
            <button class="btn-ghost cs-exp" data-fmt="md">MD</button>
          </span>
        </div>
        <p class="cs-meta">${arch.files || "?"} archivos · ${(arch.bytes/1048576).toFixed(1)} MB ·
          lenguajes: ${langs} · licencia: ${st.tiene_licencia ? "sí" : "<strong>no</strong>"}</p>
        <p class="cs-note">Análisis estático automatizado (SAST ligero) con razonamiento: insumo
          para la evaluación de QA y la auditoría de cumplimiento, no un dictamen jurídico. Marco:
          Guía SEGPRES v2.0, Ley 21.180 (Decretos 7/9/10/11), DS 83/2004 y Leyes 19.628/19.799/21.096/21.459.</p>
        ${an.resumen_ejecutivo ? `<p class="cs-exec"><strong>Resumen ejecutivo.</strong> ${esc(an.resumen_ejecutivo)}</p>` : ""}
        ${an.nivel_global ? `<p class="cs-meta">Nivel de riesgo agregado: <strong>${esc(an.nivel_global)}</strong></p>` : ""}
        ${(() => {
          const m = (R.motores && R.motores.por_motor) || (rs.por_motor) || {};
          const keys = Object.keys(m);
          const taint = (R._taint || []).length;
          if (!keys.length && !taint) return "";
          let s = keys.length ? "Motores: " + keys.map(k => `${esc(k)} (${m[k]})`).join(", ") : "";
          if (taint) s += (s ? " · " : "") + `rutas de flujo de datos: ${taint}`;
          return `<p class="cs-meta">${s}</p>`;
        })()}
        <div class="cs-summary">${sevChips} &nbsp;|&nbsp; ${catChips}</div>
        ${perms.length ? `<p class="cs-perms"><strong>Permisos Android (${perms.length}):</strong> ${esc(perms.join(", "))}</p>` : ""}
        ${cmpHtml}
        <h3>Observaciones detalladas (${findings.length})</h3>
        ${rows || '<p class="cs-ok">Sin observaciones detectadas por las reglas actuales.</p>'}
      </div>`;

    out.querySelectorAll(".cs-exp").forEach(b => b.addEventListener("click", async () => {
      const fmt = b.dataset.fmt;
      const author = (document.getElementById("codeAuthor").value || "").trim() || "no indicado";
      const old = b.textContent; b.disabled = true; b.textContent = "…";
      try {
        const resp = await fetch(`/api/codescan/export?format=${fmt}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ report: lastReport, author })
        });
        if (!resp.ok) { alert("Error al exportar"); return; }
        const blob = await resp.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `informe_cumplimiento.${fmt}`;
        a.click(); URL.revokeObjectURL(a.href);
      } catch (e) { alert("Error: " + e.message); }
      finally { b.disabled = false; b.textContent = old; }
    }));
  }
})();
