/* APIAST — Main Frontend JS | Chart.js + SSE + UI utilities */

// ── Toast Notifications ────────────────────────────────────────────────────
const toastContainer = document.getElementById("toast-container") ||
  (() => { const c = document.createElement("div"); c.id = "toast-container"; c.className = "toast-container"; document.body.appendChild(c); return c; })();

function showToast(msg, type = "info", duration = 4000) {
  const icons = { success: "✓", error: "✗", info: "ℹ" };
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${icons[type] || "•"}</span><span>${msg}</span>`;
  toastContainer.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transform = "translateX(40px)"; t.style.transition = "0.3s"; setTimeout(() => t.remove(), 350); }, duration);
}

// ── SSE Live Log Feed ──────────────────────────────────────────────────────
function connectSSE(sessionId, logEl, onEvent) {
  const es = new EventSource(`/api/scan/${sessionId}/stream`);
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === "ping") return;
      if (onEvent) onEvent(data);
      if (data.type === "log" && logEl) {
        appendLog(logEl, data.message, data.level || "INFO", data.ts);
      }
      if (data.type === "status" && (data.status === "COMPLETED" || data.status === "FAILED")) {
        es.close();
        if (data.status === "COMPLETED") showToast("Scan completed successfully!", "success");
        else showToast("Scan failed: " + (data.error || "Unknown error"), "error");
      }
    } catch (_) {}
  };
  es.onerror = () => { es.close(); };
  return es;
}

function appendLog(el, msg, level, ts) {
  const entry = document.createElement("div");
  entry.className = "log-entry";
  const time = ts ? ts.slice(11, 19) : new Date().toTimeString().slice(0, 8);
  entry.innerHTML = `<span class="log-ts">${time}</span><span class="log-${level}">[${level}]</span><span>${escHtml(msg)}</span>`;
  el.appendChild(entry);
  el.scrollTop = el.scrollHeight;
}

// ── Severity helpers ───────────────────────────────────────────────────────
function severityBadge(sev) {
  const s = (sev || "INFO").toUpperCase();
  return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`;
}
function owaspBadge(cat) {
  if (!cat) return `<span class="text-muted">—</span>`;
  return `<span class="badge badge-owasp">${cat}</span>`;
}
function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function timeAgo(isoStr) {
  if (!isoStr) return "—";
  const diff = (Date.now() - new Date(isoStr + "Z").getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff/60)}m ago`;
  if (diff < 86400) return `${Math.round(diff/3600)}h ago`;
  return `${Math.round(diff/86400)}d ago`;
}
function statusBadge(status) {
  const map = {
    COMPLETED: "badge-success", FAILED: "badge-critical",
    RUNNING: "badge-info",     PENDING: "badge-medium",
  };
  return `<span class="badge ${map[status] || "badge-info"}">${status}</span>`;
}

// ── Recommendation Accordion ───────────────────────────────────────────────
document.addEventListener("click", (e) => {
  const header = e.target.closest(".rec-header");
  if (header) {
    const body = header.nextElementSibling;
    if (body) body.classList.toggle("open");
  }
});

// ── Modal helpers ──────────────────────────────────────────────────────────
function openModal(id) { document.getElementById(id)?.classList.add("open"); }
function closeModal(id) { document.getElementById(id)?.classList.remove("open"); }
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("modal-overlay")) e.target.classList.remove("open");
  if (e.target.classList.contains("modal-close")) e.target.closest(".modal-overlay")?.classList.remove("open");
});

// ── API helpers ────────────────────────────────────────────────────────────
async function apiGet(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiPost(url, body) {
  const r = await fetch(url, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiDelete(url) {
  const r = await fetch(url, { method: "DELETE" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// ── Risk Score Chart (doughnut) ────────────────────────────────────────────
function renderRiskGauge(canvasId, score, riskLevel) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const colorMap = {
    CRITICAL: "#ff4757", HIGH: "#ff6b35", MEDIUM: "#ffa502",
    LOW: "#2ed573", INFO: "#70a1ff"
  };
  const color = colorMap[riskLevel] || "#70a1ff";
  new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [score, 10 - score],
        backgroundColor: [color, "rgba(255,255,255,0.05)"],
        borderWidth: 0, borderRadius: 4,
      }]
    },
    options: {
      cutout: "75%", responsive: true, maintainAspectRatio: true,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { duration: 1000, easing: "easeOutQuart" },
    }
  });
}

// ── Severity Bar Chart ─────────────────────────────────────────────────────
function renderSeverityChart(canvasId, counts) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0],
        backgroundColor: ["#ff4757", "#ff6b35", "#ffa502", "#2ed573"],
        borderRadius: 6, borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } },
        y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8", stepSize: 1 }, beginAtZero: true },
      },
      animation: { duration: 800 },
    }
  });
}

// ── OWASP Coverage Donut ───────────────────────────────────────────────────
function renderOwaspChart(canvasId, foundCount, totalCount) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Found", "Not Found"],
      datasets: [{
        data: [foundCount, totalCount - foundCount],
        backgroundColor: ["#ff4757", "rgba(255,255,255,0.05)"],
        borderWidth: 0, borderRadius: 4,
      }]
    },
    options: {
      cutout: "70%", responsive: true, maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: "#94a3b8", font: { size: 11 } } },
        tooltip: { enabled: true }
      },
      animation: { duration: 800 },
    }
  });
}

// ── Scan Timeline (line chart) ─────────────────────────────────────────────
function renderScanTimeline(canvasId, scans) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const labels = scans.map(s => s.created_at ? s.created_at.slice(0, 10) : "?").reverse();
  const counts = scans.map((_, i) => i + 1).reverse();
  new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Cumulative Scans",
        data: counts,
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.08)",
        fill: true, tension: 0.4,
        pointBackgroundColor: "#00d4ff",
        pointRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8", maxTicksLimit: 6 } },
        y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8", stepSize: 1 }, beginAtZero: true },
      },
    }
  });
}

// ── Active nav highlight ───────────────────────────────────────────────────
(function() {
  const path = window.location.pathname;
  document.querySelectorAll(".nav-item[data-route]").forEach(el => {
    if (path === el.dataset.route || (el.dataset.route !== "/" && path.startsWith(el.dataset.route))) {
      el.classList.add("active");
    }
  });
})();

// ── apiDelete helper ───────────────────────────────────────────────────────
async function apiDelete(url) {
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json().catch(() => ({}));
}

// ── Risk Gauge Chart ───────────────────────────────────────────────────────
let _riskGaugeChart = null;
function renderRiskGauge(canvasId, score, level) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  const ctx = el.getContext("2d");
  if (_riskGaugeChart) { _riskGaugeChart.destroy(); _riskGaugeChart = null; }
  const levelColors = { CRITICAL:"#ff4757", HIGH:"#ff6b35", MEDIUM:"#ffa502", LOW:"#2ed573", INFO:"#70a1ff" };
  const color = levelColors[level] || "#70a1ff";
  _riskGaugeChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [score, 10 - score],
        backgroundColor: [color, "rgba(255,255,255,0.05)"],
        borderWidth: 0,
        hoverOffset: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "72%",
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { animateRotate: true, duration: 800 },
    }
  });
}
