"use strict";

const state = { csrf: "", snapshot: null, activeView: "overview" };
const titles = {
  overview: "Security overview",
  detections: "Detection history",
  blocks: "Active firewall blocks",
  allowlist: "Trusted sources",
  audit: "Audit trail",
  health: "System health",
};

const $ = (selector) => document.querySelector(selector);
const all = (selector) => Array.from(document.querySelectorAll(selector));
const text = (value) => value === null || value === undefined || value === "" ? "—" : String(value);
const escapeClass = (value) => String(value || "").toLowerCase().replace(/[^a-z]/g, "");
const time = (value) => value ? new Date(value).toLocaleString() : "—";
const statusClass = (value) => {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("healthy") || normalized.includes("active") || normalized.includes("success")) return "good";
  if (normalized.includes("high") || normalized.includes("failed") || normalized.includes("error")) return "danger";
  return "warn";
};

function element(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = text(content);
  return node;
}

function empty(container, message) {
  container.replaceChildren(element("div", "empty", message));
}

function badge(value) {
  return element("span", `badge ${statusClass(value)}`, value);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(state.csrf ? { "X-CSRF-Token": state.csrf } : {}),
    },
    cache: "no-store",
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function notice(message, error = false) {
  const target = $("#notice");
  target.textContent = message;
  target.classList.toggle("error", error);
  target.hidden = false;
  window.setTimeout(() => { target.hidden = true; }, 6000);
}

function showView(name) {
  state.activeView = name;
  all(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  all(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  $("#page-title").textContent = titles[name];
}

function renderOverview(data) {
  const overview = data.overview;
  $("#operating-mode").textContent = text(overview.operating_mode).replaceAll("_", " ");
  $("#hero-risk-count").textContent = text(overview.high_risk_detections);
  const metrics = [
    ["Authentication events", overview.authentication_events, "JOURNAL EVIDENCE"],
    ["Network events", overview.network_events, "TCP/22 METADATA"],
    ["Suspicious detections", overview.suspicious_detections, "REVIEW REQUIRED"],
    ["Active blocks", overview.active_blocks, "TEMPORARY RULES"],
    ["Expired blocks", overview.expired_blocks, "REMOVED ON TIME"],
    ["Manual removals", overview.manual_removals, "OPERATOR ACTIONS"],
    ["Parser errors", overview.recent_parser_errors, "LAST 10 RECORDS"],
    ["Operating mode", String(overview.operating_mode).replaceAll("_", " "), "RESPONSE CONTROL"],
  ];
  const metricGrid = $("#metric-grid");
  metricGrid.replaceChildren(...metrics.map(([label, value, hint]) => {
    const card = element("article", "metric");
    card.append(element("small", "", label), element("strong", "", value), element("div", "trend", hint));
    return card;
  }));

  const signals = $("#overview-detections");
  if (!data.detections.length) empty(signals, "No detections have been stored.");
  else signals.replaceChildren(...data.detections.slice(0, 5).map((row) => {
    const item = element("div", "signal");
    const details = element("div");
    details.append(element("strong", "", row.source_ip), element("small", "", `${row.failed_attempts} failures · ${row.network_connections} connections`));
    item.append(details, badge(`${row.classification} · ${row.risk_score}`));
    return item;
  }));

  const health = $("#overview-health");
  if (!data.health.length) empty(health, "No health checks have reported yet.");
  else health.replaceChildren(...data.health.slice(0, 6).map((row) => {
    const item = element("div", "health-row");
    const details = element("div");
    details.append(element("strong", "", row.component.replaceAll("_", " ")), element("small", "", row.last_success ? `Last success ${time(row.last_success)}` : "Awaiting first success"));
    item.append(details, badge(row.status));
    return item;
  }));
}

function renderTable(selector, columns, rows) {
  const table = $(selector);
  table.replaceChildren();
  const headRow = document.createElement("tr");
  columns.forEach(([key, label]) => headRow.append(element("th", "", label)));
  const head = document.createElement("thead");
  head.append(headRow);
  const body = document.createElement("tbody");
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = element("td", "empty", "No records.");
    cell.colSpan = columns.length;
    row.append(cell);
    body.append(row);
  } else {
    rows.forEach((record) => {
      const row = document.createElement("tr");
      columns.forEach(([key]) => {
        const value = key.endsWith("_at") || key.endsWith("_time") ? time(record[key]) : record[key];
        const cell = element("td", key === "details" || key === "result" ? "wrap" : "", value);
        if (key === "classification" || key === "status" || key === "decision") {
          cell.replaceChildren(badge(value));
        }
        row.append(cell);
      });
      body.append(row);
    });
  }
  table.append(head, body);
}

function renderDetections(rows) {
  renderTable("#detections-table", [
    ["detection_time", "Time"], ["source_ip", "Source"], ["ip_category", "Category"],
    ["failed_attempts", "Failures"], ["invalid_user_attempts", "Invalid users"],
    ["unique_usernames", "Users"], ["network_connections", "Connections"],
    ["attempt_rate", "Rate/min"], ["risk_score", "Score"], ["classification", "Class"],
    ["decision", "Decision"],
  ], rows);
}

function renderBlocks(rows) {
  const grid = $("#blocks-grid");
  if (!rows.length) {
    empty(grid, "No active temporary blocks.");
    return;
  }
  grid.replaceChildren(...rows.map((row) => {
    const card = element("article", "data-card");
    const header = document.createElement("header");
    const title = element("div");
    title.append(element("p", "eyebrow", "BLOCKED SOURCE"), element("h3", "", row.source_ip));
    header.append(title, badge(row.status));
    const countdown = element("div", "countdown", `${row.remaining_seconds}s`);
    countdown.dataset.expiresAt = row.expires_at;
    const details = document.createElement("dl");
    [["Blocked", time(row.blocked_at)], ["Expires", time(row.expires_at)], ["Firewall", row.firewall_state], ["Result", row.last_firewall_result]].forEach(([label, value]) => {
      const wrapper = document.createElement("div");
      wrapper.append(element("dt", "", label), element("dd", "", value));
      details.append(wrapper);
    });
    const button = element("button", "button danger", "Request manual unblock");
    button.addEventListener("click", async () => {
      const reason = window.prompt("Reason for manually removing this block:");
      if (!reason) return;
      try {
        const result = await api("/api/actions/manual-unblock", {
          method: "POST",
          body: JSON.stringify({ block_id: row.block_id, source_ip: row.source_ip, reason }),
        });
        notice(result.message);
        await refresh();
      } catch (error) {
        notice(error.message, true);
      }
    });
    card.append(header, countdown, details, button);
    return card;
  }));
}

function renderAllowlist(rows) {
  const list = $("#allowlist-list");
  if (!rows.length) {
    empty(list, "No allowlist entries.");
    return;
  }
  list.replaceChildren(...rows.map((row) => {
    const item = element("div", "entry-row");
    const details = element("div");
    details.append(element("strong", "", row.ip_address), element("small", "", `${row.description} · ${row.reason}`));
    item.append(details);
    if (row.active) {
      const button = element("button", "button small danger", "Disable");
      button.addEventListener("click", async () => {
        try {
          const result = await api("/api/actions/allowlist-disable", {
            method: "POST",
            body: JSON.stringify({ allowlist_id: row.allowlist_id }),
          });
          notice(result.message);
          await refresh();
        } catch (error) {
          notice(error.message, true);
        }
      });
      item.append(button);
    } else {
      item.append(badge("inactive"));
    }
    return item;
  }));
}

function renderHealth(rows) {
  const grid = $("#health-grid");
  if (!rows.length) {
    empty(grid, "No component health data.");
    return;
  }
  grid.replaceChildren(...rows.map((row) => {
    const card = element("article", "data-card");
    const header = document.createElement("header");
    header.append(element("h3", "", row.component.replaceAll("_", " ")), badge(row.status));
    card.append(header, element("p", "updated", row.last_success ? `Last success: ${time(row.last_success)}` : "No successful check recorded"));
    if (row.last_error) card.append(element("p", "", row.last_error));
    return card;
  }));
}

function render(data) {
  state.snapshot = data;
  $("#updated-at").textContent = time(data.generated_at);
  renderOverview(data);
  renderDetections(data.detections);
  renderBlocks(data.active_blocks);
  renderAllowlist(data.allowlist);
  renderTable("#audit-table", [
    ["event_time", "Time"], ["component", "Component"], ["action", "Action"],
    ["target", "Target"], ["result", "Result"], ["details", "Details"],
  ], data.audit);
  renderTable("#actions-table", [
    ["requested_at", "Requested"], ["action", "Action"], ["source_ip", "Source"],
    ["reason", "Reason"], ["status", "Status"], ["result", "Result"],
  ], data.action_requests);
  renderHealth(data.health);
}

async function refresh() {
  $("#refresh-button").disabled = true;
  try {
    render(await api("/api/snapshot"));
  } catch (error) {
    notice(`Could not refresh dashboard: ${error.message}`, true);
  } finally {
    $("#refresh-button").disabled = false;
  }
}

async function initialize() {
  all(".nav-item").forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
  $("#refresh-button").addEventListener("click", refresh);
  $("#allowlist-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      const result = await api("/api/actions/allowlist-add", { method: "POST", body: JSON.stringify(payload) });
      notice(result.message);
      event.currentTarget.reset();
      await refresh();
    } catch (error) {
      notice(error.message, true);
    }
  });
  try {
    state.csrf = (await api("/api/session")).csrf_token;
    await refresh();
    window.setInterval(refresh, 5000);
    window.setInterval(() => {
      all(".countdown").forEach((node) => {
        node.textContent = `${Math.max(0, Math.floor((new Date(node.dataset.expiresAt) - Date.now()) / 1000))}s`;
      });
    }, 1000);
  } catch (error) {
    notice(`Dashboard initialization failed: ${error.message}`, true);
  }
}

initialize();
