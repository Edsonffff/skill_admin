(() => {
  "use strict";

  const tokenInput = document.querySelector("#admin-token");
  const loginCard = document.querySelector("#login-card");
  const dashboard = document.querySelector("#dashboard");
  const loginError = document.querySelector("#login-error");
  const dashboardError = document.querySelector("#dashboard-error");
  const serverStatus = document.querySelector("#server-status");
  let token = localStorage.getItem("skillrackAdminToken") || "";

  function setError(element, message) { element.textContent = message || ""; }
  function formatDate(value) {
    if (!value) return "Never";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
  }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { ...options, headers });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `Request failed (${response.status}).`);
    return payload;
  }

  async function refresh() {
    setError(dashboardError, "");
    const [stats, licenses] = await Promise.all([api("/api/admin/stats"), api("/api/admin/licenses")]);
    const totals = stats.totals;
    document.querySelector("#programs-done").textContent = totals.programsDone;
    document.querySelector("#programs-solved").textContent = totals.programsSolved;
    document.querySelector("#active-licenses").textContent = totals.activeLicenses;
    document.querySelector("#locked-licenses").textContent = totals.lockedLicenses;
    const body = document.querySelector("#licenses-body");
    body.replaceChildren();
    if (!licenses.licenses.length) {
      const row = document.createElement("tr");
      row.innerHTML = '<td class="empty" colspan="8">No licenses yet. Create one above.</td>';
      body.appendChild(row);
      return;
    }
    for (const license of licenses.licenses) {
      const row = document.createElement("tr");
      const status = document.createElement("span");
      status.className = `status ${license.status}`;
      status.textContent = license.status;
      const action = document.createElement("button");
      action.className = license.status === "locked" ? "unlock" : "danger";
      action.textContent = license.status === "locked" ? "Unlock" : "Lock";
      action.disabled = license.status === "expired";
      action.onclick = async () => {
        action.disabled = true;
        try {
          const path = `/api/admin/licenses/${encodeURIComponent(license.id)}/${license.status === "locked" ? "unlock" : "lock"}`;
          await api(path, { method: "POST", body: JSON.stringify({ reason: "Locked from admin dashboard." }) });
          await refresh();
        } catch (error) { setError(dashboardError, error.message); action.disabled = false; }
      };
      const cells = [
        license.userName || "Not activated",
        `••••-${license.licenseKeySuffix}`,
        status,
        formatDate(license.expiresAt),
        license.totalPrograms,
        license.solvedPrograms,
        formatDate(license.lastUsedAt),
        action
      ];
      for (const value of cells) {
        const cell = document.createElement("td");
        if (value instanceof Node) cell.appendChild(value); else cell.textContent = String(value);
        row.appendChild(cell);
      }
      body.appendChild(row);
    }
  }

  async function connect() {
    setError(loginError, "");
    try {
      await api("/api/admin/stats");
      loginCard.hidden = true;
      dashboard.hidden = false;
      await refresh();
      serverStatus.textContent = "Server online";
      serverStatus.className = "pill";
    } catch (error) {
      localStorage.removeItem("skillrackAdminToken");
      token = "";
      loginCard.hidden = false;
      dashboard.hidden = true;
      setError(loginError, error.message);
      serverStatus.textContent = "Authentication required";
    }
  }

  document.querySelector("#login-form").onsubmit = event => {
    event.preventDefault();
    token = tokenInput.value.trim();
    localStorage.setItem("skillrackAdminToken", token);
    void connect();
  };
  document.querySelector("#refresh").onclick = () => { void refresh().catch(error => setError(dashboardError, error.message)); };
  document.querySelector("#create-form").onsubmit = async event => {
    event.preventDefault();
    const output = document.querySelector("#new-key");
    setError(document.querySelector("#create-error"), "");
    try {
      const payload = await api("/api/admin/licenses", {
        method: "POST",
        body: JSON.stringify({ expiresAt: document.querySelector("#expires-at").value })
      });
      output.hidden = false;
      output.textContent = `New license key (copy now): ${payload.license.licenseKey}`;
      await refresh();
    } catch (error) { setError(document.querySelector("#create-error"), error.message); }
  };

  const defaultExpiry = new Date();
  defaultExpiry.setDate(defaultExpiry.getDate() + 30);
  document.querySelector("#expires-at").value = defaultExpiry.toISOString().slice(0, 10);
  if (token) void connect();
})();
