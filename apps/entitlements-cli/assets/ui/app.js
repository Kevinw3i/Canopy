const state = {
  selectedGroup: "RD",
  selectedMembers: "12",
  filter: "all",
  validatedAt: "just now",
  server: null,
};

function setSessionStatus(status, detail) {
  const statusNode = document.getElementById("session-status");
  const detailNode = document.getElementById("session-detail");
  if (statusNode) {
    statusNode.textContent = status;
  }
  if (detailNode) {
    detailNode.textContent = detail;
  }
}

function setValidationStatus(summary, detail, valid = true) {
  const line = document.querySelector(".validation-block strong");
  const summaryNode = document.getElementById("validation-summary");
  const detailNode = document.getElementById("validation-detail");
  if (line) {
    line.textContent = valid ? "✓ Valid" : "△ Needs attention";
    line.classList.toggle("valid-line", valid);
  }
  if (summaryNode) {
    summaryNode.textContent = summary;
  }
  if (detailNode) {
    detailNode.textContent = detail;
  }
}

async function exchangeBootstrapCode(code) {
  const response = await fetch("/api/session/exchange", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) {
    throw new Error("bootstrap exchange failed");
  }
}

async function loadServerState() {
  const response = await fetch("/api/state", {
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("session required");
  }
  return response.json();
}

function applyServerState(payload) {
  state.server = payload;
  const mode = payload.mode || "local-auth-shell";
  const catalog = payload.catalog || {};
  const runtime = payload.runtime || {};
  const identity = payload.identity || {};
  const environment = document.querySelector(".env-picker select");
  const applyButton = document.querySelector(".review-actions button[disabled]");

  setSessionStatus("Session active", mode);
  if (environment && payload.deployment?.mode) {
    environment.value = payload.deployment.mode === "terraform" ? "production" : "staging";
  }
  if (catalog.exists && runtime.exists) {
    setValidationStatus(
      "Catalog and runtime detected",
      `Identity source: ${identity.source || "unknown"}`,
      true,
    );
  } else {
    const missing = [
      catalog.exists ? null : "catalog",
      runtime.exists ? null : "runtime",
    ].filter(Boolean);
    setValidationStatus(
      "Draft preview only",
      `${missing.join(" and ")} file missing; write/apply APIs disabled`,
      false,
    );
  }
  if (applyButton) {
    applyButton.textContent = payload.capabilities?.apply ? "▢ Apply" : "▢ Apply (locked)";
  }
}

async function initializeSession() {
  const bootstrapCode = window.__CANOPY_BOOTSTRAP_CODE__;
  window.__CANOPY_BOOTSTRAP_CODE__ = null;
  try {
    if (bootstrapCode) {
      await exchangeBootstrapCode(bootstrapCode);
    }
    const payload = await loadServerState();
    applyServerState(payload);
  } catch (_error) {
    setSessionStatus("Session required", "open the one-time local URL");
    setValidationStatus("Local session unavailable", "API state is hidden until session exchange", false);
  }
}

function selectGroup(row) {
  document.querySelectorAll(".matrix tbody tr").forEach((item) => {
    item.classList.toggle("selected", item === row);
  });
  state.selectedGroup = row.dataset.group || "RD";
  state.selectedMembers = row.dataset.members || "0";
  document.getElementById("selected-group").textContent = state.selectedGroup;
  document.querySelector(".tabs button:nth-child(3)").textContent = `Members (${state.selectedMembers})`;
  document.getElementById("selected-count").textContent = "1";
}

function setFilter(filter) {
  state.filter = filter;
  document.querySelectorAll(".segmented button").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === filter);
  });

  document.querySelectorAll(".matrix tbody tr").forEach((row) => {
    const highRisk = row.querySelector("[data-risk='true'].bound");
    const database = row.children[1]?.querySelector(".bound");
    const visible =
      filter === "all" ||
      (filter === "risk" && highRisk) ||
      (filter === "database" && database);
    row.hidden = !visible;
  });
}

function toggleBinding(button) {
  button.classList.toggle("bound");
  button.textContent = button.classList.contains("bound") ? "✓" : "";
}

document.querySelectorAll(".matrix tbody tr").forEach((row) => {
  row.addEventListener("click", (event) => {
    if (event.target.matches(".check")) {
      toggleBinding(event.target);
    }
    selectGroup(row);
  });
});

document.querySelectorAll(".segmented button").forEach((button) => {
  button.addEventListener("click", () => setFilter(button.dataset.filter));
});

document.querySelector(".switch")?.addEventListener("click", (event) => {
  const button = event.currentTarget;
  const enabled = !button.classList.contains("on");
  button.classList.toggle("on", enabled);
  button.setAttribute("aria-pressed", String(enabled));
});

document.getElementById("validate-button")?.addEventListener("click", () => {
  state.validatedAt = "just now";
  document.getElementById("validation-detail").textContent = `Last validated: ${state.validatedAt}`;
});

document.getElementById("preview-button")?.addEventListener("click", () => {
  document.getElementById("session-detail").textContent = "preview refreshed";
});

initializeSession();
