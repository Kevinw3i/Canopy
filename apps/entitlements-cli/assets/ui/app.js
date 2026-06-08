const state = {
  selectedGroup: null,
  selectedPackage: null,
  selectedMembers: "0",
  filter: "all",
  search: "",
  validatedAt: "just now",
  server: null,
  draft: null,
  changes: null,
  preview: null,
  explain: null,
  dryRun: null,
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
  const line = document.querySelector(".validation-block > strong");
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

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
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

async function updateDraftBinding(group, packageId, enabled) {
  const response = await fetch("/api/draft/bindings", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group, package: packageId, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft binding update failed");
  }
  return response.json();
}

async function loadDraftPreview(group) {
  const response = await fetch("/api/preview", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft preview failed");
  }
  return response.json();
}

async function loadDraftExplain() {
  const response = await fetch("/api/explain", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft explain failed");
  }
  return response.json();
}

async function runDraftDryRun(request) {
  const response = await fetch("/api/dry-run", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft dry-run failed");
  }
  return response.json();
}

function applyServerState(payload) {
  state.server = payload;
  state.draft = payload.draft || null;
  state.changes = payload.changes || null;
  const mode = payload.mode || "local-auth-shell";
  const catalog = payload.catalog || {};
  const runtime = payload.runtime || {};
  const identity = payload.identity || {};
  const draft = payload.draft || {};
  const changes = payload.changes || {};
  const environment = document.querySelector(".env-picker select");
  const applyButton = document.querySelector(".review-actions button[disabled]");
  const previewButton = document.getElementById("preview-button");
  const explainButton = document.getElementById("explain-button");
  const dryRunButton = document.getElementById("dry-run-button");

  setSessionStatus("Session active", mode);
  if (environment && payload.deployment?.mode) {
    environment.value = payload.deployment.mode === "terraform" ? "production" : "staging";
  }
  renderDraft(draft, changes);
  if (
    state.preview &&
    (state.preview.revision !== draft.revision || state.preview.group !== state.selectedGroup)
  ) {
    state.preview = null;
  }
  if (state.explain && state.explain.revision !== draft.revision) {
    state.explain = null;
  }
  if (
    state.dryRun &&
    (state.dryRun.revision !== draft.revision ||
      state.dryRun.group !== state.selectedGroup ||
      state.dryRun.package !== state.selectedPackage)
  ) {
    state.dryRun = null;
  }
  renderPreviewSummary(state.preview);
  renderExplainSummary(state.explain);
  renderDryRunSummary(state.dryRun);
  if (!draft.loaded) {
    setValidationStatus(
      "Draft unavailable",
      draft.error || "catalog draft could not be loaded",
      false,
    );
  } else if ((changes.added_bindings?.length || 0) + (changes.removed_bindings?.length || 0) > 0) {
    setValidationStatus(
      "Draft pending review",
      `${changes.added_bindings?.length || 0} add / ${changes.removed_bindings?.length || 0} remove`,
      false,
    );
  } else if (catalog.exists && runtime.exists) {
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
  if (previewButton) {
    previewButton.disabled = !payload.capabilities?.preview;
  }
  if (explainButton) {
    explainButton.disabled = !payload.capabilities?.explain;
  }
  if (dryRunButton) {
    dryRunButton.disabled = !payload.capabilities?.dry_run;
  }
}

function renderDraft(draft, changes) {
  if (!draft.loaded) {
    renderChanges(changes || {});
    return;
  }
  const groups = draft.groups || [];
  const packages = draft.packages || [];
  if (!state.selectedGroup || !groups.some((group) => group.id === state.selectedGroup)) {
    state.selectedGroup = draft.selected_group || groups[0]?.id || null;
  }
  if (!state.selectedPackage || !packages.some((item) => item.id === state.selectedPackage)) {
    state.selectedPackage =
      firstBoundPackage(state.selectedGroup, draft.bindings || []) || packages[0]?.id || null;
  }
  renderMatrix(groups, packages, draft.bindings || []);
  renderInspector(groups, packages, draft.bindings || [], changes || {});
  renderChanges(changes || {});
  applyFilters();
}

function firstBoundPackage(groupId, bindings) {
  return bindings.find((binding) => binding.group === groupId)?.package || null;
}

function isBound(groupId, packageId, bindings) {
  return bindings.some((binding) => binding.group === groupId && binding.package === packageId);
}

function renderMatrix(groups, packages, bindings) {
  const matrix = document.querySelector(".matrix");
  if (!matrix) {
    return;
  }
  const headRow = document.createElement("tr");
  const groupsHead = document.createElement("th");
  groupsHead.append(el("strong", "", "Groups"));
  groupsHead.append(el("small", "", `${groups.length} total`));
  headRow.append(groupsHead);
  packages.forEach((pkg) => {
    const cell = document.createElement("th");
    cell.dataset.package = pkg.id;
    cell.append(el("strong", "", pkg.id));
    const summary = el("small", "", packageSummary(pkg));
    if (pkg.high_risk_features?.length) {
      summary.append(" ");
      summary.append(el("span", "risk", "△"));
    }
    cell.append(summary);
    headRow.append(cell);
  });
  const openHead = document.createElement("th");
  openHead.setAttribute("aria-label", "Open row");
  headRow.append(openHead);
  matrix.tHead.replaceChildren(headRow);

  const body = document.createElement("tbody");
  groups.forEach((group) => {
    const row = document.createElement("tr");
    row.dataset.group = group.id;
    row.dataset.members = String(group.member_count || 0);
    row.classList.toggle("selected", group.id === state.selectedGroup);

    const heading = document.createElement("th");
    heading.append(el("span", "person", "♙"));
    heading.append(el("strong", "", group.id));
    heading.append(el("small", "", groupSubtitle(group)));
    row.append(heading);

    packages.forEach((pkg) => {
      const cell = document.createElement("td");
      const button = el("button", "check", "");
      const bound = isBound(group.id, pkg.id, bindings);
      button.type = "button";
      button.dataset.package = pkg.id;
      button.classList.toggle("bound", bound);
      if (pkg.high_risk_features?.length) {
        button.dataset.risk = "true";
      }
      button.textContent = bound ? "✓" : "";
      button.setAttribute("aria-label", `${group.id} ${pkg.id} ${bound ? "bound" : "not bound"}`);
      cell.append(button);
      row.append(cell);
    });

    const openCell = document.createElement("td");
    const openButton = el("button", "row-open", "›");
    openButton.type = "button";
    openButton.setAttribute("aria-label", `Open ${group.id}`);
    openCell.append(openButton);
    row.append(openCell);
    body.append(row);
  });
  matrix.tBodies[0].replaceWith(body);
  attachMatrixEvents();
}

function packageSummary(pkg) {
  if (pkg.database_scope_count) {
    return `${pkg.database_scope_count} DB scope${pkg.database_scope_count === 1 ? "" : "s"}`;
  }
  if (pkg.mcp_ec2_diagnostic_scope_count) {
    return `${pkg.mcp_ec2_diagnostic_scope_count} EC2 diagnostic scope${pkg.mcp_ec2_diagnostic_scope_count === 1 ? "" : "s"}`;
  }
  return `${pkg.features?.length || 0} feature${pkg.features?.length === 1 ? "" : "s"}`;
}

function groupSubtitle(group) {
  const members = `${group.member_count || 0} member${group.member_count === 1 ? "" : "s"}`;
  const mappings = `${group.external_mapping_count || 0} map${group.external_mapping_count === 1 ? "" : "s"}`;
  return `${members}, ${mappings}`;
}

function renderInspector(groups, packages, bindings, changes) {
  const group = groups.find((item) => item.id === state.selectedGroup) || groups[0];
  const selectedPackage =
    packages.find((item) => item.id === state.selectedPackage) ||
    packages.find((item) => isBound(group?.id, item.id, bindings)) ||
    packages[0];
  if (!group || !selectedPackage) {
    return;
  }
  state.selectedGroup = group.id;
  state.selectedPackage = selectedPackage.id;
  state.selectedMembers = String(group.member_count || 0);

  document.getElementById("selected-group").textContent = group.id;
  document.getElementById("selected-count").textContent = "1";
  document.querySelector(".tabs button:nth-child(2)").textContent = `Permissions (${group.package_count})`;
  document.querySelector(".tabs button:nth-child(3)").textContent = `Members (${group.member_count})`;

  const packageSelect = document.querySelector(".detail-form select");
  if (packageSelect) {
    packageSelect.replaceChildren(
      ...packages.map((pkg) => {
        const option = document.createElement("option");
        option.value = pkg.id;
        option.textContent = `${pkg.id} (${pkg.features.length} features)`;
        option.selected = pkg.id === selectedPackage.id;
        return option;
      }),
    );
    packageSelect.onchange = (event) => {
      state.selectedPackage = event.target.value;
      state.dryRun = null;
      renderDryRunSummary(null);
      renderInspector(groups, packages, bindings, changes);
    };
  }

  const bound = isBound(group.id, selectedPackage.id, bindings);
  const switchButton = document.querySelector(".switch");
  const switchLabel = document.querySelector(".switch-row strong");
  if (switchButton) {
    switchButton.classList.toggle("on", bound);
    switchButton.setAttribute("aria-pressed", String(bound));
  }
  if (switchLabel) {
    switchLabel.textContent = bound ? "Enabled" : "Disabled";
  }

  const inputs = document.querySelectorAll(".detail-form fieldset input");
  if (inputs[0]) inputs[0].value = selectedPackage.scope;
  if (inputs[1]) inputs[1].value = selectedPackage.role;
  if (inputs[2]) inputs[2].value = `${selectedPackage.database_scope_count} database scope(s)`;
  if (inputs[3]) inputs[3].value = `${selectedPackage.mcp_ec2_diagnostic_scope_count} EC2 diagnostic scope(s)`;

  renderRiskList(selectedPackage, changes);
}

function renderRiskList(pkg, changes) {
  const list = document.querySelector(".risk-list");
  if (!list) {
    return;
  }
  const risks = [...(pkg.high_risk_features || [])];
  if (changes.added_bindings?.some((change) => change.package === pkg.id && change.high_risk)) {
    risks.unshift("pending high-risk binding");
  }
  const title = document.createElement("h3");
  title.append("Risk Indicators ");
  title.append(el("span", "", String(risks.length)));
  const items = risks.length ? risks.map((risk) => el("p", "", `△ ${risk}`)) : [el("p", "", "No high-risk feature in selected package")];
  list.replaceChildren(title, ...items);
}

function renderChanges(changes) {
  const added = changes.added_bindings || [];
  const removed = changes.removed_bindings || [];
  const summaryItems = document.querySelectorAll(".summary-grid strong");
  if (summaryItems[0]) {
    summaryItems[0].firstChild.textContent = String(new Set([...added, ...removed].map((change) => change.group)).size);
  }
  if (summaryItems[1]) summaryItems[1].firstChild.textContent = String(added.length);
  if (summaryItems[2]) summaryItems[2].firstChild.textContent = String(removed.length);
  if (summaryItems[3]) summaryItems[3].firstChild.textContent = "0";

  const pendingTitle = document.querySelector(".pending-block h3");
  const pendingBody = document.querySelector(".pending-block tbody");
  if (pendingTitle) {
    pendingTitle.textContent = `Pending Changes (${added.length + removed.length})`;
  }
  if (!pendingBody) {
    return;
  }
  const rows = [
    ...added.map((change) => changeRow("Add", change)),
    ...removed.map((change) => changeRow("Remove", change)),
  ];
  pendingBody.replaceChildren(...(rows.length ? rows : [emptyChangeRow()]));
}

function renderPreviewSummary(preview) {
  const result = document.getElementById("preview-result");
  if (!result) {
    return;
  }
  if (!preview) {
    result.replaceChildren(
      el("strong", "", "Preview not refreshed"),
      el("small", "", "Select a group and run Preview"),
    );
    return;
  }
  const packages = preview.packages || [];
  const highRisk = packages.reduce(
    (count, pkg) => count + (pkg.high_risk_features?.length || 0),
    0,
  );
  const accountRoles = new Set(
    packages.flatMap((pkg) =>
      (pkg.accounts || []).map(
        (account) => `${account.account_id || ""}|${account.account_name || ""}|${account.role_arn || ""}`,
      ),
    ),
  ).size;
  const databaseScopes = new Set(
    packages.flatMap((pkg) => pkg.database_scopes || []),
  ).size;
  const mcpEc2Scopes = new Set(
    packages.flatMap((pkg) => pkg.mcp_ec2_diagnostic_scopes || []),
  ).size;
  result.replaceChildren(
    el("strong", "", `${preview.group}: ${packages.length} package(s)`),
    el(
      "small",
      "",
      `${accountRoles} account role(s), ${databaseScopes} DB scope(s), ${mcpEc2Scopes} MCP EC2 scope(s)`,
    ),
    el("small", "", `${highRisk} high-risk feature(s)`),
  );
}

function renderExplainSummary(explain) {
  const result = document.getElementById("explain-result");
  if (!result) {
    return;
  }
  if (!explain) {
    result.replaceChildren(
      el("strong", "", "Explain not run"),
      el("small", "", "Uses the current operator identity"),
    );
    return;
  }
  const groups = explain.resolved_groups || [];
  const packages = explain.matched_packages || [];
  result.replaceChildren(
    el("strong", "", `${groups.length} resolved group(s)`),
    el("small", "", groups.length ? groups.join(", ") : "No matching group"),
    el("small", "", `${packages.length} matched package(s)`),
  );
}

function renderDryRunSummary(dryRun) {
  const result = document.getElementById("dry-run-result");
  if (!result) {
    return;
  }
  if (!dryRun) {
    result.replaceChildren(
      el("strong", "", "Dry Run not run"),
      el("small", "", "Select a database package first"),
    );
    return;
  }
  result.replaceChildren(
    el("strong", "", `${dryRun.allow ? "Allow" : "Deny"} ${dryRun.operation}`),
    el("small", "", dryRun.reason || "No reason returned"),
    el("small", "", dryRun.matched_rule ? `Rule: ${dryRun.matched_rule}` : "No matched rule"),
  );
}

function selectedPackageData() {
  return (state.draft?.packages || []).find((pkg) => pkg.id === state.selectedPackage) || null;
}

function mcpDatabaseDryRunRequestForPackage(pkg) {
  if (!pkg?.features?.includes("mcp:database")) {
    throw new Error("selected package does not include mcp:database");
  }
  const scope = pkg?.database_scopes?.[0];
  if (!scope) {
    throw new Error("selected package has no database scope");
  }
  const schema = scope.allowed_schemas?.[0];
  const table = scope.allowed_tables?.[0];
  const action =
    scope.allowed_actions?.find((item) => item.toLowerCase() === "select") ||
    scope.allowed_actions?.[0];
  if (!schema || !table || !action) {
    throw new Error("database scope needs schema, table, and action");
  }
  return {
    operation: "mcp-database",
    scope: scope.name,
    connection: scope.connection,
    environment: scope.environment,
    schema,
    table,
    action,
  };
}

function changeRow(type, change) {
  const row = document.createElement("tr");
  [type, change.group, change.package, type === "Add" ? "New binding" : "Removed binding", change.features.join(", ") || "package binding"].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 0) {
      cell.className = type === "Add" ? "add" : "remove";
    }
    row.append(cell);
  });
  return row;
}

function emptyChangeRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = "No pending draft changes";
  row.append(cell);
  return row;
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
  state.selectedGroup = row.dataset.group || state.selectedGroup;
  state.selectedMembers = row.dataset.members || "0";
  document.getElementById("selected-group").textContent = state.selectedGroup;
  document.querySelector(".tabs button:nth-child(3)").textContent = `Members (${state.selectedMembers})`;
  document.getElementById("selected-count").textContent = "1";
  if (state.preview?.group !== state.selectedGroup) {
    state.preview = null;
    renderPreviewSummary(null);
  }
  state.dryRun = null;
  renderDryRunSummary(null);
  if (state.draft?.loaded) {
    renderInspector(
      state.draft.groups || [],
      state.draft.packages || [],
      state.draft.bindings || [],
      state.changes || {},
    );
  }
}

function setFilter(filter) {
  state.filter = filter;
  document.querySelectorAll(".segmented button").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === filter);
  });
  applyFilters();
}

function applyFilters() {
  document.querySelectorAll(".matrix tbody tr").forEach((row) => {
    const highRisk = row.querySelector("[data-risk='true'].bound");
    const database = row.children[1]?.querySelector(".bound");
    const searchMatch = !state.search || row.dataset.group?.toLowerCase().includes(state.search);
    const visible =
      searchMatch &&
      (state.filter === "all" ||
        (state.filter === "risk" && highRisk) ||
        (state.filter === "database" && database));
    row.hidden = !visible;
  });
}

async function toggleBinding(button, row) {
  const group = row.dataset.group;
  const packageId = button.dataset.package;
  const enabled = !button.classList.contains("bound");
  if (!state.server?.capabilities?.draft_write || !group || !packageId) {
    button.classList.toggle("bound", enabled);
    button.textContent = enabled ? "✓" : "";
    return;
  }
  button.disabled = true;
  try {
    const payload = await updateDraftBinding(group, packageId, enabled);
    state.selectedGroup = group;
    state.selectedPackage = packageId;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
  } catch (error) {
    setValidationStatus("Draft update failed", error.message, false);
  } finally {
    button.disabled = false;
  }
}

function attachMatrixEvents() {
  document.querySelectorAll(".matrix tbody tr").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.matches(".check")) {
        toggleBinding(event.target, row);
      }
      selectGroup(row);
    });
  });
}

attachMatrixEvents();

document.querySelectorAll(".segmented button").forEach((button) => {
  button.addEventListener("click", () => setFilter(button.dataset.filter));
});

document.querySelector(".switch")?.addEventListener("click", (event) => {
  const button = event.currentTarget;
  const enabled = !button.classList.contains("on");
  if (state.selectedGroup && state.selectedPackage && state.server?.capabilities?.draft_write) {
    updateDraftBinding(state.selectedGroup, state.selectedPackage, enabled)
      .then((payload) => {
        state.explain = null;
        state.dryRun = null;
        applyServerState(payload);
      })
      .catch((error) => setValidationStatus("Draft update failed", error.message, false));
  } else {
    button.classList.toggle("on", enabled);
    button.setAttribute("aria-pressed", String(enabled));
  }
});

document.querySelector(".search input")?.addEventListener("input", (event) => {
  state.search = event.target.value.trim().toLowerCase();
  applyFilters();
});

document.getElementById("validate-button")?.addEventListener("click", () => {
  state.validatedAt = "just now";
  document.getElementById("validation-detail").textContent = `Last validated: ${state.validatedAt}`;
});

document.getElementById("preview-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const group = state.selectedGroup;
  if (!group || !state.server?.capabilities?.preview) {
    setValidationStatus("Preview unavailable", "catalog draft is not loaded", false);
    return;
  }
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = "◉ Previewing";
  try {
    const preview = await loadDraftPreview(group);
    preview.revision = state.draft?.revision ?? 0;
    state.preview = preview;
    renderPreviewSummary(preview);
    setValidationStatus(
      "Preview refreshed",
      `${preview.packages?.length || 0} package(s) for ${preview.group}`,
      true,
    );
    setSessionStatus("Session active", "preview refreshed");
  } catch (error) {
    setValidationStatus("Preview failed", error.message, false);
  } finally {
    button.disabled = !state.server?.capabilities?.preview;
    button.textContent = originalLabel;
  }
});

document.getElementById("explain-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!state.server?.capabilities?.explain) {
    setValidationStatus("Explain unavailable", "catalog draft is not loaded", false);
    return;
  }
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = "◎ Explaining";
  try {
    const explain = await loadDraftExplain();
    explain.revision = state.draft?.revision ?? 0;
    state.explain = explain;
    renderExplainSummary(explain);
    setValidationStatus(
      "Explain refreshed",
      `${explain.resolved_groups?.length || 0} group(s), ${explain.matched_packages?.length || 0} package(s)`,
      true,
    );
  } catch (error) {
    setValidationStatus("Explain failed", error.message, false);
  } finally {
    button.disabled = !state.server?.capabilities?.explain;
    button.textContent = originalLabel;
  }
});

document.getElementById("dry-run-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!state.server?.capabilities?.dry_run) {
    setValidationStatus("Dry Run unavailable", "catalog draft is not loaded", false);
    return;
  }
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = "▶ Running";
  try {
    const request = mcpDatabaseDryRunRequestForPackage(selectedPackageData());
    const dryRun = await runDraftDryRun(request);
    dryRun.revision = state.draft?.revision ?? 0;
    dryRun.group = state.selectedGroup;
    dryRun.package = state.selectedPackage;
    state.dryRun = dryRun;
    renderDryRunSummary(dryRun);
    setValidationStatus(
      dryRun.allow ? "Dry Run allowed" : "Dry Run denied",
      dryRun.reason || "No reason returned",
      dryRun.allow,
    );
  } catch (error) {
    setValidationStatus("Dry Run failed", error.message, false);
  } finally {
    button.disabled = !state.server?.capabilities?.dry_run;
    button.textContent = originalLabel;
  }
});

initializeSession();
