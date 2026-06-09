const state = {
  selectedGroup: null,
  selectedPackage: null,
  selectedMembers: "0",
  selectedDbConnection: null,
  currentView: "groups",
  filter: "all",
  search: "",
  server: null,
  draft: null,
  changes: null,
  databaseConnections: null,
  validation: null,
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

async function updateDatabaseConnection(request) {
  const response = await fetch("/api/draft/db-connections", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft database connection update failed");
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

async function validateDraft() {
  const response = await fetch("/api/validate", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft validation failed");
  }
  return response.json();
}

function applyServerState(payload) {
  state.server = payload;
  state.draft = payload.draft || null;
  state.changes = payload.changes || null;
  state.databaseConnections = payload.database_connections || null;
  const mode = payload.mode || "local-auth-shell";
  const catalog = payload.catalog || {};
  const runtime = payload.runtime || {};
  const identity = payload.identity || {};
  const draft = payload.draft || {};
  const changes = payload.changes || {};
  const environment = document.querySelector(".env-picker select");
  const applyButton = document.querySelector(".review-actions button[disabled]");
  const validateButton = document.getElementById("validate-button");
  const reviewValidateButton = document.getElementById("review-validate-button");
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
  if (state.validation && state.validation.revision !== draft.revision) {
    state.validation = null;
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
  renderValidateSummary(state.validation);
  renderPreviewSummary(state.preview);
  renderExplainSummary(state.explain);
  renderDryRunSummary(state.dryRun);
  renderDatabaseConnections(state.databaseConnections);
  if (!draft.loaded) {
    setValidationStatus(
      "Draft unavailable",
      draft.error || "catalog draft could not be loaded",
      false,
    );
  } else if (state.validation) {
    const blocking = state.validation.blocking_errors?.length || 0;
    const warnings = state.validation.warnings?.length || 0;
    setValidationStatus(
      state.validation.valid ? "Validation clean" : "Validation blocked",
      state.validation.valid
        ? `${state.validation.generated?.generated_rules || 0} runtime rule(s), ${warnings} warning(s)`
        : `${blocking} blocking issue(s), ${warnings} warning(s)`,
      state.validation.valid,
    );
  } else if ((changes.added_bindings?.length || 0) + (changes.removed_bindings?.length || 0) > 0) {
    setValidationStatus(
      "Draft pending review",
      `${changes.added_bindings?.length || 0} add / ${changes.removed_bindings?.length || 0} remove`,
      false,
    );
  } else if (catalog.exists && runtime.exists) {
    setValidationStatus(
      "Validation required",
      `Identity source: ${identity.source || "unknown"}`,
      false,
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
  if (validateButton) {
    validateButton.disabled = !payload.capabilities?.validate;
  }
  if (reviewValidateButton) {
    reviewValidateButton.disabled = !payload.capabilities?.validate;
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
  renderReviewApply();
}

function setActiveView(view) {
  state.currentView = view;
  const workspace = document.querySelector(".workspace");
  const groupGrid = document.querySelector(".content-grid");
  const dbView = document.querySelector(".db-connections-view");
  const reviewView = document.querySelector(".review-apply-view");
  const toolbar = document.querySelector(".toolbar");
  const title = document.querySelector(".title-row h1");
  const subtitle = document.querySelector(".title-row span");
  workspace?.classList.toggle("db-mode", view === "db-connections");
  workspace?.classList.toggle("review-mode", view === "review-apply");
  if (groupGrid) {
    groupGrid.hidden = view !== "groups";
  }
  if (dbView) {
    dbView.hidden = view !== "db-connections";
  }
  if (reviewView) {
    reviewView.hidden = view !== "review-apply";
  }
  if (toolbar) {
    toolbar.hidden = view !== "groups";
  }
  if (title) {
    title.textContent =
      view === "db-connections"
        ? "DB Connections"
        : view === "review-apply"
          ? "Review & Apply"
          : "Groups";
  }
  if (subtitle) {
    subtitle.textContent =
      view === "db-connections"
        ? "Connection Safety"
        : view === "review-apply"
          ? "Draft Gate"
          : "Entitlement Catalog";
  }
  document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === view);
  });
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

function renderDatabaseConnections(connections) {
  const rowsNode = document.getElementById("db-connection-rows");
  if (!rowsNode) {
    return;
  }
  const local = connections?.local || [];
  const required = connections?.required || [];
  const missing = connections?.missing_required || [];
  const issues = connections?.issues || [];
  const summary = document.getElementById("db-connection-summary");
  const requiredCount = document.getElementById("db-required-count");
  const issueCount = document.getElementById("db-issue-count");

  if (summary) {
    summary.textContent = connections?.configured
      ? `${local.length} draft connection(s), ${missing.length} missing required${connections?.dirty ? ", unsaved" : ""}`
      : "No --db-config configured for this UI session";
  }
  if (requiredCount) {
    requiredCount.textContent = `${required.length} required`;
  }
  if (issueCount) {
    issueCount.textContent = `${issues.length} issue${issues.length === 1 ? "" : "s"}`;
  }

  const hasSelected =
    local.some((connection) => connection.name === state.selectedDbConnection) ||
    missing.includes(state.selectedDbConnection);
  if (!state.selectedDbConnection || !hasSelected) {
    state.selectedDbConnection = local[0]?.name || missing[0] || null;
  }

  const rows = [
    ...local.map((connection) => dbConnectionRow(connection, required.includes(connection.name))),
    ...missing.map((connection) => missingDbConnectionRow(connection)),
  ];
  rowsNode.replaceChildren(...(rows.length ? rows : [emptyDbConnectionRow()]));
  renderDbConnectionInspector(connections);
}

function dbConnectionRow(connection, required) {
  const row = document.createElement("tr");
  row.dataset.connection = connection.name;
  row.classList.toggle("selected", state.selectedDbConnection === connection.name);
  row.classList.toggle(
    "db-blocking-row",
    connection.safety === "blocking" || connection.safety === "attention",
  );
  row.addEventListener("click", () => {
    state.selectedDbConnection = connection.name;
    renderDatabaseConnections(state.databaseConnections);
  });
  [
    connection.name,
    `${connection.host}:${connection.port}`,
    connection.database,
    dbSafetyLabel(connection),
    required ? "required" : "unused",
  ].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 3) {
      cell.className =
        connection.safety === "blocking" || connection.safety === "attention" ? "risk" : "ok";
    }
    row.append(cell);
  });
  return row;
}

function missingDbConnectionRow(connection) {
  const row = document.createElement("tr");
  row.dataset.connection = connection;
  row.classList.add("db-blocking-row");
  row.classList.toggle("selected", state.selectedDbConnection === connection);
  row.addEventListener("click", () => {
    state.selectedDbConnection = connection;
    renderDatabaseConnections(state.databaseConnections);
  });
  ["Missing", "not configured", connection, "blocking", "required"].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 3) {
      cell.className = "risk";
    }
    row.append(cell);
  });
  return row;
}

function emptyDbConnectionRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = "No database connections to display";
  row.append(cell);
  return row;
}

function dbSafetyLabel(connection) {
  if (connection.safety === "blocking") {
    return "blocking";
  }
  if (connection.safety === "attention") {
    return "attention";
  }
  if (connection.required_by_scope_count > 0) {
    return "ready";
  }
  return "unused";
}

function renderDbConnectionInspector(connections) {
  const local = connections?.local || [];
  const selected = local.find((connection) => connection.name === state.selectedDbConnection);
  const missing = (connections?.missing_required || []).find(
    (connection) => connection === state.selectedDbConnection,
  );
  const issues = connections?.issues || [];
  const editable = selected || missing;
  setInputValue("db-connection-name", selected?.name || missing || "");
  setInputValue("db-engine", selected?.engine || (missing ? "mysql" : ""));
  setInputValue("db-host", selected?.host || "");
  setInputValue("db-port", selected ? String(selected.port) : missing ? "3306" : "");
  setInputValue("db-name", selected?.database || "");
  setInputValue("db-secret-ref", "");
  setInputPlaceholder(
    "db-secret-ref",
    selected?.secret_ref_configured ? "configured; paste ref" : "required secret ref",
  );
  setInputValue(
    "db-connect-timeout",
    selected ? String(selected.connect_timeout_ms) : missing ? "3000" : "",
  );
  setInputValue(
    "db-statement-timeout",
    selected ? String(selected.statement_timeout_ms) : missing ? "5000" : "",
  );
  setInputValue(
    "db-explain-timeout",
    selected ? String(selected.explain_timeout_ms) : missing ? "3000" : "",
  );
  setInputValue(
    "db-max-connections",
    selected ? String(selected.max_connections) : missing ? "4" : "",
  );
  setCheckedValue("db-readonly", true);
  setCheckedValue("db-require-tls", true);
  setDbEditorDisabled(!editable);
  const name = document.getElementById("db-selected-name");
  const badge = document.getElementById("db-selected-safety");
  if (name) {
    name.textContent = selected?.name || missing || "Connection";
  }
  if (badge) {
    const safety = selected ? dbSafetyLabel(selected) : missing ? "blocking" : "Unknown";
    badge.textContent = safety;
    badge.classList.toggle("badge-risk", safety === "blocking" || safety === "attention");
  }
  renderDbSafetyList(selected, missing, issues);
}

function setDbEditorDisabled(disabled) {
  [
    "db-engine",
    "db-host",
    "db-port",
    "db-name",
    "db-secret-ref",
    "db-connect-timeout",
    "db-statement-timeout",
    "db-explain-timeout",
    "db-max-connections",
    "db-save-button",
  ].forEach((id) => {
    const input = document.getElementById(id);
    if (input) {
      input.disabled = disabled;
    }
  });
}

function setInputValue(id, value) {
  const input = document.getElementById(id);
  if (input) {
    input.value = value;
  }
}

function setInputPlaceholder(id, value) {
  const input = document.getElementById(id);
  if (input) {
    input.placeholder = value;
  }
}

function setCheckedValue(id, value) {
  const input = document.getElementById(id);
  if (input) {
    input.checked = value;
  }
}

function renderDbSafetyList(connection, missing, issues) {
  const list = document.getElementById("db-safety-list");
  if (!list) {
    return;
  }
  const relevantIssues = issues.filter((issue) => {
    const message = issue.message || "";
    return (
      (connection && message.includes(`'${connection.name}'`)) ||
      (missing && message.includes(`'${missing}'`))
    );
  });
  const title = document.createElement("h3");
  title.append("Safety Checks ");
  title.append(el("span", "", String(relevantIssues.length)));
  const items = relevantIssues.length
    ? relevantIssues.map((issue) => el("p", "", `△ ${issue.code}: ${issue.message}`))
    : [el("p", "", connection ? "Readonly TLS connection metadata is clean" : "No connection selected")];
  list.replaceChildren(title, ...items);
}

function dbConnectionDraftRequestFromForm() {
  const name = document.getElementById("db-connection-name")?.value.trim() || "";
  const secretArn = document.getElementById("db-secret-ref")?.value.trim() || "";
  const request = {
    name,
    engine: document.getElementById("db-engine")?.value.trim() || "",
    host: document.getElementById("db-host")?.value.trim() || "",
    port: Number(document.getElementById("db-port")?.value || 0),
    database: document.getElementById("db-name")?.value.trim() || "",
    readonly: true,
    connect_timeout_ms: Number(document.getElementById("db-connect-timeout")?.value || 0),
    statement_timeout_ms: Number(document.getElementById("db-statement-timeout")?.value || 0),
    explain_timeout_ms: Number(document.getElementById("db-explain-timeout")?.value || 0),
    max_connections: Number(document.getElementById("db-max-connections")?.value || 0),
    require_tls: true,
    accept_invalid_tls_certs: false,
    skip_tls_hostname_verification: false,
  };
  if (secretArn) {
    request.secret_arn = secretArn;
  }
  return request;
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
  const semantic = changes.semantic_diff || {};
  const semanticAdded = semantic.added || [];
  const semanticRemoved = semantic.removed || [];
  const highRisk = semantic.high_risk || [];
  const semanticCount = semanticAdded.length + semanticRemoved.length;
  const highRiskKeys = new Set(highRisk.map(grantKey));
  const summaryItems = document.querySelectorAll(".summary-grid strong");
  const changedGroups = new Set([
    ...added.map((change) => change.group),
    ...removed.map((change) => change.group),
    ...semanticAdded.map((grant) => grant.group),
    ...semanticRemoved.map((grant) => grant.group),
  ]);
  if (summaryItems[0]) {
    summaryItems[0].firstChild.textContent = String(changedGroups.size);
  }
  if (summaryItems[1]) summaryItems[1].firstChild.textContent = String(added.length);
  if (summaryItems[2]) summaryItems[2].firstChild.textContent = String(removed.length);
  if (summaryItems[3]) summaryItems[3].firstChild.textContent = String(semanticCount);

  const pendingTitle = document.querySelector(".pending-block h3");
  const pendingBody = document.querySelector(".pending-block tbody");
  if (pendingTitle) {
    const riskLabel = highRisk.length ? `, ${highRisk.length} high risk` : "";
    pendingTitle.textContent = `Pending Changes (${added.length + removed.length + semanticCount}${riskLabel})`;
  }
  if (!pendingBody) {
    return;
  }
  const rows = [
    ...added.map((change) => changeRow("Add", change)),
    ...removed.map((change) => changeRow("Remove", change)),
    ...semanticAdded.map((grant) =>
      semanticGrantRow("Grant", grant, highRiskKeys.has(grantKey(grant))),
    ),
    ...semanticRemoved.map((grant) => semanticGrantRow("Revoke", grant, false)),
  ];
  if (semantic.error) {
    rows.unshift(semanticErrorRow(semantic.error));
  }
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

function renderValidateSummary(validation) {
  const result = document.getElementById("validate-result");
  if (!result) {
    return;
  }
  if (!validation) {
    result.replaceChildren(
      el("strong", "", "Validate not run"),
      el("small", "", "Run Validate before Apply"),
    );
    return;
  }
  const blocking = validation.blocking_errors || [];
  const warnings = validation.warnings || [];
  const generated = validation.generated || {};
  const deployment = validation.deployment || {};
  const dbConnections = validation.database_connections || {};
  const issue = blocking[0] || warnings[0] || null;
  result.replaceChildren(
    el("strong", "", validation.valid ? "Validate clean" : "Validate blocked"),
    el("small", "", `${blocking.length} blocking, ${warnings.length} warning(s)`),
    el(
      "small",
      "mono-detail",
      `Runtime: ${generated.runtime_path || "not generated"} (${runtimeStateLabel(generated)})`,
    ),
    el("small", "mono-detail", deploymentStateLabel(deployment)),
    el("small", "", databaseConnectionStateLabel(dbConnections)),
    el(
      "small",
      "",
      issue ? `${issue.code}: ${issue.message}` : "Temp runtime generated and removed",
    ),
  );
}

function shortSha(value) {
  if (!value) {
    return "sha unavailable";
  }
  if (value.length <= 20) {
    return value;
  }
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function runtimeStateLabel(generated) {
  if (!generated?.runtime_exists) {
    return "runtime missing";
  }
  return generated.runtime_drift ? "runtime drift" : "runtime matches draft";
}

function deploymentStateLabel(deployment) {
  if (!deployment?.checked) {
    return `Deployment: ${deployment?.mode || "not configured"} not checked`;
  }
  const mode = deployment.mode || "unknown";
  const path = deployment.canonical_path || "path unavailable";
  return `Deployment: ${mode} ${path} (${shortSha(deployment.canonical_sha256)})`;
}

function listPreview(items) {
  const values = Array.isArray(items) ? items : [];
  if (!values.length) {
    return "none";
  }
  if (values.length <= 3) {
    return values.join(", ");
  }
  return `${values.slice(0, 3).join(", ")} +${values.length - 3} more`;
}

function databaseConnectionStateLabel(connections) {
  const required = connections.required || [];
  const local = connections.local_config || [];
  const deployment = connections.deployment_source || [];
  return [
    `DB connections: required ${required.length} (${listPreview(required)})`,
    `local ${local.length}`,
    `deployment ${deployment.length}`,
  ].join(", ");
}

function reviewDatabaseState(validationConnections, draftConnections, issueCount) {
  const required = validationConnections?.required || draftConnections.required || [];
  const local =
    validationConnections?.local_config || (draftConnections.local || []).map((item) => item.name);
  const deployment = validationConnections?.deployment_source || [];
  const deploymentLabel = validationConnections ? `, ${deployment.length} deploy` : "";
  return `${required.length} required, ${local.length} local${deploymentLabel}, ${issueCount} issue(s)`;
}

function isDatabaseIssue(issue) {
  const code = issue?.code || "";
  return code.includes("database") || code.includes("db_") || code.includes("tfvars");
}

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) {
    node.textContent = value;
  }
}

function renderReviewApply() {
  const view = document.querySelector(".review-apply-view");
  if (!view) {
    return;
  }
  const changes = state.changes || {};
  const validation = state.validation;
  const server = state.server || {};
  const databaseConnections = state.databaseConnections || {};
  const added = changes.added_bindings || [];
  const removed = changes.removed_bindings || [];
  const semantic = changes.semantic_diff || {};
  const semanticAdded = semantic.added || [];
  const semanticRemoved = semantic.removed || [];
  const highRisk = semantic.high_risk || [];
  const semanticCount = semanticAdded.length + semanticRemoved.length;
  const pendingCount = added.length + removed.length + semanticCount;
  const blocking = validation?.blocking_errors || [];
  const warnings = validation?.warnings || [];
  const dbIssues = databaseConnections.issues || [];
  const validationDatabaseConnections = validation?.database_connections || null;
  const validationDbIssueCount = [...blocking, ...warnings].filter(isDatabaseIssue).length;
  const dbIssueCount = dbIssues.length + validationDbIssueCount;
  const generated = validation?.generated || {};
  const deployment = validation?.deployment || server.deployment || {};
  const runtime = server.runtime || {};

  setText(
    "#review-apply-status",
    validation
      ? validation.valid
        ? "Validation is clean for the current draft."
        : "Validation found blocking issues before apply."
      : pendingCount
        ? "Draft has pending changes that need validation."
        : "No pending draft changes; validation has not run.",
  );
  setText(
    "#review-apply-gate",
    server.capabilities?.apply ? "Ready" : "Locked",
  );
  setText(
    "#review-runtime-state",
    validation ? runtimeStateLabel(generated) : runtime.exists ? "Loaded" : "Missing",
  );
  setText(
    "#review-deployment-state",
    validation ? deploymentStateLabel(deployment) : deployment.mode || "Not configured",
  );
  setText(
    "#review-db-state",
    reviewDatabaseState(validationDatabaseConnections, databaseConnections, dbIssueCount),
  );
  setText(
    "#review-change-summary",
    `${pendingCount} pending change(s), ${highRisk.length} high-risk grant(s)`,
  );
  setText("#review-high-risk-count", `${highRisk.length} high risk`);
  setText(
    "#review-validation-summary",
    validation ? (validation.valid ? "Validation clean" : "Validation blocked") : "Not run",
  );
  setText(
    "#review-validation-detail",
    validation
      ? `${blocking.length} blocking, ${warnings.length} warning(s)`
      : "Run Validate before Apply",
  );
  setText(
    "#review-runtime-path",
    generated.runtime_path || runtime.path || "entitlements.generated.toml",
  );
  setText(
    "#review-runtime-digest",
    generated.temp_runtime_sha256
      ? `Temp digest ${shortSha(generated.temp_runtime_sha256)}`
      : runtime.sha256
        ? `Current digest ${shortSha(runtime.sha256)}`
        : "Digest unavailable",
  );
  setText(
    "#review-admin-gate",
    server.capabilities?.apply ? "Admin gate passed" : "Apply disabled",
  );
  setText(
    "#review-admin-detail",
    server.capabilities?.apply
      ? "Operator identity can apply this draft."
      : "Production apply gate and transaction protocol are not enabled yet.",
  );

  const highRiskKeys = new Set(highRisk.map(grantKey));
  const rows = [
    ...added.map((change) => changeRow("Add", change)),
    ...removed.map((change) => changeRow("Remove", change)),
    ...semanticAdded.map((grant) =>
      semanticGrantRow("Grant", grant, highRiskKeys.has(grantKey(grant))),
    ),
    ...semanticRemoved.map((grant) => semanticGrantRow("Revoke", grant, false)),
  ];
  if (semantic.error) {
    rows.unshift(semanticErrorRow(semantic.error));
  }
  const reviewBody = document.getElementById("review-change-rows");
  if (reviewBody) {
    reviewBody.replaceChildren(...(rows.length ? rows : [emptyChangeRow()]));
  }

  const issues = [
    ...blocking.map((issue) => ({ ...issue, severity: "blocking" })),
    ...warnings.map((issue) => ({ ...issue, severity: "warning" })),
    ...dbIssues.map((issue) => ({ ...issue, severity: "db" })),
  ];
  const issueList = document.getElementById("review-issue-list");
  if (issueList) {
    issueList.replaceChildren(
      ...(issues.length
        ? issues.slice(0, 8).map((issue) =>
            el("p", issue.severity === "blocking" ? "risk" : "", `${issue.code}: ${issue.message}`),
          )
        : [el("p", "", validation ? "No blocking issues." : "No validation result yet.")]),
    );
  }
}

function validationButtons() {
  return ["validate-button", "review-validate-button"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
}

async function runValidation(button) {
  if (!state.server?.capabilities?.validate) {
    setValidationStatus("Validate unavailable", "catalog draft is not loaded", false);
    renderReviewApply();
    return;
  }
  const originalLabel = button.textContent;
  validationButtons().forEach((item) => {
    item.disabled = true;
  });
  button.textContent = "✓ Validating";
  try {
    const validation = await validateDraft();
    validation.revision = state.draft?.revision ?? 0;
    state.validation = validation;
    renderValidateSummary(validation);
    renderReviewApply();
    const blocking = validation.blocking_errors?.length || 0;
    const warnings = validation.warnings?.length || 0;
    setValidationStatus(
      validation.valid ? "Validation clean" : "Validation blocked",
      validation.valid
        ? `${validation.generated?.generated_rules || 0} runtime rule(s), ${warnings} warning(s)`
        : `${blocking} blocking issue(s), ${warnings} warning(s)`,
      validation.valid,
    );
  } catch (error) {
    state.validation = null;
    renderValidateSummary(null);
    renderReviewApply();
    setValidationStatus("Validation failed", error.message, false);
  } finally {
    validationButtons().forEach((item) => {
      item.disabled = !state.server?.capabilities?.validate;
    });
    button.textContent = originalLabel;
  }
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

function grantKey(grant) {
  return `${grant.group || ""}|${grant.package || ""}|${grant.kind || ""}|${grant.value || ""}`;
}

function semanticGrantRow(type, grant, highRisk) {
  const row = document.createElement("tr");
  if (highRisk) {
    row.classList.add("risk-row");
  }
  [
    highRisk ? "High risk" : type,
    grant.group || "",
    grant.package || "",
    grant.kind || "",
    grant.value || "",
  ].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 0) {
      cell.className = highRisk ? "risk" : type === "Grant" ? "add" : "remove";
    }
    if (index === 3 || index === 4) {
      cell.classList.add("grant-detail");
    }
    row.append(cell);
  });
  return row;
}

function semanticErrorRow(error) {
  const row = document.createElement("tr");
  row.classList.add("risk-row");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = `Semantic diff unavailable: ${error}`;
  row.append(cell);
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
    state.validation = null;
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
        state.validation = null;
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

document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
  item.addEventListener("click", (event) => {
    event.preventDefault();
    setActiveView(item.dataset.view || "groups");
  });
});

document.getElementById("db-save-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const request = dbConnectionDraftRequestFromForm();
  if (!request.name) {
    setValidationStatus("DB connection not selected", "select a connection row before saving", false);
    return;
  }
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = "Saving";
  try {
    const payload = await updateDatabaseConnection(request);
    applyServerState(payload);
    state.selectedDbConnection = request.name;
    renderDatabaseConnections(state.databaseConnections);
    setActiveView("db-connections");
    setValidationStatus("DB connection draft saved", `${request.name} is staged in memory`, true);
  } catch (error) {
    setValidationStatus("DB connection save failed", error.message, false);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
});

document.getElementById("validate-button")?.addEventListener("click", (event) => {
  runValidation(event.currentTarget);
});

document.getElementById("review-validate-button")?.addEventListener("click", (event) => {
  runValidation(event.currentTarget);
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
