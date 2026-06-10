const state = {
  selectedGroup: null,
  selectedPackage: null,
  selectedMembers: "0",
  selectedScope: null,
  selectedScopeResourceField: "accounts",
  selectedDatabaseScopeName: "",
  selectedMcpEc2ScopeId: "",
  selectedAccount: null,
  selectedRole: null,
  accountRoleSelection: "account",
  selectedDbConnection: null,
  draftingNewDbConnection: false,
  currentView: "overview",
  filter: "all",
  search: "",
  server: null,
  draft: null,
  changes: null,
  databaseConnections: null,
  validation: null,
  apply: null,
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

async function updateDraftMembership(group, userId, enabled) {
  const response = await fetch("/api/draft/memberships", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group, user_id: userId, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft membership update failed");
  }
  return response.json();
}

async function updateDraftGroupMapping(group, externalGroup, enabled) {
  const response = await fetch("/api/draft/group-mappings", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group, external_group: externalGroup, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft group mapping update failed");
  }
  return response.json();
}

async function updateDraftScopeResource(scope, field, value, enabled) {
  const response = await fetch("/api/draft/scopes/resources", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, field, value, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft scope resource update failed");
  }
  return response.json();
}

async function updateDraftDatabaseScope(scope, request) {
  const response = await fetch("/api/draft/scopes/database", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, ...request }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft database scope update failed");
  }
  return response.json();
}

async function updateDraftMcpEc2Scope(scope, request) {
  const response = await fetch("/api/draft/scopes/mcp-ec2", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, ...request }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft MCP EC2 scope update failed");
  }
  return response.json();
}

async function updateDraftAccount(id, accountId, name, enabled) {
  const response = await fetch("/api/draft/accounts", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, account_id: accountId, name, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft account update failed");
  }
  return response.json();
}

async function updateDraftRole(id, roleArn, enabled) {
  const response = await fetch("/api/draft/roles", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, role_arn: roleArn, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft role update failed");
  }
  return response.json();
}

async function updateDraftPackage(id, scope, role, maxSessionSeconds, enabled) {
  const response = await fetch("/api/draft/packages", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id,
      scope,
      role,
      max_session_seconds: maxSessionSeconds,
      enabled,
    }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft package update failed");
  }
  return response.json();
}

async function updateDraftPackageFeature(packageId, feature, enabled) {
  const response = await fetch("/api/draft/packages/features", {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: packageId, feature, enabled }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "draft package feature update failed");
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

async function applyDraft() {
  const response = await fetch("/api/apply", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok && !payload?.gate) {
    throw new Error(payload?.error?.message || "draft apply failed");
  }
  return payload;
}

async function importRuntimeDraft() {
  const response = await fetch("/api/import-runtime", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || "runtime import failed");
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
  const pendingCount = pendingChangeCount(changes);
  const environment = document.querySelector(".env-picker select");
  const validateButton = document.getElementById("validate-button");
  const reviewValidateButton = document.getElementById("review-validate-button");
  const previewButton = document.getElementById("preview-button");
  const explainButton = document.getElementById("explain-button");
  const dryRunButton = document.getElementById("dry-run-button");
  const importRuntimeButton = document.getElementById("import-runtime-button");

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
  if (state.apply && state.apply.revision !== draft.revision) {
    state.apply = null;
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
  } else if (pendingCount > 0) {
    setValidationStatus(
      "Draft pending review",
      `${pendingCount} staged change(s)`,
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
  syncApplyButtons();
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
  if (importRuntimeButton) {
    importRuntimeButton.disabled = !canImportRuntime(payload);
  }
  renderReviewApply();
  renderOverview();
  setActiveView(state.currentView || "overview");
}

function setActiveView(view) {
  state.currentView = view;
  const workspace = document.querySelector(".workspace");
  const overviewView = document.querySelector(".overview-view");
  const groupGrid = document.querySelector(".content-grid");
  const packagesView = document.querySelector(".packages-view");
  const scopesView = document.querySelector(".scopes-view");
  const accountsRolesView = document.querySelector(".accounts-roles-view");
  const dbView = document.querySelector(".db-connections-view");
  const reviewView = document.querySelector(".review-apply-view");
  const toolbar = document.querySelector(".toolbar");
  const title = document.querySelector(".title-row h1");
  const subtitle = document.querySelector(".title-row span");
  const titles = {
    overview: "Overview",
    groups: "Groups",
    packages: "Packages",
    scopes: "Scopes",
    "accounts-roles": "Accounts/Roles",
    "db-connections": "DB Connections",
    "review-apply": "Review & Apply",
  };
  const subtitles = {
    overview: "Catalog Health",
    groups: "Entitlement Catalog",
    packages: "Feature Toggles",
    scopes: "Resource Boundaries",
    "accounts-roles": "Identity Targets",
    "db-connections": "Connection Safety",
    "review-apply": "Draft Gate",
  };
  workspace?.classList.toggle("overview-mode", view === "overview");
  workspace?.classList.toggle("db-mode", view === "db-connections");
  workspace?.classList.toggle("review-mode", view === "review-apply");
  workspace?.classList.toggle("package-mode", view === "packages");
  workspace?.classList.toggle("scope-mode", view === "scopes");
  workspace?.classList.toggle("account-role-mode", view === "accounts-roles");
  if (overviewView) {
    overviewView.hidden = view !== "overview";
  }
  if (groupGrid) {
    groupGrid.hidden = view !== "groups";
  }
  if (packagesView) {
    packagesView.hidden = view !== "packages";
  }
  if (scopesView) {
    scopesView.hidden = view !== "scopes";
  }
  if (accountsRolesView) {
    accountsRolesView.hidden = view !== "accounts-roles";
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
    title.textContent = titles[view] || titles.groups;
  }
  if (subtitle) {
    subtitle.textContent = subtitles[view] || subtitles.groups;
  }
  document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === view);
  });
}

function renderDraft(draft, changes) {
  if (!draft.loaded) {
    renderChanges(changes || {});
    renderPackages([], []);
    renderScopes([]);
    renderAccountsRoles([], []);
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
  renderPackages(packages, draft.available_features || []);
  renderScopes(draft.scopes || []);
  renderAccountsRoles(draft.accounts || [], draft.roles || []);
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
  if (!state.draftingNewDbConnection && (!state.selectedDbConnection || !hasSelected)) {
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
    state.draftingNewDbConnection = false;
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
    state.draftingNewDbConnection = false;
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
  const creating = state.draftingNewDbConnection;
  const editable = selected || missing || creating;
  const nameInput = document.getElementById("db-connection-name");
  setInputValue("db-connection-name", creating ? "" : selected?.name || missing || "");
  setInputPlaceholder(
    "db-connection-name",
    creating ? "lowercase-name" : selected?.name || missing || "",
  );
  if (nameInput) {
    nameInput.readOnly = !creating;
  }
  setInputValue("db-engine", selected?.engine || (editable ? "mysql" : ""));
  setInputValue("db-host", selected?.host || "");
  setInputValue("db-port", selected ? String(selected.port) : editable ? "3306" : "");
  setInputValue("db-name", selected?.database || "");
  setInputValue("db-secret-ref", "");
  setInputPlaceholder(
    "db-secret-ref",
    selected?.secret_ref_configured ? "configured; paste ref" : "required secret ref",
  );
  setInputValue(
    "db-connect-timeout",
    selected ? String(selected.connect_timeout_ms) : editable ? "3000" : "",
  );
  setInputValue(
    "db-statement-timeout",
    selected ? String(selected.statement_timeout_ms) : editable ? "5000" : "",
  );
  setInputValue(
    "db-explain-timeout",
    selected ? String(selected.explain_timeout_ms) : editable ? "3000" : "",
  );
  setInputValue(
    "db-max-connections",
    selected ? String(selected.max_connections) : editable ? "4" : "",
  );
  setCheckedValue("db-readonly", true);
  setCheckedValue("db-require-tls", true);
  setDbEditorDisabled(!editable);
  const name = document.getElementById("db-selected-name");
  const badge = document.getElementById("db-selected-safety");
  if (name) {
    name.textContent = creating ? "New connection" : selected?.name || missing || "Connection";
  }
  if (badge) {
    const safety = creating ? "Draft" : selected ? dbSafetyLabel(selected) : missing ? "blocking" : "Unknown";
    badge.textContent = safety;
    badge.classList.toggle("badge-risk", safety === "blocking" || safety === "attention");
  }
  renderDbSafetyList(selected, missing, issues, creating);
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

function renderDbSafetyList(connection, missing, issues, creating = false) {
  const list = document.getElementById("db-safety-list");
  if (!list) {
    return;
  }
  if (creating) {
    const title = document.createElement("h3");
    title.append("Safety Checks ");
    title.append(el("span", "", "0"));
    list.replaceChildren(
      title,
      el("p", "", "New connection drafts must stay readonly, TLS-required, and secret-ref only"),
    );
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

function renderPackages(packages, availableFeatures) {
  const rowsNode = document.getElementById("package-rows");
  if (!rowsNode) {
    return;
  }
  const summary = document.getElementById("package-summary");
  const featureCount = document.getElementById("package-feature-count");
  const riskCount = document.getElementById("package-risk-count");
  const highRiskPackages = packages.filter((pkg) => pkg.high_risk_features?.length);
  const totalFeatures = packages.reduce((count, pkg) => count + (pkg.features?.length || 0), 0);
  if (summary) {
    summary.textContent = `${packages.length} package(s), ${highRiskPackages.length} high-risk package(s)`;
  }
  if (featureCount) {
    featureCount.textContent = `${totalFeatures} enabled feature(s)`;
  }
  if (riskCount) {
    riskCount.textContent = `${highRiskPackages.length} high risk`;
  }

  const hasSelected = packages.some((pkg) => pkg.id === state.selectedPackage);
  if (!state.selectedPackage || !hasSelected) {
    state.selectedPackage = packages[0]?.id || null;
  }

  rowsNode.replaceChildren(
    ...(packages.length ? packages.map(packageRow) : [emptyPackageRow()]),
  );
  renderPackageInspector(packages, availableFeatures);
}

function packageRow(pkg) {
  const row = document.createElement("tr");
  row.dataset.package = pkg.id;
  row.classList.toggle("selected", pkg.id === state.selectedPackage);
  row.classList.toggle("package-risk-row", Boolean(pkg.high_risk_features?.length));
  row.addEventListener("click", () => {
    state.selectedPackage = pkg.id;
    renderPackages(state.draft?.packages || [], state.draft?.available_features || []);
  });
  [
    pkg.id,
    pkg.scope,
    pkg.role,
    `${pkg.features?.length || 0} enabled`,
    pkg.high_risk_features?.length ? pkg.high_risk_features.join(", ") : "none",
  ].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 4 && pkg.high_risk_features?.length) {
      cell.className = "risk";
    }
    row.append(cell);
  });
  return row;
}

function emptyPackageRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = "No packages to display";
  row.append(cell);
  return row;
}

function renderPackageInspector(packages, availableFeatures) {
  const selected = packages.find((pkg) => pkg.id === state.selectedPackage) || null;
  const name = document.getElementById("package-selected-name");
  const badge = document.getElementById("package-selected-risk");
  setText("#package-selected-scope", selected?.scope || "-");
  setText("#package-selected-role", selected?.role || "-");
  setText("#package-selected-db", String(selected?.database_scope_count || 0));
  setText(
    "#package-selected-session",
    selected?.max_session_seconds ? `${selected.max_session_seconds}s` : "default",
  );
  if (name) {
    name.textContent = selected?.id || "Package";
  }
  if (badge) {
    const riskCount = selected?.high_risk_features?.length || 0;
    badge.textContent = riskCount ? `${riskCount} high risk` : "No risk";
    badge.classList.toggle("badge-risk", riskCount > 0);
  }
  renderPackageEditor(selected);

  const list = document.getElementById("package-feature-toggles");
  if (!list) {
    return;
  }
  const title = document.createElement("h3");
  title.append("Feature Toggles ");
  title.append(el("span", "", String(availableFeatures.length)));
  if (!selected) {
    list.replaceChildren(title, el("p", "", "No package selected"));
    return;
  }
  const enabled = new Set(selected.features || []);
  const toggles = availableFeatures.map((feature) =>
    packageFeatureToggle(selected.id, feature, enabled.has(feature.id)),
  );
  list.replaceChildren(title, ...toggles);
}

function renderPackageEditor(selected) {
  const canWrite = Boolean(state.server?.capabilities?.draft_write);
  const scopes = state.draft?.scopes || [];
  const roles = state.draft?.roles || [];
  const idInput = document.getElementById("package-edit-id");
  const scopeSelect = document.getElementById("package-edit-scope");
  const roleSelect = document.getElementById("package-edit-role");
  const sessionInput = document.getElementById("package-edit-session");
  const saveButton = document.getElementById("package-save-button");
  const deleteButton = document.getElementById("package-delete-button");

  setElementInputValue(idInput, selected?.id || "", !canWrite);
  setSelectOptions(scopeSelect, scopes.map((scope) => scope.id), selected?.scope || scopes[0]?.id || "", !canWrite);
  setSelectOptions(roleSelect, roles.map((role) => role.id), selected?.role || roles[0]?.id || "", !canWrite);
  setElementInputValue(
    sessionInput,
    selected?.max_session_seconds ? String(selected.max_session_seconds) : "",
    !canWrite,
  );
  if (saveButton) {
    saveButton.disabled = !canWrite || !scopes.length || !roles.length;
  }
  if (deleteButton) {
    deleteButton.disabled = !canWrite || !selected?.id;
  }
}

function setSelectOptions(select, values, selectedValue, disabled) {
  if (!(select instanceof HTMLSelectElement)) {
    return;
  }
  select.replaceChildren(
    ...values.map((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      return option;
    }),
  );
  select.value = selectedValue;
  select.disabled = disabled || values.length === 0;
}

function packageFeatureToggle(packageId, feature, checked) {
  const label = document.createElement("label");
  label.className = feature.high_risk ? "feature-toggle feature-risk" : "feature-toggle";
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = checked;
  input.disabled = !state.server?.capabilities?.draft_write;
  input.dataset.package = packageId;
  input.dataset.feature = feature.id;
  input.addEventListener("change", (event) => {
    togglePackageFeature(event.currentTarget);
  });
  const text = document.createElement("span");
  text.append(el("strong", "", feature.id));
  text.append(el("small", "", feature.high_risk ? "High-risk entitlement" : featureSummary(feature.id)));
  label.append(input, text);
  return label;
}

function featureSummary(feature) {
  if (feature.startsWith("mcp:")) {
    return "MCP access feature";
  }
  if (feature.startsWith("ecs:")) {
    return "ECS access feature";
  }
  if (feature.startsWith("ec2:")) {
    return "EC2 access feature";
  }
  if (feature.startsWith("cloudwatch:")) {
    return "CloudWatch access feature";
  }
  return "Catalog feature";
}

function renderScopes(scopes) {
  const rowsNode = document.getElementById("scope-rows");
  if (!rowsNode) {
    return;
  }
  const summary = document.getElementById("scope-summary");
  const resourceCount = document.getElementById("scope-resource-count");
  const guardrailCount = document.getElementById("scope-guardrail-count");
  const totalResources = scopes.reduce((count, scope) => count + scopeResourceCount(scope), 0);
  const totalGuardrails = scopes.reduce((count, scope) => count + scopeGuardrailCount(scope), 0);
  if (summary) {
    summary.textContent = `${scopes.length} scope(s), ${totalResources} resource boundary item(s)`;
  }
  if (resourceCount) {
    resourceCount.textContent = `${totalResources} resources`;
  }
  if (guardrailCount) {
    guardrailCount.textContent = `${totalGuardrails} guardrails`;
  }

  const hasSelected = scopes.some((scope) => scope.id === state.selectedScope);
  if (!state.selectedScope || !hasSelected) {
    state.selectedScope = scopes[0]?.id || null;
  }
  rowsNode.replaceChildren(...(scopes.length ? scopes.map(scopeRow) : [emptyScopeRow()]));
  renderScopeInspector(scopes);
}

const SCOPE_RESOURCE_LABELS = {
  accounts: "Accounts",
  regions: "Regions",
  log_group_arns: "Log Groups",
  clusters: "ECS Clusters",
  os_users: "OS Users",
};

const SCOPE_RESOURCE_PLACEHOLDERS = {
  accounts: "account id from Accounts/Roles",
  regions: "aws region, e.g. ap-northeast-1",
  log_group_arns: "log group ARN or pattern",
  clusters: "cluster name or pattern",
  os_users: "linux user, e.g. ec2-user",
};

function scopeResourceCount(scope) {
  return (
    (scope.accounts?.length || 0) +
    (scope.regions?.length || 0) +
    (scope.log_group_arns?.length || 0) +
    (scope.clusters?.length || 0) +
    (scope.os_users?.length || 0) +
    (scope.database_scopes?.length || 0) +
    (scope.mcp_ec2_diagnostic_scopes?.length || 0)
  );
}

function scopeGuardrailCount(scope) {
  return (
    (scope.instance_tag_selectors?.length || 0) +
    (scope.excluded_tag_selectors?.length || 0) +
    (scope.task_tag_selectors?.length || 0) +
    (scope.excluded_task_tag_selectors?.length || 0) +
    (scope.excluded_container_names?.length || 0) +
    (scope.allow_broad_cluster_discovery ? 1 : 0)
  );
}

function scopeRow(scope) {
  const row = document.createElement("tr");
  row.dataset.scope = scope.id;
  row.classList.toggle("selected", scope.id === state.selectedScope);
  row.classList.toggle("scope-risk-row", scope.allow_broad_cluster_discovery);
  row.addEventListener("click", () => {
    state.selectedScope = scope.id;
    state.selectedDatabaseScopeName = "";
    renderScopes(state.draft?.scopes || []);
  });
  [
    scope.id,
    listPreview(scope.accounts),
    listPreview(scope.regions),
    listPreview(scope.packages),
    `${scopeResourceCount(scope)} resources, ${scopeGuardrailCount(scope)} guardrails`,
  ].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 4 && scope.allow_broad_cluster_discovery) {
      cell.className = "risk";
    }
    row.append(cell);
  });
  return row;
}

function emptyScopeRow() {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = "No scopes to display";
  row.append(cell);
  return row;
}

function renderScopeInspector(scopes) {
  const selected = scopes.find((scope) => scope.id === state.selectedScope) || null;
  const name = document.getElementById("scope-selected-name");
  const badge = document.getElementById("scope-selected-mode");
  if (name) {
    name.textContent = selected?.id || "Scope";
  }
  if (badge) {
    badge.textContent = selected?.allow_broad_cluster_discovery ? "Broad cluster" : "Guarded";
    badge.classList.toggle("badge-risk", Boolean(selected?.allow_broad_cluster_discovery));
  }
  setText("#scope-selected-accounts", String(selected?.accounts?.length || 0));
  setText("#scope-selected-regions", String(selected?.regions?.length || 0));
  setText("#scope-selected-logs", String(selected?.log_group_arns?.length || 0));
  setText("#scope-selected-ecs", String(selected?.clusters?.length || 0));
  setText("#scope-selected-db", String(selected?.database_scopes?.length || 0));
  setText("#scope-selected-mcp-ec2", String(selected?.mcp_ec2_diagnostic_scopes?.length || 0));
  renderScopeResourceEditor(selected);
  renderScopeDatabaseEditor(selected);
  renderScopeMcpEc2Editor(selected);

  const list = document.getElementById("scope-detail-list");
  if (!list) {
    return;
  }
  const title = document.createElement("h3");
  title.append("Scope Details ");
  title.append(el("span", "", String(selected ? scopeResourceCount(selected) : 0)));
  if (!selected) {
    list.replaceChildren(title, el("p", "", "No scope selected"));
    return;
  }
  const blocks = [
    scopeDetailBlock("Description", selected.description ? [selected.description] : []),
    scopeDetailBlock("Business Scope", selected.business_scopes || []),
    scopeDetailBlock("Packages", selected.packages || []),
    scopeDetailBlock("Accounts", selected.accounts || []),
    scopeDetailBlock("Regions", selected.regions || []),
    scopeDetailBlock("Log Groups", selected.log_group_arns || []),
    scopeDetailBlock("ECS Clusters", selected.clusters || []),
    scopeDetailBlock("Instance Tags", selected.instance_tag_selectors || []),
    scopeDetailBlock("Excluded Instance Tags", selected.excluded_tag_selectors || []),
    scopeDetailBlock("Task Tags", selected.task_tag_selectors || []),
    scopeDetailBlock("Excluded Task Tags", selected.excluded_task_tag_selectors || []),
    scopeDetailBlock("Excluded Containers", selected.excluded_container_names || []),
    scopeDetailBlock("OS Users", selected.os_users || []),
    scopeDetailBlock("Database Scopes", (selected.database_scopes || []).map(databaseScopeLine)),
    scopeDetailBlock(
      "MCP EC2 Diagnostics",
      (selected.mcp_ec2_diagnostic_scopes || []).map(mcpEc2ScopeLine),
    ),
  ];
  list.replaceChildren(title, ...blocks);
}

function renderScopeResourceEditor(scope) {
  const select = document.getElementById("scope-resource-field");
  const input = document.getElementById("scope-resource-input");
  const addButton = document.getElementById("scope-resource-add-button");
  const list = document.getElementById("scope-resource-list");
  const field = SCOPE_RESOURCE_LABELS[state.selectedScopeResourceField]
    ? state.selectedScopeResourceField
    : "accounts";
  state.selectedScopeResourceField = field;

  if (select) {
    select.value = field;
    select.disabled = !scope || !state.server?.capabilities?.draft_write;
  }
  if (input) {
    input.placeholder = SCOPE_RESOURCE_PLACEHOLDERS[field] || "resource value";
    input.disabled = !scope || !state.server?.capabilities?.draft_write;
  }
  if (addButton) {
    addButton.disabled = !scope || !state.server?.capabilities?.draft_write;
  }
  if (!list) {
    return;
  }
  if (!scope) {
    list.replaceChildren(el("p", "", "No scope selected"));
    return;
  }
  const values = [...(scope[field] || [])].sort();
  if (!values.length) {
    list.replaceChildren(el("p", "", `No ${SCOPE_RESOURCE_LABELS[field].toLowerCase()}`));
    return;
  }
  list.replaceChildren(
    ...values.map((value) => {
      const row = el("div", "scope-resource-list-row");
      row.append(el("span", "", value));
      const removeButton = el("button", "", "×");
      removeButton.type = "button";
      removeButton.dataset.scopeResourceField = field;
      removeButton.dataset.scopeResourceValue = value;
      removeButton.setAttribute("aria-label", `Remove ${value}`);
      row.append(removeButton);
      return row;
    }),
  );
}

function renderScopeDatabaseEditor(scope) {
  const canWrite = Boolean(scope && state.server?.capabilities?.draft_write);
  const databaseScopes = scope?.database_scopes || [];
  const selector = document.getElementById("scope-db-template");
  const selectedName = databaseScopes.some((item) => item.name === state.selectedDatabaseScopeName)
    ? state.selectedDatabaseScopeName
    : databaseScopes[0]?.name || "";
  state.selectedDatabaseScopeName = selectedName;
  const selected = databaseScopes.find((item) => item.name === selectedName) || null;

  if (selector instanceof HTMLSelectElement) {
    selector.replaceChildren(
      optionElement("", "New database scope"),
      ...databaseScopes.map((item) => optionElement(item.name, item.name)),
    );
    selector.value = selectedName;
    selector.disabled = !scope;
  }

  setFormInputValue("scope-db-name", selected?.name || "", !canWrite);
  setFormInputValue("scope-db-connection", selected?.connection || suggestedDbConnectionName(), !canWrite);
  setFormInputValue("scope-db-environment", selected?.environment || "production", !canWrite);
  setFormInputValue("scope-db-schemas", (selected?.allowed_schemas || []).join(", "), !canWrite);
  setFormInputValue("scope-db-tables", (selected?.allowed_tables || []).join(", "), !canWrite);
  setFormInputValue("scope-db-actions", (selected?.allowed_actions || ["select"]).join(", "), !canWrite);
  setFormInputValue("scope-db-max-rows", selected ? String(selected.max_rows) : "100", !canWrite);
  setFormInputValue(
    "scope-db-statement-timeout",
    selected ? String(selected.statement_timeout_ms) : "5000",
    !canWrite,
  );
  setFormInputValue(
    "scope-db-max-examined",
    selected ? String(selected.max_examined_rows) : "10000",
    !canWrite,
  );
  setFormCheckedValue("scope-db-require-explain", true, true);
  setFormCheckedValue("scope-db-full-scan", Boolean(selected?.allow_full_table_scan), !canWrite);
  setFormCheckedValue("scope-db-allow-views", Boolean(selected?.allow_views), !canWrite);
  const saveButton = document.getElementById("scope-db-save-button");
  if (saveButton) {
    saveButton.disabled = !canWrite;
  }
  const deleteButton = document.getElementById("scope-db-delete-button");
  if (deleteButton) {
    deleteButton.disabled = !canWrite || !selected;
  }
}

function renderScopeMcpEc2Editor(scope) {
  const canWrite = Boolean(scope && state.server?.capabilities?.draft_write);
  const mcpEc2Scopes = scope?.mcp_ec2_diagnostic_scopes || [];
  const selector = document.getElementById("scope-mcp-ec2-template");
  const selectedId = mcpEc2Scopes.some((item) => item.id === state.selectedMcpEc2ScopeId)
    ? state.selectedMcpEc2ScopeId
    : mcpEc2Scopes[0]?.id || "";
  state.selectedMcpEc2ScopeId = selectedId;
  const selected = mcpEc2Scopes.find((item) => item.id === selectedId) || null;

  if (selector instanceof HTMLSelectElement) {
    selector.replaceChildren(
      optionElement("", "New MCP EC2 scope"),
      ...mcpEc2Scopes.map((item) => optionElement(item.id, item.id)),
    );
    selector.value = selectedId;
    selector.disabled = !scope;
  }

  setFormInputValue("scope-mcp-ec2-id", selected?.id || "", !canWrite);
  setFormInputValue("scope-mcp-ec2-private-refs", (selected?.private_target_refs || []).join(", "), !canWrite);
  setFormInputValue("scope-mcp-ec2-denylist", selected?.denylist_version || "builtin-v1", !canWrite);
  setFormInputValue(
    "scope-mcp-ec2-allowlist",
    selected?.allowlist_rule_id || `${state.selectedScope || "scope"}-diagnostics-v1`,
    !canWrite,
  );
  setFormInputValue("scope-mcp-ec2-max-lines", selected ? String(selected.max_lines) : "100", !canWrite);
  setFormInputValue(
    "scope-mcp-ec2-max-since",
    selected ? String(selected.max_since_seconds) : "900",
    !canWrite,
  );
  setFormInputValue("scope-mcp-ec2-timeout", selected ? String(selected.max_timeout_seconds) : "30", !canWrite);
  setFormInputValue("scope-mcp-ec2-matches", selected ? String(selected.max_matches) : "50", !canWrite);
  setFormInputValue(
    "scope-mcp-ec2-probe-budget",
    selected ? String(selected.connectivity_probe_budget_per_window) : "20",
    !canWrite,
  );
  setFormInputValue(
    "scope-mcp-ec2-budget-window",
    selected ? String(selected.budget_window_seconds) : "600",
    !canWrite,
  );
  setFormInputValue("scope-mcp-ec2-logs", mcpEc2LogPathLines(selected), !canWrite);
  setFormInputValue("scope-mcp-ec2-journals", mcpEc2JournalLines(selected), !canWrite);
  setFormInputValue("scope-mcp-ec2-http", mcpEc2HttpLines(selected), !canWrite);
  setFormInputValue("scope-mcp-ec2-tcp", mcpEc2TcpLines(selected), !canWrite);
  setFormInputValue("scope-mcp-ec2-dns", mcpEc2DnsLines(selected), !canWrite);

  const saveButton = document.getElementById("scope-mcp-ec2-save-button");
  if (saveButton) {
    saveButton.disabled = !canWrite;
  }
  const deleteButton = document.getElementById("scope-mcp-ec2-delete-button");
  if (deleteButton) {
    deleteButton.disabled = !canWrite || !selected;
  }
}

function optionElement(value, label) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  return option;
}

function setFormInputValue(id, value, disabled) {
  const input = document.getElementById(id);
  if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
    input.value = value;
    input.disabled = disabled;
  }
}

function setFormCheckedValue(id, checked, disabled) {
  const input = document.getElementById(id);
  if (input instanceof HTMLInputElement) {
    input.checked = checked;
    input.disabled = disabled;
  }
}

function suggestedDbConnectionName() {
  const connections = state.databaseConnections || {};
  return connections.local?.[0]?.name || connections.missing_required?.[0] || "";
}

function csvValues(id) {
  const raw = document.getElementById(id)?.value || "";
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function positiveIntegerFromInput(id) {
  const value = Number(document.getElementById(id)?.value || 0);
  return Number.isInteger(value) && value > 0 ? value : null;
}

function databaseScopeDraftRequestFromForm() {
  return {
    name: document.getElementById("scope-db-name")?.value.trim() || "",
    connection: document.getElementById("scope-db-connection")?.value.trim() || "",
    environment: document.getElementById("scope-db-environment")?.value.trim() || "",
    allowed_schemas: csvValues("scope-db-schemas"),
    allowed_tables: csvValues("scope-db-tables"),
    allowed_actions: csvValues("scope-db-actions"),
    max_rows: positiveIntegerFromInput("scope-db-max-rows"),
    statement_timeout_ms: positiveIntegerFromInput("scope-db-statement-timeout"),
    require_explain: true,
    max_examined_rows: positiveIntegerFromInput("scope-db-max-examined"),
    allow_full_table_scan: Boolean(document.getElementById("scope-db-full-scan")?.checked),
    allow_views: Boolean(document.getElementById("scope-db-allow-views")?.checked),
    enabled: true,
  };
}

function mcpEc2ScopeDraftRequestFromForm() {
  return {
    id: document.getElementById("scope-mcp-ec2-id")?.value.trim() || "",
    private_target_refs: csvValues("scope-mcp-ec2-private-refs"),
    allowed_log_paths: textareaLines("scope-mcp-ec2-logs").map(parseMcpEc2LogPathLine),
    allowed_journal_units: textareaLines("scope-mcp-ec2-journals").map(parseMcpEc2JournalLine),
    allowed_http_urls: textareaLines("scope-mcp-ec2-http").map(parseMcpEc2HttpLine),
    allowed_tcp_targets: textareaLines("scope-mcp-ec2-tcp").map(parseMcpEc2TcpLine),
    allowed_dns_targets: textareaLines("scope-mcp-ec2-dns").map(parseMcpEc2DnsLine),
    max_lines: positiveIntegerFromInput("scope-mcp-ec2-max-lines"),
    max_since_seconds: positiveIntegerFromInput("scope-mcp-ec2-max-since"),
    max_timeout_seconds: positiveIntegerFromInput("scope-mcp-ec2-timeout"),
    max_matches: positiveIntegerFromInput("scope-mcp-ec2-matches"),
    connectivity_probe_budget_per_window: positiveIntegerFromInput("scope-mcp-ec2-probe-budget"),
    budget_window_seconds: positiveIntegerFromInput("scope-mcp-ec2-budget-window"),
    denylist_version: document.getElementById("scope-mcp-ec2-denylist")?.value.trim() || "",
    allowlist_rule_id: document.getElementById("scope-mcp-ec2-allowlist")?.value.trim() || "",
    enabled: true,
  };
}

function textareaLines(id) {
  const raw = document.getElementById(id)?.value || "";
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function lineParts(line) {
  return line.split("|").map((part) => part.trim());
}

function parseMcpEc2SafeFlag(value) {
  const normalized = (value || "safe").trim().toLowerCase();
  if (!normalized || normalized === "safe" || normalized === "true" || normalized === "yes") {
    return true;
  }
  if (normalized === "unsafe" || normalized === "false" || normalized === "no") {
    return false;
  }
  throw new Error(`unknown safe output flag '${value}'`);
}

function isMcpEc2SafeFlagToken(value) {
  if (!value) {
    return false;
  }
  return ["safe", "unsafe", "true", "false", "yes", "no"].includes(value.trim().toLowerCase());
}

function inferMcpEc2SafePrefix(pathPattern) {
  const index = pathPattern.lastIndexOf("/");
  if (index <= 0) {
    return "/";
  }
  return pathPattern.slice(0, index + 1);
}

function parseMcpEc2LogPathLine(line) {
  const [pathPattern, canonicalSafePrefix, safeFlag] = lineParts(line);
  if (!pathPattern) {
    throw new Error("log path is required");
  }
  return {
    path_pattern: pathPattern,
    canonical_safe_prefix: canonicalSafePrefix || inferMcpEc2SafePrefix(pathPattern),
    safe_for_mcp_output: parseMcpEc2SafeFlag(safeFlag),
  };
}

function parseMcpEc2JournalLine(line) {
  const [unit, safeFlag] = lineParts(line);
  if (!unit) {
    throw new Error("journal unit is required");
  }
  return {
    unit,
    safe_for_mcp_output: parseMcpEc2SafeFlag(safeFlag),
  };
}

function parseMcpEc2HttpLine(line) {
  const parts = lineParts(line);
  const normalizedUrl = parts[0];
  let queryPolicy = parts[1];
  let safeFlag = parts[2];
  let privateTargetRef = parts[3];
  if (!normalizedUrl) {
    throw new Error("HTTP URL is required");
  }
  if (isMcpEc2SafeFlagToken(queryPolicy)) {
    privateTargetRef = safeFlag;
    safeFlag = queryPolicy;
    queryPolicy = "no_query";
  }
  return {
    normalized_url: normalizedUrl,
    query_policy: normalizeMcpEc2QueryPolicy(queryPolicy),
    safe_for_mcp_output: parseMcpEc2SafeFlag(safeFlag),
    private_target_ref: privateTargetRef || null,
  };
}

function normalizeMcpEc2QueryPolicy(value) {
  const normalized = (value || "no_query").trim().toLowerCase().replaceAll("-", "_");
  if (normalized === "no_query" || normalized === "exact_only") {
    return normalized;
  }
  throw new Error(`unknown HTTP query policy '${value}'`);
}

function parseMcpEc2TcpLine(line) {
  const [target, privateTargetRef] = lineParts(line);
  const separator = target.lastIndexOf(":");
  if (separator <= 0) {
    throw new Error("TCP target must use host:port");
  }
  const host = target.slice(0, separator).trim();
  const port = Number(target.slice(separator + 1).trim());
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("TCP target must use a valid host:port");
  }
  return {
    host,
    port,
    private_target_ref: privateTargetRef || null,
  };
}

function parseMcpEc2DnsLine(line) {
  const [host, records, safeFlag, privateTargetRef] = lineParts(line);
  if (!host) {
    throw new Error("DNS host is required");
  }
  const recordTypes = (records || "A")
    .split(",")
    .map((record) => record.trim().toUpperCase())
    .filter(Boolean);
  if (!recordTypes.length || recordTypes.some((record) => !["A", "AAAA", "CNAME"].includes(record))) {
    throw new Error("DNS record types must be A, AAAA, or CNAME");
  }
  return {
    host,
    record_types: recordTypes,
    safe_for_mcp_output: parseMcpEc2SafeFlag(safeFlag),
    private_target_ref: privateTargetRef || null,
  };
}

function mcpEc2LogPathLines(scope) {
  return (scope?.allowed_log_paths || [])
    .map((path) =>
      [
        path.path_pattern,
        path.canonical_safe_prefix,
        path.safe_for_mcp_output ? "safe" : "unsafe",
      ].join(" | "),
    )
    .join("\n");
}

function mcpEc2JournalLines(scope) {
  return (scope?.allowed_journal_units || [])
    .map((unit) => [unit.unit, unit.safe_for_mcp_output ? "safe" : "unsafe"].join(" | "))
    .join("\n");
}

function mcpEc2HttpLines(scope) {
  return (scope?.allowed_http_urls || [])
    .map((url) =>
      [
        url.normalized_url,
        url.query_policy || "no_query",
        url.safe_for_mcp_output ? "safe" : "unsafe",
        url.private_target_ref || "",
      ].join(" | "),
    )
    .join("\n");
}

function mcpEc2TcpLines(scope) {
  return (scope?.allowed_tcp_targets || [])
    .map((target) => [`${target.host}:${target.port}`, target.private_target_ref || ""].join(" | "))
    .join("\n");
}

function mcpEc2DnsLines(scope) {
  return (scope?.allowed_dns_targets || [])
    .map((target) =>
      [
        target.host,
        (target.record_types || []).join(","),
        target.safe_for_mcp_output ? "safe" : "unsafe",
        target.private_target_ref || "",
      ].join(" | "),
    )
    .join("\n");
}

function mcpEc2CommandCount(request) {
  return (
    request.allowed_log_paths.length +
    request.allowed_journal_units.length +
    request.allowed_http_urls.length +
    request.allowed_tcp_targets.length +
    request.allowed_dns_targets.length
  );
}

function mcpEc2UnsafeOutputCount(request) {
  return [
    ...request.allowed_log_paths,
    ...request.allowed_journal_units,
    ...request.allowed_http_urls,
    ...request.allowed_dns_targets,
  ].filter((item) => item.safe_for_mcp_output === false).length;
}

function scopeDetailBlock(title, values) {
  const block = document.createElement("section");
  block.className = "scope-detail-block";
  block.append(el("h4", "", title));
  if (!values.length) {
    block.append(el("p", "", "none"));
    return block;
  }
  values.forEach((value) => {
    block.append(el("p", "", value));
  });
  return block;
}

function databaseScopeLine(scope) {
  return [
    `${scope.name}: ${scope.connection}/${scope.environment}`,
    `schemas ${listFull(scope.allowed_schemas)}`,
    `tables ${listFull(scope.allowed_tables)}`,
    `actions ${listFull(scope.allowed_actions)}`,
    `${scope.max_rows} rows, ${scope.max_examined_rows} examined, ${scope.statement_timeout_ms}ms`,
    scope.require_explain ? "explain required" : "explain optional",
    scope.allow_full_table_scan ? "full scan allowed" : "full scan blocked",
    scope.allow_views ? "views allowed" : "views blocked",
  ].join("; ");
}

function mcpEc2ScopeLine(scope) {
  return [
    `${scope.id}: logs ${listFull(scope.log_paths)}`,
    `journals ${listFull(scope.journal_units)}`,
    `http ${listFull(scope.http_urls)}`,
    `tcp ${listFull(scope.tcp_targets)}`,
    `dns ${listFull(scope.dns_targets)}`,
    `private refs ${listFull(scope.private_target_refs)}`,
    `limits ${scope.max_lines} lines, ${scope.max_matches} matches, ${scope.max_since_seconds}s since, ${scope.max_timeout_seconds}s timeout`,
    `budget ${scope.connectivity_probe_budget_per_window}/${scope.budget_window_seconds}s`,
    `allowlist ${scope.allowlist_rule_id || "none"}`,
    `denylist ${scope.denylist_version || "none"}`,
    `unsafe outputs ${scope.unsafe_output_count}`,
  ].join("; ");
}

function renderAccountsRoles(accounts, roles) {
  const accountRows = document.getElementById("account-rows");
  const roleRows = document.getElementById("role-rows");
  if (!accountRows || !roleRows) {
    return;
  }
  const summary = document.getElementById("account-role-summary");
  const accountCount = document.getElementById("account-count");
  const roleCount = document.getElementById("role-count");
  const accountUsage = document.getElementById("account-usage-summary");
  const roleUsage = document.getElementById("role-usage-summary");
  const totalAccountScopes = accounts.reduce((count, account) => count + (account.scopes?.length || 0), 0);
  const totalRolePackages = roles.reduce((count, role) => count + (role.packages?.length || 0), 0);
  if (summary) {
    summary.textContent = `${accounts.length} account(s), ${roles.length} role target(s)`;
  }
  if (accountCount) {
    accountCount.textContent = `${accounts.length} accounts`;
  }
  if (roleCount) {
    roleCount.textContent = `${roles.length} roles`;
  }
  if (accountUsage) {
    accountUsage.textContent = `${totalAccountScopes} scope binding(s)`;
  }
  if (roleUsage) {
    roleUsage.textContent = `${totalRolePackages} package binding(s)`;
  }

  if (!state.selectedAccount || !accounts.some((account) => account.id === state.selectedAccount)) {
    state.selectedAccount = accounts[0]?.id || null;
  }
  if (!state.selectedRole || !roles.some((role) => role.id === state.selectedRole)) {
    state.selectedRole = roles[0]?.id || null;
  }
  if (state.accountRoleSelection === "role" && !state.selectedRole) {
    state.accountRoleSelection = "account";
  }
  if (state.accountRoleSelection === "account" && !state.selectedAccount && state.selectedRole) {
    state.accountRoleSelection = "role";
  }

  accountRows.replaceChildren(
    ...(accounts.length ? accounts.map(accountRow) : [emptyAccountRoleRow(5, "No accounts to display")]),
  );
  roleRows.replaceChildren(
    ...(roles.length ? roles.map(roleRow) : [emptyAccountRoleRow(5, "No roles to display")]),
  );
  renderAccountRoleInspector(accounts, roles);
}

function accountRow(account) {
  const row = document.createElement("tr");
  row.dataset.account = account.id;
  row.classList.toggle(
    "selected",
    state.accountRoleSelection === "account" && account.id === state.selectedAccount,
  );
  row.addEventListener("click", () => {
    state.accountRoleSelection = "account";
    state.selectedAccount = account.id;
    renderAccountsRoles(state.draft?.accounts || [], state.draft?.roles || []);
  });
  [
    account.id,
    account.name,
    account.account_id,
    String(account.scopes?.length || 0),
    String(account.packages?.length || 0),
  ].forEach((value) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    row.append(cell);
  });
  return row;
}

function roleRow(role) {
  const row = document.createElement("tr");
  row.dataset.role = role.id;
  row.classList.toggle(
    "selected",
    state.accountRoleSelection === "role" && role.id === state.selectedRole,
  );
  row.addEventListener("click", () => {
    state.accountRoleSelection = "role";
    state.selectedRole = role.id;
    renderAccountsRoles(state.draft?.accounts || [], state.draft?.roles || []);
  });
  [
    role.id,
    role.mode,
    listPreview(role.accounts),
    String(role.packages?.length || 0),
    role.role_arn,
  ].forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 4) {
      cell.className = "mono-detail";
    }
    row.append(cell);
  });
  return row;
}

function emptyAccountRoleRow(colSpan, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colSpan;
  cell.textContent = message;
  row.append(cell);
  return row;
}

function renderAccountRoleInspector(accounts, roles) {
  const selectedAccount = accounts.find((account) => account.id === state.selectedAccount) || null;
  const selectedRole = roles.find((role) => role.id === state.selectedRole) || null;
  const showRole = state.accountRoleSelection === "role";
  const title = document.getElementById("account-role-selected-name");
  const badge = document.getElementById("account-role-selected-mode");
  const detailList = document.getElementById("account-role-detail-list");
  if (!detailList) {
    return;
  }

  if (showRole) {
    if (title) {
      title.textContent = selectedRole?.id || "Role";
    }
    if (badge) {
      badge.textContent = selectedRole?.mode || "Role";
      badge.classList.toggle("badge-risk", selectedRole?.mode === "concrete");
    }
    setText("#account-role-primary-label", "Role ARN");
    setText("#account-role-primary-value", selectedRole?.role_arn || "-");
    setText("#account-role-secondary-label", "Mode");
    setText("#account-role-secondary-value", selectedRole?.mode || "-");
    setText("#account-role-scope-label", "Scopes");
    setText("#account-role-scope-count", "-");
    setText("#account-role-package-label", "Packages");
    setText("#account-role-package-count", String(selectedRole?.packages?.length || 0));
    setText("#account-role-account-label", "Accounts");
    setText("#account-role-account-count", String(selectedRole?.accounts?.length || 0));
    setText("#account-role-role-label", "Role Type");
    setText("#account-role-role-count", selectedRole?.mode || "-");
    renderAccountRoleEditor("role", selectedRole);
    if (!selectedRole) {
      detailList.replaceChildren(accountRoleDetailHeading("Role Details", 0), el("p", "", "No role selected"));
      return;
    }
    const blocks = [
      accountRoleDetailBlock("Role ARN", selectedRole.role_arn ? [selectedRole.role_arn] : []),
      accountRoleDetailBlock("Applies To Accounts", selectedRole.accounts || []),
      accountRoleDetailBlock("Packages", selectedRole.packages || []),
    ];
    const heading = accountRoleDetailHeading("Role Details", blocks.length);
    detailList.replaceChildren(heading, ...blocks);
    return;
  }

  if (title) {
    title.textContent = selectedAccount?.id || "Account";
  }
  if (badge) {
    badge.textContent = "Account";
    badge.classList.remove("badge-risk");
  }
  setText("#account-role-primary-label", "Account ID");
  setText("#account-role-primary-value", selectedAccount?.account_id || "-");
  setText("#account-role-secondary-label", "Name");
  setText("#account-role-secondary-value", selectedAccount?.name || "-");
  setText("#account-role-scope-label", "Scopes");
  setText("#account-role-scope-count", String(selectedAccount?.scopes?.length || 0));
  setText("#account-role-package-label", "Packages");
  setText("#account-role-package-count", String(selectedAccount?.packages?.length || 0));
  setText("#account-role-account-label", "Roles");
  setText("#account-role-account-count", String(selectedAccount?.roles?.length || 0));
  setText("#account-role-role-label", "AWS Account");
  setText("#account-role-role-count", selectedAccount?.account_id || "-");
  renderAccountRoleEditor("account", selectedAccount);
  if (!selectedAccount) {
    detailList.replaceChildren(accountRoleDetailHeading("Account Details", 0), el("p", "", "No account selected"));
    return;
  }
  const blocks = [
    accountRoleDetailBlock("Account", [selectedAccount.account_id, selectedAccount.name]),
    accountRoleDetailBlock("Scopes", selectedAccount.scopes || []),
    accountRoleDetailBlock("Packages", selectedAccount.packages || []),
    accountRoleDetailBlock("Roles", selectedAccount.roles || []),
  ];
  const heading = accountRoleDetailHeading("Account Details", blocks.length);
  detailList.replaceChildren(heading, ...blocks);
}

function renderAccountRoleEditor(kind, selected) {
  const isRole = kind === "role";
  const canWrite = Boolean(state.server?.capabilities?.draft_write);
  const idInput = document.getElementById("account-role-edit-id");
  const primaryInput = document.getElementById("account-role-edit-primary");
  const secondaryInput = document.getElementById("account-role-edit-secondary");
  const secondaryRow = document.getElementById("account-role-edit-secondary-row");
  const saveButton = document.getElementById("account-role-save-button");
  const deleteButton = document.getElementById("account-role-delete-button");

  setText("#account-role-edit-id-label", isRole ? "Role" : "Account");
  setText("#account-role-edit-primary-label", isRole ? "Role ARN" : "AWS Account");
  setText("#account-role-edit-secondary-label", "Name");
  if (secondaryRow) {
    secondaryRow.hidden = isRole;
  }

  setElementInputValue(idInput, selected?.id || "", !canWrite);
  setElementInputValue(
    primaryInput,
    isRole ? selected?.role_arn || "" : selected?.account_id || "",
    !canWrite,
  );
  setElementInputValue(secondaryInput, isRole ? "" : selected?.name || "", !canWrite || isRole);
  if (saveButton) {
    saveButton.disabled = !canWrite;
  }
  if (deleteButton) {
    deleteButton.disabled = !canWrite || !selected?.id;
  }
}

function setElementInputValue(input, value, disabled) {
  if (input instanceof HTMLInputElement) {
    input.value = value;
    input.disabled = disabled;
  }
}

function accountRoleDetailHeading(title, count) {
  const heading = document.createElement("h3");
  heading.append(`${title} `);
  heading.append(el("span", "", String(count)));
  return heading;
}

function accountRoleDetailBlock(title, values) {
  const block = document.createElement("section");
  block.className = "account-role-detail-block";
  block.append(el("h4", "", title));
  if (!values.length) {
    block.append(el("p", "", "none"));
    return block;
  }
  values.forEach((value) => {
    block.append(el("p", "", value));
  });
  return block;
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

  renderIdentityWiring(group);
  renderRiskList(selectedPackage, changes);
}

function renderIdentityWiring(group) {
  renderIdentityList("membership-list", group.members || [], "membership");
  renderIdentityList("group-mapping-list", group.external_mappings || [], "group-mapping");
}

function renderIdentityList(listId, values, kind) {
  const list = document.getElementById(listId);
  if (!list) {
    return;
  }
  const items = [...values].sort();
  if (!items.length) {
    list.replaceChildren(el("p", "", kind === "membership" ? "No direct members" : "No external mappings"));
    return;
  }
  list.replaceChildren(
    ...items.map((value) => {
      const row = el("div", "identity-list-row");
      row.append(el("span", "", value));
      const removeButton = el("button", "", "×");
      removeButton.type = "button";
      removeButton.dataset.identityKind = kind;
      removeButton.dataset.identityValue = value;
      removeButton.setAttribute("aria-label", `Remove ${value}`);
      row.append(removeButton);
      return row;
    }),
  );
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
  const addedMemberships = changes.added_memberships || [];
  const removedMemberships = changes.removed_memberships || [];
  const addedMappings = changes.added_group_mappings || [];
  const removedMappings = changes.removed_group_mappings || [];
  const addedScopeResources = changes.added_scope_resources || [];
  const removedScopeResources = changes.removed_scope_resources || [];
  const objectChanges = [...accountRoleChanges(changes), ...packageChanges(changes)];
  const identityCount =
    addedMemberships.length +
    removedMemberships.length +
    addedMappings.length +
    removedMappings.length;
  const scopeResourceCount = addedScopeResources.length + removedScopeResources.length;
  const objectCount = objectChanges.length;
  const highRiskKeys = new Set(highRisk.map(grantKey));
  const summaryItems = document.querySelectorAll(".summary-grid strong");
  const changedGroups = new Set([
    ...added.map((change) => change.group),
    ...removed.map((change) => change.group),
    ...semanticAdded.map((grant) => grant.group),
    ...semanticRemoved.map((grant) => grant.group),
    ...addedMemberships.map((change) => change.group),
    ...removedMemberships.map((change) => change.group),
    ...addedMappings.map((change) => change.group),
    ...removedMappings.map((change) => change.group),
    ...addedScopeResources.map((change) => `scope:${change.scope}`),
    ...removedScopeResources.map((change) => `scope:${change.scope}`),
    ...objectChanges.map((change) => `${change.type}:${change.id}`),
  ]);
  if (summaryItems[0]) {
    summaryItems[0].firstChild.textContent = String(changedGroups.size);
  }
  if (summaryItems[1]) summaryItems[1].firstChild.textContent = String(added.length);
  if (summaryItems[2]) summaryItems[2].firstChild.textContent = String(removed.length);
  if (summaryItems[3]) summaryItems[3].firstChild.textContent = String(semanticCount + identityCount + scopeResourceCount + objectCount);

  const pendingTitle = document.querySelector(".pending-block h3");
  const pendingBody = document.querySelector(".pending-block tbody");
  if (pendingTitle) {
    const riskLabel = highRisk.length ? `, ${highRisk.length} high risk` : "";
    pendingTitle.textContent = `Pending Changes (${added.length + removed.length + semanticCount + identityCount + scopeResourceCount + objectCount}${riskLabel})`;
  }
  if (!pendingBody) {
    return;
  }
  const rows = [
    ...added.map((change) => changeRow("Add", change)),
    ...removed.map((change) => changeRow("Remove", change)),
    ...addedMemberships.map((change) => identityChangeRow("Add", "Direct membership", change.group, change.user_id)),
    ...removedMemberships.map((change) => identityChangeRow("Remove", "Direct membership", change.group, change.user_id)),
    ...addedMappings.map((change) => identityChangeRow("Add", "External mapping", change.group, change.external_group)),
    ...removedMappings.map((change) => identityChangeRow("Remove", "External mapping", change.group, change.external_group)),
    ...addedScopeResources.map((change) => scopeResourceChangeRow("Add", change)),
    ...removedScopeResources.map((change) => scopeResourceChangeRow("Remove", change)),
    ...objectChanges.map((change) => accountRoleChangeRow(change)),
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

function listFull(items) {
  const values = Array.isArray(items) ? items : [];
  return values.length ? values.join(", ") : "none";
}

function pendingChangeCount(changes) {
  const semantic = changes.semantic_diff || {};
  return [
    changes.added_bindings,
    changes.removed_bindings,
    changes.added_memberships,
    changes.removed_memberships,
    changes.added_group_mappings,
    changes.removed_group_mappings,
    changes.added_scope_resources,
    changes.removed_scope_resources,
    changes.added_accounts,
    changes.removed_accounts,
    changes.updated_accounts,
    changes.added_roles,
    changes.removed_roles,
    changes.updated_roles,
    changes.added_packages,
    changes.removed_packages,
    changes.updated_packages,
    semantic.added,
    semantic.removed,
  ].reduce((count, items) => count + (items?.length || 0), 0);
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

function fileStateLabel(file) {
  if (!file) {
    return "Not configured";
  }
  if (!file.exists) {
    return "Missing";
  }
  if (!file.readable) {
    return "Unreadable";
  }
  return file.sha256 ? `Loaded ${shortSha(file.sha256)}` : "Loaded";
}

function fileStatusKind(file) {
  if (!file?.exists || !file?.readable) {
    return "risk";
  }
  return "ok";
}

function canImportRuntime(server) {
  const importRuntime = server?.import_runtime;
  return Boolean(
    server?.capabilities?.import_runtime &&
      importRuntime?.exists &&
      importRuntime?.readable,
  );
}

function resetDraftSelection() {
  state.selectedGroup = null;
  state.selectedPackage = null;
  state.selectedMembers = "0";
  state.selectedScope = null;
  state.selectedAccount = null;
  state.selectedRole = null;
  state.selectedDbConnection = null;
}

function overviewStatusRow(label, status, detail, kind = "ok") {
  const row = el("div", `overview-status-row ${kind}`);
  row.append(el("span", "", label), el("strong", "", status), el("small", "", detail));
  return row;
}

function renderOverview() {
  const view = document.querySelector(".overview-view");
  if (!view) {
    return;
  }
  const server = state.server || {};
  const draft = state.draft || {};
  const changes = state.changes || {};
  const validation = state.validation;
  const apply = state.apply;
  const databaseConnections = state.databaseConnections || {};
  const groups = draft.groups || [];
  const packages = draft.packages || [];
  const scopes = draft.scopes || [];
  const accounts = draft.accounts || [];
  const roles = draft.roles || [];
  const localDbConnections = databaseConnections.local || [];
  const semantic = changes.semantic_diff || {};
  const semanticAdded = semantic.added || [];
  const semanticRemoved = semantic.removed || [];
  const highRisk = semantic.high_risk || [];
  const added = changes.added_bindings || [];
  const removed = changes.removed_bindings || [];
  const semanticCount = semanticAdded.length + semanticRemoved.length;
  const identityCount =
    (changes.added_memberships?.length || 0) +
    (changes.removed_memberships?.length || 0) +
    (changes.added_group_mappings?.length || 0) +
    (changes.removed_group_mappings?.length || 0);
  const scopeResourceCount =
    (changes.added_scope_resources?.length || 0) +
    (changes.removed_scope_resources?.length || 0);
  const objectCount = accountRoleChanges(changes).length + packageChanges(changes).length;
  const pendingCount = added.length + removed.length + semanticCount + identityCount + scopeResourceCount + objectCount;
  const packageHighRisk = packages.reduce(
    (count, pkg) => count + (pkg.high_risk_features?.length || 0),
    0,
  );
  const blocking = validation?.blocking_errors || [];
  const warnings = validation?.warnings || [];
  const dbIssues = databaseConnections.issues || [];
  const missingDb = databaseConnections.missing_required || [];
  const validationDb = validation?.database_connections || null;
  const deployment = validation?.deployment || server.deployment || {};
  const generated = validation?.generated || {};
  const runtime = server.runtime || {};
  const importRuntime = server.import_runtime || null;
  const identity = server.identity || {};
  const importButton = document.getElementById("import-runtime-button");

  setText(
    "#overview-summary",
    draft.loaded
      ? `${groups.length} group(s), ${packages.length} package(s), ${scopes.length} scope(s)`
      : draft.error || "Catalog draft is not loaded.",
  );
  setText(
    "#overview-validation-state",
    validation ? (validation.valid ? "Validation clean" : "Validation blocked") : "Validation not run",
  );
  setText(
    "#overview-apply-state",
    apply?.applied
      ? "Apply complete"
      : apply?.status === "blocked"
        ? "Apply blocked"
        : server.capabilities?.apply
          ? "Apply ready"
          : "Apply locked",
  );
  setText("#overview-group-count", String(groups.length));
  setText("#overview-package-count", String(packages.length));
  setText("#overview-scope-count", String(scopes.length));
  setText("#overview-account-count", String(accounts.length));
  setText("#overview-role-count", String(roles.length));
  setText("#overview-db-count", String(localDbConnections.length));
  setText("#overview-pending-count", String(pendingCount));
  setText("#overview-high-risk-count", String(highRisk.length + packageHighRisk));
  setText(
    "#overview-draft-detail",
    draft.loaded ? `Revision ${draft.revision ?? 0}` : "No draft loaded",
  );
  setText(
    "#overview-change-detail",
    pendingCount
      ? `${pendingCount} pending change(s), ${highRisk.length} high-risk grant(s)`
      : "No pending changes",
  );
  setText(
    "#overview-runtime-detail",
    validation ? runtimeStateLabel(generated) : fileStateLabel(runtime),
  );
  setText(
    "#overview-deployment-detail",
    validation ? deploymentStateLabel(deployment) : deployment.mode || "Deployment not checked",
  );
  setText(
    "#overview-import-detail",
    importRuntime ? fileStateLabel(importRuntime) : "Not configured",
  );
  setText(
    "#overview-import-path",
    importRuntime?.path || "Start with --import-runtime to enable import.",
  );
  if (importButton) {
    importButton.disabled = !canImportRuntime(server);
    importButton.textContent = canImportRuntime(server)
      ? "Import Runtime Draft"
      : "Import Unavailable";
  }
  setText(
    "#overview-db-detail",
    databaseConnections.configured
      ? `${localDbConnections.length} local connection(s)`
      : "No local DB config",
  );
  setText(
    "#overview-db-issue-detail",
    `${missingDb.length} missing, ${dbIssues.length} local issue(s)`,
  );

  const statusList = document.getElementById("overview-status-list");
  if (!statusList) {
    return;
  }
  const validationKind = validation ? (validation.valid ? "ok" : "risk") : "warn";
  const dbKind = dbIssues.length || missingDb.length ? "risk" : databaseConnections.configured ? "ok" : "warn";
  const deploymentKind = validation
    ? deployment.checked
      ? "ok"
      : "warn"
    : deployment.mode
      ? "warn"
      : "risk";
  statusList.replaceChildren(
    overviewStatusRow(
      "Catalog",
      fileStateLabel(server.catalog),
      server.catalog?.path || "catalog path unavailable",
      fileStatusKind(server.catalog),
    ),
    overviewStatusRow(
      "Runtime",
      validation ? runtimeStateLabel(generated) : fileStateLabel(runtime),
      validation
        ? `${generated.generated_rules || 0} generated rule(s)`
        : runtime.path || "runtime path unavailable",
      validation ? (generated.runtime_drift ? "warn" : "ok") : fileStatusKind(runtime),
    ),
    overviewStatusRow(
      "Import Runtime",
      server.import_runtime ? fileStateLabel(server.import_runtime) : "Not configured",
      server.import_runtime?.path || "runtime import is optional",
      server.import_runtime ? fileStatusKind(server.import_runtime) : "warn",
    ),
    overviewStatusRow(
      "Deployment",
      validation ? deploymentStateLabel(deployment) : deployment.mode || "Not configured",
      deployment.canonical_path || "Production validate/apply needs canonical deployment input",
      deploymentKind,
    ),
    overviewStatusRow(
      "DB Connections",
      databaseConnections.configured
        ? `${localDbConnections.length} local, ${missingDb.length} missing`
        : "Not configured",
      `${databaseConnections.required?.length || 0} required, ${dbIssues.length} issue(s)`,
      dbKind,
    ),
    overviewStatusRow(
      "Validation",
      validation ? (validation.valid ? "Clean" : "Blocked") : "Not run",
      validation
        ? `${blocking.length} blocking, ${warnings.length} warning(s)`
        : "Run validation before apply",
      validationKind,
    ),
    overviewStatusRow(
      "Identity",
      identity.source || "Unknown",
      `${identity.operator_external_group_count || 0} external group(s), dev identity ${identity.dev_identity_allowed ? "enabled" : "disabled"}`,
      identity.source ? "ok" : "warn",
    ),
    overviewStatusRow(
      "Database Deploy Check",
      validationDb ? databaseConnectionStateLabel(validationDb) : "Not checked",
      "Validated against generated runtime and deployment source when available",
      validationDb ? "ok" : "warn",
    ),
  );
}

function renderReviewApply() {
  const view = document.querySelector(".review-apply-view");
  if (!view) {
    return;
  }
  const changes = state.changes || {};
  const validation = state.validation;
  const apply = state.apply;
  const applyGate = apply?.gate || null;
  const server = state.server || {};
  const databaseConnections = state.databaseConnections || {};
  const added = changes.added_bindings || [];
  const removed = changes.removed_bindings || [];
  const semantic = changes.semantic_diff || {};
  const semanticAdded = semantic.added || [];
  const semanticRemoved = semantic.removed || [];
  const highRisk = semantic.high_risk || [];
  const semanticCount = semanticAdded.length + semanticRemoved.length;
  const addedMemberships = changes.added_memberships || [];
  const removedMemberships = changes.removed_memberships || [];
  const addedMappings = changes.added_group_mappings || [];
  const removedMappings = changes.removed_group_mappings || [];
  const addedScopeResources = changes.added_scope_resources || [];
  const removedScopeResources = changes.removed_scope_resources || [];
  const objectChanges = [...accountRoleChanges(changes), ...packageChanges(changes)];
  const identityCount =
    addedMemberships.length +
    removedMemberships.length +
    addedMappings.length +
    removedMappings.length;
  const scopeResourceCount = addedScopeResources.length + removedScopeResources.length;
  const objectCount = objectChanges.length;
  const pendingCount = added.length + removed.length + semanticCount + identityCount + scopeResourceCount + objectCount;
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
    applyGate
      ? `${apply.applied ? "Applied" : apply.status === "blocked" ? "Apply blocked" : "Apply locked"}: ${applyGate.message}`
      : validation
      ? validation.valid
        ? "Validation is clean for the current draft."
        : "Validation found blocking issues before apply."
      : pendingCount
        ? "Draft has pending changes that need validation."
        : "No pending draft changes; validation has not run.",
  );
  setText(
    "#review-apply-gate",
    applyGate
      ? applyGate.state === "validation_blocked"
        ? "Blocked"
        : "Locked"
      : server.capabilities?.apply
        ? "Ready"
        : "Locked",
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
    applyGate
      ? applyGate.reason_code
      : server.capabilities?.apply
        ? "Admin gate passed"
        : "Apply disabled",
  );
  setText(
    "#review-admin-detail",
    applyGate
      ? applyGate.message
      : server.capabilities?.apply
      ? "Operator identity can apply this draft."
      : "Production apply gate and transaction protocol are not enabled yet.",
  );

  const highRiskKeys = new Set(highRisk.map(grantKey));
  const rows = [
    ...added.map((change) => changeRow("Add", change)),
    ...removed.map((change) => changeRow("Remove", change)),
    ...addedMemberships.map((change) =>
      identityChangeRow("Add", "Direct membership", change.group, change.user_id),
    ),
    ...removedMemberships.map((change) =>
      identityChangeRow("Remove", "Direct membership", change.group, change.user_id),
    ),
    ...addedMappings.map((change) =>
      identityChangeRow("Add", "External mapping", change.group, change.external_group),
    ),
    ...removedMappings.map((change) =>
      identityChangeRow("Remove", "External mapping", change.group, change.external_group),
    ),
    ...addedScopeResources.map((change) => scopeResourceChangeRow("Add", change)),
    ...removedScopeResources.map((change) => scopeResourceChangeRow("Remove", change)),
    ...objectChanges.map((change) => accountRoleChangeRow(change)),
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
    ...(applyGate && !apply.applied
      ? [
          {
            severity: "blocking",
            code: applyGate.reason_code,
            message: applyGate.message,
          },
        ]
      : []),
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

function applyButtons() {
  return ["apply-button", "review-apply-button"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
}

function canCheckApply() {
  return Boolean(state.draft?.loaded);
}

function syncApplyButtons() {
  const apply = state.apply;
  const locked = !state.server?.capabilities?.apply;
  const label = apply?.applied
    ? "▢ Applied"
    : locked
      ? "▢ Apply locked"
      : "▢ Apply";
  applyButtons().forEach((button) => {
    button.disabled = !canCheckApply();
    button.classList.toggle("apply-locked", locked || !apply?.applied);
    button.textContent = label;
  });
}

async function runValidation(button) {
  if (!state.server?.capabilities?.validate) {
    setValidationStatus("Validate unavailable", "catalog draft is not loaded", false);
    renderReviewApply();
    renderOverview();
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
    renderOverview();
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
    renderOverview();
    setValidationStatus("Validation failed", error.message, false);
  } finally {
    validationButtons().forEach((item) => {
      item.disabled = !state.server?.capabilities?.validate;
    });
    button.textContent = originalLabel;
  }
}

async function runApply(button) {
  if (!canCheckApply()) {
    setValidationStatus("Apply unavailable", "catalog draft is not loaded", false);
    renderReviewApply();
    renderOverview();
    return;
  }
  applyButtons().forEach((item) => {
    item.disabled = true;
  });
  button.textContent = "▢ Checking";
  try {
    const apply = await applyDraft();
    apply.revision = state.draft?.revision ?? 0;
    state.apply = apply;
    if (apply.validation) {
      apply.validation.revision = apply.revision;
      state.validation = apply.validation;
      renderValidateSummary(apply.validation);
    }
    renderReviewApply();
    renderOverview();
    const gate = apply.gate || {};
    setValidationStatus(
      apply.applied ? "Apply complete" : apply.status === "blocked" ? "Apply blocked" : "Apply locked",
      gate.message || "Apply gate did not allow this draft",
      apply.applied,
    );
  } catch (error) {
    state.apply = null;
    renderReviewApply();
    renderOverview();
    setValidationStatus("Apply failed", error.message, false);
  } finally {
    syncApplyButtons();
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

function accountRoleChanges(changes) {
  return [
    ...(changes.added_accounts || []).map((change) => ({
      ...change,
      type: "account",
      action: "Add",
      label: "Account added",
      detail: `${change.account_id} / ${change.name}`,
    })),
    ...(changes.removed_accounts || []).map((change) => ({
      ...change,
      type: "account",
      action: "Remove",
      label: "Account removed",
      detail: `${change.account_id} / ${change.name}`,
    })),
    ...(changes.updated_accounts || []).map((change) => ({
      ...change,
      type: "account",
      action: "Update",
      label: "Account updated",
      detail: `${change.account_id} / ${change.name}`,
    })),
    ...(changes.added_roles || []).map((change) => ({
      ...change,
      type: "role",
      action: "Add",
      label: "Role added",
      detail: change.role_arn,
    })),
    ...(changes.removed_roles || []).map((change) => ({
      ...change,
      type: "role",
      action: "Remove",
      label: "Role removed",
      detail: change.role_arn,
    })),
    ...(changes.updated_roles || []).map((change) => ({
      ...change,
      type: "role",
      action: "Update",
      label: "Role updated",
      detail: change.role_arn,
    })),
  ];
}

function packageChanges(changes) {
  return [
    ...(changes.added_packages || []).map((change) => ({
      ...change,
      type: "package",
      action: "Add",
      label: "Package added",
      detail: packageChangeDetail(change),
    })),
    ...(changes.removed_packages || []).map((change) => ({
      ...change,
      type: "package",
      action: "Remove",
      label: "Package removed",
      detail: packageChangeDetail(change),
    })),
    ...(changes.updated_packages || []).map((change) => ({
      ...change,
      type: "package",
      action: "Update",
      label: "Package updated",
      detail: packageChangeDetail(change),
    })),
  ];
}

function packageChangeDetail(change) {
  const session = change.max_session_seconds ? `${change.max_session_seconds}s` : "default";
  return `${change.scope} / ${change.role}; ${change.features?.length || 0} feature(s); session ${session}`;
}

function accountRoleChangeRow(change) {
  const row = document.createElement("tr");
  [
    change.action,
    `${change.type}:${change.id}`,
    catalogObjectTargetLabel(change.type),
    change.label,
    change.detail,
  ].forEach((cellValue, index) => {
    const cell = document.createElement("td");
    cell.textContent = cellValue;
    if (index === 0) {
      cell.className = change.action === "Remove" ? "remove" : "add";
    }
    if (index === 4) {
      cell.classList.add("grant-detail");
    }
    row.append(cell);
  });
  return row;
}

function catalogObjectTargetLabel(type) {
  if (type === "account") {
    return "account target";
  }
  if (type === "package") {
    return "package target";
  }
  return "role target";
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

function identityChangeRow(type, changeLabel, group, value) {
  const row = document.createElement("tr");
  [type, group, "identity", changeLabel, value].forEach((cellValue, index) => {
    const cell = document.createElement("td");
    cell.textContent = cellValue;
    if (index === 0) {
      cell.className = type === "Add" ? "add" : "remove";
    }
    if (index === 4) {
      cell.classList.add("grant-detail");
    }
    row.append(cell);
  });
  return row;
}

function scopeResourceChangeRow(type, change) {
  const row = document.createElement("tr");
  [
    type,
    `scope:${change.scope}`,
    scopeResourceLabel(change.field),
    "Scope resource",
    change.value,
  ].forEach((cellValue, index) => {
    const cell = document.createElement("td");
    cell.textContent = cellValue;
    if (index === 0) {
      cell.className = type === "Add" ? "add" : "remove";
    }
    if (index === 4) {
      cell.classList.add("grant-detail");
    }
    row.append(cell);
  });
  return row;
}

function scopeResourceLabel(field) {
  return SCOPE_RESOURCE_LABELS[field] || field || "Scope";
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
    renderOverview();
    setActiveView(state.currentView || "overview");
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

async function togglePackageFeature(input) {
  const packageId = input.dataset.package;
  const feature = input.dataset.feature;
  const enabled = input.checked;
  if (!state.server?.capabilities?.draft_write || !packageId || !feature) {
    input.checked = !enabled;
    return;
  }
  input.disabled = true;
  try {
    const payload = await updateDraftPackageFeature(packageId, feature, enabled);
    state.selectedPackage = packageId;
    state.validation = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("packages");
  } catch (error) {
    input.checked = !enabled;
    renderPackages(state.draft?.packages || [], state.draft?.available_features || []);
    setValidationStatus("Package feature update failed", error.message, false);
  } finally {
    input.disabled = !state.server?.capabilities?.draft_write;
  }
}

async function savePackageDraft(enabled) {
  const id = document.getElementById("package-edit-id")?.value.trim() || "";
  const scope = document.getElementById("package-edit-scope")?.value || "";
  const role = document.getElementById("package-edit-role")?.value || "";
  const sessionText = document.getElementById("package-edit-session")?.value.trim() || "";
  const maxSessionSeconds = sessionText ? Number(sessionText) : null;
  if (!id) {
    setValidationStatus("Package update unavailable", "package id is required", false);
    return;
  }
  if (sessionText && (!Number.isInteger(maxSessionSeconds) || maxSessionSeconds <= 0)) {
    setValidationStatus(
      "Package update unavailable",
      "session cap must be a positive whole number of seconds",
      false,
    );
    return;
  }
  try {
    const payload = await updateDraftPackage(id, scope, role, maxSessionSeconds, enabled);
    state.selectedPackage = enabled ? id : state.selectedPackage;
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("packages");
    setValidationStatus(
      enabled ? "Package draft saved" : "Package draft removed",
      `${id} ${enabled ? "is staged in memory" : "was removed from draft"}`,
      true,
    );
  } catch (error) {
    setValidationStatus("Package update failed", error.message, false);
  }
}

document.getElementById("package-save-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await savePackageDraft(true);
  } finally {
    renderPackageInspector(state.draft?.packages || [], state.draft?.available_features || []);
  }
});

document.getElementById("package-delete-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await savePackageDraft(false);
  } finally {
    renderPackageInspector(state.draft?.packages || [], state.draft?.available_features || []);
  }
});

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

document.querySelectorAll("[data-overview-target]").forEach((button) => {
  button.addEventListener("click", () => {
    setActiveView(button.dataset.overviewTarget || "groups");
  });
});

async function updateScopeResource(field, value, enabled) {
  const scope = state.selectedScope;
  const trimmedValue = value.trim();
  if (!scope || !field || !trimmedValue) {
    setValidationStatus("Scope update unavailable", "select a scope and enter a resource value", false);
    return;
  }
  try {
    const payload = await updateDraftScopeResource(scope, field, trimmedValue, enabled);
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("scopes");
    setValidationStatus(
      enabled ? "Scope resource added" : "Scope resource removed",
      `${scopeResourceLabel(field)} ${trimmedValue} ${enabled ? "is staged for" : "was removed from"} ${scope}`,
      false,
    );
  } catch (error) {
    setValidationStatus("Scope update failed", error.message, false);
  }
}

document.getElementById("scope-resource-field")?.addEventListener("change", (event) => {
  if (!(event.target instanceof HTMLSelectElement)) {
    return;
  }
  state.selectedScopeResourceField = event.target.value;
  renderScopeInspector(state.draft?.scopes || []);
});

document.getElementById("scope-resource-add-button")?.addEventListener("click", async () => {
  const input = document.getElementById("scope-resource-input");
  const select = document.getElementById("scope-resource-field");
  const field =
    select instanceof HTMLSelectElement ? select.value : state.selectedScopeResourceField;
  const value = input?.value || "";
  await updateScopeResource(field, value, true);
  if (input) {
    input.value = "";
  }
});

document.getElementById("scope-db-template")?.addEventListener("change", (event) => {
  if (!(event.target instanceof HTMLSelectElement)) {
    return;
  }
  state.selectedDatabaseScopeName = event.target.value;
  renderScopeInspector(state.draft?.scopes || []);
});

document.getElementById("scope-mcp-ec2-template")?.addEventListener("change", (event) => {
  if (!(event.target instanceof HTMLSelectElement)) {
    return;
  }
  state.selectedMcpEc2ScopeId = event.target.value;
  renderScopeInspector(state.draft?.scopes || []);
});

async function saveDatabaseScopeDraft(enabled, button) {
  const scope = state.selectedScope;
  const request = databaseScopeDraftRequestFromForm();
  request.enabled = enabled;
  if (!enabled) {
    request.max_rows = request.max_rows || 1;
    request.statement_timeout_ms = request.statement_timeout_ms || 1;
    request.max_examined_rows = request.max_examined_rows || 1;
  }
  if (!scope || !request.name) {
    setValidationStatus("DB scope update unavailable", "select a scope and enter a DB scope name", false);
    return;
  }
  if (enabled && (
    !request.connection ||
    !request.environment ||
    !request.allowed_schemas.length ||
    !request.allowed_tables.length ||
    !request.allowed_actions.length ||
    !request.max_rows ||
    !request.statement_timeout_ms ||
    !request.max_examined_rows
  )) {
    setValidationStatus(
      "DB scope update unavailable",
      "connection, environment, schemas, tables, actions, and positive limits are required",
      false,
    );
    return;
  }
  const originalLabel = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = enabled ? "Saving" : "Removing";
  }
  try {
    const payload = await updateDraftDatabaseScope(scope, request);
    state.selectedDatabaseScopeName = enabled ? request.name : "";
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("scopes");
    setValidationStatus(
      enabled ? "DB scope draft saved" : "DB scope draft removed",
      `${request.name} ${enabled ? "is staged for" : "was removed from"} ${scope}`,
      enabled ? !(request.allow_full_table_scan || request.allow_views) : true,
    );
  } catch (error) {
    setValidationStatus("DB scope update failed", error.message, false);
  } finally {
    if (button) {
      button.textContent = originalLabel;
    }
    renderScopeInspector(state.draft?.scopes || []);
  }
}

document.getElementById("scope-db-save-button")?.addEventListener("click", async (event) => {
  await saveDatabaseScopeDraft(true, event.currentTarget);
});

document.getElementById("scope-db-delete-button")?.addEventListener("click", async (event) => {
  await saveDatabaseScopeDraft(false, event.currentTarget);
});

async function saveMcpEc2ScopeDraft(enabled, button) {
  const scope = state.selectedScope;
  let request;
  try {
    request = mcpEc2ScopeDraftRequestFromForm();
  } catch (error) {
    setValidationStatus("MCP EC2 scope update unavailable", error.message, false);
    return;
  }
  request.enabled = enabled;
  if (!enabled) {
    request.max_lines = request.max_lines || 1;
    request.max_since_seconds = request.max_since_seconds || 1;
    request.max_timeout_seconds = request.max_timeout_seconds || 1;
    request.max_matches = request.max_matches || 1;
    request.connectivity_probe_budget_per_window = request.connectivity_probe_budget_per_window || 1;
    request.budget_window_seconds = request.budget_window_seconds || 1;
    request.denylist_version = request.denylist_version || "remove";
    request.allowlist_rule_id = request.allowlist_rule_id || "remove";
  }
  if (!scope || !request.id) {
    setValidationStatus("MCP EC2 scope update unavailable", "select a scope and enter an MCP EC2 scope id", false);
    return;
  }
  if (
    enabled &&
    (!request.max_lines ||
      !request.max_since_seconds ||
      !request.max_timeout_seconds ||
      !request.max_matches ||
      !request.connectivity_probe_budget_per_window ||
      !request.budget_window_seconds ||
      !request.denylist_version ||
      !request.allowlist_rule_id ||
      !mcpEc2CommandCount(request))
  ) {
    setValidationStatus(
      "MCP EC2 scope update unavailable",
      "targets, positive limits, denylist, and allowlist are required",
      false,
    );
    return;
  }
  const originalLabel = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = enabled ? "Saving" : "Removing";
  }
  try {
    const payload = await updateDraftMcpEc2Scope(scope, request);
    state.selectedMcpEc2ScopeId = enabled ? request.id : "";
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("scopes");
    setValidationStatus(
      enabled ? "MCP EC2 scope draft saved" : "MCP EC2 scope draft removed",
      `${request.id} ${enabled ? "is staged for" : "was removed from"} ${scope}`,
      enabled ? mcpEc2UnsafeOutputCount(request) === 0 : true,
    );
  } catch (error) {
    setValidationStatus("MCP EC2 scope update failed", error.message, false);
  } finally {
    if (button) {
      button.textContent = originalLabel;
    }
    renderScopeInspector(state.draft?.scopes || []);
  }
}

document.getElementById("scope-mcp-ec2-save-button")?.addEventListener("click", async (event) => {
  await saveMcpEc2ScopeDraft(true, event.currentTarget);
});

document.getElementById("scope-mcp-ec2-delete-button")?.addEventListener("click", async (event) => {
  await saveMcpEc2ScopeDraft(false, event.currentTarget);
});

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const button = event.target.closest("[data-scope-resource-field]");
  if (!(button instanceof HTMLElement)) {
    return;
  }
  updateScopeResource(
    button.dataset.scopeResourceField || "",
    button.dataset.scopeResourceValue || "",
    false,
  );
});

async function saveAccountRoleDraft(enabled) {
  const isRole = state.accountRoleSelection === "role";
  const idInput = document.getElementById("account-role-edit-id");
  const primaryInput = document.getElementById("account-role-edit-primary");
  const secondaryInput = document.getElementById("account-role-edit-secondary");
  const id = idInput instanceof HTMLInputElement ? idInput.value.trim() : "";
  const primary = primaryInput instanceof HTMLInputElement ? primaryInput.value.trim() : "";
  const secondary = secondaryInput instanceof HTMLInputElement ? secondaryInput.value.trim() : "";
  if (!id) {
    setValidationStatus(
      isRole ? "Role update unavailable" : "Account update unavailable",
      isRole ? "role id is required" : "account id is required",
      false,
    );
    return;
  }
  try {
    const payload = isRole
      ? await updateDraftRole(id, primary, enabled)
      : await updateDraftAccount(id, primary, secondary, enabled);
    state.accountRoleSelection = isRole ? "role" : "account";
    state.selectedRole = isRole ? id : state.selectedRole;
    state.selectedAccount = isRole ? state.selectedAccount : id;
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("accounts-roles");
    setValidationStatus(
      enabled ? "Draft target saved" : "Draft target removed",
      `${isRole ? "role" : "account"} ${id} ${enabled ? "is staged" : "was removed from draft"}`,
      enabled,
    );
  } catch (error) {
    setValidationStatus("Draft target update failed", error.message, false);
  }
}

document.getElementById("account-role-save-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await saveAccountRoleDraft(true);
  } finally {
    renderAccountRoleInspector(state.draft?.accounts || [], state.draft?.roles || []);
  }
});

document.getElementById("account-role-delete-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await saveAccountRoleDraft(false);
  } finally {
    renderAccountRoleInspector(state.draft?.accounts || [], state.draft?.roles || []);
  }
});

async function updateIdentityWiring(kind, value, enabled) {
  const group = state.selectedGroup;
  const trimmedValue = value.trim();
  if (!group || !trimmedValue) {
    setValidationStatus("Identity update unavailable", "select a group and enter an identity value", false);
    return;
  }
  try {
    const payload =
      kind === "membership"
        ? await updateDraftMembership(group, trimmedValue, enabled)
        : await updateDraftGroupMapping(group, trimmedValue, enabled);
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("groups");
    setValidationStatus(
      enabled ? "Identity wiring added" : "Identity wiring removed",
      `${trimmedValue} ${enabled ? "is staged for" : "was removed from"} ${group}`,
      false,
    );
  } catch (error) {
    setValidationStatus("Identity update failed", error.message, false);
  }
}

document.getElementById("membership-add-button")?.addEventListener("click", async () => {
  const input = document.getElementById("membership-user-input");
  const value = input?.value || "";
  await updateIdentityWiring("membership", value, true);
  if (input) {
    input.value = "";
  }
});

document.getElementById("group-mapping-add-button")?.addEventListener("click", async () => {
  const input = document.getElementById("group-mapping-input");
  const value = input?.value || "";
  await updateIdentityWiring("group-mapping", value, true);
  if (input) {
    input.value = "";
  }
});

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const button = event.target.closest("[data-identity-kind]");
  if (!(button instanceof HTMLElement)) {
    return;
  }
  updateIdentityWiring(button.dataset.identityKind, button.dataset.identityValue || "", false);
});

document.getElementById("import-runtime-button")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!canImportRuntime(state.server)) {
    setValidationStatus(
      "Import unavailable",
      "start the UI with a readable --import-runtime path",
      false,
    );
    return;
  }
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = "Importing";
  try {
    const payload = await importRuntimeDraft();
    resetDraftSelection();
    state.validation = null;
    state.preview = null;
    state.explain = null;
    state.dryRun = null;
    applyServerState(payload);
    setActiveView("overview");
    setValidationStatus(
      "Runtime imported",
      "draft was replaced in memory; run Validate before Apply",
      false,
    );
  } catch (error) {
    setValidationStatus("Runtime import failed", error.message, false);
  } finally {
    button.disabled = !canImportRuntime(state.server);
    button.textContent = canImportRuntime(state.server)
      ? originalLabel
      : "Import Unavailable";
  }
});

document.getElementById("db-new-button")?.addEventListener("click", () => {
  state.draftingNewDbConnection = true;
  state.selectedDbConnection = null;
  renderDatabaseConnections(state.databaseConnections);
  setActiveView("db-connections");
  document.getElementById("db-connection-name")?.focus();
  setValidationStatus(
    "DB connection draft ready",
    "enter lowercase metadata and a secret reference before saving",
    true,
  );
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
    state.draftingNewDbConnection = false;
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

document.getElementById("apply-button")?.addEventListener("click", (event) => {
  runApply(event.currentTarget);
});

document.getElementById("review-apply-button")?.addEventListener("click", (event) => {
  runApply(event.currentTarget);
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
