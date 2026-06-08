const state = {
  selectedGroup: "RD",
  selectedMembers: "12",
  filter: "all",
  validatedAt: "just now",
};

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
  document.querySelector(".validation-block span").textContent = `Last validated: ${state.validatedAt}`;
});

document.getElementById("preview-button")?.addEventListener("click", () => {
  document.querySelector(".save-state small").textContent = "preview refreshed";
});

if (window.__CANOPY_BOOTSTRAP_CODE__) {
  window.__CANOPY_BOOTSTRAP_CODE__ = null;
}
