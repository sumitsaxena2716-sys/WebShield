(() => {
  "use strict";
  const menuToggle = document.querySelector(".menu-toggle");
  const nav = document.querySelector(".primary-nav");
  if (menuToggle && nav) {
    menuToggle.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      menuToggle.setAttribute("aria-expanded", String(open));
      menuToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    });
    nav.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
      nav.classList.remove("open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "Open navigation");
    }));
    document.addEventListener("keydown", event => {
      if (event.key === "Escape") {
        nav.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  const year = document.getElementById("copyright-year");
  if (year) year.textContent = String(new Date().getFullYear());

  const form = document.getElementById("scan-form");
  if (!form) return;

  const targetInput = document.getElementById("target-url");
  const clearButton = document.getElementById("clear-url");
  const scanButton = document.getElementById("scan-button");
  const status = document.getElementById("status-message");
  const results = document.getElementById("results");
  let latestResult = null;

  clearButton?.addEventListener("click", () => {
    targetInput.value = "";
    targetInput.focus();
  });

  function showStatus(message, type = "success") {
    status.textContent = message;
    status.className = `status-message ${type}`;
    status.hidden = false;
  }
  function safeText(element, value, fallback = "—") {
    element.textContent = value === null || value === undefined || value === "" ? fallback : String(value);
  }
  function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function renderFindings(items) {
    const container = document.getElementById("findings-list");
    container.replaceChildren();
    if (!items.length) {
      container.append(make("p", "muted", "No findings returned."));
      return;
    }
    items.forEach(item => {
      const card = make("article", "finding");
      const top = make("div", "finding-top");
      top.append(make("h4", "", item.title || "Untitled finding"));
      top.append(make("span", `severity ${item.severity || "info"}`, item.severity || "info"));
      card.append(top);
      card.append(make("p", "", item.detail || ""));
      const recommendation = make("p", "recommendation");
      recommendation.append(make("b", "", "Next step: "));
      recommendation.append(document.createTextNode(item.recommendation || "Review this finding."));
      card.append(recommendation);
      container.append(card);
    });
  }
  function renderLinks(items) {
    const container = document.getElementById("links-list");
    container.replaceChildren();
    if (!items.length) {
      container.append(make("p", "muted", "Link checking was disabled or no eligible links were found."));
      return;
    }
    items.forEach(item => {
      const card = make("div", `link-item ${item.ok ? "" : "broken"}`);
      const link = make("a", "", item.url);
      link.href = item.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      card.append(link);
      const state = item.ok ? `HTTP ${item.status}` : (item.status ? `HTTP ${item.status}` : (item.error || "Could not verify"));
      card.append(make("small", "", state));
      container.append(card);
    });
  }
  function renderResult(data) {
    latestResult = data;
    results.hidden = false;
    safeText(document.getElementById("result-target"), `${data.final_url} · HTTP ${data.status_code}`);
    safeText(document.getElementById("score-value"), data.score);
    document.getElementById("score-bar").style.width = `${Math.max(0, Math.min(100, data.score))}%`;
    safeText(document.getElementById("count-high"), data.summary?.high ?? 0);
    safeText(document.getElementById("count-medium"), data.summary?.medium ?? 0);
    safeText(document.getElementById("count-low"), data.summary?.low ?? 0);
    safeText(document.getElementById("count-info"), data.summary?.info ?? 0);
    renderFindings(data.findings || []);
    renderLinks(data.links || []);
    safeText(document.getElementById("page-status"), data.status_code);
    safeText(document.getElementById("page-title"), data.page_info?.title);
    safeText(document.getElementById("page-description"), data.page_info?.description);
    safeText(document.getElementById("page-viewport"), data.page_info?.viewport ? "Present" : "Not found");
    safeText(document.getElementById("page-favicon"), data.page_info?.favicon);
    safeText(document.getElementById("limitations-text"), (data.limitations || []).join(" "));
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    if (!document.getElementById("authorized").checked) {
      showStatus("Please confirm that you own the website or have explicit permission to scan it.", "error");
      return;
    }
    scanButton.disabled = true;
    scanButton.querySelector(".button-label").textContent = "Scanning safely…";
    showStatus("Scan started. The scanner uses bounded, non-invasive HTTP checks.", "success");
    results.hidden = true;
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          url: targetInput.value.trim(),
          authorized: document.getElementById("authorized").checked,
          check_links: document.getElementById("check-links").checked
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The scan failed. Please try again.");
      renderResult(data);
      showStatus("Scan complete. Review the findings and validate them in context.", "success");
    } catch (error) {
      showStatus(error.message || "The scan could not be completed. Please try again.", "error");
    } finally {
      scanButton.disabled = false;
      scanButton.querySelector(".button-label").textContent = "Run security scan";
    }
  });

  document.getElementById("download-report")?.addEventListener("click", () => {
    if (!latestResult) {
      showStatus("Run a scan before downloading a report.", "error");
      return;
    }
    const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `webshield-report-${latestResult.scan_id || "latest"}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    showStatus("Report download started.", "success");
  });
})();
